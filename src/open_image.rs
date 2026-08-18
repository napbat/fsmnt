//! Opening a filesystem inside a decoded disk-image container.
//!
//! [`open_image_with_options`] resolves *where* the filesystem is — a
//! partition ordinal from [`image_layout`](crate::image_layout), or a byte
//! offset for media no partition table describes — bounds a reader to the
//! bytes the image actually carries there, and hands it to whichever
//! registered driver claims the detected boot sector.
//!
//! The failures are enumerated rather than flattened to strings
//! ([`OpenImageError`]) because each one names the next thing to try: which
//! partition to pick, how far back the primary superblock lies, which
//! credential is missing.

use std::sync::Arc;

use tracing::debug;

use fsmnt_core::{FsError, TargetFilesystem};
use fsmnt_device::{
    AbsentHead, DetectedBootSector, DeviceReader, DriverRegistry, FilesystemOpenOptions,
    FilesystemRoot, ImageFormat, ImageOpenError, ImageReader, LeadingGapReader, PartitionReader,
    ReadSubstitutions, TolerantReader,
};

use crate::ext_backup;
use crate::layout::{self, ImageLayoutOptions, LayoutOrigin};
use crate::truncation;

/// A filesystem opened from a decoded disk-image container, ready to mount.
pub struct OpenedImage {
    /// The filesystem opened by a registered driver.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// The detected boot-sector type at the selected image offset.
    pub detected: DetectedBootSector,
    /// Byte offset the filesystem was opened at within the decoded media.
    /// For a selected partition this is the partition's start, not the
    /// offset originally requested.
    pub offset: u64,
    /// Bytes of the selected range the decoded media actually carries.
    ///
    /// This is the window the filesystem was opened in, so it never runs
    /// past the end of the image even when the partition table says the
    /// partition does; compare it with
    /// [`declared_size_bytes`](Self::declared_size_bytes) to see whether the
    /// image is short of the extent it describes.
    pub size_bytes: u64,
    /// Length the partition table declares for the selected range, which for
    /// a truncated image can exceed [`size_bytes`](Self::size_bytes). Equal
    /// to `size_bytes` when no partition was selected.
    pub declared_size_bytes: u64,
    /// Bytes the opened filesystem claims for itself that the image does not
    /// carry, or `None` when it fits (see
    /// [`missing_filesystem_bytes`](crate::missing_filesystem_bytes)).
    ///
    /// A filesystem whose superblock is present but whose data is not opens
    /// normally and then fails one read at a time; this states up front how
    /// much of it is missing.
    pub truncated_by: Option<u64>,
    /// Container format used to expose the decoded media.
    pub format: ImageFormat,
    /// Running totals of bytes served as zeros in place of data the image
    /// could not provide — present only when the filesystem was opened with
    /// [`ImageOpenOptions::with_best_effort_reads`], and shared with the
    /// reader so a caller can report them after the mount ends.
    pub substitutions: Option<Arc<ReadSubstitutions>>,
    /// Where the partition ordinal was resolved, when one was used: the
    /// image's own table, its backup GPT, or a **synthetic** table
    /// reconstructed from a scan ([`LayoutOrigin::Scan`]). `None` when the
    /// filesystem was addressed by byte offset. Library callers that record
    /// how a volume was located should keep this alongside the mount.
    pub layout_origin: Option<LayoutOrigin>,
}

/// Failure to decode an image or open a filesystem within its virtual media.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenImageError {
    /// The image container could not be opened or decoded.
    #[error(transparent)]
    Container(#[from] ImageOpenError),
    /// The selected byte offset does not address decoded media.
    #[error("offset {offset} is at or past the end of {path:?} ({size_bytes} decoded bytes)")]
    OffsetOutOfRange {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Requested decoded-media offset.
        offset: u64,
        /// Total decoded-media size.
        size_bytes: u64,
    },
    /// The selected offset identifies another partition table.
    #[error(
        "{path:?} contains a partition table at offset {offset} ({detected:?}); select a partition with `--partition N` (see `fsmnt partitions {}`)",
        path.display()
    )]
    PartitionTable {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset that contains the partition table.
        offset: u64,
        /// Partition-table type detected at the offset.
        detected: DetectedBootSector,
    },
    /// The image layout could not be read to enumerate its partitions.
    #[error("failed to read the partition layout of {path:?}: {source}")]
    Layout {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// Reconstructing the layout by scanning the media failed part-way.
    #[error("failed to scan {path:?} for filesystems: {source}")]
    Scan {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// The scan failure.
        #[source]
        source: crate::ScanError,
    },
    /// The requested partition ordinal is not present in the image.
    #[error(
        "partition {partition} not found in {path:?}: the image has {available} partition(s); list them with `fsmnt partitions {}`",
        path.display()
    )]
    PartitionNotFound {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Requested 0-based partition ordinal.
        partition: usize,
        /// Number of partitions the image actually exposes.
        available: usize,
    },
    /// The selected offset holds an ext *backup* superblock, not the start
    /// of a filesystem.
    ///
    /// Backup copies sit partway into an ext filesystem (with
    /// `sparse_super`, at block groups 1, 3, 5, 7, 9, 25, 27, …). Opening
    /// from one would locate every structure relative to the wrong place
    /// and present an empty volume, so it is refused with the group number
    /// as a hint that the real start is earlier.
    #[error(
        "offset {offset} in {path:?} holds an ext backup superblock (block group {group}); {} — mount that, or list partitions with `fsmnt partitions {}`",
        primary_location(*filesystem_start),
        path.display()
    )]
    ExtBackupSuperblock {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset that holds the backup copy.
        offset: u64,
        /// Block group the backup superblock belongs to.
        group: u16,
        /// Where the filesystem this copy belongs to begins, computed from
        /// the geometry the copy itself records. `None` when that geometry
        /// places the start before the beginning of the media, which means
        /// the copy is stale or coincidental rather than a backup of a
        /// filesystem living here.
        filesystem_start: Option<u64>,
    },
    /// Nothing is readable at the selected offset, but an ext backup
    /// superblock one block group in says a filesystem starts there.
    ///
    /// The offset was right and its primary metadata is destroyed —
    /// zeroed, overwritten, or simply never copied by a partial imaging
    /// run. The volume is still openable from the copy.
    #[error(
        "no filesystem at offset {offset} in {path:?}, but an ext backup superblock for it exists at {backup_offset} (group {group}); retry with `--backup-superblock {group}`"
    )]
    ExtPrimaryDamaged {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset whose primary metadata is unreadable.
        offset: u64,
        /// Block group holding the usable copy.
        group: u32,
        /// Decoded-media offset of that copy.
        backup_offset: u64,
    },
    /// A head the medium does not carry was combined with a location
    /// inside it.
    ///
    /// [`ImageOpenOptions::with_head_absent`] says the filesystem starts
    /// *before* byte 0 of the image; a partition ordinal, a scanned
    /// ordinal, or a positive offset each say it starts somewhere *within*
    /// it. Both cannot be true, and guessing which one the caller meant
    /// would put every structure at the wrong place.
    #[error(
        "the image was declared to begin {head_absent} bytes into its filesystem, which puts the \
         filesystem's start before byte 0; {location} names a location inside the image instead, \
         and the two cannot both be where the filesystem is"
    )]
    HeadAbsentConflictsWithLocation {
        /// Bytes of the filesystem that precede the image.
        head_absent: u64,
        /// The conflicting way of saying where the filesystem is.
        location: &'static str,
    },
    /// The image begins inside its filesystem, so there is nothing at
    /// offset 0 to detect, and no backup superblock was named to open it
    /// through.
    ///
    /// By construction the primary superblock (or boot sector) is one of
    /// the bytes that were never acquired. ext scatters copies of its
    /// superblock through the volume, so the volume is still openable —
    /// but only once the caller says which copy to use.
    #[error(
        "{path:?} begins {head_absent} bytes into its filesystem, so the primary superblock is \
         among the bytes it does not carry and nothing at offset 0 can be classified; open it \
         through a surviving copy with `--backup-superblock GROUP` (`fsmnt scan` names the \
         groups whose backups are present)"
    )]
    HeadAbsentPrimaryUnreadable {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Bytes of the filesystem that precede the image.
        head_absent: u64,
    },
    /// Reading or classifying the selected boot sector failed.
    #[error("failed to detect a filesystem at offset {offset} in {path:?}: {source}")]
    Detection {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset being inspected.
        offset: u64,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// A registered filesystem driver could not open the detected media.
    #[error("failed to open {detected:?} at offset {offset} in {path:?}: {source}")]
    Filesystem {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset handed to the driver.
        offset: u64,
        /// Filesystem type detected at the offset.
        detected: DetectedBootSector,
        /// Driver or filesystem parser failure.
        #[source]
        source: FsError,
    },
}

/// Phrase naming where a filesystem starts, for
/// [`OpenImageError::ExtBackupSuperblock`].
fn primary_location(filesystem_start: Option<u64>) -> String {
    filesystem_start.map_or_else(
        || "the primary lies earlier".to_string(),
        |start| format!("the filesystem starts at offset {start}"),
    )
}

/// Location and filesystem-root choices for opening a disk image.
#[derive(Clone, Debug)]
pub struct ImageOpenOptions {
    offset: u64,
    head_absent: u64,
    partition: Option<usize>,
    sector_size: Option<u32>,
    scan_stride: Option<u64>,
    best_effort_reads: bool,
    filesystem: FilesystemOpenOptions,
}

impl ImageOpenOptions {
    /// Use the beginning of the decoded image and the filesystem's default
    /// root.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            offset: 0,
            head_absent: 0,
            partition: None,
            sector_size: None,
            scan_stride: None,
            best_effort_reads: false,
            filesystem: FilesystemOpenOptions::new(),
        }
    }

    /// Resolve [`with_partition`](Self::with_partition) against a
    /// **synthetic** table reconstructed by scanning the media every
    /// `stride` bytes for filesystem starts, instead of the partition table
    /// at the front of the image (see [`LayoutOrigin::Scan`]). The ordinal
    /// then means "the N-th filesystem the scan finds", which holds only for
    /// this image at this stride.
    #[must_use]
    pub const fn with_scan(mut self, stride: u64) -> Self {
        self.scan_stride = Some(stride);
        self
    }

    /// Zero-fill what the image cannot provide instead of failing the read:
    /// bytes past the end of a truncated dump (up to the extent the
    /// partition table or the requested window declares) and sectors that
    /// error. Off by default — zeros are not data — and every substitution
    /// is counted in [`OpenedImage::substitutions`] so the report can say
    /// how much of what was read was really there.
    #[must_use]
    pub const fn with_best_effort_reads(mut self, best_effort: bool) -> Self {
        self.best_effort_reads = best_effort;
        self
    }

    /// Select the byte offset of the filesystem within decoded image media.
    ///
    /// Use this for media whose filesystem no partition table describes;
    /// prefer [`with_partition`](Self::with_partition) for a partitioned
    /// whole-disk image.
    #[must_use]
    pub const fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// State that the image begins `bytes` into its filesystem: the
    /// filesystem's own first `bytes` bytes were never acquired.
    ///
    /// The mirror image of [`with_offset`](Self::with_offset). An offset
    /// says "the filesystem starts this far into the image"; this says the
    /// image starts this far into the *filesystem* — a slice cut out of a
    /// larger volume, which `fsmnt scan` reports as "the filesystem starts
    /// N bytes before this medium". The image is then presented as the
    /// whole volume, with the first `bytes` absent, so structures the
    /// filesystem addresses by its own geometry land where it expects them
    /// instead of `bytes` too early.
    ///
    /// The primary superblock is among the absent bytes by construction, so
    /// this is only useful together with
    /// [`FilesystemOpenOptions::with_ext_backup_superblock`], which names a
    /// surviving copy to open through; without one the open fails with
    /// [`OpenImageError::HeadAbsentPrimaryUnreadable`]. Reads that reach
    /// into the head fail with the absent-head message unless
    /// [`with_best_effort_reads`](Self::with_best_effort_reads) is on, which
    /// serves them as zeros counted in
    /// [`ReadSubstitutions::absent_bytes`](fsmnt_device::ReadSubstitutions::absent_bytes).
    /// The ext driver itself copes either way: opening through a backup
    /// treats an unreadable primary as merely absent, and salvage skips the
    /// groups it cannot read.
    ///
    /// Mutually exclusive with a non-zero [`with_offset`](Self::with_offset),
    /// with [`with_partition`](Self::with_partition), and with
    /// [`with_scan`](Self::with_scan): each of those names a location
    /// *inside* the image, and the filesystem cannot both begin before the
    /// image and somewhere within it. Combining them fails with
    /// [`OpenImageError::HeadAbsentConflictsWithLocation`].
    #[must_use]
    pub const fn with_head_absent(mut self, bytes: u64) -> Self {
        self.head_absent = bytes;
        self
    }

    /// Select a partition of the image by its ordinal, counting non-empty
    /// partition-table entries from 0 — the same numbering
    /// [`image_layout`](crate::image_layout) prints and `fsmnt mount DRIVE
    /// --partition` uses.
    ///
    /// The partition's own start offset and length bound the filesystem, so
    /// this supersedes [`with_offset`](Self::with_offset): any offset set
    /// alongside a partition is ignored, and callers that select a partition
    /// should leave the offset at 0.
    #[must_use]
    pub const fn with_partition(mut self, partition: usize) -> Self {
        self.partition = Some(partition);
        self
    }

    /// Read the image's partition table in sectors of `sector_size` bytes.
    ///
    /// Only affects [`with_partition`](Self::with_partition): a dump of a
    /// 4Kn drive keeps its GPT header at byte 4096 and counts entry LBAs in
    /// 4096-byte units, so the partition offsets come out eight times too
    /// small when it is read as 512-byte sectors. Left unset, enumeration
    /// detects the sector size (see
    /// [`ImageLayout::sector_size_auto_detected`](crate::ImageLayout::sector_size_auto_detected)).
    #[must_use]
    pub const fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = Some(sector_size);
        self
    }

    /// Choose the filesystem-owned tree or container volume to expose.
    #[must_use]
    pub fn with_filesystem_root(mut self, root: FilesystemRoot) -> Self {
        self.filesystem = self.filesystem.with_root(root);
        self
    }

    /// Allow (default) or decline journal and orphan replay into an
    /// in-memory overlay; see
    /// [`FilesystemOpenOptions::with_journal_replay`]. The source is never
    /// written either way.
    #[must_use]
    pub fn with_journal_replay(mut self, replay: bool) -> Self {
        self.filesystem = self.filesystem.with_journal_replay(replay);
        self
    }

    /// Replace every filesystem-level option (root selector, journal
    /// replay, backup-superblock group, salvage) with `filesystem` at once.
    #[must_use]
    pub fn with_filesystem_options(mut self, filesystem: FilesystemOpenOptions) -> Self {
        self.filesystem = filesystem;
        self
    }

    /// Byte offset of the filesystem within decoded image media. Ignored
    /// when [`partition`](Self::partition) selects a partition.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Bytes of the filesystem that precede the image, or 0 when the image
    /// starts where its filesystem does.
    #[must_use]
    pub const fn head_absent(&self) -> u64 {
        self.head_absent
    }

    /// Partition ordinal to open, if one was selected.
    #[must_use]
    pub const fn partition(&self) -> Option<usize> {
        self.partition
    }

    /// Requested partition-table sector size, if one was set.
    #[must_use]
    pub const fn sector_size(&self) -> Option<u32> {
        self.sector_size
    }

    /// The stride of the media scan a partition ordinal is resolved against,
    /// or `None` when the image's own partition table is used.
    #[must_use]
    pub const fn scan_stride(&self) -> Option<u64> {
        self.scan_stride
    }

    /// Whether reads the image cannot satisfy are zero-filled rather than
    /// failed.
    #[must_use]
    pub const fn best_effort_reads(&self) -> bool {
        self.best_effort_reads
    }

    /// Requested filesystem-open options.
    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemOpenOptions {
        &self.filesystem
    }
}

impl Default for ImageOpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Open a filesystem at the beginning of a supported disk image.
///
/// EWF container signatures are detected automatically and sibling segments
/// are discovered from the supplied segment path. Fixed, dynamic, and
/// differencing VHD/VHDX containers are decoded into virtual media; parent
/// locators resolve accessible `.avhd` and `.avhdx` chains. Use
/// [`open_image_with_options`] when the decoded image starts with a partition
/// table or when a non-default filesystem root is needed.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, its selected
/// range is empty, it starts with a partition table, filesystem detection
/// fails, or no registered driver can open it.
pub fn open_image(
    path: impl AsRef<std::path::Path>,
    drivers: &DriverRegistry,
) -> Result<OpenedImage, OpenImageError> {
    open_image_with_options(path, drivers, ImageOpenOptions::new())
}

/// Open a filesystem from a supported disk image with explicit options.
///
/// A partitioned whole-disk image is addressed by partition ordinal with
/// [`ImageOpenOptions::with_partition`], which bounds the filesystem to that
/// partition's extent; [`image_layout`](crate::image_layout) lists the
/// ordinals. Without a partition the offset is used as-is, addressing
/// decoded logical media rather than EWF segment bytes or VHD/VHDX
/// container storage, and the filesystem spans the rest of the image.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, the selected
/// partition does not exist, the resolved offset is at or past the end of
/// the decoded image, the selected range starts with a partition table,
/// filesystem detection fails, or no registered driver can open the detected
/// filesystem and requested root.
pub fn open_image_with_options(
    path: impl AsRef<std::path::Path>,
    drivers: &DriverRegistry,
    options: ImageOpenOptions,
) -> Result<OpenedImage, OpenImageError> {
    let path = path.as_ref();
    let ImageOpenOptions {
        offset,
        head_absent,
        partition,
        sector_size,
        scan_stride,
        best_effort_reads,
        filesystem,
    } = options;
    if head_absent > 0 {
        if let Some(location) = conflicting_location(offset, partition, scan_stride) {
            return Err(OpenImageError::HeadAbsentConflictsWithLocation {
                head_absent,
                location,
            });
        }
        return open_image_head_absent(path, drivers, head_absent, best_effort_reads, &filesystem);
    }
    let layout::LocatedImagePartition {
        mut image,
        offset,
        declared_bytes,
        available_bytes,
        origin: layout_origin,
    } = locate_image_window(path, partition, offset, sector_size, scan_stride)?;

    // Bounded to the window so a dead sector 0 can still be classified from
    // the copies each format keeps (FAT32/exFAT backup regions, the NTFS
    // boot sector mirrored in the volume's last sector).
    let detected = fsmnt_device::detect_boot_sector_within(&mut image, offset, available_bytes)
        .map_err(|source| OpenImageError::Detection {
            path: path.to_path_buf(),
            offset,
            source,
        })?;
    let detected = ext_backup::detection_with_backup_request(detected, &filesystem);
    debug!(
        path = %path.display(),
        offset,
        detected = ?detected,
        "classified the boot sector at the selected image offset"
    );
    if matches!(
        detected,
        DetectedBootSector::MbrPartitioned | DetectedBootSector::GptPartitioned
    ) {
        return Err(OpenImageError::PartitionTable {
            path: path.to_path_buf(),
            offset,
            detected,
        });
    }
    if detected == DetectedBootSector::Unknown {
        explain_unknown(&mut image, path, offset, available_bytes)?;
    }

    let format = image.format();
    // With best-effort reads the window is the *declared* extent: the
    // missing tail reads as zeros (and is counted) instead of ending the
    // media early, so a filesystem whose data runs past the dump's end can
    // still be walked for what is there.
    let (source, window, substitutions): (
        Box<dyn DeviceReader>,
        u64,
        Option<Arc<ReadSubstitutions>>,
    ) = if best_effort_reads {
        let declared_end = offset.saturating_add(declared_bytes);
        let (tolerant, stats) = TolerantReader::new(image, declared_end).map_err(|source| {
            OpenImageError::Detection {
                path: path.to_path_buf(),
                offset,
                source,
            }
        })?;
        (Box::new(tolerant), declared_bytes, Some(stats))
    } else {
        (Box::new(image), available_bytes, None)
    };
    let reader = PartitionReader::new(source, offset, window);
    let filesystem = drivers
        .open_with_options(Box::new(reader), detected, &filesystem)
        .map_err(|source| OpenImageError::Filesystem {
            path: path.to_path_buf(),
            offset,
            detected,
            source,
        })?;

    let truncated_by =
        truncation::missing_filesystem_bytes(filesystem.total_size(), available_bytes);
    Ok(OpenedImage {
        filesystem,
        detected,
        offset,
        size_bytes: available_bytes,
        declared_size_bytes: declared_bytes,
        truncated_by,
        format,
        substitutions,
        layout_origin,
    })
}

/// The way of naming a location inside the image that a caller combined
/// with an absent head, or `None` when nothing conflicts.
const fn conflicting_location(
    offset: u64,
    partition: Option<usize>,
    scan_stride: Option<u64>,
) -> Option<&'static str> {
    if partition.is_some() {
        Some("a partition ordinal (`--partition`)")
    } else if scan_stride.is_some() {
        Some("a scanned ordinal (`--scan`)")
    } else if offset > 0 {
        Some("a positive byte offset (`--offset`)")
    } else {
        None
    }
}

/// Open a filesystem the image begins *inside*: its first `head_absent`
/// bytes were never acquired.
///
/// The image is presented as the whole volume through a
/// [`LeadingGapReader`], so the filesystem addresses its structures at the
/// offsets its own geometry names. Two consequences follow, and both are
/// deliberate. Detection at offset 0 has nothing to read — the primary
/// superblock is one of the absent bytes — so an absent-head failure is
/// taken as "unknown" and the caller's backup-superblock request selects
/// the driver, exactly as it does for a head that was zeroed rather than
/// never captured. And no partition table is consulted at all: an image
/// that starts mid-filesystem has no table of its own to read.
fn open_image_head_absent(
    path: &std::path::Path,
    drivers: &DriverRegistry,
    head_absent: u64,
    best_effort_reads: bool,
    filesystem: &FilesystemOpenOptions,
) -> Result<OpenedImage, OpenImageError> {
    let detection_error = |source| OpenImageError::Detection {
        path: path.to_path_buf(),
        offset: 0,
        source,
    };
    let image = ImageReader::open(path)?;
    let format = image.format();
    let carried_bytes = image.len();
    let volume_bytes = head_absent.saturating_add(carried_bytes);
    let gapped = LeadingGapReader::new(image, head_absent).map_err(detection_error)?;

    // The tolerant wrapper goes on *before* detection, not after it as the
    // ordinary path does: with best-effort reads the absent head is zeros
    // from the first probe onwards, which is what lets a small gap — one
    // that stops short of the superblock at byte 1024 — still classify.
    let (mut source, substitutions): (Box<dyn DeviceReader>, Option<Arc<ReadSubstitutions>>) =
        if best_effort_reads {
            let (tolerant, stats) =
                TolerantReader::new(gapped, volume_bytes).map_err(detection_error)?;
            (Box::new(tolerant), Some(stats))
        } else {
            (Box::new(gapped), None)
        };

    let detected = match fsmnt_device::detect_boot_sector_within(&mut source, 0, volume_bytes) {
        Ok(detected) => detected,
        Err(error) if AbsentHead::in_error(&error).is_some() => DetectedBootSector::Unknown,
        Err(error) => return Err(detection_error(error)),
    };
    let detected = ext_backup::detection_with_backup_request(detected, filesystem);
    debug!(
        path = %path.display(),
        head_absent,
        carried_bytes,
        volume_bytes,
        detected = ?detected,
        best_effort_reads,
        "opening an image that begins inside its own filesystem"
    );
    if detected == DetectedBootSector::Unknown {
        return Err(OpenImageError::HeadAbsentPrimaryUnreadable {
            path: path.to_path_buf(),
            head_absent,
        });
    }

    let reader = PartitionReader::new(source, 0, volume_bytes);
    let opened = drivers
        .open_with_options(Box::new(reader), detected, filesystem)
        .map_err(|source| OpenImageError::Filesystem {
            path: path.to_path_buf(),
            offset: 0,
            detected,
            source,
        })?;
    let truncated_by = truncation::missing_filesystem_bytes(opened.total_size(), volume_bytes);
    Ok(OpenedImage {
        filesystem: opened,
        detected,
        offset: 0,
        size_bytes: volume_bytes,
        declared_size_bytes: volume_bytes,
        truncated_by,
        format,
        substitutions,
        // No table was read, and no scan was run: the caller stated where
        // the volume begins relative to the image, which is not a
        // provenance any layout can claim.
        layout_origin: None,
    })
}

/// Resolve *where* the filesystem is: a partition ordinal from the image's
/// own table (or from a scan of the media), or a byte offset the caller
/// named.
fn locate_image_window(
    path: &std::path::Path,
    partition: Option<usize>,
    offset: u64,
    sector_size: Option<u32>,
    scan_stride: Option<u64>,
) -> Result<layout::LocatedImagePartition, OpenImageError> {
    let located = if let Some(partition) = partition {
        let mut layout_options = ImageLayoutOptions::new();
        if let Some(sector_size) = sector_size {
            layout_options = layout_options.with_sector_size(sector_size);
        }
        if let Some(stride) = scan_stride {
            layout_options = layout_options.with_scan(true).with_scan_stride(stride);
        }
        layout::locate_image_partition(path, partition, layout_options)?
    } else {
        open_image_tail(path, offset)?
    };
    debug!(
        path = %path.display(),
        format = %located.image.format(),
        decoded_bytes = located.image.len(),
        partition = ?partition,
        origin = ?located.origin,
        offset = located.offset,
        declared_bytes = located.declared_bytes,
        available_bytes = located.available_bytes,
        "located the filesystem window inside the decoded image"
    );
    Ok(located)
}

/// Open the decoded media and take everything from `offset` to its end.
///
/// This is the no-partition path: without a partition table entry to bound
/// the filesystem, the rest of the image is all the extent there is — so
/// nothing of it can be missing.
fn open_image_tail(
    path: &std::path::Path,
    offset: u64,
) -> Result<layout::LocatedImagePartition, OpenImageError> {
    let image = ImageReader::open(path)?;
    let image_size = image.len();
    if offset >= image_size {
        return Err(OpenImageError::OffsetOutOfRange {
            path: path.to_path_buf(),
            offset,
            size_bytes: image_size,
        });
    }
    let available_bytes = image_size - offset;
    Ok(layout::LocatedImagePartition {
        image,
        offset,
        declared_bytes: available_bytes,
        available_bytes,
        origin: None,
    })
}

/// Turn a `DetectedBootSector::Unknown` at `offset` into the most useful
/// error the bytes around it allow — or `Ok(())` when there is nothing more
/// to say, in which case the caller lets the driver registry report "no
/// filesystem driver for Unknown".
///
/// Two ext situations are recognised. An ext *backup* superblock at the
/// offset (the offset came from a magic-number scan more often than not)
/// is reported with the group number and, from the copy's own geometry,
/// where the filesystem really starts. Failing that, a filesystem that does
/// start here but whose primary metadata is destroyed still has its own
/// group-1 backup one block group in, naming this offset as its start; that
/// is reported with the `--backup-superblock` way in.
fn explain_unknown(
    image: &mut ImageReader,
    path: &std::path::Path,
    offset: u64,
    available_bytes: u64,
) -> Result<(), OpenImageError> {
    let detection_error = |source| OpenImageError::Detection {
        path: path.to_path_buf(),
        offset,
        source,
    };
    if let Some(info) =
        fsmnt_device::ext_backup_superblock_info_at(image, offset).map_err(detection_error)?
    {
        return Err(OpenImageError::ExtBackupSuperblock {
            path: path.to_path_buf(),
            offset,
            group: info.group,
            filesystem_start: info.filesystem_start(offset),
        });
    }
    if let Some(backup_offset) = ext_backup::find_group_one_backup(image, offset, available_bytes)
        .map_err(detection_error)?
    {
        return Err(OpenImageError::ExtPrimaryDamaged {
            path: path.to_path_buf(),
            offset,
            group: 1,
            backup_offset,
        });
    }
    Ok(())
}
