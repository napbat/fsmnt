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

use fsmnt_core::{FsError, TargetFilesystem};
use fsmnt_device::{
    DetectedBootSector, DriverRegistry, FilesystemOpenOptions, FilesystemRoot, ImageFormat,
    ImageOpenError, ImageReader, PartitionReader,
};

use crate::image_layout::{self, ImageLayoutOptions};
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
    /// carry, or `None` when it fits (see [`missing_filesystem_bytes`]).
    ///
    /// A filesystem whose superblock is present but whose data is not opens
    /// normally and then fails one read at a time; this states up front how
    /// much of it is missing.
    pub truncated_by: Option<u64>,
    /// Container format used to expose the decoded media.
    pub format: ImageFormat,
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
        "offset {offset} in {path:?} holds an ext backup superblock (block group {group}), not the start of a filesystem; the primary lies earlier — list partitions with `fsmnt partitions {}`",
        path.display()
    )]
    ExtBackupSuperblock {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset that holds the backup copy.
        offset: u64,
        /// Block group the backup superblock belongs to.
        group: u16,
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

/// Location and filesystem-root choices for opening a disk image.
#[derive(Clone, Debug)]
pub struct ImageOpenOptions {
    offset: u64,
    partition: Option<usize>,
    sector_size: Option<u32>,
    filesystem: FilesystemOpenOptions,
}

impl ImageOpenOptions {
    /// Use the beginning of the decoded image and the filesystem's default
    /// root.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            offset: 0,
            partition: None,
            sector_size: None,
            filesystem: FilesystemOpenOptions::new(),
        }
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

    /// Select a partition of the image by its ordinal, counting non-empty
    /// partition-table entries from 0 — the same numbering
    /// [`image_layout`] prints and `mount-device --partition` uses.
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
    /// [`ImageLayout::sector_size_auto_detected`]).
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

    /// Replace every filesystem-level option (root selector, journal replay)
    /// with `filesystem` at once.
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
/// partition's extent; [`image_layout`] lists the ordinals. Without a
/// partition the offset is used as-is, addressing decoded logical media
/// rather than EWF segment bytes or VHD/VHDX container storage, and the
/// filesystem spans the rest of the image.
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
        partition,
        sector_size,
        filesystem,
    } = options;
    let image_layout::LocatedImagePartition {
        mut image,
        offset,
        declared_bytes,
        available_bytes,
    } = if let Some(partition) = partition {
        let mut layout_options = ImageLayoutOptions::new();
        if let Some(sector_size) = sector_size {
            layout_options = layout_options.with_sector_size(sector_size);
        }
        image_layout::locate_image_partition(path, partition, layout_options)?
    } else {
        open_image_tail(path, offset)?
    };

    let detected = fsmnt_device::detect_boot_sector_at(&mut image, offset).map_err(|source| {
        OpenImageError::Detection {
            path: path.to_path_buf(),
            offset,
            source,
        }
    })?;
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
        // Detection refuses ext backup superblocks; say so precisely rather
        // than "no filesystem driver for Unknown" — the offset came from a
        // magic-number scan more often than not, and the group number tells
        // the user how far back the real start is.
        let backup =
            fsmnt_device::ext_backup_superblock_at(&mut image, offset).map_err(|source| {
                OpenImageError::Detection {
                    path: path.to_path_buf(),
                    offset,
                    source,
                }
            })?;
        if let Some(group) = backup {
            return Err(OpenImageError::ExtBackupSuperblock {
                path: path.to_path_buf(),
                offset,
                group,
            });
        }
    }

    let format = image.format();
    let reader = PartitionReader::new(image, offset, available_bytes);
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
    })
}

/// Open the decoded media and take everything from `offset` to its end.
///
/// This is the no-partition path: without a partition table entry to bound
/// the filesystem, the rest of the image is all the extent there is — so
/// nothing of it can be missing.
fn open_image_tail(
    path: &std::path::Path,
    offset: u64,
) -> Result<image_layout::LocatedImagePartition, OpenImageError> {
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
    Ok(image_layout::LocatedImagePartition {
        image,
        offset,
        declared_bytes: available_bytes,
        available_bytes,
    })
}
