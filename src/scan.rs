//! Find filesystems anywhere in a medium, wherever they sit.
//!
//! [`image_layout`](crate::image_layout) and
//! [`drive_layout`](crate::drive_layout) answer "what does the partition
//! table say?". This module answers the question that remains when there is
//! no partition table, when it is corrupt, or when it disagrees with the
//! media: *what is actually in these bytes?*
//!
//! [`scan_image`] reads the decoded media once, front to back, and
//! classifies every stride-aligned position with the same probes mounting
//! uses — so an offset it reports is an offset `fsmnt mount SOURCE --offset`
//! can open. [`scan_drive`] does the same for a live drive, and
//! [`scan_media`] for anything else that reads and seeks. Two things make
//! the result readable rather than a wall of magic numbers:
//!
//! - **Backup superblocks are folded into their primary.** An ext filesystem
//!   scatters superblock copies through itself; each one carries the block
//!   group it belongs to, which is enough to compute where its filesystem
//!   began. A copy whose primary was found is listed as corroboration for
//!   that hit; a copy whose primary was *not* found is reported on its own,
//!   naming the offset the filesystem would have started at — which is the
//!   offset worth trying when the front of a partition has been overwritten.
//! - **Hits inside a filesystem of known size are suppressed**, so a 3 GB
//!   ext partition does not report every stray `0xAA55` in its file data.
//!   Ext superblocks are exempt: a superblock inside another filesystem's
//!   claimed extent is evidence that the extent is wrong, which is exactly
//!   what a scan is for.
//! - **Evidence is corroborated before it is called a filesystem.** A
//!   magic number is a few bytes and a scan of a large medium meets plenty
//!   of them by chance, or in file data that once *was* filesystem metadata.
//!   So an ext primary superblock counts as a start only when the group
//!   descriptor table that must follow it is there (see
//!   [`ext_start_check`]), and a `55 AA` counts as a partition table only
//!   when its four entries describe extents a partitioner could have written
//!   (see [`Mbr::is_plausible_table`]). What fails those tests is still
//!   reported — as what it actually is, folded into one line.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tracing::debug;

use fsmnt_device::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_PROBE_SIZE, DetectedBootSector,
    ExtStartCheck, FS_DETECT_PROBE_SIZE, HostDriveEnumerator, HostDriveError, HostDriveId,
    ImageOpenError, ImageReader, Mbr, ParsedBootSector, SectorReader, ext_start_check,
    ext_superblock_info, is_btrfs_primary_superblock, parse_boot_sector,
};

/// Default distance between candidate positions.
///
/// Filesystems are laid down on a block boundary, and 4 KiB is the largest
/// alignment every common one shares. `--stride 512` finds the rest at eight
/// times the work.
pub const DEFAULT_STRIDE: u64 = 4096;

/// How much media is read at a time. Large enough that the scan is one
/// sequential pass rather than a seek per candidate position.
const CHUNK_SIZE: usize = 64 << 20;

/// Bytes read *before* the first position of each chunk, so a superblock
/// sitting at the position itself can be probed with the 1024 bytes of
/// filesystem that would precede it.
const LEAD_IN: u64 = 1024;

/// Options for [`scan_image_with_options`].
#[derive(Clone, Copy, Debug)]
pub struct ScanOptions {
    stride: u64,
}

impl ScanOptions {
    /// Scan every [`DEFAULT_STRIDE`]-aligned position.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stride: DEFAULT_STRIDE,
        }
    }

    /// Test positions every `stride` bytes instead.
    #[must_use]
    pub const fn with_stride(mut self, stride: u64) -> Self {
        self.stride = stride;
        self
    }

    /// Distance between candidate positions.
    #[must_use]
    pub const fn stride(&self) -> u64 {
        self.stride
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// What a scan found at one offset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanHit {
    /// Byte offset in the medium. For a filesystem this is the offset to
    /// hand to `fsmnt mount SOURCE --offset`; for a backup superblock it is
    /// where the copy itself sits, not where its filesystem starts.
    pub offset: u64,
    /// What the bytes at `offset` are.
    pub kind: ScanHitKind,
    /// Size the structure claims for its filesystem, where the format states
    /// one. Not a measurement — a truncated image reports the size the
    /// superblock was written with.
    pub size_bytes: Option<u64>,
    /// Backup superblocks found inside this filesystem, in offset order.
    /// Only ever populated for an ext filesystem hit.
    pub backup_superblocks: Vec<ExtBackupSuperblock>,
}

impl ScanHit {
    /// The offset `fsmnt mount SOURCE --offset` would take for this hit, if
    /// it is mountable at all.
    ///
    /// A partition table is not mountable, and a stray backup superblock is
    /// mountable only at the filesystem start it implies — never at its own
    /// offset, which the ext driver refuses on purpose. Superblock copies
    /// that no backup corroborates are not mountable either: nothing says a
    /// filesystem begins where they sit.
    #[must_use]
    pub fn mount_offset(&self) -> Option<u64> {
        match self.kind {
            ScanHitKind::Filesystem(_) => Some(self.offset),
            ScanHitKind::ExtBackupSuperblock {
                filesystem_start, ..
            } => filesystem_start,
            ScanHitKind::ExtPrimaryCopies { .. } => {
                (!self.backup_superblocks.is_empty()).then_some(self.offset)
            }
            ScanHitKind::PartitionTable(_) => None,
        }
    }
}

/// The hits a scan numbers for `fsmnt mount SOURCE --scan --partition N`:
/// every hit with a [`mount_offset`](ScanHit::mount_offset), in scan order.
///
/// The number is **synthetic** — it comes from this scan of this medium with
/// these options, not from any partition table on it — so it holds only for
/// the same medium scanned with the same stride. It is a convenience over
/// pasting the offset, not an identity of the volume.
///
/// Evidence a scan cannot act on is deliberately absent: a partition table,
/// a backup superblock whose filesystem starts before this medium, and a
/// superblock copy nothing corroborates all appear in the hit list and none
/// of them gets a number, because there is no offset to hand a mount.
#[must_use]
pub fn mountable_hits(hits: &[ScanHit]) -> Vec<&ScanHit> {
    hits.iter()
        .filter(|hit| hit.mount_offset().is_some())
        .collect()
}

/// The kind of structure a [`ScanHit`] identifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanHitKind {
    /// The start of a filesystem of this type.
    Filesystem(DetectedBootSector),
    /// A partition table, which describes filesystems rather than being one.
    PartitionTable(DetectedBootSector),
    /// Backup superblock(s) of an ext filesystem whose primary this scan did
    /// not confirm.
    ///
    /// [`ScanHit::offset`] is the first copy; the other copies of the same
    /// filesystem that agree on the start are in
    /// [`ScanHit::backup_superblocks`].
    ExtBackupSuperblock {
        /// Block group the first copy belongs to.
        group: u16,
        /// Offset its filesystem would have started at, or `None` when that
        /// would fall before the start of the media.
        filesystem_start: Option<u64>,
        /// Bytes by which the implied start precedes the medium — the medium
        /// is a slice that begins inside the filesystem. `Some` exactly when
        /// `filesystem_start` is `None`.
        start_before_medium: Option<u64>,
    },
    /// Copies of an ext primary superblock (group 0) that are NOT followed by
    /// their group descriptor table: block 0 journalled inside a filesystem,
    /// or a start whose table is damaged.
    ///
    /// [`ScanHit::offset`] is the first, `last_offset` the last, `copies` how
    /// many. Backups that name `offset` as their filesystem's start land in
    /// [`ScanHit::backup_superblocks`], and only then is the hit mountable.
    ExtPrimaryCopies {
        /// How many copies were folded into this one hit.
        copies: usize,
        /// Offset of the last copy, so the run's extent is on record.
        last_offset: u64,
    },
}

/// An ext superblock copy found inside a filesystem the scan also located.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtBackupSuperblock {
    /// Byte offset of the copy in the decoded media.
    pub offset: u64,
    /// Block group it belongs to.
    pub group: u16,
}

/// Why a scan could not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScanError {
    /// The image container could not be opened or decoded.
    #[error(transparent)]
    Container(#[from] ImageOpenError),
    /// The drive could not be opened or queried.
    #[error(transparent)]
    Drive(#[from] HostDriveError),
    /// The drive's length is unknown, so there is nothing to scan *to*.
    ///
    /// Unlike an image file, a drive has no length of its own to fall back
    /// on: if the operating system will not say how large it is and seeking
    /// to its end does not either, a scan cannot know when to stop.
    #[error(
        "drive {drive} did not report a size, and a scan has to know how far the media runs; \
         image the drive and scan the image instead"
    )]
    UnknownDriveSize {
        /// Drive that would not state its size.
        drive: HostDriveId,
    },
    /// Reading the media failed part-way through.
    #[error("failed to read {path:?} at offset {offset}: {source}")]
    Read {
        /// Image path supplied by the caller, or the drive's device path.
        path: PathBuf,
        /// Media offset the read started at.
        offset: u64,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// A stride of zero would test the same position forever.
    #[error("scan stride must be at least 1 byte")]
    ZeroStride,
}

impl ScanError {
    /// Attach the medium's identity to a reader-level failure.
    fn from_media(error: MediaScanError, path: &Path) -> Self {
        match error {
            MediaScanError::ZeroStride => Self::ZeroStride,
            MediaScanError::Read { offset, source } => Self::Read {
                path: path.to_path_buf(),
                offset,
                source,
            },
        }
    }
}

/// Scan a raw, EWF, VHD, or VHDX image for filesystem starts.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, or if reading
/// its decoded media fails.
pub fn scan_image(path: impl AsRef<Path>) -> Result<Vec<ScanHit>, ScanError> {
    scan_image_with_options(path, ScanOptions::new())
}

/// Scan an image with an explicit stride.
///
/// # Errors
///
/// Returns an error if the stride is zero, the image cannot be opened or
/// decoded, or reading its decoded media fails.
pub fn scan_image_with_options(
    path: impl AsRef<Path>,
    options: ScanOptions,
) -> Result<Vec<ScanHit>, ScanError> {
    let path = path.as_ref();
    let mut image = ImageReader::open(path)?;
    let length = image.len();
    scan_media(&mut image, length, options).map_err(|error| ScanError::from_media(error, path))
}

/// Scan a physical drive for filesystem starts.
///
/// The counterpart to [`scan_image`] for a live drive: a drive whose
/// partition table was wiped and an image of one are the same forensic
/// situation, so both are searched the same way and report the same offsets.
/// Reads go through a sector-aligning view, because raw block-device handles
/// reject reads that are not whole sectors.
///
/// The enumerator type parameter selects the platform: on Windows, Linux,
/// and macOS, use [`HostDrives`](crate::HostDrives).
///
/// # Errors
///
/// Returns an error if the stride is zero, the drive cannot be opened, its
/// size is unknown, or reading it fails part-way through.
pub fn scan_drive<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    options: ScanOptions,
) -> Result<Vec<ScanHit>, ScanError> {
    let info = E::get_drive_info(drive).ok();
    let mut reader = E::open_drive(drive)?;
    let length = crate::layout::drive_length(info.as_ref(), &mut reader).ok_or_else(|| {
        ScanError::UnknownDriveSize {
            drive: drive.clone(),
        }
    })?;
    let sector_size = info
        .as_ref()
        .and_then(|info| info.sector_size)
        .filter(|size| size.is_power_of_two())
        .unwrap_or(crate::layout::DEFAULT_SECTOR_SIZE);
    let path = info.map_or_else(|| PathBuf::from(drive.as_str()), |info| info.path);
    // The readable length has to be a whole number of sectors; a drive whose
    // reported size is not is reported as the sectors it does hold.
    let aligned = length - length % u64::from(sector_size);
    let mut media =
        SectorReader::new(reader, aligned, sector_size).map_err(|source| ScanError::Read {
            path: path.clone(),
            offset: 0,
            source,
        })?;
    scan_media(&mut media, aligned, options).map_err(|error| ScanError::from_media(error, &path))
}

/// Why a scan of an unnamed medium could not complete.
///
/// [`scan_media`] knows how far the media runs but not what it is called, so
/// its failures carry an offset and leave naming the medium to the caller —
/// which is how [`scan_image`] can say *which* image failed to read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MediaScanError {
    /// A stride of zero would test the same position forever.
    #[error("scan stride must be at least 1 byte")]
    ZeroStride,
    /// Reading the media failed part-way through.
    #[error("failed to read the media at offset {offset}: {source}")]
    Read {
        /// Media offset the read started at.
        offset: u64,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
}

/// Scan `length` bytes of `media` for filesystem starts, in one sequential
/// pass.
///
/// The engine behind [`scan_image`] and [`scan_drive`], exposed for media
/// that are neither: a decrypted container, an in-memory carve, a reader
/// from another crate. `length` bounds the search — reads past it are never
/// attempted, and a short read simply ends the scan.
///
/// # Errors
///
/// Returns an error if the stride is zero or reading the media fails.
pub fn scan_media(
    media: &mut (impl Read + Seek),
    length: u64,
    options: ScanOptions,
) -> Result<Vec<ScanHit>, MediaScanError> {
    if options.stride == 0 {
        return Err(MediaScanError::ZeroStride);
    }
    let mut state = ScanState::default();
    let probe_tail = probe_tail();
    let mut buffer = vec![0_u8; chunk_capacity(length, probe_tail, options.stride)];
    let mut position = 0_u64;

    while position < length {
        let read_at = position.saturating_sub(LEAD_IN);
        let filled =
            read_chunk(media, read_at, &mut buffer).map_err(|source| MediaScanError::Read {
                offset: read_at,
                source,
            })?;
        if filled == 0 {
            break;
        }
        let chunk_end = read_at.saturating_add(u64::try_from(filled).unwrap_or(u64::MAX));
        debug!(
            start = read_at,
            end = chunk_end,
            length,
            "read a chunk of the media to classify"
        );
        // Positions whose probe window runs past the bytes in hand are left
        // for the next chunk — unless there is no next chunk, in which case
        // a short window is all there will ever be.
        let last_position = if chunk_end >= length {
            length
        } else {
            chunk_end.saturating_sub(probe_tail)
        };
        if last_position <= position {
            break;
        }
        while position < last_position {
            let Ok(offset) = usize::try_from(position - read_at) else {
                break;
            };
            state.classify(&buffer[..filled], offset, position);
            position = position.saturating_add(options.stride);
        }
    }

    Ok(state.into_hits())
}

/// Bytes past a candidate position every probe together needs: the Btrfs
/// superblock sits 64 KiB in, further than any other.
fn probe_tail() -> u64 {
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET
        .saturating_add(u64::try_from(BTRFS_SUPERBLOCK_PROBE_SIZE).unwrap_or(u64::MAX))
}

/// Read buffer size: [`CHUNK_SIZE`], or the whole of a smaller image, but
/// never so small that a chunk cannot advance past its own probe tail.
fn chunk_capacity(length: u64, probe_tail: u64, stride: u64) -> usize {
    let minimum = LEAD_IN
        .saturating_add(probe_tail)
        .saturating_add(stride.max(1));
    let wanted = length.saturating_add(LEAD_IN).max(minimum);
    usize::try_from(wanted)
        .unwrap_or(CHUNK_SIZE)
        .min(CHUNK_SIZE)
}

/// Fill `buffer` from `offset`, tolerating a short read at end of media.
fn read_chunk(
    media: &mut (impl Read + Seek),
    offset: u64,
    buffer: &mut [u8],
) -> std::io::Result<usize> {
    media.seek(SeekFrom::Start(offset))?;
    let mut filled = 0;
    while filled < buffer.len() {
        match media.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Hits gathered so far, plus what is needed to fold and filter new ones.
#[derive(Default)]
struct ScanState {
    hits: Vec<ScanHit>,
    /// The ext filesystem UUID behind each hit, in step with `hits`.
    ///
    /// A `ScanHit` carries no identity of its own, and identity is what
    /// decides whether a superblock copy belongs to a filesystem already
    /// found or announces a different one.
    uuids: Vec<Option<[u8; 16]>>,
    /// End of the furthest extent claimed by a filesystem already reported.
    covered_end: u64,
    /// Offsets of ext superblock copies already recorded, so a stride that
    /// tests both alignments does not report the same copy twice.
    seen_superblocks: Vec<u64>,
}

impl ScanState {
    /// Test one candidate position against every probe.
    fn classify(&mut self, chunk: &[u8], offset: usize, position: u64) {
        let Some(tail) = chunk.get(offset..) else {
            return;
        };
        let window = &tail[..tail.len().min(FS_DETECT_PROBE_SIZE)];

        if let Some(detected) = detect(chunk, offset, window) {
            self.record_detected(position, detected, window, tail);
        }

        // An ext superblock lies 1024 bytes into its filesystem, so a copy
        // is found either by probing the filesystem byte that precedes it
        // (a primary, and a backup on a 1 KiB-block filesystem) or by
        // probing the copy's own offset (every backup on a filesystem with
        // larger blocks, which start their groups on a block boundary).
        self.record_backup(position.saturating_add(LEAD_IN), window);
        if let Some(lead_in) = offset.checked_sub(usize::try_from(LEAD_IN).unwrap_or(usize::MAX))
            && position >= LEAD_IN
        {
            let shifted = &chunk[lead_in..];
            self.record_backup(
                position,
                &shifted[..shifted.len().min(FS_DETECT_PROBE_SIZE)],
            );
        }
    }

    /// Record a filesystem or partition table found at `position`.
    ///
    /// `window` is the detection prefix; `tail` runs from `position` to the
    /// end of the chunk, which reaches past the group descriptor table of
    /// even a 64 KiB-block ext filesystem.
    fn record_detected(
        &mut self,
        position: u64,
        detected: DetectedBootSector,
        window: &[u8],
        tail: &[u8],
    ) {
        let is_ext = detected == DetectedBootSector::Ext;
        if position < self.covered_end && !is_ext {
            return;
        }
        if detected.is_partition_table() && !is_plausible_partition_table(window) {
            debug!(
                offset = position,
                ?detected,
                "skipped a boot signature whose four entries are not a partition table"
            );
            return;
        }
        let size_bytes = declared_size(detected, window);
        // A copy of a superblock sits *inside* the filesystem it describes,
        // so its declared size still marks bytes that are file data rather
        // than filesystem starts — the suppression is right either way.
        if let Some(size) = size_bytes {
            self.covered_end = self.covered_end.max(position.saturating_add(size));
        }
        if is_ext {
            self.seen_superblocks.push(position.saturating_add(LEAD_IN));
            let uuid = ext_superblock_info(window).map(|info| info.uuid);
            if ext_start_check(tail) == ExtStartCheck::Unconfirmed {
                self.record_primary_copy(position, size_bytes, uuid);
                return;
            }
            self.push_hit(
                ScanHit {
                    offset: position,
                    kind: ScanHitKind::Filesystem(detected),
                    size_bytes,
                    backup_superblocks: Vec::new(),
                },
                uuid,
            );
            return;
        }
        let kind = if detected.is_partition_table() {
            ScanHitKind::PartitionTable(detected)
        } else {
            ScanHitKind::Filesystem(detected)
        };
        self.push_hit(
            ScanHit {
                offset: position,
                kind,
                size_bytes,
                backup_superblocks: Vec::new(),
            },
            None,
        );
    }

    /// Record a group-0 superblock at `position` that its own bytes cannot
    /// establish as a filesystem start.
    ///
    /// One journalled transaction produces one such copy, and a busy
    /// filesystem has journalled block 0 dozens of times, so the copies are
    /// folded into a single run rather than listed one per line.
    fn record_primary_copy(
        &mut self,
        position: u64,
        size_bytes: Option<u64>,
        uuid: Option<[u8; 16]>,
    ) {
        if self.inside_ext_filesystem(position, uuid) {
            debug!(
                offset = position,
                "dropped a copy of a primary superblock lying inside its own filesystem — the \
                 journal recorded block 0, this is not a second filesystem"
            );
            return;
        }
        if self.last_hit_is_primary_copies(uuid)
            && let Some(hit) = self.hits.last_mut()
            && let ScanHitKind::ExtPrimaryCopies {
                copies,
                last_offset,
            } = &mut hit.kind
        {
            *copies += 1;
            *last_offset = position;
            return;
        }
        self.push_hit(
            ScanHit {
                offset: position,
                kind: ScanHitKind::ExtPrimaryCopies {
                    copies: 1,
                    last_offset: position,
                },
                size_bytes,
                backup_superblocks: Vec::new(),
            },
            uuid,
        );
    }

    /// Record an ext backup superblock sitting at `superblock_offset`, whose
    /// bytes start 1024 into `window`.
    fn record_backup(&mut self, superblock_offset: u64, window: &[u8]) {
        let Some(info) = ext_superblock_info(window) else {
            return;
        };
        if info.is_primary() || self.seen_superblocks.contains(&superblock_offset) {
            return;
        }
        self.seen_superblocks.push(superblock_offset);

        // The implied start is a signed quantity: an image cut out of the
        // middle of a filesystem carries backups whose arithmetic lands
        // before byte zero, and by how much is exactly what says "this
        // medium begins inside a filesystem".
        let start = superblock_offset.checked_sub(info.copy_offset());
        let start_before_medium = start
            .is_none()
            .then(|| info.copy_offset().saturating_sub(superblock_offset));
        let copy = ExtBackupSuperblock {
            offset: superblock_offset,
            group: info.block_group_nr,
        };

        let corroborates = start
            .and_then(|start| self.ext_filesystem_at(start))
            .or_else(|| start.and_then(|start| self.ext_primary_copies_at(start, info.uuid)))
            .or_else(|| self.ext_orphan_implying(info.uuid, start, start_before_medium));
        if let Some(index) = corroborates {
            self.hits[index].backup_superblocks.push(copy);
            return;
        }
        self.push_hit(
            ScanHit {
                offset: superblock_offset,
                kind: ScanHitKind::ExtBackupSuperblock {
                    group: info.block_group_nr,
                    filesystem_start: start,
                    start_before_medium,
                },
                size_bytes: Some(info.size_bytes()),
                backup_superblocks: Vec::new(),
            },
            Some(info.uuid),
        );
    }

    /// Add a hit and the filesystem identity that goes with it.
    fn push_hit(&mut self, hit: ScanHit, uuid: Option<[u8; 16]>) {
        self.hits.push(hit);
        self.uuids.push(uuid);
    }

    /// Index of the ext filesystem hit that starts exactly at `offset`.
    fn ext_filesystem_at(&self, offset: u64) -> Option<usize> {
        self.hits.iter().position(|hit| {
            hit.offset == offset && hit.kind == ScanHitKind::Filesystem(DetectedBootSector::Ext)
        })
    }

    /// Index of a run of superblock copies that begins at `offset` and
    /// belongs to the filesystem `uuid` names — the damaged-primary case,
    /// where a backup vouches for a start the descriptor table could not.
    fn ext_primary_copies_at(&self, offset: u64, uuid: [u8; 16]) -> Option<usize> {
        self.hits
            .iter()
            .zip(&self.uuids)
            .position(|(hit, hit_uuid)| {
                hit.offset == offset
                    && matches!(hit.kind, ScanHitKind::ExtPrimaryCopies { .. })
                    && *hit_uuid == Some(uuid)
            })
    }

    /// Index of an orphan backup hit for the same filesystem that implies the
    /// same start, so the copies of one lost filesystem stay on one line.
    fn ext_orphan_implying(
        &self,
        uuid: [u8; 16],
        start: Option<u64>,
        before: Option<u64>,
    ) -> Option<usize> {
        self.hits
            .iter()
            .zip(&self.uuids)
            .position(|(hit, hit_uuid)| {
                *hit_uuid == Some(uuid)
                    && matches!(
                        hit.kind,
                        ScanHitKind::ExtBackupSuperblock {
                            filesystem_start,
                            start_before_medium,
                            ..
                        } if filesystem_start == start && start_before_medium == before
                    )
            })
    }

    /// Whether `position` falls inside the extent claimed by an ext
    /// filesystem this scan already confirmed and identified as `uuid`.
    fn inside_ext_filesystem(&self, position: u64, uuid: Option<[u8; 16]>) -> bool {
        uuid.is_some()
            && self.hits.iter().zip(&self.uuids).any(|(hit, hit_uuid)| {
                *hit_uuid == uuid
                    && hit.kind == ScanHitKind::Filesystem(DetectedBootSector::Ext)
                    && position >= hit.offset
                    && position < hit.offset.saturating_add(hit.size_bytes.unwrap_or(0))
            })
    }

    /// Whether the most recent hit is a run of copies of the same
    /// filesystem's primary superblock, and so can absorb another.
    fn last_hit_is_primary_copies(&self, uuid: Option<[u8; 16]>) -> bool {
        uuid.is_some()
            && self.uuids.last().copied().flatten() == uuid
            && self
                .hits
                .last()
                .is_some_and(|hit| matches!(hit.kind, ScanHitKind::ExtPrimaryCopies { .. }))
    }

    /// The hits in offset order.
    fn into_hits(self) -> Vec<ScanHit> {
        let mut hits = self.hits;
        hits.sort_by_key(|hit| hit.offset);
        hits
    }
}

/// Classify the bytes at `offset`, including the Btrfs superblock that sits
/// 64 KiB further into the chunk.
fn detect(chunk: &[u8], offset: usize, window: &[u8]) -> Option<DetectedBootSector> {
    let detected = DetectedBootSector::from_bytes(window);
    if detected != DetectedBootSector::Unknown {
        return Some(detected);
    }
    let superblock = usize::try_from(BTRFS_PRIMARY_SUPERBLOCK_OFFSET)
        .ok()
        .and_then(|relative| offset.checked_add(relative))
        .and_then(|start| chunk.get(start..))?;
    is_btrfs_primary_superblock(superblock).then_some(DetectedBootSector::Btrfs)
}

/// Whether the sector at the start of `window` is a partition table rather
/// than data that happens to end in `55 AA`.
///
/// Mount-time parsing stays lenient — a damaged table is still a table, and
/// refusing to read it would lose the partitions it does describe — but a
/// scan meets a stray boot signature every few megabytes of file data, and
/// each one it believes is a row an examiner has to rule out by hand.
fn is_plausible_partition_table(window: &[u8]) -> bool {
    Mbr::from_bytes(window).is_some_and(Mbr::is_plausible_table)
}

/// The size the structure at the start of `window` claims for its
/// filesystem, where the format records one.
fn declared_size(detected: DetectedBootSector, window: &[u8]) -> Option<u64> {
    match detected {
        DetectedBootSector::Ext => ext_superblock_info(window).map(|info| info.size_bytes()),
        DetectedBootSector::Ntfs
        | DetectedBootSector::BitLocker
        | DetectedBootSector::Fat12
        | DetectedBootSector::Fat16
        | DetectedBootSector::Fat32
        | DetectedBootSector::ExFat => boot_sector_size(window),
        _ => None,
    }
}

/// Volume size from a DOS-family boot sector.
fn boot_sector_size(window: &[u8]) -> Option<u64> {
    let volume = match parse_boot_sector(window).ok()? {
        ParsedBootSector::Ntfs { bpb, ebpb, .. } => (
            ebpb.total_sectors.get(),
            u32::from(bpb.bytes_per_sector.get()),
        ),
        ParsedBootSector::BitLocker {
            bpb, total_sectors, ..
        } => (total_sectors, u32::from(bpb.bytes_per_sector.get())),
        ParsedBootSector::Fat12 { bpb, .. }
        | ParsedBootSector::Fat16 { bpb, .. }
        | ParsedBootSector::Fat32 { bpb, .. } => (
            u64::from(bpb.total_sectors()),
            u32::from(bpb.bytes_per_sector.get()),
        ),
        ParsedBootSector::ExFat { boot_sector } => (
            boot_sector.volume_length.get(),
            boot_sector.bytes_per_sector(),
        ),
        ParsedBootSector::Hpfs { .. }
        | ParsedBootSector::Mbr { .. }
        | ParsedBootSector::Gpt { .. } => return None,
    };
    let (sectors, bytes_per_sector) = volume;
    let size = sectors.checked_mul(u64::from(bytes_per_sector))?;
    (size > 0).then_some(size)
}

#[cfg(test)]
mod tests;
