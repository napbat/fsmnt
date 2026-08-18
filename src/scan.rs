//! Find filesystems anywhere in a decoded disk image.
//!
//! [`image_layout`](crate::image_layout) answers "what does the partition
//! table say?". This module answers the question that remains when there is
//! no partition table, when it is corrupt, or when it disagrees with the
//! media: *what is actually in these bytes?*
//!
//! [`scan_image`] reads the decoded media once, front to back, and
//! classifies every stride-aligned position with the same probes mounting
//! uses — so an offset it reports is an offset `mount-image --offset` can
//! open. Two things make the result readable rather than a wall of magic
//! numbers:
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

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use fsmnt_device::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_PROBE_SIZE, DetectedBootSector,
    FS_DETECT_PROBE_SIZE, ImageOpenError, ImageReader, ParsedBootSector, ext_superblock_info,
    is_btrfs_primary_superblock, parse_boot_sector,
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
    /// Byte offset in the decoded media. For a filesystem this is the offset
    /// to hand to `mount-image --offset`; for a backup superblock it is
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

/// The kind of structure a [`ScanHit`] identifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanHitKind {
    /// The start of a filesystem of this type.
    Filesystem(DetectedBootSector),
    /// A partition table, which describes filesystems rather than being one.
    PartitionTable(DetectedBootSector),
    /// An ext backup superblock whose primary was not found by this scan.
    ExtBackupSuperblock {
        /// Block group the copy belongs to.
        group: u16,
        /// Offset its filesystem would have started at, or `None` when that
        /// would fall before the start of the media (so the copy cannot
        /// belong to a filesystem inside this image).
        filesystem_start: Option<u64>,
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
    /// Reading the decoded media failed part-way through.
    #[error("failed to read {path:?} at offset {offset}: {source}")]
    Read {
        /// Image path supplied by the caller.
        path: PathBuf,
        /// Decoded-media offset the read started at.
        offset: u64,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// A stride of zero would test the same position forever.
    #[error("scan stride must be at least 1 byte")]
    ZeroStride,
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
    scan_media(&mut image, length, options).map_err(|error| match error {
        MediaScanError::ZeroStride => ScanError::ZeroStride,
        MediaScanError::Read { offset, source } => ScanError::Read {
            path: path.to_path_buf(),
            offset,
            source,
        },
    })
}

/// A failure from the reader-level scan, before it knows the image path.
#[derive(Debug)]
enum MediaScanError {
    ZeroStride,
    Read { offset: u64, source: std::io::Error },
}

/// Scan `length` bytes of `media`, one sequential pass.
fn scan_media(
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
    /// End of the furthest extent claimed by a filesystem already reported.
    covered_end: u64,
    /// Offsets of ext superblock copies already recorded, so a stride that
    /// tests both alignments does not report the same copy twice.
    seen_superblocks: Vec<u64>,
}

impl ScanState {
    /// Test one candidate position against every probe.
    fn classify(&mut self, chunk: &[u8], offset: usize, position: u64) {
        let window = chunk
            .get(offset..)
            .map(|rest| &rest[..rest.len().min(FS_DETECT_PROBE_SIZE)]);
        let Some(window) = window else {
            return;
        };

        if let Some(detected) = detect(chunk, offset, window) {
            self.record_detected(position, detected, window);
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
    fn record_detected(&mut self, position: u64, detected: DetectedBootSector, window: &[u8]) {
        let is_ext = detected == DetectedBootSector::Ext;
        if position < self.covered_end && !is_ext {
            return;
        }
        let size_bytes = declared_size(detected, window);
        if let Some(size) = size_bytes {
            self.covered_end = self.covered_end.max(position.saturating_add(size));
        }
        if is_ext {
            self.seen_superblocks.push(position.saturating_add(LEAD_IN));
        }
        let kind = if detected.is_partition_table() {
            ScanHitKind::PartitionTable(detected)
        } else {
            ScanHitKind::Filesystem(detected)
        };
        self.hits.push(ScanHit {
            offset: position,
            kind,
            size_bytes,
            backup_superblocks: Vec::new(),
        });
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

        let start = superblock_offset.checked_sub(info.copy_offset());
        if let Some(index) = start.and_then(|start| self.ext_filesystem_at(start)) {
            self.hits[index]
                .backup_superblocks
                .push(ExtBackupSuperblock {
                    offset: superblock_offset,
                    group: info.block_group_nr,
                });
            return;
        }
        self.hits.push(ScanHit {
            offset: superblock_offset,
            kind: ScanHitKind::ExtBackupSuperblock {
                group: info.block_group_nr,
                filesystem_start: start,
            },
            size_bytes: Some(info.size_bytes()),
            backup_superblocks: Vec::new(),
        });
    }

    /// Index of the ext filesystem hit that starts exactly at `offset`.
    fn ext_filesystem_at(&self, offset: u64) -> Option<usize> {
        self.hits.iter().position(|hit| {
            hit.offset == offset && hit.kind == ScanHitKind::Filesystem(DetectedBootSector::Ext)
        })
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
mod tests {
    use super::{
        DetectedBootSector, ExtBackupSuperblock, ScanHitKind, ScanOptions, ext_superblock_info,
        scan_media,
    };
    use std::io::Cursor;

    const IMAGE_SIZE: usize = 16 << 20;
    const FAT_OFFSET: u64 = 1 << 20;
    /// Sector count and sector size of the synthetic FAT12 volume.
    const FAT_SECTORS: u32 = 2880;
    const FAT_SECTOR_SIZE: u32 = 512;

    /// Write a minimal but valid FAT12 boot sector.
    fn write_fat(media: &mut [u8], offset: u64) {
        let offset = usize::try_from(offset).expect("offset fits");
        let sector = &mut media[offset..offset + 512];
        sector[0x00..0x03].copy_from_slice(&[0xeb, 0x3c, 0x90]);
        sector[0x03..0x0b].copy_from_slice(b"mkfs.fat");
        sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
        sector[0x0d] = 1;
        sector[0x0e..0x10].copy_from_slice(&1_u16.to_le_bytes());
        sector[0x10] = 2;
        sector[0x11..0x13].copy_from_slice(&224_u16.to_le_bytes());
        sector[0x13..0x15].copy_from_slice(&2880_u16.to_le_bytes());
        sector[0x15] = 0xf0;
        sector[0x16..0x18].copy_from_slice(&9_u16.to_le_bytes());
        sector[510..512].copy_from_slice(&[0x55, 0xaa]);
    }

    /// Geometry of a synthetic ext filesystem.
    struct Ext {
        block_size: u32,
        blocks_count: u32,
        blocks_per_group: u32,
        first_data_block: u32,
    }

    impl Ext {
        /// Byte offset of the group `group` superblock copy from the start.
        fn copy_offset(&self, group: u32) -> u64 {
            if group == 0 {
                return 1024;
            }
            u64::from(self.first_data_block + group * self.blocks_per_group)
                * u64::from(self.block_size)
        }

        fn size_bytes(&self) -> u64 {
            u64::from(self.blocks_count) * u64::from(self.block_size)
        }

        /// Write the group `group` superblock copy into `media`, for a
        /// filesystem starting at `start`.
        fn write(&self, media: &mut [u8], start: u64, group: u32) -> u64 {
            let offset = usize::try_from(start + self.copy_offset(group)).expect("offset");
            let sb = &mut media[offset..offset + 0x160];
            sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes()); // s_inodes_count
            sb[0x04..0x08].copy_from_slice(&self.blocks_count.to_le_bytes());
            sb[0x14..0x18].copy_from_slice(&self.first_data_block.to_le_bytes());
            let log = self.block_size.trailing_zeros() - 10;
            sb[0x18..0x1c].copy_from_slice(&log.to_le_bytes());
            sb[0x20..0x24].copy_from_slice(&self.blocks_per_group.to_le_bytes());
            sb[0x28..0x2c].copy_from_slice(&2048_u32.to_le_bytes()); // s_inodes_per_group
            sb[0x38..0x3a].copy_from_slice(&0xef53_u16.to_le_bytes());
            let group = u16::try_from(group).expect("group fits");
            sb[0x5a..0x5c].copy_from_slice(&group.to_le_bytes());
            start + self.copy_offset(u32::from(group))
        }
    }

    /// The 1 KiB-block filesystem used by most tests: its backups land 1024
    /// bytes past a 4 KiB boundary, so the scan finds them by probing the
    /// filesystem byte that precedes the copy.
    fn small_block_ext() -> Ext {
        Ext {
            block_size: 1024,
            blocks_count: 12288,
            blocks_per_group: 8192,
            first_data_block: 1,
        }
    }

    #[test]
    fn a_filesystem_and_its_backup_superblocks_are_found_and_folded() {
        let mut media = vec![0_u8; IMAGE_SIZE];
        write_fat(&mut media, FAT_OFFSET);
        let ext = small_block_ext();
        let start = 4 << 20;
        ext.write(&mut media, start, 0);
        let backup = ext.write(&mut media, start, 1);

        let length = u64::try_from(media.len()).expect("length");
        let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

        assert_eq!(hits.len(), 2, "{hits:#?}");
        assert_eq!(hits[0].offset, FAT_OFFSET);
        assert_eq!(
            hits[0].kind,
            ScanHitKind::Filesystem(DetectedBootSector::Fat12)
        );
        assert_eq!(
            hits[0].size_bytes,
            Some(u64::from(FAT_SECTORS) * u64::from(FAT_SECTOR_SIZE))
        );

        assert_eq!(hits[1].offset, start);
        assert_eq!(
            hits[1].kind,
            ScanHitKind::Filesystem(DetectedBootSector::Ext)
        );
        assert_eq!(hits[1].size_bytes, Some(ext.size_bytes()));
        assert_eq!(
            hits[1].backup_superblocks,
            vec![ExtBackupSuperblock {
                offset: backup,
                group: 1
            }],
            "the backup belongs to the primary, not to a hit of its own"
        );
    }

    #[test]
    fn a_backup_on_a_large_block_filesystem_is_found_at_its_own_offset() {
        // Groups start on a block boundary, so with 4 KiB blocks the copy
        // sits *at* a stride-aligned offset rather than 1024 past one.
        let ext = Ext {
            block_size: 4096,
            blocks_count: 2048,
            blocks_per_group: 1024,
            first_data_block: 0,
        };
        let mut media = vec![0_u8; IMAGE_SIZE];
        let start = 1 << 20;
        ext.write(&mut media, start, 0);
        let backup = ext.write(&mut media, start, 1);
        assert_eq!(backup % 4096, 0, "the copy is stride-aligned itself");

        let length = u64::try_from(media.len()).expect("length");
        let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(hits[0].offset, start);
        assert_eq!(
            hits[0].backup_superblocks,
            vec![ExtBackupSuperblock {
                offset: backup,
                group: 1
            }]
        );
    }

    #[test]
    fn a_backup_without_its_primary_names_the_start_it_implies() {
        let ext = small_block_ext();
        let mut media = vec![0_u8; IMAGE_SIZE];
        let start = 4 << 20;
        let backup = ext.write(&mut media, start, 1);

        let length = u64::try_from(media.len()).expect("length");
        let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(hits[0].offset, backup);
        assert_eq!(
            hits[0].kind,
            ScanHitKind::ExtBackupSuperblock {
                group: 1,
                filesystem_start: Some(start),
            }
        );
        assert_eq!(hits[0].size_bytes, Some(ext.size_bytes()));
    }

    #[test]
    fn a_finer_stride_does_not_report_the_same_superblock_twice() {
        let ext = small_block_ext();
        let mut media = vec![0_u8; IMAGE_SIZE];
        let start = 4 << 20;
        ext.write(&mut media, start, 0);
        ext.write(&mut media, start, 1);

        let length = u64::try_from(media.len()).expect("length");
        let options = ScanOptions::new().with_stride(512);
        let hits = scan_media(&mut Cursor::new(media), length, options).expect("scan");

        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(hits[0].backup_superblocks.len(), 1, "{hits:#?}");
    }

    #[test]
    fn boot_sectors_inside_a_sized_filesystem_are_not_reported() {
        let ext = Ext {
            block_size: 1024,
            blocks_count: 16384,
            blocks_per_group: 8192,
            first_data_block: 1,
        };
        let mut media = vec![0_u8; IMAGE_SIZE];
        ext.write(&mut media, 0, 0);
        // File data that happens to look like a FAT boot sector.
        write_fat(&mut media, 8 << 20);

        let length = u64::try_from(media.len()).expect("length");
        let hits = scan_media(&mut Cursor::new(media), length, ScanOptions::new()).expect("scan");

        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(
            hits[0].kind,
            ScanHitKind::Filesystem(DetectedBootSector::Ext)
        );
        assert_eq!(hits[0].size_bytes, Some(ext.size_bytes()));
    }

    #[test]
    fn a_zero_stride_is_refused_rather_than_looping() {
        let options = ScanOptions::new().with_stride(0);
        let result = scan_media(&mut Cursor::new(vec![0_u8; 4096]), 4096, options);
        assert!(result.is_err());
    }

    #[test]
    fn empty_media_produces_no_hits() {
        let hits =
            scan_media(&mut Cursor::new(Vec::new()), 0, ScanOptions::new()).expect("empty scan");
        assert!(hits.is_empty());
    }

    #[test]
    fn superblock_geometry_matches_the_synthetic_layout() {
        let ext = small_block_ext();
        let mut media = vec![0_u8; 1 << 20];
        ext.write(&mut media, 0, 0);
        let info = ext_superblock_info(&media).expect("primary superblock");
        assert!(info.is_primary());
        assert_eq!(info.size_bytes(), ext.size_bytes());
        assert_eq!(info.copy_offset(), 1024);
    }
}
