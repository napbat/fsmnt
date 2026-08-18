//! Opening an ext volume from the backup copy of its metadata.
//!
//! ext2/3/4 replicate the superblock and, unless `META_BG` is set, the
//! whole group-descriptor table into later block groups (`sparse_super`
//! puts copies in groups 1, 3, 5, 7, 9, 25, 27, …). When the primary copy
//! at the start of the volume is unreadable, `e2fsck -b` reads one of those
//! instead; this module gives fsmnt the same escape hatch.
//!
//! The parser is never taught about copies: [`patch_from_backup`] locates
//! the backup, reads it, and hands back a [`PatchedReader`] that presents
//! those bytes at the primary locations. Every other byte still comes from
//! the source, and nothing is written back.

use fs_ext::io::{Read, Seek, SeekFrom};
use fsmnt_core::{FsError, FsResult};
use tracing::debug;

use crate::patched::PatchedReader;

/// Byte offset of the superblock within a filesystem, and its length.
const SUPERBLOCK_OFFSET: u64 = 1024;
/// Bytes an ext superblock occupies, primary and backup alike.
const SUPERBLOCK_LEN: usize = 1024;

/// `s_blocks_count_lo`.
const SB_BLOCKS_COUNT_LO: usize = 0x04;
/// `s_first_data_block`: 1 for 1 KiB blocks, 0 otherwise.
const SB_FIRST_DATA_BLOCK: usize = 0x14;
/// `s_log_block_size`: block size is `1024 << value`.
const SB_LOG_BLOCK_SIZE: usize = 0x18;
/// `s_blocks_per_group`.
const SB_BLOCKS_PER_GROUP: usize = 0x20;
/// `s_magic`.
const SB_MAGIC: usize = 0x38;
/// `s_block_group_nr`: the group this copy belongs to (0 in the primary).
const SB_BLOCK_GROUP_NR: usize = 0x5A;
/// `s_feature_incompat`.
const SB_FEATURE_INCOMPAT: usize = 0x60;
/// `s_desc_size`: group-descriptor size when `64BIT` is set.
const SB_DESC_SIZE: usize = 0xFE;
/// `s_blocks_count_hi`.
const SB_BLOCKS_COUNT_HI: usize = 0x150;

/// The ext superblock signature.
const EXT_MAGIC: u16 = 0xEF53;
/// `INCOMPAT_META_BG`: the group-descriptor table is scattered across the
/// filesystem instead of sitting in one run after the superblock.
const INCOMPAT_META_BG: u32 = 0x0010;
/// `INCOMPAT_64BIT`: group descriptors are `s_desc_size` bytes, not 32.
const INCOMPAT_64BIT: u32 = 0x0080;
/// Group-descriptor size without `64BIT`.
const MIN_DESC_SIZE: u32 = 32;

/// Block sizes ext supports, smallest first.
const BLOCK_SIZES: [u32; 7] = [1024, 2048, 4096, 8192, 16384, 32768, 65536];

/// Geometry read out of a superblock copy.
#[derive(Clone, Copy)]
struct Geometry {
    block_size: u32,
    blocks_per_group: u32,
    first_data_block: u32,
    blocks_count: u64,
    incompat: u32,
    desc_size: u32,
}

impl Geometry {
    /// Parse the fields that place block groups, or `None` when `buf` does
    /// not hold a structurally plausible superblock.
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SUPERBLOCK_LEN {
            return None;
        }
        if u16::from_le_bytes([buf[SB_MAGIC], buf[SB_MAGIC + 1]]) != EXT_MAGIC {
            return None;
        }
        let log_block_size = read_u32(buf, SB_LOG_BLOCK_SIZE);
        if log_block_size > 6 {
            return None;
        }
        let blocks_per_group = read_u32(buf, SB_BLOCKS_PER_GROUP);
        if blocks_per_group == 0 {
            return None;
        }
        let incompat = read_u32(buf, SB_FEATURE_INCOMPAT);
        let desc_size = if incompat & INCOMPAT_64BIT == 0 {
            MIN_DESC_SIZE
        } else {
            u32::from(u16::from_le_bytes([
                buf[SB_DESC_SIZE],
                buf[SB_DESC_SIZE + 1],
            ]))
        };
        let blocks_count = if incompat & INCOMPAT_64BIT == 0 {
            u64::from(read_u32(buf, SB_BLOCKS_COUNT_LO))
        } else {
            u64::from(read_u32(buf, SB_BLOCKS_COUNT_LO))
                | (u64::from(read_u32(buf, SB_BLOCKS_COUNT_HI)) << 32)
        };
        Some(Self {
            block_size: 1024_u32 << log_block_size,
            blocks_per_group,
            first_data_block: read_u32(buf, SB_FIRST_DATA_BLOCK),
            blocks_count,
            incompat,
            desc_size: desc_size.max(MIN_DESC_SIZE),
        })
    }

    /// Byte offset of the first block of `group`.
    fn group_start(&self, group: u32) -> Option<u64> {
        u64::from(group)
            .checked_mul(u64::from(self.blocks_per_group))?
            .checked_add(u64::from(self.first_data_block))?
            .checked_mul(u64::from(self.block_size))
    }

    /// Byte offset of the primary group-descriptor table: the block after
    /// the primary superblock (block 2 for 1 KiB blocks, block 1 above).
    fn primary_gdt_offset(&self) -> Option<u64> {
        u64::from(self.first_data_block)
            .checked_add(1)?
            .checked_mul(u64::from(self.block_size))
    }

    /// Number of block groups this geometry describes.
    fn group_count(&self) -> Option<u64> {
        let data_blocks = self
            .blocks_count
            .checked_sub(u64::from(self.first_data_block))?;
        Some(data_blocks.div_ceil(u64::from(self.blocks_per_group)))
    }

    /// Bytes the whole group-descriptor table occupies, rounded up to
    /// whole blocks — the run the parser reads after the superblock.
    fn gdt_len(&self) -> Option<u64> {
        let per_block = u64::from(self.block_size / self.desc_size);
        if per_block == 0 {
            return None;
        }
        let blocks = self.group_count()?.div_ceil(per_block);
        blocks.checked_mul(u64::from(self.block_size))
    }

    /// Whether the group-descriptor table is scattered (`META_BG`), in
    /// which case no single contiguous backup copy follows the superblock.
    fn is_meta_bg(&self) -> bool {
        self.incompat & INCOMPAT_META_BG != 0
    }
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read exactly `len` bytes at `offset`, or as many as the source still
/// holds. A short result is normal on a truncated image.
fn read_at<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> FsResult<Vec<u8>> {
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(FsError::from)?;
    let mut buffer = vec![0_u8; len];
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(FsError::from(e)),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Every byte offset at which group `group` could begin, cheapest first.
///
/// The backup superblock records the geometry needed to find it, so
/// locating it without a readable primary means guessing where to look and
/// then confirming from what is there. mkfs derives `blocks_per_group`
/// from the block size (`8 × block_size`, one bitmap block per group) and
/// `-g` overrides it with a smaller power of two, so enumerating those
/// combinations covers every filesystem that standard tools produce.
/// `hint` — the primary superblock's own geometry, when it still parses —
/// is tried first, which is the common "descriptors damaged, superblock
/// intact" case.
fn candidate_offsets(group: u32, hint: Option<Geometry>, limit: u64) -> Vec<u64> {
    let mut offsets = Vec::new();
    let mut push = |offset: Option<u64>| {
        if let Some(offset) = offset
            && offset >= SUPERBLOCK_OFFSET
            && offset < limit
            && !offsets.contains(&offset)
        {
            offsets.push(offset);
        }
    };
    push(hint.and_then(|geometry| geometry.group_start(group)));
    let mut generated: Vec<u64> = Vec::new();
    for block_size in BLOCK_SIZES {
        let first_data_block = u64::from(u8::from(block_size == 1024));
        let mut blocks_per_group = u64::from(block_size) * 8;
        while blocks_per_group >= 8 {
            let start = u64::from(group)
                .checked_mul(blocks_per_group)
                .and_then(|blocks| blocks.checked_add(first_data_block))
                .and_then(|blocks| blocks.checked_mul(u64::from(block_size)));
            if let Some(start) = start {
                generated.push(start);
            }
            blocks_per_group /= 2;
        }
    }
    generated.sort_unstable();
    for offset in generated {
        push(Some(offset));
    }
    offsets
}

/// Read the superblock copy at `offset` if it really is `group`'s backup.
///
/// The copy has to name `group` in `s_block_group_nr` *and* its own
/// geometry has to place group `group` exactly where the copy was found.
/// That self-consistency check is what lets the search try many candidate
/// offsets without ever accepting a stale or coincidental superblock.
fn read_backup_at<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    group: u32,
) -> FsResult<Option<(Geometry, Vec<u8>)>> {
    let buffer = read_at(reader, offset, SUPERBLOCK_LEN)?;
    let Some(geometry) = Geometry::parse(&buffer) else {
        return Ok(None);
    };
    let recorded = u16::from_le_bytes([buffer[SB_BLOCK_GROUP_NR], buffer[SB_BLOCK_GROUP_NR + 1]]);
    if u32::from(recorded) != group {
        return Ok(None);
    }
    if geometry.group_start(group) != Some(offset) {
        return Ok(None);
    }
    Ok(Some((geometry, buffer)))
}

/// Wrap `reader` so the metadata backed up in block group `group` is
/// presented where the parser looks for the primary.
///
/// The superblock copy is always patched in at byte 1024. Without
/// `META_BG` the group-descriptor table copy that follows it is patched in
/// over the primary table as well, so a volume whose first blocks are
/// entirely gone still opens. **With `META_BG` only the superblock is
/// patched**: that layout scatters descriptor blocks across the
/// filesystem instead of keeping one contiguous backup run, and the
/// primary descriptor blocks are read from wherever they already live.
///
/// # Errors
///
/// Returns an error when `group` is 0 (that is the primary), when the
/// source cannot be read, or when no self-consistent backup superblock for
/// `group` can be found.
pub(super) fn patch_from_backup<R: Read + Seek>(
    mut reader: R,
    group: u32,
) -> FsResult<PatchedReader<R>> {
    if group == 0 {
        return Err(FsError::Filesystem(
            "block group 0 holds the primary superblock, not a backup copy; omit the backup \
             superblock selector to open from the primary"
                .to_string(),
        ));
    }
    let limit = reader.seek(SeekFrom::End(0)).map_err(FsError::from)?;
    // The primary is a hint, not a requirement: on a medium that begins
    // inside the filesystem the bytes at 1024 are absent, and the whole
    // point of opening through a backup is that the primary may be gone.
    let hint = read_at(&mut reader, SUPERBLOCK_OFFSET, SUPERBLOCK_LEN)
        .ok()
        .and_then(|buffer| Geometry::parse(&buffer));

    let mut found = None;
    for offset in candidate_offsets(group, hint, limit) {
        // A candidate that cannot be read is simply not where the copy is:
        // on a medium that begins inside the filesystem the low candidates
        // are absent, and on damaged media one bad sector must not end the
        // search for a copy that lies further on.
        match read_backup_at(&mut reader, offset, group) {
            Ok(Some(backup)) => {
                found = Some((offset, backup));
                break;
            }
            Ok(None) => {}
            Err(error) => {
                debug!(offset, group, %error, "a candidate backup superblock offset could not be read");
            }
        }
    }
    let Some((offset, (geometry, superblock))) = found else {
        return Err(FsError::Filesystem(format!(
            "no ext backup superblock for block group {group} was found; with sparse_super only \
             groups 1, 3, 5, 7, 9, 25, 27, 49, 81, … keep one, and a copy that is itself damaged \
             or past the end of a truncated image cannot be used"
        )));
    };

    debug!(
        group,
        offset,
        block_size = geometry.block_size,
        blocks_per_group = geometry.blocks_per_group,
        meta_bg = geometry.is_meta_bg(),
        "found the ext backup superblock; presenting it where the primary belongs"
    );
    let mut patched = PatchedReader::new(reader).with_patch(SUPERBLOCK_OFFSET, superblock);
    if !geometry.is_meta_bg() {
        patch_group_descriptors(&mut patched, offset, geometry)?;
    }
    Ok(patched)
}

/// Copy the backup group-descriptor table — the run of blocks immediately
/// after the backup superblock — over the primary table's location.
///
/// A short read is kept rather than rejected: on a truncated image the
/// descriptors that did survive still locate the inode tables in the
/// groups they cover, which is exactly what salvage needs.
fn patch_group_descriptors<R: Read + Seek>(
    patched: &mut PatchedReader<R>,
    backup_offset: u64,
    geometry: Geometry,
) -> FsResult<()> {
    let (Some(source), Some(target), Some(len)) = (
        backup_offset.checked_add(u64::from(geometry.block_size)),
        geometry.primary_gdt_offset(),
        geometry.gdt_len(),
    ) else {
        return Ok(());
    };
    let Ok(len) = usize::try_from(len) else {
        return Ok(());
    };
    // Read through the patched reader: it already serves the backup
    // superblock, and the descriptor run never overlaps it.
    let descriptors = read_at(patched, source, len)?;
    if !descriptors.is_empty() {
        patched.add_patch(target, descriptors);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal superblock image: `groups` groups of `blocks_per_group`
    /// blocks, with a backup copy at the start of every group.
    fn synthetic(block_size: u32, blocks_per_group: u32, groups: u32) -> Vec<u8> {
        let first_data_block = u32::from(block_size == 1024);
        let total_blocks =
            u64::from(first_data_block) + u64::from(blocks_per_group) * u64::from(groups);
        let len = usize::try_from(total_blocks * u64::from(block_size)).expect("fits usize");
        let mut image = vec![0_u8; len];
        for group in 0..groups {
            let offset = if group == 0 {
                usize::try_from(SUPERBLOCK_OFFSET).expect("fits usize")
            } else {
                usize::try_from(
                    (u64::from(first_data_block) + u64::from(group) * u64::from(blocks_per_group))
                        * u64::from(block_size),
                )
                .expect("fits usize")
            };
            let sb = &mut image[offset..offset + SUPERBLOCK_LEN];
            sb[SB_BLOCKS_COUNT_LO..SB_BLOCKS_COUNT_LO + 4]
                .copy_from_slice(&u32::try_from(total_blocks).expect("fits u32").to_le_bytes());
            sb[SB_FIRST_DATA_BLOCK..SB_FIRST_DATA_BLOCK + 4]
                .copy_from_slice(&first_data_block.to_le_bytes());
            sb[SB_LOG_BLOCK_SIZE..SB_LOG_BLOCK_SIZE + 4]
                .copy_from_slice(&(block_size.trailing_zeros() - 10).to_le_bytes());
            sb[SB_BLOCKS_PER_GROUP..SB_BLOCKS_PER_GROUP + 4]
                .copy_from_slice(&blocks_per_group.to_le_bytes());
            sb[SB_MAGIC..SB_MAGIC + 2].copy_from_slice(&EXT_MAGIC.to_le_bytes());
            sb[SB_BLOCK_GROUP_NR..SB_BLOCK_GROUP_NR + 2]
                .copy_from_slice(&u16::try_from(group).expect("fits u16").to_le_bytes());
        }
        image
    }

    #[test]
    fn finds_a_backup_with_a_non_default_blocks_per_group() {
        // -b 1024 -g 1024: the default would be 8192 blocks per group, so
        // this only resolves because the search confirms geometry from the
        // copy it finds rather than assuming the default.
        let image = synthetic(1024, 1024, 8);
        let mut reader = std::io::Cursor::new(image);
        let offset = candidate_offsets(1, None, u64::MAX)
            .into_iter()
            .find(|offset| {
                read_backup_at(&mut reader, *offset, 1)
                    .expect("read")
                    .is_some()
            })
            .expect("group 1 backup is findable");
        assert_eq!(offset, 1025 * 1024);
    }

    #[test]
    fn a_group_without_a_backup_is_reported() {
        // Group 9 is past the end of an 8-group filesystem, so no copy of
        // it exists anywhere in the image.
        let image = synthetic(1024, 1024, 8);
        let Err(error) = patch_from_backup(std::io::Cursor::new(image), 9) else {
            panic!("group 9 does not exist in an 8-group filesystem");
        };
        assert!(
            error.to_string().contains("no ext backup superblock"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn group_zero_is_refused() {
        let Err(error) = patch_from_backup(std::io::Cursor::new(vec![0_u8; 8192]), 0) else {
            panic!("group 0 is the primary, not a backup");
        };
        assert!(
            error.to_string().contains("primary superblock"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_backup_is_served_at_the_primary_offset() {
        let image = synthetic(4096, 32768, 2);
        let mut patched =
            patch_from_backup(std::io::Cursor::new(image), 1).expect("group 1 backup opens");
        let mut buffer = [0_u8; SUPERBLOCK_LEN];
        patched
            .seek(SeekFrom::Start(SUPERBLOCK_OFFSET))
            .expect("seek");
        patched.read_exact(&mut buffer).expect("read superblock");
        assert_eq!(
            u16::from_le_bytes([buffer[SB_BLOCK_GROUP_NR], buffer[SB_BLOCK_GROUP_NR + 1]]),
            1,
            "byte 1024 must now serve group 1's copy",
        );
    }

    #[test]
    fn candidates_cover_the_default_layouts_and_stay_inside_the_source() {
        let unbounded = candidate_offsets(1, None, u64::MAX);
        // The mkfs defaults for 1 KiB, 2 KiB and 4 KiB blocks: one bitmap
        // block per group, so 8 × block_size blocks per group.
        for expected in [8_389_632_u64, 33_554_432, 134_217_728] {
            assert!(
                unbounded.contains(&expected),
                "default layout offset {expected} must be probed",
            );
        }
        let bounded = candidate_offsets(1, None, 1_000_000);
        assert!(
            bounded.iter().all(|offset| *offset < 1_000_000),
            "a candidate past the end of the source is a wasted read",
        );
    }
}
