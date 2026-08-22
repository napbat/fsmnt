//! Minimal QNX6 geometry used by filesystem detection.
//!
//! This module intentionally stops at identification and declared volume
//! geometry. Checksums, snapshot selection, inode trees, and file traversal
//! belong to the `fs-qnx6` format crate.

/// Bytes reserved for the boot loader before the primary superblock.
pub const BOOT_AREA_SIZE: u64 = 0x2000;

/// Bytes reserved around each of the paired superblock records.
pub const SUPERBLOCK_AREA_SIZE: u64 = 0x1000;

/// Byte offset at which filesystem block zero begins.
pub const DATA_AREA_OFFSET: u64 = BOOT_AREA_SIZE + SUPERBLOCK_AREA_SIZE;

/// Number of bytes in one checksummed superblock record.
pub const SUPERBLOCK_SIZE: usize = 0x200;

/// QNX6 Power-Safe filesystem magic (`0x6819_1122`).
pub const SUPERBLOCK_MAGIC: u32 = 0x6819_1122;

/// Bytes required to validate a superblock's identifying geometry.
pub const SUPERBLOCK_PROBE_SIZE: usize = 0x44;

/// Prefix length required to reach the complete primary superblock.
pub const VOLUME_PROBE_SIZE: usize = 0x2000 + SUPERBLOCK_SIZE;

/// Byte order encoded by the on-disk magic.
#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

fn byte_order(superblock: &[u8]) -> Option<ByteOrder> {
    let magic = superblock.get(..4)?.try_into().ok()?;
    if u32::from_le_bytes(magic) == SUPERBLOCK_MAGIC {
        Some(ByteOrder::Little)
    } else if u32::from_be_bytes(magic) == SUPERBLOCK_MAGIC {
        Some(ByteOrder::Big)
    } else {
        None
    }
}

fn read_u32(superblock: &[u8], offset: usize, order: ByteOrder) -> Option<u32> {
    let bytes = superblock.get(offset..offset + 4)?.try_into().ok()?;
    Some(match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    })
}

/// Validate the identifying fields of a normal QNX6 superblock.
///
/// `superblock` starts at the magic, rather than at the beginning of the
/// volume. Full opening deliberately performs stronger validation in the
/// format crate, including the CRC and paired-snapshot agreement.
#[must_use]
pub fn is_superblock(superblock: &[u8]) -> bool {
    if superblock.len() < SUPERBLOCK_PROBE_SIZE {
        return false;
    }
    let Some(order) = byte_order(superblock) else {
        return false;
    };
    let Some(block_size) = read_u32(superblock, 0x30, order) else {
        return false;
    };
    if !matches!(block_size, 512 | 1024 | 2048 | 4096) {
        return false;
    }
    let Some(num_inodes) = read_u32(superblock, 0x34, order) else {
        return false;
    };
    let Some(free_inodes) = read_u32(superblock, 0x38, order) else {
        return false;
    };
    let Some(num_blocks) = read_u32(superblock, 0x3c, order) else {
        return false;
    };
    let Some(free_blocks) = read_u32(superblock, 0x40, order) else {
        return false;
    };
    num_inodes > 0 && free_inodes <= num_inodes && num_blocks > 0 && free_blocks <= num_blocks
}

/// Total volume length claimed by one QNX6 superblock record.
///
/// `superblock` starts at the magic. The result includes the boot area,
/// filesystem data blocks, and both reserved superblock areas.
#[must_use]
pub fn superblock_volume_size(superblock: &[u8]) -> Option<u64> {
    if !is_superblock(superblock) {
        return None;
    }
    let order = byte_order(superblock)?;
    let block_size = u64::from(read_u32(superblock, 0x30, order)?);
    let num_blocks = u64::from(read_u32(superblock, 0x3c, order)?);
    num_blocks
        .checked_mul(block_size)?
        .checked_add(DATA_AREA_OFFSET)?
        .checked_add(SUPERBLOCK_AREA_SIZE)
}

pub(super) fn probe_volume(volume: &[u8]) -> bool {
    let offset = usize::try_from(BOOT_AREA_SIZE).ok();
    offset
        .and_then(|offset| volume.get(offset..))
        .is_some_and(is_superblock)
}

pub(super) fn volume_size(volume: &[u8]) -> Option<u64> {
    let offset = usize::try_from(BOOT_AREA_SIZE).ok()?;
    superblock_volume_size(volume.get(offset..)?)
}
