//! ext2/ext3/ext4 superblock probing and geometry.
//!
//! ext has no boot signature to key on, so detection reads the superblock at
//! byte 1024 and sanity-checks its fields. The same fields answer two
//! further questions a scan over unpartitioned media asks: how large the
//! filesystem claims to be, and — for one of the backup copies scattered
//! through it — where its filesystem began.

use super::{read_u16_le, read_u32_le};

/// Byte offset of the superblock within an ext filesystem, and of the copy
/// within any detection prefix that starts at a candidate offset.
pub(super) const EXT_SUPERBLOCK_OFFSET: usize = 1024;
pub(super) const SB_S_BLOCKS_COUNT_LO: usize = 0x04;
pub(super) const SB_S_FIRST_DATA_BLOCK: usize = 0x14;
pub(super) const SB_S_LOG_BLOCK_SIZE: usize = 0x18;
pub(super) const SB_S_BLOCKS_PER_GROUP: usize = 0x20;
pub(super) const SB_S_INODES_PER_GROUP: usize = 0x28;
pub(super) const SB_S_MAGIC: usize = 0x38;
/// `s_block_group_nr`: the block group this superblock copy belongs to.
/// e2fsprogs writes 0 into the primary and the group number into every
/// backup (`sparse_super` puts them in groups 1, 3, 5, 7, 9, 25, 27, …),
/// which is what lets a probe tell a filesystem start from a copy that
/// merely sits somewhere inside one.
pub(super) const SB_S_BLOCK_GROUP_NR: usize = 0x5A;
/// `s_feature_incompat`: only when its `64BIT` bit is set does
/// `s_blocks_count_hi` carry meaning; older filesystems leave the field as
/// padding that must not be folded into the block count.
pub(super) const SB_S_FEATURE_INCOMPAT: usize = 0x60;
pub(super) const SB_S_BLOCKS_COUNT_HI: usize = 0x150;
/// `INCOMPAT_64BIT`, which promotes the block count to 64 bits.
pub(super) const EXT_INCOMPAT_64BIT: u32 = 0x0000_0080;
pub(super) const EXT_PROBE_MIN_LEN: usize = EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR + 2; // 0x45C
pub(super) const EXT_MAGIC: u16 = 0xEF53;

/// Structural sanity of an ext superblock at offset 1024 of `buf`: the
/// magic plus the cheap field checks that keep a coincidental 0xEF53 in a
/// GPT partition-entry array from passing. Says nothing about whether the
/// copy is the primary — see [`probe_ext`] and [`ext_backup_superblock_group`].
pub(super) fn ext_superblock_plausible(buf: &[u8]) -> bool {
    if buf.len() < EXT_PROBE_MIN_LEN {
        return false;
    }
    if read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_MAGIC) != EXT_MAGIC {
        return false;
    }
    // s_log_block_size gates 0..=6 (block size 1 KiB .. 64 KiB) per
    // fs-ext's own superblock parser.
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE) > 6 {
        return false;
    }
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP) == 0 {
        return false;
    }
    if read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_INODES_PER_GROUP) == 0 {
        return false;
    }
    true
}

/// Prefix probe for the *start* of an ext2/ext3/ext4 filesystem: a
/// plausible superblock whose `s_block_group_nr` is 0.
///
/// Backup superblocks carry their own group number there, so an offset
/// that lands on one partway into a filesystem is not reported as `Ext`.
/// Mounting from a backup used to "succeed" — the group descriptors were
/// then read from the wrong place and the volume exposed no files, which
/// in a forensic context reads as "this partition is empty".
pub(super) fn probe_ext(buf: &[u8]) -> bool {
    ext_superblock_plausible(buf)
        && read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR) == 0
}

/// Geometry read from a plausible ext2/ext3/ext4 superblock.
///
/// Enough to answer the two questions a scan over unpartitioned media asks
/// of every superblock it finds: how big does this filesystem claim to be,
/// and — for a backup copy — where would its filesystem have started?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtSuperblockInfo {
    /// Block size in bytes, `1024 << s_log_block_size` (1 KiB … 64 KiB).
    pub block_size: u32,
    /// `s_blocks_count`, including the high half when `INCOMPAT_64BIT` is set.
    pub blocks_count: u64,
    /// `s_blocks_per_group`.
    pub blocks_per_group: u32,
    /// `s_first_data_block`: 1 for 1 KiB blocks, 0 for every larger size.
    pub first_data_block: u32,
    /// `s_block_group_nr`: 0 in the primary superblock, the owning group in
    /// every backup copy.
    pub block_group_nr: u16,
}

impl ExtSuperblockInfo {
    /// Whether this copy is the filesystem's primary superblock.
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.block_group_nr == 0
    }

    /// Total size in bytes the superblock claims for its filesystem.
    #[must_use]
    pub fn size_bytes(&self) -> u64 {
        self.blocks_count.saturating_mul(u64::from(self.block_size))
    }

    /// Byte offset of *this* superblock copy from the filesystem's first
    /// byte.
    ///
    /// The primary always sits at byte 1024, whatever the block size. Every
    /// backup sits at the start of its group's first block, so subtracting
    /// this from a copy's absolute offset gives the filesystem start — the
    /// offset a mount would need.
    #[must_use]
    pub fn copy_offset(&self) -> u64 {
        if self.is_primary() {
            // The primary copy always sits at byte 1024 of the filesystem,
            // whatever the block size — that is what makes a 1 KiB-block
            // filesystem's first data block 1 rather than 0.
            return 1024;
        }
        let block = u64::from(self.first_data_block).saturating_add(
            u64::from(self.block_group_nr).saturating_mul(u64::from(self.blocks_per_group)),
        );
        block.saturating_mul(u64::from(self.block_size))
    }
}

/// Read the geometry of an ext superblock sitting at offset 1024 of `buf`.
///
/// Returns `None` unless the bytes pass the same plausibility checks
/// detection uses, so a coincidental `0xEF53` does not yield a filesystem
/// size or an implied start. Says nothing about primary versus backup —
/// [`ExtSuperblockInfo::is_primary`] answers that.
#[must_use]
pub fn ext_superblock_info(buf: &[u8]) -> Option<ExtSuperblockInfo> {
    if !ext_superblock_plausible(buf) {
        return None;
    }
    let log_block_size = read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_LOG_BLOCK_SIZE);
    // `ext_superblock_plausible` already gated s_log_block_size to 0..=6.
    let block_size = 1024_u32 << log_block_size;
    let blocks_count_lo = u64::from(read_u32_le(
        buf,
        EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_COUNT_LO,
    ));
    let feature_incompat = read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_FEATURE_INCOMPAT);
    let blocks_count = if feature_incompat & EXT_INCOMPAT_64BIT == 0 {
        blocks_count_lo
    } else {
        let high = read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_COUNT_HI).unwrap_or(0);
        blocks_count_lo | (u64::from(high) << 32)
    };
    Some(ExtSuperblockInfo {
        block_size,
        blocks_count,
        blocks_per_group: read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP),
        first_data_block: read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_FIRST_DATA_BLOCK),
        block_group_nr: read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR),
    })
}

/// If `buf` (the first bytes at a candidate offset) holds an ext **backup**
/// superblock, return the block group it belongs to.
///
/// Returns `None` for a primary superblock and for anything that is not a
/// plausible ext superblock, so callers can turn a `Unknown` detection
/// into a precise diagnosis: "this is a copy from group N, not the start of
/// the filesystem".
#[must_use]
pub fn ext_backup_superblock_group(buf: &[u8]) -> Option<u16> {
    if !ext_superblock_plausible(buf) {
        return None;
    }
    match read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR) {
        0 => None,
        group => Some(group),
    }
}

/// Read a little-endian `u32` only if the buffer reaches that far.
///
/// The plausibility probe deliberately stops at 0x45C, so fields beyond it
/// (`s_blocks_count_hi`) must tolerate a shorter prefix.
fn read_u32_le_at(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
