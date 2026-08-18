//! ext2/ext3/ext4 superblock probing and geometry.
//!
//! ext has no boot signature to key on, so detection reads the superblock at
//! byte 1024 and sanity-checks its fields. The same fields answer two
//! further questions a scan over unpartitioned media asks: how large the
//! filesystem claims to be, and — for one of the backup copies scattered
//! through it — where its filesystem began.
//!
//! A third question only a scan asks is whether a *primary* superblock is
//! really the front of a filesystem. Nothing in the superblock itself says
//! so: an ext4 journal records whole blocks, so block 0 — superblock
//! included — is copied verbatim into the journal on every transaction that
//! touches it, and each copy reads as a pristine primary. What distinguishes
//! the real thing is the group descriptor table that must immediately follow
//! it, so [`ext_start_check`] goes and looks. See
//! [`ExtStartCheck`] for what its three answers mean.

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
/// `s_rev_level`: revision 0 predates a stored inode size and fixes it at
/// 128 bytes, so `s_inode_size` must not be read on such a filesystem.
pub(super) const SB_S_REV_LEVEL: usize = 0x4C;
pub(super) const SB_S_INODE_SIZE: usize = 0x58;
pub(super) const SB_S_FEATURE_COMPAT: usize = 0x5C;
/// `s_feature_incompat`: only when its `64BIT` bit is set does
/// `s_blocks_count_hi` carry meaning; older filesystems leave the field as
/// padding that must not be folded into the block count.
pub(super) const SB_S_FEATURE_INCOMPAT: usize = 0x60;
pub(super) const SB_S_FEATURE_RO_COMPAT: usize = 0x64;
pub(super) const SB_S_UUID: usize = 0x68;
/// `s_desc_size`: the width of one group descriptor, meaningful only on a
/// `64BIT` filesystem; everything older uses the fixed 32-byte descriptor.
pub(super) const SB_S_DESC_SIZE: usize = 0xFE;
pub(super) const SB_S_BLOCKS_COUNT_HI: usize = 0x150;
pub(super) const SB_S_CHECKSUM_TYPE: usize = 0x175;
pub(super) const SB_S_CHECKSUM_SEED: usize = 0x270;
/// `INCOMPAT_64BIT`, which promotes the block count to 64 bits.
pub(super) const EXT_INCOMPAT_64BIT: u32 = 0x0000_0080;
/// `INCOMPAT_CSUM_SEED`: the metadata checksum seed is stored in the
/// superblock rather than derived from the UUID, so the UUID can be changed
/// on a mounted filesystem without rewriting every checksum.
pub(super) const EXT_INCOMPAT_CSUM_SEED: u32 = 0x0000_2000;
/// `RO_COMPAT_GDT_CSUM`: the ext4 `uninit_bg` CRC-16 over each group
/// descriptor, superseded by `METADATA_CSUM`.
pub(super) const EXT_RO_COMPAT_GDT_CSUM: u32 = 0x0000_0010;
/// `RO_COMPAT_METADATA_CSUM`: CRC-32C over every metadata block, group
/// descriptors included.
pub(super) const EXT_RO_COMPAT_METADATA_CSUM: u32 = 0x0000_0400;
/// The only `s_checksum_type` ext4 has ever defined: CRC-32C.
pub(super) const EXT_CHECKSUM_TYPE_CRC32C: u8 = 1;
/// Width of a group descriptor before `64BIT` widened it.
pub(super) const EXT_LEGACY_DESC_SIZE: u32 = 32;
pub(super) const EXT_PROBE_MIN_LEN: usize = EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR + 2; // 0x45C
pub(super) const EXT_MAGIC: u16 = 0xEF53;

/// Field offsets within one group descriptor. The `_hi` halves exist only
/// on a `64BIT` filesystem whose descriptors are at least 64 bytes wide.
const BG_BLOCK_BITMAP_LO: usize = 0x00;
const BG_INODE_BITMAP_LO: usize = 0x04;
const BG_INODE_TABLE_LO: usize = 0x08;
const BG_FREE_BLOCKS_COUNT_LO: usize = 0x0C;
const BG_FREE_INODES_COUNT_LO: usize = 0x0E;
const BG_USED_DIRS_COUNT_LO: usize = 0x10;
const BG_FLAGS: usize = 0x12;
const BG_ITABLE_UNUSED_LO: usize = 0x1C;
const BG_CHECKSUM: usize = 0x1E;
const BG_BLOCK_BITMAP_HI: usize = 0x20;
const BG_INODE_BITMAP_HI: usize = 0x24;
const BG_INODE_TABLE_HI: usize = 0x28;
/// Every `bg_flags` bit ext4 defines: `INODE_UNINIT`, `BLOCK_UNINIT`,
/// `ITABLE_ZEROED`. Anything outside them is not a descriptor.
const BG_FLAGS_KNOWN: u16 = 0x0007;

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
    /// `s_uuid`: the filesystem's identity, and the only field that ties a
    /// stray superblock copy to the filesystem it was copied from.
    pub uuid: [u8; 16],
    /// `s_inodes_per_group`.
    pub inodes_per_group: u32,
    /// Bytes per inode: fixed at 128 on a revision-0 filesystem, otherwise
    /// `s_inode_size`.
    pub inode_size: u32,
    /// `s_feature_compat`.
    pub feature_compat: u32,
    /// `s_feature_incompat`.
    pub feature_incompat: u32,
    /// `s_feature_ro_compat`.
    pub feature_ro_compat: u32,
    /// Bytes per group descriptor: 32, or `s_desc_size` on a `64BIT`
    /// filesystem.
    pub desc_size: u32,
}

impl ExtSuperblockInfo {
    /// Whether this copy is the filesystem's primary superblock.
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        self.block_group_nr == 0
    }

    /// Bytes one block group spans, which is also the distance between
    /// consecutive backup superblocks.
    #[must_use]
    pub fn group_size_bytes(&self) -> u64 {
        u64::from(self.blocks_per_group).saturating_mul(u64::from(self.block_size))
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
    let sixty_four_bit = feature_incompat & EXT_INCOMPAT_64BIT != 0;
    let blocks_count = if sixty_four_bit {
        let high = read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_COUNT_HI).unwrap_or(0);
        blocks_count_lo | (u64::from(high) << 32)
    } else {
        blocks_count_lo
    };
    // Revision 0 has no `s_inode_size` field at all — the 128-byte inode is
    // part of the format — so reading one there would pick up whatever the
    // padding happens to hold.
    let inode_size = if read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_REV_LEVEL) == Some(0) {
        128
    } else {
        u32::from(read_u16_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_INODE_SIZE).unwrap_or(0))
    };
    let desc_size = if sixty_four_bit {
        u32::from(read_u16_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_DESC_SIZE).unwrap_or(0))
    } else {
        EXT_LEGACY_DESC_SIZE
    };
    Some(ExtSuperblockInfo {
        block_size,
        blocks_count,
        blocks_per_group: read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCKS_PER_GROUP),
        first_data_block: read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_FIRST_DATA_BLOCK),
        block_group_nr: read_u16_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_BLOCK_GROUP_NR),
        uuid: read_uuid_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_UUID).unwrap_or([0; 16]),
        inodes_per_group: read_u32_le(buf, EXT_SUPERBLOCK_OFFSET + SB_S_INODES_PER_GROUP),
        inode_size,
        feature_compat: read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_FEATURE_COMPAT)
            .unwrap_or(0),
        feature_incompat,
        feature_ro_compat: read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_FEATURE_RO_COMPAT)
            .unwrap_or(0),
        desc_size,
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

/// An ext **backup** superblock together with the geometry needed to work
/// out where its filesystem begins.
///
/// Produced by [`ext_backup_superblock_info`]; a projection of
/// [`ExtSuperblockInfo`] for callers that only deal in backups. Every field
/// is read from the copy itself, so the numbers describe the filesystem the
/// copy belongs to even when nothing else of it is readable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtBackupSuperblock {
    /// `s_block_group_nr` — the block group this copy belongs to. Always
    /// non-zero; group 0 is the primary and is not reported here.
    pub group: u16,
    /// Block size in bytes (`1024 << s_log_block_size`).
    pub block_size: u32,
    /// `s_blocks_per_group`.
    pub blocks_per_group: u32,
    /// `s_first_data_block`: 1 for 1 KiB blocks, 0 otherwise.
    pub first_data_block: u32,
}

impl ExtBackupSuperblock {
    /// Byte distance from the start of the filesystem to the first block of
    /// [`group`](Self::group), i.e. to this backup copy.
    ///
    /// `None` on arithmetic overflow, which only a nonsensical copy can
    /// produce.
    #[must_use]
    pub fn group_start_bytes(&self) -> Option<u64> {
        u64::from(self.group)
            .checked_mul(u64::from(self.blocks_per_group))?
            .checked_add(u64::from(self.first_data_block))?
            .checked_mul(u64::from(self.block_size))
    }

    /// Where the filesystem starts, given that this copy was found by a
    /// probe at `probe_offset`.
    ///
    /// Probes read the superblock at `probe_offset + 1024`, matching a
    /// filesystem start, whereas a backup copy occupies its block group's
    /// first block from byte zero — hence the `+ 1024` correction before
    /// stepping back over the groups that precede it.
    ///
    /// `None` when the recorded geometry places the start before the
    /// beginning of the source, which means the copy is stale or
    /// coincidental rather than a backup of a filesystem living here.
    #[must_use]
    pub fn filesystem_start(&self, probe_offset: u64) -> Option<u64> {
        let superblock_offset = u64::try_from(EXT_SUPERBLOCK_OFFSET).ok()?;
        probe_offset
            .checked_add(superblock_offset)?
            .checked_sub(self.group_start_bytes()?)
    }
}

/// If `buf` (the first bytes at a candidate offset) holds an ext **backup**
/// superblock, describe it.
///
/// Returns `None` for a primary superblock and for anything that is not a
/// plausible ext superblock. The geometry travels with the copy, so a
/// caller can turn "no filesystem here" into "this is group N's copy and
/// the filesystem starts at byte X" — see
/// [`ExtBackupSuperblock::filesystem_start`].
#[must_use]
pub fn ext_backup_superblock_info(buf: &[u8]) -> Option<ExtBackupSuperblock> {
    let info = ext_superblock_info(buf)?;
    if info.is_primary() {
        return None;
    }
    Some(ExtBackupSuperblock {
        group: info.block_group_nr,
        block_size: info.block_size,
        blocks_per_group: info.blocks_per_group,
        first_data_block: info.first_data_block,
    })
}

/// Read a little-endian `u32` only if the buffer reaches that far.
///
/// The plausibility probe deliberately stops at 0x45C, so fields beyond it
/// (`s_blocks_count_hi`, the feature masks, the UUID) must tolerate a
/// shorter prefix rather than panicking on it.
fn read_u32_le_at(buf: &[u8], off: usize) -> Option<u32> {
    let bytes = buf.get(off..off.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u16` only if the buffer reaches that far.
fn read_u16_le_at(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read the 16 UUID bytes only if the buffer reaches that far.
fn read_uuid_at(buf: &[u8], off: usize) -> Option<[u8; 16]> {
    let bytes = buf.get(off..off.checked_add(16)?)?;
    let mut uuid = [0_u8; 16];
    uuid.copy_from_slice(bytes);
    Some(uuid)
}

/// What the bytes after a primary superblock say about whether a filesystem
/// really starts there.
///
/// A primary superblock is followed immediately by the group descriptor
/// table — the first descriptor sits in the block after
/// `s_first_data_block`, and every filesystem written this century carries a
/// checksum over it. A copy of block 0 sitting in a journal, or a carved
/// fragment of one, has some unrelated block there instead, so the
/// descriptor is the discriminator a magic number cannot be.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtStartCheck {
    /// The descriptor table is where it has to be and describes group 0 of
    /// this superblock's filesystem: this is a filesystem start.
    Confirmed,
    /// The superblock is plausible but what follows it is not its group
    /// descriptor table. Either the bytes are a copy of block 0 that lives
    /// somewhere else (a journal record, a carved fragment), or the table of
    /// a real filesystem here has been damaged — corroborating evidence,
    /// such as a backup superblock naming this offset, is what tells the two
    /// apart.
    Unconfirmed,
    /// Nothing was decided: the bytes are not a plausible primary
    /// superblock, or the buffer stops before the first descriptor. Callers
    /// should fall back on whatever they would have done without this check.
    Inconclusive,
}

/// Whether the group descriptor table that must follow a primary superblock
/// is there.
///
/// `buf` starts at the candidate filesystem start, so the superblock is at
/// `buf[1024..]` and the first group descriptor at
/// `(s_first_data_block + 1) * block_size`. This is a *scan* discriminator
/// and deliberately stricter than detection: mount-time classification stays
/// lenient so a filesystem whose descriptor table is damaged can still be
/// recognised as ext and rescued from a backup superblock.
#[must_use]
pub fn ext_start_check(buf: &[u8]) -> ExtStartCheck {
    if !probe_ext(buf) {
        return ExtStartCheck::Inconclusive;
    }
    let Some(info) = ext_superblock_info(buf) else {
        return ExtStartCheck::Inconclusive;
    };
    // A descriptor width the format cannot produce is decided here rather
    // than by the slice below, so a wild `s_desc_size` reads as "not a
    // start" instead of "the buffer was too short".
    if !descriptor_width_plausible(&info) {
        return ExtStartCheck::Unconfirmed;
    }
    let Some(desc) = first_group_descriptor(buf, &info) else {
        return ExtStartCheck::Inconclusive;
    };
    if descriptor_is_structural(&info, desc) && descriptor_checksum_holds(buf, &info, desc) {
        ExtStartCheck::Confirmed
    } else {
        ExtStartCheck::Unconfirmed
    }
}

/// Whether `s_desc_size` is a width ext4 can actually have written: the
/// fixed 32 bytes before `64BIT`, and a power of two from 32 to 1024 after.
fn descriptor_width_plausible(info: &ExtSuperblockInfo) -> bool {
    if info.feature_incompat & EXT_INCOMPAT_64BIT == 0 {
        return info.desc_size == EXT_LEGACY_DESC_SIZE;
    }
    info.desc_size.is_power_of_two() && (EXT_LEGACY_DESC_SIZE..=1024).contains(&info.desc_size)
}

/// The group-0 descriptor, or `None` when `buf` stops before it ends.
fn first_group_descriptor<'a>(buf: &'a [u8], info: &ExtSuperblockInfo) -> Option<&'a [u8]> {
    let start = usize::try_from(
        u64::from(info.first_data_block)
            .checked_add(1)?
            .checked_mul(u64::from(info.block_size))?,
    )
    .ok()?;
    let end = start.checked_add(usize::try_from(info.desc_size).ok()?)?;
    buf.get(start..end)
}

/// Whether every field of the group-0 descriptor is consistent with the
/// geometry its superblock declares.
///
/// `desc` is at least [`EXT_LEGACY_DESC_SIZE`] bytes long, which
/// [`descriptor_width_plausible`] establishes before it is sliced.
fn descriptor_is_structural(info: &ExtSuperblockInfo, desc: &[u8]) -> bool {
    let block_size = u64::from(info.block_size);
    if !info.inode_size.is_power_of_two()
        || info.inode_size < 128
        || u64::from(info.inode_size) > block_size
    {
        return false;
    }
    // One block holds the group's inode bitmap, eight inodes to the byte.
    if u64::from(info.inodes_per_group) > block_size.saturating_mul(8) {
        return false;
    }

    let wide = info.feature_incompat & EXT_INCOMPAT_64BIT != 0 && info.desc_size >= 64;
    let blocks = [
        descriptor_block(desc, BG_BLOCK_BITMAP_LO, BG_BLOCK_BITMAP_HI, wide),
        descriptor_block(desc, BG_INODE_BITMAP_LO, BG_INODE_BITMAP_HI, wide),
        descriptor_block(desc, BG_INODE_TABLE_LO, BG_INODE_TABLE_HI, wide),
    ];
    let first_data_block = u64::from(info.first_data_block);
    for (index, block) in blocks.iter().enumerate() {
        // The three metadata areas are distinct blocks inside the
        // filesystem, and none of them can be the block the superblock
        // itself occupies.
        let Some(block) = *block else { return false };
        if block <= first_data_block || block >= info.blocks_count {
            return false;
        }
        if blocks[..index].contains(&Some(block)) {
            return false;
        }
    }
    let Some(inode_table) = blocks[2] else {
        return false;
    };
    let table_blocks = u64::from(info.inodes_per_group)
        .saturating_mul(u64::from(info.inode_size))
        .div_ceil(block_size);
    if inode_table.saturating_add(table_blocks) > info.blocks_count {
        return false;
    }

    let (Some(free_blocks), Some(free_inodes), Some(used_dirs), Some(unused), Some(flags)) = (
        read_u16_le_at(desc, BG_FREE_BLOCKS_COUNT_LO),
        read_u16_le_at(desc, BG_FREE_INODES_COUNT_LO),
        read_u16_le_at(desc, BG_USED_DIRS_COUNT_LO),
        read_u16_le_at(desc, BG_ITABLE_UNUSED_LO),
        read_u16_le_at(desc, BG_FLAGS),
    ) else {
        return false;
    };
    u32::from(free_blocks) <= info.blocks_per_group
        && u32::from(free_inodes) <= info.inodes_per_group
        && u32::from(used_dirs) <= info.inodes_per_group
        && u32::from(unused) <= info.inodes_per_group
        && flags & !BG_FLAGS_KNOWN == 0
}

/// One block pointer from a group descriptor, joining its high half when the
/// filesystem is 64-bit and the descriptor is wide enough to carry one.
fn descriptor_block(desc: &[u8], lo: usize, hi: usize, wide: bool) -> Option<u64> {
    let low = u64::from(read_u32_le_at(desc, lo)?);
    if !wide {
        return Some(low);
    }
    let high = u64::from(read_u32_le_at(desc, hi)?);
    Some(low | (high << 32))
}

/// Whether the group-0 descriptor carries the checksum its filesystem's
/// features call for, and whether it matches.
///
/// A filesystem with neither checksum feature is judged on structure alone,
/// which is all ext2 ever offered.
fn descriptor_checksum_holds(buf: &[u8], info: &ExtSuperblockInfo, desc: &[u8]) -> bool {
    let Some(stored) = read_u16_le_at(desc, BG_CHECKSUM) else {
        return false;
    };
    let checksum_type = buf.get(EXT_SUPERBLOCK_OFFSET + SB_S_CHECKSUM_TYPE).copied();
    if info.feature_ro_compat & EXT_RO_COMPAT_METADATA_CSUM != 0
        && checksum_type == Some(EXT_CHECKSUM_TYPE_CRC32C)
    {
        // `INCOMPAT_CSUM_SEED` exists so the UUID can be changed on a live
        // filesystem; the seed then no longer derives from it.
        let seed = if info.feature_incompat & EXT_INCOMPAT_CSUM_SEED == 0 {
            ext4_crc32c(!0, &info.uuid)
        } else {
            read_u32_le_at(buf, EXT_SUPERBLOCK_OFFSET + SB_S_CHECKSUM_SEED).unwrap_or(0)
        };
        return descriptor_crc32c(seed, desc) == stored;
    }
    if info.feature_ro_compat & EXT_RO_COMPAT_GDT_CSUM != 0 {
        return descriptor_crc16(&info.uuid, desc) == stored;
    }
    true
}

/// The `METADATA_CSUM` checksum of the group-0 descriptor: CRC-32C over the
/// group number and the descriptor with its own checksum field zeroed,
/// truncated to 16 bits.
fn descriptor_crc32c(seed: u32, desc: &[u8]) -> u16 {
    let mut crc = ext4_crc32c(seed, &0_u32.to_le_bytes());
    crc = ext4_crc32c(crc, &desc[..BG_CHECKSUM]);
    crc = ext4_crc32c(crc, &[0_u8; 2]);
    if desc.len() > BG_CHECKSUM + 2 {
        crc = ext4_crc32c(crc, &desc[BG_CHECKSUM + 2..]);
    }
    let bytes = crc.to_le_bytes();
    u16::from_le_bytes([bytes[0], bytes[1]])
}

/// The legacy `GDT_CSUM` checksum of the group-0 descriptor: CRC-16 over the
/// UUID, the group number, and the descriptor with its checksum field left
/// out.
///
/// The two ext4 checksum paths are not symmetric, and this is where they
/// differ: `ext4_group_desc_csum` feeds a zeroed stand-in for `bg_checksum`
/// on the `METADATA_CSUM` path but simply steps over the field on this one.
/// Feeding zeros here instead produces a checksum no filesystem carries —
/// verified against a real `GDT_CSUM` volume, whose group-0 descriptor
/// checksums correctly only this way.
fn descriptor_crc16(uuid: &[u8; 16], desc: &[u8]) -> u16 {
    let mut crc = ext4_crc16(0xFFFF, uuid);
    crc = ext4_crc16(crc, &0_u32.to_le_bytes());
    crc = ext4_crc16(crc, &desc[..BG_CHECKSUM]);
    if desc.len() > BG_CHECKSUM + 2 {
        crc = ext4_crc16(crc, &desc[BG_CHECKSUM + 2..]);
    }
    crc
}

/// The kernel's raw `__crc32c_le(crc, data)`, which every ext4 metadata
/// checksum accumulates.
///
/// The `crc32c` crate offers only the pre- and post-inverted form, so the
/// raw accumulation is `!crc32c_append(!crc, data)`. It lives here rather
/// than in the ext parser because this crate is the lower layer: `fs-ext`
/// depends on it, so this is the one place both can share.
#[must_use]
pub fn ext4_crc32c(crc: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!crc, data)
}

/// ext4's legacy `GDT_CSUM` CRC-16: reflected polynomial 0xA001, initial
/// value 0xFFFF, no final inversion. Shared with `fs-ext` for the same
/// reason as [`ext4_crc32c`].
#[must_use]
pub fn ext4_crc16(crc: u16, data: &[u8]) -> u16 {
    const POLY: u16 = 0xA001;
    let mut crc = crc;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            if crc & 1 == 0 {
                crc >>= 1;
            } else {
                crc = (crc >> 1) ^ POLY;
            }
        }
    }
    crc
}
