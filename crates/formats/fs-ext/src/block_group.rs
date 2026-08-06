use alloc::vec::Vec;
use zerocopy::byteorder::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::feature_flags::{CompatFeatures, RoCompatFeatures};
use crate::io::{Read, Seek, SeekFrom};

/// Pure-data carrier for GDT-layout parameters. Constructed once at
/// [`Ext`] open and reused everywhere code needs to resolve GDT block
/// addresses (descriptor reads, mutator GDT patches, reservation
/// accounting). Fields are private so all construction goes through
/// the validating constructors.
#[derive(Clone, Debug)]
pub(crate) struct GdtLayout {
    first_data_block: u32,
    block_size: u32,
    blocks_per_group: u32,
    desc_size: u16,
    desc_per_block: u32,
    first_meta_bg: u32,
    meta_bg: bool,
    sparse_super: bool,
    sparse_super2: bool,
    backup_bgs: [u32; 2],
    group_count: u32,
    total_desc_blocks: u32,
    reserved_gdt_blocks: u16,
}

impl GdtLayout {
    /// Validating constructor used by `Ext::open_impl` and tests.
    #[expect(
        clippy::too_many_arguments,
        reason = "carrier with no obvious sub-grouping"
    )]
    pub(crate) fn from_parts(
        first_data_block: u32,
        block_size: u32,
        blocks_per_group: u32,
        desc_size: u16,
        first_meta_bg: u32,
        meta_bg: bool,
        sparse_super: bool,
        sparse_super2: bool,
        backup_bgs: [u32; 2],
        group_count: u32,
        reserved_gdt_blocks: u16,
    ) -> Result<Self> {
        if desc_size < 32 {
            return Err(ExtError::InvalidSuperblock {
                reason: "s_desc_size is below 32-byte RawGroupDesc32",
            });
        }
        if u32::from(desc_size) > block_size {
            return Err(ExtError::InvalidSuperblock {
                reason: "desc_size exceeds block_size",
            });
        }
        if !block_size.is_multiple_of(u32::from(desc_size)) {
            return Err(ExtError::InvalidSuperblock {
                reason: "block_size is not a multiple of desc_size",
            });
        }
        let desc_per_block = block_size / u32::from(desc_size);
        let total_desc_blocks = group_count.div_ceil(desc_per_block);
        if meta_bg && first_meta_bg > total_desc_blocks {
            return Err(ExtError::InvalidSuperblock {
                reason: "s_first_meta_bg exceeds descriptor block count",
            });
        }

        Ok(Self {
            first_data_block,
            block_size,
            blocks_per_group,
            desc_size,
            desc_per_block,
            first_meta_bg,
            meta_bg,
            sparse_super,
            sparse_super2,
            backup_bgs,
            group_count,
            total_desc_blocks,
            reserved_gdt_blocks,
        })
    }

    pub(crate) fn first_data_block(&self) -> u32 {
        self.first_data_block
    }

    pub(crate) fn block_size(&self) -> u32 {
        self.block_size
    }

    pub(crate) fn blocks_per_group(&self) -> u32 {
        self.blocks_per_group
    }

    pub(crate) fn desc_size(&self) -> u16 {
        self.desc_size
    }

    pub(crate) fn desc_per_block(&self) -> u32 {
        self.desc_per_block
    }

    pub(crate) fn first_meta_bg(&self) -> u32 {
        self.first_meta_bg
    }

    pub(crate) fn meta_bg(&self) -> bool {
        self.meta_bg
    }

    pub(crate) fn group_count(&self) -> u32 {
        self.group_count
    }

    pub(crate) fn total_desc_blocks(&self) -> u32 {
        self.total_desc_blocks
    }

    pub(crate) fn reserved_gdt_blocks(&self) -> u16 {
        self.reserved_gdt_blocks
    }
}

/// 32-byte base group descriptor (always present).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawGroupDesc32 {
    /// 0x00: Block bitmap location (lower 32 bits).
    pub bg_block_bitmap_lo: U32<LE>,
    /// 0x04: Inode bitmap location (lower 32 bits).
    pub bg_inode_bitmap_lo: U32<LE>,
    /// 0x08: Inode table location (lower 32 bits).
    pub bg_inode_table_lo: U32<LE>,
    /// 0x0C: Free block count (lower 16 bits).
    pub bg_free_blocks_count_lo: U16<LE>,
    /// 0x0E: Free inode count (lower 16 bits).
    pub bg_free_inodes_count_lo: U16<LE>,
    /// 0x10: Used directory count (lower 16 bits).
    pub bg_used_dirs_count_lo: U16<LE>,
    /// 0x12: Block group flags.
    pub bg_flags: U16<LE>,
    /// 0x14: Exclude bitmap location (lower 32 bits).
    pub bg_exclude_bitmap_lo: U32<LE>,
    /// 0x18: Block bitmap checksum (lower 16 bits).
    pub bg_block_bitmap_csum_lo: U16<LE>,
    /// 0x1A: Inode bitmap checksum (lower 16 bits).
    pub bg_inode_bitmap_csum_lo: U16<LE>,
    /// 0x1C: Unused inode count (lower 16 bits).
    pub bg_itable_unused_lo: U16<LE>,
    /// 0x1E: Group descriptor checksum.
    pub bg_checksum: U16<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawGroupDesc32>() == 32,
    "RawGroupDesc32 must be exactly 32 bytes"
);

/// 32-byte extension for 64-bit mode (offsets 0x20-0x3F).
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawGroupDesc64Ext {
    /// 0x20: Block bitmap location (upper 32 bits).
    pub bg_block_bitmap_hi: U32<LE>,
    /// 0x24: Inode bitmap location (upper 32 bits).
    pub bg_inode_bitmap_hi: U32<LE>,
    /// 0x28: Inode table location (upper 32 bits).
    pub bg_inode_table_hi: U32<LE>,
    /// 0x2C: Free block count (upper 16 bits).
    pub bg_free_blocks_count_hi: U16<LE>,
    /// 0x2E: Free inode count (upper 16 bits).
    pub bg_free_inodes_count_hi: U16<LE>,
    /// 0x30: Used directory count (upper 16 bits).
    pub bg_used_dirs_count_hi: U16<LE>,
    /// 0x32: Unused inode count (upper 16 bits).
    pub bg_itable_unused_hi: U16<LE>,
    /// 0x34: Exclude bitmap location (upper 32 bits).
    pub bg_exclude_bitmap_hi: U32<LE>,
    /// 0x38: Block bitmap checksum (upper 16 bits).
    pub bg_block_bitmap_csum_hi: U16<LE>,
    /// 0x3A: Inode bitmap checksum (upper 16 bits).
    pub bg_inode_bitmap_csum_hi: U16<LE>,
    /// 0x3C: Reserved.
    pub _reserved: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawGroupDesc64Ext>() == 32,
    "RawGroupDesc64Ext must be exactly 32 bytes"
);

/// Processed group descriptor with combined 64-bit fields.
#[derive(Debug)]
pub(crate) struct GroupDescriptor {
    pub inode_table: u64,
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub free_blocks_count: u32,
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "parsed for group descriptor accounting")
    )]
    pub free_inodes_count: u32,
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub flags: u16,
    pub checksum: crate::checksum::ChecksumState,
}

fn combine_u64(lo: u32, hi: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Estimate the free allocation-unit count for a group whose block bitmap was
/// previously marked uninitialized.
///
/// Mirrors the kernel shape in Linux v6.12 `fs/ext4/balloc.c`
/// `ext4_free_clusters_after_init`: start with this group's cluster count and
/// subtract metadata clusters resident in the group.
#[allow(dead_code, reason = "consumed by fast-commit replay")]
pub(crate) fn free_clusters_after_init(ext: &Ext, group: u32, gdp: &GroupDescriptor) -> u32 {
    let mut reserved = alloc::collections::BTreeSet::new();
    reserve_metadata_allocation_units(ext, group, gdp, &mut reserved);

    allocation_units_in_group(ext, group).saturating_sub(reserved.len() as u64) as u32
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
pub(crate) fn reserve_metadata_allocation_units(
    ext: &Ext,
    group: u32,
    gdp: &GroupDescriptor,
    reserved: &mut alloc::collections::BTreeSet<u64>,
) {
    let group_first = group_first_block(ext, group);
    if group_has_super(ext, group) {
        reserve_block_range_units(ext, group, group_first, 1, reserved);
    }

    // GDT blocks (classical-contiguous + META_BG primary/backups) must be
    // computed independently of group_has_super(). In pure META_BG layouts a
    // metagroup's primary GDT block can live in a non-sparse-super group
    // (for example group 32 with 1 KiB blocks and desc_per_block = 32).
    let mut gdt_blocks = alloc::collections::BTreeSet::new();
    reserve_gdt_blocks_resident_in_group(&ext.gdt_layout, group, &mut gdt_blocks);
    for &block in &gdt_blocks {
        reserve_block_range_units(ext, group, block, 1, reserved);
    }

    reserve_block_range_units(ext, group, gdp.block_bitmap, 1, reserved);
    reserve_block_range_units(ext, group, gdp.inode_bitmap, 1, reserved);

    let inode_table_bytes = u64::from(ext.inodes_per_group) * u64::from(ext.inode_size);
    let inode_table_blocks = inode_table_bytes.div_ceil(u64::from(ext.block_size));
    reserve_block_range_units(ext, group, gdp.inode_table, inode_table_blocks, reserved);
}

pub(crate) fn allocation_units_in_group(ext: &Ext, group: u32) -> u64 {
    let group_first = group_first_block(ext, group);
    if group_first >= ext.blocks_count {
        return 0;
    }
    let group_blocks = ext
        .blocks_count
        .saturating_sub(group_first)
        .min(u64::from(ext.blocks_per_group));
    group_blocks.div_ceil(u64::from(ext.blocks_per_cluster).max(1))
}

fn reserve_block_range_units(
    ext: &Ext,
    group: u32,
    start: u64,
    len: u64,
    reserved: &mut alloc::collections::BTreeSet<u64>,
) {
    let ratio = u64::from(ext.blocks_per_cluster).max(1);
    let group_first = group_first_block(ext, group);
    let group_blocks = ext
        .blocks_count
        .saturating_sub(group_first)
        .min(u64::from(ext.blocks_per_group));
    let group_last = group_first.saturating_add(group_blocks);
    let end = start.saturating_add(len).min(group_last);
    let mut block = start.max(group_first);
    while block < end {
        let local = block - group_first;
        let unit = local / ratio;
        reserved.insert(unit);
        block = group_first.saturating_add(unit.saturating_add(1).saturating_mul(ratio));
    }
}

fn group_first_block(ext: &Ext, group: u32) -> u64 {
    u64::from(ext.first_data_block)
        .saturating_add(u64::from(group).saturating_mul(u64::from(ext.blocks_per_group)))
}

pub(crate) fn group_has_super(ext: &Ext, group: u32) -> bool {
    if ext.compat.contains(CompatFeatures::SPARSE_SUPER2) {
        return group == 0
            || ext
                .backup_bgs
                .iter()
                .any(|&backup| backup != 0 && backup == group);
    }
    if !ext.ro_compat.contains(RoCompatFeatures::SPARSE_SUPER) {
        return true;
    }
    group == 0
        || group == 1
        || is_power_of(group, 3)
        || is_power_of(group, 5)
        || is_power_of(group, 7)
}

fn is_power_of(mut n: u32, base: u32) -> bool {
    if n < base {
        return false;
    }
    while n.is_multiple_of(base) {
        n /= base;
    }
    n == 1
}

/// `&GdtLayout` flavor of [`group_has_super`]. Identical logic, layout-shaped
/// inputs so `descriptor_block_loc` can run before [`Ext`] exists.
pub(crate) fn group_has_super_for_layout(layout: &GdtLayout, group: u32) -> bool {
    if layout.sparse_super2 {
        return group == 0
            || layout
                .backup_bgs
                .iter()
                .any(|&backup| backup != 0 && backup == group);
    }
    if !layout.sparse_super {
        return true;
    }
    group == 0
        || group == 1
        || is_power_of(group, 3)
        || is_power_of(group, 5)
        || is_power_of(group, 7)
}

/// Absolute block number of the GDT block holding descriptor block `desc_block_nr`.
///
/// Mirrors Linux `fs/ext4/super.c::descriptor_loc()` including the
/// 1 KiB / `first_data_block == 0` quirk.
pub(crate) fn descriptor_block_loc(layout: &GdtLayout, desc_block_nr: u32) -> u64 {
    let first_data_block = u64::from(layout.first_data_block());

    if !layout.meta_bg() || desc_block_nr < layout.first_meta_bg() {
        return first_data_block + 1 + u64::from(desc_block_nr);
    }

    let first_bg = u64::from(desc_block_nr) * u64::from(layout.desc_per_block());
    let metagroup_first_block = first_data_block + first_bg * u64::from(layout.blocks_per_group());
    let has_super = group_has_super_for_layout(layout, first_bg as u32);
    let mut nr = metagroup_first_block + u64::from(has_super);

    if layout.block_size() == 1024
        && layout.first_data_block() == 0
        && desc_block_nr == 0
        && layout.first_meta_bg() == 0
    {
        nr += 1;
    }

    nr
}

/// Absolute block number of the GDT block containing the descriptor for `group`.
pub(crate) fn descriptor_block_for_group(layout: &GdtLayout, group: u32) -> u64 {
    descriptor_block_loc(layout, group / layout.desc_per_block())
}

/// `&GdtLayout` flavor of [`group_first_block`].
pub(crate) fn group_first_block_for_layout(layout: &GdtLayout, group: u32) -> u64 {
    u64::from(layout.first_data_block())
        .saturating_add(u64::from(group).saturating_mul(u64::from(layout.blocks_per_group())))
}

/// Reserve all GDT blocks (primary or backup) that physically reside in
/// `group`. Replaces the classical-only `gdt_blocks = group_count *
/// desc_size / block_size` assumption with a META_BG-aware computation.
pub(crate) fn reserve_gdt_blocks_resident_in_group(
    layout: &GdtLayout,
    group: u32,
    reserved: &mut alloc::collections::BTreeSet<u64>,
) {
    if layout.group_count() == 0 {
        return;
    }

    let group_first = group_first_block_for_layout(layout, group);

    // Classical-prefix span: all `s_first_meta_bg` (or `total_desc_blocks`
    // when META_BG is off) contiguous GDT blocks live in every sparse-super
    // backup group, plus `reserved_gdt_blocks` reserved-resize span.
    if group_has_super_for_layout(layout, group) {
        let classical_blocks = if layout.meta_bg() {
            u64::from(layout.first_meta_bg().min(layout.total_desc_blocks()))
        } else {
            u64::from(layout.total_desc_blocks())
        };
        let len = classical_blocks + u64::from(layout.reserved_gdt_blocks());
        for offset in 0..len {
            reserved.insert(group_first + 1 + offset);
        }
    }

    // META_BG primary/backup positions: 1 GDT block per metagroup at
    // primary, 2nd-BG backup, last-BG backup. Skip when not META_BG.
    if !layout.meta_bg() {
        return;
    }
    let dpb = layout.desc_per_block();
    let group_count = layout.group_count();

    // A group can only be a primary/backup of the metagroup that contains it
    // (mg = group / dpb).  It is impossible for `group` to be, say, the
    // backup1 of mg-1, because backup1 of (mg-1) = (mg-1)*dpb + 1 = group -
    // dpb + 1, which equals `group` only when dpb == 1 — but dpb >= 16 for
    // any valid ext2/3/4 filesystem (block_size / desc_size >= 1024 / 64).
    // So a single candidate metagroup suffices and the lookup is O(1).
    let mg = group / dpb;
    if mg < layout.first_meta_bg() || mg >= layout.total_desc_blocks() {
        return;
    }
    let primary_bg = mg * dpb;
    let backup1_bg = (primary_bg + 1).min(group_count - 1);
    let backup2_bg = (primary_bg + dpb - 1).min(group_count - 1);

    // Only reserve when this BG hosts the GDT block in question.
    for bg in [primary_bg, backup1_bg, backup2_bg] {
        if bg != group {
            continue;
        }
        let bg_first = group_first_block_for_layout(layout, bg);
        let offset = u64::from(group_has_super_for_layout(layout, bg));
        reserved.insert(bg_first + offset);
    }
}

/// Read one descriptor block into `buf`, mapping `UnexpectedEof` to a
/// contextual [`ExtError::UnexpectedEof`] so truncated images surface
/// useful diagnostics instead of a bare `io::Error`.
pub(crate) fn read_descriptor_block<T: Read + Seek>(fs: &mut T, buf: &mut [u8]) -> Result<()> {
    let offset = fs.stream_position().map_err(ExtError::Io)?;
    fs.read_exact(buf).map_err(|e| match e.kind() {
        crate::io::ErrorKind::UnexpectedEof => ExtError::UnexpectedEof {
            context: "group descriptor block",
            offset,
        },
        _ => ExtError::Io(e),
    })
}

/// Read all group descriptors from the GDT.
///
/// Loops over descriptor blocks (one I/O per block) and resolves each
/// block's address via [`descriptor_block_loc`], so both classical and
/// META_BG layouts are handled uniformly. Per-descriptor parsing
/// (32-byte base + optional 32-byte 64-bit extension) and CRC32C
/// validation are unchanged.
pub(crate) fn read_group_descriptors<T: Read + Seek>(
    fs: &mut T,
    layout: &GdtLayout,
    is_64bit: bool,
    checksum_seed: Option<u32>,
) -> Result<Vec<GroupDescriptor>> {
    let block_size = layout.block_size();
    let desc_size = layout.desc_size();
    let desc_per_block = layout.desc_per_block();
    let group_count = layout.group_count();

    let mut descs = Vec::with_capacity(group_count as usize);
    let mut block_buf = alloc::vec![0u8; block_size as usize];

    for desc_block_nr in 0..layout.total_desc_blocks() {
        let block = descriptor_block_loc(layout, desc_block_nr);
        fs.seek(SeekFrom::Start(block * u64::from(block_size)))?;
        read_descriptor_block(fs, &mut block_buf)?;

        for desc_idx in 0..desc_per_block {
            let group = desc_block_nr * desc_per_block + desc_idx;
            if group >= group_count {
                break;
            }

            let off = (desc_idx as usize) * (desc_size as usize);
            let desc_bytes = &block_buf[off..off + desc_size as usize];

            let base = RawGroupDesc32::ref_from_bytes(&desc_bytes[..32]).map_err(|_| {
                ExtError::InvalidGroupDescriptor {
                    group,
                    reason: "descriptor too short",
                }
            })?;

            let (bitmap_hi, inode_bmp_hi, table_hi, free_blk_hi, free_ino_hi) = if is_64bit
                && desc_size >= 64
            {
                let ext = RawGroupDesc64Ext::ref_from_bytes(&desc_bytes[32..64]).map_err(|_| {
                    ExtError::InvalidGroupDescriptor {
                        group,
                        reason: "64-bit extension too short",
                    }
                })?;
                (
                    ext.bg_block_bitmap_hi.get(),
                    ext.bg_inode_bitmap_hi.get(),
                    ext.bg_inode_table_hi.get(),
                    ext.bg_free_blocks_count_hi.get(),
                    ext.bg_free_inodes_count_hi.get(),
                )
            } else {
                (0u32, 0u32, 0u32, 0u16, 0u16)
            };

            let csum = match checksum_seed {
                Some(seed) => crate::checksum::verify_group_descriptor(seed, group, desc_bytes),
                None => crate::checksum::ChecksumState::Unknown,
            };

            descs.push(GroupDescriptor {
                inode_table: combine_u64(base.bg_inode_table_lo.get(), table_hi),
                block_bitmap: combine_u64(base.bg_block_bitmap_lo.get(), bitmap_hi),
                inode_bitmap: combine_u64(base.bg_inode_bitmap_lo.get(), inode_bmp_hi),
                free_blocks_count: combine_u64(
                    u32::from(base.bg_free_blocks_count_lo.get()),
                    u32::from(free_blk_hi),
                ) as u32,
                free_inodes_count: combine_u64(
                    u32::from(base.bg_free_inodes_count_lo.get()),
                    u32::from(free_ino_hi),
                ) as u32,
                flags: base.bg_flags.get(),
                checksum: csum,
            });
        }
    }

    Ok(descs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_group_desc32_size() {
        assert_eq!(core::mem::size_of::<RawGroupDesc32>(), 32);
    }

    #[test]
    fn raw_group_desc64_ext_size() {
        assert_eq!(core::mem::size_of::<RawGroupDesc64Ext>(), 32);
    }

    #[test]
    fn combine_u64_works() {
        assert_eq!(combine_u64(0xDEAD_BEEF, 0x0000_0001), 0x0000_0001_DEAD_BEEF);
        assert_eq!(combine_u64(42, 0), 42);
    }

    #[test]
    fn group_has_super_uses_sparse_super2_backup_groups() {
        let ext = ext_for_free_clusters_test(
            CompatFeatures::SPARSE_SUPER2,
            RoCompatFeatures::empty(),
            0,
            [5, 9],
        );

        assert!(group_has_super(&ext, 0));
        assert!(group_has_super(&ext, 5));
        assert!(group_has_super(&ext, 9));
        assert!(!group_has_super(&ext, 1));
        assert!(!group_has_super(&ext, 3));
        assert!(!group_has_super(&ext, 7));
    }

    #[test]
    fn free_clusters_after_init_subtracts_reserved_gdt_blocks() {
        let without_reserved = ext_for_free_clusters_test(
            CompatFeatures::empty(),
            RoCompatFeatures::empty(),
            0,
            [0, 0],
        );
        let with_reserved = ext_for_free_clusters_test(
            CompatFeatures::empty(),
            RoCompatFeatures::empty(),
            2,
            [0, 0],
        );
        let gdp = GroupDescriptor {
            inode_table: 20,
            block_bitmap: 10,
            inode_bitmap: 11,
            free_blocks_count: 0,
            free_inodes_count: 0,
            flags: 0,
            checksum: crate::checksum::ChecksumState::Unknown,
        };

        assert_eq!(
            free_clusters_after_init(&with_reserved, 0, &gdp),
            free_clusters_after_init(&without_reserved, 0, &gdp) - 2
        );
    }

    #[test]
    fn free_clusters_after_init_counts_reserved_clusters_relative_to_group() {
        let ext = Ext {
            inodes_count: 64,
            blocks_count: 1024,
            block_size: 1024,
            group_count: 16,
            inodes_per_group: 4,
            inode_size: 128,
            first_data_block: 1,
            gdt_layout: GdtLayout::from_parts(
                1,
                1024,
                64,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                16,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 64,
            cluster_size: 4096,
            blocks_per_cluster: 4,
            clusters_per_group: 16,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::empty(),
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        };
        let gdp = GroupDescriptor {
            inode_table: 9,
            block_bitmap: 3,
            inode_bitmap: 4,
            free_blocks_count: 0,
            free_inodes_count: 0,
            flags: 0,
            checksum: crate::checksum::ChecksumState::Unknown,
        };

        assert_eq!(
            free_clusters_after_init(&ext, 0, &gdp),
            14,
            "metadata at absolute blocks 1,2,3,4,9 occupies local clusters 0 and 2"
        );
    }

    fn ext_for_free_clusters_test(
        compat: CompatFeatures,
        ro_compat: RoCompatFeatures,
        reserved_gdt_blocks: u16,
        backup_bgs: [u32; 2],
    ) -> Ext {
        let sparse_super = ro_compat.contains(RoCompatFeatures::SPARSE_SUPER);
        let sparse_super2 = compat.contains(CompatFeatures::SPARSE_SUPER2);
        Ext {
            inodes_count: 64,
            blocks_count: 1024,
            block_size: 1024,
            group_count: 16,
            inodes_per_group: 4,
            inode_size: 128,
            first_data_block: 1,
            gdt_layout: GdtLayout::from_parts(
                1,
                1024,
                64,
                32,
                0,
                false,
                sparse_super,
                sparse_super2,
                backup_bgs,
                16,
                reserved_gdt_blocks,
            )
            .expect("test layout"),
            blocks_per_group: 64,
            cluster_size: 1024,
            blocks_per_cluster: 1,
            clusters_per_group: 64,
            backup_bgs,
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat,
            compat,
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        }
    }

    #[test]
    fn gdt_layout_assembles_classical_layout() {
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 4096,
            desc_size: 64,
            first_data_block: 0,
            blocks_per_group: 32_768,
            group_count: 4,
            first_meta_bg: 0,
            meta_bg: false,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 7,
        })
        .expect("classical layout must validate");

        assert_eq!(layout.first_data_block(), 0);
        assert_eq!(layout.block_size(), 4096);
        assert_eq!(layout.desc_per_block(), 64);
        assert_eq!(layout.first_meta_bg(), 0);
        assert!(!layout.meta_bg());
        assert_eq!(layout.total_desc_blocks(), 1);
    }

    #[test]
    fn gdt_layout_rejects_desc_size_below_32() {
        let err = build_layout(GdtLayoutTestSpec {
            desc_size: 16,
            ..GdtLayoutTestSpec::classical_4k_64bit()
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidSuperblock { reason }
                    if reason == "s_desc_size is below 32-byte RawGroupDesc32"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn gdt_layout_rejects_desc_size_exceeds_block_size() {
        let err = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 2048,
            ..GdtLayoutTestSpec::classical_4k_64bit()
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidSuperblock { reason }
                    if reason == "desc_size exceeds block_size"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn gdt_layout_rejects_block_size_not_multiple_of_desc_size() {
        let err = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 96, // 1024 % 96 != 0
            ..GdtLayoutTestSpec::classical_4k_64bit()
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidSuperblock { reason }
                    if reason == "block_size is not a multiple of desc_size"
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn gdt_layout_rejects_first_meta_bg_exceeds_total_desc_blocks() {
        let err = build_layout(GdtLayoutTestSpec {
            meta_bg: true,
            first_meta_bg: 10, // total_desc_blocks = 1, so 10 > 1
            ..GdtLayoutTestSpec::classical_4k_64bit()
        })
        .unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidSuperblock { reason }
                    if reason == "s_first_meta_bg exceeds descriptor block count"
            ),
            "got {err:?}"
        );
    }

    #[derive(Clone, Copy)]
    struct GdtLayoutTestSpec {
        block_size: u32,
        desc_size: u16,
        first_data_block: u32,
        blocks_per_group: u32,
        group_count: u32,
        first_meta_bg: u32,
        meta_bg: bool,
        sparse_super: bool,
        sparse_super2: bool,
        backup_bgs: [u32; 2],
        reserved_gdt_blocks: u16,
    }

    impl GdtLayoutTestSpec {
        fn classical_4k_64bit() -> Self {
            Self {
                block_size: 4096,
                desc_size: 64,
                first_data_block: 0,
                blocks_per_group: 32_768,
                group_count: 4,
                first_meta_bg: 0,
                meta_bg: false,
                sparse_super: true,
                sparse_super2: false,
                backup_bgs: [0, 0],
                reserved_gdt_blocks: 0,
            }
        }
    }

    fn build_layout(spec: GdtLayoutTestSpec) -> Result<GdtLayout> {
        GdtLayout::from_parts(
            spec.first_data_block,
            spec.block_size,
            spec.blocks_per_group,
            spec.desc_size,
            spec.first_meta_bg,
            spec.meta_bg,
            spec.sparse_super,
            spec.sparse_super2,
            spec.backup_bgs,
            spec.group_count,
            spec.reserved_gdt_blocks,
        )
    }

    #[test]
    fn descriptor_block_loc_classical() {
        // first_data_block=1, classical layout.
        // desc_block_nr 0 → block 2, desc_block_nr 3 → block 5.
        let layout = build_layout(GdtLayoutTestSpec {
            first_data_block: 1,
            meta_bg: false,
            group_count: 256,
            ..GdtLayoutTestSpec::classical_4k_64bit()
        })
        .unwrap();
        assert_eq!(descriptor_block_loc(&layout, 0), 2);
        assert_eq!(descriptor_block_loc(&layout, 3), 5);
    }

    #[test]
    fn descriptor_block_loc_meta_bg_pure() {
        // 1 KiB blocks, 32-byte descs, desc_per_block = 32.
        // blocks_per_group = 1024.
        // first_data_block = 1, meta_bg = true, first_meta_bg = 0.
        // For desc_block_nr 0: metagroup 0, first_bg = 0,
        //   metagroup_first_block = 1, group_has_super(0) = true → +1 → block 2.
        // For desc_block_nr 1: metagroup 1, first_bg = 32,
        //   metagroup_first_block = 1 + 32*1024 = 32_769,
        //   group_has_super(32) = false (not 0/1/power of 3,5,7) → +0 → 32_769.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 0,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        assert_eq!(descriptor_block_loc(&layout, 0), 2);
        assert_eq!(descriptor_block_loc(&layout, 1), 32_769);
    }

    #[test]
    fn descriptor_block_loc_meta_bg_mixed() {
        // first_meta_bg = 1: desc_block_nr 0 classical, desc_block_nr 1 meta_bg.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 1,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        // Classical for desc_block_nr 0: first_data_block + 1 + 0 = 2.
        assert_eq!(descriptor_block_loc(&layout, 0), 2);
        // META_BG for desc_block_nr 1: same as meta_bg_pure case above.
        assert_eq!(descriptor_block_loc(&layout, 1), 32_769);
    }

    #[test]
    fn descriptor_block_loc_1k_quirk_first_data_block_zero() {
        // 1 KiB blocks + first_data_block = 0 + meta_bg + first_meta_bg = 0
        // + desc_block_nr = 0: +1 quirk applies.
        // Without quirk: metagroup_first_block = 0, has_super(0) = true → 1.
        // With quirk: 1 + 1 = 2.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 0,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 0,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        assert_eq!(descriptor_block_loc(&layout, 0), 2);
    }

    #[test]
    fn read_descriptor_block_maps_eof_to_contextual_error() {
        use crate::io::SeekFrom;
        let mut cursor = std::io::Cursor::new(vec![0u8; 100]);
        cursor.seek(SeekFrom::Start(50)).unwrap();
        let mut buf = [0u8; 64];
        let err = read_descriptor_block(&mut cursor, &mut buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::UnexpectedEof {
                    context: "group descriptor block",
                    offset: 50
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn read_descriptor_block_succeeds_when_data_available() {
        use std::io::Seek;
        let mut cursor = std::io::Cursor::new(vec![0xABu8; 100]);
        let mut buf = [0u8; 64];
        read_descriptor_block(&mut cursor, &mut buf).unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));
        assert_eq!(cursor.stream_position().unwrap(), 64);
    }

    #[test]
    fn descriptor_block_loc_metagroup_first_bg_no_sparse_super() {
        // 4 KiB blocks, desc_per_block = 64, blocks_per_group = 32_768.
        // Metagroup 1's first BG = 64. group_has_super(64) is false
        // (not 0, 1, or power of 3/5/7).
        // metagroup_first_block = 1 + 64*32_768 = 2_097_153 → no +1 → 2_097_153.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 4096,
            desc_size: 64,
            first_data_block: 1,
            blocks_per_group: 32_768,
            group_count: 256, // 4 desc_blocks
            first_meta_bg: 0,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        assert_eq!(descriptor_block_loc(&layout, 1), 2_097_153);
    }

    #[test]
    fn read_group_descriptors_returns_vec_in_group_order_under_mixed_mode() {
        // Layout: 1 KiB blocks, 32-byte descs, desc_per_block = 32.
        // group_count = 64 → total_desc_blocks = 2.
        // first_meta_bg = 1 → desc block 0 classical, desc block 1 META_BG.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 1,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();

        // Build an image large enough to include both GDT block locations.
        // Classical desc block 0 at block 2 (offset 2048).
        // META_BG desc block 1 at block 32_769 (offset 33_555_456 ≈ 32 MiB).
        let block_size = layout.block_size() as usize;
        let total_blocks = 32_770usize;
        let mut image = alloc::vec![0u8; total_blocks * block_size];

        // Sentinel: write a recognizable bg_block_bitmap_lo into each descriptor slot.
        // bg_block_bitmap_lo lives at byte offset 0 in RawGroupDesc32.
        write_sentinel_descriptors(&mut image, &layout);

        let mut cursor = std::io::Cursor::new(image);
        let descs = read_group_descriptors(
            &mut cursor,
            &layout,
            /* is_64bit */ false,
            /* checksum_seed */ None,
        )
        .expect("read descriptors");

        assert_eq!(descs.len(), layout.group_count() as usize);
        for (group, desc) in descs.iter().enumerate() {
            // Each test descriptor's bg_block_bitmap_lo == group sentinel.
            assert_eq!(
                desc.block_bitmap, group as u64,
                "group {group} sentinel mismatch"
            );
        }
    }

    fn write_sentinel_descriptors(image: &mut [u8], layout: &GdtLayout) {
        let block_size = layout.block_size() as usize;
        let desc_size = layout.desc_size() as usize;
        let dpb = layout.desc_per_block() as usize;
        for desc_block_nr in 0..layout.total_desc_blocks() {
            let block = descriptor_block_loc(layout, desc_block_nr) as usize;
            let block_off = block * block_size;
            for desc_idx in 0..dpb {
                let group = (desc_block_nr as usize) * dpb + desc_idx;
                if group >= layout.group_count() as usize {
                    break;
                }
                let desc_off = block_off + desc_idx * desc_size;
                // bg_block_bitmap_lo at offset 0, little-endian u32.
                image[desc_off..desc_off + 4].copy_from_slice(&(group as u32).to_le_bytes());
            }
        }
    }

    #[test]
    fn reserve_classical_only_matches_legacy_span() {
        // Group 0 with sparse-super: reserves 1 superblock + total_desc_blocks
        // contiguous GDT blocks + reserved_gdt_blocks at group_first + 1.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 4096,
            desc_size: 64,
            first_data_block: 0,
            blocks_per_group: 32_768,
            group_count: 4, // total_desc_blocks = 1
            first_meta_bg: 0,
            meta_bg: false,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 7,
        })
        .unwrap();
        let mut reserved = alloc::collections::BTreeSet::new();
        reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
        // 1 contiguous GDT block + 7 reserved_gdt_blocks = 8 blocks.
        assert_eq!(reserved.len(), 8);
        // Starting at group_first + 1 = 1.
        assert!(reserved.iter().min().copied() == Some(1));
        assert!(reserved.iter().max().copied() == Some(8));
    }

    #[test]
    fn reserve_meta_bg_pure_reserves_one_block_per_metagroup_position() {
        // 1 KiB blocks, 32-byte descs, desc_per_block = 32, blocks_per_group = 1024.
        // group_count = 64 → 2 metagroups.
        // Metagroup 0: BGs 0, 1, 31 host primary/backup1/backup2 GDT.
        // For group 0 (sparse-super): reserve 1 GDT block at descriptor_block_loc(0).
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 0,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        let mut reserved = alloc::collections::BTreeSet::new();
        reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
        // Pure META_BG, no classical span. Group 0 hosts metagroup 0's primary.
        assert_eq!(reserved.len(), 1);
        assert!(reserved.contains(&descriptor_block_loc(&layout, 0)));

        // Regression: group 32 is the primary host for metagroup 1 but is not a
        // sparse-super group. The caller must reserve META_BG primary blocks even
        // when group_has_super(group) is false.
        reserved.clear();
        reserve_gdt_blocks_resident_in_group(&layout, 32, &mut reserved);
        assert_eq!(reserved.len(), 1);
        assert!(reserved.contains(&descriptor_block_loc(&layout, 1)));

        // Backup1 of metagroup 0: group 1 (sparse-super). primary_bg+1 = 1.
        reserved.clear();
        reserve_gdt_blocks_resident_in_group(&layout, 1, &mut reserved);
        assert_eq!(reserved.len(), 1);
        assert!(
            reserved.contains(&1026),
            "group 1 backup1: bg_first(1025) + has_super(1) = 1026"
        );

        // Backup2 of metagroup 0: group 31 (non-sparse-super). primary_bg+dpb-1 = 31.
        reserved.clear();
        reserve_gdt_blocks_resident_in_group(&layout, 31, &mut reserved);
        assert_eq!(reserved.len(), 1);
        assert!(
            reserved.contains(&31_745),
            "group 31 backup2: bg_first(31745) + has_super(0) = 31745"
        );
    }

    #[test]
    fn reserve_meta_bg_mixed_classical_prefix_uses_first_meta_bg_count() {
        // first_meta_bg = 1: classical-prefix span = 1 contiguous GDT block.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 64,
            first_meta_bg: 1,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 3,
        })
        .unwrap();
        let mut reserved = alloc::collections::BTreeSet::new();
        reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
        // Group 0 (sparse-super): 1 classical GDT block + 3 reserved = 4 blocks
        // contiguous starting at group_first + 1 = 2.
        assert!(reserved.contains(&2));
        assert!(reserved.contains(&3));
        assert!(reserved.contains(&4));
        assert!(reserved.contains(&5));
        assert_eq!(reserved.len(), 4);
    }

    #[test]
    fn reserve_meta_bg_partial_last_metagroup_dedupes_backups() {
        // group_count = 33 → metagroup 1 has only 1 BG (group 32).
        // Primary, backup1 (group 33 → clamped to 32), backup2 (group 32) all collapse.
        let layout = build_layout(GdtLayoutTestSpec {
            block_size: 1024,
            desc_size: 32,
            first_data_block: 1,
            blocks_per_group: 1024,
            group_count: 33,
            first_meta_bg: 0,
            meta_bg: true,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        })
        .unwrap();
        let mut reserved = alloc::collections::BTreeSet::new();
        reserve_gdt_blocks_resident_in_group(&layout, 32, &mut reserved);
        // Group 32 hosts metagroup 1's primary; backup positions collapse onto it.
        assert_eq!(reserved.len(), 1);
        assert!(reserved.contains(&(1u64 + 32 * 1024)));
    }
}
