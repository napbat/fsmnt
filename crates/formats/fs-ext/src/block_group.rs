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
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical ext4 bg_* on-disk identifiers"
)]
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

    u32::try_from(
        allocation_units_in_group(ext, group).saturating_sub(
            u64::try_from(reserved.len())
                .expect("the number of reserved units fits in the u64 filesystem count"),
        ),
    )
    .expect("one block group cannot contain more than u32::MAX allocation units")
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
    let has_super = group_has_super_for_layout(
        layout,
        u32::try_from(first_bg)
            .expect("a valid descriptor block cannot address a group above u32::MAX"),
    );
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
/// `META_BG` layouts are handled uniformly. Per-descriptor parsing
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
                free_blocks_count: u32::from(base.bg_free_blocks_count_lo.get())
                    | (u32::from(free_blk_hi) << 16),
                free_inodes_count: u32::from(base.bg_free_inodes_count_lo.get())
                    | (u32::from(free_ino_hi) << 16),
                flags: base.bg_flags.get(),
                checksum: csum,
            });
        }
    }

    Ok(descs)
}

#[cfg(test)]
#[path = "block_group_tests/mod.rs"]
mod tests;
