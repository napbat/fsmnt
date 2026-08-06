use super::{
    BTreeMap, BTreeSet, BlockClass, Ext, ExtError, GroupTally, MutatorError, MutatorResult,
    ScratchBlock,
};

/// Apply a group tally's freed counts to a raw group descriptor byte slice.
///
/// Modifies the lo and (when 64-bit) hi halves of `bg_free_blocks_count`,
/// `bg_free_inodes_count`, and `bg_used_dirs_count` in place.
///
/// Offsets (per ext4 on-disk layout):
/// - `bg_free_blocks_count_lo` at 0x0C, `_hi` at 0x2C
/// - `bg_free_inodes_count_lo` at 0x0E, `_hi` at 0x2E
/// - `bg_used_dirs_count_lo`   at 0x10, `_hi` at 0x30
pub(super) fn apply_group_tally(ext: &Ext, desc_bytes: &mut [u8], tally: GroupTally) {
    let is_64 = ext.desc_size >= 64;

    // bg_free_blocks_count: add clusters_freed, subtract clusters_allocated.
    let hi_off = is_64.then_some(0x2C);
    let current = read_desc_u32_split(desc_bytes, 0x0C, hi_off);
    let updated = current
        .saturating_add(u32::try_from(tally.clusters_freed).unwrap_or(u32::MAX))
        .saturating_sub(u32::try_from(tally.clusters_allocated).unwrap_or(u32::MAX));
    write_desc_u32_split(desc_bytes, 0x0C, hi_off, updated);

    // bg_free_inodes_count: add inodes_freed.
    let hi_off = is_64.then_some(0x2E);
    let current = read_desc_u32_split(desc_bytes, 0x0E, hi_off);
    write_desc_u32_split(
        desc_bytes,
        0x0E,
        hi_off,
        current.saturating_add(tally.inodes_freed),
    );

    // bg_used_dirs_count: subtract dirs_freed.
    let hi_off = is_64.then_some(0x30);
    let current = read_desc_u32_split(desc_bytes, 0x10, hi_off);
    write_desc_u32_split(
        desc_bytes,
        0x10,
        hi_off,
        current.saturating_sub(tally.dirs_freed),
    );
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
pub(super) fn project_block_range_to_alloc_units(
    pblk: u64,
    block_len: u32,
    ratio: u64,
    first_data_block: u64,
) -> MutatorResult<(u64, u64)> {
    if ratio == 0 {
        return Err(MutatorError::Ext(ExtError::InvalidSuperblock {
            reason: "blocks_per_cluster is zero",
        }));
    }
    let rel_start = pblk
        .checked_sub(first_data_block)
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;
    if block_len == 0 {
        return Ok((rel_start / ratio, 0));
    }
    let rel_end = rel_start
        .checked_add(u64::from(block_len))
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;
    let first = rel_start / ratio;
    let last_excl = rel_end.div_ceil(ratio);
    Ok((first, last_excl - first))
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
pub(super) fn allocation_units_per_group(ext: &Ext, ratio: u64) -> MutatorResult<u64> {
    let clusters_per_group = if ext.clusters_per_group != 0 {
        u64::from(ext.clusters_per_group)
    } else {
        u64::from(ext.blocks_per_group) / ratio
    };
    if clusters_per_group == 0 {
        return Err(MutatorError::Ext(ExtError::InvalidSuperblock {
            reason: "clusters_per_group is zero",
        }));
    }
    Ok(clusters_per_group)
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
pub(super) fn mark_bitmap_bits(
    bitmap: &mut [u8],
    bit_start: u64,
    count: u64,
    alloc: bool,
) -> MutatorResult<u32> {
    let mut changed = 0u32;
    for bit_index in bit_start..bit_start.saturating_add(count) {
        let byte = (bit_index / 8) as usize;
        let Some(slot) = bitmap.get_mut(byte) else {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: bit_index,
            }));
        };
        let mask = 1u8 << (bit_index % 8);
        let already_allocated = *slot & mask != 0;
        if alloc {
            if !already_allocated {
                *slot |= mask;
                changed = changed.saturating_add(1);
            }
        } else if already_allocated {
            *slot &= !mask;
            changed = changed.saturating_add(1);
        }
    }
    Ok(changed)
}

pub(super) fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

pub(super) fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

pub(super) fn read_desc_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

pub(super) fn write_desc_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn read_desc_u32_split(bytes: &[u8], off_lo: usize, off_hi: Option<usize>) -> u32 {
    let lo = u32::from(read_desc_u16(bytes, off_lo));
    let hi = off_hi.map_or(0, |o| u32::from(read_desc_u16(bytes, o)));
    (hi << 16) | lo
}

pub(super) fn write_desc_u32_split(
    bytes: &mut [u8],
    off_lo: usize,
    off_hi: Option<usize>,
    value: u32,
) {
    let encoded = value.to_le_bytes();
    bytes[off_lo..off_lo + 2].copy_from_slice(&encoded[..2]);
    if let Some(o) = off_hi {
        bytes[o..o + 2].copy_from_slice(&encoded[2..]);
    }
}

/// Apply accumulated free-count totals to the raw sb-host block bytes.
///
/// Modifies `s_free_blocks_count_lo` (0x0C) and `_hi` (0x150 if 64-bit),
/// and `s_free_inodes_count` (0x10) within the 1024-byte superblock region.
pub(super) fn apply_sb_tallies(
    ext: &Ext,
    sb_bytes: &mut [u8],
    clusters_freed: u64,
    inodes_freed: u64,
) {
    // The superblock occupies bytes 1024..2048 on >1 KiB-block filesystems,
    // or bytes 0..1024 on 1 KiB-block filesystems. All sb field offsets below
    // are relative to the start of the 1024-byte superblock region.
    let sb_off: usize = if ext.block_size > 1024 { 1024 } else { 0 };

    let current_lo = u32::from_le_bytes(sb_bytes[sb_off + 0x0C..sb_off + 0x10].try_into().unwrap());
    let current_hi = if ext.is_64bit {
        u32::from_le_bytes(sb_bytes[sb_off + 0x150..sb_off + 0x154].try_into().unwrap())
    } else {
        0
    };
    let current_blocks = (u64::from(current_hi) << 32) | u64::from(current_lo);
    let new_blocks = current_blocks.saturating_add(clusters_freed);
    let new_block_bytes = new_blocks.to_le_bytes();
    sb_bytes[sb_off + 0x0C..sb_off + 0x10].copy_from_slice(&new_block_bytes[..4]);
    if ext.is_64bit {
        sb_bytes[sb_off + 0x150..sb_off + 0x154].copy_from_slice(&new_block_bytes[4..]);
    }

    let current_inodes =
        u32::from_le_bytes(sb_bytes[sb_off + 0x10..sb_off + 0x14].try_into().unwrap());
    let new_inodes =
        u32::try_from(u64::from(current_inodes).saturating_add(inodes_freed)).unwrap_or(u32::MAX);
    sb_bytes[sb_off + 0x10..sb_off + 0x14].copy_from_slice(&new_inodes.to_le_bytes());
}

/// Recompute per-block checksums for all scratch blocks that carry inline
/// checksum fields (inode table, xattr, extent tree, orphan-file blocks).
///
/// Bitmap and group-descriptor checksums are handled separately in
/// `recompute_group_descriptor_checksums`.
pub(super) fn recompute_block_checksums(
    ext: &Ext,
    blocks: &mut BTreeMap<u64, ScratchBlock>,
) -> MutatorResult<()> {
    use crate::checksum;
    if !ext.has_metadata_csum() {
        return Ok(());
    }
    let seed = ext.checksum_seed.unwrap_or(0);

    // Collect the block numbers that need processing so we can iterate mutably.
    let block_nums: alloc::vec::Vec<u64> = blocks.keys().copied().collect();

    for block_num in block_nums {
        let scratch = blocks.get_mut(&block_num).expect("just collected from map");
        match scratch.class {
            BlockClass::InodeTable { .. } => {
                let inode_size = usize::from(ext.inode_size);
                let mutated: alloc::vec::Vec<u32> =
                    scratch.mutated_inodes.iter().copied().collect();
                for inum in mutated {
                    let index_in_group = (inum - 1) % ext.inodes_per_group;
                    let byte_offset_in_group = u64::from(index_in_group)
                        * u64::try_from(inode_size)
                            .expect("validated inode sizes fit in the u64 on-disk offset domain");
                    let block_size = u64::from(ext.block_size);
                    let slot_offset =
                        usize::try_from(byte_offset_in_group % block_size).map_err(|_| {
                            MutatorError::Ext(ExtError::InvalidInode {
                                inode: inum,
                                reason: "inode slot offset exceeds addressable memory",
                            })
                        })?;
                    // Zero checksum slots before computing — mirrors verify_inode feeding.
                    let slot_bytes = &mut scratch.content[slot_offset..slot_offset + inode_size];
                    // Read generation at offset 0x64 before zeroing anything.
                    let generation = u32::from_le_bytes(slot_bytes[0x64..0x68].try_into().unwrap());
                    let has_hi = inode_size > 128;
                    // Zero checksum fields before computing so they feed as 0.
                    slot_bytes[0x7C..0x7E].copy_from_slice(&[0u8; 2]);
                    if has_hi {
                        slot_bytes[0x82..0x84].copy_from_slice(&[0u8; 2]);
                    }
                    let (lo, hi) =
                        checksum::compute_inode_csum(seed, inum, generation, slot_bytes, has_hi);
                    slot_bytes[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                    if has_hi {
                        slot_bytes[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                    }
                }
            }
            BlockClass::XattrBlock => {
                // Zero h_checksum before computing.
                scratch.content[0x10..0x14].copy_from_slice(&[0u8; 4]);
                let csum = checksum::compute_xattr_block_csum(seed, block_num, &scratch.content);
                scratch.content[0x10..0x14].copy_from_slice(&csum.to_le_bytes());
            }
            BlockClass::ExtentBlock {
                owner_inode,
                owner_generation,
            } => {
                let csum = checksum::compute_extent_block_csum(
                    seed,
                    owner_inode,
                    owner_generation,
                    &scratch.content,
                );
                let eh_max = u16::from_le_bytes([scratch.content[4], scratch.content[5]]) as usize;
                let tail_off = 12 + eh_max * 12;
                if tail_off + 4 <= scratch.content.len() {
                    scratch.content[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
                }
            }
            BlockClass::OrphanFileBlock {
                file_inode,
                file_generation,
            } => {
                let csum = checksum::compute_orphan_file_block_csum(
                    seed,
                    file_inode,
                    file_generation,
                    block_num,
                    &scratch.content,
                );
                let tail_off = scratch.content.len() - 4;
                scratch.content[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
            }
            BlockClass::DirectoryBlock { block, parent_inum } => {
                debug_assert_eq!(block, block_num);
                let _ = parent_inum;
                // Directory tail checksum recompute is implemented with the
                // directory replay primitives that consume this block class.
            }
            // Bitmap csums: computed in recompute_group_descriptor_checksums.
            BlockClass::BlockBitmap { .. }
            | BlockClass::InodeBitmap { .. }
            | BlockClass::GroupDescriptor { .. }
            | BlockClass::IndirectBlock => {
                // Legacy ext2/3 indirect pointer blocks have no per-block checksum
                // on any ext filesystem version. Bitmap and descriptor checksums
                // are recomputed in `recompute_group_descriptor_checksums`.
            }
        }
    }
    Ok(())
}

/// Update GDT-level bitmap-csum fields for each dirty group's bitmap scratches,
/// then recompute `bg_checksum` for every group descriptor scratch block.
pub(super) fn recompute_group_descriptor_checksums(
    ext: &Ext,
    blocks: &mut BTreeMap<u64, ScratchBlock>,
    dirty_groups: &BTreeSet<u32>,
) -> MutatorResult<()> {
    use crate::checksum;

    let desc_size = usize::from(ext.desc_size);

    // Step A: propagate bitmap checksums into GDT scratch entries.
    if ext.has_metadata_csum() {
        let seed = ext.checksum_seed.unwrap_or(0);
        let dpb = ext.gdt_layout.desc_per_block();

        for &group in dirty_groups {
            // Compute CRC pairs under immutable borrow, then apply under
            // mutable borrow — avoids cloning full bitmap blocks (up to 64 KiB
            // each) that the previous snapshot approach required.
            let pairs: alloc::vec::Vec<(BlockClass, (u16, u16))> = blocks
                .values()
                .filter_map(|s| match s.class {
                    BlockClass::BlockBitmap { group: g } if g == group => {
                        Some((s.class, checksum::compute_bitmap_csum(seed, &s.content)))
                    }
                    BlockClass::InodeBitmap { group: g } if g == group => {
                        Some((s.class, checksum::compute_bitmap_csum(seed, &s.content)))
                    }
                    _ => None,
                })
                .collect();

            if pairs.is_empty() {
                continue;
            }

            let gdt_block = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group);
            let offset_in_block = (group % dpb) as usize * desc_size;

            let Some(gdt_scratch) = blocks.get_mut(&gdt_block) else {
                continue;
            };
            let desc_bytes = &mut gdt_scratch.content[offset_in_block..offset_in_block + desc_size];

            for (kind, (lo, hi)) in &pairs {
                match kind {
                    BlockClass::BlockBitmap { .. } => {
                        // bg_block_bitmap_csum_lo at 0x18..0x1A; _hi at 0x38..0x3A
                        desc_bytes[0x18..0x1A].copy_from_slice(&lo.to_le_bytes());
                        if desc_size >= 64 {
                            desc_bytes[0x38..0x3A].copy_from_slice(&hi.to_le_bytes());
                        }
                    }
                    BlockClass::InodeBitmap { .. } => {
                        // bg_inode_bitmap_csum_lo at 0x1A..0x1C; _hi at 0x3A..0x3C
                        desc_bytes[0x1A..0x1C].copy_from_slice(&lo.to_le_bytes());
                        if desc_size >= 64 {
                            desc_bytes[0x3A..0x3C].copy_from_slice(&hi.to_le_bytes());
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    // Step B: recompute bg_checksum on every dirty GDT scratch block.
    let gdt_blocks: alloc::vec::Vec<(u64, u32)> = blocks
        .iter()
        .filter_map(|(&b, s)| match s.class {
            BlockClass::GroupDescriptor { desc_block_nr } => Some((b, desc_block_nr)),
            _ => None,
        })
        .collect();

    let dpb = ext.gdt_layout.desc_per_block();
    for (gdt_block, desc_block_nr) in gdt_blocks {
        let Some(gdt_scratch) = blocks.get_mut(&gdt_block) else {
            continue;
        };
        let descs_per_block = usize::try_from(dpb).map_err(|_| {
            MutatorError::Ext(ExtError::InvalidGroupDescriptor {
                group: 0,
                reason: "descriptors-per-block exceeds addressable memory",
            })
        })?;
        let first_group = desc_block_nr * dpb;

        for i in 0..descs_per_block {
            let offset = i * desc_size;
            if offset + desc_size > gdt_scratch.content.len() {
                break;
            }
            let group = first_group
                + u32::try_from(i)
                    .expect("the descriptor index is bounded by descriptors_per_block");
            // Only recompute the checksum for groups that are actually dirty.
            if !dirty_groups.contains(&group) {
                continue;
            }
            let desc_bytes = &mut gdt_scratch.content[offset..offset + desc_size];
            // Zero bg_checksum before computing.
            desc_bytes[0x1E..0x20].copy_from_slice(&[0u8; 2]);
            let csum = if ext.has_metadata_csum() {
                let seed = ext.checksum_seed.unwrap_or(0);
                checksum::compute_group_descriptor_csum_crc32c(seed, group, desc_bytes)
            } else if ext.has_gdt_csum() {
                checksum::compute_group_descriptor_csum_crc16(&ext.uuid, group, desc_bytes)
            } else {
                continue;
            };
            desc_bytes[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
        }
    }

    Ok(())
}
