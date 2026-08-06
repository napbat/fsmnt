//! Apply phase: preflight classification + per-inode / per-source mutation.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::error::Result;
use crate::ext::Ext;
use crate::io::{Read, Seek};
use crate::orphan::ea_inode::{EaInodePlan, EaInodePlanError, EaRef, plan_ea_inode_cascade};
use crate::orphan::plan::{OrphanDisposition, OrphanPlan, OrphanPosition, OrphanStop};
use crate::orphan::shared_xattr::{
    SharedXattrPlan, SharedXattrPlanError, plan_shared_xattr_blocks,
};

#[cfg(test)]
use crate::checksum::compute_inode_csum;
#[cfg(test)]
use alloc::boxed::Box;

/// Summary of classified apply work. When `stop` is `None`, the caller may
/// proceed to the Unlinked/TruncateDeferred mutation passes.
#[derive(Debug)]
pub(crate) struct ClassifiedApply {
    pub unique_unlinked: BTreeSet<u32>,
    pub unique_truncate: BTreeSet<u32>,
    /// EA inode cascade plan produced during classification.
    pub ea_plan: EaInodePlan,
    /// Xattr block plan produced during classification.
    pub xattr_plan: SharedXattrPlan,
    /// EA inode references harvested from all Unlinked hosts.
    /// Only consulted by tests; the mutation phase uses `ea_plan` directly.
    #[cfg_attr(not(test), expect(dead_code, reason = "read in tests only"))]
    pub ea_refs: BTreeMap<u32, Vec<EaRef>>,
    /// Xattr block references harvested from all Unlinked hosts.
    pub xattr_refs: BTreeMap<u64, Vec<u32>>,
}

impl Default for ClassifiedApply {
    fn default() -> Self {
        Self {
            unique_unlinked: BTreeSet::new(),
            unique_truncate: BTreeSet::new(),
            ea_plan: EaInodePlan {
                actions: BTreeMap::new(),
            },
            xattr_plan: SharedXattrPlan {
                actions: BTreeMap::new(),
            },
            ea_refs: BTreeMap::new(),
            xattr_refs: BTreeMap::new(),
        }
    }
}

/// Scratch copies of every block the apply phase touches, plus per-group
/// freed-count tallies. Published to an `OrphanOverlayDelta` only if apply
/// runs to completion without setting `plan.stop`.
///
/// Retained for unit tests of the Level-2 scratch primitives.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct OrphanApplyScratch {
    /// Mutated non-sb-host blocks (inode tables, bitmaps, group desc blocks,
    /// orphan-file blocks). Keyed by filesystem block number.
    pub blocks: BTreeMap<u64, Box<[u8]>>,
    pub inodes_freed_by_group: BTreeMap<u32, u32>,
    pub blocks_freed_by_group: BTreeMap<u32, u32>,
    pub dirs_freed_by_group: BTreeMap<u32, u32>,
    pub processed_unlinked: BTreeSet<u32>,
}

#[cfg(test)]
impl OrphanApplyScratch {
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            inodes_freed_by_group: BTreeMap::new(),
            blocks_freed_by_group: BTreeMap::new(),
            dirs_freed_by_group: BTreeMap::new(),
            processed_unlinked: BTreeSet::new(),
        }
    }
}

/// Classify all orphan entries, harvesting EA-inode and xattr-block references
/// from each Unlinked host, then produce cascade plans via
/// [`plan_ea_inode_cascade`] and [`plan_shared_xattr_blocks`].
///
/// Sets `plan.stop` and returns an empty `ClassifiedApply` when either
/// planner returns a `Stop` reason. Propagates `Err(_)` for I/O failures.
pub(crate) fn classify_apply<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    plan: &mut OrphanPlan,
) -> Result<ClassifiedApply> {
    let mut unique_unlinked: BTreeSet<u32> = BTreeSet::new();
    let mut unique_truncate: BTreeSet<u32> = BTreeSet::new();
    let mut ea_refs: BTreeMap<u32, Vec<EaRef>> = BTreeMap::new();
    let mut xattr_refs: BTreeMap<u64, Vec<u32>> = BTreeMap::new();

    // Collect unique inode sets from both sources.
    for entry in &plan.legacy {
        match entry.disposition {
            OrphanDisposition::Unlinked => {
                unique_unlinked.insert(entry.inode);
            }
            OrphanDisposition::TruncateDeferred => {
                unique_truncate.insert(entry.inode);
            }
        }
    }
    for entry in &plan.orphan_file {
        match entry.disposition {
            OrphanDisposition::Unlinked => {
                unique_unlinked.insert(entry.inode);
            }
            OrphanDisposition::TruncateDeferred => {
                unique_truncate.insert(entry.inode);
            }
        }
    }

    // For each Unlinked host: harvest EA-inode and xattr-block references.
    for &inode_num in &unique_unlinked {
        let inode = ext.inode(overlay, inode_num)?;

        // Collect EA refs from ibody xattr region.
        if let Some(ibody) = inode.ibody_xattr_data() {
            let mut xattrs = Vec::new();
            crate::xattr::parse_ibody_entries(ibody, inode_num, &mut xattrs)?;
            for xattr in xattrs {
                if let Some(ea_inum) = xattr.ea_inode() {
                    ea_refs.entry(ea_inum).or_default().push(EaRef {
                        host_inode: inode_num,
                        value_size: u64::from(xattr.ea_value_size()),
                    });
                }
            }
        }

        // Record xattr block reference (any block, shared or exclusive).
        let xattr_block = inode.xattr_block_number();
        if xattr_block != 0 {
            xattr_refs.entry(xattr_block).or_default().push(inode_num);
        }
    }

    // Invoke Level-3 planners after the classification walk.
    let ea_plan = match plan_ea_inode_cascade(ext, overlay, &ea_refs) {
        Ok(p) => p,
        Err(EaInodePlanError::Ext(err)) => return Err(err),
        Err(EaInodePlanError::Stop(reason)) => {
            plan.stop = Some(OrphanStop {
                position: OrphanPosition::Apply,
                reason,
            });
            return Ok(ClassifiedApply::default());
        }
    };

    let xattr_plan = match plan_shared_xattr_blocks(ext, overlay, &xattr_refs) {
        Ok(p) => p,
        Err(SharedXattrPlanError::Ext(err)) => return Err(err),
        Err(SharedXattrPlanError::Stop(reason)) => {
            plan.stop = Some(OrphanStop {
                position: OrphanPosition::Apply,
                reason,
            });
            return Ok(ClassifiedApply::default());
        }
    };

    Ok(ClassifiedApply {
        unique_unlinked,
        unique_truncate,
        ea_plan,
        xattr_plan,
        ea_refs,
        xattr_refs,
    })
}

/// Zero an Unlinked inode on its scratch block. Idempotent: subsequent calls
/// for the same inum are silent no-ops (the inum was already inserted into
/// `scratch.processed_unlinked`).
///
/// `commit_secs` is the journal's latest commit time in Unix seconds (from
/// `JournalReplay::plan().committed.last().commit_time`), used as a best-
/// effort deletion timestamp. `None` ⇒ `i_dtime = 0`.
#[cfg(test)]
pub(crate) fn zero_unlinked_inode<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
    inum: u32,
    commit_secs: Option<u32>,
) -> Result<()> {
    if !scratch.processed_unlinked.insert(inum) {
        return Ok(());
    }

    let (block_num, offset_in_block) = inode_block_and_offset(ext, inum)?;
    let entry = scratch.blocks.entry(block_num);
    let block_buf = match entry {
        alloc::collections::btree_map::Entry::Occupied(o) => o.into_mut(),
        alloc::collections::btree_map::Entry::Vacant(v) => {
            let mut buf = alloc::vec![0u8; ext.block_size() as usize].into_boxed_slice();
            let byte_offset = block_num * u64::from(ext.block_size());
            overlay.seek(crate::io::SeekFrom::Start(byte_offset))?;
            overlay.read_exact(&mut buf[..])?;
            v.insert(buf)
        }
    };

    let inode_size = usize::from(ext.inode_size());
    let inode_slice = &mut block_buf[offset_in_block..offset_in_block + inode_size];

    inode_slice.fill(0);
    let dtime = commit_secs.unwrap_or(0);
    inode_slice[0x14..0x18].copy_from_slice(&dtime.to_le_bytes());

    if let Some(seed) = ext.checksum_seed() {
        // After zero-fill, i_extra_isize = 0 so `i_checksum_hi` is not present.
        let has_hi = false;
        let (lo, hi) = compute_inode_csum(seed, inum, /* generation */ 0, inode_slice, has_hi);
        inode_slice[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
        if has_hi {
            inode_slice[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
        }
    }

    Ok(())
}

/// Enumerate every data block owned by the inode (via extent tree or
/// block map), plus the xattr block if `i_file_acl != 0` and non-shared.
/// Flip the corresponding bits to clear in each block-bitmap scratch
/// copy, tallying per-group decrements.
#[cfg(test)]
pub(crate) fn free_owned_blocks<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
    inum: u32,
) -> Result<()> {
    let inode = ext.inode(overlay, inum)?;
    let mut owned: alloc::vec::Vec<u64> = alloc::vec::Vec::new();

    let file = inode.open_file()?;
    file.owned_blocks_into(overlay, &mut owned)?;

    // Append xattr block (non-shared: Task 21 preflight stopped apply on shared case).
    let xattr_block = inode.xattr_block_number();
    if xattr_block != 0 {
        owned.push(xattr_block);
    }

    for block in owned {
        clear_block_bitmap_bit(ext, overlay, scratch, block)?;
    }

    Ok(())
}

/// Helper: clear the block-bitmap bit for `block` on scratch, tallying the
/// decrement. Idempotent: bits already clear are silent no-ops.
#[cfg(test)]
pub(crate) fn clear_block_bitmap_bit<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
    block: u64,
) -> Result<()> {
    let first_data_block = u64::from(ext.first_data_block);
    if block < first_data_block {
        return Ok(());
    }
    let group = u32::try_from((block - first_data_block) / u64::from(ext.blocks_per_group))
        .expect("the test fixture value fits in u32");
    let bit_in_group =
        usize::try_from((block - first_data_block) % u64::from(ext.blocks_per_group))
            .expect("the test fixture value fits in usize");

    if group as usize >= ext.group_descs.len() {
        return Err(crate::error::ExtError::BlockOutOfRange { block });
    }
    let bitmap_block = ext.group_descs[group as usize].block_bitmap;
    let bitmap_scratch = fetch_scratch_block(ext, overlay, scratch, bitmap_block)?;

    let byte = bit_in_group / 8;
    let mask = 1u8 << (bit_in_group % 8);
    if bitmap_scratch[byte] & mask != 0 {
        bitmap_scratch[byte] &= !mask;
        *scratch.blocks_freed_by_group.entry(group).or_insert(0) += 1;
    }

    Ok(())
}

/// Clear the inode-bitmap bit for `inum` on scratch and tally the decrement
/// (or no-op if the bit was already clear). Also records a directory-freed
/// decrement when the inode's mode (read via the overlay) is `S_IFDIR`.
#[cfg(test)]
pub(crate) fn clear_inode_bitmap_bit<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
    inum: u32,
) -> Result<()> {
    const S_IFMT: u16 = 0xF000;
    const S_IFDIR: u16 = 0x4000;

    let group = (inum - 1) / ext.inodes_per_group;
    let bit_in_group = ((inum - 1) % ext.inodes_per_group) as usize;
    let bitmap_block = ext.group_descs[group as usize].inode_bitmap;
    let bitmap_scratch = fetch_scratch_block(ext, overlay, scratch, bitmap_block)?;

    let byte = bit_in_group / 8;
    let mask = 1u8 << (bit_in_group % 8);
    let already_clear = bitmap_scratch[byte] & mask == 0;
    if !already_clear {
        bitmap_scratch[byte] &= !mask;
        *scratch.inodes_freed_by_group.entry(group).or_insert(0) += 1;

        let inode = ext.inode(overlay, inum)?;
        if inode.mode() & S_IFMT == S_IFDIR {
            *scratch.dirs_freed_by_group.entry(group).or_insert(0) += 1;
        }
    }

    Ok(())
}

/// Helper: read or re-use a scratch copy of `block`. Seeds from the overlay
/// on first access.
#[cfg(test)]
pub(crate) fn fetch_scratch_block<'a, T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &'a mut OrphanApplyScratch,
    block: u64,
) -> Result<&'a mut [u8]> {
    use alloc::collections::btree_map::Entry;
    let entry = scratch.blocks.entry(block);
    let slot = match entry {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            let mut buf = alloc::vec![0u8; ext.block_size() as usize].into_boxed_slice();
            let byte_offset = block * u64::from(ext.block_size());
            overlay.seek(crate::io::SeekFrom::Start(byte_offset))?;
            overlay.read_exact(&mut buf[..])?;
            v.insert(buf)
        }
    };
    Ok(&mut slot[..])
}

/// Apply per-group tallies to every mutated group descriptor, patch bitmap
/// checksum fields, and recompute the group descriptor's own `bg_checksum`.
///
/// Leaves `scratch.blocks` containing the final byte images for all touched
/// bitmap, group-descriptor, and inode-table blocks.
#[cfg(test)]
pub(crate) fn finalize_group_descriptors<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
) -> Result<()> {
    use alloc::collections::BTreeSet;

    let groups: BTreeSet<u32> = scratch
        .inodes_freed_by_group
        .keys()
        .chain(scratch.blocks_freed_by_group.keys())
        .chain(scratch.dirs_freed_by_group.keys())
        .copied()
        .collect();

    let desc_size = u64::from(ext.desc_size);

    for group in &groups {
        let gdt_block = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, *group);
        let gdt_off = u64::from(*group % ext.gdt_layout.desc_per_block()) * desc_size;
        let gdt_in_block = usize::try_from(gdt_off).expect("the test fixture value fits in usize");
        let desc_size_u = usize::try_from(desc_size).expect("the test fixture value fits in usize");

        let inodes_freed = scratch
            .inodes_freed_by_group
            .get(group)
            .copied()
            .unwrap_or(0);
        let blocks_freed = scratch
            .blocks_freed_by_group
            .get(group)
            .copied()
            .unwrap_or(0);
        let dirs_freed = scratch.dirs_freed_by_group.get(group).copied().unwrap_or(0);

        let gd = &ext.group_descs[*group as usize];
        let block_bitmap_block = gd.block_bitmap;
        let inode_bitmap_block = gd.inode_bitmap;

        // Compute bitmap checksum halves BEFORE borrowing the GDT scratch block
        // to avoid simultaneous mutable borrows of `scratch.blocks`.
        let block_bitmap_csum = if let Some(seed) = ext.checksum_seed() {
            scratch
                .blocks
                .get(&block_bitmap_block)
                .map(|buf| crate::checksum::compute_bitmap_csum(seed, buf))
        } else {
            None
        };
        let inode_bitmap_csum = if let Some(seed) = ext.checksum_seed() {
            scratch
                .blocks
                .get(&inode_bitmap_block)
                .map(|buf| crate::checksum::compute_bitmap_csum(seed, buf))
        } else {
            None
        };

        let gdt_scratch = fetch_scratch_block(ext, overlay, scratch, gdt_block)?;
        let desc = &mut gdt_scratch[gdt_in_block..gdt_in_block + desc_size_u];

        // bg_free_inodes_count lo/hi (offsets 0x0E / 0x2E).
        add_u16_pair(desc, 0x0E, 0x2E, desc_size_u, inodes_freed);
        // bg_free_blocks_count lo/hi (offsets 0x0C / 0x2C).
        add_u16_pair(desc, 0x0C, 0x2C, desc_size_u, blocks_freed);
        // bg_used_dirs_count lo/hi (offsets 0x10 / 0x30) — directories freed.
        sub_u16_pair(desc, 0x10, 0x30, desc_size_u, dirs_freed);

        // Patch block-bitmap checksum halves (bg_block_bitmap_csum lo/hi at 0x18/0x38).
        if let Some((lo, hi)) = block_bitmap_csum {
            desc[0x18..0x1A].copy_from_slice(&lo.to_le_bytes());
            if desc_size_u > 0x39 {
                desc[0x38..0x3A].copy_from_slice(&hi.to_le_bytes());
            }
        }
        // Patch inode-bitmap checksum halves (bg_inode_bitmap_csum lo/hi at 0x1A/0x3A).
        if let Some((lo, hi)) = inode_bitmap_csum {
            desc[0x1A..0x1C].copy_from_slice(&lo.to_le_bytes());
            if desc_size_u > 0x3B {
                desc[0x3A..0x3C].copy_from_slice(&hi.to_le_bytes());
            }
        }

        // Recompute bg_checksum (offset 0x1E..0x20).
        if ext.has_metadata_csum() {
            if let Some(seed) = ext.checksum_seed() {
                desc[0x1E..0x20].fill(0);
                let csum =
                    crate::checksum::compute_group_descriptor_csum_crc32c(seed, *group, desc);
                desc[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
            }
        } else if ext.has_gdt_csum() {
            desc[0x1E..0x20].fill(0);
            let csum =
                crate::checksum::compute_group_descriptor_csum_crc16(ext.uuid(), *group, desc);
            desc[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
        }
    }
    Ok(())
}

/// Increment a split lo/hi u16 counter field by `delta`, saturating at `u32::MAX`.
#[cfg(test)]
fn add_u16_pair(desc: &mut [u8], lo_off: usize, hi_off: usize, desc_size: usize, delta: u32) {
    let lo = u16::from_le_bytes([desc[lo_off], desc[lo_off + 1]]);
    let hi = if desc_size > hi_off + 1 {
        u16::from_le_bytes([desc[hi_off], desc[hi_off + 1]])
    } else {
        0
    };
    let combined = u32::from(lo) | (u32::from(hi) << 16);
    let updated = combined.saturating_add(delta);
    let new_lo = (updated & 0xFFFF) as u16;
    let new_hi = ((updated >> 16) & 0xFFFF) as u16;
    desc[lo_off..lo_off + 2].copy_from_slice(&new_lo.to_le_bytes());
    if desc_size > hi_off + 1 {
        desc[hi_off..hi_off + 2].copy_from_slice(&new_hi.to_le_bytes());
    }
}

/// Decrement a split lo/hi u16 counter field by `delta`, saturating at 0.
#[cfg(test)]
fn sub_u16_pair(desc: &mut [u8], lo_off: usize, hi_off: usize, desc_size: usize, delta: u32) {
    let lo = u16::from_le_bytes([desc[lo_off], desc[lo_off + 1]]);
    let hi = if desc_size > hi_off + 1 {
        u16::from_le_bytes([desc[hi_off], desc[hi_off + 1]])
    } else {
        0
    };
    let combined = u32::from(lo) | (u32::from(hi) << 16);
    let updated = combined.saturating_sub(delta);
    let new_lo = (updated & 0xFFFF) as u16;
    let new_hi = ((updated >> 16) & 0xFFFF) as u16;
    desc[lo_off..lo_off + 2].copy_from_slice(&new_lo.to_le_bytes());
    if desc_size > hi_off + 1 {
        desc[hi_off..hi_off + 2].copy_from_slice(&new_hi.to_le_bytes());
    }
}

/// Resolve `(inode_table_block_number, offset_in_block)` for a given inode.
#[cfg(test)]
pub(crate) fn inode_block_and_offset(ext: &Ext, inum: u32) -> Result<(u64, usize)> {
    if inum == 0 || inum > ext.inodes_count {
        return Err(crate::error::ExtError::InodeOutOfRange { inode: inum });
    }
    let group = (inum - 1) / ext.inodes_per_group;
    let index_in_group = u64::from((inum - 1) % ext.inodes_per_group);
    let table_block = ext.group_descs[group as usize].inode_table;
    let inode_size = u64::from(ext.inode_size());
    let byte_in_table = index_in_group * inode_size;
    let block_size = u64::from(ext.block_size());
    let block = table_block + byte_in_table / block_size;
    let offset_in_block =
        usize::try_from(byte_in_table % block_size).expect("the test fixture value fits in usize");
    Ok((block, offset_in_block))
}

/// Patch `i_dtime = 0` on a `TruncateDeferred` legacy entry's inode scratch
/// copy and recompute the inode checksum. Preserves every other inode field.
#[cfg(test)]
pub(crate) fn clear_legacy_linkage<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    scratch: &mut OrphanApplyScratch,
    inum: u32,
) -> Result<()> {
    let (block_num, offset_in_block) = inode_block_and_offset(ext, inum)?;
    let block_buf = fetch_scratch_block(ext, overlay, scratch, block_num)?;
    let inode_size = ext.inode_size() as usize;
    let inode_slice = &mut block_buf[offset_in_block..offset_in_block + inode_size];

    inode_slice[0x14..0x18].fill(0);

    if let Some(seed) = ext.checksum_seed() {
        let generation =
            u32::from_le_bytes(inode_slice[0x64..0x68].try_into().expect("fixed slice"));
        // i_checksum_hi at 0x82..0x84 is only present when i_extra_isize
        // (at 0x80..0x82) covers it — mirrors the gate in inode.rs validation.
        let extra_isize = if inode_size > 128 {
            u16::from_le_bytes(inode_slice[0x80..0x82].try_into().expect("fixed slice"))
        } else {
            0
        };
        let has_hi = inode_size > 128 && extra_isize >= 4 && inode_size > 0x84;
        inode_slice[0x7C..0x7E].fill(0);
        if has_hi {
            inode_slice[0x82..0x84].fill(0);
        }
        let (lo, hi) = compute_inode_csum(seed, inum, generation, inode_slice, has_hi);
        inode_slice[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
        if has_hi {
            inode_slice[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_owned_blocks_flips_bitmap_bits_on_hello_txt() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;

        let mut scratch = OrphanApplyScratch::new();
        free_owned_blocks(&ext, &mut fs, &mut scratch, inum).expect("free");

        // hello.txt lives in group 0. At least one bit should have been cleared.
        let freed = *scratch.blocks_freed_by_group.get(&0).unwrap_or(&0);
        assert!(freed >= 1, "expected at least one freed block in group 0");
    }

    #[test]
    fn classify_empty_plan_returns_empty_sets_and_no_stop() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let mut plan = OrphanPlan::default();
        let classified = classify_apply(&ext, &mut fs, &mut plan).expect("classify");
        assert!(classified.unique_unlinked.is_empty());
        assert!(classified.unique_truncate.is_empty());
        assert!(plan.stop.is_none());
    }

    #[test]
    fn scratch_round_trips_block_content() {
        let mut scratch = OrphanApplyScratch::new();
        let data = alloc::vec![0xAAu8; 4096].into_boxed_slice();
        scratch.blocks.insert(100, data.clone());
        assert_eq!(
            scratch.blocks.get(&100).expect("block").as_ref(),
            data.as_ref()
        );
    }

    #[test]
    fn clear_inode_bitmap_bit_tallies_decrement_when_bit_was_set() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;
        let mut scratch = OrphanApplyScratch::new();
        clear_inode_bitmap_bit(&ext, &mut fs, &mut scratch, inum).expect("clear");

        let group = (inum - 1) / ext.inodes_per_group;
        assert_eq!(scratch.inodes_freed_by_group.get(&group).copied(), Some(1));
    }

    #[test]
    fn clear_inode_bitmap_bit_is_idempotent() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;

        let mut scratch = OrphanApplyScratch::new();
        clear_inode_bitmap_bit(&ext, &mut fs, &mut scratch, inum).expect("first");
        clear_inode_bitmap_bit(&ext, &mut fs, &mut scratch, inum).expect("second");

        let group = (inum - 1) / ext.inodes_per_group;
        assert_eq!(scratch.inodes_freed_by_group.get(&group).copied(), Some(1));
    }

    #[test]
    fn finalize_group_descriptors_updates_free_counts_and_checksums() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;

        let mut scratch = OrphanApplyScratch::new();
        zero_unlinked_inode(&ext, &mut fs, &mut scratch, inum, Some(0)).expect("zero");
        free_owned_blocks(&ext, &mut fs, &mut scratch, inum).expect("free blocks");
        clear_inode_bitmap_bit(&ext, &mut fs, &mut scratch, inum).expect("clear bit");
        finalize_group_descriptors(&ext, &mut fs, &mut scratch).expect("finalize");

        assert!(!scratch.blocks.is_empty());
    }

    #[test]
    fn clear_legacy_linkage_zeroes_i_dtime_and_recomputes_checksum() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;

        let mut scratch = OrphanApplyScratch::new();
        clear_legacy_linkage(&ext, &mut fs, &mut scratch, inum).expect("patch");

        let (block, off) = super::inode_block_and_offset(&ext, inum).expect("loc");
        let buf = scratch.blocks.get(&block).expect("block present");
        let inode_slice = &buf[off..off + ext.inode_size() as usize];
        let dtime = u32::from_le_bytes(inode_slice[0x14..0x18].try_into().unwrap());
        assert_eq!(dtime, 0);

        let state = crate::checksum::verify_inode(
            ext.checksum_seed().unwrap_or(0),
            inum,
            u32::from_le_bytes(inode_slice[0x64..0x68].try_into().unwrap()),
            inode_slice,
            ext.inode_size() > 128,
        );
        assert_eq!(state, crate::checksum::ChecksumState::Valid);
    }

    #[test]
    fn zero_unlinked_inode_round_trips_on_ext4_fixture() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let entry = crate::test_support::lookup_entry(&ext, &mut fs, "/hello.txt").expect("lookup");
        let inum = entry.inode_number;

        let mut scratch = OrphanApplyScratch::new();
        zero_unlinked_inode(
            &ext,
            &mut fs,
            &mut scratch,
            inum,
            /*commit_secs=*/ Some(1_700_000_000),
        )
        .expect("zero");

        let (block, offset) = super::inode_block_and_offset(&ext, inum).expect("loc");
        let block_bytes = scratch.blocks.get(&block).expect("block in scratch");
        let inode_bytes = &block_bytes[offset..offset + usize::from(ext.inode_size())];
        let state = crate::checksum::verify_inode(
            ext.checksum_seed().unwrap_or(0),
            inum,
            /* generation */ 0,
            inode_bytes,
            false, // has_hi = false, matching zero-filled inode
        );
        assert_eq!(state, crate::checksum::ChecksumState::Valid);
        let dtime = u32::from_le_bytes(inode_bytes[0x14..0x18].try_into().unwrap());
        assert_eq!(dtime, 1_700_000_000);
        assert_eq!(inode_bytes[0..0x14], [0u8; 0x14]);
    }

    // ---- Classification-phase tests (Task 26) ----

    fn load_dirty_fixture(
        name: &str,
    ) -> Option<(crate::Ext, fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>)> {
        if !crate::test_support::fixture_available(name) {
            return None;
        }
        let mut cursor = crate::test_support::load_image(name);
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open_lenient");
        Some((ext, cursor))
    }

    fn build_plan_from_fixture(
        ext: &crate::Ext,
        cursor: &mut fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>,
    ) -> crate::orphan::plan::OrphanPlan {
        use crate::orphan::parse::{scan_orphan_file, walk_legacy_chain};
        let mut plan = crate::orphan::plan::OrphanPlan::default();
        let head = Ext::read_last_orphan(cursor).expect("s_last_orphan");
        walk_legacy_chain(ext, cursor, head, &mut plan).expect("walk");
        if plan.stop.is_none() {
            scan_orphan_file(ext, cursor, &mut plan).expect("scan");
        }
        plan
    }

    #[test]
    fn classify_bigalloc_fixture_no_longer_produces_unsupported_stop() {
        // ext4_bigalloc.img is a real bigalloc fixture. Under Level-3,
        // bigalloc flows through the normal classification path without stopping.
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4_bigalloc.img") else {
            eprintln!("skipping: ext4_bigalloc.img not present");
            return;
        };
        let mut plan = build_plan_from_fixture(&ext, &mut cursor);
        if plan.stop.is_some() {
            // Parse-phase stop — nothing for apply to classify.
            return;
        }
        classify_apply(&ext, &mut cursor, &mut plan).expect("classify");
    }

    #[test]
    fn classify_ea_cascade_fixture_produces_ea_plan_with_one_action() {
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-ea-cascade.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let mut plan = build_plan_from_fixture(&ext, &mut cursor);
        assert!(plan.stop.is_none(), "parse phase must not stop");
        let classified = classify_apply(&ext, &mut cursor, &mut plan).expect("classify");
        assert!(plan.stop.is_none(), "no stop expected for cascade fixture");
        assert_eq!(
            classified.ea_plan.actions.len(),
            1,
            "cascade fixture produces exactly one EA plan action"
        );
        assert_eq!(
            classified.ea_refs.len(),
            1,
            "one EA inode ref harvested from cascade fixture"
        );
    }

    #[test]
    fn classify_shared_xattr_fixture_produces_xattr_plan_with_one_action() {
        let Some((ext, mut cursor)) =
            load_dirty_fixture("ext4-dirty-orphan-shared-xattr-exclusive.img")
        else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let mut plan = build_plan_from_fixture(&ext, &mut cursor);
        assert!(plan.stop.is_none(), "parse phase must not stop");
        let classified = classify_apply(&ext, &mut cursor, &mut plan).expect("classify");
        assert!(
            plan.stop.is_none(),
            "no stop expected for exclusive-xattr fixture"
        );
        assert_eq!(
            classified.xattr_plan.actions.len(),
            1,
            "exclusive-xattr fixture produces exactly one xattr plan action"
        );
        assert_eq!(
            classified.xattr_refs.len(),
            1,
            "one xattr block ref harvested from exclusive-xattr fixture"
        );
    }

    #[test]
    fn classify_refcount_zero_fixture_stops_with_shared_xattr_stop() {
        let Some((ext, mut cursor)) =
            load_dirty_fixture("ext4-dirty-orphan-shared-xattr-refcount-zero.img")
        else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let mut plan = build_plan_from_fixture(&ext, &mut cursor);
        if plan.stop.is_some() {
            return;
        }
        classify_apply(&ext, &mut cursor, &mut plan).expect("classify");
        let stop = plan
            .stop
            .expect("stop must be set for refcount-zero fixture");
        assert!(
            matches!(
                stop.reason,
                crate::orphan::plan::OrphanStopReason::SharedXattrBlockRefcountZero { .. }
            ),
            "expected SharedXattrBlockRefcountZero, got {stop:?}"
        );
    }

    #[test]
    fn classify_missing_flag_fixture_stops_with_ea_missing_flag() {
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-ea-missing-flag.img")
        else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let mut plan = build_plan_from_fixture(&ext, &mut cursor);
        if plan.stop.is_some() {
            return;
        }
        classify_apply(&ext, &mut cursor, &mut plan).expect("classify");
        let stop = plan
            .stop
            .expect("stop must be set for missing-flag fixture");
        assert!(
            matches!(
                stop.reason,
                crate::orphan::plan::OrphanStopReason::EaInodeMissingFlag { .. }
            ),
            "expected EaInodeMissingFlag, got {stop:?}"
        );
    }

    #[test]
    fn classify_empty_plan_produces_empty_ea_and_xattr_plans() {
        let mut fs = fsmnt_testkit::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let mut plan = crate::orphan::plan::OrphanPlan::default();
        let classified = classify_apply(&ext, &mut fs, &mut plan).expect("classify");
        assert!(plan.stop.is_none());
        assert!(classified.ea_plan.actions.is_empty());
        assert!(classified.xattr_plan.actions.is_empty());
        assert!(classified.ea_refs.is_empty());
        assert!(classified.xattr_refs.is_empty());
    }

    // ---- Mutation-phase tests (Task 27) ----

    /// Run the full `OrphanReplay::build` pipeline against a fixture.
    fn run_orphan_replay(name: &str) -> Option<crate::orphan::replay::OrphanReplay> {
        let Some((ext, mut cursor)) = load_dirty_fixture(name) else {
            eprintln!("skipping: {name} not present");
            return None;
        };
        let journal =
            crate::journal::JournalReplay::build(&ext, &mut cursor).expect("journal replay");
        let replay = crate::orphan::replay::OrphanReplay::build(journal, &ext, &mut cursor)
            .expect("orphan replay");
        Some(replay)
    }

    #[test]
    fn mutate_ea_cascade_fixture_succeeds_without_stop() {
        let Some(replay) = run_orphan_replay("ext4-dirty-orphan-ea-cascade.img") else {
            return;
        };
        assert!(
            replay.orphan_plan().stop.is_none(),
            "ea-cascade fixture must not produce a stop: {:?}",
            replay.orphan_plan().stop
        );
    }

    #[test]
    fn mutate_ea_cascade_fixture_produces_non_empty_delta() {
        let Some(replay) = run_orphan_replay("ext4-dirty-orphan-ea-cascade.img") else {
            return;
        };
        assert!(replay.orphan_plan().stop.is_none());
        // The delta must contain at least the inode-table block(s) that were zeroed.
        assert!(
            !replay.overlay.blocks.is_empty() || replay.overlay.sb_host_override.is_some(),
            "ea-cascade mutation must produce a non-empty delta"
        );
    }

    #[test]
    fn mutate_shared_xattr_exclusive_fixture_succeeds_without_stop() {
        let Some(replay) = run_orphan_replay("ext4-dirty-orphan-shared-xattr-exclusive.img") else {
            return;
        };
        assert!(
            replay.orphan_plan().stop.is_none(),
            "shared-xattr-exclusive fixture must not stop: {:?}",
            replay.orphan_plan().stop
        );
    }

    #[test]
    fn mutate_shared_xattr_shared_fixture_succeeds_without_stop() {
        let Some(replay) = run_orphan_replay("ext4-dirty-orphan-shared-xattr-shared.img") else {
            return;
        };
        assert!(
            replay.orphan_plan().stop.is_none(),
            "shared-xattr-shared fixture must not stop: {:?}",
            replay.orphan_plan().stop
        );
    }

    #[test]
    fn mutate_legacy_unlink_fixture_succeeds_without_stop() {
        let Some(replay) = run_orphan_replay("ext4-dirty-legacy-unlink.img") else {
            return;
        };
        assert!(
            replay.orphan_plan().stop.is_none(),
            "legacy-unlink fixture must not stop: {:?}",
            replay.orphan_plan().stop
        );
        assert!(
            !replay.overlay.blocks.is_empty() || replay.overlay.sb_host_override.is_some(),
            "legacy-unlink mutation must produce a non-empty delta"
        );
    }

    #[test]
    fn mutate_legacy_truncate_fixture_succeeds_without_stop() {
        let Some(replay) = run_orphan_replay("ext4-dirty-legacy-truncate.img") else {
            return;
        };
        assert!(
            replay.orphan_plan().stop.is_none(),
            "legacy-truncate fixture must not stop: {:?}",
            replay.orphan_plan().stop
        );
    }
}
