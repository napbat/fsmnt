//! Fast-commit extent-tree surgery. See spec §9.
use alloc::vec::Vec;

use crate::checksum::ChecksumState;
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::parse_header;
use crate::io::{Read, Seek};
use crate::orphan::{Mutator, MutatorError};

use super::plan::ExtentReplayReason;

const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_ENTRY_SIZE: usize = 12;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_INITIALIZED_EXTENT_LEN: u16 = 32768;
const MAX_UNWRITTEN_EXTENT_LEN: u16 = 32767;
const UNWRITTEN_FLAG: u16 = 32768;

/// FC ADD_RANGE extent record decoded from on-disk bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawExtent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_pblk: u64,
    pub unwritten: bool,
}

impl RawExtent {
    /// Decode the 12-byte `struct ext4_extent` payload from
    /// FC ADD_RANGE (`fc_ex` field). All fields little-endian.
    pub(crate) fn from_on_disk(raw: &[u8; 12]) -> Self {
        let ee_block = u32::from_le_bytes(raw[0..4].try_into().expect("len 12"));
        let raw_len = u16::from_le_bytes(raw[4..6].try_into().expect("len 12"));
        let unwritten = raw_len > 32768;
        let ee_len = if unwritten { raw_len - 32768 } else { raw_len };
        let ee_start_hi = u16::from_le_bytes(raw[6..8].try_into().expect("len 12"));
        let ee_start_lo = u32::from_le_bytes(raw[8..12].try_into().expect("len 12"));
        let ee_pblk = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);

        Self {
            ee_block,
            ee_len,
            ee_pblk,
            unwritten,
        }
    }
}

#[derive(Debug)]
pub(crate) enum ExtentSurgeryOutcome {
    Applied,
    /// ADD_RANGE or DEL_RANGE would require a new extent index/leaf block.
    RequiresMetadataAllocation,
    /// DEL_RANGE applied and Task 22 must shrink inode size if needed.
    AppliedNeedsShrink {
        /// Furthest post-delete logical extent end, exclusive. Empty files use
        /// zero, matching `shrink_inode`'s byte-size contract.
        end_block_exclusive: u32,
    },
    /// DEL_RANGE only -- caller should skip this record and emit
    /// `FastCommitWarningKind::LogicalRangeInvalid`.
    LogicalRangeInvalid {
        lblk: u32,
        len: u32,
    },
    /// Pass-B: extent surgery failed for a concrete reason. Caller
    /// halts FC replay with a stop carrying the reason.
    Failed(ExtentReplayReason),
}

pub(crate) struct ExtentSurgeon<'ext, 'op, T> {
    ext: &'ext Ext,
    fs: &'op mut T,
    mutator: &'op mut Mutator<'ext>,
    allocation_units_freed: u32,
    allocation_units_allocated: u32,
}

impl<'ext, 'op, T: Read + Seek> ExtentSurgeon<'ext, 'op, T> {
    pub(crate) fn new(ext: &'ext Ext, fs: &'op mut T, mutator: &'op mut Mutator<'ext>) -> Self {
        Self {
            ext,
            fs,
            mutator,
            allocation_units_freed: 0,
            allocation_units_allocated: 0,
        }
    }

    pub(crate) fn allocation_units_freed(&self) -> u32 {
        self.allocation_units_freed
    }

    /// Allocation units consumed by metadata-block allocations during tree
    /// grow (new extent index/leaf blocks).
    pub(crate) fn allocation_units_allocated(&self) -> u32 {
        self.allocation_units_allocated
    }

    /// Allocate a new metadata block for tree grow, tallying the allocation.
    fn allocate_grow_block(&mut self, inum: u32) -> Result<u64> {
        let block = self
            .mutator
            .allocate_metadata_block(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        self.allocation_units_allocated = self.allocation_units_allocated.saturating_add(1);
        Ok(block)
    }

    pub(crate) fn add_range(&mut self, inum: u32, ext: RawExtent) -> Result<ExtentSurgeryOutcome> {
        let blocks_per_cluster = self.ext.blocks_per_cluster();
        if blocks_per_cluster > 1 && !ext.ee_pblk.is_multiple_of(u64::from(blocks_per_cluster)) {
            return Ok(ExtentSurgeryOutcome::Failed(
                ExtentReplayReason::BigallocPblkNotClusterAligned,
            ));
        }
        if let Err(err) = validate_new_extent(inum, ext) {
            return structural_error_to_outcome(err);
        }
        validate_physical_range(self.ext, ext)?;

        let inode_bytes = self
            .mutator
            .current_inode_bytes(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        if inode_bytes.len() < 0x28 + 60 || inode_bytes.len() < 0x68 {
            return Err(ExtError::InvalidInode {
                inode: inum,
                reason: "too short",
            });
        }

        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[0x28..0x28 + 60]);
        let generation = u32::from_le_bytes(inode_bytes[0x64..0x68].try_into().expect("len 4"));

        // First attempt applies in place. If the target leaf is full, grow the
        // tree (mirrors `ext4_ext_create_new_leaf`) and retry the in-place edit
        // against the grown tree.
        match self.try_add_range_in_place(inum, generation, &i_block, ext, blocks_per_cluster)? {
            InPlaceAdd::Done(outcome) => return Ok(outcome),
            InPlaceAdd::NeedsGrow => {}
        }
        match self.grow_for_add(inum, generation, &i_block, ext.ee_block)? {
            GrowResult::Grown => {}
            GrowResult::Halt(outcome) => return Ok(outcome),
        }
        let inode_bytes = self
            .mutator
            .current_inode_bytes(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[0x28..0x28 + 60]);
        match self.try_add_range_in_place(inum, generation, &i_block, ext, blocks_per_cluster)? {
            InPlaceAdd::Done(outcome) => Ok(outcome),
            // A single grow always creates enough room: a depth-grow turns the
            // root into a 1-entry node and a split halves a full node.
            InPlaceAdd::NeedsGrow => Ok(ExtentSurgeryOutcome::RequiresMetadataAllocation),
        }
    }

    /// Attempt an in-place ADD_RANGE edit against the current tree. Returns
    /// `NeedsGrow` when the target leaf is full and a grow is required.
    fn try_add_range_in_place(
        &mut self,
        inum: u32,
        generation: u32,
        i_block: &[u8; 60],
        ext: RawExtent,
        blocks_per_cluster: u32,
    ) -> Result<InPlaceAdd> {
        let target = match self.find_target_leaf(inum, generation, i_block, ext.ee_block) {
            Ok(target) => target,
            Err(err) => return surgery_error_to_outcome(err).map(InPlaceAdd::Done),
        };
        let old_first_logical = match first_leaf_logical(&target.bytes, inum) {
            Ok(first) => first,
            Err(err) => return structural_error_to_outcome(err).map(InPlaceAdd::Done),
        };
        let edit = match edit_leaf(
            &target.bytes,
            inum,
            ext,
            blocks_per_cluster,
            target.successor_logical_bound,
        ) {
            Ok(edit) => edit,
            Err(err) => return structural_error_to_outcome(err).map(InPlaceAdd::Done),
        };
        match edit {
            LeafEdit::Unchanged => Ok(InPlaceAdd::Done(ExtentSurgeryOutcome::Applied)),
            LeafEdit::LeafFull => Ok(InPlaceAdd::NeedsGrow),
            LeafEdit::StructurallyUnsupported => Ok(InPlaceAdd::Done(
                ExtentSurgeryOutcome::RequiresMetadataAllocation,
            )),
            LeafEdit::Patched {
                bytes,
                free_old_physical,
            } => {
                if let Some((pblk, len)) = free_old_physical {
                    let freed = self
                        .mutator
                        .mark_block_range_free(self.fs, pblk, len)
                        .map_err(mutator_error_to_ext)?;
                    self.allocation_units_freed = self.allocation_units_freed.saturating_add(freed);
                }
                let new_first_logical = first_leaf_logical(&bytes, inum)?;
                self.patch_node(inum, generation, target.location, &bytes)?;
                if old_first_logical != new_first_logical {
                    let new_first_logical =
                        new_first_logical.ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
                    self.patch_parent_index_keys(
                        inum,
                        generation,
                        &target.ancestors,
                        new_first_logical,
                    )?;
                }
                Ok(InPlaceAdd::Done(ExtentSurgeryOutcome::Applied))
            }
        }
    }

    pub(crate) fn del_range(
        &mut self,
        inum: u32,
        lblk_start: u32,
        lblk_end_inclusive: u32,
    ) -> Result<ExtentSurgeryOutcome> {
        if lblk_start > lblk_end_inclusive || lblk_end_inclusive.checked_add(1).is_none() {
            return Ok(ExtentSurgeryOutcome::LogicalRangeInvalid {
                lblk: lblk_start,
                len: logical_range_len_for_outcome(lblk_start, lblk_end_inclusive),
            });
        }
        let range = LogicalDeleteRange {
            start: lblk_start,
            end_exclusive: lblk_end_inclusive + 1,
        };

        let inode_bytes = self
            .mutator
            .current_inode_bytes(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        if inode_bytes.len() < 0x28 + 60 || inode_bytes.len() < 0x68 {
            return Err(ExtError::InvalidInode {
                inode: inum,
                reason: "too short",
            });
        }

        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[0x28..0x28 + 60]);
        let generation = u32::from_le_bytes(inode_bytes[0x64..0x68].try_into().expect("len 4"));

        let edit = match self.delete_node(
            inum,
            generation,
            &i_block,
            None,
            range,
            self.ext.blocks_per_cluster(),
        ) {
            Ok(edit) => edit,
            Err(SurgeryError::RequiresMetadataAllocation) => {
                // A punch-hole that splits one extent overflowed the leaf.
                // Split that leaf (`ext4_ext_create_new_leaf`) so the extra
                // record fits, then retry the delete against the grown tree.
                match self.grow_for_add(inum, generation, &i_block, range.start)? {
                    GrowResult::Grown => {}
                    GrowResult::Halt(outcome) => return Ok(outcome),
                }
                return self.del_range_after_grow(inum, generation, range);
            }
            Err(err) => return surgery_error_to_outcome(err),
        };

        self.apply_delete_edit(inum, generation, edit)
    }

    /// Re-run a DEL_RANGE delete after a tree grow added the leaf capacity the
    /// punch-hole split required.
    fn del_range_after_grow(
        &mut self,
        inum: u32,
        generation: u32,
        range: LogicalDeleteRange,
    ) -> Result<ExtentSurgeryOutcome> {
        let inode_bytes = self
            .mutator
            .current_inode_bytes(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        if inode_bytes.len() < 0x28 + 60 {
            return Err(ExtError::InvalidInode {
                inode: inum,
                reason: "too short",
            });
        }
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[0x28..0x28 + 60]);
        let edit = match self.delete_node(
            inum,
            generation,
            &i_block,
            None,
            range,
            self.ext.blocks_per_cluster(),
        ) {
            Ok(edit) => edit,
            // One grow always provides enough room for the single split record.
            Err(SurgeryError::RequiresMetadataAllocation) => {
                return Ok(ExtentSurgeryOutcome::RequiresMetadataAllocation);
            }
            Err(err) => return surgery_error_to_outcome(err),
        };
        self.apply_delete_edit(inum, generation, edit)
    }

    /// Materialize a `DeleteNodeEdit`: validate bigalloc frees, free physical
    /// runs, patch external nodes and the inline root.
    fn apply_delete_edit(
        &mut self,
        inum: u32,
        generation: u32,
        edit: DeleteNodeEdit,
    ) -> Result<ExtentSurgeryOutcome> {
        if let Err(err) = validate_bigalloc_del_frees(&edit, self.ext.blocks_per_cluster()) {
            return surgery_error_to_outcome(err);
        }

        let tree_changed = edit.changed || !edit.patches.is_empty() || !edit.free_ranges.is_empty();
        if !tree_changed {
            return Ok(ExtentSurgeryOutcome::Applied);
        }

        let end_block_exclusive = edit.end_block_exclusive;
        for free in edit.free_ranges {
            let freed = self
                .mutator
                .mark_block_range_free(self.fs, free.pblk, free.len)
                .map_err(mutator_error_to_ext)?;
            self.allocation_units_freed = self.allocation_units_freed.saturating_add(freed);
        }
        for (block, bytes) in &edit.patches {
            self.patch_node(inum, generation, LeafLocation::ExternalBlock(*block), bytes)?;
        }
        if edit.changed {
            let root = edit
                .bytes
                .as_deref()
                .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
            self.patch_node(inum, generation, LeafLocation::InlineRoot, root)?;
        }

        Ok(ExtentSurgeryOutcome::AppliedNeedsShrink {
            end_block_exclusive,
        })
    }

    /// Lower `i_size` to the byte offset represented by the post-delete
    /// exclusive logical extent end. Empty files pass `0` and truncate to zero.
    pub(crate) fn shrink_inode(&mut self, inum: u32, end_block_exclusive: u32) -> Result<()> {
        let target_size = u64::from(end_block_exclusive)
            .checked_mul(u64::from(self.ext.block_size()))
            .ok_or(ExtError::InvalidInode {
                inode: inum,
                reason: "shrink target size overflows",
            })?;

        let inode_bytes = self
            .mutator
            .current_inode_bytes(self.fs, inum)
            .map_err(mutator_error_to_ext)?;
        if inode_bytes.len() < 0x70 {
            return Err(ExtError::InvalidInode {
                inode: inum,
                reason: "too short",
            });
        }

        let size_lo = u32::from_le_bytes(inode_bytes[0x04..0x08].try_into().expect("len 4"));
        let size_hi = u32::from_le_bytes(inode_bytes[0x6C..0x70].try_into().expect("len 4"));
        let current_size = u64::from(size_lo) | (u64::from(size_hi) << 32);
        if current_size <= target_size {
            return Ok(());
        }

        self.mutator
            .patch_inode_scratch(self.fs, inum, |inode_bytes| {
                if inode_bytes.len() < 0x70 {
                    return Err(MutatorError::Ext(ExtError::InvalidInode {
                        inode: inum,
                        reason: "too short",
                    }));
                }
                inode_bytes[0x04..0x08].copy_from_slice(&(target_size as u32).to_le_bytes());
                inode_bytes[0x6C..0x70]
                    .copy_from_slice(&((target_size >> 32) as u32).to_le_bytes());
                Ok(())
            })
            .map_err(mutator_error_to_ext)
    }

    fn delete_node(
        &mut self,
        inum: u32,
        generation: u32,
        node: &[u8],
        this_block: Option<u64>,
        range: LogicalDeleteRange,
        blocks_per_cluster: u32,
    ) -> SurgeryResult<DeleteNodeEdit> {
        let hdr = checked_header(node, inum)?;
        validate_node_header(node, hdr, inum)?;
        let depth = hdr.eh_depth.get();
        if depth == 0 {
            return delete_from_leaf(node, inum, this_block, range, blocks_per_cluster);
        }

        validate_index_order(node, hdr.eh_entries.get(), inum)?;
        let entries = usize::from(hdr.eh_entries.get());
        if entries == 0 {
            return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
                inode: inum,
            }));
        }
        let max = usize::from(hdr.eh_max.get());
        let original = index_records(node, entries, inum)?;
        let mut surviving = Vec::new();
        let mut last_surviving_child_end = None;
        let mut free_ranges = Vec::new();
        let mut surviving_data_ranges = Vec::new();
        let mut patches = Vec::new();

        for (idx, record) in original.iter().copied().enumerate() {
            let next_logical = original.get(idx + 1).map(|next| next.logical);
            if range.end_exclusive <= record.logical
                || next_logical.is_some_and(|upper| range.start >= upper)
            {
                if blocks_per_cluster > 1 {
                    let child_bytes =
                        self.read_child_node(inum, generation, record.child, depth - 1)?;
                    let child_end = self.collect_data_ranges_and_logical_end(
                        inum,
                        generation,
                        &child_bytes,
                        &mut surviving_data_ranges,
                        true,
                    )?;
                    last_surviving_child_end = Some(Some(child_end));
                } else {
                    last_surviving_child_end = Some(None);
                }
                surviving.push(record);
                continue;
            }
            let child_bytes = self.read_child_node(inum, generation, record.child, depth - 1)?;

            let mut child_edit = self.delete_node(
                inum,
                generation,
                &child_bytes,
                Some(record.child),
                range,
                blocks_per_cluster,
            )?;
            free_ranges.append(&mut child_edit.free_ranges);
            surviving_data_ranges.append(&mut child_edit.surviving_data_ranges);
            patches.append(&mut child_edit.patches);

            if let Some(child_node) = child_edit.bytes {
                let child_end = child_edit.end_block_exclusive;
                let first_logical = child_edit
                    .first_logical
                    .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
                if child_edit.changed {
                    patches.push((record.child, child_node));
                }
                surviving.push(IndexRecord {
                    logical: first_logical,
                    child: record.child,
                });
                last_surviving_child_end = Some(Some(child_end));
            }
        }

        if surviving.is_empty() {
            if let Some(block) = this_block {
                free_ranges.push(PlannedFree {
                    pblk: block,
                    len: 1,
                    kind: PlannedFreeKind::Metadata,
                });
                return Ok(DeleteNodeEdit {
                    bytes: None,
                    changed: true,
                    first_logical: None,
                    free_ranges,
                    surviving_data_ranges,
                    end_block_exclusive: 0,
                    patches,
                });
            }

            return Ok(DeleteNodeEdit {
                bytes: Some(empty_inline_leaf_root(node, inum)?),
                changed: true,
                first_logical: None,
                free_ranges,
                surviving_data_ranges,
                end_block_exclusive: 0,
                patches,
            });
        }

        let end_block_exclusive = match last_surviving_child_end {
            Some(Some(end)) => end,
            Some(None) => {
                let rightmost = surviving
                    .last()
                    .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
                let child_bytes =
                    self.read_child_node(inum, generation, rightmost.child, depth - 1)?;
                self.collect_data_ranges_and_logical_end(
                    inum,
                    generation,
                    &child_bytes,
                    &mut surviving_data_ranges,
                    false,
                )?
            }
            None => 0,
        };

        let changed = surviving != original;
        let bytes = if changed {
            let mut patched = node.to_vec();
            rewrite_index_records(&mut patched, &surviving, max, inum)?;
            Some(patched)
        } else {
            Some(node.to_vec())
        };
        Ok(DeleteNodeEdit {
            bytes,
            changed,
            first_logical: Some(surviving[0].logical),
            free_ranges,
            surviving_data_ranges,
            end_block_exclusive,
            patches,
        })
    }

    fn collect_data_ranges_and_logical_end(
        &mut self,
        inum: u32,
        generation: u32,
        node: &[u8],
        ranges: &mut Vec<(u64, u32)>,
        collect_ranges: bool,
    ) -> SurgeryResult<u32> {
        let hdr = checked_header(node, inum)?;
        validate_node_header(node, hdr, inum)?;
        let depth = hdr.eh_depth.get();
        let entries = usize::from(hdr.eh_entries.get());
        if depth == 0 {
            validate_leaf_order(node, entries, inum)?;
            let mut end_block_exclusive = 0;
            for record in leaf_records(node, entries, inum)? {
                if collect_ranges {
                    ranges.push((record.pblk, u32::from(record.len)));
                }
                end_block_exclusive = end_block_exclusive.max(logical_end(record, inum)?);
            }
            return Ok(end_block_exclusive);
        }

        if entries == 0 {
            return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
                inode: inum,
            }));
        }
        validate_index_order(node, hdr.eh_entries.get(), inum)?;
        let mut end_block_exclusive = 0;
        for record in index_records(node, entries, inum)? {
            let child_bytes = self.read_child_node(inum, generation, record.child, depth - 1)?;
            end_block_exclusive =
                end_block_exclusive.max(self.collect_data_ranges_and_logical_end(
                    inum,
                    generation,
                    &child_bytes,
                    ranges,
                    collect_ranges,
                )?);
        }
        Ok(end_block_exclusive)
    }

    fn read_child_node(
        &mut self,
        inum: u32,
        generation: u32,
        child: u64,
        expected_depth: u16,
    ) -> SurgeryResult<Vec<u8>> {
        if child >= self.ext.blocks_count {
            return Err(SurgeryError::Failed(
                ExtentReplayReason::SiblingBlockOutOfRange,
            ));
        }

        let (child_bytes, from_scratch) = self
            .mutator
            .current_block_bytes(self.fs, child)
            .map_err(mutator_error_to_ext)
            .map_err(SurgeryError::Ext)?;
        if !from_scratch {
            self.verify_extent_block_checksum(inum, generation, &child_bytes)?;
        }
        let child_hdr = checked_header(&child_bytes, inum)?;
        validate_node_header(&child_bytes, child_hdr, inum)?;
        if child_hdr.eh_depth.get() != expected_depth {
            return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
                inode: inum,
            }));
        }
        Ok(child_bytes.into_vec())
    }

    fn find_target_leaf(
        &mut self,
        inum: u32,
        generation: u32,
        root: &[u8; 60],
        logical_block: u32,
    ) -> SurgeryResult<LeafTarget> {
        let mut bytes = root.to_vec();
        let mut location = LeafLocation::InlineRoot;
        let mut ancestors = Vec::new();
        let mut successor_logical_bound = None;
        let mut levels_seen = 0u16;

        loop {
            let hdr = checked_header(&bytes, inum)?;
            validate_node_header(&bytes, hdr, inum)?;
            let depth = hdr.eh_depth.get();
            if depth == 0 {
                return Ok(LeafTarget {
                    location,
                    bytes,
                    ancestors,
                    successor_logical_bound,
                });
            }
            validate_index_order(&bytes, hdr.eh_entries.get(), inum)?;
            levels_seen = levels_seen.saturating_add(1);
            if levels_seen > MAX_EXTENT_DEPTH {
                return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
                    inode: inum,
                }));
            }

            let (child_index, child) =
                choose_child_entry(&bytes, hdr.eh_entries.get(), inum, logical_block)?;
            if child >= self.ext.blocks_count {
                return Err(SurgeryError::Failed(
                    ExtentReplayReason::SiblingBlockOutOfRange,
                ));
            }
            if child_index + 1 < usize::from(hdr.eh_entries.get()) {
                let next = read_index_record(&bytes, child_index + 1, inum)?.logical;
                successor_logical_bound =
                    Some(successor_logical_bound.map_or(next, |bound: u32| bound.min(next)));
            }
            let (child_bytes, from_scratch) = self
                .mutator
                .current_block_bytes(self.fs, child)
                .map_err(mutator_error_to_ext)
                .map_err(SurgeryError::Ext)?;
            if !from_scratch {
                self.verify_extent_block_checksum(inum, generation, &child_bytes)?;
            }
            let child_hdr = checked_header(&child_bytes, inum)?;
            validate_node_header(&child_bytes, child_hdr, inum)?;
            if child_hdr.eh_depth.get() != depth - 1 {
                return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
                    inode: inum,
                }));
            }

            let parent_location = location;
            let parent_bytes = core::mem::replace(&mut bytes, child_bytes.into_vec());
            ancestors.push(AncestorNode {
                location: parent_location,
                bytes: parent_bytes,
                child_index,
            });
            location = LeafLocation::ExternalBlock(child);
        }
    }

    fn verify_extent_block_checksum(
        &self,
        inum: u32,
        generation: u32,
        bytes: &[u8],
    ) -> SurgeryResult<()> {
        if let Some(seed) = self.ext.checksum_seed() {
            let state = crate::checksum::verify_extent_block(seed, inum, generation, bytes);
            if state != ChecksumState::Valid {
                return Err(SurgeryError::Failed(
                    ExtentReplayReason::ExtentBlockChecksumInvalid,
                ));
            }
        }
        Ok(())
    }

    fn patch_node(
        &mut self,
        inum: u32,
        generation: u32,
        location: LeafLocation,
        bytes: &[u8],
    ) -> Result<()> {
        match location {
            LeafLocation::InlineRoot => {
                if bytes.len() != 60 {
                    return Err(ExtError::InvalidExtentHeader { inode: inum });
                }
                self.mutator
                    .patch_inode_scratch(self.fs, inum, |inode_bytes| {
                        inode_bytes[0x28..0x28 + 60].copy_from_slice(bytes);
                        Ok(())
                    })
                    .map_err(mutator_error_to_ext)?;
            }
            LeafLocation::ExternalBlock(block) => {
                self.mutator
                    .patch_extent_block(self.fs, block, inum, generation, |block_bytes| {
                        if block_bytes.len() != bytes.len() {
                            return Err(MutatorError::Ext(ExtError::InvalidExtentHeader {
                                inode: inum,
                            }));
                        }
                        block_bytes.copy_from_slice(bytes);
                        Ok(())
                    })
                    .map_err(mutator_error_to_ext)?;
            }
        }
        Ok(())
    }

    fn patch_parent_index_keys(
        &mut self,
        inum: u32,
        generation: u32,
        ancestors: &[AncestorNode],
        new_child_first_logical: u32,
    ) -> Result<()> {
        let propagated_logical = new_child_first_logical;

        for ancestor in ancestors.iter().rev() {
            let record = read_index_record(&ancestor.bytes, ancestor.child_index, inum)?;
            if record.logical == propagated_logical {
                break;
            }

            let mut patched = ancestor.bytes.clone();
            write_index_logical(&mut patched, ancestor.child_index, propagated_logical, inum)?;
            self.patch_node(inum, generation, ancestor.location, &patched)?;

            if ancestor.child_index != 0 {
                break;
            }
        }

        Ok(())
    }

    /// Grow the extent tree so the leaf covering `logical_block` gains a free
    /// slot. Mirrors `ext4_ext_create_new_leaf`: a full inode-root leaf is
    /// converted to a depth-1 index (`ext4_ext_grow_indepth`); a full external
    /// leaf is split (`ext4_ext_split`) with the new index entry propagated up,
    /// recursively splitting full index nodes. Returns `Halt(outcome)` when
    /// the grow cannot proceed — `RequiresMetadataAllocation` at
    /// `MAX_EXTENT_DEPTH`, or a concrete `Failed(reason)` from a
    /// corrupted-tree probe failure.
    ///
    /// Every block allocation and node patch is staged in the per-transaction
    /// `Mutator` scratch. A failure part-way through a multi-level grow leaves
    /// no orphan metadata: `apply.rs::stop_current_tx` drops the mutator,
    /// discarding all scratch including the bitmap bits set for newly allocated
    /// metadata blocks.
    fn grow_for_add(
        &mut self,
        inum: u32,
        generation: u32,
        i_block: &[u8; 60],
        logical_block: u32,
    ) -> Result<GrowResult> {
        let target = match self.find_target_leaf(inum, generation, i_block, logical_block) {
            Ok(target) => target,
            // Preserve the concrete failure: a corrupted-tree probe
            // failure (sibling out of range, malformed header) must
            // surface as `Failed(reason)`, not be flattened into a
            // max-depth `RequiresMetadataAllocation`.
            Err(err) => return surgery_error_to_outcome(err).map(GrowResult::Halt),
        };
        match target.location {
            LeafLocation::InlineRoot => self.grow_root_leaf(inum, generation, &target.bytes),
            LeafLocation::ExternalBlock(block) => {
                self.split_leaf_and_propagate(inum, generation, block, &target)
            }
        }
    }

    /// `ext4_ext_grow_indepth` for a leaf root: move every inline-root leaf
    /// record into a freshly allocated external leaf block; the inline root
    /// becomes a depth-1 index node with a single child entry.
    fn grow_root_leaf(&mut self, inum: u32, generation: u32, root: &[u8]) -> Result<GrowResult> {
        let records = node_leaf_records(root, inum)?;
        let first_logical = records
            .first()
            .map(|record| record.logical)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        let new_block = self.allocate_grow_block(inum)?;

        let leaf_bytes = build_leaf_block(self.ext, &records, generation, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(new_block),
            &leaf_bytes,
        )?;

        let new_root = build_inline_index_root(
            root,
            &[IndexRecord {
                logical: first_logical,
                child: new_block,
            }],
            inum,
        )?;
        self.patch_node(inum, generation, LeafLocation::InlineRoot, &new_root)?;
        Ok(GrowResult::Grown)
    }

    /// `ext4_ext_split` at the leaf level: split a full external leaf into two
    /// blocks and propagate the new index entry into the parent.
    fn split_leaf_and_propagate(
        &mut self,
        inum: u32,
        generation: u32,
        leaf_block: u64,
        target: &LeafTarget,
    ) -> Result<GrowResult> {
        let records = node_leaf_records(&target.bytes, inum)?;
        let mid = records.len() / 2;
        let (low, high) = records.split_at(mid);
        let high_first = high
            .first()
            .map(|record| record.logical)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;

        let new_block = self.allocate_grow_block(inum)?;

        let low_bytes = rewrite_node_leaf(&target.bytes, low, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(leaf_block),
            &low_bytes,
        )?;
        let high_bytes = build_leaf_block(self.ext, high, generation, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(new_block),
            &high_bytes,
        )?;

        let new_entry = IndexRecord {
            logical: high_first,
            child: new_block,
        };
        let parent_idx = target.ancestors.len().checked_sub(1).ok_or(
            // A full external leaf always has at least one ancestor (the root).
            ExtError::InvalidExtentHeader { inode: inum },
        )?;
        self.insert_index_entry(inum, generation, &target.ancestors, parent_idx, new_entry)
    }

    /// Insert `new_entry` into `ancestors[level]`, splitting that index node and
    /// recursing up when it is full. Mirrors `ext4_ext_split` for index nodes
    /// and `ext4_ext_grow_indepth` when the inline root must gain a level.
    fn insert_index_entry(
        &mut self,
        inum: u32,
        generation: u32,
        ancestors: &[AncestorNode],
        level: usize,
        new_entry: IndexRecord,
    ) -> Result<GrowResult> {
        let ancestor = ancestors
            .get(level)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        let mut records = node_index_records(&ancestor.bytes, inum)?;
        let hdr = checked_header(&ancestor.bytes, inum)?;
        let max = usize::from(hdr.eh_max.get());
        insert_index_record_sorted(&mut records, new_entry, inum)?;

        if records.len() <= max {
            let patched = rewrite_node_index(&ancestor.bytes, &records, inum)?;
            self.patch_node(inum, generation, ancestor.location, &patched)?;
            return Ok(GrowResult::Grown);
        }

        match ancestor.location {
            LeafLocation::InlineRoot => {
                self.grow_root_index(inum, generation, &ancestor.bytes, &records)
            }
            LeafLocation::ExternalBlock(block) => {
                let ctx = IndexSplitContext {
                    inum,
                    generation,
                    node_block: block,
                    node_bytes: ancestor.bytes.clone(),
                };
                self.split_index_node(ctx, &records, ancestors, level)
            }
        }
    }

    /// `ext4_ext_grow_indepth` for an index root: move the entire (now
    /// overflowing) inline-root index content into a new external block and
    /// rebuild the inline root as a single-entry index one level deeper.
    fn grow_root_index(
        &mut self,
        inum: u32,
        generation: u32,
        root: &[u8],
        records: &[IndexRecord],
    ) -> Result<GrowResult> {
        let root_hdr = checked_header(root, inum)?;
        let new_depth = root_hdr.eh_depth.get();
        if new_depth >= MAX_EXTENT_DEPTH {
            return Ok(GrowResult::Halt(
                ExtentSurgeryOutcome::RequiresMetadataAllocation,
            ));
        }
        let first_logical = records
            .first()
            .map(|record| record.logical)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        let new_block = self.allocate_grow_block(inum)?;

        let child_bytes =
            build_index_block(self.ext, records, root_hdr.eh_depth.get(), generation, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(new_block),
            &child_bytes,
        )?;

        let new_root = build_inline_index_root_at_depth(
            root,
            &[IndexRecord {
                logical: first_logical,
                child: new_block,
            }],
            new_depth + 1,
            inum,
        )?;
        self.patch_node(inum, generation, LeafLocation::InlineRoot, &new_root)?;
        Ok(GrowResult::Grown)
    }

    /// `ext4_ext_split` at an index level: split a full external index node and
    /// propagate the new index entry into the grandparent.
    fn split_index_node(
        &mut self,
        ctx: IndexSplitContext,
        records: &[IndexRecord],
        ancestors: &[AncestorNode],
        level: usize,
    ) -> Result<GrowResult> {
        let IndexSplitContext {
            inum,
            generation,
            node_block,
            node_bytes,
        } = ctx;
        let depth = checked_header(&node_bytes, inum)?.eh_depth.get();
        let mid = records.len() / 2;
        let (low, high) = records.split_at(mid);
        let high_first = high
            .first()
            .map(|record| record.logical)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;

        let new_block = self.allocate_grow_block(inum)?;

        let low_bytes = rewrite_node_index(&node_bytes, low, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(node_block),
            &low_bytes,
        )?;
        let high_bytes = build_index_block(self.ext, high, depth, generation, inum)?;
        self.patch_node(
            inum,
            generation,
            LeafLocation::ExternalBlock(new_block),
            &high_bytes,
        )?;

        let new_entry = IndexRecord {
            logical: high_first,
            child: new_block,
        };
        let parent_level = level
            .checked_sub(1)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        self.insert_index_entry(inum, generation, ancestors, parent_level, new_entry)
    }
}

#[derive(Debug)]
struct IndexSplitContext {
    inum: u32,
    generation: u32,
    node_block: u64,
    node_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
enum LeafLocation {
    InlineRoot,
    ExternalBlock(u64),
}

#[derive(Debug)]
struct LeafTarget {
    location: LeafLocation,
    bytes: Vec<u8>,
    ancestors: Vec<AncestorNode>,
    successor_logical_bound: Option<u32>,
}

#[derive(Debug)]
struct AncestorNode {
    location: LeafLocation,
    bytes: Vec<u8>,
    child_index: usize,
}

#[derive(Debug)]
enum LeafEdit {
    Unchanged,
    /// The target leaf has no free slot — a tree grow adds capacity.
    LeafFull,
    /// The new extent's logical range cannot occupy this structural slot
    /// (spans a sibling leaf, overlaps a neighbor, or extends past the mapped
    /// extent). Growing does not help; replay halts.
    StructurallyUnsupported,
    Patched {
        bytes: Vec<u8>,
        free_old_physical: Option<(u64, u32)>,
    },
}

#[derive(Debug)]
enum InPlaceAdd {
    Done(ExtentSurgeryOutcome),
    NeedsGrow,
}

#[derive(Debug)]
enum GrowResult {
    /// The tree gained capacity; retry the in-place edit.
    Grown,
    /// The grow could not proceed. Replay halts with this exact
    /// outcome — `RequiresMetadataAllocation` for the true max-depth
    /// case, or a concrete `Failed(reason)` propagated from a
    /// corrupted-tree probe failure.
    Halt(ExtentSurgeryOutcome),
}

#[derive(Debug)]
enum SurgeryError {
    Ext(ExtError),
    RequiresMetadataAllocation,
    Failed(ExtentReplayReason),
}

type SurgeryResult<T> = core::result::Result<T, SurgeryError>;

impl From<ExtError> for SurgeryError {
    fn from(err: ExtError) -> Self {
        Self::Ext(err)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LeafRecord {
    logical: u32,
    len: u16,
    pblk: u64,
    unwritten: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IndexRecord {
    logical: u32,
    child: u64,
}

#[derive(Clone, Copy, Debug)]
struct LogicalDeleteRange {
    start: u32,
    end_exclusive: u32,
}

#[derive(Debug)]
struct DeleteNodeEdit {
    bytes: Option<Vec<u8>>,
    changed: bool,
    first_logical: Option<u32>,
    free_ranges: Vec<PlannedFree>,
    surviving_data_ranges: Vec<(u64, u32)>,
    end_block_exclusive: u32,
    patches: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlannedFree {
    pblk: u64,
    len: u32,
    kind: PlannedFreeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedFreeKind {
    Data,
    Metadata,
}

#[derive(Clone, Copy, Debug)]
struct MappedEditContext {
    inum: u32,
    entries: usize,
    max: usize,
    idx: usize,
    blocks_per_cluster: u32,
}

fn edit_leaf(
    leaf: &[u8],
    inum: u32,
    new_extent: RawExtent,
    blocks_per_cluster: u32,
    successor_logical_bound: Option<u32>,
) -> Result<LeafEdit> {
    let hdr = checked_header(leaf, inum)?;
    validate_node_header(leaf, hdr, inum)?;
    if hdr.eh_depth.get() != 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }

    let entries = usize::from(hdr.eh_entries.get());
    let max = usize::from(hdr.eh_max.get());
    validate_leaf_order(leaf, entries, inum)?;
    let mut node = leaf.to_vec();
    let new_record = LeafRecord::from_raw(new_extent);
    let new_end = logical_end(new_record, inum)?;
    if let Some(bound) = successor_logical_bound
        && new_end > bound
    {
        return Ok(LeafEdit::StructurallyUnsupported);
    }
    let mut insert_pos = entries;

    for idx in 0..entries {
        let existing = read_leaf_record(&node, idx, inum)?;
        let existing_end = logical_end(existing, inum)?;
        if new_record.logical >= existing.logical && new_record.logical < existing_end {
            return edit_mapped_record(
                &node,
                MappedEditContext {
                    inum,
                    entries,
                    max,
                    idx,
                    blocks_per_cluster,
                },
                existing,
                new_record,
                new_end,
            );
        }
        if new_record.logical < existing.logical {
            if new_end > existing.logical {
                return Ok(LeafEdit::StructurallyUnsupported);
            }
            insert_pos = idx;
            break;
        }
    }

    if insert_pos > 0 {
        let left_idx = insert_pos - 1;
        let left = read_leaf_record(&node, left_idx, inum)?;
        if can_merge(left, new_record, blocks_per_cluster) {
            let mut merged = merge_records(left, new_record, inum)?;
            let mut new_entries = entries;
            if insert_pos < entries {
                let right = read_leaf_record(&node, insert_pos, inum)?;
                if can_merge(merged, right, blocks_per_cluster) {
                    merged = merge_records(merged, right, inum)?;
                    remove_leaf_record(&mut node, insert_pos, entries, inum)?;
                    new_entries -= 1;
                    write_entry_count(&mut node, new_entries, inum)?;
                }
            }
            write_leaf_record(&mut node, left_idx, merged, inum)?;
            return Ok(LeafEdit::Patched {
                bytes: node,
                free_old_physical: None,
            });
        }
    }

    if insert_pos < entries {
        let right = read_leaf_record(&node, insert_pos, inum)?;
        if can_merge(new_record, right, blocks_per_cluster) {
            let merged = merge_records(new_record, right, inum)?;
            write_leaf_record(&mut node, insert_pos, merged, inum)?;
            return Ok(LeafEdit::Patched {
                bytes: node,
                free_old_physical: None,
            });
        }
    }

    if entries >= max {
        return Ok(LeafEdit::LeafFull);
    }

    for slot in (insert_pos..entries).rev() {
        let record = read_leaf_record(&node, slot, inum)?;
        write_leaf_record(&mut node, slot + 1, record, inum)?;
    }
    write_leaf_record(&mut node, insert_pos, new_record, inum)?;
    write_entry_count(&mut node, entries + 1, inum)?;
    Ok(LeafEdit::Patched {
        bytes: node,
        free_old_physical: None,
    })
}

fn edit_mapped_record(
    node: &[u8],
    ctx: MappedEditContext,
    existing: LeafRecord,
    new_record: LeafRecord,
    new_end: u32,
) -> Result<LeafEdit> {
    let existing_end = logical_end(existing, ctx.inum)?;
    if new_end > existing_end {
        return Ok(LeafEdit::StructurallyUnsupported);
    }
    let logical_offset = new_record.logical - existing.logical;
    let existing_pblk_at_range =
        existing
            .pblk
            .checked_add(u64::from(logical_offset))
            .ok_or(ExtError::BlockOutOfRange {
                block: existing.pblk,
            })?;

    if existing_pblk_at_range == new_record.pblk && existing.unwritten == new_record.unwritten {
        return Ok(LeafEdit::Unchanged);
    }

    let left_len = logical_offset;
    let right_len = existing_end - new_end;
    let mut replacement = Vec::new();
    if left_len > 0 {
        replacement.push(LeafRecord {
            logical: existing.logical,
            len: u16::try_from(left_len)
                .map_err(|_| ExtError::InvalidExtentHeader { inode: ctx.inum })?,
            pblk: existing.pblk,
            unwritten: existing.unwritten,
        });
    }
    replacement.push(new_record);
    if right_len > 0 {
        replacement.push(LeafRecord {
            logical: new_end,
            len: u16::try_from(right_len)
                .map_err(|_| ExtError::InvalidExtentHeader { inode: ctx.inum })?,
            pblk: existing_pblk_at_range
                .checked_add(u64::from(new_record.len))
                .ok_or(ExtError::InvalidExtentHeader { inode: ctx.inum })?,
            unwritten: existing.unwritten,
        });
    }

    let mut records = leaf_records(node, ctx.entries, ctx.inum)?;
    records.splice(ctx.idx..ctx.idx + 1, replacement);
    let records = coalesce_records(records, ctx.blocks_per_cluster, ctx.inum)?;
    if records.len() > ctx.max {
        return Ok(LeafEdit::LeafFull);
    }

    let mut patched = node.to_vec();
    rewrite_leaf_records(&mut patched, &records, ctx.max, ctx.inum)?;
    let free_old_physical = (existing_pblk_at_range != new_record.pblk)
        .then_some((existing_pblk_at_range, u32::from(new_record.len)));
    Ok(LeafEdit::Patched {
        bytes: patched,
        free_old_physical,
    })
}

fn delete_from_leaf(
    leaf: &[u8],
    inum: u32,
    this_block: Option<u64>,
    range: LogicalDeleteRange,
    blocks_per_cluster: u32,
) -> SurgeryResult<DeleteNodeEdit> {
    let hdr = checked_header(leaf, inum)?;
    validate_node_header(leaf, hdr, inum)?;
    if hdr.eh_depth.get() != 0 {
        return Err(SurgeryError::Ext(ExtError::InvalidExtentHeader {
            inode: inum,
        }));
    }

    let entries = usize::from(hdr.eh_entries.get());
    let max = usize::from(hdr.eh_max.get());
    validate_leaf_order(leaf, entries, inum)?;
    let original = leaf_records(leaf, entries, inum)?;
    let mut replacement = Vec::new();
    let mut free_ranges = Vec::new();

    for record in original.iter().copied() {
        let record_end = logical_end(record, inum)?;
        if record_end <= range.start || record.logical >= range.end_exclusive {
            replacement.push(record);
            continue;
        }

        let overlap_start = record.logical.max(range.start);
        let overlap_end = record_end.min(range.end_exclusive);
        let overlap_len = overlap_end
            .checked_sub(overlap_start)
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        let physical_offset = overlap_start - record.logical;
        let free_pblk = record
            .pblk
            .checked_add(u64::from(physical_offset))
            .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
        free_ranges.push(PlannedFree {
            pblk: free_pblk,
            len: overlap_len,
            kind: PlannedFreeKind::Data,
        });

        let left_len = overlap_start - record.logical;
        if left_len > 0 {
            replacement.push(LeafRecord {
                logical: record.logical,
                len: u16::try_from(left_len)
                    .map_err(|_| ExtError::InvalidExtentHeader { inode: inum })?,
                pblk: record.pblk,
                unwritten: record.unwritten,
            });
        }

        let right_len = record_end - overlap_end;
        if right_len > 0 {
            let right_pblk = record
                .pblk
                .checked_add(u64::from(overlap_end - record.logical))
                .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
            replacement.push(LeafRecord {
                logical: overlap_end,
                len: u16::try_from(right_len)
                    .map_err(|_| ExtError::InvalidExtentHeader { inode: inum })?,
                pblk: right_pblk,
                unwritten: record.unwritten,
            });
        }
    }

    let replacement = coalesce_records(replacement, blocks_per_cluster, inum)?;
    if replacement.len() > max {
        return Err(SurgeryError::RequiresMetadataAllocation);
    }
    let end_block_exclusive = max_leaf_logical_end(&replacement, inum)?;
    let surviving_data_ranges = replacement
        .iter()
        .map(|record| (record.pblk, u32::from(record.len)))
        .collect();
    if replacement == original {
        return Ok(DeleteNodeEdit {
            bytes: Some(leaf.to_vec()),
            changed: false,
            first_logical: replacement.first().map(|record| record.logical),
            free_ranges,
            surviving_data_ranges,
            end_block_exclusive,
            patches: Vec::new(),
        });
    }
    if replacement.is_empty()
        && let Some(block) = this_block
    {
        free_ranges.push(PlannedFree {
            pblk: block,
            len: 1,
            kind: PlannedFreeKind::Metadata,
        });
        return Ok(DeleteNodeEdit {
            bytes: None,
            changed: true,
            first_logical: None,
            free_ranges,
            surviving_data_ranges: Vec::new(),
            end_block_exclusive: 0,
            patches: Vec::new(),
        });
    }

    let mut patched = leaf.to_vec();
    rewrite_leaf_records(&mut patched, &replacement, max, inum)?;
    Ok(DeleteNodeEdit {
        bytes: Some(patched),
        changed: true,
        first_logical: replacement.first().map(|record| record.logical),
        free_ranges,
        surviving_data_ranges,
        end_block_exclusive,
        patches: Vec::new(),
    })
}

fn max_leaf_logical_end(records: &[LeafRecord], inum: u32) -> Result<u32> {
    records.iter().try_fold(0, |max_end, record| {
        logical_end(*record, inum).map(|record_end| max_end.max(record_end))
    })
}

fn validate_bigalloc_del_frees(
    edit: &DeleteNodeEdit,
    blocks_per_cluster: u32,
) -> SurgeryResult<()> {
    let cluster_blocks = u64::from(blocks_per_cluster);
    if cluster_blocks <= 1 {
        return Ok(());
    }

    for free in edit
        .free_ranges
        .iter()
        .filter(|free| free.kind == PlannedFreeKind::Data)
    {
        let len = u64::from(free.len);
        if !free.pblk.is_multiple_of(cluster_blocks) || !len.is_multiple_of(cluster_blocks) {
            return Err(SurgeryError::Failed(
                ExtentReplayReason::BigallocPartialClusterDelRange,
            ));
        }

        let free_end = free
            .pblk
            .checked_add(len)
            .ok_or(ExtError::BlockOutOfRange { block: free.pblk })?;
        for &(survivor_pblk, survivor_len) in &edit.surviving_data_ranges {
            if range_touches_cluster_window(
                survivor_pblk,
                u64::from(survivor_len),
                free.pblk,
                free_end,
                cluster_blocks,
            )? {
                return Err(SurgeryError::Failed(
                    ExtentReplayReason::BigallocPartialClusterDelRange,
                ));
            }
        }
    }

    Ok(())
}

fn range_touches_cluster_window(
    pblk: u64,
    len: u64,
    free_start: u64,
    free_end: u64,
    cluster_blocks: u64,
) -> Result<bool> {
    if len == 0 {
        return Ok(false);
    }
    let end = pblk
        .checked_add(len)
        .ok_or(ExtError::BlockOutOfRange { block: pblk })?;
    let cluster_start = (free_start / cluster_blocks) * cluster_blocks;
    let free_end_minus_one = free_end
        .checked_sub(1)
        .ok_or(ExtError::BlockOutOfRange { block: free_start })?;
    let cluster_end = ((free_end_minus_one / cluster_blocks) + 1)
        .checked_mul(cluster_blocks)
        .ok_or(ExtError::BlockOutOfRange {
            block: free_end_minus_one,
        })?;
    Ok(pblk < cluster_end && end > cluster_start)
}

fn can_merge(left: LeafRecord, right: LeafRecord, blocks_per_cluster: u32) -> bool {
    if left.unwritten != right.unwritten {
        return false;
    }
    let Some(left_logical_end) = left.logical.checked_add(u32::from(left.len)) else {
        return false;
    };
    if left_logical_end != right.logical {
        return false;
    }
    let Some(left_physical_end) = left.pblk.checked_add(u64::from(left.len)) else {
        return false;
    };
    if left_physical_end != right.pblk {
        return false;
    }
    let Some(merged_len) = left.len.checked_add(right.len) else {
        return false;
    };
    if !extent_len_encodes(merged_len, left.unwritten) {
        return false;
    }

    let ratio = u64::from(blocks_per_cluster);
    if ratio > 1
        && (!left.pblk.is_multiple_of(ratio)
            || !right.pblk.is_multiple_of(ratio)
            || !left_physical_end.is_multiple_of(ratio))
    {
        return false;
    }

    true
}

fn merge_records(left: LeafRecord, right: LeafRecord, inum: u32) -> Result<LeafRecord> {
    let len = left
        .len
        .checked_add(right.len)
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
    encode_extent_len(len, left.unwritten, inum)?;
    Ok(LeafRecord { len, ..left })
}

fn checked_header(buf: &[u8], inum: u32) -> Result<crate::extent::RawExtentHeader> {
    if buf.len() < EXTENT_HEADER_SIZE {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    parse_header(buf, inum)
}

fn validate_node_header(buf: &[u8], hdr: crate::extent::RawExtentHeader, inum: u32) -> Result<()> {
    let entries = usize::from(hdr.eh_entries.get());
    let max = usize::from(hdr.eh_max.get());
    let depth = hdr.eh_depth.get();
    if depth > MAX_EXTENT_DEPTH || entries > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let capacity = buf.len().saturating_sub(EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
    if entries > capacity || max > capacity {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    Ok(())
}

fn validate_index_order(buf: &[u8], entries: u16, inum: u32) -> Result<()> {
    let mut previous = None;
    for idx in 0..usize::from(entries) {
        let current = read_index_record(buf, idx, inum)?;
        if let Some(previous) = previous
            && current.logical <= previous
        {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        previous = Some(current.logical);
    }
    Ok(())
}

fn choose_child_entry(buf: &[u8], entries: u16, inum: u32, logical: u32) -> Result<(usize, u64)> {
    if entries == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }

    let mut chosen = read_index_record(buf, 0, inum)?;
    let mut chosen_idx = 0;
    if chosen.logical > logical {
        return Ok((chosen_idx, chosen.child));
    }

    for idx in 1..usize::from(entries) {
        let current = read_index_record(buf, idx, inum)?;
        if current.logical > logical {
            break;
        }
        chosen = current;
        chosen_idx = idx;
    }

    Ok((chosen_idx, chosen.child))
}

fn read_index_record(buf: &[u8], idx: usize, inum: u32) -> Result<IndexRecord> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let logical = read_u32_le(buf, off);
    let child_lo = read_u32_le(buf, off + 4);
    let child_hi = read_u16_le(buf, off + 8);
    let child = (u64::from(child_hi) << 32) | u64::from(child_lo);
    Ok(IndexRecord { logical, child })
}

fn index_records(buf: &[u8], entries: usize, inum: u32) -> Result<Vec<IndexRecord>> {
    let mut records = Vec::new();
    for idx in 0..entries {
        records.push(read_index_record(buf, idx, inum)?);
    }
    Ok(records)
}

fn read_leaf_record(buf: &[u8], idx: usize, inum: u32) -> Result<LeafRecord> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let logical = read_u32_le(buf, off);
    let raw_len = read_u16_le(buf, off + 4);
    let unwritten = raw_len > UNWRITTEN_FLAG;
    let len = if unwritten {
        raw_len - UNWRITTEN_FLAG
    } else {
        raw_len
    };
    if len == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let pblk_hi = read_u16_le(buf, off + 6);
    let pblk_lo = read_u32_le(buf, off + 8);
    let pblk = (u64::from(pblk_hi) << 32) | u64::from(pblk_lo);
    Ok(LeafRecord {
        logical,
        len,
        pblk,
        unwritten,
    })
}

fn leaf_records(buf: &[u8], entries: usize, inum: u32) -> Result<Vec<LeafRecord>> {
    let mut records = Vec::new();
    for idx in 0..entries {
        records.push(read_leaf_record(buf, idx, inum)?);
    }
    Ok(records)
}

fn validate_leaf_order(buf: &[u8], entries: usize, inum: u32) -> Result<()> {
    let mut previous_end = None;
    for idx in 0..entries {
        let current = read_leaf_record(buf, idx, inum)?;
        let current_end = logical_end(current, inum)?;
        if let Some(previous_end) = previous_end
            && current.logical < previous_end
        {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        previous_end = Some(current_end);
    }
    Ok(())
}

fn coalesce_records(
    records: Vec<LeafRecord>,
    blocks_per_cluster: u32,
    inum: u32,
) -> Result<Vec<LeafRecord>> {
    let mut out: Vec<LeafRecord> = Vec::new();
    for record in records {
        if let Some(last) = out.last_mut()
            && can_merge(*last, record, blocks_per_cluster)
        {
            *last = merge_records(*last, record, inum)?;
            continue;
        }
        out.push(record);
    }
    Ok(out)
}

fn rewrite_leaf_records(
    buf: &mut [u8],
    records: &[LeafRecord],
    max: usize,
    inum: u32,
) -> Result<()> {
    write_entry_count(buf, records.len(), inum)?;
    for slot in 0..max {
        let off = entry_offset(slot);
        if off + EXTENT_ENTRY_SIZE > buf.len() {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        buf[off..off + EXTENT_ENTRY_SIZE].fill(0);
    }
    for (idx, record) in records.iter().enumerate() {
        write_leaf_record(buf, idx, *record, inum)?;
    }
    Ok(())
}

fn rewrite_index_records(
    buf: &mut [u8],
    records: &[IndexRecord],
    max: usize,
    inum: u32,
) -> Result<()> {
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    write_entry_count(buf, records.len(), inum)?;
    for slot in 0..max {
        let off = entry_offset(slot);
        if off + EXTENT_ENTRY_SIZE > buf.len() {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        buf[off..off + EXTENT_ENTRY_SIZE].fill(0);
    }
    for (idx, record) in records.iter().enumerate() {
        write_index_record(buf, idx, *record, inum)?;
    }
    Ok(())
}

/// Capacity of an external extent block, accounting for the 4-byte
/// `ext4_extent_tail` checksum slot (`eh_max = (block_size-12)/12 - 1`).
fn external_node_max(ext: &Ext) -> Result<usize> {
    let capacity = (ext.block_size() as usize)
        .checked_sub(EXTENT_HEADER_SIZE)
        .map(|usable| usable / EXTENT_ENTRY_SIZE)
        .ok_or(ExtError::InvalidExtentHeader { inode: 0 })?;
    capacity
        .checked_sub(1)
        .ok_or(ExtError::InvalidExtentHeader { inode: 0 })
}

fn write_node_header(buf: &mut [u8], entries: usize, max: usize, depth: u16, generation: u32) {
    buf[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    buf[2..4].copy_from_slice(&(entries as u16).to_le_bytes());
    buf[4..6].copy_from_slice(&(max as u16).to_le_bytes());
    buf[6..8].copy_from_slice(&depth.to_le_bytes());
    buf[8..12].copy_from_slice(&generation.to_le_bytes());
}

/// Read every leaf record present in `node` (driven by `eh_entries`).
fn node_leaf_records(node: &[u8], inum: u32) -> Result<Vec<LeafRecord>> {
    let hdr = checked_header(node, inum)?;
    validate_node_header(node, hdr, inum)?;
    leaf_records(node, usize::from(hdr.eh_entries.get()), inum)
}

/// Read every index record present in `node` (driven by `eh_entries`).
fn node_index_records(node: &[u8], inum: u32) -> Result<Vec<IndexRecord>> {
    let hdr = checked_header(node, inum)?;
    validate_node_header(node, hdr, inum)?;
    index_records(node, usize::from(hdr.eh_entries.get()), inum)
}

/// Build a fresh external leaf block holding `records`.
fn build_leaf_block(
    ext: &Ext,
    records: &[LeafRecord],
    generation: u32,
    inum: u32,
) -> Result<Vec<u8>> {
    let max = external_node_max(ext)?;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let mut block = alloc::vec![0u8; ext.block_size() as usize];
    write_node_header(&mut block, records.len(), max, 0, generation);
    for (idx, record) in records.iter().enumerate() {
        write_leaf_record(&mut block, idx, *record, inum)?;
    }
    Ok(block)
}

/// Build a fresh external index block holding `records` at `depth`.
fn build_index_block(
    ext: &Ext,
    records: &[IndexRecord],
    depth: u16,
    generation: u32,
    inum: u32,
) -> Result<Vec<u8>> {
    let max = external_node_max(ext)?;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let mut block = alloc::vec![0u8; ext.block_size() as usize];
    write_node_header(&mut block, records.len(), max, depth, generation);
    for (idx, record) in records.iter().enumerate() {
        write_index_record(&mut block, idx, *record, inum)?;
    }
    Ok(block)
}

/// Rewrite an existing leaf node's entries in place, preserving its `eh_max`.
fn rewrite_node_leaf(node: &[u8], records: &[LeafRecord], inum: u32) -> Result<Vec<u8>> {
    let hdr = checked_header(node, inum)?;
    let max = usize::from(hdr.eh_max.get());
    let mut patched = node.to_vec();
    rewrite_leaf_records(&mut patched, records, max, inum)?;
    Ok(patched)
}

/// Rewrite an existing index node's entries in place, preserving its `eh_max`.
fn rewrite_node_index(node: &[u8], records: &[IndexRecord], inum: u32) -> Result<Vec<u8>> {
    let hdr = checked_header(node, inum)?;
    let max = usize::from(hdr.eh_max.get());
    let mut patched = node.to_vec();
    rewrite_index_records(&mut patched, records, max, inum)?;
    Ok(patched)
}

/// Build a 60-byte inline index root one level above its single child.
fn build_inline_index_root(root: &[u8], records: &[IndexRecord], inum: u32) -> Result<Vec<u8>> {
    build_inline_index_root_at_depth(root, records, 1, inum)
}

/// Build a 60-byte inline index root at `depth` holding `records`. The inode
/// `i_block` root holds at most 4 entries.
fn build_inline_index_root_at_depth(
    root: &[u8],
    records: &[IndexRecord],
    depth: u16,
    inum: u32,
) -> Result<Vec<u8>> {
    if root.len() != 60 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let max = (60 - EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let generation = u32::from_le_bytes(root[8..12].try_into().expect("len 4"));
    let mut new_root = alloc::vec![0u8; 60];
    write_node_header(&mut new_root, records.len(), max, depth, generation);
    for (idx, record) in records.iter().enumerate() {
        write_index_record(&mut new_root, idx, *record, inum)?;
    }
    Ok(new_root)
}

/// Insert `new_entry` into `records` keeping ascending `logical` order. A
/// duplicate logical key is structural corruption.
fn insert_index_record_sorted(
    records: &mut Vec<IndexRecord>,
    new_entry: IndexRecord,
    inum: u32,
) -> Result<()> {
    let mut insert_pos = records.len();
    for (idx, record) in records.iter().enumerate() {
        if record.logical == new_entry.logical {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        if record.logical > new_entry.logical {
            insert_pos = idx;
            break;
        }
    }
    records.insert(insert_pos, new_entry);
    Ok(())
}

fn write_index_record(buf: &mut [u8], idx: usize, record: IndexRecord, inum: u32) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[off..off + 4].copy_from_slice(&record.logical.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&(record.child as u32).to_le_bytes());
    buf[off + 8..off + 10].copy_from_slice(&((record.child >> 32) as u16).to_le_bytes());
    buf[off + 10..off + 12].fill(0);
    Ok(())
}

fn write_leaf_record(buf: &mut [u8], idx: usize, record: LeafRecord, inum: u32) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let encoded_len = encode_extent_len(record.len, record.unwritten, inum)?;
    buf[off..off + 4].copy_from_slice(&record.logical.to_le_bytes());
    buf[off + 4..off + 6].copy_from_slice(&encoded_len.to_le_bytes());
    buf[off + 6..off + 8].copy_from_slice(&((record.pblk >> 32) as u16).to_le_bytes());
    buf[off + 8..off + 12].copy_from_slice(&(record.pblk as u32).to_le_bytes());
    Ok(())
}

fn write_index_logical(buf: &mut [u8], idx: usize, logical: u32, inum: u32) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[off..off + 4].copy_from_slice(&logical.to_le_bytes());
    Ok(())
}

fn remove_leaf_record(buf: &mut [u8], idx: usize, entries: usize, inum: u32) -> Result<()> {
    for slot in idx + 1..entries {
        let record = read_leaf_record(buf, slot, inum)?;
        write_leaf_record(buf, slot - 1, record, inum)?;
    }
    let last = entry_offset(entries - 1);
    if last + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[last..last + EXTENT_ENTRY_SIZE].fill(0);
    Ok(())
}

fn write_entry_count(buf: &mut [u8], entries: usize, inum: u32) -> Result<()> {
    let entries =
        u16::try_from(entries).map_err(|_| ExtError::InvalidExtentHeader { inode: inum })?;
    buf[2..4].copy_from_slice(&entries.to_le_bytes());
    Ok(())
}

fn logical_end(record: LeafRecord, inum: u32) -> Result<u32> {
    record
        .logical
        .checked_add(u32::from(record.len))
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })
}

fn first_leaf_logical(leaf: &[u8], inum: u32) -> Result<Option<u32>> {
    let hdr = checked_header(leaf, inum)?;
    validate_node_header(leaf, hdr, inum)?;
    if hdr.eh_depth.get() != 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    if hdr.eh_entries.get() == 0 {
        return Ok(None);
    }
    Ok(Some(read_leaf_record(leaf, 0, inum)?.logical))
}

fn empty_inline_leaf_root(root: &[u8], inum: u32) -> Result<Vec<u8>> {
    if root.len() != 60 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let hdr = checked_header(root, inum)?;
    let mut empty = alloc::vec![0u8; 60];
    empty[0..2].copy_from_slice(&hdr.eh_magic.get().to_le_bytes());
    empty[4..6].copy_from_slice(&4u16.to_le_bytes());
    Ok(empty)
}

fn extent_len_encodes(len: u16, unwritten: bool) -> bool {
    encode_extent_len(len, unwritten, u32::MAX).is_ok()
}

fn encode_extent_len(len: u16, unwritten: bool, inum: u32) -> Result<u16> {
    if len == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    if unwritten {
        // ext4 stores unwritten extents as raw ee_len > 0x8000.
        // 0x8000 itself is reserved for initialized length 32768, so
        // the largest encodable unwritten actual length is 32767.
        if len <= MAX_UNWRITTEN_EXTENT_LEN {
            Ok(len + UNWRITTEN_FLAG)
        } else {
            Err(ExtError::InvalidExtentHeader { inode: inum })
        }
    } else if len <= MAX_INITIALIZED_EXTENT_LEN {
        Ok(len)
    } else {
        Err(ExtError::InvalidExtentHeader { inode: inum })
    }
}

fn validate_new_extent(inum: u32, ext: RawExtent) -> Result<()> {
    encode_extent_len(ext.ee_len, ext.unwritten, inum)?;
    ext.ee_block
        .checked_add(u32::from(ext.ee_len))
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
    Ok(())
}

fn validate_physical_range(ext: &Ext, extent: RawExtent) -> Result<()> {
    if extent.ee_pblk < u64::from(ext.first_data_block) {
        return Err(ExtError::BlockOutOfRange {
            block: extent.ee_pblk,
        });
    }
    let end =
        extent
            .ee_pblk
            .checked_add(u64::from(extent.ee_len))
            .ok_or(ExtError::BlockOutOfRange {
                block: extent.ee_pblk,
            })?;
    if extent.ee_pblk >= ext.blocks_count || end > ext.blocks_count {
        return Err(ExtError::BlockOutOfRange { block: end });
    }
    Ok(())
}

fn logical_range_len_for_outcome(lblk_start: u32, lblk_end_inclusive: u32) -> u32 {
    if lblk_start > lblk_end_inclusive {
        return 0;
    }
    let len = u64::from(lblk_end_inclusive) - u64::from(lblk_start) + 1;
    u32::try_from(len).unwrap_or(u32::MAX)
}

impl LeafRecord {
    fn from_raw(ext: RawExtent) -> Self {
        Self {
            logical: ext.ee_block,
            len: ext.ee_len,
            pblk: ext.ee_pblk,
            unwritten: ext.unwritten,
        }
    }
}

fn entry_offset(idx: usize) -> usize {
    EXTENT_HEADER_SIZE + idx * EXTENT_ENTRY_SIZE
}

fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("len 2"))
}

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("len 4"))
}

fn mutator_error_to_ext(err: MutatorError) -> ExtError {
    match err {
        MutatorError::Ext(err) => err,
        MutatorError::BigallocClusterOverlap { inode, .. } => {
            ExtError::InvalidExtentHeader { inode }
        }
    }
}

fn surgery_error_to_outcome(err: SurgeryError) -> Result<ExtentSurgeryOutcome> {
    match err {
        SurgeryError::Failed(reason) => Ok(ExtentSurgeryOutcome::Failed(reason)),
        SurgeryError::RequiresMetadataAllocation => {
            Ok(ExtentSurgeryOutcome::RequiresMetadataAllocation)
        }
        SurgeryError::Ext(err) => structural_error_to_outcome(err),
    }
}

fn structural_error_to_outcome(err: ExtError) -> Result<ExtentSurgeryOutcome> {
    match err {
        ExtError::InvalidExtentHeader { .. } => Ok(ExtentSurgeryOutcome::Failed(
            ExtentReplayReason::ExtentHeaderMalformed,
        )),
        ExtError::Io(err) => Err(ExtError::Io(err)),
        err => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use crate::error::ExtError;
    use crate::ext::Ext;
    use crate::io::SeekFrom;
    use crate::orphan::Mutator;
    use std::io::Seek as _;
    use std::io::Write as _;

    use super::{ExtentSurgeon, ExtentSurgeryOutcome, RawExtent};

    const EXTENT_MAGIC: u16 = 0xF30A;
    const TEST_INUM: u32 = 12;

    #[test]
    fn decodes_initialized_extent() {
        let raw = [
            0x34, 0x12, 0x00, 0x00, // ee_block
            0x08, 0x00, // ee_len
            0x00, 0x00, // ee_start_hi
            0x78, 0x56, 0x34, 0x12, // ee_start_lo
        ];

        let extent = RawExtent::from_on_disk(&raw);

        assert_eq!(extent.ee_block, 0x1234);
        assert_eq!(extent.ee_len, 8);
        assert_eq!(extent.ee_pblk, 0x1234_5678);
        assert!(!extent.unwritten);
    }

    #[test]
    fn decodes_unwritten_extent_len_without_high_bit() {
        let raw = [
            0x01, 0x00, 0x00, 0x00, // ee_block
            0x05, 0x80, // ee_len with unwritten bit
            0x00, 0x00, // ee_start_hi
            0x02, 0x00, 0x00, 0x00, // ee_start_lo
        ];

        let extent = RawExtent::from_on_disk(&raw);

        assert_eq!(extent.ee_block, 1);
        assert_eq!(extent.ee_len, 5);
        assert_eq!(extent.ee_pblk, 2);
        assert!(extent.unwritten);
    }

    #[test]
    fn decodes_initialized_max_len_boundary() {
        let raw = [
            0x02, 0x00, 0x00, 0x00, // ee_block
            0x00, 0x80, // initialized max len, not unwritten
            0x00, 0x00, // ee_start_hi
            0x03, 0x00, 0x00, 0x00, // ee_start_lo
        ];

        let extent = RawExtent::from_on_disk(&raw);

        assert_eq!(extent.ee_len, 32768);
        assert!(!extent.unwritten);
    }

    #[test]
    fn composes_48_bit_physical_block() {
        let raw = [
            0x00, 0x00, 0x00, 0x00, // ee_block
            0x01, 0x00, // ee_len
            0x34, 0x12, // ee_start_hi
            0x78, 0x56, 0x34, 0x12, // ee_start_lo
        ];

        let extent = RawExtent::from_on_disk(&raw);

        assert_eq!(extent.ee_pblk, 0x1234_1234_5678);
    }

    #[test]
    fn add_range_inserts_into_empty_inode_root() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(ext, &mut cursor, &mut mutator, TEST_INUM, leaf_root(&[], 4));

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 4, 100, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 4, 100, false)]);
    }

    #[test]
    fn add_range_merges_with_left_neighbor_when_all_four_conditions_hold() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(4, 2, 104, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 6, 100, false)]);
    }

    #[test]
    fn add_range_does_not_merge_when_unwritten_flag_differs() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(4, 2, 104, true))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 4, 100, false), (4, 2, 104, true)]);
    }

    #[test]
    fn add_range_grows_full_inode_root_into_index_root_with_new_leaf() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[
                    raw_extent(0, 1, 100, false),
                    raw_extent(10, 1, 110, false),
                    raw_extent(20, 1, 120, false),
                    raw_extent(30, 1, 130, false),
                ],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(40, 1, 200, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(
            u16::from_le_bytes(root[6..8].try_into().unwrap()),
            1,
            "depth"
        );
        assert_eq!(
            u16::from_le_bytes(root[2..4].try_into().unwrap()),
            1,
            "entries"
        );
        let child = index_root_first_child(root);
        assert!(
            finalized_block_bitmap_bit(&delta.blocks, ext, child),
            "new leaf block bitmap bit set"
        );
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, child),
            vec![
                (0, 1, 100, false),
                (10, 1, 110, false),
                (20, 1, 120, false),
                (30, 1, 130, false),
                (40, 1, 200, false),
            ]
        );
        assert!(
            verify_finalized_extent_block(&delta.blocks, ext, TEST_INUM, child),
            "new leaf checksum valid"
        );
    }

    #[test]
    fn add_range_splits_full_external_leaf_when_parent_has_room() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let leaf_block = 220;
        mutator
            .mark_block_range_allocated(&mut cursor, leaf_block, 1)
            .expect("allocate leaf block");
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(0, 1, 100, false),
                    raw_extent(10, 1, 110, false),
                    raw_extent(20, 1, 120, false),
                    raw_extent(30, 1, 130, false),
                ],
                4,
                0,
            ),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(40, 1, 200, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(
            u16::from_le_bytes(root[2..4].try_into().unwrap()),
            2,
            "entries"
        );
        let mut all = finalized_extent_block_records(&delta.blocks, leaf_block);
        let new_leaf = index_root_second_child(root);
        all.extend(finalized_extent_block_records(&delta.blocks, new_leaf));
        assert_eq!(
            all,
            vec![
                (0, 1, 100, false),
                (10, 1, 110, false),
                (20, 1, 120, false),
                (30, 1, 130, false),
                (40, 1, 200, false),
            ]
        );
        assert!(finalized_block_bitmap_bit(&delta.blocks, ext, new_leaf));
        assert!(verify_finalized_extent_block(
            &delta.blocks,
            ext,
            TEST_INUM,
            new_leaf
        ));
    }

    #[test]
    fn add_range_splits_index_node_when_parent_index_also_full() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let leaves: [u64; 4] = [221, 222, 223, 224];
        let index_block = 225;
        for &block in &leaves {
            mutator
                .mark_block_range_allocated(&mut cursor, block, 1)
                .expect("allocate leaf");
        }
        mutator
            .mark_block_range_allocated(&mut cursor, index_block, 1)
            .expect("allocate index");
        for (idx, &block) in leaves.iter().enumerate() {
            let base = (idx as u32) * 10;
            stage_extent_block(
                ext,
                &mut cursor,
                &mut mutator,
                TEST_INUM,
                block,
                leaf_block_bytes(
                    ext,
                    &[
                        raw_extent(base, 1, 1000 + u64::from(base), false),
                        raw_extent(base + 2, 1, 1002 + u64::from(base), false),
                        raw_extent(base + 4, 1, 1004 + u64::from(base), false),
                        raw_extent(base + 6, 1, 1006 + u64::from(base), false),
                    ],
                    4,
                    0,
                ),
            );
        }
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_block,
            index_block_bytes(
                ext,
                &[
                    (0, leaves[0]),
                    (10, leaves[1]),
                    (20, leaves[2]),
                    (30, leaves[3]),
                ],
                4,
                1,
            ),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, index_block)], 4, 2),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(1, 1, 1900, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
        assert!(records.contains(&(1, 1, 1900, false)), "new extent present");
        assert_eq!(records.len(), 17, "16 original + 1 new extent");
        assert!(records.windows(2).all(|w| w[0].0 < w[1].0), "sorted");
    }

    #[test]
    fn add_range_leaf_split_is_cluster_aligned_under_bigalloc() {
        let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
        let leaf_block = 228;
        // Free a low cluster so the metadata-block allocator finds a slot
        // within the bigalloc fixture's cluster-bitmap window.
        mutator
            .mark_block_range_free(&mut cursor, 400, 4)
            .expect("free cluster");
        mutator
            .mark_block_range_allocated(&mut cursor, leaf_block, 1)
            .expect("allocate leaf");
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(0, 1, 100, false),
                    raw_extent(10, 1, 200, false),
                    raw_extent(20, 1, 300, false),
                    raw_extent(30, 1, 400, false),
                ],
                4,
                0,
            ),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(40, 1, 500, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        let new_leaf = index_root_second_child(root);
        assert!(
            new_leaf.is_multiple_of(u64::from(ext.blocks_per_cluster)),
            "allocated metadata block must be cluster-aligned: {new_leaf}"
        );
    }

    #[test]
    fn add_range_returns_requires_metadata_allocation_when_depth_would_exceed_max() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        // depth-5 inline root index -> depth-4..depth-1 external index nodes,
        // each full (4 entries), down to a full leaf. A leaf split must cascade
        // up through every full index node and try to grow the depth-5 root,
        // which would push depth to 6.
        let leaf_block = 240u64;
        let spine: [u64; 4] = [241, 242, 243, 244];
        for &block in spine.iter().chain(core::iter::once(&leaf_block)) {
            mutator
                .mark_block_range_allocated(&mut cursor, block, 1)
                .expect("allocate spine block");
        }
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(0, 1, 300, false),
                    raw_extent(2, 1, 302, false),
                    raw_extent(4, 1, 304, false),
                    raw_extent(6, 1, 306, false),
                ],
                4,
                0,
            ),
        );
        // spine[0] is depth-4; spine[3] is depth-1 (children are leaves). Each
        // node's filler entries occupy a per-level numeric band so that keys
        // propagated upward by a split never collide with a parent's keys.
        let stubs = |band: u32| [(band + 1, 300u64), (band + 2, 301u64), (band + 3, 302u64)];
        for (level, &block) in spine.iter().enumerate() {
            let depth = (4 - level) as u16;
            let child = if level + 1 < spine.len() {
                spine[level + 1]
            } else {
                leaf_block
            };
            let band = stubs(((level as u32) + 1) * 1_000_000);
            stage_extent_block(
                ext,
                &mut cursor,
                &mut mutator,
                TEST_INUM,
                block,
                index_block_bytes(ext, &[(0, child), band[0], band[1], band[2]], 4, depth),
            );
        }
        let root_band = stubs(9_000_000);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(
                &[(0, spine[0]), root_band[0], root_band[1], root_band[2]],
                4,
                5,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(1, 1, 500, false))
                .expect("add range")
        };

        // The grow cascade allocated several metadata blocks before reaching
        // the depth-5 root and giving up. `apply.rs::stop_current_tx` rolls
        // those back by dropping the per-transaction mutator, so this outcome
        // never leaves orphan metadata blocks behind.
        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::RequiresMetadataAllocation
        ));
    }

    #[test]
    fn del_range_leaf_split_when_punch_overflows_external_leaf() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let leaf_block = 230;
        mutator
            .mark_block_range_allocated(&mut cursor, leaf_block, 1)
            .expect("allocate leaf");
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(0, 2, old_pblk, false),
                    raw_extent(10, 2, old_pblk + 10, false),
                    raw_extent(20, 10, old_pblk + 20, false),
                    raw_extent(40, 2, old_pblk + 40, false),
                ],
                4,
                0,
            ),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 24, 25).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::AppliedNeedsShrink { .. }
        ));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
        assert_eq!(
            records,
            vec![
                (0, 2, old_pblk, false),
                (10, 2, old_pblk + 10, false),
                (20, 4, old_pblk + 20, false),
                (26, 4, old_pblk + 26, false),
                (40, 2, old_pblk + 40, false),
            ]
        );
    }

    #[test]
    fn add_range_remap_to_different_pblk_frees_old_physical_and_updates_extent() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let new_pblk = old_pblk + 32;
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 1, new_pblk, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 1, new_pblk, false)]);
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
    }

    #[test]
    fn add_range_flag_flip_in_place() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 4, 100, true))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 4, 100, true)]);
    }

    #[test]
    fn add_range_noop_when_already_matches() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 4, 100, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
        assert_eq!(records, vec![(0, 4, 100, false)]);
        assert_eq!(delta.blocks.len(), 1);
    }

    #[test]
    fn add_range_rejects_misaligned_pblk_under_bigalloc() {
        let ext = Ext::dummy_for_test_bigalloc(4);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        let sb_host_block = vec![0u8; ext.block_size() as usize].into_boxed_slice();
        let mut mutator = Mutator::new(ext, &sb_host_block);
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);

        let outcome = surgeon
            .add_range(TEST_INUM, raw_extent(0, 1, 2, false))
            .expect("add range");

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPblkNotClusterAligned)
        ));
    }

    #[test]
    fn add_range_external_leaf_insert_updates_parent_index_key() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let leaf_block = 200;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 2, 100, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 0);
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, leaf_block),
            vec![(0, 2, 100, false), (10, 2, 110, false)]
        );
    }

    #[test]
    fn add_range_external_leaf_flag_flip_patches_extent_block() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let leaf_block = 201;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(10, 2, 110, true))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, leaf_block),
            vec![(10, 2, 110, true)]
        );
    }

    #[test]
    fn add_range_rejects_child_depth_mismatch() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let child_block = 202;
        let grandchild_block = 203;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            grandchild_block,
            leaf_block_bytes(ext, &[], 4, 0),
        );
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            child_block,
            index_block_bytes(ext, &[(0, grandchild_block)], 4, 1),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, child_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 1, 100, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
        ));
    }

    #[test]
    fn add_range_rejects_overlapping_leaf_entries() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[raw_extent(10, 4, 110, false), raw_extent(12, 2, 120, false)],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(20, 1, 200, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
        ));
    }

    #[test]
    fn add_range_rejects_unsorted_leaf_entries() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[raw_extent(20, 1, 120, false), raw_extent(10, 1, 110, false)],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(30, 1, 130, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
        ));
    }

    #[test]
    fn add_range_returns_requires_metadata_allocation_when_unmapped_crosses_next_leaf_bound() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let left_leaf = 204;
        let right_leaf = 205;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            left_leaf,
            leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
        );
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            right_leaf,
            leaf_block_bytes(ext, &[raw_extent(20, 2, 120, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, left_leaf), (20, right_leaf)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(15, 10, 200, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::RequiresMetadataAllocation
        ));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, left_leaf),
            vec![(10, 2, 110, false)]
        );
    }

    #[test]
    fn add_range_partial_remap_splits_extent_and_frees_only_target_old_physical() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let new_pblk = old_pblk + 32;
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(3, 2, new_pblk, false))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![
                (0, 3, old_pblk, false),
                (3, 2, new_pblk, false),
                (5, 5, old_pblk + 5, false),
            ]
        );
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 3
        ));
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 4
        ));
    }

    #[test]
    fn add_range_partial_flag_flip_splits_extent_without_freeing_physical() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(3, 2, 103, true))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 3, 100, false), (3, 2, 103, true), (5, 5, 105, false),]
        );
        assert_eq!(delta.blocks.len(), 1);
    }

    #[test]
    fn add_range_partial_update_grows_tree_when_split_overflows_full_leaf() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, 100, false)], 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(3, 2, 103, true))
                .expect("add range")
        };

        assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
        assert_eq!(
            records,
            vec![(0, 3, 100, false), (3, 2, 103, true), (5, 5, 105, false)]
        );
    }

    #[test]
    fn add_range_maps_checksum_failure_to_failed_outcome() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        assert!(
            ext.checksum_seed().is_some(),
            "ext4.img fixture must exercise metadata checksums"
        );
        let leaf_block = 206;
        write_disk_block(
            ext,
            &mut cursor,
            leaf_block,
            &leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(10, 2, 110, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentBlockChecksumInvalid)
        ));
    }

    #[test]
    fn add_range_maps_child_out_of_range_to_failed_outcome() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, ext.blocks_count)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 1, 100, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::SiblingBlockOutOfRange)
        ));
    }

    #[test]
    fn add_range_maps_malformed_root_to_failed_outcome() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let mut root = leaf_root(&[], 4);
        root[0..2].copy_from_slice(&0xBEEFu16.to_le_bytes());
        stage_inode_root(ext, &mut cursor, &mut mutator, TEST_INUM, root);

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 1, 100, false))
                .expect("add range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
        ));
    }

    #[test]
    fn add_range_rejects_pblk_before_first_data_block() {
        let (ext, mut cursor, mut mutator) = fixture_mutator_with_first_data_block(10);

        let err = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .add_range(TEST_INUM, raw_extent(0, 1, 1, false))
                .expect_err("pblk before first_data_block must be rejected")
        };

        assert!(matches!(err, ExtError::BlockOutOfRange { block: 1 }));
    }

    #[test]
    fn del_range_removes_logical_range_and_frees_physical() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[
                    raw_extent(0, 2, old_pblk, false),
                    raw_extent(10, 2, old_pblk + 10, false),
                ],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 12);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(10, 2, old_pblk + 10, false)]
        );
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 1
        ));
    }

    #[test]
    fn del_range_partial_overlap_splits_extent() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 3, 4).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 10);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false),]
        );
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 3
        ));
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 4
        ));
    }

    #[test]
    fn del_range_collapses_emptied_leaf_and_frees_index_block() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let index_block = 210;
        let leaf_block = 211;
        mutator
            .mark_block_range_allocated(&mut cursor, index_block, 1)
            .expect("allocate index block");
        mutator
            .mark_block_range_allocated(&mut cursor, leaf_block, 1)
            .expect("allocate leaf block");
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(ext, &[raw_extent(0, 2, old_pblk, false)], 4, 0),
        );
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_block,
            index_block_bytes(ext, &[(0, leaf_block)], 4, 1),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, index_block)], 4, 2),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 0);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(u16::from_le_bytes(root[2..4].try_into().unwrap()), 0);
        assert_eq!(u16::from_le_bytes(root[6..8].try_into().unwrap()), 0);
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 1
        ));
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, index_block));
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, leaf_block));
    }

    #[test]
    fn del_range_returns_logical_range_invalid_for_overflow_lblk() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 2, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .del_range(TEST_INUM, u32::MAX, u32::MAX)
                .expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::LogicalRangeInvalid {
                lblk: u32::MAX,
                len: 1
            }
        ));
    }

    #[test]
    fn del_range_returns_explicit_shrink_followup_for_task22() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 2, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 1, 1).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 1);
    }

    #[test]
    fn shrink_inode_lowers_i_size_when_extent_end_is_below() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 5, old_pblk, false)], 4),
        );
        stage_inode_size(
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            u64::from(ext.block_size()) * 8,
        );

        {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            let outcome = surgeon.del_range(TEST_INUM, 3, 4).expect("delete range");
            let end_block_exclusive = shrink_end_block_exclusive(outcome);
            surgeon
                .shrink_inode(TEST_INUM, end_block_exclusive)
                .expect("shrink inode");
        }

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 3, old_pblk, false)]
        );
        assert_eq!(
            finalized_inode_size(&delta.blocks, ext, TEST_INUM),
            u64::from(ext.block_size()) * 3
        );
    }

    #[test]
    fn shrink_inode_all_extents_deleted_lowers_i_size_to_zero() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 2, old_pblk, false)], 4),
        );
        stage_inode_size(
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            u64::from(ext.block_size()) * 2,
        );

        {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            let outcome = surgeon.del_range(TEST_INUM, 0, 1).expect("delete range");
            let end_block_exclusive = shrink_end_block_exclusive(outcome);
            assert_eq!(end_block_exclusive, 0);
            surgeon
                .shrink_inode(TEST_INUM, end_block_exclusive)
                .expect("shrink inode");
        }

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![]
        );
        assert_eq!(finalized_inode_size(&delta.blocks, ext, TEST_INUM), 0);
    }

    #[test]
    fn shrink_inode_noop_does_not_create_inode_table_patch() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();

        {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .shrink_inode(TEST_INUM, u32::MAX)
                .expect("shrink inode");
        }

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.blocks.is_empty(),
            "no-op shrink must not stage an inode-table patch"
        );
    }

    #[test]
    fn shrink_inode_truncates_high_i_size_bits() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 2, old_pblk, false)], 4),
        );
        stage_inode_size(&mut cursor, &mut mutator, TEST_INUM, 5 * 1024 * 1024 * 1024);

        {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.shrink_inode(TEST_INUM, 2).expect("shrink inode");
        }

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_size(&delta.blocks, ext, TEST_INUM),
            u64::from(ext.block_size()) * 2
        );
    }

    #[test]
    fn shrink_inode_middle_delete_uses_furthest_extent_end() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let original_size = u64::from(ext.block_size()) * 10;
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
        );
        stage_inode_size(&mut cursor, &mut mutator, TEST_INUM, original_size);

        {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            let outcome = surgeon.del_range(TEST_INUM, 3, 4).expect("delete range");
            let end_block_exclusive = shrink_end_block_exclusive(outcome);
            assert_eq!(end_block_exclusive, 10);
            surgeon
                .shrink_inode(TEST_INUM, end_block_exclusive)
                .expect("shrink inode");
        }

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false)]
        );
        assert_eq!(
            finalized_inode_size(&delta.blocks, ext, TEST_INUM),
            original_size
        );
    }

    #[test]
    fn del_range_external_leaf_suffix_updates_parent_index_key() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let leaf_block = 212;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(10, 4, old_pblk, false),
                    raw_extent(20, 2, old_pblk + 20, false),
                ],
                4,
                0,
            ),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 10, 11).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 22);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 12);
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, leaf_block),
            vec![(12, 2, old_pblk + 2, false), (20, 2, old_pblk + 20, false)]
        );
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 1
        ));
    }

    #[test]
    fn del_range_middle_split_grows_tree_when_punch_overflows_full_leaf() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 10, old_pblk, false)], 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 3, 4).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::AppliedNeedsShrink { .. }
        ));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
        assert_eq!(
            records,
            vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false)]
        );
    }

    #[test]
    fn del_range_spans_external_leaves_and_frees_each_overlap() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        let old_pblk = first_root_data_block(ext, &mut cursor);
        let second_pblk = old_pblk + 32;
        mutator
            .mark_block_range_allocated(&mut cursor, second_pblk, 3)
            .expect("allocate second data run");
        let left_leaf = 213;
        let right_leaf = 214;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            left_leaf,
            leaf_block_bytes(ext, &[raw_extent(10, 3, old_pblk, false)], 4, 0),
        );
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            right_leaf,
            leaf_block_bytes(ext, &[raw_extent(20, 3, second_pblk, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, left_leaf), (20, right_leaf)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 12, 20).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 23);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
        assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(root[24..28].try_into().unwrap()), 21);
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, left_leaf),
            vec![(10, 2, old_pblk, false)]
        );
        assert_eq!(
            finalized_extent_block_records(&delta.blocks, right_leaf),
            vec![(21, 2, second_pblk + 1, false)]
        );
        assert!(!finalized_block_bitmap_bit(
            &delta.blocks,
            ext,
            old_pblk + 2
        ));
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, second_pblk));
    }

    #[test]
    fn del_range_maps_checksum_failure_to_failed_outcome() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        assert!(
            ext.checksum_seed().is_some(),
            "ext4.img fixture must exercise metadata checksums"
        );
        let leaf_block = 215;
        write_disk_block(
            ext,
            &mut cursor,
            leaf_block,
            &leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
        );
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(10, leaf_block)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 10, 11).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentBlockChecksumInvalid)
        ));
    }

    #[test]
    fn del_range_maps_child_out_of_range_to_failed_outcome() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            index_root(&[(0, ext.blocks_count)], 4, 1),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::SiblingBlockOutOfRange)
        ));
    }

    #[test]
    fn del_range_rejects_overlapping_leaf_entries() {
        let (ext, mut cursor, mut mutator) = fixture_mutator();
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[raw_extent(10, 4, 110, false), raw_extent(12, 2, 120, false)],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 11, 11).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
        ));
    }

    #[test]
    fn del_range_free_failure_does_not_patch_extent_tree_scratch() {
        let (ext, mut cursor, mut mutator) = fixture_mutator_with_first_data_block(10);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 2, 1, false)], 4),
        );

        let err = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .del_range(TEST_INUM, 0, 1)
                .expect_err("free below first_data_block must fail")
        };

        assert!(matches!(err, ExtError::BlockOutOfRange { block: 1 }));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 2, 1, false)]
        );
    }

    #[test]
    fn del_range_bigalloc_rejects_prefix_partial_cluster_without_dirtying() {
        assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(0, 0);
    }

    #[test]
    fn del_range_bigalloc_rejects_suffix_partial_cluster_without_dirtying() {
        assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(3, 3);
    }

    #[test]
    fn del_range_bigalloc_rejects_middle_partial_cluster_without_dirtying() {
        assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(1, 2);
    }

    #[test]
    fn del_range_bigalloc_full_cluster_delete_succeeds() {
        let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 0, 3).expect("delete range")
        };

        assert_del_range_applied_needs_shrink(outcome, 0);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![]
        );
        assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, 100));
    }

    #[test]
    fn del_range_bigalloc_rejects_full_cluster_delete_with_same_cluster_survivor() {
        let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(
                &[raw_extent(0, 4, 100, false), raw_extent(10, 1, 102, false)],
                4,
            ),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon.del_range(TEST_INUM, 0, 3).expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPartialClusterDelRange)
        ));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 4, 100, false), (10, 1, 102, false)]
        );
    }

    #[test]
    fn extent_len_encoding_boundaries_match_ext4_encoding() {
        assert_eq!(
            super::encode_extent_len(32768, false, TEST_INUM).expect("initialized max"),
            32768
        );
        assert_eq!(
            super::encode_extent_len(32767, true, TEST_INUM).expect("unwritten max"),
            65535
        );
        assert!(matches!(
            super::encode_extent_len(32768, true, TEST_INUM),
            Err(ExtError::InvalidExtentHeader { inode: TEST_INUM })
        ));
    }

    fn fixture_mutator() -> (&'static Ext, std::io::Cursor<Vec<u8>>, Mutator<'static>) {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let ext = Box::leak(Box::new(ext));
        let mutator = Mutator::new(ext, &sb_host_block);
        (ext, cursor, mutator)
    }

    fn fixture_mutator_with_first_data_block(
        first_data_block: u32,
    ) -> (&'static Ext, std::io::Cursor<Vec<u8>>, Mutator<'static>) {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let mut ext = Ext::new(&mut cursor).expect("open ext4.img");
        ext.first_data_block = first_data_block;
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let ext = Box::leak(Box::new(ext));
        let mutator = Mutator::new(ext, &sb_host_block);
        (ext, cursor, mutator)
    }

    fn fixture_bigalloc_mutator(
        blocks_per_cluster: u32,
    ) -> (&'static Ext, std::io::Cursor<Vec<u8>>, Mutator<'static>) {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let mut ext = Ext::new(&mut cursor).expect("open ext4.img");
        ext.ro_compat
            .insert(crate::feature_flags::RoCompatFeatures::BIGALLOC);
        ext.blocks_per_cluster = blocks_per_cluster;
        ext.cluster_size = ext.block_size * blocks_per_cluster;
        ext.clusters_per_group = ext.blocks_per_group / blocks_per_cluster;
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let ext = Box::leak(Box::new(ext));
        let mutator = Mutator::new(ext, &sb_host_block);
        (ext, cursor, mutator)
    }

    fn assert_del_range_applied_needs_shrink(
        outcome: ExtentSurgeryOutcome,
        expected_end_block_exclusive: u32,
    ) {
        assert_eq!(
            shrink_end_block_exclusive(outcome),
            expected_end_block_exclusive
        );
    }

    fn shrink_end_block_exclusive(outcome: ExtentSurgeryOutcome) -> u32 {
        let ExtentSurgeryOutcome::AppliedNeedsShrink {
            end_block_exclusive,
        } = outcome
        else {
            panic!("unexpected outcome: {outcome:?}");
        };
        end_block_exclusive
    }

    fn assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(
        lblk_start: u32,
        lblk_end_inclusive: u32,
    ) {
        let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
        stage_inode_root(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            leaf_root(&[raw_extent(0, 4, 100, false)], 4),
        );

        let outcome = {
            let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
            surgeon
                .del_range(TEST_INUM, lblk_start, lblk_end_inclusive)
                .expect("delete range")
        };

        assert!(matches!(
            outcome,
            ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPartialClusterDelRange)
        ));
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
            vec![(0, 4, 100, false)]
        );
        assert!(
            !delta.blocks.contains_key(&ext.group_descs[0].block_bitmap),
            "partial-cluster failure must happen before bitmap scratch is staged"
        );
    }

    fn raw_extent(ee_block: u32, ee_len: u16, ee_pblk: u64, unwritten: bool) -> RawExtent {
        RawExtent {
            ee_block,
            ee_len,
            ee_pblk,
            unwritten,
        }
    }

    fn leaf_root(extents: &[RawExtent], max: u16) -> [u8; 60] {
        let mut root = [0u8; 60];
        root[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        root[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
        root[4..6].copy_from_slice(&max.to_le_bytes());
        for (idx, extent) in extents.iter().enumerate() {
            write_extent_record(&mut root, 12 + idx * 12, *extent);
        }
        root
    }

    fn index_root(entries: &[(u32, u64)], max: u16, depth: u16) -> [u8; 60] {
        let mut root = [0u8; 60];
        root[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        root[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        root[4..6].copy_from_slice(&max.to_le_bytes());
        root[6..8].copy_from_slice(&depth.to_le_bytes());
        for (idx, &(logical, child)) in entries.iter().enumerate() {
            write_index_record(&mut root, 12 + idx * 12, logical, child);
        }
        root
    }

    fn leaf_block_bytes(ext: &Ext, extents: &[RawExtent], max: u16, depth: u16) -> Vec<u8> {
        let mut block = vec![0u8; ext.block_size() as usize];
        block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        block[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
        block[4..6].copy_from_slice(&max.to_le_bytes());
        block[6..8].copy_from_slice(&depth.to_le_bytes());
        for (idx, extent) in extents.iter().enumerate() {
            write_extent_record(&mut block, 12 + idx * 12, *extent);
        }
        block
    }

    fn index_block_bytes(ext: &Ext, entries: &[(u32, u64)], max: u16, depth: u16) -> Vec<u8> {
        let mut block = vec![0u8; ext.block_size() as usize];
        block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        block[2..4].copy_from_slice(&(entries.len() as u16).to_le_bytes());
        block[4..6].copy_from_slice(&max.to_le_bytes());
        block[6..8].copy_from_slice(&depth.to_le_bytes());
        for (idx, &(logical, child)) in entries.iter().enumerate() {
            write_index_record(&mut block, 12 + idx * 12, logical, child);
        }
        block
    }

    fn write_extent_record(buf: &mut [u8], offset: usize, extent: RawExtent) {
        buf[offset..offset + 4].copy_from_slice(&extent.ee_block.to_le_bytes());
        buf[offset + 4..offset + 6].copy_from_slice(&encoded_len(extent).to_le_bytes());
        buf[offset + 6..offset + 8].copy_from_slice(&((extent.ee_pblk >> 32) as u16).to_le_bytes());
        buf[offset + 8..offset + 12].copy_from_slice(&(extent.ee_pblk as u32).to_le_bytes());
    }

    fn write_index_record(buf: &mut [u8], offset: usize, logical: u32, child: u64) {
        buf[offset..offset + 4].copy_from_slice(&logical.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&(child as u32).to_le_bytes());
        buf[offset + 8..offset + 10].copy_from_slice(&((child >> 32) as u16).to_le_bytes());
    }

    fn encoded_len(extent: RawExtent) -> u16 {
        if extent.unwritten {
            extent.ee_len + 32768
        } else {
            extent.ee_len
        }
    }

    fn stage_inode_root<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        cursor: &mut T,
        mutator: &mut Mutator<'_>,
        inum: u32,
        root: [u8; 60],
    ) {
        assert!(inum <= ext.inodes_count);
        mutator
            .patch_inode_scratch(cursor, inum, |inode_bytes| {
                inode_bytes[0x00..0x02].copy_from_slice(&0x81A4u16.to_le_bytes());
                let flags = u32::from_le_bytes(inode_bytes[0x20..0x24].try_into().unwrap())
                    | crate::inode::InodeFlags::EXTENTS_FL.bits();
                inode_bytes[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
                inode_bytes[0x28..0x28 + 60].copy_from_slice(&root);
                Ok(())
            })
            .expect("stage inode root");
    }

    fn stage_inode_size<T: crate::io::Read + crate::io::Seek>(
        cursor: &mut T,
        mutator: &mut Mutator<'_>,
        inum: u32,
        size: u64,
    ) {
        mutator
            .patch_inode_scratch(cursor, inum, |inode_bytes| {
                inode_bytes[0x04..0x08].copy_from_slice(&(size as u32).to_le_bytes());
                inode_bytes[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
                Ok(())
            })
            .expect("stage inode size");
    }

    fn stage_extent_block<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        cursor: &mut T,
        mutator: &mut Mutator<'_>,
        inum: u32,
        block: u64,
        content: Vec<u8>,
    ) {
        assert_eq!(content.len(), ext.block_size() as usize);
        mutator
            .patch_extent_block(cursor, block, inum, 0, |block_bytes| {
                block_bytes.copy_from_slice(&content);
                Ok(())
            })
            .expect("stage extent block");
    }

    fn write_disk_block(
        ext: &Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        block: u64,
        content: &[u8],
    ) {
        assert_eq!(content.len(), ext.block_size() as usize);
        cursor
            .seek(SeekFrom::Start(block * u64::from(ext.block_size())))
            .expect("seek disk block");
        cursor.write_all(content).expect("write disk block");
    }

    fn finalized_inode_extent_root<'a>(
        blocks: &'a BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        inum: u32,
    ) -> &'a [u8] {
        let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
        &inode_bytes[0x28..0x28 + 60]
    }

    fn finalized_inode_extent_records(
        blocks: &BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        inum: u32,
    ) -> Vec<(u32, u16, u64, bool)> {
        let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
        let root = &inode_bytes[0x28..0x28 + 60];
        let entries = u16::from_le_bytes(root[2..4].try_into().unwrap()) as usize;
        let mut out = Vec::new();
        for idx in 0..entries {
            let off = 12 + idx * 12;
            let ee_block = u32::from_le_bytes(root[off..off + 4].try_into().unwrap());
            let ee_len_raw = u16::from_le_bytes(root[off + 4..off + 6].try_into().unwrap());
            let unwritten = ee_len_raw > 32768;
            let ee_len = if unwritten {
                ee_len_raw - 32768
            } else {
                ee_len_raw
            };
            let hi = u16::from_le_bytes(root[off + 6..off + 8].try_into().unwrap());
            let lo = u32::from_le_bytes(root[off + 8..off + 12].try_into().unwrap());
            let pblk = (u64::from(hi) << 32) | u64::from(lo);
            out.push((ee_block, ee_len, pblk, unwritten));
        }
        out
    }

    fn finalized_inode_size(blocks: &BTreeMap<u64, Box<[u8]>>, ext: &Ext, inum: u32) -> u64 {
        let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
        let lo = u32::from_le_bytes(inode_bytes[0x04..0x08].try_into().unwrap());
        let hi = u32::from_le_bytes(inode_bytes[0x6C..0x70].try_into().unwrap());
        u64::from(lo) | (u64::from(hi) << 32)
    }

    fn finalized_inode_bytes<'a>(
        blocks: &'a BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        inum: u32,
    ) -> &'a [u8] {
        let (block, offset, size) = inode_table_slot(ext, inum);
        let block_bytes = blocks.get(&block).expect("inode table block finalized");
        &block_bytes[offset..offset + size]
    }

    fn inode_table_slot(ext: &Ext, inum: u32) -> (u64, usize, usize) {
        let group = (inum - 1) / ext.inodes_per_group;
        let index_in_group = u64::from((inum - 1) % ext.inodes_per_group);
        let inode_size = u64::from(ext.inode_size());
        let byte_in_table = index_in_group * inode_size;
        let block_size = u64::from(ext.block_size());
        let table_block = ext.group_descs[group as usize].inode_table;
        let block = table_block + byte_in_table / block_size;
        let offset = (byte_in_table % block_size) as usize;
        (block, offset, inode_size as usize)
    }

    fn finalized_block_bitmap_bit(blocks: &BTreeMap<u64, Box<[u8]>>, ext: &Ext, pblk: u64) -> bool {
        let group =
            ((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group)) as usize;
        let bitmap_block = ext.group_descs[group].block_bitmap;
        let bitmap = blocks.get(&bitmap_block).expect("bitmap block finalized");
        let block_in_group =
            (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
        let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
        let byte = (alloc_unit / 8) as usize;
        let bit = (alloc_unit % 8) as u8;
        bitmap[byte] & (1u8 << bit) != 0
    }

    fn finalized_extent_block_records(
        blocks: &BTreeMap<u64, Box<[u8]>>,
        block: u64,
    ) -> Vec<(u32, u16, u64, bool)> {
        let block_bytes = blocks.get(&block).expect("extent block finalized");
        decoded_extent_records(block_bytes)
    }

    fn index_child(node: &[u8], idx: usize) -> u64 {
        let off = 12 + idx * 12;
        let lo = u32::from_le_bytes(node[off + 4..off + 8].try_into().unwrap());
        let hi = u16::from_le_bytes(node[off + 8..off + 10].try_into().unwrap());
        (u64::from(hi) << 32) | u64::from(lo)
    }

    fn index_root_first_child(root: &[u8]) -> u64 {
        index_child(root, 0)
    }

    fn index_root_second_child(root: &[u8]) -> u64 {
        index_child(root, 1)
    }

    fn verify_finalized_extent_block(
        blocks: &BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        inum: u32,
        block: u64,
    ) -> bool {
        let Some(seed) = ext.checksum_seed() else {
            return true;
        };
        let block_bytes = blocks.get(&block).expect("extent block finalized");
        crate::checksum::verify_extent_block(seed, inum, 0, block_bytes)
            == crate::checksum::ChecksumState::Valid
    }

    /// Walk the finalized extent tree (inode root + external blocks) and
    /// collect every leaf extent record, sorted by logical block.
    fn finalized_all_leaf_records<T: crate::io::Read + crate::io::Seek>(
        blocks: &BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        inum: u32,
        cursor: &mut T,
    ) -> Vec<(u32, u16, u64, bool)> {
        let root = finalized_inode_extent_root(blocks, ext, inum).to_vec();
        let mut out = Vec::new();
        collect_leaf_records(blocks, ext, &root, cursor, &mut out);
        out.sort_by_key(|record| record.0);
        out
    }

    fn collect_leaf_records<T: crate::io::Read + crate::io::Seek>(
        blocks: &BTreeMap<u64, Box<[u8]>>,
        ext: &Ext,
        node: &[u8],
        cursor: &mut T,
        out: &mut Vec<(u32, u16, u64, bool)>,
    ) {
        let depth = u16::from_le_bytes(node[6..8].try_into().unwrap());
        let entries = u16::from_le_bytes(node[2..4].try_into().unwrap()) as usize;
        if depth == 0 {
            out.extend(decoded_extent_records(node));
            return;
        }
        for idx in 0..entries {
            let child = index_child(node, idx);
            let child_bytes = blocks.get(&child).cloned().unwrap_or_else(|| {
                let mut buf = vec![0u8; ext.block_size() as usize];
                cursor
                    .seek(SeekFrom::Start(child * u64::from(ext.block_size())))
                    .expect("seek child");
                cursor.read_exact(&mut buf).expect("read child");
                buf.into_boxed_slice()
            });
            collect_leaf_records(blocks, ext, &child_bytes, cursor, out);
        }
    }

    fn decoded_extent_records(node: &[u8]) -> Vec<(u32, u16, u64, bool)> {
        let entries = u16::from_le_bytes(node[2..4].try_into().unwrap()) as usize;
        let mut out = Vec::new();
        for idx in 0..entries {
            let off = 12 + idx * 12;
            let ee_block = u32::from_le_bytes(node[off..off + 4].try_into().unwrap());
            let ee_len_raw = u16::from_le_bytes(node[off + 4..off + 6].try_into().unwrap());
            let unwritten = ee_len_raw > 32768;
            let ee_len = if unwritten {
                ee_len_raw - 32768
            } else {
                ee_len_raw
            };
            let hi = u16::from_le_bytes(node[off + 6..off + 8].try_into().unwrap());
            let lo = u32::from_le_bytes(node[off + 8..off + 12].try_into().unwrap());
            let pblk = (u64::from(hi) << 32) | u64::from(lo);
            out.push((ee_block, ee_len, pblk, unwritten));
        }
        out
    }

    fn first_root_data_block<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        cursor: &mut T,
    ) -> u64 {
        let inode = ext.inode(cursor, 2).expect("root inode");
        let i_block = inode.i_block();
        crate::extent::resolve_extent(ext, cursor, 2, inode.generation(), &i_block, 0)
            .expect("resolve root extent")
            .expect("root extent")
            .physical_block
    }

    fn read_sb_block<T: crate::io::Read + crate::io::Seek>(ext: &Ext, fs: &mut T) -> Box<[u8]> {
        let sb_host_block_num: u64 = if ext.block_size() > 1024 { 0 } else { 1 };
        let mut sb_bytes = vec![0u8; ext.block_size() as usize].into_boxed_slice();
        fs.seek(SeekFrom::Start(
            sb_host_block_num * u64::from(ext.block_size()),
        ))
        .expect("seek sb host");
        fs.read_exact(&mut sb_bytes).expect("read sb host");
        sb_bytes
    }
}
