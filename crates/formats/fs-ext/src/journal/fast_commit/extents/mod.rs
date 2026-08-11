//! Fast-commit extent-tree surgery. See spec §9.
use alloc::vec::Vec;

use crate::checksum::ChecksumState;
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::parse_header;
use crate::io::{Read, Seek};
use crate::orphan::{Mutator, MutatorError};

use super::plan::ExtentReplayReason;

mod edit;
mod grow;
mod tree;

use edit::{can_merge, delete_from_leaf, edit_leaf, merge_records, validate_bigalloc_del_frees};
use tree::{
    build_index_block, build_inline_index_root, build_inline_index_root_at_depth, build_leaf_block,
    checked_header, choose_child_entry, coalesce_records, empty_inline_leaf_root,
    encode_extent_len, extent_len_encodes, first_leaf_logical, index_records,
    insert_index_record_sorted, leaf_records, logical_end, logical_range_len_for_outcome,
    mutator_error_to_ext, node_index_records, node_leaf_records, read_index_record,
    read_leaf_record, remove_leaf_record, rewrite_index_records, rewrite_leaf_records,
    rewrite_node_index, rewrite_node_leaf, structural_error_to_outcome, surgery_error_to_outcome,
    validate_index_order, validate_leaf_order, validate_new_extent, validate_node_header,
    validate_physical_range, write_entry_count, write_index_logical, write_leaf_record,
};

const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_ENTRY_SIZE: usize = 12;
const MAX_EXTENT_DEPTH: u16 = 5;
const MAX_INITIALIZED_EXTENT_LEN: u16 = 32768;
const MAX_UNWRITTEN_EXTENT_LEN: u16 = 32767;
const UNWRITTEN_FLAG: u16 = 32768;

/// FC `ADD_RANGE` extent record decoded from on-disk bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawExtent {
    pub ee_block: u32,
    pub ee_len: u16,
    pub ee_pblk: u64,
    pub unwritten: bool,
}

impl RawExtent {
    /// Decode the 12-byte `struct ext4_extent` payload from
    /// FC `ADD_RANGE` (`fc_ex` field). All fields little-endian.
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
    /// `ADD_RANGE` or `DEL_RANGE` would require a new extent index/leaf block.
    RequiresMetadataAllocation,
    /// `DEL_RANGE` applied and Task 22 must shrink inode size if needed.
    AppliedNeedsShrink {
        /// Furthest post-delete logical extent end, exclusive. Empty files use
        /// zero, matching `shrink_inode`'s byte-size contract.
        end_block_exclusive: u32,
    },
    /// `DEL_RANGE` only -- caller should skip this record and emit
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

    /// Attempt an in-place `ADD_RANGE` edit against the current tree. Returns
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

    /// Re-run a `DEL_RANGE` delete after a tree grow added the leaf capacity the
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
                let size_bytes = target_size.to_le_bytes();
                inode_bytes[0x04..0x08].copy_from_slice(&size_bytes[..4]);
                inode_bytes[0x6C..0x70].copy_from_slice(&size_bytes[4..]);
                Ok(())
            })
            .map_err(mutator_error_to_ext)
    }

    fn delete_index_children(
        &mut self,
        original: &[IndexRecord],
        params: DeleteIndexParams,
    ) -> SurgeryResult<DeleteIndexState> {
        let mut state = DeleteIndexState::default();
        for (index, record) in original.iter().copied().enumerate() {
            let next_logical = original.get(index + 1).map(|next| next.logical);
            let outside_range = params.range.end_exclusive <= record.logical
                || next_logical.is_some_and(|upper| params.range.start >= upper);
            if outside_range {
                if params.blocks_per_cluster > 1 {
                    let child_bytes = self.read_child_node(
                        params.inum,
                        params.generation,
                        record.child,
                        params.depth - 1,
                    )?;
                    let child_end = self.collect_data_ranges_and_logical_end(
                        params.inum,
                        params.generation,
                        &child_bytes,
                        &mut state.surviving_data_ranges,
                        true,
                    )?;
                    state.last_surviving_child_end = RightmostChildEnd::Known(child_end);
                } else {
                    state.last_surviving_child_end = RightmostChildEnd::Unresolved;
                }
                state.surviving.push(record);
                continue;
            }

            let child_bytes = self.read_child_node(
                params.inum,
                params.generation,
                record.child,
                params.depth - 1,
            )?;
            let mut child_edit = self.delete_node(
                params.inum,
                params.generation,
                &child_bytes,
                Some(record.child),
                params.range,
                params.blocks_per_cluster,
            )?;
            state.free_ranges.append(&mut child_edit.free_ranges);
            state
                .surviving_data_ranges
                .append(&mut child_edit.surviving_data_ranges);
            state.patches.append(&mut child_edit.patches);
            if let Some(child_node) = child_edit.bytes {
                let first_logical = child_edit
                    .first_logical
                    .ok_or(ExtError::InvalidExtentHeader { inode: params.inum })?;
                if child_edit.changed {
                    state.patches.push((record.child, child_node));
                }
                state.surviving.push(IndexRecord {
                    logical: first_logical,
                    child: record.child,
                });
                state.last_surviving_child_end =
                    RightmostChildEnd::Known(child_edit.end_block_exclusive);
            }
        }
        Ok(state)
    }

    fn finish_index_delete(
        &mut self,
        node: &[u8],
        this_block: Option<u64>,
        max: usize,
        original: &[IndexRecord],
        mut state: DeleteIndexState,
        params: DeleteIndexParams,
    ) -> SurgeryResult<DeleteNodeEdit> {
        if state.surviving.is_empty() {
            if let Some(block) = this_block {
                state.free_ranges.push(PlannedFree {
                    pblk: block,
                    len: 1,
                    kind: PlannedFreeKind::Metadata,
                });
                return Ok(DeleteNodeEdit {
                    bytes: None,
                    changed: true,
                    first_logical: None,
                    free_ranges: state.free_ranges,
                    surviving_data_ranges: state.surviving_data_ranges,
                    end_block_exclusive: 0,
                    patches: state.patches,
                });
            }
            return Ok(DeleteNodeEdit {
                bytes: Some(empty_inline_leaf_root(node, params.inum)?),
                changed: true,
                first_logical: None,
                free_ranges: state.free_ranges,
                surviving_data_ranges: state.surviving_data_ranges,
                end_block_exclusive: 0,
                patches: state.patches,
            });
        }

        let end_block_exclusive = match state.last_surviving_child_end {
            RightmostChildEnd::Known(end) => end,
            RightmostChildEnd::Unresolved => {
                let rightmost = state
                    .surviving
                    .last()
                    .ok_or(ExtError::InvalidExtentHeader { inode: params.inum })?;
                let child_bytes = self.read_child_node(
                    params.inum,
                    params.generation,
                    rightmost.child,
                    params.depth - 1,
                )?;
                self.collect_data_ranges_and_logical_end(
                    params.inum,
                    params.generation,
                    &child_bytes,
                    &mut state.surviving_data_ranges,
                    false,
                )?
            }
            RightmostChildEnd::Absent => 0,
        };
        let changed = state.surviving != original;
        let bytes = if changed {
            let mut rewritten_node = node.to_vec();
            rewrite_index_records(&mut rewritten_node, &state.surviving, max, params.inum)?;
            Some(rewritten_node)
        } else {
            Some(node.to_vec())
        };
        Ok(DeleteNodeEdit {
            bytes,
            changed,
            first_logical: state.surviving.first().map(|record| record.logical),
            free_ranges: state.free_ranges,
            surviving_data_ranges: state.surviving_data_ranges,
            end_block_exclusive,
            patches: state.patches,
        })
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
        let params = DeleteIndexParams {
            inum,
            generation,
            depth,
            range,
            blocks_per_cluster,
        };
        let state = self.delete_index_children(&original, params)?;
        self.finish_index_delete(node, this_block, max, &original, state, params)
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

#[derive(Clone, Copy)]
struct DeleteIndexParams {
    inum: u32,
    generation: u32,
    depth: u16,
    range: LogicalDeleteRange,
    blocks_per_cluster: u32,
}

#[derive(Default)]
struct DeleteIndexState {
    surviving: Vec<IndexRecord>,
    last_surviving_child_end: RightmostChildEnd,
    free_ranges: Vec<PlannedFree>,
    surviving_data_ranges: Vec<(u64, u32)>,
    patches: Vec<(u64, Vec<u8>)>,
}

#[derive(Default)]
enum RightmostChildEnd {
    #[default]
    Absent,
    Unresolved,
    Known(u32),
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

#[cfg(test)]
#[path = "../extents_tests/mod.rs"]
mod tests;
