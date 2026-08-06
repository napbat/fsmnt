use super::{
    AncestorNode, ExtError, ExtentSurgeon, ExtentSurgeryOutcome, GrowResult, IndexRecord,
    IndexSplitContext, LeafLocation, LeafTarget, MAX_EXTENT_DEPTH, Read, Result, Seek,
    build_index_block, build_inline_index_root, build_inline_index_root_at_depth, build_leaf_block,
    checked_header, insert_index_record_sorted, node_index_records, node_leaf_records,
    rewrite_node_index, rewrite_node_leaf, surgery_error_to_outcome,
};

impl<T: Read + Seek> ExtentSurgeon<'_, '_, T> {
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
    pub(super) fn grow_for_add(
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
