use super::{
    DeleteNodeEdit, ExtError, ExtentReplayReason, LeafEdit, LeafRecord, LogicalDeleteRange,
    MappedEditContext, PlannedFree, PlannedFreeKind, RawExtent, Result, SurgeryError,
    SurgeryResult, Vec, checked_header, coalesce_records, encode_extent_len, extent_len_encodes,
    leaf_records, logical_end, read_leaf_record, remove_leaf_record, rewrite_leaf_records,
    validate_leaf_order, validate_node_header, write_entry_count, write_leaf_record,
};

pub(super) fn edit_leaf(
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

pub(super) fn edit_mapped_record(
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
    records.splice(ctx.idx..=ctx.idx, replacement);
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

fn delete_record_overlap(
    record: LeafRecord,
    range: LogicalDeleteRange,
    inum: u32,
    replacement: &mut Vec<LeafRecord>,
    free_ranges: &mut Vec<PlannedFree>,
) -> SurgeryResult<()> {
    let record_end = logical_end(record, inum)?;
    if record_end <= range.start || record.logical >= range.end_exclusive {
        replacement.push(record);
        return Ok(());
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
    Ok(())
}

pub(super) fn delete_from_leaf(
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
        delete_record_overlap(record, range, inum, &mut replacement, &mut free_ranges)?;
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

pub(super) fn max_leaf_logical_end(records: &[LeafRecord], inum: u32) -> Result<u32> {
    records.iter().try_fold(0, |max_end, record| {
        logical_end(*record, inum).map(|record_end| max_end.max(record_end))
    })
}

pub(super) fn validate_bigalloc_del_frees(
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

pub(super) fn range_touches_cluster_window(
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

pub(super) fn can_merge(left: LeafRecord, right: LeafRecord, blocks_per_cluster: u32) -> bool {
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

pub(super) fn merge_records(left: LeafRecord, right: LeafRecord, inum: u32) -> Result<LeafRecord> {
    let len = left
        .len
        .checked_add(right.len)
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
    encode_extent_len(len, left.unwritten, inum)?;
    Ok(LeafRecord { len, ..left })
}
