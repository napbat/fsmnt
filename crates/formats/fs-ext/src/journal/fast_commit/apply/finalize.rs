use super::{
    BTreeSet, BlockOverlay, Ext, ExtError, FastCommitPlan, FastCommitPosition, FastCommitStop,
    FastCommitTagCounts, FastCommitWarning, FastCommitWarningKind, Mutator, MutatorError,
    OrphanOverlayDelta, Read, Result, ScanResult, Seek, Vec, WARNING_CAP,
};

pub(crate) fn merge_delta_into_overlay(overlay: &mut BlockOverlay, delta: OrphanOverlayDelta) {
    for (block, content) in delta.blocks {
        overlay.blocks.insert(block, content);
    }
    if let Some(sb_host) = delta.sb_host_override {
        overlay.sb_host_block_content = sb_host;
    }
}

pub(super) fn merge_tag_counts(dst: &mut FastCommitTagCounts, src: &FastCommitTagCounts) {
    dst.head += src.head;
    dst.pad += src.pad;
    dst.inode += src.inode;
    dst.creat += src.creat;
    dst.link += src.link;
    dst.unlink += src.unlink;
    dst.add_range += src.add_range;
    dst.del_range += src.del_range;
}

pub(super) fn push_warning_capped(plan: &mut FastCommitPlan, warning: FastCommitWarning) {
    if let Some(existing) = plan
        .warnings
        .iter_mut()
        .find(|existing| same_aggregation_key(existing, &warning))
    {
        existing.occurrences += warning.occurrences;
        return;
    }
    if plan.warnings.len() >= WARNING_CAP {
        plan.warnings_truncated = true;
        return;
    }
    plan.warnings.push(warning);
}

pub(super) fn same_aggregation_key(a: &FastCommitWarning, b: &FastCommitWarning) -> bool {
    use FastCommitWarningKind::{
        DirectoryReplayFailed, FinalizerExtentWalkFailed, InodeOutOfRange, LogicalRangeInvalid,
        PhysicalBlockOutOfRange, UnlinkTargetMissing,
    };
    match (&a.kind, &b.kind) {
        (InodeOutOfRange { inum: x }, InodeOutOfRange { inum: y })
        | (PhysicalBlockOutOfRange { inum: x, .. }, PhysicalBlockOutOfRange { inum: y, .. })
        | (LogicalRangeInvalid { inum: x, .. }, LogicalRangeInvalid { inum: y, .. })
        | (FinalizerExtentWalkFailed { inum: x }, FinalizerExtentWalkFailed { inum: y }) => x == y,
        (
            DirectoryReplayFailed {
                parent_inum: pa,
                reason: ra,
            },
            DirectoryReplayFailed {
                parent_inum: pb,
                reason: rb,
            },
        ) => pa == pb && ra == rb,
        (
            UnlinkTargetMissing {
                parent_inum: pa,
                child_inum: ca,
            },
            UnlinkTargetMissing {
                parent_inum: pb,
                child_inum: cb,
            },
        ) => pa == pb && ca == cb,
        _ => false,
    }
}

pub(super) fn propagate_scan_stop(plan: &mut FastCommitPlan, scan: &ScanResult) {
    if plan.stop.is_none()
        && let Some(stop) = scan.stop.as_ref()
    {
        plan.stop = Some(clone_stop(stop));
    }
}

pub(super) fn clone_stop(stop: &FastCommitStop) -> FastCommitStop {
    FastCommitStop {
        position: stop.position,
        last_committed_tid: stop.last_committed_tid,
        reason: stop.reason,
    }
}

pub(crate) fn mutator_error_to_ext(err: MutatorError) -> ExtError {
    match err {
        MutatorError::Ext(err) => err,
        MutatorError::BigallocClusterOverlap { inode, .. } => {
            ExtError::InvalidExtentHeader { inode }
        }
    }
}

/// Pass-C: reconcile allocation bitmaps for every inode modified by committed
/// fast-commit transactions. The returned mutator is finalized and merged by
/// the caller after this pass.
pub(crate) fn finalize_pass<'a, T: Read + Seek>(
    ext: &'a Ext,
    reader: &mut T,
    mut mutator: Mutator<'a>,
    modified_inodes: &BTreeSet<u32>,
    plan: &mut FastCommitPlan,
) -> Result<Mutator<'a>> {
    'inode: for &inum in modified_inodes {
        let inode = match ext.inode(reader, inum) {
            Ok(inode) => inode,
            Err(ExtError::Io(err)) => return Err(ExtError::Io(err)),
            Err(_) => {
                push_finalizer_extent_walk_failed(plan, inum);
                continue;
            }
        };

        if inode
            .flags()
            .contains(crate::inode::InodeFlags::INLINE_DATA_FL)
        {
            continue;
        }
        if !inode.flags().contains(crate::inode::InodeFlags::EXTENTS_FL) {
            push_finalizer_extent_walk_failed(plan, inum);
            continue;
        }

        let i_block = inode.i_block();
        let generation = inode.generation();
        let mut allocations = Vec::new();
        match crate::extent::collect_tagged_extent_blocks_into(
            ext,
            reader,
            inum,
            generation,
            &i_block,
            &mut allocations,
        ) {
            Ok(()) => {}
            Err(ExtError::Io(err)) => return Err(ExtError::Io(err)),
            Err(_) => {
                push_finalizer_extent_walk_failed(plan, inum);
                continue;
            }
        }

        if allocations.iter().any(|&allocation| {
            let (pblk, len) = allocation_physical_range(allocation);
            allocation_range_invalid(ext, pblk, len)
        }) {
            push_finalizer_extent_walk_failed(plan, inum);
            continue;
        }

        for allocation in allocations {
            let (pblk, len) = allocation_physical_range(allocation);
            let changed = match mutator.mark_block_range_allocated(reader, pblk, len) {
                Ok(changed) => changed,
                Err(MutatorError::Ext(ExtError::Io(err))) => return Err(ExtError::Io(err)),
                Err(_) => {
                    push_finalizer_extent_walk_failed(plan, inum);
                    continue 'inode;
                }
            };
            plan.allocation_units_marked_allocated += u64::from(changed);
        }
    }

    Ok(mutator)
}

pub(super) fn allocation_physical_range(allocation: crate::extent::ExtentAllocation) -> (u64, u32) {
    match allocation {
        crate::extent::ExtentAllocation::Data {
            physical_start,
            block_len,
            ..
        } => (physical_start, block_len),
        crate::extent::ExtentAllocation::IndexBlock(block) => (block, 1),
    }
}

pub(super) fn allocation_range_invalid(ext: &Ext, pblk: u64, len: u32) -> bool {
    if len == 0 || pblk < u64::from(ext.first_data_block) {
        return true;
    }
    let Some(end) = pblk.checked_add(u64::from(len)) else {
        return true;
    };
    pblk >= ext.blocks_count || end > ext.blocks_count
}

pub(super) fn push_finalizer_extent_walk_failed(plan: &mut FastCommitPlan, inum: u32) {
    push_warning_capped(
        plan,
        FastCommitWarning {
            position: FastCommitPosition {
                fc_block: 0,
                block_offset: 0,
                fs_byte_offset: 0,
            },
            current_tid: None,
            kind: FastCommitWarningKind::FinalizerExtentWalkFailed { inum },
            occurrences: 1,
        },
    );
}
