//! Fast-commit pass-B applier and pass-C finalizer. See spec sections 5.2-5.3.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::extents::{ExtentSurgeon, ExtentSurgeryOutcome, RawExtent};
use super::parse::{RegionCursor, ScanResult};
use super::plan::{
    DirectoryReplayReason, FastCommitPlan, FastCommitPosition, FastCommitStop,
    FastCommitStopReason, FastCommitTagCounts, FastCommitWarning, FastCommitWarningKind,
};
use super::tlv::{
    FC_TAG_ADD_RANGE, FC_TAG_CREAT, FC_TAG_DEL_RANGE, FC_TAG_HEAD, FC_TAG_INODE, FC_TAG_LINK,
    FC_TAG_PAD, FC_TAG_TAIL, FC_TAG_UNLINK, decode_add_range, decode_del_range, decode_dentry,
    decode_head, decode_inode, decode_tail,
};
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{Read, Seek};
use crate::journal::replay::BlockOverlay;
use crate::orphan::{
    DirReplayOutcome, HtreeSurgeon, LinkCountChange, Mutator, MutatorError, OrphanOverlayDelta,
};

/// Maximum entries retained in `FastCommitPlan::warnings` (spec section 7.4).
mod finalize;
mod helpers;

pub(crate) use finalize::{finalize_pass, merge_delta_into_overlay, mutator_error_to_ext};
use finalize::{merge_tag_counts, propagate_scan_stop, push_warning_capped};
use helpers::{
    adjust_child_links_count, compose_reader, current_inode_flags, current_inode_mode,
    dentry_file_type, increment_dentry_tag_count, logical_range_invalid, physical_range_invalid,
    position_at, push_directory_replay_warning, push_warning_to_tx, stop_current_tx,
};

const WARNING_CAP: usize = 256;
const S_IFMT: u16 = 0xF000;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;

/// Per-transaction counters and warnings. The mutation scratch lives in the
/// companion per-tx `Mutator`; rollback is dropping that mutator before TAIL.
pub(crate) struct TxBuffer {
    pub(crate) current_tid: u32,
    pub(crate) tag_counts: FastCommitTagCounts,
    pub(crate) warnings: Vec<FastCommitWarning>,
    pub(crate) modified_inodes: BTreeSet<u32>,
    pub(crate) allocation_units_marked_free: u64,
    pub(crate) allocation_units_marked_allocated: u64,
}

pub(crate) struct ApplyState {
    pub(crate) plan: FastCommitPlan,
    pub(crate) modified_inodes: BTreeSet<u32>,
    pub(crate) composed_overlay: BlockOverlay,
}

/// Pass-B: apply `scan.valid_tag_count` validated tags. Each FC transaction
/// gets a fresh mutator, committed only when its TAIL is reached.
pub(crate) fn apply_pass<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    mut composed_overlay: BlockOverlay,
    blocks: &[&[u8]],
    block_size: u32,
    fc_first: u32,
    scan: &ScanResult,
) -> Result<ApplyState> {
    let mut plan = FastCommitPlan::default();
    let mut modified_inodes = BTreeSet::new();

    if scan.valid_tag_count == 0 {
        propagate_scan_stop(&mut plan, scan);
        return Ok(ApplyState {
            plan,
            modified_inodes,
            composed_overlay,
        });
    }

    let mut remaining = scan.valid_tag_count;
    let mut tx_state: Option<(Mutator<'_>, TxBuffer)> = None;
    let mut cursor = RegionCursor::new(blocks);

    while remaining > 0 {
        let (rel_block_idx, record_offset) = cursor.position();
        let Some(header) = cursor.read_header() else {
            break;
        };
        let tag = u16::from_le_bytes([header[0], header[1]]);
        let fc_len = u16::from_le_bytes([header[2], header[3]]);

        if tag == 0 && fc_len == 0 && tx_state.is_none() {
            cursor.advance_to_next_block();
            continue;
        }

        let Some(payload) = cursor.read_exact_vec(usize::from(fc_len)) else {
            break;
        };

        let record = PassRecord {
            relative_block: rel_block_idx,
            record_offset,
            tag,
            value_len: fc_len,
            payload: &payload,
        };
        let should_stop = apply_record(
            &mut ApplyRecordContext {
                ext,
                fs,
                composed_overlay: &mut composed_overlay,
                tx_state: &mut tx_state,
                plan: &mut plan,
                modified_inodes: &mut modified_inodes,
                block_size,
                fc_first,
            },
            &record,
        )?;
        remaining -= 1;
        if should_stop {
            break;
        }
    }

    propagate_scan_stop(&mut plan, scan);
    plan.inodes_modified = u32::try_from(modified_inodes.len()).unwrap_or(u32::MAX);

    Ok(ApplyState {
        plan,
        modified_inodes,
        composed_overlay,
    })
}

struct PassRecord<'a> {
    relative_block: usize,
    record_offset: usize,
    tag: u16,
    value_len: u16,
    payload: &'a [u8],
}

struct ApplyRecordContext<'ext, 'work, T> {
    ext: &'ext Ext,
    fs: &'work mut T,
    composed_overlay: &'work mut BlockOverlay,
    tx_state: &'work mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &'work mut FastCommitPlan,
    modified_inodes: &'work mut BTreeSet<u32>,
    block_size: u32,
    fc_first: u32,
}

fn begin_transaction<'ext>(
    ext: &'ext Ext,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    payload: &[u8],
) -> Result<()> {
    let head = decode_head(payload)?;
    let superblock_host = composed_overlay.sb_host_block_content.to_vec();
    *tx_state = Some((
        Mutator::new(ext, &superblock_host),
        TxBuffer {
            current_tid: head.tid,
            tag_counts: FastCommitTagCounts {
                head: 1,
                ..FastCommitTagCounts::default()
            },
            warnings: Vec::new(),
            modified_inodes: BTreeSet::new(),
            allocation_units_marked_free: 0,
            allocation_units_marked_allocated: 0,
        },
    ));
    Ok(())
}

fn apply_inode_pass_record<T: Read + Seek>(
    context: &mut ApplyRecordContext<'_, '_, T>,
    record: &PassRecord<'_>,
    position: FastCommitPosition,
) -> Result<bool> {
    let inode = decode_inode(record.payload)?;
    let inode_size = usize::from(context.ext.inode_size());
    if !(128..=inode_size).contains(&inode.raw_inode.len()) {
        stop_current_tx(
            context.tx_state,
            context.plan,
            position,
            FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_INODE,
                fc_len: record.value_len,
                reason: "inode raw_inode length out of [128, s_inode_size]",
            },
        );
        return Ok(true);
    }
    if inode.fc_ino == 0 || inode.fc_ino > context.ext.inodes_count {
        if let Some((_, transaction)) = context.tx_state.as_mut() {
            let current_tid = transaction.current_tid;
            push_warning_to_tx(
                transaction,
                FastCommitWarning {
                    position,
                    current_tid: Some(current_tid),
                    kind: FastCommitWarningKind::InodeOutOfRange { inum: inode.fc_ino },
                    occurrences: 1,
                },
            );
            transaction.tag_counts.inode += 1;
        }
        return Ok(false);
    }
    if let Some((mutator, transaction)) = context.tx_state.as_mut() {
        mutator
            .patch_inode_scratch(
                &mut compose_reader(context.fs, context.composed_overlay),
                inode.fc_ino,
                |bytes| {
                    bytes[..inode.raw_inode.len()].copy_from_slice(inode.raw_inode);
                    Ok(())
                },
            )
            .map_err(mutator_error_to_ext)?;
        transaction.modified_inodes.insert(inode.fc_ino);
        transaction.tag_counts.inode += 1;
    }
    Ok(false)
}

fn commit_transaction<T: Read + Seek>(context: &mut ApplyRecordContext<'_, '_, T>) -> Result<()> {
    let Some((mutator, transaction)) = context.tx_state.take() else {
        return Ok(());
    };
    let delta = {
        let mut overlay_reader = compose_reader(context.fs, context.composed_overlay);
        mutator.finalize(&mut overlay_reader)
    }
    .map_err(mutator_error_to_ext)?;
    merge_delta_into_overlay(context.composed_overlay, delta);
    context.plan.transactions_replayed += 1;
    merge_tag_counts(&mut context.plan.tag_counts, &transaction.tag_counts);
    context.plan.tag_counts.tail += 1;
    context.plan.last_committed_tid = Some(transaction.current_tid);
    context.plan.allocation_units_marked_free += transaction.allocation_units_marked_free;
    context.plan.allocation_units_marked_allocated += transaction.allocation_units_marked_allocated;
    context.modified_inodes.extend(transaction.modified_inodes);
    for warning in transaction.warnings {
        push_warning_capped(context.plan, warning);
    }
    Ok(())
}

fn apply_record<T: Read + Seek>(
    context: &mut ApplyRecordContext<'_, '_, T>,
    record: &PassRecord<'_>,
) -> Result<bool> {
    let position = position_at(
        record.relative_block,
        record.record_offset,
        context.block_size,
        context.fc_first,
    );
    match record.tag {
        FC_TAG_HEAD => {
            begin_transaction(
                context.ext,
                context.composed_overlay,
                context.tx_state,
                record.payload,
            )?;
            Ok(false)
        }
        FC_TAG_PAD => {
            if let Some((_, transaction)) = context.tx_state.as_mut() {
                transaction.tag_counts.pad += 1;
            }
            Ok(false)
        }
        FC_TAG_INODE => apply_inode_pass_record(context, record, position),
        FC_TAG_CREAT | FC_TAG_LINK | FC_TAG_UNLINK => apply_dentry_record(
            context.ext,
            context.fs,
            context.composed_overlay,
            context.tx_state,
            context.plan,
            &DentryRecord {
                position,
                tag: record.tag,
                payload: record.payload,
            },
        ),
        FC_TAG_ADD_RANGE => apply_add_range_record(
            context.ext,
            context.fs,
            context.composed_overlay,
            context.tx_state,
            context.plan,
            record.payload,
            position,
        ),
        FC_TAG_DEL_RANGE => apply_del_range_record(
            context.ext,
            context.fs,
            context.composed_overlay,
            context.tx_state,
            context.plan,
            record.payload,
            position,
        ),
        FC_TAG_TAIL => {
            let _tail = decode_tail(record.payload)?;
            commit_transaction(context)?;
            Ok(false)
        }
        _ => Ok(false),
    }
}

struct DentryRecord<'a> {
    position: FastCommitPosition,
    tag: u16,
    payload: &'a [u8],
}

fn apply_add_range_record<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    payload: &[u8],
    position: FastCommitPosition,
) -> Result<bool> {
    let add_range = decode_add_range(payload)?;
    let inum = add_range.fc_ino;
    let raw_extent = RawExtent::from_on_disk(&add_range.raw_extent);

    let Some((_, tx_buf)) = tx_state.as_mut() else {
        return Ok(false);
    };

    if inum == 0 || inum > ext.inodes_count {
        push_warning_to_tx(
            tx_buf,
            FastCommitWarning {
                position,
                current_tid: Some(tx_buf.current_tid),
                kind: FastCommitWarningKind::InodeOutOfRange { inum },
                occurrences: 1,
            },
        );
        tx_buf.tag_counts.add_range += 1;
        return Ok(false);
    }

    if physical_range_invalid(ext, raw_extent) {
        push_warning_to_tx(
            tx_buf,
            FastCommitWarning {
                position,
                current_tid: Some(tx_buf.current_tid),
                kind: FastCommitWarningKind::PhysicalBlockOutOfRange {
                    inum,
                    pblk: raw_extent.ee_pblk,
                    len: u32::from(raw_extent.ee_len),
                },
                occurrences: 1,
            },
        );
        tx_buf.tag_counts.add_range += 1;
        return Ok(false);
    }

    let (outcome, allocation_units_freed, allocation_units_allocated) = {
        let Some((tx_mutator, _)) = tx_state.as_mut() else {
            return Ok(false);
        };
        let mut reader = compose_reader(fs, composed_overlay);
        let mut surgeon = ExtentSurgeon::new(ext, &mut reader, tx_mutator);
        let outcome = surgeon.add_range(inum, raw_extent)?;
        (
            outcome,
            surgeon.allocation_units_freed(),
            surgeon.allocation_units_allocated(),
        )
    };

    match outcome {
        ExtentSurgeryOutcome::Applied => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                tx_buf.modified_inodes.insert(inum);
                // Final ADD_RANGE allocation marking is pass-C's job; pass-B
                // carries frees from replaced mappings and metadata blocks
                // allocated by extent-tree grow.
                tx_buf.allocation_units_marked_free += u64::from(allocation_units_freed);
                tx_buf.allocation_units_marked_allocated += u64::from(allocation_units_allocated);
                tx_buf.tag_counts.add_range += 1;
            }
            Ok(false)
        }
        ExtentSurgeryOutcome::RequiresMetadataAllocation => {
            stop_current_tx(
                tx_state,
                plan,
                position,
                FastCommitStopReason::ExtentReplayRequiresMetadataAllocation { inum },
            );
            Ok(true)
        }
        ExtentSurgeryOutcome::Failed(reason) => {
            stop_current_tx(
                tx_state,
                plan,
                position,
                FastCommitStopReason::ExtentReplayFailed { inum, reason },
            );
            Ok(true)
        }
        ExtentSurgeryOutcome::AppliedNeedsShrink { .. }
        | ExtentSurgeryOutcome::LogicalRangeInvalid { .. } => Ok(false),
    }
}

#[derive(Clone, Copy)]
struct DelRangeRecord {
    position: FastCommitPosition,
    inum: u32,
    logical_start: u32,
    len: u32,
}

fn del_range_should_skip<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    record: DelRangeRecord,
) -> Result<bool> {
    let Some((_, transaction)) = tx_state.as_mut() else {
        return Ok(true);
    };
    if record.inum == 0 || record.inum > ext.inodes_count {
        let current_tid = transaction.current_tid;
        push_warning_to_tx(
            transaction,
            FastCommitWarning {
                position: record.position,
                current_tid: Some(current_tid),
                kind: FastCommitWarningKind::InodeOutOfRange { inum: record.inum },
                occurrences: 1,
            },
        );
        transaction.tag_counts.del_range += 1;
        return Ok(true);
    }
    if !logical_range_invalid(
        ext,
        fs,
        composed_overlay,
        tx_state,
        record.inum,
        record.logical_start,
        record.len,
    )? {
        return Ok(false);
    }
    if let Some((_, transaction)) = tx_state.as_mut() {
        let current_tid = transaction.current_tid;
        push_warning_to_tx(
            transaction,
            FastCommitWarning {
                position: record.position,
                current_tid: Some(current_tid),
                kind: FastCommitWarningKind::LogicalRangeInvalid {
                    inum: record.inum,
                    lblk: record.logical_start,
                    len: record.len,
                },
                occurrences: 1,
            },
        );
        transaction.tag_counts.del_range += 1;
    }
    Ok(true)
}

fn finish_del_range(
    tx_state: &mut Option<(Mutator<'_>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    record: DelRangeRecord,
    outcome: &ExtentSurgeryOutcome,
    allocation_units_freed: u32,
    allocation_units_allocated: u32,
) -> bool {
    match outcome {
        ExtentSurgeryOutcome::Applied => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                transaction.tag_counts.del_range += 1;
            }
            false
        }
        ExtentSurgeryOutcome::AppliedNeedsShrink { .. } => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                transaction.modified_inodes.insert(record.inum);
                transaction.allocation_units_marked_free += u64::from(allocation_units_freed);
                transaction.allocation_units_marked_allocated +=
                    u64::from(allocation_units_allocated);
                transaction.tag_counts.del_range += 1;
            }
            false
        }
        ExtentSurgeryOutcome::RequiresMetadataAllocation => {
            stop_current_tx(
                tx_state,
                plan,
                record.position,
                FastCommitStopReason::ExtentReplayRequiresMetadataAllocation { inum: record.inum },
            );
            true
        }
        ExtentSurgeryOutcome::Failed(reason) => {
            stop_current_tx(
                tx_state,
                plan,
                record.position,
                FastCommitStopReason::ExtentReplayFailed {
                    inum: record.inum,
                    reason: *reason,
                },
            );
            true
        }
        ExtentSurgeryOutcome::LogicalRangeInvalid { lblk, len } => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                let current_tid = transaction.current_tid;
                push_warning_to_tx(
                    transaction,
                    FastCommitWarning {
                        position: record.position,
                        current_tid: Some(current_tid),
                        kind: FastCommitWarningKind::LogicalRangeInvalid {
                            inum: record.inum,
                            lblk: *lblk,
                            len: *len,
                        },
                        occurrences: 1,
                    },
                );
                transaction.tag_counts.del_range += 1;
            }
            false
        }
    }
}

fn apply_del_range_record<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    payload: &[u8],
    position: FastCommitPosition,
) -> Result<bool> {
    let del_range = decode_del_range(payload)?;
    let record = DelRangeRecord {
        position,
        inum: del_range.fc_ino,
        logical_start: del_range.fc_lblk,
        len: del_range.fc_len,
    };
    if del_range_should_skip(ext, fs, composed_overlay, tx_state, record)? {
        return Ok(false);
    }

    let end_inclusive = record
        .logical_start
        .checked_add(record.len)
        .and_then(|end_exclusive| end_exclusive.checked_sub(1))
        .expect("validated nonzero logical range");

    let (outcome, allocation_units_freed, allocation_units_allocated) = {
        let Some((tx_mutator, _)) = tx_state.as_mut() else {
            return Ok(false);
        };
        let mut reader = compose_reader(fs, composed_overlay);
        let mut surgeon = ExtentSurgeon::new(ext, &mut reader, tx_mutator);
        let outcome = surgeon.del_range(record.inum, record.logical_start, end_inclusive)?;
        if let ExtentSurgeryOutcome::AppliedNeedsShrink {
            end_block_exclusive,
        } = outcome
        {
            surgeon.shrink_inode(record.inum, end_block_exclusive)?;
        }
        (
            outcome,
            surgeon.allocation_units_freed(),
            surgeon.allocation_units_allocated(),
        )
    };
    Ok(finish_del_range(
        tx_state,
        plan,
        record,
        &outcome,
        allocation_units_freed,
        allocation_units_allocated,
    ))
}

#[derive(Clone, Copy)]
struct DentryInfo<'a> {
    position: FastCommitPosition,
    tag: u16,
    parent_inum: u32,
    child_inum: u32,
    name: &'a [u8],
}

enum DentryPreparation {
    Skip,
    Stop,
    Ready { parent_indexed: bool, file_type: u8 },
}

fn prepare_dentry<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    info: DentryInfo<'_>,
) -> Result<DentryPreparation> {
    if tx_state.is_none() {
        return Ok(DentryPreparation::Skip);
    }
    if info.parent_inum == 0 || info.parent_inum > ext.inodes_count {
        if let Some((_, transaction)) = tx_state.as_mut() {
            push_directory_replay_warning(
                transaction,
                info.position,
                info.parent_inum,
                DirectoryReplayReason::ParentInodeMissing,
            );
            increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
        }
        return Ok(DentryPreparation::Skip);
    }
    let Some((mutator, _)) = tx_state.as_ref() else {
        return Ok(DentryPreparation::Skip);
    };
    let parent_mode = current_inode_mode(mutator, fs, composed_overlay, info.parent_inum)?;
    if parent_mode & S_IFMT != S_IFDIR {
        if let Some((_, transaction)) = tx_state.as_mut() {
            push_directory_replay_warning(
                transaction,
                info.position,
                info.parent_inum,
                DirectoryReplayReason::ParentNotADirectory,
            );
            increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
        }
        return Ok(DentryPreparation::Skip);
    }
    let link_delta = if info.tag == FC_TAG_UNLINK { -1 } else { 1 };
    if let Some(reason) =
        adjust_child_links_count(fs, composed_overlay, tx_state, info.child_inum, link_delta)?
    {
        stop_current_tx(tx_state, plan, info.position, reason);
        return Ok(DentryPreparation::Stop);
    }
    let Some((mutator, _)) = tx_state.as_ref() else {
        return Ok(DentryPreparation::Skip);
    };
    let parent_indexed = current_inode_flags(mutator, fs, composed_overlay, info.parent_inum)?
        .contains(crate::inode::InodeFlags::INDEX_FL);
    let file_type = if info.tag == FC_TAG_UNLINK {
        0
    } else {
        let mut reader = compose_reader(fs, composed_overlay);
        dentry_file_type(mutator, &mut reader, info.child_inum)?
    };
    Ok(DentryPreparation::Ready {
        parent_indexed,
        file_type,
    })
}

fn mutate_dentry<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    info: DentryInfo<'_>,
    parent_indexed: bool,
    file_type: u8,
) -> Result<DirReplayOutcome> {
    let Some((mutator, _)) = tx_state.as_mut() else {
        return Ok(DirReplayOutcome::SkippedTargetMissing);
    };
    let mut reader = compose_reader(fs, composed_overlay);
    if parent_indexed {
        let mut surgeon = HtreeSurgeon::new(ext, &mut reader, mutator);
        if info.tag == FC_TAG_UNLINK {
            surgeon
                .remove_entry(info.parent_inum, info.child_inum, info.name)
                .map_err(mutator_error_to_ext)
        } else {
            surgeon
                .add_entry(info.parent_inum, info.child_inum, info.name, file_type)
                .map_err(mutator_error_to_ext)
        }
    } else if info.tag == FC_TAG_UNLINK {
        mutator
            .dir_remove_entry(&mut reader, info.parent_inum, info.child_inum, info.name)
            .map_err(mutator_error_to_ext)
    } else {
        mutator
            .dir_append_entry(
                &mut reader,
                info.parent_inum,
                info.child_inum,
                info.name,
                file_type,
            )
            .map_err(mutator_error_to_ext)
    }
}

fn finish_dentry<T: Read + Seek>(
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'_>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    info: DentryInfo<'_>,
    outcome: DirReplayOutcome,
) -> Result<bool> {
    match outcome {
        DirReplayOutcome::Applied => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                transaction.modified_inodes.insert(info.parent_inum);
                transaction.modified_inodes.insert(info.child_inum);
                increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
            }
        }
        DirReplayOutcome::SkippedHtree => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                push_directory_replay_warning(
                    transaction,
                    info.position,
                    info.parent_inum,
                    DirectoryReplayReason::HtreeNotMaintained,
                );
                transaction.modified_inodes.insert(info.child_inum);
                increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
            }
        }
        DirReplayOutcome::SkippedTargetMissing if info.tag == FC_TAG_UNLINK => {
            if let Some(reason) =
                adjust_child_links_count(fs, composed_overlay, tx_state, info.child_inum, 1)?
            {
                stop_current_tx(tx_state, plan, info.position, reason);
                return Ok(true);
            }
            if let Some((mutator, _)) = tx_state.as_mut() {
                mutator
                    .prune_inode_table_block_if_unchanged(
                        &mut compose_reader(fs, composed_overlay),
                        info.child_inum,
                    )
                    .map_err(mutator_error_to_ext)?;
            }
            if let Some((_, transaction)) = tx_state.as_mut() {
                let current_tid = transaction.current_tid;
                push_warning_to_tx(
                    transaction,
                    FastCommitWarning {
                        position: info.position,
                        current_tid: Some(current_tid),
                        kind: FastCommitWarningKind::UnlinkTargetMissing {
                            parent_inum: info.parent_inum,
                            child_inum: info.child_inum,
                        },
                        occurrences: 1,
                    },
                );
                increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
            }
        }
        DirReplayOutcome::SkippedTargetMissing => {
            if let Some((_, transaction)) = tx_state.as_mut() {
                increment_dentry_tag_count(&mut transaction.tag_counts, info.tag);
            }
        }
    }
    Ok(false)
}

fn apply_dentry_record<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    record: &DentryRecord<'_>,
) -> Result<bool> {
    let dentry = decode_dentry(record.payload)?;
    let info = DentryInfo {
        position: record.position,
        tag: record.tag,
        parent_inum: dentry.parent_inum,
        child_inum: dentry.child_inum,
        name: dentry.name,
    };
    let (parent_indexed, file_type) =
        match prepare_dentry(ext, fs, composed_overlay, tx_state, plan, info)? {
            DentryPreparation::Skip => return Ok(false),
            DentryPreparation::Stop => return Ok(true),
            DentryPreparation::Ready {
                parent_indexed,
                file_type,
            } => (parent_indexed, file_type),
        };
    let outcome = mutate_dentry(
        ext,
        fs,
        composed_overlay,
        tx_state,
        info,
        parent_indexed,
        file_type,
    )?;
    finish_dentry(fs, composed_overlay, tx_state, plan, info, outcome)
}

#[cfg(test)]
#[path = "apply_tests/mod.rs"]
mod tests;
