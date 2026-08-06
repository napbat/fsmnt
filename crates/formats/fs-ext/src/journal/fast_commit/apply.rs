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

        match tag {
            FC_TAG_HEAD => {
                let head = decode_head(&payload)?;
                let sb_host_bytes = composed_overlay.sb_host_block_content.to_vec();
                let mutator = Mutator::new(ext, &sb_host_bytes);
                let buf = TxBuffer {
                    current_tid: head.tid,
                    tag_counts: FastCommitTagCounts {
                        head: 1,
                        ..FastCommitTagCounts::default()
                    },
                    warnings: Vec::new(),
                    modified_inodes: BTreeSet::new(),
                    allocation_units_marked_free: 0,
                    allocation_units_marked_allocated: 0,
                };
                tx_state = Some((mutator, buf));
            }
            FC_TAG_PAD => {
                if let Some((_, buf)) = tx_state.as_mut() {
                    buf.tag_counts.pad += 1;
                }
            }
            FC_TAG_INODE => {
                let inode = decode_inode(&payload)?;
                let position = position_at(rel_block_idx, record_offset, block_size, fc_first);

                let inode_size = usize::from(ext.inode_size());
                if !(128..=inode_size).contains(&inode.raw_inode.len()) {
                    stop_current_tx(
                        &mut tx_state,
                        &mut plan,
                        position,
                        FastCommitStopReason::MalformedRecord {
                            tag: FC_TAG_INODE,
                            fc_len,
                            reason: "inode raw_inode length out of [128, s_inode_size]",
                        },
                    );
                    break;
                }

                if inode.fc_ino == 0 || inode.fc_ino > ext.inodes_count {
                    if let Some((_, tx_buf)) = tx_state.as_mut() {
                        push_warning_to_tx(
                            tx_buf,
                            FastCommitWarning {
                                position,
                                current_tid: Some(tx_buf.current_tid),
                                kind: FastCommitWarningKind::InodeOutOfRange { inum: inode.fc_ino },
                                occurrences: 1,
                            },
                        );
                        tx_buf.tag_counts.inode += 1;
                    }
                    remaining -= 1;
                    continue;
                }

                if let Some((tx_mutator, tx_buf)) = tx_state.as_mut() {
                    tx_mutator
                        .patch_inode_scratch(
                            &mut compose_reader(fs, &composed_overlay),
                            inode.fc_ino,
                            |bytes| {
                                bytes[..inode.raw_inode.len()].copy_from_slice(inode.raw_inode);
                                Ok(())
                            },
                        )
                        .map_err(mutator_error_to_ext)?;
                    tx_buf.modified_inodes.insert(inode.fc_ino);
                    tx_buf.tag_counts.inode += 1;
                }
            }
            FC_TAG_CREAT | FC_TAG_LINK | FC_TAG_UNLINK => {
                let position = position_at(rel_block_idx, record_offset, block_size, fc_first);
                let record = DentryRecord {
                    position,
                    tag,
                    payload: &payload,
                };
                if apply_dentry_record(
                    ext,
                    fs,
                    &composed_overlay,
                    &mut tx_state,
                    &mut plan,
                    record,
                )? {
                    break;
                }
            }
            FC_TAG_ADD_RANGE => {
                let position = position_at(rel_block_idx, record_offset, block_size, fc_first);
                if apply_add_range_record(
                    ext,
                    fs,
                    &composed_overlay,
                    &mut tx_state,
                    &mut plan,
                    &payload,
                    position,
                )? {
                    break;
                }
            }
            FC_TAG_DEL_RANGE => {
                let position = position_at(rel_block_idx, record_offset, block_size, fc_first);
                if apply_del_range_record(
                    ext,
                    fs,
                    &composed_overlay,
                    &mut tx_state,
                    &mut plan,
                    &payload,
                    position,
                )? {
                    break;
                }
            }
            FC_TAG_TAIL => {
                let _ = decode_tail(&payload)?;
                if let Some((mutator, buf)) = tx_state.take() {
                    let delta = {
                        let mut overlay_reader = compose_reader(fs, &composed_overlay);
                        mutator.finalize(&mut overlay_reader)
                    }
                    .map_err(mutator_error_to_ext)?;
                    merge_delta_into_overlay(&mut composed_overlay, delta);

                    plan.transactions_replayed += 1;
                    merge_tag_counts(&mut plan.tag_counts, &buf.tag_counts);
                    plan.tag_counts.tail += 1;
                    plan.last_committed_tid = Some(buf.current_tid);
                    plan.allocation_units_marked_free += buf.allocation_units_marked_free;
                    plan.allocation_units_marked_allocated += buf.allocation_units_marked_allocated;
                    modified_inodes.extend(buf.modified_inodes);
                    for warning in buf.warnings {
                        push_warning_capped(&mut plan, warning);
                    }
                }
            }
            _ => {
                // INODE, dentry, and extent handlers land in later tasks.
            }
        }

        remaining -= 1;
    }

    propagate_scan_stop(&mut plan, scan);
    plan.inodes_modified = modified_inodes.len() as u32;

    Ok(ApplyState {
        plan,
        modified_inodes,
        composed_overlay,
    })
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
    let inum = del_range.fc_ino;

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
        tx_buf.tag_counts.del_range += 1;
        return Ok(false);
    }

    if logical_range_invalid(
        ext,
        fs,
        composed_overlay,
        tx_state,
        inum,
        del_range.fc_lblk,
        del_range.fc_len,
    )? {
        if let Some((_, tx_buf)) = tx_state.as_mut() {
            push_warning_to_tx(
                tx_buf,
                FastCommitWarning {
                    position,
                    current_tid: Some(tx_buf.current_tid),
                    kind: FastCommitWarningKind::LogicalRangeInvalid {
                        inum,
                        lblk: del_range.fc_lblk,
                        len: del_range.fc_len,
                    },
                    occurrences: 1,
                },
            );
            tx_buf.tag_counts.del_range += 1;
        }
        return Ok(false);
    }

    let end_inclusive = del_range
        .fc_lblk
        .checked_add(del_range.fc_len)
        .and_then(|end_exclusive| end_exclusive.checked_sub(1))
        .expect("validated nonzero logical range");

    let (outcome, allocation_units_freed, allocation_units_allocated) = {
        let Some((tx_mutator, _)) = tx_state.as_mut() else {
            return Ok(false);
        };
        let mut reader = compose_reader(fs, composed_overlay);
        let mut surgeon = ExtentSurgeon::new(ext, &mut reader, tx_mutator);
        let outcome = surgeon.del_range(inum, del_range.fc_lblk, end_inclusive)?;
        if let ExtentSurgeryOutcome::AppliedNeedsShrink {
            end_block_exclusive,
        } = outcome
        {
            surgeon.shrink_inode(inum, end_block_exclusive)?;
        }
        (
            outcome,
            surgeon.allocation_units_freed(),
            surgeon.allocation_units_allocated(),
        )
    };

    match outcome {
        ExtentSurgeryOutcome::Applied => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                tx_buf.tag_counts.del_range += 1;
            }
            Ok(false)
        }
        ExtentSurgeryOutcome::AppliedNeedsShrink { .. } => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                tx_buf.modified_inodes.insert(inum);
                tx_buf.allocation_units_marked_free += u64::from(allocation_units_freed);
                tx_buf.allocation_units_marked_allocated += u64::from(allocation_units_allocated);
                tx_buf.tag_counts.del_range += 1;
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
        ExtentSurgeryOutcome::LogicalRangeInvalid { lblk, len } => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                push_warning_to_tx(
                    tx_buf,
                    FastCommitWarning {
                        position,
                        current_tid: Some(tx_buf.current_tid),
                        kind: FastCommitWarningKind::LogicalRangeInvalid { inum, lblk, len },
                        occurrences: 1,
                    },
                );
                tx_buf.tag_counts.del_range += 1;
            }
            Ok(false)
        }
    }
}

fn apply_dentry_record<'ext, T: Read + Seek>(
    ext: &'ext Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'ext>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    record: DentryRecord<'_>,
) -> Result<bool> {
    let dentry = decode_dentry(record.payload)?;
    let parent_inum = dentry.parent_inum;
    let child_inum = dentry.child_inum;
    let name = dentry.name;

    if tx_state.is_none() {
        return Ok(false);
    }

    if parent_inum == 0 || parent_inum > ext.inodes_count {
        if let Some((_, tx_buf)) = tx_state.as_mut() {
            push_directory_replay_warning(
                tx_buf,
                record.position,
                parent_inum,
                DirectoryReplayReason::ParentInodeMissing,
            );
            increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
        }
        return Ok(false);
    }

    let parent_mode = {
        let Some((tx_mutator, _)) = tx_state.as_ref() else {
            return Ok(false);
        };
        current_inode_mode(tx_mutator, fs, composed_overlay, parent_inum)?
    };
    if parent_mode & S_IFMT != S_IFDIR {
        if let Some((_, tx_buf)) = tx_state.as_mut() {
            push_directory_replay_warning(
                tx_buf,
                record.position,
                parent_inum,
                DirectoryReplayReason::ParentNotADirectory,
            );
            increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
        }
        return Ok(false);
    }

    let delta = if record.tag == FC_TAG_UNLINK { -1 } else { 1 };
    if let Some(reason) =
        adjust_child_links_count(fs, composed_overlay, tx_state, child_inum, delta)?
    {
        stop_current_tx(tx_state, plan, record.position, reason);
        return Ok(true);
    }

    let parent_indexed = {
        let Some((tx_mutator, _)) = tx_state.as_ref() else {
            return Ok(false);
        };
        current_inode_flags(tx_mutator, fs, composed_overlay, parent_inum)?
            .contains(crate::inode::InodeFlags::INDEX_FL)
    };

    // CREAT/LINK need the child's file_type; compute it before any
    // surgeon borrows the mutator exclusively.
    let file_type = if record.tag == FC_TAG_UNLINK {
        0
    } else {
        let Some((tx_mutator, _)) = tx_state.as_ref() else {
            return Ok(false);
        };
        let mut reader = compose_reader(fs, composed_overlay);
        dentry_file_type(tx_mutator, &mut reader, child_inum)?
    };

    let outcome = {
        let Some((tx_mutator, _)) = tx_state.as_mut() else {
            return Ok(false);
        };
        let mut reader = compose_reader(fs, composed_overlay);
        if parent_indexed {
            let mut surgeon = HtreeSurgeon::new(ext, &mut reader, tx_mutator);
            if record.tag == FC_TAG_UNLINK {
                surgeon
                    .remove_entry(parent_inum, child_inum, name)
                    .map_err(mutator_error_to_ext)?
            } else {
                surgeon
                    .add_entry(parent_inum, child_inum, name, file_type)
                    .map_err(mutator_error_to_ext)?
            }
        } else if record.tag == FC_TAG_UNLINK {
            tx_mutator
                .dir_remove_entry(&mut reader, parent_inum, child_inum, name)
                .map_err(mutator_error_to_ext)?
        } else {
            tx_mutator
                .dir_append_entry(&mut reader, parent_inum, child_inum, name, file_type)
                .map_err(mutator_error_to_ext)?
        }
    };

    match outcome {
        DirReplayOutcome::Applied => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                tx_buf.modified_inodes.insert(parent_inum);
                tx_buf.modified_inodes.insert(child_inum);
                increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
            }
        }
        DirReplayOutcome::SkippedHtree => {
            if let Some((_, tx_buf)) = tx_state.as_mut() {
                push_directory_replay_warning(
                    tx_buf,
                    record.position,
                    parent_inum,
                    DirectoryReplayReason::HtreeNotMaintained,
                );
                tx_buf.modified_inodes.insert(child_inum);
                increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
            }
        }
        DirReplayOutcome::SkippedTargetMissing => {
            if record.tag == FC_TAG_UNLINK {
                if let Some(reason) =
                    adjust_child_links_count(fs, composed_overlay, tx_state, child_inum, 1)?
                {
                    stop_current_tx(tx_state, plan, record.position, reason);
                    return Ok(true);
                }
                if let Some((tx_mutator, _)) = tx_state.as_mut() {
                    tx_mutator
                        .prune_inode_table_block_if_unchanged(
                            &mut compose_reader(fs, composed_overlay),
                            child_inum,
                        )
                        .map_err(mutator_error_to_ext)?;
                }
                if let Some((_, tx_buf)) = tx_state.as_mut() {
                    push_warning_to_tx(
                        tx_buf,
                        FastCommitWarning {
                            position: record.position,
                            current_tid: Some(tx_buf.current_tid),
                            kind: FastCommitWarningKind::UnlinkTargetMissing {
                                parent_inum,
                                child_inum,
                            },
                            occurrences: 1,
                        },
                    );
                    increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
                }
            } else if let Some((_, tx_buf)) = tx_state.as_mut() {
                increment_dentry_tag_count(&mut tx_buf.tag_counts, record.tag);
            }
        }
    }

    Ok(false)
}

fn adjust_child_links_count<T: Read + Seek>(
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'_>, TxBuffer)>,
    child_inum: u32,
    delta: i32,
) -> Result<Option<FastCommitStopReason>> {
    let Some((tx_mutator, _)) = tx_state.as_mut() else {
        return Ok(None);
    };
    let change = tx_mutator
        .adjust_inode_links_count(&mut compose_reader(fs, composed_overlay), child_inum, delta)
        .map_err(mutator_error_to_ext)?;
    Ok(match change {
        LinkCountChange::Applied { .. } => None,
        LinkCountChange::Underflow {
            from,
            would_be_delta,
        }
        | LinkCountChange::Overflow {
            from,
            would_be_delta,
        } => Some(FastCommitStopReason::LinkCountOverflow {
            inum: child_inum,
            current: from,
            delta: would_be_delta,
        }),
    })
}

fn physical_range_invalid(ext: &Ext, raw_extent: RawExtent) -> bool {
    if raw_extent.ee_pblk < u64::from(ext.first_data_block) {
        return true;
    }
    let Some(end) = raw_extent.ee_pblk.checked_add(u64::from(raw_extent.ee_len)) else {
        return true;
    };
    raw_extent.ee_pblk >= ext.blocks_count || end > ext.blocks_count
}

fn logical_range_invalid<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    tx_state: &mut Option<(Mutator<'_>, TxBuffer)>,
    inum: u32,
    lblk: u32,
    len: u32,
) -> Result<bool> {
    if len == 0 {
        return Ok(true);
    }
    let Some(end_exclusive) = lblk.checked_add(len) else {
        return Ok(true);
    };

    let Some((tx_mutator, _)) = tx_state.as_mut() else {
        return Ok(false);
    };
    let inode_bytes = tx_mutator
        .current_inode_bytes(&mut compose_reader(fs, composed_overlay), inum)
        .map_err(mutator_error_to_ext)?;
    if inode_bytes.len() < 0x70 {
        return Err(ExtError::InvalidInode {
            inode: inum,
            reason: "too short",
        });
    }

    let size_lo = u32::from_le_bytes(inode_bytes[0x04..0x08].try_into().expect("len 4"));
    let size_hi = u32::from_le_bytes(inode_bytes[0x6C..0x70].try_into().expect("len 4"));
    let i_size = u64::from(size_lo) | (u64::from(size_hi) << 32);
    let block_size = u64::from(ext.block_size());
    let logical_capacity = i_size.div_ceil(block_size);

    Ok(u64::from(end_exclusive) > logical_capacity)
}

fn current_inode_mode<T: Read + Seek>(
    tx_mutator: &Mutator<'_>,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    inum: u32,
) -> Result<u16> {
    let inode = tx_mutator
        .current_inode_bytes(&mut compose_reader(fs, composed_overlay), inum)
        .map_err(mutator_error_to_ext)?;
    Ok(u16::from_le_bytes(inode[0..2].try_into().unwrap()))
}

fn current_inode_flags<T: Read + Seek>(
    tx_mutator: &Mutator<'_>,
    fs: &mut T,
    composed_overlay: &BlockOverlay,
    inum: u32,
) -> Result<crate::inode::InodeFlags> {
    let inode = tx_mutator
        .current_inode_bytes(&mut compose_reader(fs, composed_overlay), inum)
        .map_err(mutator_error_to_ext)?;
    let raw = u32::from_le_bytes(inode[0x20..0x24].try_into().unwrap());
    Ok(crate::inode::InodeFlags::from_bits_retain(raw))
}

fn dentry_file_type<T: Read + Seek>(
    tx_mutator: &Mutator<'_>,
    fs: &mut T,
    child_inum: u32,
) -> Result<u8> {
    let inode = tx_mutator
        .current_inode_bytes(fs, child_inum)
        .map_err(mutator_error_to_ext)?;
    let mode = u16::from_le_bytes(inode[0..2].try_into().unwrap());
    Ok(if mode & S_IFMT == S_IFREG {
        1
    } else if mode & S_IFMT == S_IFDIR {
        2
    } else if mode & S_IFMT == S_IFLNK {
        7
    } else {
        0
    })
}

fn push_directory_replay_warning(
    tx_buf: &mut TxBuffer,
    position: FastCommitPosition,
    parent_inum: u32,
    reason: DirectoryReplayReason,
) {
    push_warning_to_tx(
        tx_buf,
        FastCommitWarning {
            position,
            current_tid: Some(tx_buf.current_tid),
            kind: FastCommitWarningKind::DirectoryReplayFailed {
                parent_inum,
                reason,
            },
            occurrences: 1,
        },
    );
}

fn increment_dentry_tag_count(counts: &mut FastCommitTagCounts, tag: u16) {
    match tag {
        FC_TAG_CREAT => counts.creat += 1,
        FC_TAG_LINK => counts.link += 1,
        FC_TAG_UNLINK => counts.unlink += 1,
        _ => {}
    }
}

fn position_at(
    rel_block_idx: usize,
    record_offset: usize,
    block_size: u32,
    fc_first: u32,
) -> FastCommitPosition {
    let fc_block = fc_first.saturating_add(rel_block_idx as u32);
    let block_offset = record_offset as u32;
    FastCommitPosition {
        fc_block,
        block_offset,
        fs_byte_offset: u64::from(fc_block) * u64::from(block_size) + u64::from(block_offset),
    }
}

fn stop_current_tx(
    tx_state: &mut Option<(Mutator<'_>, TxBuffer)>,
    plan: &mut FastCommitPlan,
    position: FastCommitPosition,
    reason: FastCommitStopReason,
) {
    let _ = tx_state.take();
    plan.stop = Some(FastCommitStop {
        position,
        last_committed_tid: plan.last_committed_tid,
        reason,
    });
}

fn push_warning_to_tx(tx_buf: &mut TxBuffer, warning: FastCommitWarning) {
    tx_buf.warnings.push(warning);
}

fn compose_reader<'a, T: Read + Seek>(
    fs: &'a mut T,
    composed: &'a BlockOverlay,
) -> crate::OverlayReader<'a, 'a, T, BlockOverlay> {
    crate::OverlayReader::new(fs, composed)
}

pub(crate) fn merge_delta_into_overlay(overlay: &mut BlockOverlay, delta: OrphanOverlayDelta) {
    for (block, content) in delta.blocks {
        overlay.blocks.insert(block, content);
    }
    if let Some(sb_host) = delta.sb_host_override {
        overlay.sb_host_block_content = sb_host;
    }
}

fn merge_tag_counts(dst: &mut FastCommitTagCounts, src: &FastCommitTagCounts) {
    dst.head += src.head;
    dst.pad += src.pad;
    dst.inode += src.inode;
    dst.creat += src.creat;
    dst.link += src.link;
    dst.unlink += src.unlink;
    dst.add_range += src.add_range;
    dst.del_range += src.del_range;
}

fn push_warning_capped(plan: &mut FastCommitPlan, warning: FastCommitWarning) {
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

fn same_aggregation_key(a: &FastCommitWarning, b: &FastCommitWarning) -> bool {
    use FastCommitWarningKind::*;
    match (&a.kind, &b.kind) {
        (InodeOutOfRange { inum: x }, InodeOutOfRange { inum: y }) => x == y,
        (PhysicalBlockOutOfRange { inum: x, .. }, PhysicalBlockOutOfRange { inum: y, .. }) => {
            x == y
        }
        (LogicalRangeInvalid { inum: x, .. }, LogicalRangeInvalid { inum: y, .. }) => x == y,
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
        (FinalizerExtentWalkFailed { inum: x }, FinalizerExtentWalkFailed { inum: y }) => x == y,
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

fn propagate_scan_stop(plan: &mut FastCommitPlan, scan: &ScanResult) {
    if plan.stop.is_none()
        && let Some(stop) = scan.stop.as_ref()
    {
        plan.stop = Some(clone_stop(stop));
    }
}

fn clone_stop(stop: &FastCommitStop) -> FastCommitStop {
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

fn allocation_physical_range(allocation: crate::extent::ExtentAllocation) -> (u64, u32) {
    match allocation {
        crate::extent::ExtentAllocation::Data {
            physical_start,
            block_len,
            ..
        } => (physical_start, block_len),
        crate::extent::ExtentAllocation::IndexBlock(block) => (block, 1),
    }
}

fn allocation_range_invalid(ext: &Ext, pblk: u64, len: u32) -> bool {
    if len == 0 || pblk < u64::from(ext.first_data_block) {
        return true;
    }
    let Some(end) = pblk.checked_add(u64::from(len)) else {
        return true;
    };
    pblk >= ext.blocks_count || end > ext.blocks_count
}

fn push_finalizer_extent_walk_failed(plan: &mut FastCommitPlan, inum: u32) {
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

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;

    use fs_common::iter::FsTryIterator;

    use crate::io::{Read, Seek, SeekFrom};
    use crate::journal::fast_commit::extents::RawExtent;
    use crate::journal::fast_commit::parse::scan_fc_region;
    use crate::journal::fast_commit::test_support::{FcTxBuilder, fc_region};
    use crate::journal::fast_commit::tlv::FC_TAG_INODE;
    use crate::journal::replay::BlockOverlay;
    use crate::journal::{DirectoryReplayReason, ExtentReplayReason, FastCommitStopReason};

    use super::*;

    const BS: u32 = 4096;
    const FC_FIRST: u32 = 100;
    const TID: u32 = 100;
    const EXTENT_MAGIC: u16 = 0xF30A;

    fn classic_overlay_for_fixture(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
    ) -> BlockOverlay {
        let block_size = ext.block_size();
        let sb_host_block = if block_size > 1024 { 0 } else { 1 };
        cursor
            .seek(SeekFrom::Start(sb_host_block * u64::from(block_size)))
            .expect("seek sb host block");
        let mut sb_host_content = alloc::vec![0u8; block_size as usize];
        cursor
            .read_exact(&mut sb_host_content)
            .expect("read sb host block");
        BlockOverlay {
            block_size,
            blocks: BTreeMap::new(),
            sb_host_block,
            sb_host_block_content: sb_host_content.into_boxed_slice(),
        }
    }

    fn fixture_ext() -> (crate::Ext, std::io::Cursor<Vec<u8>>) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let bytes = std::fs::read(path).expect("read ext4 fixture");
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
        (ext, cursor)
    }

    fn raw_inode_from_overlay(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        inum: u32,
    ) -> Vec<u8> {
        let group = (inum - 1) / ext.inodes_per_group;
        let index = (inum - 1) % ext.inodes_per_group;
        let table_block = ext.group_descs[group as usize].inode_table;
        let byte_offset = table_block * u64::from(ext.block_size())
            + u64::from(index) * u64::from(ext.inode_size());
        let mut reader = compose_reader(cursor, overlay);
        reader
            .seek(SeekFrom::Start(byte_offset))
            .expect("seek raw inode");
        let mut bytes = alloc::vec![0u8; usize::from(ext.inode_size())];
        reader.read_exact(&mut bytes).expect("read raw inode");
        bytes
    }

    fn read_links_count_from_overlay(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        inum: u32,
    ) -> u16 {
        let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
        u16::from_le_bytes(inode[0x1A..0x1C].try_into().unwrap())
    }

    fn inode_byte_offset(ext: &crate::Ext, inum: u32, inode_relative_offset: usize) -> usize {
        let group = (inum - 1) / ext.inodes_per_group;
        let index = (inum - 1) % ext.inodes_per_group;
        let table_block = ext.group_descs[group as usize].inode_table;
        table_block as usize * ext.block_size() as usize
            + index as usize * usize::from(ext.inode_size())
            + inode_relative_offset
    }

    fn set_links_count_in_image(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        inum: u32,
        links_count: u16,
    ) {
        let offset = inode_byte_offset(ext, inum, 0x1A);
        cursor.get_mut()[offset..offset + 2].copy_from_slice(&links_count.to_le_bytes());
    }

    fn write_raw_inode_to_image(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        inum: u32,
        raw_inode: &[u8],
    ) {
        let offset = inode_byte_offset(ext, inum, 0);
        let len = usize::from(ext.inode_size());
        assert_eq!(raw_inode.len(), len);
        cursor.get_mut()[offset..offset + len].copy_from_slice(raw_inode);
    }

    fn set_inode_mode(raw_inode: &mut [u8], mode: u16) {
        raw_inode[0..2].copy_from_slice(&mode.to_le_bytes());
    }

    fn set_inode_size(raw_inode: &mut [u8], size: u64) {
        raw_inode[0x04..0x08].copy_from_slice(&(size as u32).to_le_bytes());
        raw_inode[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
    }

    fn set_inode_extent_root(raw_inode: &mut [u8], root: [u8; 60]) {
        set_inode_mode(raw_inode, S_IFREG | 0o644);
        let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
            | crate::inode::InodeFlags::EXTENTS_FL.bits();
        raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        raw_inode[0x28..0x28 + 60].copy_from_slice(&root);
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

    fn write_extent_record(buf: &mut [u8], offset: usize, extent: RawExtent) {
        buf[offset..offset + 4].copy_from_slice(&extent.ee_block.to_le_bytes());
        buf[offset + 4..offset + 6].copy_from_slice(&encoded_len(extent).to_le_bytes());
        buf[offset + 6..offset + 8].copy_from_slice(&((extent.ee_pblk >> 32) as u16).to_le_bytes());
        buf[offset + 8..offset + 12].copy_from_slice(&(extent.ee_pblk as u32).to_le_bytes());
    }

    fn encoded_len(extent: RawExtent) -> u16 {
        if extent.unwritten {
            extent.ee_len + 32768
        } else {
            extent.ee_len
        }
    }

    fn inode_extent_records(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        inum: u32,
    ) -> Vec<(u32, u16, u64, bool)> {
        let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
        decoded_extent_records(&inode[0x28..0x28 + 60])
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
            out.push((
                ee_block,
                ee_len,
                (u64::from(hi) << 32) | u64::from(lo),
                unwritten,
            ));
        }
        out
    }

    fn inode_size_from_overlay(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        inum: u32,
    ) -> u64 {
        let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
        let lo = u32::from_le_bytes(inode[0x04..0x08].try_into().unwrap());
        let hi = u32::from_le_bytes(inode[0x6C..0x70].try_into().unwrap());
        u64::from(lo) | (u64::from(hi) << 32)
    }

    fn overlay_block_bitmap_bit(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        pblk: u64,
    ) -> bool {
        let group =
            ((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group)) as usize;
        let bitmap_block = ext.group_descs[group].block_bitmap;
        let bitmap = if let Some(block) = overlay.blocks.get(&bitmap_block) {
            block.to_vec()
        } else {
            let mut bytes = alloc::vec![0u8; ext.block_size() as usize];
            cursor
                .seek(SeekFrom::Start(bitmap_block * u64::from(ext.block_size())))
                .expect("seek bitmap");
            cursor.read_exact(&mut bytes).expect("read bitmap");
            bytes
        };
        let block_in_group =
            (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
        let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
        let byte = (alloc_unit / 8) as usize;
        let bit = (alloc_unit % 8) as u8;
        bitmap[byte] & (1u8 << bit) != 0
    }

    fn first_root_data_block<T: Read + Seek>(ext: &crate::Ext, cursor: &mut T) -> u64 {
        let inode = ext.inode(cursor, 2).expect("root inode");
        let i_block = inode.i_block();
        crate::extent::resolve_extent(ext, cursor, 2, inode.generation(), &i_block, 0)
            .expect("resolve root extent")
            .expect("root extent")
            .physical_block
    }

    fn inode_table_block(ext: &crate::Ext, inum: u32) -> u64 {
        let group = (inum - 1) / ext.inodes_per_group;
        let index = (inum - 1) % ext.inodes_per_group;
        let table_block = ext.group_descs[group as usize].inode_table;
        table_block + (u64::from(index) * u64::from(ext.inode_size())) / u64::from(ext.block_size())
    }

    fn raw_dir_entry_from_overlay(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        overlay: &BlockOverlay,
        parent: u32,
        name: &[u8],
    ) -> Option<(u32, u8)> {
        let mut reader = compose_reader(cursor, overlay);
        let mut dir = ext.directory_at(parent);
        let mut iter = dir.raw_entries(&mut reader).expect("raw directory entries");
        while let Some(entry) = iter.try_next(&mut reader).expect("read raw dir entry") {
            if entry.name_bytes() == name {
                return Some((entry.inode_number(), entry.file_type()));
            }
        }
        None
    }

    fn apply_single_tx(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        tx: Vec<u8>,
    ) -> ApplyState {
        let composed = classic_overlay_for_fixture(ext, cursor);
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        assert!(scan.stop.is_none());
        apply_pass(ext, cursor, composed, &block_refs, BS, FC_FIRST, &scan).expect("apply")
    }

    fn split_tx_across_blocks(tx: &[u8], block_size: usize) -> Vec<Vec<u8>> {
        tx.chunks(block_size).map(<[u8]>::to_vec).collect()
    }

    #[test]
    fn apply_head_tail_only_increments_transactions_replayed() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);

        let tx = FcTxBuilder::new(TID).head(0).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        assert!(scan.stop.is_none());

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.last_committed_tid, Some(TID));
        assert!(state.plan.stop.is_none());
        assert!(state.modified_inodes.is_empty());
        assert!(state.composed_overlay.blocks.is_empty());
    }

    #[test]
    fn apply_pass_propagates_scan_stop_after_committing_prior_txs() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);

        let tx1 = FcTxBuilder::new(TID).head(0).build();
        let tx2 = FcTxBuilder::new(TID).head(0).build();
        let tx3 = FcTxBuilder::new(TID).head(0).build_with_bad_crc();
        let blocks = fc_region(alloc::vec![tx1, tx2, tx3], 8, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 2);
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::TailChecksumInvalid { .. }),
        ));
    }

    #[test]
    fn apply_inode_record_overwrites_inode_bytes() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 2;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        raw[0] ^= 0xFF;
        raw[1] ^= 0x0F;
        raw[40..48].copy_from_slice(b"fcinode!");

        let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");
        let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

        assert_eq!(&after[0..2], &raw[0..2]);
        assert_eq!(&after[40..48], b"fcinode!");
        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(state.plan.inodes_modified, 1);
        assert!(state.modified_inodes.contains(&inum));
    }

    #[test]
    fn apply_inode_record_preserves_tail_bytes_when_record_is_128_and_inode_size_is_256() {
        let (ext, mut cursor) = fixture_ext();
        assert_eq!(ext.inode_size(), 256);
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 2;
        let before = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        let mut raw = before[..128].to_vec();
        raw[0] ^= 0xFF;
        raw[40..48].copy_from_slice(b"prefix!!");

        let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");
        let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

        assert_eq!(&after[0..1], &raw[0..1]);
        assert_eq!(&after[40..48], b"prefix!!");
        assert_eq!(&after[128..130], &before[128..130]);
        assert_eq!(&after[132..], &before[132..]);
    }

    #[test]
    fn apply_inode_record_with_oor_inum_emits_warning_and_continues() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let oor_inum = ext.inodes_count + 1;

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .inode(oor_inum, &[0xA5; 128])
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(state.plan.warnings.len(), 1);
        assert_eq!(state.plan.warnings[0].current_tid, Some(TID));
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::InodeOutOfRange { inum: oor_inum }
        );
        assert!(state.modified_inodes.is_empty());
    }

    #[test]
    fn apply_inode_record_with_invalid_length_emits_malformed_record_stop() {
        let (ext, mut cursor) = fixture_ext();
        assert_eq!(ext.inode_size(), 256);
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);

        let tx = FcTxBuilder::new(TID).head(0).inode(2, &[0xCC; 512]).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        assert!(scan.stop.is_none());

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 0);
        assert!(state.composed_overlay.blocks.is_empty());
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_INODE,
                fc_len: 516,
                reason: "inode raw_inode length out of [128, s_inode_size]",
            })
        ));
    }

    #[test]
    fn apply_inode_record_crossing_block_boundary_commits() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 2;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        raw[0] ^= 0xFF;
        raw[40..48].copy_from_slice(b"crossing");

        let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
        let blocks = split_tx_across_blocks(&tx, 80);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, 80, FC_FIRST, TID);
        assert!(scan.stop.is_none());

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            80,
            FC_FIRST,
            &scan,
        )
        .expect("apply");
        let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(&after[0..1], &raw[0..1]);
        assert_eq!(&after[40..48], b"crossing");
    }

    #[test]
    fn apply_inode_record_with_oor_inum_and_invalid_length_stops_malformed() {
        let (ext, mut cursor) = fixture_ext();
        assert_eq!(ext.inode_size(), 256);
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let oor_inum = ext.inodes_count + 1;

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .inode(oor_inum, &[0xDD; 512])
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        assert!(scan.stop.is_none());

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 0);
        assert!(state.plan.warnings.is_empty());
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_INODE,
                fc_len: 516,
                reason: "inode raw_inode length out of [128, s_inode_size]",
            })
        ));
    }

    #[test]
    fn apply_add_range_inserts_extent_and_records_modified_inode() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let old_pblk = first_root_data_block(&ext, &mut cursor);
        let new_pblk = old_pblk + 32;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
        set_inode_size(&mut raw, u64::from(BS));

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .inode(inum, &raw)
            .add_range(inum, 0, 1, new_pblk, false)
            .build();
        let state = apply_single_tx(&ext, &mut cursor, tx);

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(state.plan.tag_counts.add_range, 1);
        assert_eq!(state.plan.allocation_units_marked_free, 1);
        assert!(state.modified_inodes.contains(&inum));
        assert_eq!(
            inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
            vec![(0, 1, new_pblk, false)]
        );
        assert!(!overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &state.composed_overlay,
            old_pblk
        ));
    }

    #[test]
    fn apply_add_range_with_oor_inum_emits_warning() {
        let (ext, mut cursor) = fixture_ext();
        let oor_inum = ext.inodes_count + 1;
        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .add_range(oor_inum, 0, 1, 100, false)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.add_range, 1);
        assert_eq!(state.plan.warnings.len(), 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::InodeOutOfRange { inum: oor_inum }
        );
        assert!(state.modified_inodes.is_empty());
    }

    #[test]
    fn apply_add_range_with_oor_pblk_emits_physical_block_out_of_range_warning() {
        let (ext, mut cursor) = fixture_ext();
        let inum = 12;
        let pblk = ext.blocks_count;
        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .add_range(inum, 0, 1, pblk, false)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.add_range, 1);
        assert_eq!(state.plan.warnings.len(), 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::PhysicalBlockOutOfRange { inum, pblk, len: 1 }
        );
        assert!(state.modified_inodes.is_empty());
    }

    #[test]
    fn apply_add_range_grows_full_inode_root_instead_of_halting() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        set_inode_extent_root(
            &mut raw,
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
        set_inode_size(&mut raw, u64::from(BS));

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .inode(inum, &raw)
                .add_range(inum, 40, 1, 200, false)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.add_range, 1);
        assert!(state.modified_inodes.contains(&inum));
        assert_eq!(state.plan.allocation_units_marked_allocated, 1);
    }

    #[test]
    fn apply_add_range_failed_extent_surgery_rolls_back_and_halts() {
        let (mut ext, mut cursor) = fixture_ext();
        ext.blocks_per_cluster = 4;
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[], 4));
        set_inode_size(&mut raw, u64::from(BS));

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .inode(inum, &raw)
                .add_range(inum, 0, 1, 101, false)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 0);
        assert!(state.composed_overlay.blocks.is_empty());
        assert!(state.modified_inodes.is_empty());
        assert_eq!(state.plan.tag_counts.add_range, 0);
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::ExtentReplayFailed {
                inum: stopped,
                reason: ExtentReplayReason::BigallocPblkNotClusterAligned,
            }) if *stopped == inum
        ));
    }

    #[test]
    fn apply_del_range_removes_logical_and_frees_physical() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let old_pblk = first_root_data_block(&ext, &mut cursor);
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
        set_inode_size(&mut raw, u64::from(BS));

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .inode(inum, &raw)
                .del_range(inum, 0, 1)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(state.plan.tag_counts.del_range, 1);
        assert_eq!(state.plan.allocation_units_marked_free, 1);
        assert!(state.modified_inodes.contains(&inum));
        assert_eq!(
            inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
            Vec::<(u32, u16, u64, bool)>::new()
        );
        assert_eq!(
            inode_size_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum),
            0
        );
        assert!(!overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &state.composed_overlay,
            old_pblk
        ));
    }

    #[test]
    fn apply_del_range_inside_sparse_hole_does_not_shrink_or_mark_modified() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let old_pblk = first_root_data_block(&ext, &mut cursor);
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
        set_inode_size(&mut raw, u64::from(BS) * 10);
        write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID).head(0).del_range(inum, 5, 2).build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.inode, 0);
        assert_eq!(state.plan.tag_counts.del_range, 1);
        assert_eq!(state.plan.allocation_units_marked_free, 0);
        assert!(
            !state.modified_inodes.contains(&inum),
            "no-op hole delete must not add a modified inode solely for DEL_RANGE"
        );
        assert_eq!(
            inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
            vec![(0, 1, old_pblk, false)]
        );
        assert_eq!(
            inode_size_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum),
            u64::from(BS) * 10
        );
    }

    #[test]
    fn apply_del_range_with_logical_overflow_emits_logical_range_invalid_warning() {
        let (ext, mut cursor) = fixture_ext();
        let inum = 12;
        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .del_range(inum, u32::MAX, 2)
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert!(state.plan.stop.is_none());
        assert_eq!(state.plan.tag_counts.del_range, 1);
        assert_eq!(state.plan.warnings.len(), 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::LogicalRangeInvalid {
                inum,
                lblk: u32::MAX,
                len: 2,
            }
        );
        assert!(state.modified_inodes.is_empty());
    }

    #[test]
    fn apply_creat_appends_dir_entry_and_increments_links() {
        let (ext, mut cursor) = fixture_ext();
        let parent = 2;
        let child = 20;
        let name = b"fc-created";
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .creat(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.creat, 1);
        assert!(state.plan.warnings.is_empty());
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links + 1
        );
        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
            Some((child, 1))
        );
        assert!(state.modified_inodes.contains(&parent));
        assert!(state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_creat_with_htree_parent_maintains_index_without_warning() {
        // Issue #116: a CREAT into an htree-indexed parent (inode 21,
        // /htree_dir) is now replayed through the dx-tree instead of
        // emitting a DirectoryReplayFailed { HtreeNotMaintained } warning.
        let (ext, mut cursor) = fixture_ext();
        let parent = 21;
        let child = 20;
        let name = b"fc-htree-add";
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .creat(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.creat, 1);
        assert!(
            state.plan.warnings.is_empty(),
            "htree CREAT must not emit a DirectoryReplayFailed warning"
        );
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links + 1
        );
        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
            Some((child, 1)),
            "the new dentry must be present in the htree parent"
        );
        assert!(
            state.modified_inodes.contains(&parent),
            "the htree parent is now a modified inode"
        );
        assert!(state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_unlink_with_htree_parent_maintains_index_without_warning() {
        // Issue #116: an UNLINK from an htree-indexed parent removes the
        // dentry through the dx-tree. file_002.txt is inode 23.
        let (ext, mut cursor) = fixture_ext();
        let parent = 21;
        let child = 23;
        let name = b"file_002.txt";

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .unlink(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.unlink, 1);
        assert!(
            state.plan.warnings.is_empty(),
            "htree UNLINK must not emit a DirectoryReplayFailed warning"
        );
        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
            None,
            "the unlinked dentry must be gone from the htree parent"
        );
        assert!(state.modified_inodes.contains(&parent));
    }

    #[test]
    fn apply_creat_with_missing_parent_emits_directory_replay_failed_warning_with_parent_inode_missing()
     {
        let (ext, mut cursor) = fixture_ext();
        let parent = ext.inodes_count + 1;
        let child = 20;

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .creat(parent, child, b"fc-missing-parent")
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.creat, 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::DirectoryReplayFailed {
                parent_inum: parent,
                reason: DirectoryReplayReason::ParentInodeMissing,
            }
        );
        assert!(!state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_creat_with_link_count_overflow_rolls_back_tx_and_halts() {
        let (ext, mut cursor) = fixture_ext();
        let child = 20;
        set_links_count_in_image(&ext, &mut cursor, child, u16::MAX);
        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .creat(2, child, b"fc-overflow")
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 0);
        assert!(state.composed_overlay.blocks.is_empty());
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::LinkCountOverflow {
                inum,
                current: u16::MAX,
                delta: 1
            }) if *inum == child
        ));
    }

    #[test]
    fn apply_link_increments_link_count_and_appends_entry() {
        let (ext, mut cursor) = fixture_ext();
        let parent = 2;
        let child = 20;
        let name = b"hello-hardlink";
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .link(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.link, 1);
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links + 1
        );
        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
            Some((child, 1))
        );
    }

    #[test]
    fn apply_unlink_removes_entry_and_decrements_links() {
        let (ext, mut cursor) = fixture_ext();
        let parent = 2;
        let child = 20;
        let name = b"hello.txt";
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .unlink(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.unlink, 1);
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links - 1
        );
        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
            None
        );
        assert!(state.modified_inodes.contains(&parent));
        assert!(state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_unlink_with_target_missing_emits_unlink_target_missing_warning() {
        let (ext, mut cursor) = fixture_ext();
        let child = 20;
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .unlink(2, child, b"missing-link")
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.unlink, 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::UnlinkTargetMissing {
                parent_inum: 2,
                child_inum: child,
            }
        );
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links
        );
        assert!(!state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_unlink_with_target_missing_prunes_net_neutral_inode_scratch() {
        let (ext, mut cursor) = fixture_ext();
        let child = 20;
        let inode_block = inode_table_block(&ext, child);

        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .unlink(2, child, b"missing-link")
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.unlink, 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::UnlinkTargetMissing {
                parent_inum: 2,
                child_inum: child,
            }
        );
        assert!(
            !state.composed_overlay.blocks.contains_key(&inode_block),
            "net-neutral rollback must not emit the inode-table scratch block"
        );
    }

    #[test]
    fn apply_creat_uses_child_mode_from_in_flight_inode_scratch_for_file_type() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let child = 20;
        let name = b"fc-symlink-type";
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, child);
        set_inode_mode(&mut raw, 0xA000 | 0o777);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .inode(child, &raw)
            .creat(2, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(
            raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, 2, name),
            Some((child, 7))
        );
        assert_eq!(state.plan.tag_counts.creat, 1);
    }

    #[test]
    fn apply_creat_parent_precheck_observes_in_flight_inode_scratch_mode() {
        let (ext, mut cursor) = fixture_ext();
        let composed = classic_overlay_for_fixture(&ext, &mut cursor);
        let parent = 2;
        let child = 20;
        let name = b"fc-parent-now-file";
        let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);
        let mut raw_parent = raw_inode_from_overlay(&ext, &mut cursor, &composed, parent);
        set_inode_mode(&mut raw_parent, 0x8000 | 0o644);

        let tx = FcTxBuilder::new(TID)
            .head(0)
            .inode(parent, &raw_parent)
            .creat(parent, child, name)
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
        let state = apply_pass(
            &ext,
            &mut cursor,
            composed,
            &block_refs,
            BS,
            FC_FIRST,
            &scan,
        )
        .expect("apply");

        assert_eq!(state.plan.transactions_replayed, 1);
        assert_eq!(state.plan.tag_counts.inode, 1);
        assert_eq!(state.plan.tag_counts.creat, 1);
        assert_eq!(
            state.plan.warnings[0].kind,
            FastCommitWarningKind::DirectoryReplayFailed {
                parent_inum: parent,
                reason: DirectoryReplayReason::ParentNotADirectory,
            }
        );
        assert_eq!(
            read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
            before_links
        );
        assert!(!state.modified_inodes.contains(&child));
    }

    #[test]
    fn apply_unlink_with_link_count_underflow_rolls_back_tx_and_halts() {
        let (ext, mut cursor) = fixture_ext();
        let child = 20;
        set_links_count_in_image(&ext, &mut cursor, child, 0);
        let state = apply_single_tx(
            &ext,
            &mut cursor,
            FcTxBuilder::new(TID)
                .head(0)
                .unlink(2, child, b"hello.txt")
                .build(),
        );

        assert_eq!(state.plan.transactions_replayed, 0);
        assert!(state.composed_overlay.blocks.is_empty());
        assert!(matches!(
            state.plan.stop.as_ref().map(|s| &s.reason),
            Some(FastCommitStopReason::LinkCountOverflow {
                inum,
                current: 0,
                delta: -1
            }) if *inum == child
        ));
    }

    mod finalizer {
        use alloc::collections::BTreeSet;

        use super::*;

        fn clear_block_bitmap_bit_in_image(
            ext: &crate::Ext,
            cursor: &mut std::io::Cursor<Vec<u8>>,
            pblk: u64,
        ) {
            let group = ((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group))
                as usize;
            let block_in_group =
                (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
            let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
            let bitmap_block = ext.group_descs[group].block_bitmap;
            let byte_offset =
                bitmap_block as usize * ext.block_size() as usize + (alloc_unit / 8) as usize;
            let mask = 1u8 << (alloc_unit % 8);
            cursor.get_mut()[byte_offset] &= !mask;
        }

        fn write_disk_block(
            ext: &crate::Ext,
            cursor: &mut std::io::Cursor<Vec<u8>>,
            block: u64,
            content: &[u8],
        ) {
            assert_eq!(content.len(), ext.block_size() as usize);
            let offset = block as usize * ext.block_size() as usize;
            cursor.get_mut()[offset..offset + content.len()].copy_from_slice(content);
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

        fn leaf_block_bytes(ext: &crate::Ext, extents: &[RawExtent], max: u16) -> Vec<u8> {
            let mut block = alloc::vec![0u8; ext.block_size() as usize];
            block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
            block[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
            block[4..6].copy_from_slice(&max.to_le_bytes());
            for (idx, extent) in extents.iter().enumerate() {
                write_extent_record(&mut block, 12 + idx * 12, *extent);
            }
            block
        }

        fn write_index_record(buf: &mut [u8], offset: usize, logical: u32, child: u64) {
            buf[offset..offset + 4].copy_from_slice(&logical.to_le_bytes());
            buf[offset + 4..offset + 8].copy_from_slice(&(child as u32).to_le_bytes());
            buf[offset + 8..offset + 10].copy_from_slice(&((child >> 32) as u16).to_le_bytes());
        }

        fn set_inline_data_flag(raw_inode: &mut [u8]) {
            let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
                | crate::inode::InodeFlags::INLINE_DATA_FL.bits();
            raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        }

        fn set_extents_flag(raw_inode: &mut [u8]) {
            let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
                | crate::inode::InodeFlags::EXTENTS_FL.bits();
            raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
        }

        fn run_finalizer(
            ext: &crate::Ext,
            cursor: &mut std::io::Cursor<Vec<u8>>,
            mut overlay: BlockOverlay,
            modified_inodes: &BTreeSet<u32>,
            plan: &mut FastCommitPlan,
        ) -> BlockOverlay {
            let sb_host_bytes = overlay.sb_host_block_content.to_vec();
            let mutator = Mutator::new(ext, &sb_host_bytes);
            let mutator = {
                let mut reader = compose_reader(cursor, &overlay);
                finalize_pass(ext, &mut reader, mutator, modified_inodes, plan)
                    .expect("pass-C finalizer")
            };
            let delta = {
                let mut reader = compose_reader(cursor, &overlay);
                mutator.finalize(&mut reader).expect("finalize pass-C")
            };
            merge_delta_into_overlay(&mut overlay, delta);
            overlay
        }

        #[test]
        fn finalizer_marks_data_blocks_allocated_for_modified_inodes() {
            let (ext, mut cursor) = fixture_ext();
            assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
            let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
            let inum = 12;
            let pblk = first_root_data_block(&ext, &mut cursor) + 32;
            let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
            set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 2, pblk, false)], 4));
            set_inode_size(&mut raw, u64::from(BS) * 2);
            write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk + 1);
            assert!(!overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
            assert!(!overlay_block_bitmap_bit(
                &ext,
                &mut cursor,
                &overlay,
                pblk + 1
            ));

            let mut modified_inodes = BTreeSet::new();
            modified_inodes.insert(inum);
            let mut plan = FastCommitPlan {
                stop: Some(FastCommitStop {
                    position: FastCommitPosition {
                        fc_block: FC_FIRST,
                        block_offset: 0,
                        fs_byte_offset: u64::from(FC_FIRST) * u64::from(BS),
                    },
                    last_committed_tid: Some(TID),
                    reason: FastCommitStopReason::RegionExhaustedMidTransaction,
                }),
                ..FastCommitPlan::default()
            };

            let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

            assert!(overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
            assert!(overlay_block_bitmap_bit(
                &ext,
                &mut cursor,
                &overlay,
                pblk + 1
            ));
            assert_eq!(plan.allocation_units_marked_allocated, 2);
            assert!(plan.stop.is_some(), "pass-C must not clear existing stops");
            assert!(plan.warnings.is_empty());
        }

        #[test]
        fn finalizer_marks_internal_index_blocks_allocated() {
            let (mut ext, mut cursor) = fixture_ext();
            ext.checksum_seed = None;
            assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
            let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
            let inum = 12;
            let index_block = first_root_data_block(&ext, &mut cursor) + 64;
            let data_pblk = index_block + 4;
            let leaf = leaf_block_bytes(&ext, &[raw_extent(0, 1, data_pblk, false)], 340);
            write_disk_block(&ext, &mut cursor, index_block, &leaf);
            let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
            set_inode_extent_root(&mut raw, index_root(&[(0, index_block)], 4, 1));
            set_inode_size(&mut raw, u64::from(BS));
            write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, index_block);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, data_pblk);

            let mut modified_inodes = BTreeSet::new();
            modified_inodes.insert(inum);
            let mut plan = FastCommitPlan::default();
            let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

            assert!(overlay_block_bitmap_bit(
                &ext,
                &mut cursor,
                &overlay,
                index_block
            ));
            assert!(overlay_block_bitmap_bit(
                &ext,
                &mut cursor,
                &overlay,
                data_pblk
            ));
            assert_eq!(plan.allocation_units_marked_allocated, 2);
            assert!(plan.warnings.is_empty());
        }

        #[test]
        fn finalizer_skips_inline_data_inodes() {
            let (ext, mut cursor) = fixture_ext();
            assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
            let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
            let inum = 12;
            let pblk = first_root_data_block(&ext, &mut cursor) + 96;
            let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
            set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, pblk, false)], 4));
            set_inline_data_flag(&mut raw);
            set_inode_size(&mut raw, 0);
            write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);

            let mut modified_inodes = BTreeSet::new();
            modified_inodes.insert(inum);
            let mut plan = FastCommitPlan::default();
            let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

            assert!(!overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
            assert_eq!(plan.allocation_units_marked_allocated, 0);
            assert!(plan.warnings.is_empty());
        }

        #[test]
        fn finalizer_emits_warning_on_corrupt_extent_tree_and_continues_other_inodes() {
            let (ext, mut cursor) = fixture_ext();
            assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
            let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
            let corrupt_inum = 12;
            let valid_inum = 13;
            let pblk = first_root_data_block(&ext, &mut cursor) + 128;

            let mut corrupt_raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, corrupt_inum);
            set_inode_mode(&mut corrupt_raw, S_IFREG | 0o644);
            set_extents_flag(&mut corrupt_raw);
            corrupt_raw[0x28..0x2A].copy_from_slice(&0xDEADu16.to_le_bytes());
            write_raw_inode_to_image(&ext, &mut cursor, corrupt_inum, &corrupt_raw);

            let mut valid_raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, valid_inum);
            set_inode_extent_root(
                &mut valid_raw,
                leaf_root(&[raw_extent(0, 1, pblk, false)], 4),
            );
            set_inode_size(&mut valid_raw, u64::from(BS));
            write_raw_inode_to_image(&ext, &mut cursor, valid_inum, &valid_raw);
            clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);

            let modified_inodes = BTreeSet::from([corrupt_inum, valid_inum]);
            let mut plan = FastCommitPlan::default();
            let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

            assert_eq!(plan.warnings.len(), 1);
            assert_eq!(
                plan.warnings[0].kind,
                FastCommitWarningKind::FinalizerExtentWalkFailed { inum: corrupt_inum }
            );
            assert_eq!(plan.warnings[0].occurrences, 1);
            assert!(overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
            assert_eq!(plan.allocation_units_marked_allocated, 1);
        }
    }
}
