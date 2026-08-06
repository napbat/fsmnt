//! Shared helpers for applying fast-commit records.

use super::{
    DirectoryReplayReason, Ext, ExtError, FC_TAG_CREAT, FC_TAG_LINK, FC_TAG_UNLINK, FastCommitPlan,
    FastCommitPosition, FastCommitStop, FastCommitStopReason, FastCommitTagCounts,
    FastCommitWarning, FastCommitWarningKind, LinkCountChange, Mutator, RawExtent, Read, Result,
    S_IFDIR, S_IFLNK, S_IFMT, S_IFREG, Seek, TxBuffer, mutator_error_to_ext,
};
use crate::journal::replay::BlockOverlay;

pub(super) fn adjust_child_links_count<T: Read + Seek>(
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

pub(super) fn physical_range_invalid(ext: &Ext, raw_extent: RawExtent) -> bool {
    if raw_extent.ee_pblk < u64::from(ext.first_data_block) {
        return true;
    }
    let Some(end) = raw_extent.ee_pblk.checked_add(u64::from(raw_extent.ee_len)) else {
        return true;
    };
    raw_extent.ee_pblk >= ext.blocks_count || end > ext.blocks_count
}

pub(super) fn logical_range_invalid<T: Read + Seek>(
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

pub(super) fn current_inode_mode<T: Read + Seek>(
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

pub(super) fn current_inode_flags<T: Read + Seek>(
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

pub(super) fn dentry_file_type<T: Read + Seek>(
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

pub(super) fn push_directory_replay_warning(
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

pub(super) fn increment_dentry_tag_count(counts: &mut FastCommitTagCounts, tag: u16) {
    match tag {
        FC_TAG_CREAT => counts.creat += 1,
        FC_TAG_LINK => counts.link += 1,
        FC_TAG_UNLINK => counts.unlink += 1,
        _ => {}
    }
}

pub(super) fn position_at(
    rel_block_idx: usize,
    record_offset: usize,
    block_size: u32,
    fc_first: u32,
) -> FastCommitPosition {
    let fc_block = fc_first.saturating_add(
        u32::try_from(rel_block_idx)
            .expect("a fast-commit region cannot contain more than u32::MAX blocks"),
    );
    let block_offset = u32::try_from(record_offset)
        .expect("a fast-commit record offset is bounded by the u32 block size");
    FastCommitPosition {
        fc_block,
        block_offset,
        fs_byte_offset: u64::from(fc_block) * u64::from(block_size) + u64::from(block_offset),
    }
}

pub(super) fn stop_current_tx(
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

pub(super) fn push_warning_to_tx(tx_buf: &mut TxBuffer, warning: FastCommitWarning) {
    tx_buf.warnings.push(warning);
}

pub(super) fn compose_reader<'a, T: Read + Seek>(
    fs: &'a mut T,
    composed: &'a BlockOverlay,
) -> crate::OverlayReader<'a, 'a, T, BlockOverlay> {
    crate::OverlayReader::new(fs, composed)
}
