use super::{
    AllocationKind, AllocationRun, Ext, ExtError, IndirectTruncateResult, Read, Result, Seek,
    SeekFrom,
};

/// Result returned by `walk_indirect_block` for one indirect block.
struct IndirectBlockResult {
    freed_runs: alloc::vec::Vec<AllocationRun>,
    /// Count of child indirect-pointer blocks (not this block itself) that
    /// remain live. The caller adds 1 if `survivor.is_some()`.
    surviving_metadata_blocks: u64,
    /// `Some((mutated, content))` when this indirect block survives (at least
    /// one non-sparse pointer was kept). `mutated` is `true` when freed child-
    /// pointer slots were zeroed in `content` — callers push to
    /// `surviving_indirect_patches` only when `mutated`. `None` means the
    /// block was fully freed; the caller adds it to `freed_runs` as Metadata.
    survivor: Option<(bool, alloc::boxed::Box<[u8]>)>,
    /// Surviving indirect patches from child indirect blocks (recursive).
    surviving_indirect_patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)>,
}

/// Parameters threaded through the recursive indirect-block walker to
/// stay under the 7-argument lint limit.
struct WalkParams {
    inode_num: u32,
    cutoff: u64,
    ppb: u64,
    blocks_count: u64,
    block_size: u64,
}

fn read_indirect_block<T: Read + Seek>(
    params: &WalkParams,
    overlay: &mut T,
    physical_block: u64,
) -> Result<alloc::vec::Vec<u8>> {
    let block_size =
        usize::try_from(params.block_size).map_err(|_| ExtError::InvalidIndirectBlock {
            inode: params.inode_num,
            reason: "block size exceeds addressable memory",
        })?;
    let byte_offset =
        physical_block
            .checked_mul(params.block_size)
            .ok_or(ExtError::InvalidIndirectBlock {
                inode: params.inode_num,
                reason: "block pointer byte offset overflows u64",
            })?;
    let mut buffer = alloc::vec![0u8; block_size];
    overlay
        .seek(SeekFrom::Start(byte_offset))
        .map_err(ExtError::Io)?;
    overlay.read_exact(&mut buffer).map_err(ExtError::Io)?;
    Ok(buffer)
}

/// Walk one indirect block at the given `level` (1=single, 2=double,
/// 3=triple) and collect freed `AllocationRun`s.
///
/// - `level == 1`: this block contains direct-data pointers.
/// - `level > 1`: this block contains pointers to sub-indirect blocks.
///
/// Returns an `IndirectBlockResult`:
/// - `survivor`: `Some(buf)` when at least one non-sparse pointer survives,
///   with freed child-pointer slots zeroed; `None` when all non-sparse
///   pointers were freed (caller must add this block to `freed_runs` as Metadata).
/// - `surviving_metadata_blocks`: count of surviving child indirect blocks
///   (not this block itself). The caller adds 1 if `survivor.is_some()`.
/// - `freed_runs`, `surviving_indirect_patches`: accumulated results.
fn walk_indirect_block<T: Read + Seek>(
    p: &WalkParams,
    overlay: &mut T,
    phys_block: u64,
    first_lblock: u64,
    level: u32,
) -> Result<IndirectBlockResult> {
    let mut buf = read_indirect_block(p, overlay, phys_block)?;

    let mut runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();
    let mut any_kept = false;
    let mut buf_mutated = false;
    // Count of child indirect-pointer blocks that survive (not this block itself).
    let mut child_meta: u64 = 0;
    let mut patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)> = alloc::vec::Vec::new();

    for slot in 0..p.ppb {
        let slot_offset =
            usize::try_from(slot * 4).map_err(|_| ExtError::InvalidIndirectBlock {
                inode: p.inode_num,
                reason: "indirect pointer offset exceeds addressable memory",
            })?;
        let ptr = u32::from_le_bytes(
            buf[slot_offset..slot_offset + 4]
                .try_into()
                .expect("4-byte slice"),
        );
        if ptr == 0 {
            // Sparse hole — neither kept nor freed. Indirect block survival is
            // determined purely by whether any real pointers survive.
            continue;
        }

        let ptr64 = u64::from(ptr);
        if ptr64 >= p.blocks_count {
            return Err(ExtError::InvalidIndirectBlock {
                inode: p.inode_num,
                reason: "block pointer exceeds filesystem blocks_count",
            });
        }

        // Logical block range covered by this slot.
        let span = level_span(level, p.ppb);
        let lblock_start = first_lblock + slot * span;

        if level == 1 {
            // Direct-data pointer.
            if lblock_start < p.cutoff {
                // Before cutoff — keep.
                any_kept = true;
            } else {
                // At or past cutoff — free as Data run; zero this slot in buf.
                runs.push(AllocationRun {
                    physical_start: ptr64,
                    block_len: 1,
                    kind: AllocationKind::Data {
                        logical_cluster_start: lblock_start,
                    },
                });
                buf[slot_offset..slot_offset + 4].copy_from_slice(&0u32.to_le_bytes());
                buf_mutated = true;
            }
        } else {
            // Indirect block.
            let lblock_last_inclusive = lblock_start + span - 1;

            if lblock_last_inclusive < p.cutoff {
                // Entire subtree before cutoff — keep everything.
                // This child indirect block survives; count it + its children.
                any_kept = true;
                let child_result = walk_indirect_block(p, overlay, ptr64, lblock_start, level - 1)?;
                // child block itself + its surviving descendants.
                child_meta += 1 + child_result.surviving_metadata_blocks;
                // Propagate patches from the child's subtree.
                patches.extend(child_result.surviving_indirect_patches);
                // The child itself survives entirely — add its patch if mutated.
                if let Some((true, child_buf)) = child_result.survivor {
                    patches.push((ptr64, child_buf));
                }
            } else if lblock_start >= p.cutoff {
                // Entire subtree at or past cutoff — collect recursively and
                // then free the indirect block itself.
                let child_result = walk_indirect_block(p, overlay, ptr64, lblock_start, level - 1)?;
                runs.extend(child_result.freed_runs);
                // Free this indirect block as Metadata; zero the slot.
                runs.push(AllocationRun {
                    physical_start: ptr64,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                });
                buf[slot_offset..slot_offset + 4].copy_from_slice(&0u32.to_le_bytes());
                buf_mutated = true;
            } else {
                // Subtree straddles the cutoff — recurse, keep partial, maybe
                // collapse if nothing survived.
                let child_result = walk_indirect_block(p, overlay, ptr64, lblock_start, level - 1)?;
                runs.extend(child_result.freed_runs);
                patches.extend(child_result.surviving_indirect_patches);
                if let Some((mutated, child_buf)) = child_result.survivor {
                    any_kept = true;
                    // This child indirect block survives + its surviving descendants.
                    child_meta += 1 + child_result.surviving_metadata_blocks;
                    if mutated {
                        patches.push((ptr64, child_buf));
                    }
                } else {
                    // All child slots were freed — collapse this indirect block;
                    // zero the slot in our buffer.
                    runs.push(AllocationRun {
                        physical_start: ptr64,
                        block_len: 1,
                        kind: AllocationKind::Metadata,
                    });
                    buf[slot_offset..slot_offset + 4].copy_from_slice(&0u32.to_le_bytes());
                    buf_mutated = true;
                }
            }
        }
    }

    // Return the buffer when anything survived. The buffer is marked mutated
    // only when freed slots were zeroed; callers only push it to patches when
    // `buf_mutated` — but we always return the full buffer so the caller has
    // valid content either way. Pass `buf_mutated` alongside via `survivor`.
    let survivor = any_kept.then(|| (buf_mutated, buf.into_boxed_slice()));

    Ok(IndirectBlockResult {
        freed_runs: runs,
        surviving_metadata_blocks: child_meta,
        survivor,
        surviving_indirect_patches: patches,
    })
}

/// Span (in logical blocks) covered by one slot at a given indirection level.
///
/// - level 1: 1 block per slot (direct-data pointer)
/// - level 2: ppb blocks per slot (single-indirect → direct)
/// - level 3: ppb² blocks per slot (double-indirect → single → direct)
#[inline]
fn level_span(level: u32, ppb: u64) -> u64 {
    match level {
        2 => ppb,
        3 => ppb * ppb,
        _ => 1,
    }
}

struct IndirectMapState {
    freed_runs: alloc::vec::Vec<AllocationRun>,
    new_i_block: [u8; 60],
    surviving_metadata_blocks: u64,
    surviving_indirect_patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)>,
}

fn process_indirect_root<T: Read + Seek>(
    params: &WalkParams,
    overlay: &mut T,
    state: &mut IndirectMapState,
    byte_offset: usize,
    first_logical_block: u64,
    level: u32,
) -> Result<()> {
    let pointer = u32::from_le_bytes(
        state.new_i_block[byte_offset..byte_offset + 4]
            .try_into()
            .expect("an indirect root pointer occupies four bytes"),
    );
    if pointer == 0 {
        return Ok(());
    }
    let physical_block = u64::from(pointer);
    if physical_block >= params.blocks_count {
        return Err(ExtError::InvalidIndirectBlock {
            inode: params.inode_num,
            reason: "indirect root pointer exceeds filesystem blocks_count",
        });
    }
    let root_span = match level {
        1 => params.ppb,
        2 => params.ppb * params.ppb,
        3 => params.ppb * params.ppb * params.ppb,
        _ => 1,
    };
    let last_logical_block = first_logical_block + root_span - 1;

    if last_logical_block < params.cutoff {
        if level == 1 {
            state.surviving_metadata_blocks += 1;
            return Ok(());
        }
        let child =
            walk_indirect_block(params, overlay, physical_block, first_logical_block, level)?;
        state.surviving_metadata_blocks += 1 + child.surviving_metadata_blocks;
        state
            .surviving_indirect_patches
            .extend(child.surviving_indirect_patches);
        if let Some((true, buffer)) = child.survivor {
            state
                .surviving_indirect_patches
                .push((physical_block, buffer));
        }
        return Ok(());
    }

    let child = walk_indirect_block(params, overlay, physical_block, first_logical_block, level)?;
    state.freed_runs.extend(child.freed_runs);
    if first_logical_block >= params.cutoff {
        state.freed_runs.push(AllocationRun {
            physical_start: physical_block,
            block_len: 1,
            kind: AllocationKind::Metadata,
        });
        state.new_i_block[byte_offset..byte_offset + 4].fill(0);
        return Ok(());
    }

    state
        .surviving_indirect_patches
        .extend(child.surviving_indirect_patches);
    if let Some((mutated, buffer)) = child.survivor {
        state.surviving_metadata_blocks += 1 + child.surviving_metadata_blocks;
        if mutated {
            state
                .surviving_indirect_patches
                .push((physical_block, buffer));
        }
    } else {
        state.freed_runs.push(AllocationRun {
            physical_start: physical_block,
            block_len: 1,
            kind: AllocationKind::Metadata,
        });
        state.new_i_block[byte_offset..byte_offset + 4].fill(0);
    }
    Ok(())
}

/// Walk the classical ext2/3 indirect-block-map in `i_block[0..60]`.
///
/// Layout:
/// - `[0..48]`  = 12 direct block pointers (logical blocks 0..11)
/// - `[48..52]` = single-indirect pointer  (logical blocks 12..12+ppb-1)
/// - `[52..56]` = double-indirect pointer  (logical blocks 12+ppb..12+ppb+ppb²-1)
/// - `[56..60]` = triple-indirect pointer  (logical blocks 12+ppb+ppb²..12+ppb+ppb²+ppb³-1)
///
/// Returns freed `AllocationRun`s, the rewritten `new_i_block`, and the
/// count of surviving indirect-pointer blocks (for accurate `i_blocks`
/// recomputation). Freeing collapsed indirect blocks is included in
/// `freed_runs` as `AllocationKind::Metadata` entries.
pub(crate) fn walk_indirect_map<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    inode_num: u32,
    i_block: &[u8; 60],
    cutoff: u64,
) -> Result<IndirectTruncateResult> {
    let ppb = u64::from(ext.block_size) / 4;
    let p = WalkParams {
        inode_num,
        cutoff,
        ppb,
        blocks_count: ext.blocks_count,
        block_size: u64::from(ext.block_size),
    };

    let mut state = IndirectMapState {
        freed_runs: alloc::vec::Vec::new(),
        new_i_block: *i_block,
        surviving_metadata_blocks: 0,
        surviving_indirect_patches: alloc::vec::Vec::new(),
    };

    for slot in 0..12u64 {
        let byte_off =
            usize::try_from(slot * 4).expect("the direct block pointers occupy only 48 bytes");
        let ptr = u32::from_le_bytes(
            state.new_i_block[byte_off..byte_off + 4]
                .try_into()
                .expect("a direct pointer occupies four bytes"),
        );
        if ptr == 0 {
            continue;
        }
        let ptr64 = u64::from(ptr);
        if ptr64 >= p.blocks_count {
            return Err(ExtError::InvalidIndirectBlock {
                inode: inode_num,
                reason: "direct block pointer exceeds filesystem blocks_count",
            });
        }
        if slot >= cutoff {
            state.freed_runs.push(AllocationRun {
                physical_start: ptr64,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: slot,
                },
            });
            state.new_i_block[byte_off..byte_off + 4].fill(0);
        }
    }

    process_indirect_root(&p, overlay, &mut state, 48, 12, 1)?;
    process_indirect_root(&p, overlay, &mut state, 52, 12 + ppb, 2)?;
    process_indirect_root(&p, overlay, &mut state, 56, 12 + ppb + ppb * ppb, 3)?;

    Ok(IndirectTruncateResult {
        freed_runs: state.freed_runs,
        new_i_block: state.new_i_block,
        surviving_metadata_blocks: state.surviving_metadata_blocks,
        surviving_indirect_patches: state.surviving_indirect_patches,
    })
}
