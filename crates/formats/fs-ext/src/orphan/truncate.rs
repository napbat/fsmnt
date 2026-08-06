//! Truncate-completion apply path for orphan Level-3. See
//! `docs/superpowers/specs/2026-04-24-fs-ext-orphan-level3-design.md` §2.1.

use zerocopy::FromBytes;

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::{RawExtent, RawExtentHeader, RawExtentIndex, index_child_block, parse_header};
use crate::inode::InodeFlags;
use crate::io::{Read, Seek, SeekFrom};
use crate::orphan::mutator::{AllocationKind, AllocationRun, Mutator, MutatorError, MutatorResult};

/// Magic number present in every extent tree node header.
const EXTENT_MAGIC: u16 = 0xF30A;

/// Compute the retain cutoff: the first logical cluster that must be
/// freed. All clusters `< retain_cutoff` are kept; clusters `>=
/// retain_cutoff` are freed.
///
/// For `target_size == 0` → retain 0 clusters (free everything). For
/// `target_size > 0` → retain through the cluster containing
/// `target_size - 1`, which yields `(target_size - 1) / cluster_size + 1`.
///
/// On non-bigalloc filesystems, `cluster_size == block_size`, so this
/// returns the block cutoff.
#[inline]
pub(crate) fn retain_cutoff_logical_cluster(target_size: u64, cluster_size: u64) -> u64 {
    if target_size == 0 {
        0
    } else {
        (target_size - 1) / cluster_size + 1
    }
}

/// Result of walking an indirect-block-map inode's block-pointer tree.
#[derive(Debug)]
pub(crate) struct IndirectTruncateResult {
    pub(crate) freed_runs: alloc::vec::Vec<AllocationRun>,
    /// Rewritten 60-byte block-pointer array. Direct pointers in slots
    /// past the cutoff are zeroed; surviving direct pointers are preserved
    /// verbatim. Indirect-pointer slots whose subtrees were fully freed
    /// are zeroed (collapsed).
    pub(crate) new_i_block: [u8; 60],
    /// Number of indirect-pointer blocks (single-, double-, triple-indirect)
    /// that remain live after truncation. Used to compute `i_blocks`
    /// accurately for partial indirect-tree truncations.
    pub(crate) surviving_metadata_blocks: u64,
    /// Surviving indirect blocks whose contents changed (freed child pointers
    /// were zeroed). Each entry is `(physical_block, new_content)`. The caller
    /// must publish these through `Mutator::patch_indirect_block` before
    /// finalizing, so the on-disk block has freed slots zeroed.
    pub(crate) surviving_indirect_patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)>,
}

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
    /// block was fully freed; the caller adds it to freed_runs as Metadata.
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

/// Walk one indirect block at the given `level` (1=single, 2=double,
/// 3=triple) and collect freed `AllocationRun`s.
///
/// - `level == 1`: this block contains direct-data pointers.
/// - `level > 1`: this block contains pointers to sub-indirect blocks.
///
/// Returns an `IndirectBlockResult`:
/// - `survivor`: `Some(buf)` when at least one non-sparse pointer survives,
///   with freed child-pointer slots zeroed; `None` when all non-sparse
///   pointers were freed (caller must add this block to freed_runs as Metadata).
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
    let mut buf = alloc::vec![0u8; p.block_size as usize];
    let byte_offset =
        phys_block
            .checked_mul(p.block_size)
            .ok_or(ExtError::InvalidIndirectBlock {
                inode: p.inode_num,
                reason: "block pointer byte offset overflows u64",
            })?;
    overlay
        .seek(SeekFrom::Start(byte_offset))
        .map_err(ExtError::Io)?;
    overlay.read_exact(&mut buf).map_err(ExtError::Io)?;

    let mut runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();
    let mut any_kept = false;
    let mut buf_mutated = false;
    // Count of child indirect-pointer blocks that survive (not this block itself).
    let mut child_meta: u64 = 0;
    let mut patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)> = alloc::vec::Vec::new();

    for slot in 0..p.ppb {
        let slot_offset = (slot * 4) as usize;
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
        1 => 1,
        2 => ppb,
        3 => ppb * ppb,
        _ => 1,
    }
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

    let mut freed_runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();
    let mut new_i_block = *i_block;
    let mut surviving_metadata_blocks: u64 = 0;
    let mut surviving_indirect_patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)> =
        alloc::vec::Vec::new();

    // --- Direct block pointers (slots 0..12, bytes 0..48) ---
    for slot in 0..12u64 {
        let byte_off = (slot * 4) as usize;
        let ptr = u32::from_le_bytes(new_i_block[byte_off..byte_off + 4].try_into().unwrap());
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
            freed_runs.push(AllocationRun {
                physical_start: ptr64,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: slot,
                },
            });
            new_i_block[byte_off..byte_off + 4].copy_from_slice(&0u32.to_le_bytes());
        }
    }

    // --- Single-indirect pointer (slot 12, bytes 48..52) ---
    // Covers logical blocks [12, 12+ppb).
    {
        let ptr = u32::from_le_bytes(new_i_block[48..52].try_into().unwrap());
        if ptr != 0 {
            let ptr64 = u64::from(ptr);
            if ptr64 >= p.blocks_count {
                return Err(ExtError::InvalidIndirectBlock {
                    inode: inode_num,
                    reason: "single-indirect pointer exceeds filesystem blocks_count",
                });
            }
            let first_lblock = 12u64;
            let last_lblock_inclusive = first_lblock + ppb - 1;
            if last_lblock_inclusive < cutoff {
                // Entire range before cutoff — keep as-is; this block survives.
                surviving_metadata_blocks += 1;
            } else if first_lblock >= cutoff {
                // Entire range at or past cutoff — free all + collapse.
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 1)?;
                freed_runs.extend(child_result.freed_runs);
                freed_runs.push(AllocationRun {
                    physical_start: ptr64,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                });
                new_i_block[48..52].copy_from_slice(&0u32.to_le_bytes());
            } else {
                // Straddles cutoff — recurse, collapse if all freed.
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 1)?;
                freed_runs.extend(child_result.freed_runs);
                surviving_indirect_patches.extend(child_result.surviving_indirect_patches);
                if let Some((mutated, child_buf)) = child_result.survivor {
                    // Single-indirect block itself survives.
                    surviving_metadata_blocks += 1;
                    if mutated {
                        surviving_indirect_patches.push((ptr64, child_buf));
                    }
                } else {
                    freed_runs.push(AllocationRun {
                        physical_start: ptr64,
                        block_len: 1,
                        kind: AllocationKind::Metadata,
                    });
                    new_i_block[48..52].copy_from_slice(&0u32.to_le_bytes());
                }
            }
        }
    }

    // --- Double-indirect pointer (slot 13, bytes 52..56) ---
    // Covers logical blocks [12+ppb, 12+ppb+ppb²).
    {
        let ptr = u32::from_le_bytes(new_i_block[52..56].try_into().unwrap());
        if ptr != 0 {
            let ptr64 = u64::from(ptr);
            if ptr64 >= p.blocks_count {
                return Err(ExtError::InvalidIndirectBlock {
                    inode: inode_num,
                    reason: "double-indirect pointer exceeds filesystem blocks_count",
                });
            }
            let first_lblock = 12 + ppb;
            let last_lblock_inclusive = first_lblock + ppb * ppb - 1;
            if last_lblock_inclusive < cutoff {
                // Keep as-is; count this block + all its child single-indirect blocks.
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 2)?;
                // This block + children from walker.
                surviving_metadata_blocks += 1 + child_result.surviving_metadata_blocks;
                // Propagate patches — child subtree survived entirely, no mutations.
                surviving_indirect_patches.extend(child_result.surviving_indirect_patches);
                if let Some((true, child_buf)) = child_result.survivor {
                    surviving_indirect_patches.push((ptr64, child_buf));
                }
            } else if first_lblock >= cutoff {
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 2)?;
                freed_runs.extend(child_result.freed_runs);
                freed_runs.push(AllocationRun {
                    physical_start: ptr64,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                });
                new_i_block[52..56].copy_from_slice(&0u32.to_le_bytes());
            } else {
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 2)?;
                freed_runs.extend(child_result.freed_runs);
                surviving_indirect_patches.extend(child_result.surviving_indirect_patches);
                if let Some((mutated, child_buf)) = child_result.survivor {
                    // This block + its surviving single-indirect children.
                    surviving_metadata_blocks += 1 + child_result.surviving_metadata_blocks;
                    if mutated {
                        surviving_indirect_patches.push((ptr64, child_buf));
                    }
                } else {
                    freed_runs.push(AllocationRun {
                        physical_start: ptr64,
                        block_len: 1,
                        kind: AllocationKind::Metadata,
                    });
                    new_i_block[52..56].copy_from_slice(&0u32.to_le_bytes());
                }
            }
        }
    }

    // --- Triple-indirect pointer (slot 14, bytes 56..60) ---
    // Covers logical blocks [12+ppb+ppb², 12+ppb+ppb²+ppb³).
    {
        let ptr = u32::from_le_bytes(new_i_block[56..60].try_into().unwrap());
        if ptr != 0 {
            let ptr64 = u64::from(ptr);
            if ptr64 >= p.blocks_count {
                return Err(ExtError::InvalidIndirectBlock {
                    inode: inode_num,
                    reason: "triple-indirect pointer exceeds filesystem blocks_count",
                });
            }
            let first_lblock = 12 + ppb + ppb * ppb;
            let last_lblock_inclusive = first_lblock + ppb * ppb * ppb - 1;
            if last_lblock_inclusive < cutoff {
                // Keep as-is; count this block + all descendants.
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 3)?;
                surviving_metadata_blocks += 1 + child_result.surviving_metadata_blocks;
                surviving_indirect_patches.extend(child_result.surviving_indirect_patches);
                if let Some((true, child_buf)) = child_result.survivor {
                    surviving_indirect_patches.push((ptr64, child_buf));
                }
            } else if first_lblock >= cutoff {
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 3)?;
                freed_runs.extend(child_result.freed_runs);
                freed_runs.push(AllocationRun {
                    physical_start: ptr64,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                });
                new_i_block[56..60].copy_from_slice(&0u32.to_le_bytes());
            } else {
                let child_result = walk_indirect_block(&p, overlay, ptr64, first_lblock, 3)?;
                freed_runs.extend(child_result.freed_runs);
                surviving_indirect_patches.extend(child_result.surviving_indirect_patches);
                if let Some((mutated, child_buf)) = child_result.survivor {
                    surviving_metadata_blocks += 1 + child_result.surviving_metadata_blocks;
                    if mutated {
                        surviving_indirect_patches.push((ptr64, child_buf));
                    }
                } else {
                    freed_runs.push(AllocationRun {
                        physical_start: ptr64,
                        block_len: 1,
                        kind: AllocationKind::Metadata,
                    });
                    new_i_block[56..60].copy_from_slice(&0u32.to_le_bytes());
                }
            }
        }
    }

    Ok(IndirectTruncateResult {
        freed_runs,
        new_i_block,
        surviving_metadata_blocks,
        surviving_indirect_patches,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Deep-tree (depth > 0) extent-truncate walker
// ─────────────────────────────────────────────────────────────────────────────

/// Result of walking one extent tree node during truncation.
struct ExtentNodeResult {
    /// Freed data and metadata runs collected from this node and its children.
    freed_runs: alloc::vec::Vec<AllocationRun>,
    /// Number of surviving physical metadata blocks (leaf or index blocks that
    /// still carry live extents after truncation).
    surviving_metadata_blocks: u64,
    /// Number of surviving file-data blocks still referenced by this subtree.
    surviving_data_blocks: u64,
    /// `Some(content)` when the node survives with at least one live entry.
    /// The content has freed entries zeroed and `eh_entries` reduced.
    /// `None` when all entries were freed — the caller may free the block.
    survivor: Option<alloc::boxed::Box<[u8]>>,
    /// Patches for surviving child nodes that were rewritten. Each entry is
    /// `(physical_block, new_content)`. Callers publish via
    /// `mutator.patch_extent_block`.
    surviving_extent_patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)>,
}

/// Parameters threaded through the recursive extent-tree walker.
struct ExtentWalkParams {
    inode_num: u32,
    inode_generation: u32,
    checksum_seed: Option<u32>,
    retain_cutoff_blocks: u64,
    blocks_per_cluster: u64,
    blocks_count: u64,
    block_size: u64,
}

/// Walk one extent-tree node at `node_depth` (from the *node's own* header)
/// and collect freed runs + surviving content.
///
/// - `node_bytes`: the raw node content (12-byte header + 12-byte entries).
/// - `this_block`: `None` for the in-inode root; `Some(phys)` for an on-disk node
///   (used to decide whether to emit it as a freed Metadata run).
/// - `retain_cutoff_blocks`: first logical block that must be freed.
///
/// # Recursion
/// - For index nodes (depth > 0): iterate children, recurse into straddlers,
///   collect everything-past-cutoff into freed runs, keep everything-before as-is.
/// - For leaf nodes (depth == 0): iterate extents, split straddlers, collect freed
///   data runs.
///
/// MVP note: depth-2 trees are handled when every index child's subtree is either
/// entirely before or entirely past the cutoff.  For a depth-2 tree whose index
/// node straddles the cutoff, the function recurses correctly: it enters the
/// straddling child (which is a depth-1 node) and handles it the same way.
/// Full depth-N support is thus automatic — the recursion bottoms out at depth 0.
fn walk_extent_node<T: Read + Seek>(
    p: &ExtentWalkParams,
    overlay: &mut T,
    node_bytes: &[u8],
    this_block: Option<u64>,
) -> MutatorResult<ExtentNodeResult> {
    let hdr = parse_header(node_bytes, p.inode_num).map_err(MutatorError::Ext)?;
    let depth = hdr.eh_depth.get();
    let entries = usize::from(hdr.eh_entries.get());

    let entry_data = &node_bytes[12..];

    if depth == 0 {
        walk_extent_leaf(p, entry_data, entries, node_bytes, this_block)
    } else {
        walk_extent_index(
            p, overlay, entry_data, entries, node_bytes, this_block, depth,
        )
    }
}

/// Handle a leaf node: walk extents and partition into survivors / freed runs.
fn walk_extent_leaf(
    p: &ExtentWalkParams,
    entry_data: &[u8],
    entries: usize,
    node_bytes: &[u8],
    this_block: Option<u64>,
) -> MutatorResult<ExtentNodeResult> {
    let mut surviving: alloc::vec::Vec<(u32, u16, u64)> = alloc::vec::Vec::new();
    let mut freed_runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();
    let mut surviving_data_blocks: u64 = 0;

    for i in 0..entries {
        let off = i * 12;
        if off + 12 > entry_data.len() {
            break;
        }
        let Some(raw) = RawExtent::ref_from_bytes(&entry_data[off..off + 12]).ok() else {
            break;
        };
        let ee_block = raw.ee_block.get();
        let ee_len_raw = raw.ee_len.get();
        let uninitialized = ee_len_raw > 32768;
        let ee_len = if uninitialized {
            ee_len_raw - 32768
        } else {
            ee_len_raw
        };
        let ee_start = (u64::from(raw.ee_start_hi.get()) << 32) | u64::from(raw.ee_start_lo.get());

        let lc_first = u64::from(ee_block) / p.blocks_per_cluster;
        let lc_last = (u64::from(ee_block) + u64::from(ee_len) - 1) / p.blocks_per_cluster;

        if lc_last < p.retain_cutoff_blocks / p.blocks_per_cluster {
            // Entire extent before cutoff — keep.
            surviving.push((ee_block, ee_len_raw, ee_start));
            surviving_data_blocks = surviving_data_blocks.saturating_add(u64::from(ee_len));
        } else if lc_first >= p.retain_cutoff_blocks / p.blocks_per_cluster {
            // Entire extent at or past cutoff — free.
            freed_runs.push(AllocationRun {
                physical_start: ee_start,
                block_len: u32::from(ee_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: lc_first,
                },
            });
        } else {
            // Straddles — split.
            let cutoff_block = p.retain_cutoff_blocks;
            let survive_len = (cutoff_block - u64::from(ee_block)) as u16;
            let survive_len_enc = if uninitialized {
                survive_len + 32768
            } else {
                survive_len
            };
            surviving.push((ee_block, survive_len_enc, ee_start));
            surviving_data_blocks = surviving_data_blocks.saturating_add(u64::from(survive_len));

            let suffix_start = ee_start + u64::from(survive_len);
            let suffix_len = ee_len - survive_len;
            freed_runs.push(AllocationRun {
                physical_start: suffix_start,
                block_len: u32::from(suffix_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: p.retain_cutoff_blocks / p.blocks_per_cluster,
                },
            });
        }
    }

    let any_kept = !surviving.is_empty();

    if !any_kept {
        // Leaf is empty after truncation. Free the leaf block itself as Metadata.
        let mut runs = freed_runs;
        if let Some(phys) = this_block {
            runs.push(AllocationRun {
                physical_start: phys,
                block_len: 1,
                kind: AllocationKind::Metadata,
            });
        }
        return Ok(ExtentNodeResult {
            freed_runs: runs,
            surviving_metadata_blocks: 0,
            surviving_data_blocks: 0,
            survivor: None,
            surviving_extent_patches: alloc::vec::Vec::new(),
        });
    }

    // Build rewritten leaf node content.
    let mut new_content = node_bytes.to_vec();
    // Update eh_entries.
    new_content[2..4].copy_from_slice(&(surviving.len() as u16).to_le_bytes());
    // Zero all entry slots then write survivors.
    let max_entries = usize::from(u16::from_le_bytes([node_bytes[4], node_bytes[5]]));
    for slot in 0..max_entries {
        let off = 12 + slot * 12;
        if off + 12 <= new_content.len() {
            new_content[off..off + 12].fill(0);
        }
    }
    for (idx, (ee_block, ee_len_enc, ee_start)) in surviving.iter().enumerate() {
        let off = 12 + idx * 12;
        new_content[off..off + 4].copy_from_slice(&ee_block.to_le_bytes());
        new_content[off + 4..off + 6].copy_from_slice(&ee_len_enc.to_le_bytes());
        new_content[off + 6..off + 8].copy_from_slice(&((*ee_start >> 32) as u16).to_le_bytes());
        new_content[off + 8..off + 12].copy_from_slice(&(*ee_start as u32).to_le_bytes());
    }

    // Surviving metadata blocks: 1 for this leaf block itself (it stays allocated).
    let surviving_metadata_blocks = this_block.map_or(0, |_| 1);

    Ok(ExtentNodeResult {
        freed_runs,
        surviving_metadata_blocks,
        surviving_data_blocks,
        survivor: Some(new_content.into_boxed_slice()),
        surviving_extent_patches: alloc::vec::Vec::new(),
    })
}

/// Handle an index node: walk index entries, recurse into children.
fn walk_extent_index<T: Read + Seek>(
    p: &ExtentWalkParams,
    overlay: &mut T,
    entry_data: &[u8],
    entries: usize,
    node_bytes: &[u8],
    this_block: Option<u64>,
    _node_depth: u16,
) -> MutatorResult<ExtentNodeResult> {
    let mut freed_runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();
    let mut patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)> = alloc::vec::Vec::new();
    let mut surviving_meta: u64 = 0;
    let mut surviving_data: u64 = 0;
    // Surviving index entries (ei_block, child_phys) to write into updated node.
    let mut surviving_idx: alloc::vec::Vec<(u32, u64)> = alloc::vec::Vec::new();

    for i in 0..entries {
        let off = i * 12;
        if off + 12 > entry_data.len() {
            break;
        }
        let Some(idx) = RawExtentIndex::ref_from_bytes(&entry_data[off..off + 12]).ok() else {
            break;
        };
        let ei_block = idx.ei_block.get();
        let child_phys = index_child_block(idx);

        if child_phys >= p.blocks_count {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: child_phys,
            }));
        }

        // Determine the logical-block range covered by this child entry.
        // The child covers [ei_block, next_ei_block) or [ei_block, ∞) for the last entry.
        let next_ei_block = if i + 1 < entries {
            let next_off = (i + 1) * 12;
            if next_off + 12 <= entry_data.len() {
                RawExtentIndex::ref_from_bytes(&entry_data[next_off..next_off + 12])
                    .ok()
                    .map(|nx| u64::from(nx.ei_block.get()))
            } else {
                None
            }
        } else {
            None
        };
        // The child's logical range starts at `ei_block`.
        // The last block covered is `next_ei_block - 1`, or u64::MAX for the last entry.
        let lblock_start = u64::from(ei_block);
        let lblock_last = next_ei_block.map_or(u64::MAX, |n| n.saturating_sub(1));

        let entirely_before = lblock_last != u64::MAX && lblock_last < p.retain_cutoff_blocks;
        let entirely_past = lblock_start >= p.retain_cutoff_blocks;

        if entirely_before {
            // Keep this child entirely, but still walk it so external extent
            // block checksums and malformed child headers cannot be skipped.
            let child_bytes = read_extent_block_checked(p, overlay, child_phys)?;
            let child_result = walk_extent_node(p, overlay, &child_bytes, Some(child_phys))?;
            if child_result.survivor.is_none() || !child_result.freed_runs.is_empty() {
                return Err(MutatorError::Ext(ExtError::InvalidExtentHeader {
                    inode: p.inode_num,
                }));
            }
            surviving_idx.push((ei_block, child_phys));
            surviving_meta = surviving_meta.saturating_add(child_result.surviving_metadata_blocks);
            surviving_data = surviving_data.saturating_add(child_result.surviving_data_blocks);
        } else if entirely_past {
            // Free this child's entire subtree + the child block itself.
            let child_bytes = read_extent_block_checked(p, overlay, child_phys)?;
            let child_result = walk_extent_node(p, overlay, &child_bytes, Some(child_phys))?;
            freed_runs.extend(child_result.freed_runs);
            // child_result.freed_runs already includes the child_phys Metadata run
            // when the leaf is empty (or sub-nodes collapse). But for an entirely-past
            // index block, we need to ensure the child phys is freed.
            // The recursive call with `this_block = Some(child_phys)` ensures that:
            // - If the child is a leaf with no survivors → it emits a Metadata run for itself.
            // - If the child is an index node with all children past cutoff → same.
            // However our recursive call returns survivor=None in that case, and the
            // Metadata run for the actual block `child_phys` is emitted inside.
            // We do NOT add `child_phys` again here to avoid double-freeing.
        } else {
            // Child straddles the cutoff — recurse.
            let child_bytes = read_extent_block_checked(p, overlay, child_phys)?;
            let child_result = walk_extent_node(p, overlay, &child_bytes, Some(child_phys))?;
            freed_runs.extend(child_result.freed_runs);
            patches.extend(child_result.surviving_extent_patches);
            if let Some(new_child_content) = child_result.survivor {
                // Child survived — keep entry, count metadata, publish patch.
                surviving_idx.push((ei_block, child_phys));
                surviving_meta =
                    surviving_meta.saturating_add(child_result.surviving_metadata_blocks);
                surviving_data = surviving_data.saturating_add(child_result.surviving_data_blocks);
                patches.push((child_phys, new_child_content));
            } else {
                // Child fully collapsed — nothing to keep.
            }
        }
    }

    let any_kept = !surviving_idx.is_empty();

    if !any_kept {
        // All children freed. Free this index node itself if on-disk.
        if let Some(phys) = this_block {
            freed_runs.push(AllocationRun {
                physical_start: phys,
                block_len: 1,
                kind: AllocationKind::Metadata,
            });
        }
        return Ok(ExtentNodeResult {
            freed_runs,
            surviving_metadata_blocks: 0,
            surviving_data_blocks: 0,
            survivor: None,
            surviving_extent_patches: patches,
        });
    }

    // Build rewritten index node content.
    let mut new_content = node_bytes.to_vec();
    new_content[2..4].copy_from_slice(&(surviving_idx.len() as u16).to_le_bytes());
    let max_entries = usize::from(u16::from_le_bytes([node_bytes[4], node_bytes[5]]));
    for slot in 0..max_entries {
        let off = 12 + slot * 12;
        if off + 12 <= new_content.len() {
            new_content[off..off + 12].fill(0);
        }
    }
    for (idx_pos, (ei_block, child_phys)) in surviving_idx.iter().enumerate() {
        let off = 12 + idx_pos * 12;
        new_content[off..off + 4].copy_from_slice(&ei_block.to_le_bytes());
        new_content[off + 4..off + 8].copy_from_slice(&(*child_phys as u32).to_le_bytes());
        // ei_leaf_hi = (child_phys >> 32) as u16 at off+8..off+10
        new_content[off + 8..off + 10].copy_from_slice(&((*child_phys >> 32) as u16).to_le_bytes());
        // padding at off+10..off+12 stays 0
    }

    // This index block itself counts as surviving metadata (if it's an on-disk block).
    let this_meta = this_block.map_or(0, |_| 1);

    Ok(ExtentNodeResult {
        freed_runs,
        surviving_metadata_blocks: surviving_meta + this_meta,
        surviving_data_blocks: surviving_data,
        survivor: Some(new_content.into_boxed_slice()),
        surviving_extent_patches: patches,
    })
}

/// Read and validate an external extent-tree block from the overlay.
fn read_extent_block_checked<T: Read + Seek>(
    p: &ExtentWalkParams,
    overlay: &mut T,
    phys: u64,
) -> MutatorResult<alloc::vec::Vec<u8>> {
    if phys >= p.blocks_count {
        return Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: phys }));
    }
    let mut buf = alloc::vec![0u8; p.block_size as usize];
    let byte_offset = phys
        .checked_mul(p.block_size)
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: phys }))?;
    overlay
        .seek(SeekFrom::Start(byte_offset))
        .map_err(ExtError::Io)?;
    overlay.read_exact(&mut buf).map_err(ExtError::Io)?;
    if let Some(seed) = p.checksum_seed {
        let state =
            crate::checksum::verify_extent_block(seed, p.inode_num, p.inode_generation, &buf);
        if state != crate::checksum::ChecksumState::Valid {
            return Err(MutatorError::Ext(ExtError::InvalidExtentHeader {
                inode: p.inode_num,
            }));
        }
    }
    Ok(buf)
}

/// Caller-supplied context for `complete_truncate_deep_extent`.
struct DeepExtentParams<'a> {
    inode_num: u32,
    inode_generation: u32,
    i_block_raw: &'a [u8; 60],
    retain_cutoff_blocks: u64,
    blocks_per_cluster: u64,
    block_size: u64,
}

/// Handle `complete_truncate` for EXTENTS_FL inodes with depth > 0 extent trees.
///
/// Walks the tree recursively:
/// - Frees data blocks for extents entirely past `retain_cutoff_blocks`.
/// - Frees leaf/index metadata blocks when all their entries are freed.
/// - Rewrites surviving leaf blocks via `mutator.patch_extent_block`.
/// - Rewrites the in-inode root to reflect the reduced entry set.
///
/// If all entries are freed, the root is rewritten to an empty depth-0 header
/// (matching Linux's post-truncate behaviour).
fn complete_truncate_deep_extent<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    mutator: &mut Mutator<'_>,
    dp: DeepExtentParams<'_>,
) -> MutatorResult<()> {
    let inode_num = dp.inode_num;
    let inode_generation = dp.inode_generation;
    let block_size = dp.block_size;
    let p = ExtentWalkParams {
        inode_num,
        inode_generation,
        checksum_seed: ext.checksum_seed(),
        retain_cutoff_blocks: dp.retain_cutoff_blocks,
        blocks_per_cluster: dp.blocks_per_cluster,
        blocks_count: ext.blocks_count,
        block_size,
    };

    // Walk the in-inode root (this_block = None because the root is inline).
    let root_result = walk_extent_node(&p, overlay, dp.i_block_raw, None)?;

    // Free all collected data + metadata runs.
    mutator.free_allocations(overlay, inode_num, &root_result.freed_runs)?;

    // Publish surviving child blocks with rewritten content.
    for (phys, new_content) in root_result.surviving_extent_patches {
        mutator.patch_extent_block(overlay, phys, inode_num, inode_generation, |buf| {
            buf.copy_from_slice(&new_content);
            Ok(())
        })?;
    }

    mutator.patch_inode_scratch(overlay, inode_num, |inode_bytes| {
        let inline = &mut inode_bytes[0x28..0x28 + 60];

        match root_result.survivor {
            None => {
                // All entries freed — write an empty depth-0 header.
                inline.fill(0);
                inline[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
                // eh_entries=0, eh_max=4, eh_depth=0, eh_generation=0.
                inline[4..6].copy_from_slice(&4u16.to_le_bytes());
                write_i_blocks_field(inode_bytes, 0, block_size);
            }
            Some(new_root) => {
                // Partial survival — write the updated root content.
                let copy_len = new_root.len().min(60);
                inline[..copy_len].copy_from_slice(&new_root[..copy_len]);

                let surviving_blocks = root_result
                    .surviving_data_blocks
                    .saturating_add(root_result.surviving_metadata_blocks);
                write_i_blocks_field(inode_bytes, surviving_blocks, block_size);
            }
        }

        Ok(())
    })?;

    Ok(())
}

/// Count non-zero direct block pointers in the first 48 bytes of `i_block`.
fn count_surviving_direct_blocks(i_block: &[u8; 60]) -> u64 {
    (0..12u64)
        .filter(|&slot| {
            let off = (slot * 4) as usize;
            u32::from_le_bytes(i_block[off..off + 4].try_into().unwrap()) != 0
        })
        .count() as u64
}

/// Rewrite `i_blocks` and (for the indirect path) `i_block` after truncation.
///
/// `surviving_blocks` counts filesystem-sized blocks that remain allocated
/// (direct data blocks + surviving indirect-metadata blocks).
/// `huge_file` comes from `HUGE_FILE_FL` in `i_flags`.
fn write_i_blocks_field(inode_bytes: &mut [u8], surviving_blocks: u64, block_size: u64) {
    let i_flags_raw = u32::from_le_bytes(inode_bytes[0x20..0x24].try_into().unwrap());
    let huge_file = i_flags_raw & 0x0004_0000 != 0;

    let new_i_blocks = if huge_file {
        surviving_blocks
    } else {
        surviving_blocks.saturating_mul(block_size / 512)
    };

    // Write i_blocks_lo at offset 0x1C (32-bit).
    inode_bytes[0x1C..0x20].copy_from_slice(&(new_i_blocks as u32).to_le_bytes());
    // Write i_blocks_hi at osd2.linux2.l_i_blocks_high, offset 0x74 (16-bit).
    inode_bytes[0x74..0x76].copy_from_slice(&((new_i_blocks >> 32) as u16).to_le_bytes());
}

/// Handle `complete_truncate` for pre-EXTENTS_FL (indirect-block-map) inodes.
fn complete_truncate_indirect<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    mutator: &mut Mutator<'_>,
    inode_num: u32,
    i_block_raw: &[u8; 60],
    retain_cutoff_blocks: u64,
    block_size: u64,
) -> MutatorResult<()> {
    let result = walk_indirect_map(ext, overlay, inode_num, i_block_raw, retain_cutoff_blocks)
        .map_err(MutatorError::Ext)?;

    mutator.free_allocations(overlay, inode_num, &result.freed_runs)?;

    // Publish surviving indirect blocks with freed child pointers zeroed.
    // Must happen before i_blocks recomputation so the final delta is coherent.
    for (phys_block, new_content) in result.surviving_indirect_patches {
        mutator.patch_indirect_block(overlay, phys_block, |buf| {
            buf.copy_from_slice(&new_content);
            Ok(())
        })?;
    }

    let new_i_block = result.new_i_block;

    // Count surviving blocks for i_blocks recomputation:
    // surviving direct data blocks + all surviving indirect-metadata blocks
    // (the walker threads the accurate count bottom-up through the tree).
    let surviving_direct = count_surviving_direct_blocks(&new_i_block);
    let surviving_blocks = surviving_direct + result.surviving_metadata_blocks;

    mutator.patch_inode_scratch(overlay, inode_num, |inode_bytes| {
        write_i_blocks_field(inode_bytes, surviving_blocks, block_size);

        // Write new i_block at inode offset 0x28.
        inode_bytes[0x28..0x28 + 60].copy_from_slice(&new_i_block);

        Ok(())
    })?;

    Ok(())
}

/// Complete a pending truncate on `inode_num` by freeing every data
/// allocation at or past `retain_cutoff`, shrinking the extent tree or
/// indirect-block map accordingly, and recomputing `i_blocks`.
///
/// Supports:
/// - EXTENTS_FL inodes with a depth-0 (in-inode root) extent tree.
/// - EXTENTS_FL inodes with depth > 0 external extent-tree blocks.
/// - Pre-EXTENTS_FL inodes using the classical ext2/3 indirect-block-map
///   (`i_block[0..60]`): 12 direct + single + double + triple indirect.
///
/// Bigalloc overlap detection fires inside `mutator.free_allocations` and
/// surfaces as `Err(MutatorError::BigallocClusterOverlap { .. })`. The
/// caller (replay.rs) routes this into `OrphanStopReason::BigallocClusterOverlap`
/// with an empty delta, matching the unlink/EA/xattr soft-stop paths.
pub(crate) fn complete_truncate<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    mutator: &mut Mutator<'_>,
    inode_num: u32,
    target_size: u64,
) -> MutatorResult<()> {
    let cluster_size = u64::from(ext.cluster_size);
    let blocks_per_cluster = u64::from(ext.blocks_per_cluster);
    let block_size = u64::from(ext.block_size());
    let retain_cutoff = retain_cutoff_logical_cluster(target_size, cluster_size);
    let retain_cutoff_blocks =
        retain_cutoff
            .checked_mul(blocks_per_cluster)
            .ok_or(MutatorError::Ext(ExtError::InvalidExtentHeader {
                inode: inode_num,
            }))?;

    let inode = ext.inode(overlay, inode_num).map_err(MutatorError::Ext)?;

    if !inode.flags().contains(InodeFlags::EXTENTS_FL) {
        let i_block = inode.i_block();
        return complete_truncate_indirect(
            ext,
            overlay,
            mutator,
            inode_num,
            &i_block,
            retain_cutoff_blocks,
            block_size,
        );
    }

    let i_block = inode.i_block();
    let header = RawExtentHeader::ref_from_bytes(&i_block[..12])
        .map_err(|_| MutatorError::Ext(ExtError::InvalidExtentHeader { inode: inode_num }))?;

    if header.eh_magic.get() != EXTENT_MAGIC {
        return Err(MutatorError::Ext(ExtError::InvalidExtentHeader {
            inode: inode_num,
        }));
    }
    if header.eh_depth.get() != 0 {
        // Deep-tree path: recursive walker handles depth > 0.
        let dp = DeepExtentParams {
            inode_num,
            inode_generation: inode.generation(),
            i_block_raw: &i_block,
            retain_cutoff_blocks,
            blocks_per_cluster,
            block_size,
        };
        return complete_truncate_deep_extent(ext, overlay, mutator, dp);
    }

    let entries = header.eh_entries.get();

    // Walk leaf extents in i_block[12..60], partitioning into survivors and runs to free.
    let mut surviving: alloc::vec::Vec<(u32, u16, u64)> = alloc::vec::Vec::new();
    let mut runs: alloc::vec::Vec<AllocationRun> = alloc::vec::Vec::new();

    for i in 0..(entries as usize) {
        let off = 12 + i * 12;
        if off + 12 > i_block.len() {
            break;
        }
        let Some(raw) = RawExtent::ref_from_bytes(&i_block[off..off + 12]).ok() else {
            break;
        };

        let ee_block = raw.ee_block.get();
        let ee_len_raw = raw.ee_len.get();
        // Uninitialized extents have ee_len > 32768; same block allocation.
        let uninitialized = ee_len_raw > 32768;
        let ee_len = if uninitialized {
            ee_len_raw - 32768
        } else {
            ee_len_raw
        };
        let ee_start = (u64::from(raw.ee_start_hi.get()) << 32) | u64::from(raw.ee_start_lo.get());

        let lc_first = u64::from(ee_block) / blocks_per_cluster;
        let lc_last = (u64::from(ee_block) + u64::from(ee_len) - 1) / blocks_per_cluster;

        if lc_last < retain_cutoff {
            // Whole extent before cutoff — keep as-is.
            surviving.push((ee_block, ee_len_raw, ee_start));
        } else if lc_first >= retain_cutoff {
            // Whole extent at or past cutoff — free.
            runs.push(AllocationRun {
                physical_start: ee_start,
                block_len: u32::from(ee_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: lc_first,
                },
            });
        } else {
            // Straddles the cutoff boundary — split.
            let split_block = retain_cutoff_blocks;
            let survive_len = (split_block - u64::from(ee_block)) as u16;
            // Preserve the uninitialized high-bit on the surviving prefix.
            let survive_len_encoded = if uninitialized {
                survive_len + 32768
            } else {
                survive_len
            };
            surviving.push((ee_block, survive_len_encoded, ee_start));

            let suffix_start = ee_start + u64::from(survive_len);
            let suffix_len = ee_len - survive_len;
            runs.push(AllocationRun {
                physical_start: suffix_start,
                block_len: u32::from(suffix_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: retain_cutoff,
                },
            });
        }
    }

    mutator.free_allocations(overlay, inode_num, &runs)?;

    // Count surviving blocks for i_blocks recomputation.
    let surviving_blocks: u64 = surviving
        .iter()
        .map(|(_, len_encoded, _)| {
            let true_len = if *len_encoded > 32768 {
                *len_encoded - 32768
            } else {
                *len_encoded
            };
            u64::from(true_len)
        })
        .sum();

    mutator.patch_inode_scratch(overlay, inode_num, |inode_bytes| {
        write_i_blocks_field(inode_bytes, surviving_blocks, block_size);

        // Rewrite extent header + leaf entries inline at i_block (offset 0x28..0x28+60).
        let inline = &mut inode_bytes[0x28..0x28 + 60];

        // Header fields.
        inline[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        inline[2..4].copy_from_slice(&(surviving.len() as u16).to_le_bytes());
        inline[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max = 4 for depth-0 inline
        inline[6..8].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0
        inline[8..12].copy_from_slice(&0u32.to_le_bytes()); // eh_generation

        // Zero all 4 extent slots before writing surviving entries.
        for slot in 0..4 {
            let off = 12 + slot * 12;
            inline[off..off + 12].fill(0);
        }

        // Write surviving entries.
        for (idx, (ee_block, ee_len_encoded, ee_start)) in surviving.iter().enumerate() {
            let off = 12 + idx * 12;
            inline[off..off + 4].copy_from_slice(&ee_block.to_le_bytes());
            inline[off + 4..off + 6].copy_from_slice(&ee_len_encoded.to_le_bytes());
            inline[off + 6..off + 8].copy_from_slice(&((*ee_start >> 32) as u16).to_le_bytes());
            inline[off + 8..off + 12].copy_from_slice(&(*ee_start as u32).to_le_bytes());
        }

        Ok(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn retain_cutoff_zero_size_retains_nothing() {
        assert_eq!(retain_cutoff_logical_cluster(0, 4096), 0);
    }

    #[test]
    fn retain_cutoff_one_byte_retains_one_cluster() {
        assert_eq!(retain_cutoff_logical_cluster(1, 4096), 1);
    }

    #[test]
    fn retain_cutoff_exactly_one_cluster_size_retains_one_cluster() {
        assert_eq!(retain_cutoff_logical_cluster(4096, 4096), 1);
    }

    #[test]
    fn retain_cutoff_one_byte_past_cluster_retains_two() {
        assert_eq!(retain_cutoff_logical_cluster(4097, 4096), 2);
    }

    #[test]
    fn retain_cutoff_bigalloc_16k_cluster() {
        assert_eq!(retain_cutoff_logical_cluster(1, 16384), 1);
        assert_eq!(retain_cutoff_logical_cluster(16384, 16384), 1);
        assert_eq!(retain_cutoff_logical_cluster(16385, 16384), 2);
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn load_dirty_fixture(name: &str) -> Option<(Ext, std::io::Cursor<alloc::vec::Vec<u8>>)> {
        let bytes = std::fs::read(fixture_path(name)).ok()?;
        let cursor = std::io::Cursor::new(bytes);
        // We need two cursors: one for open_lenient, one for subsequent ops.
        // Reload so we can pass the same cursor to open_lenient and then use it.
        let bytes2 = std::fs::read(fixture_path(name)).ok()?;
        let mut cursor2 = std::io::Cursor::new(bytes2);
        let ext = Ext::open_lenient(&mut cursor2).expect("open_lenient dirty fixture");
        // Rewind so callers start from the beginning.
        cursor2.set_position(0);
        let _ = cursor; // drop the first cursor
        Some((ext, cursor2))
    }

    fn read_sb_block(
        ext: &Ext,
        cursor: &mut std::io::Cursor<alloc::vec::Vec<u8>>,
    ) -> alloc::vec::Vec<u8> {
        use crate::io::SeekFrom;
        let sb_block: u64 = if ext.block_size() > 1024 { 0 } else { 1 };
        let mut sb_bytes = alloc::vec![0u8; ext.block_size() as usize];
        cursor
            .seek(SeekFrom::Start(sb_block * u64::from(ext.block_size())))
            .expect("seek sb");
        cursor.read_exact(&mut sb_bytes).expect("read sb host");
        sb_bytes
    }

    #[test]
    fn complete_truncate_to_zero_frees_every_data_block() {
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-truncate-unlink.img")
        else {
            eprintln!("skipping: fixture not available");
            return;
        };

        let target_inum = ext.last_orphan(&mut cursor).expect("read s_last_orphan");
        assert_ne!(target_inum, 0, "fixture must have a chain head");

        let sb_bytes = read_sb_block(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);

        complete_truncate(&ext, &mut cursor, &mut mutator, target_inum, 0).expect("truncate to 0");

        // At least one block bitmap was dirtied (blocks were freed).
        assert!(
            mutator.block_bitmap_scratch_count() > 0,
            "truncate-to-zero must dirty at least one block bitmap"
        );
    }

    #[test]
    fn complete_truncate_to_zero_rewrites_extent_header_with_zero_entries() {
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-truncate-unlink.img")
        else {
            eprintln!("skipping: fixture not available");
            return;
        };

        let target_inum = ext.last_orphan(&mut cursor).expect("read s_last_orphan");
        assert_ne!(target_inum, 0, "fixture must have a chain head");

        let sb_bytes = read_sb_block(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);

        complete_truncate(&ext, &mut cursor, &mut mutator, target_inum, 0).expect("truncate to 0");

        // Read back the inode table scratch to verify extent header entries = 0.
        // The inode table scratch should have been seeded and mutated.
        // We can verify this via patch_inode_scratch's side effect — the inode's
        // block table block must be in the scratch set.
        // Use a second patch_inode_scratch call to read back the written header.
        let mut observed_entries = 0u16;
        let mut observed_i_blocks = u32::MAX;
        mutator
            .patch_inode_scratch(&mut cursor, target_inum, |inode_bytes| {
                // eh_entries is at offset 0x28 + 2 within inode bytes.
                observed_entries =
                    u16::from_le_bytes(inode_bytes[0x28 + 2..0x28 + 4].try_into().unwrap());
                observed_i_blocks = u32::from_le_bytes(inode_bytes[0x1C..0x20].try_into().unwrap());
                Ok(())
            })
            .expect("read back inode scratch");

        assert_eq!(
            observed_entries, 0,
            "truncated inode must have 0 extent entries"
        );
        assert_eq!(
            observed_i_blocks, 0,
            "truncated inode must have i_blocks = 0"
        );
    }

    // -------------------------------------------------------------------------
    // Synthetic indirect-block-map tests
    // -------------------------------------------------------------------------

    /// Build a synthetic overlay `Cursor<Vec<u8>>` large enough to hold all the
    /// blocks referenced in `pointer_map`. Each entry is `(block_num, pointers)`;
    /// `pointers` are written as LE u32s at the start of `block_num * block_size`.
    ///
    /// `total_blocks` sets the size of the backing buffer in filesystem blocks.
    fn build_synthetic_overlay(
        total_blocks: u64,
        block_size: u64,
        pointer_map: &[(u64, &[u32])],
    ) -> Cursor<alloc::vec::Vec<u8>> {
        let size = (total_blocks * block_size) as usize;
        let mut buf = alloc::vec![0u8; size];
        for &(block_num, ptrs) in pointer_map {
            let base = (block_num * block_size) as usize;
            for (i, &p) in ptrs.iter().enumerate() {
                let off = base + i * 4;
                buf[off..off + 4].copy_from_slice(&p.to_le_bytes());
            }
        }
        Cursor::new(buf)
    }

    /// Build a synthetic `Ext` with `blocks_count` set high enough for our tests.
    fn ext_for_indirect_tests(blocks_count: u64) -> &'static Ext {
        use crate::checksum::ChecksumState;
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use alloc::boxed::Box;

        let ext = Box::new(Ext {
            inodes_count: 0,
            blocks_count,
            block_size: 4096,
            group_count: 0,
            inodes_per_group: 1,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                4096,
                0,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                0,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 0,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 0,
            backup_bgs: [0, 0],
            desc_size: 0,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::empty(),
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }

    // --- Test 1: direct pointers only, all past cutoff, free all ---

    #[test]
    fn indirect_truncate_direct_only_past_cutoff_frees_all() {
        // ppb = 4096 / 4 = 1024
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        // Set up 3 direct block pointers in slots 0, 1, 2 at physical blocks
        // 500, 501, 502.
        let mut i_block = [0u8; 60];
        i_block[0..4].copy_from_slice(&500u32.to_le_bytes());
        i_block[4..8].copy_from_slice(&501u32.to_le_bytes());
        i_block[8..12].copy_from_slice(&502u32.to_le_bytes());

        // Cutoff = 0 → free everything.
        let total_blocks = 600u64;
        let mut overlay = build_synthetic_overlay(total_blocks, block_size, &[]);

        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 0).expect("walk");

        // All 3 direct blocks should be freed as Data runs.
        assert_eq!(result.freed_runs.len(), 3, "expected 3 freed runs");
        let phys: alloc::vec::Vec<u64> =
            result.freed_runs.iter().map(|r| r.physical_start).collect();
        assert!(phys.contains(&500));
        assert!(phys.contains(&501));
        assert!(phys.contains(&502));

        // new_i_block should have zeros in the first 12 bytes.
        assert_eq!(&result.new_i_block[0..12], &[0u8; 12]);
        // Indirect slots still zero.
        assert_eq!(&result.new_i_block[48..60], &[0u8; 12]);
    }

    // --- Test 2: direct pointers, partial cutoff ---

    #[test]
    fn indirect_truncate_direct_only_mid_cutoff_partial_free() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        // 12 direct pointers at physical blocks 1000..1012.
        let mut i_block = [0u8; 60];
        for slot in 0..12usize {
            let phys = (1000 + slot) as u32;
            i_block[slot * 4..slot * 4 + 4].copy_from_slice(&phys.to_le_bytes());
        }

        // Cutoff = 6 → logical blocks 0..5 kept, 6..11 freed.
        let mut overlay = build_synthetic_overlay(2000, block_size, &[]);
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 6).expect("walk");

        // 6 blocks freed (lblock 6..11).
        assert_eq!(result.freed_runs.len(), 6);

        // Slots 0..5 intact, slots 6..11 zeroed.
        for slot in 0..6usize {
            let phys = u32::from_le_bytes(
                result.new_i_block[slot * 4..slot * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(phys, (1000 + slot) as u32, "slot {slot} should survive");
        }
        for slot in 6..12usize {
            let phys = u32::from_le_bytes(
                result.new_i_block[slot * 4..slot * 4 + 4]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(phys, 0, "slot {slot} should be zeroed");
        }
    }

    // --- Test 3: single indirect, full free, collapses indirect block ---

    #[test]
    fn indirect_truncate_single_indirect_full_free_and_collapses_indirect_block() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4; // 1024

        // Single-indirect block at physical block 2000.
        // It contains 3 data pointers at physical blocks 3000, 3001, 3002.
        let mut i_block = [0u8; 60];
        i_block[48..52].copy_from_slice(&2000u32.to_le_bytes());

        let mut ptrs_buf = alloc::vec![0u32; ppb as usize];
        ptrs_buf[0] = 3000;
        ptrs_buf[1] = 3001;
        ptrs_buf[2] = 3002;
        let ptrs_u32: alloc::vec::Vec<u32> = ptrs_buf.clone();

        // Build overlay: place the indirect block at block 2000.
        let total_blocks = 5000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];
        let base = (2000u64 * block_size) as usize;
        for (i, &p) in ptrs_u32.iter().enumerate() {
            overlay_buf[base + i * 4..base + i * 4 + 4].copy_from_slice(&p.to_le_bytes());
        }
        let mut overlay = Cursor::new(overlay_buf);

        // Cutoff = 12 → lblock 12 (first single-indirect slot) and beyond → free all.
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 12).expect("walk");

        // 3 data runs + 1 metadata run for the indirect block itself.
        assert_eq!(result.freed_runs.len(), 4, "3 data + 1 metadata = 4 runs");
        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(
            metadata_runs.len(),
            1,
            "indirect block collapsed to 1 metadata run"
        );
        assert_eq!(metadata_runs[0].physical_start, 2000);

        // Single-indirect pointer slot should be zeroed.
        assert_eq!(&result.new_i_block[48..52], &[0u8; 4]);
    }

    // --- Test 4: single indirect, partial free, keeps indirect block ---

    #[test]
    fn indirect_truncate_single_indirect_partial_free_keeps_indirect_block() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4;

        // Single-indirect block at physical block 2100.
        // Slots 0, 1 have data at 3100, 3101; rest zero.
        let mut i_block = [0u8; 60];
        i_block[48..52].copy_from_slice(&2100u32.to_le_bytes());

        let mut overlay_buf = alloc::vec![0u8; (5000u64 * block_size) as usize];
        let base = (2100u64 * block_size) as usize;
        overlay_buf[base..base + 4].copy_from_slice(&3100u32.to_le_bytes());
        overlay_buf[base + 4..base + 8].copy_from_slice(&3101u32.to_le_bytes());
        let mut overlay = Cursor::new(overlay_buf);

        // Cutoff = 13 → lblock 12 (slot 0 in single-indirect = lblock 12) kept,
        //              lblock 13 (slot 1) freed.
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 13).expect("walk");

        // 1 data run for lblock 13.
        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 1);
        assert_eq!(data_runs[0].physical_start, 3101);

        // No metadata run — indirect block survives (slot 0 still has data).
        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(metadata_runs.len(), 0, "indirect block must NOT be freed");

        // Single-indirect pointer slot should still be non-zero.
        let ptr = u32::from_le_bytes(result.new_i_block[48..52].try_into().unwrap());
        assert_eq!(ptr, 2100, "single-indirect slot must be preserved");

        let _ = ppb;
    }

    // --- Test 5: double indirect, partial free, frees some child indirect blocks ---

    #[test]
    fn indirect_truncate_double_indirect_partial_free_frees_some_indirects() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4; // 1024

        // Double-indirect at physical block 4000.
        // Slot 0 → single-indirect at 4001 (covers lblocks 12+ppb .. 12+ppb+ppb-1 = 12+1024..12+2047)
        //   Wait: double-indirect slot 0 covers [12+ppb .. 12+ppb+ppb-1].
        //   Slot 0 contains single-indirect block 4001.
        //   Slot 1 → single-indirect at 4002.
        // The single-indirect blocks each contain one data pointer.
        // 4001 slot 0 → data block 5000
        // 4002 slot 0 → data block 5001
        //
        // Cutoff = 12+ppb+ppb (= 12 + 1024 + 1024 = 2060).
        // Slot 0 of double-indirect covers [12+ppb, 12+ppb+ppb-1] = [1036, 2059] — entirely before cutoff.
        // Slot 1 of double-indirect covers [12+ppb+ppb, 12+ppb+ppb+ppb-1] = [2060, 3083] — all at/past cutoff.

        let cutoff = 12 + ppb + ppb;

        let mut i_block = [0u8; 60];
        i_block[52..56].copy_from_slice(&4000u32.to_le_bytes());

        let total_blocks = 7000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];

        // Double-indirect block 4000: slot 0 → 4001, slot 1 → 4002.
        let base_4000 = (4000u64 * block_size) as usize;
        overlay_buf[base_4000..base_4000 + 4].copy_from_slice(&4001u32.to_le_bytes());
        overlay_buf[base_4000 + 4..base_4000 + 8].copy_from_slice(&4002u32.to_le_bytes());

        // Single-indirect 4001: slot 0 → data 5000.
        let base_4001 = (4001u64 * block_size) as usize;
        overlay_buf[base_4001..base_4001 + 4].copy_from_slice(&5000u32.to_le_bytes());

        // Single-indirect 4002: slot 0 → data 5001.
        let base_4002 = (4002u64 * block_size) as usize;
        overlay_buf[base_4002..base_4002 + 4].copy_from_slice(&5001u32.to_le_bytes());

        let mut overlay = Cursor::new(overlay_buf);

        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

        // Slot 0 of double-indirect is entirely before cutoff → kept, no runs.
        // Slot 1 of double-indirect is entirely at/past cutoff → 1 data run (5001)
        //   + 1 metadata run (4002 single-indirect) + NOT the double-indirect itself
        //   because slot 0 survives.

        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 1, "only 1 data block freed");
        assert_eq!(data_runs[0].physical_start, 5001);

        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(
            metadata_runs.len(),
            1,
            "single-indirect 4002 freed as metadata"
        );
        assert_eq!(metadata_runs[0].physical_start, 4002);

        // Double-indirect pointer (bytes 52..56) preserved — slot 0 still alive.
        let ptr = u32::from_le_bytes(result.new_i_block[52..56].try_into().unwrap());
        assert_eq!(ptr, 4000, "double-indirect slot preserved");
    }

    // --- Test 6: triple indirect, full free, collapses all three levels ---

    #[test]
    fn indirect_truncate_triple_indirect_full_free_collapses_all_three_levels() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4; // 1024

        // Triple-indirect at physical block 6000.
        // first_lblock = 12 + ppb + ppb² = 12 + 1024 + 1048576 = 1049612
        // Cutoff = 1049612 → entire range freed.
        let cutoff = 12 + ppb + ppb * ppb;

        let mut i_block = [0u8; 60];
        i_block[56..60].copy_from_slice(&6000u32.to_le_bytes());

        let total_blocks = 7000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];

        // Triple-indirect 6000: slot 0 → double-indirect at 6001.
        let base_6000 = (6000u64 * block_size) as usize;
        overlay_buf[base_6000..base_6000 + 4].copy_from_slice(&6001u32.to_le_bytes());

        // Double-indirect 6001: slot 0 → single-indirect at 6002.
        let base_6001 = (6001u64 * block_size) as usize;
        overlay_buf[base_6001..base_6001 + 4].copy_from_slice(&6002u32.to_le_bytes());

        // Single-indirect 6002: slot 0 → data at 6003.
        let base_6002 = (6002u64 * block_size) as usize;
        overlay_buf[base_6002..base_6002 + 4].copy_from_slice(&6003u32.to_le_bytes());

        let mut overlay = Cursor::new(overlay_buf);

        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

        // 1 data run (6003) + 3 metadata runs (6002, 6001, 6000).
        assert_eq!(result.freed_runs.len(), 4);

        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 1);
        assert_eq!(data_runs[0].physical_start, 6003);

        let metadata_phys: alloc::collections::BTreeSet<u64> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .map(|r| r.physical_start)
            .collect();
        assert!(metadata_phys.contains(&6000));
        assert!(metadata_phys.contains(&6001));
        assert!(metadata_phys.contains(&6002));

        // Triple-indirect slot zeroed.
        assert_eq!(&result.new_i_block[56..60], &[0u8; 4]);
    }

    // --- Test 7: sparse holes preserved ---

    #[test]
    fn indirect_truncate_sparse_holes_preserved() {
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        // Slots 0 and 2 have data; slot 1 is a sparse hole (zero).
        let mut i_block = [0u8; 60];
        i_block[0..4].copy_from_slice(&700u32.to_le_bytes()); // lblock 0
        // i_block[4..8] left zero → sparse hole at lblock 1
        i_block[8..12].copy_from_slice(&701u32.to_le_bytes()); // lblock 2

        // Cutoff = 5 → all direct blocks kept (lblocks 0, 2 < 5).
        let mut overlay = build_synthetic_overlay(1000, block_size, &[]);
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 5).expect("walk");

        assert_eq!(
            result.freed_runs.len(),
            0,
            "nothing freed when all blocks before cutoff"
        );

        // Verify slot 0 and 2 preserved, slot 1 still zero.
        let p0 = u32::from_le_bytes(result.new_i_block[0..4].try_into().unwrap());
        let p1 = u32::from_le_bytes(result.new_i_block[4..8].try_into().unwrap());
        let p2 = u32::from_le_bytes(result.new_i_block[8..12].try_into().unwrap());
        assert_eq!(p0, 700);
        assert_eq!(p1, 0, "sparse hole must remain zero");
        assert_eq!(p2, 701);
    }

    // --- Test 8: malformed pointer beyond blocks_count returns error ---

    #[test]
    fn indirect_truncate_malformed_pointer_beyond_blocks_count_returns_structural_error() {
        let blocks_count = 500u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        // Direct pointer at slot 0 references block 999 which exceeds blocks_count=500.
        let mut i_block = [0u8; 60];
        i_block[0..4].copy_from_slice(&999u32.to_le_bytes());

        let mut overlay = build_synthetic_overlay(1000, block_size, &[]);

        let err = walk_indirect_map(ext, &mut overlay, 1, &i_block, 0)
            .expect_err("must fail on malformed pointer");

        match err {
            ExtError::InvalidIndirectBlock { inode, .. } => {
                assert_eq!(inode, 1);
            }
            other => panic!("expected InvalidIndirectBlock, got {other:?}"),
        }
    }

    // --- Test 9: sparse holes only → indirect block must collapse ---

    #[test]
    fn indirect_truncate_sparse_holes_only_collapses_indirect_block() {
        // Single-indirect block at physical 2200.
        // Slots: [10, 0, 11, 0, 12, <rest zero>].
        // Cutoff = 12 → lblocks 12, 13, 14 (slots 0, 1, 2 of single-indirect
        // covering lblocks 12, 13, 14) are all at/past cutoff.
        //
        // After truncation: real pointers 10/11/12 are freed.
        // The remaining slots are all zero (sparse holes).
        // The indirect block itself must be freed (collapsed).
        // any_kept must be false because zero-slots contribute nothing.
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        let mut i_block = [0u8; 60];
        i_block[48..52].copy_from_slice(&2200u32.to_le_bytes());

        let total_blocks = 5000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];
        let base = (2200u64 * block_size) as usize;
        // slots: [10, 0, 11, 0, 12, rest=0]
        overlay_buf[base..base + 4].copy_from_slice(&10u32.to_le_bytes()); // slot 0 → lblock 12
        // slot 1 stays zero (sparse hole)
        overlay_buf[base + 8..base + 12].copy_from_slice(&11u32.to_le_bytes()); // slot 2 → lblock 14
        // slot 3 stays zero
        overlay_buf[base + 16..base + 20].copy_from_slice(&12u32.to_le_bytes()); // slot 4 → lblock 16
        let mut overlay = Cursor::new(overlay_buf);

        // Cutoff = 12 → all of these lblocks are at/past cutoff → all real pointers freed.
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 12).expect("walk");

        // 3 data runs (10, 11, 12) + 1 metadata run (indirect block 2200).
        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 3, "3 real data blocks freed");

        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(
            metadata_runs.len(),
            1,
            "indirect block 2200 must be collapsed (freed), not kept alive by sparse holes"
        );
        assert_eq!(metadata_runs[0].physical_start, 2200);

        // Single-indirect slot must be zeroed.
        assert_eq!(&result.new_i_block[48..52], &[0u8; 4]);
    }

    // --- Test 10: partial double-indirect surviving_metadata_blocks ---

    #[test]
    fn indirect_truncate_partial_double_indirect_i_blocks_counts_surviving_metadata() {
        // Double-indirect at physical 4100.
        // Slot 0 → single-indirect 4101 (covers lblocks [12+ppb .. 12+ppb+ppb-1])
        //   4101 slot 0 → data 5100, slot 1 → data 5101, slot 2 → data 5102, slot 3 → data 5103
        // Slot 1 → single-indirect 4102 (covers lblocks [12+ppb+ppb .. 12+ppb+ppb+ppb-1])
        //   4102 slot 0 → data 5104, slot 1 → data 5105, slot 2 → data 5106, slot 3 → data 5107
        // Rest of double-indirect slots zero.
        //
        // Cutoff = 12 + ppb + ppb*ppb + ppb*ppb*ppb  (far beyond everything → nothing freed).
        // All 8 data blocks survive. Both single-indirect blocks survive.
        // The double-indirect block itself survives.
        // surviving_metadata_blocks = 3 (double-indirect + 2 single-indirects).
        // surviving_data_blocks = 8.
        // total = 11.
        //
        // Verify: IndirectTruncateResult.surviving_metadata_blocks == 3.
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4; // 1024

        let mut i_block = [0u8; 60];
        i_block[52..56].copy_from_slice(&4100u32.to_le_bytes());

        let total_blocks = 8000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];

        // Double-indirect 4100: slot 0 → 4101, slot 1 → 4102.
        let base_4100 = (4100u64 * block_size) as usize;
        overlay_buf[base_4100..base_4100 + 4].copy_from_slice(&4101u32.to_le_bytes());
        overlay_buf[base_4100 + 4..base_4100 + 8].copy_from_slice(&4102u32.to_le_bytes());

        // Single-indirect 4101: slots 0..3 → data 5100..5103.
        let base_4101 = (4101u64 * block_size) as usize;
        for i in 0u32..4 {
            let off = base_4101 + (i as usize) * 4;
            overlay_buf[off..off + 4].copy_from_slice(&(5100u32 + i).to_le_bytes());
        }

        // Single-indirect 4102: slots 0..3 → data 5104..5107.
        let base_4102 = (4102u64 * block_size) as usize;
        for i in 0u32..4 {
            let off = base_4102 + (i as usize) * 4;
            overlay_buf[off..off + 4].copy_from_slice(&(5104u32 + i).to_le_bytes());
        }

        let mut overlay = Cursor::new(overlay_buf);

        // Cutoff far past everything → nothing freed.
        let cutoff = 12 + ppb + ppb * ppb + ppb * ppb * ppb;
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

        // No runs freed.
        assert_eq!(result.freed_runs.len(), 0, "nothing should be freed");

        // surviving_metadata_blocks: double-indirect (4100) + 2 single-indirects (4101, 4102) = 3.
        assert_eq!(
            result.surviving_metadata_blocks, 3,
            "must count double-indirect + 2 single-indirect blocks as surviving metadata"
        );

        // Double-indirect pointer preserved.
        let ptr = u32::from_le_bytes(result.new_i_block[52..56].try_into().unwrap());
        assert_eq!(ptr, 4100, "double-indirect slot preserved");

        let _ = ppb;
    }

    // --- Test 11: partial single-indirect zeros freed child pointers ---

    #[test]
    fn indirect_truncate_partial_single_indirect_zeros_freed_child_pointers() {
        // Single-indirect block at physical 2300.
        // Slots 0, 1, 2, 3 → data blocks DATA_A=300, DATA_B=301, DATA_C=302, DATA_D=303.
        // Logical blocks 12, 13, 14, 15 respectively.
        // Cutoff = 14 → keep slots 0 and 1 (lblocks 12, 13), free slots 2 and 3 (lblocks 14, 15).
        //
        // Expected:
        // 1. DATA_C (302) and DATA_D (303) appear in freed_runs as Data.
        // 2. surviving_indirect_patches contains (2300, buf) where buf has
        //    slot 0 (300) and slot 1 (301) preserved and slots 2, 3 zeroed.
        // 3. new_i_block[48..52] still points at 2300 (indirect block survives).
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);

        let mut i_block = [0u8; 60];
        i_block[48..52].copy_from_slice(&2300u32.to_le_bytes());

        let total_blocks = 5000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];
        let base = (2300u64 * block_size) as usize;
        overlay_buf[base..base + 4].copy_from_slice(&300u32.to_le_bytes()); // slot 0 → lblock 12
        overlay_buf[base + 4..base + 8].copy_from_slice(&301u32.to_le_bytes()); // slot 1 → lblock 13
        overlay_buf[base + 8..base + 12].copy_from_slice(&302u32.to_le_bytes()); // slot 2 → lblock 14
        overlay_buf[base + 12..base + 16].copy_from_slice(&303u32.to_le_bytes()); // slot 3 → lblock 15
        let mut overlay = Cursor::new(overlay_buf);

        // Cutoff = 14 → keep lblocks 12, 13; free lblocks 14, 15.
        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 14).expect("walk");

        // DATA_C and DATA_D freed.
        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 2, "2 data blocks freed");
        let data_phys: alloc::collections::BTreeSet<u64> =
            data_runs.iter().map(|r| r.physical_start).collect();
        assert!(data_phys.contains(&302), "DATA_C must be freed");
        assert!(data_phys.contains(&303), "DATA_D must be freed");

        // No metadata run — indirect block survives.
        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(
            metadata_runs.len(),
            0,
            "indirect block 2300 must not be freed"
        );

        // Indirect block pointer preserved in new_i_block.
        let ptr = u32::from_le_bytes(result.new_i_block[48..52].try_into().unwrap());
        assert_eq!(ptr, 2300, "single-indirect pointer must be preserved");

        // The surviving indirect block patch must be present.
        assert_eq!(
            result.surviving_indirect_patches.len(),
            1,
            "one surviving indirect block patch"
        );
        let (patch_phys, patch_buf) = &result.surviving_indirect_patches[0];
        assert_eq!(*patch_phys, 2300, "patch is for block 2300");

        // Verify: slots 0 and 1 preserved, slots 2 and 3 zeroed.
        let s0 = u32::from_le_bytes(patch_buf[0..4].try_into().unwrap());
        let s1 = u32::from_le_bytes(patch_buf[4..8].try_into().unwrap());
        let s2 = u32::from_le_bytes(patch_buf[8..12].try_into().unwrap());
        let s3 = u32::from_le_bytes(patch_buf[12..16].try_into().unwrap());
        assert_eq!(s0, 300, "slot 0 preserved");
        assert_eq!(s1, 301, "slot 1 preserved");
        assert_eq!(s2, 0, "slot 2 zeroed (freed child pointer)");
        assert_eq!(s3, 0, "slot 3 zeroed (freed child pointer)");
    }

    // --- Test 12: partial double-indirect zeros pointers to collapsed single-indirects ---

    #[test]
    fn indirect_truncate_partial_double_indirect_zeros_pointers_to_collapsed_singles() {
        // Double-indirect at physical 4200.
        // Slot 0 → single-indirect 4201 (covers lblocks [12+ppb .. 12+ppb+ppb-1]).
        //   4201 slot 0 → data 5200.
        // Slot 1 → single-indirect 4202 (covers lblocks [12+ppb+ppb .. 12+ppb+ppb+ppb-1]).
        //   4202 slot 0 → data 5201.
        //
        // Cutoff = 12 + ppb + ppb (= 2060 for ppb=1024):
        //   Slot 0 entire range [1036, 2059] is before cutoff → kept entirely.
        //   Slot 1 entire range [2060, 3083] is at/past cutoff → collapsed.
        //
        // Expected:
        // - Double-indirect block 4200 is in surviving_indirect_patches with
        //   slot 0 preserved (4201) and slot 1 zeroed (4202 collapsed).
        // - Single-indirect 4201 is in surviving_indirect_patches (survives entirely
        //   — the walk entered it to count surviving_metadata_blocks).
        //   Actually since the ENTIRE subtree of slot 0 survives, we only need to
        //   verify the double-indirect patch has slot 1 zeroed.
        let blocks_count = 100_000u64;
        let ext = ext_for_indirect_tests(blocks_count);
        let block_size = u64::from(ext.block_size);
        let ppb = block_size / 4; // 1024

        let cutoff = 12 + ppb + ppb;

        let mut i_block = [0u8; 60];
        i_block[52..56].copy_from_slice(&4200u32.to_le_bytes());

        let total_blocks = 8000u64;
        let mut overlay_buf = alloc::vec![0u8; (total_blocks * block_size) as usize];

        // Double-indirect 4200: slot 0 → 4201, slot 1 → 4202.
        let base_4200 = (4200u64 * block_size) as usize;
        overlay_buf[base_4200..base_4200 + 4].copy_from_slice(&4201u32.to_le_bytes());
        overlay_buf[base_4200 + 4..base_4200 + 8].copy_from_slice(&4202u32.to_le_bytes());

        // Single-indirect 4201: slot 0 → data 5200.
        let base_4201 = (4201u64 * block_size) as usize;
        overlay_buf[base_4201..base_4201 + 4].copy_from_slice(&5200u32.to_le_bytes());

        // Single-indirect 4202: slot 0 → data 5201.
        let base_4202 = (4202u64 * block_size) as usize;
        overlay_buf[base_4202..base_4202 + 4].copy_from_slice(&5201u32.to_le_bytes());

        let mut overlay = Cursor::new(overlay_buf);

        let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

        // 1 data run for 5201 (slot 1 of double-indirect, its child is freed).
        let data_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
            .collect();
        assert_eq!(data_runs.len(), 1, "only 1 data block freed (5201)");
        assert_eq!(data_runs[0].physical_start, 5201);

        // 1 metadata run for 4202 (single-indirect child collapsed).
        let metadata_runs: alloc::vec::Vec<_> = result
            .freed_runs
            .iter()
            .filter(|r| matches!(r.kind, AllocationKind::Metadata))
            .collect();
        assert_eq!(metadata_runs.len(), 1, "single-indirect 4202 collapsed");
        assert_eq!(metadata_runs[0].physical_start, 4202);

        // Double-indirect pointer preserved.
        let ptr = u32::from_le_bytes(result.new_i_block[52..56].try_into().unwrap());
        assert_eq!(ptr, 4200, "double-indirect pointer preserved");

        // There must be a patch for block 4200 (the double-indirect block itself).
        let di_patch = result
            .surviving_indirect_patches
            .iter()
            .find(|(phys, _)| *phys == 4200);
        assert!(di_patch.is_some(), "double-indirect 4200 must have a patch");
        let (_, di_buf) = di_patch.unwrap();

        // Slot 0 must be preserved (4201), slot 1 must be zeroed (4202 collapsed).
        let d_s0 = u32::from_le_bytes(di_buf[0..4].try_into().unwrap());
        let d_s1 = u32::from_le_bytes(di_buf[4..8].try_into().unwrap());
        assert_eq!(
            d_s0, 4201,
            "slot 0 preserved pointing at single-indirect 4201"
        );
        assert_eq!(d_s1, 0, "slot 1 zeroed — child 4202 was collapsed");

        let _ = ppb;
    }

    // --- Integration test: partial truncate on the truncate-partial fixture ---

    #[test]
    fn complete_truncate_partial_retains_first_cluster_and_frees_rest() {
        let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-truncate-partial.img")
        else {
            eprintln!("skipping: fixture not available");
            return;
        };

        let target_inum = ext.last_orphan(&mut cursor).expect("read s_last_orphan");
        assert_ne!(target_inum, 0, "fixture must have a chain head");

        // Force partial truncate: i_size = 2049 fits entirely inside block 0.
        // retain_cutoff = 1, so block 0 is retained and block 1 is freed.
        // This is smaller than the fixture's on-disk i_size (4097); the test
        // exercises the straddling-cluster path that the fixture alone cannot.
        let target_size = 2049u64;

        let sb_bytes = read_sb_block(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);

        complete_truncate(&ext, &mut cursor, &mut mutator, target_inum, target_size)
            .expect("truncate partial");

        // Assert: at least one block bitmap was scratched (block 1 freed).
        assert!(
            mutator.block_bitmap_scratch_count() >= 1,
            "partial truncate must free at least one block"
        );

        // Read back the inode scratch to verify eh_entries == 1 (one surviving extent
        // covering logical block 0) and i_blocks is exactly block_size/512 = 8
        // (for a 2-block-fs-block file where only 1 block survives).
        let mut observed_entries = 0u16;
        let mut observed_i_blocks = u32::MAX;
        let mut observed_ee_block = u32::MAX;
        let mut observed_ee_len = u16::MAX;
        mutator
            .patch_inode_scratch(&mut cursor, target_inum, |inode_bytes| {
                // eh_entries at inode_bytes[0x28 + 2 .. 0x28 + 4]
                observed_entries =
                    u16::from_le_bytes(inode_bytes[0x28 + 2..0x28 + 4].try_into().unwrap());
                // i_blocks_lo at inode_bytes[0x1C .. 0x20]
                observed_i_blocks = u32::from_le_bytes(inode_bytes[0x1C..0x20].try_into().unwrap());
                // First leaf extent at inode_bytes[0x28 + 12 ..], 12 bytes.
                observed_ee_block =
                    u32::from_le_bytes(inode_bytes[0x28 + 12..0x28 + 16].try_into().unwrap());
                observed_ee_len =
                    u16::from_le_bytes(inode_bytes[0x28 + 16..0x28 + 18].try_into().unwrap());
                Ok(())
            })
            .expect("read back inode scratch");

        assert_eq!(observed_entries, 1, "one surviving extent");
        // i_blocks: surviving blocks (1) * block_size/512 (8) = 8 (512-byte sectors).
        // HUGE_FILE_FL is OFF on multiblock.bin, so i_blocks is in sectors.
        assert_eq!(
            observed_i_blocks, 8,
            "i_blocks reflects single surviving block"
        );
        assert_eq!(
            observed_ee_block, 0,
            "surviving extent starts at logical block 0"
        );
        assert_eq!(observed_ee_len, 1, "surviving extent has length 1");
    }

    // -------------------------------------------------------------------------
    // Depth-1 extent-tree (deep-tree) truncate tests (Fix G)
    // -------------------------------------------------------------------------

    /// Build a synthetic depth-1 extent-tree overlay.
    ///
    /// Root lives in the 60-byte i_block:
    ///   Header: magic=0xF30A, eh_entries=idx_count, eh_max=4, eh_depth=1, eh_generation=0
    ///   Index entries (12 bytes each): (ei_block, leaf_phys_block)
    ///
    /// Each leaf block is written into the backing buffer at
    /// `leaf_phys_block * block_size`.  A leaf block contains:
    ///   Header: magic, eh_entries=extents.len(), eh_max=340, eh_depth=0, eh_generation=0
    ///   Extent entries: (ee_block, ee_len, ee_start_lo)
    ///
    /// Returns `(i_block, Cursor<Vec<u8>>)`.
    #[allow(clippy::type_complexity)]
    fn build_depth1_tree(
        block_size: u64,
        total_blocks: u64,
        // (ei_block, leaf_phys, leaf_extents: [(ee_block, ee_len, ee_start_lo)])
        index_entries: &[(u32, u64, &[(u32, u16, u32)])],
    ) -> ([u8; 60], Cursor<alloc::vec::Vec<u8>>) {
        let mut i_block = [0u8; 60];
        // Root header.
        i_block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        i_block[2..4].copy_from_slice(&(index_entries.len() as u16).to_le_bytes());
        i_block[4..6].copy_from_slice(&4u16.to_le_bytes());
        i_block[6..8].copy_from_slice(&1u16.to_le_bytes()); // eh_depth = 1
        // eh_generation = 0 (zeroed)

        let mut disk = alloc::vec![0u8; (total_blocks * block_size) as usize];

        for (slot, &(ei_block, leaf_phys, leaf_extents)) in index_entries.iter().enumerate() {
            let idx_off = 12 + slot * 12;
            i_block[idx_off..idx_off + 4].copy_from_slice(&ei_block.to_le_bytes());
            i_block[idx_off + 4..idx_off + 8].copy_from_slice(&(leaf_phys as u32).to_le_bytes());
            // ei_leaf_hi = 0

            // Build leaf block at leaf_phys * block_size.
            let base = (leaf_phys * block_size) as usize;
            disk[base..base + 2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
            disk[base + 2..base + 4].copy_from_slice(&(leaf_extents.len() as u16).to_le_bytes());
            disk[base + 4..base + 6].copy_from_slice(&340u16.to_le_bytes()); // eh_max
            // eh_depth = 0 (zeroed)
            for (ei, &(ee_block, ee_len, ee_start_lo)) in leaf_extents.iter().enumerate() {
                let eoff = base + 12 + ei * 12;
                disk[eoff..eoff + 4].copy_from_slice(&ee_block.to_le_bytes());
                disk[eoff + 4..eoff + 6].copy_from_slice(&ee_len.to_le_bytes());
                // ee_start_hi = 0
                disk[eoff + 8..eoff + 12].copy_from_slice(&ee_start_lo.to_le_bytes());
            }
        }

        (i_block, Cursor::new(disk))
    }

    /// Build a minimal `Ext` for extent-tree tests.  blocks_count is set large
    /// enough for the physical blocks used; block_size=4096, no checksums.
    fn ext_for_extent_tests(blocks_count: u64) -> &'static crate::ext::Ext {
        use crate::checksum::ChecksumState;
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use alloc::boxed::Box;

        let ext = Box::new(crate::ext::Ext {
            inodes_count: 1000,
            blocks_count,
            block_size: 4096,
            group_count: 1,
            inodes_per_group: 1000,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                4096,
                32768,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 32768,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 32768,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::empty(),
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![crate::block_group::GroupDescriptor {
                block_bitmap: 1,
                inode_bitmap: 2,
                inode_table: 3,
                free_blocks_count: 0,
                free_inodes_count: 0,
                flags: 0,
                checksum: ChecksumState::Unknown,
            }],
            checksum_seed: None,
            superblock_checksum: ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }

    fn ext_for_extent_tests_with_checksum(
        blocks_count: u64,
        checksum_seed: u32,
    ) -> &'static crate::ext::Ext {
        use crate::checksum::ChecksumState;
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use alloc::boxed::Box;

        let ext = Box::new(crate::ext::Ext {
            inodes_count: 1000,
            blocks_count,
            block_size: 4096,
            group_count: 1,
            inodes_per_group: 1000,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                4096,
                32768,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 32768,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 32768,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::empty(),
            compat: CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![crate::block_group::GroupDescriptor {
                block_bitmap: 1,
                inode_bitmap: 2,
                inode_table: 3,
                free_blocks_count: 0,
                free_inodes_count: 0,
                flags: 0,
                checksum: ChecksumState::Unknown,
            }],
            checksum_seed: Some(checksum_seed),
            superblock_checksum: ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        });
        Box::leak(ext)
    }

    /// Build sb_bytes for use with `Mutator::new` (block-size bytes of zeros).
    fn dummy_sb_bytes() -> alloc::vec::Vec<u8> {
        alloc::vec![0u8; 4096]
    }

    // --- Depth-1 Test 1: leaf entirely past cutoff is freed ---

    #[test]
    fn complete_truncate_depth_one_prunes_leaf_blocks_past_cutoff() {
        // Tree: depth=1, 2 index entries.
        // L0 (leaf phys=200): extent ee_block=0, ee_len=10, ee_start=100  → logical 0..9
        // L1 (leaf phys=201): extent ee_block=10, ee_len=10, ee_start=200 → logical 10..19
        //
        // Cutoff: retain_blocks=10 → retain logical 0..9, free logical 10..19.
        //
        // Expected:
        //  - L0 data block run NOT freed (before cutoff).
        //  - L1 data block run freed: phys 200..209 (10 blocks), as Data.
        //  - L1 leaf block (phys 201) freed as Metadata.
        let ext = ext_for_extent_tests(10_000);
        let block_size = u64::from(ext.block_size);

        let (i_block, mut overlay) = build_depth1_tree(
            block_size,
            500,
            &[
                (0u32, 200u64, &[(0u32, 10u16, 100u32)]),
                (10u32, 201u64, &[(10u32, 10u16, 200u32)]),
            ],
        );

        // Build the full inode bytes in the overlay at inode table block 3.
        // (inode_table=3, inode_size=256, inum=1 → slot 0 in block 3)
        let itable_base = 3usize * 4096;
        let inode_bytes = overlay.get_mut();

        // Set EXTENTS_FL.
        let flags_off = itable_base + 0x20;
        let flags = 0x0008_0000u32; // EXTENTS_FL
        inode_bytes[flags_off..flags_off + 4].copy_from_slice(&flags.to_le_bytes());

        // Write i_block (the depth-1 root) at inode offset 0x28.
        let iblock_off = itable_base + 0x28;
        inode_bytes[iblock_off..iblock_off + 60].copy_from_slice(&i_block);

        // Set i_size to 10 * 4096 (target_size we will truncate to).
        let target_size = 10u64 * 4096;
        inode_bytes[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(target_size as u32).to_le_bytes());

        // Also need inode_count > 0 for mutator (inum=1 must be valid).
        // ext.inodes_count=1000; inum=1 is valid (1 <= 1000).

        // Need group_descs[0].block_bitmap to be a valid block.
        // Our ext has group_descs[0].block_bitmap=1 — fine.

        // We also need i_blocks_lo to be non-zero (realistic).
        // Write 20*8=160 as i_blocks_lo (20 data blocks * 8 sectors/block).
        let i_blocks_lo: u32 = 20 * 8;
        inode_bytes[itable_base + 0x1C..itable_base + 0x20]
            .copy_from_slice(&i_blocks_lo.to_le_bytes());

        // Seed bitmap at block 1 with all bits set (blocks 1..32768 allocated).
        let bitmap_base = 4096usize;
        for b in inode_bytes[bitmap_base..bitmap_base + 4096].iter_mut() {
            *b = 0xFF;
        }

        let sb_bytes = dummy_sb_bytes();
        let mut mutator = crate::orphan::mutator::Mutator::new(ext, &sb_bytes);

        // Call complete_truncate with target_size = 10 * block_size.
        complete_truncate(ext, &mut overlay, &mut mutator, 1, target_size)
            .expect("depth-1 truncate should succeed");

        // Verify: at least one block bitmap was dirtied (L1 data + L1 leaf freed).
        assert!(
            mutator.block_bitmap_scratch_count() > 0,
            "depth-1 prune must dirty block bitmap"
        );
    }

    // --- Depth-1 Test 2: leaf straddles cutoff — leaf block survives but is rewritten ---

    #[test]
    fn complete_truncate_depth_one_preserves_index_block_when_any_leaf_survives() {
        // Tree: depth=1, 2 index entries.
        // L0 (leaf phys=300): extent ee_block=0, ee_len=10, ee_start=100  → logical 0..9
        // L1 (leaf phys=301): extent ee_block=10, ee_len=10, ee_start=200 → logical 10..19
        //
        // Cutoff: retain_blocks=15 → retain logical 0..14, free logical 15..19.
        // L0 entirely before cutoff → unchanged.
        // L1 straddles: keep blocks 10..14 (5 blocks), free blocks 15..19 (5 blocks).
        //
        // Expected:
        //  - block bitmap dirtied (5 data blocks freed).
        //  - L1 leaf block (phys 301) NOT freed (still allocated; patched via extent_block).
        //  - The inode extent root's entries include L0 and (rewritten) L1 entry.
        let ext = ext_for_extent_tests(10_000);
        let block_size = u64::from(ext.block_size);

        let (i_block, mut overlay) = build_depth1_tree(
            block_size,
            500,
            &[
                (0u32, 300u64, &[(0u32, 10u16, 100u32)]),
                (10u32, 301u64, &[(10u32, 10u16, 200u32)]),
            ],
        );

        let itable_base = 3usize * 4096;
        let inode_bytes = overlay.get_mut();
        let flags_off = itable_base + 0x20;
        inode_bytes[flags_off..flags_off + 4].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        let iblock_off = itable_base + 0x28;
        inode_bytes[iblock_off..iblock_off + 60].copy_from_slice(&i_block);
        // target_size = 15 blocks
        let target_size = 15u64 * 4096;
        inode_bytes[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(target_size as u32).to_le_bytes());
        inode_bytes[itable_base + 0x1C..itable_base + 0x20]
            .copy_from_slice(&(20u32 * 8).to_le_bytes());
        let bitmap_base = 4096usize;
        for b in inode_bytes[bitmap_base..bitmap_base + 4096].iter_mut() {
            *b = 0xFF;
        }

        let sb_bytes = dummy_sb_bytes();
        let mut mutator = crate::orphan::mutator::Mutator::new(ext, &sb_bytes);

        complete_truncate(ext, &mut overlay, &mut mutator, 1, target_size)
            .expect("depth-1 partial truncate should succeed");

        // Block bitmap was dirtied (5 blocks freed from L1's tail).
        assert!(
            mutator.block_bitmap_scratch_count() > 0,
            "partial depth-1 truncate must dirty block bitmap"
        );
    }

    #[test]
    fn complete_truncate_depth_one_partial_recomputes_i_blocks_exactly() {
        let ext = ext_for_extent_tests(10_000);
        let block_size = u64::from(ext.block_size);

        let (i_block, mut overlay) = build_depth1_tree(
            block_size,
            500,
            &[
                (0u32, 300u64, &[(0u32, 10u16, 1000u32)]),
                (10u32, 301u64, &[(10u32, 10u16, 2000u32)]),
            ],
        );

        let itable_base = 3usize * 4096;
        let inode_bytes = overlay.get_mut();
        inode_bytes[itable_base + 0x20..itable_base + 0x24]
            .copy_from_slice(&0x0008_0000u32.to_le_bytes());
        inode_bytes[itable_base + 0x28..itable_base + 0x28 + 60].copy_from_slice(&i_block);
        inode_bytes[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(15u32 * 4096u32).to_le_bytes());
        inode_bytes[itable_base + 0x1C..itable_base + 0x20]
            .copy_from_slice(&(20u32 * 8).to_le_bytes());
        for b in inode_bytes[4096..8192].iter_mut() {
            *b = 0xFF;
        }

        let sb_bytes = dummy_sb_bytes();
        let mut mutator = crate::orphan::mutator::Mutator::new(ext, &sb_bytes);

        complete_truncate(ext, &mut overlay, &mut mutator, 1, 15u64 * 4096)
            .expect("depth-1 partial truncate should succeed");

        let mut observed_i_blocks = u32::MAX;
        mutator
            .patch_inode_scratch(&mut overlay, 1, |inode_bytes| {
                observed_i_blocks = u32::from_le_bytes(inode_bytes[0x1C..0x20].try_into().unwrap());
                Ok(())
            })
            .expect("read inode scratch");

        // Surviving allocations: 15 data blocks + 2 surviving leaf blocks.
        // i_blocks stores 512-byte sectors when HUGE_FILE_FL is not set.
        assert_eq!(observed_i_blocks, 17 * 8);
    }

    #[test]
    fn complete_truncate_depth_one_rejects_bad_checksum_in_kept_child() {
        let ext = ext_for_extent_tests_with_checksum(10_000, 0x1234_5678);
        let block_size = u64::from(ext.block_size);

        let (i_block, mut overlay) = build_depth1_tree(
            block_size,
            500,
            &[
                (0u32, 300u64, &[(0u32, 10u16, 1000u32)]),
                (10u32, 301u64, &[(10u32, 10u16, 2000u32)]),
            ],
        );

        // Make the straddling child checksum-valid so the only failure is the
        // entirely-kept child at block 300, whose checksum remains zero.
        let leaf301 = 301usize * 4096;
        let csum = crate::checksum::compute_extent_block_csum(
            0x1234_5678,
            1,
            0,
            &overlay.get_ref()[leaf301..leaf301 + 4096],
        );
        overlay.get_mut()[leaf301 + 4092..leaf301 + 4096].copy_from_slice(&csum.to_le_bytes());

        let itable_base = 3usize * 4096;
        let inode_bytes = overlay.get_mut();
        inode_bytes[itable_base + 0x20..itable_base + 0x24]
            .copy_from_slice(&0x0008_0000u32.to_le_bytes());
        inode_bytes[itable_base + 0x28..itable_base + 0x28 + 60].copy_from_slice(&i_block);
        inode_bytes[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(15u32 * 4096u32).to_le_bytes());
        for b in inode_bytes[4096..8192].iter_mut() {
            *b = 0xFF;
        }

        let sb_bytes = dummy_sb_bytes();
        let mut mutator = crate::orphan::mutator::Mutator::new(ext, &sb_bytes);

        match complete_truncate(ext, &mut overlay, &mut mutator, 1, 15u64 * 4096) {
            Err(MutatorError::Ext(ExtError::InvalidExtentHeader { inode })) => {
                assert_eq!(inode, 1);
            }
            other => panic!("expected InvalidExtentHeader from kept child checksum, got {other:?}"),
        }
    }

    // --- Depth-1 Test 3: cutoff=0 collapses all leaves — root rewritten to empty ---

    #[test]
    fn complete_truncate_depth_one_collapses_index_block_when_all_children_freed() {
        // Tree: depth=1, 2 index entries (same as test 1).
        // Cutoff: 0 → free everything.
        //
        // Expected:
        //  - All data blocks freed.
        //  - Both leaf blocks freed as Metadata.
        //  - Inode extent root rewritten to empty header (eh_entries=0, eh_depth=0).
        //  - i_blocks set to 0.
        let ext = ext_for_extent_tests(10_000);
        let block_size = u64::from(ext.block_size);

        let (i_block, mut overlay) = build_depth1_tree(
            block_size,
            500,
            &[
                (0u32, 400u64, &[(0u32, 10u16, 100u32)]),
                (10u32, 401u64, &[(10u32, 10u16, 200u32)]),
            ],
        );

        let itable_base = 3usize * 4096;
        let inode_bytes = overlay.get_mut();
        let flags_off = itable_base + 0x20;
        inode_bytes[flags_off..flags_off + 4].copy_from_slice(&0x0008_0000u32.to_le_bytes());
        let iblock_off = itable_base + 0x28;
        inode_bytes[iblock_off..iblock_off + 60].copy_from_slice(&i_block);
        inode_bytes[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(20u32 * 4096u32).to_le_bytes());
        inode_bytes[itable_base + 0x1C..itable_base + 0x20]
            .copy_from_slice(&(20u32 * 8).to_le_bytes());
        let bitmap_base = 4096usize;
        for b in inode_bytes[bitmap_base..bitmap_base + 4096].iter_mut() {
            *b = 0xFF;
        }

        let sb_bytes = dummy_sb_bytes();
        let mut mutator = crate::orphan::mutator::Mutator::new(ext, &sb_bytes);

        complete_truncate(ext, &mut overlay, &mut mutator, 1, 0)
            .expect("depth-1 truncate-to-zero should succeed");

        // Read back the inode scratch to verify eh_entries=0 and i_blocks=0.
        let mut observed_entries = u16::MAX;
        let mut observed_depth = u16::MAX;
        let mut observed_i_blocks = u32::MAX;
        mutator
            .patch_inode_scratch(&mut overlay, 1, |inode_bytes| {
                observed_entries =
                    u16::from_le_bytes(inode_bytes[0x28 + 2..0x28 + 4].try_into().unwrap());
                observed_depth =
                    u16::from_le_bytes(inode_bytes[0x28 + 6..0x28 + 8].try_into().unwrap());
                observed_i_blocks = u32::from_le_bytes(inode_bytes[0x1C..0x20].try_into().unwrap());
                Ok(())
            })
            .expect("read back inode scratch");

        assert_eq!(
            observed_entries, 0,
            "all-freed depth-1 tree: root must have 0 entries"
        );
        assert_eq!(
            observed_depth, 0,
            "all-freed depth-1 tree: root must collapse to depth 0"
        );
        assert_eq!(
            observed_i_blocks, 0,
            "all-freed depth-1 tree: i_blocks must be 0"
        );
    }
}
