//! Truncate-completion apply path for orphan Level-3. See
//! `docs/superpowers/specs/2026-04-24-fs-ext-orphan-level3-design.md` §2.1.

use zerocopy::FromBytes;

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::extent::{RawExtent, RawExtentHeader, RawExtentIndex, index_child_block, parse_header};
use crate::inode::InodeFlags;
use crate::io::{Read, Seek, SeekFrom};
use crate::orphan::mutator::{AllocationKind, AllocationRun, Mutator, MutatorError, MutatorResult};

mod indirect;

pub(crate) use indirect::walk_indirect_map;

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
        Ok(walk_extent_leaf(
            p, entry_data, entries, node_bytes, this_block,
        ))
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
) -> ExtentNodeResult {
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
            let survive_len = u16::try_from(cutoff_block - u64::from(ee_block))
                .expect("a surviving extent prefix cannot exceed its u16 extent length");
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

    finish_extent_leaf(
        node_bytes,
        this_block,
        &surviving,
        freed_runs,
        surviving_data_blocks,
    )
}

fn finish_extent_leaf(
    node_bytes: &[u8],
    this_block: Option<u64>,
    surviving: &[(u32, u16, u64)],
    mut freed_runs: alloc::vec::Vec<AllocationRun>,
    surviving_data_blocks: u64,
) -> ExtentNodeResult {
    if surviving.is_empty() {
        if let Some(physical) = this_block {
            freed_runs.push(AllocationRun {
                physical_start: physical,
                block_len: 1,
                kind: AllocationKind::Metadata,
            });
        }
        return ExtentNodeResult {
            freed_runs,
            surviving_metadata_blocks: 0,
            surviving_data_blocks: 0,
            survivor: None,
            surviving_extent_patches: alloc::vec::Vec::new(),
        };
    }

    let mut new_content = node_bytes.to_vec();
    new_content[2..4].copy_from_slice(
        &u16::try_from(surviving.len())
            .expect("an extent node cannot contain more than u16::MAX records")
            .to_le_bytes(),
    );
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
        let physical_bytes = ee_start.to_le_bytes();
        new_content[off + 6..off + 8].copy_from_slice(&physical_bytes[4..6]);
        new_content[off + 8..off + 12].copy_from_slice(&physical_bytes[..4]);
    }

    let surviving_metadata_blocks = this_block.map_or(0, |_| 1);

    ExtentNodeResult {
        freed_runs,
        surviving_metadata_blocks,
        surviving_data_blocks,
        survivor: Some(new_content.into_boxed_slice()),
        surviving_extent_patches: alloc::vec::Vec::new(),
    }
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

    Ok(finish_extent_index(
        node_bytes,
        this_block,
        &surviving_idx,
        freed_runs,
        patches,
        surviving_meta,
        surviving_data,
    ))
}

fn finish_extent_index(
    node_bytes: &[u8],
    this_block: Option<u64>,
    surviving: &[(u32, u64)],
    mut freed_runs: alloc::vec::Vec<AllocationRun>,
    patches: alloc::vec::Vec<(u64, alloc::boxed::Box<[u8]>)>,
    surviving_metadata_blocks: u64,
    surviving_data_blocks: u64,
) -> ExtentNodeResult {
    if surviving.is_empty() {
        if let Some(physical) = this_block {
            freed_runs.push(AllocationRun {
                physical_start: physical,
                block_len: 1,
                kind: AllocationKind::Metadata,
            });
        }
        return ExtentNodeResult {
            freed_runs,
            surviving_metadata_blocks: 0,
            surviving_data_blocks: 0,
            survivor: None,
            surviving_extent_patches: patches,
        };
    }

    let mut new_content = node_bytes.to_vec();
    new_content[2..4].copy_from_slice(
        &u16::try_from(surviving.len())
            .expect("an extent index cannot contain more than u16::MAX records")
            .to_le_bytes(),
    );
    let max_entries = usize::from(u16::from_le_bytes([node_bytes[4], node_bytes[5]]));
    for slot in 0..max_entries {
        let off = 12 + slot * 12;
        if off + 12 <= new_content.len() {
            new_content[off..off + 12].fill(0);
        }
    }
    for (idx_pos, (ei_block, child_phys)) in surviving.iter().enumerate() {
        let off = 12 + idx_pos * 12;
        new_content[off..off + 4].copy_from_slice(&ei_block.to_le_bytes());
        let child_bytes = child_phys.to_le_bytes();
        new_content[off + 4..off + 8].copy_from_slice(&child_bytes[..4]);
        // ei_leaf_hi is bytes 4..6 of the 48-bit physical block number.
        new_content[off + 8..off + 10].copy_from_slice(&child_bytes[4..6]);
        // padding at off+10..off+12 stays 0
    }

    let this_meta = this_block.map_or(0, |_| 1);

    ExtentNodeResult {
        freed_runs,
        surviving_metadata_blocks: surviving_metadata_blocks + this_meta,
        surviving_data_blocks,
        survivor: Some(new_content.into_boxed_slice()),
        surviving_extent_patches: patches,
    }
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
    let block_size = usize::try_from(p.block_size)
        .map_err(|_| MutatorError::Ext(ExtError::InvalidExtentHeader { inode: p.inode_num }))?;
    let mut buf = alloc::vec![0u8; block_size];
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

/// Handle `complete_truncate` for `EXTENTS_FL` inodes with depth > 0 extent trees.
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
    dp: &DeepExtentParams<'_>,
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
    let count = (0..12u64)
        .filter(|&slot| {
            let off = usize::try_from(slot * 4)
                .expect("the twelve direct block pointers occupy only 48 bytes");
            u32::from_le_bytes(i_block[off..off + 4].try_into().unwrap()) != 0
        })
        .count();
    u64::try_from(count).expect("the direct block count cannot exceed twelve")
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
    let encoded = new_i_blocks.to_le_bytes();
    inode_bytes[0x1C..0x20].copy_from_slice(&encoded[..4]);
    // Write i_blocks_hi at osd2.linux2.l_i_blocks_high, offset 0x74 (16-bit).
    inode_bytes[0x74..0x76].copy_from_slice(&encoded[4..6]);
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

struct InlineTruncatePlan {
    surviving: alloc::vec::Vec<(u32, u16, u64)>,
    freed_runs: alloc::vec::Vec<AllocationRun>,
}

fn plan_inline_extent_truncate(
    i_block: &[u8; 60],
    entries: u16,
    retain_cutoff: u64,
    retain_cutoff_blocks: u64,
    blocks_per_cluster: u64,
) -> InlineTruncatePlan {
    let mut surviving = alloc::vec::Vec::new();
    let mut freed_runs = alloc::vec::Vec::new();
    for index in 0..usize::from(entries) {
        let offset = 12 + index * 12;
        if offset + 12 > i_block.len() {
            break;
        }
        let Some(raw) = RawExtent::ref_from_bytes(&i_block[offset..offset + 12]).ok() else {
            break;
        };

        let logical_start = raw.ee_block.get();
        let encoded_len = raw.ee_len.get();
        let uninitialized = encoded_len > 32768;
        let extent_len = if uninitialized {
            encoded_len - 32768
        } else {
            encoded_len
        };
        let physical_start =
            (u64::from(raw.ee_start_hi.get()) << 32) | u64::from(raw.ee_start_lo.get());
        let first_cluster = u64::from(logical_start) / blocks_per_cluster;
        let last_cluster =
            (u64::from(logical_start) + u64::from(extent_len) - 1) / blocks_per_cluster;

        if last_cluster < retain_cutoff {
            surviving.push((logical_start, encoded_len, physical_start));
        } else if first_cluster >= retain_cutoff {
            freed_runs.push(AllocationRun {
                physical_start,
                block_len: u32::from(extent_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: first_cluster,
                },
            });
        } else {
            let surviving_len = u16::try_from(retain_cutoff_blocks - u64::from(logical_start))
                .expect("a surviving extent prefix cannot exceed its u16 extent length");
            let encoded_surviving_len = if uninitialized {
                surviving_len + 32768
            } else {
                surviving_len
            };
            surviving.push((logical_start, encoded_surviving_len, physical_start));
            freed_runs.push(AllocationRun {
                physical_start: physical_start + u64::from(surviving_len),
                block_len: u32::from(extent_len - surviving_len),
                kind: AllocationKind::Data {
                    logical_cluster_start: retain_cutoff,
                },
            });
        }
    }
    InlineTruncatePlan {
        surviving,
        freed_runs,
    }
}

fn write_inline_extent_root(
    inode_bytes: &mut [u8],
    surviving: &[(u32, u16, u64)],
    surviving_blocks: u64,
    block_size: u64,
) {
    write_i_blocks_field(inode_bytes, surviving_blocks, block_size);
    let inline = &mut inode_bytes[0x28..0x28 + 60];
    inline.fill(0);
    inline[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    inline[2..4].copy_from_slice(
        &u16::try_from(surviving.len())
            .expect("the inline extent root has at most four records")
            .to_le_bytes(),
    );
    inline[4..6].copy_from_slice(&4u16.to_le_bytes());
    for (index, (logical_start, encoded_len, physical_start)) in surviving.iter().enumerate() {
        let offset = 12 + index * 12;
        inline[offset..offset + 4].copy_from_slice(&logical_start.to_le_bytes());
        inline[offset + 4..offset + 6].copy_from_slice(&encoded_len.to_le_bytes());
        let physical_bytes = physical_start.to_le_bytes();
        inline[offset + 6..offset + 8].copy_from_slice(&physical_bytes[4..6]);
        inline[offset + 8..offset + 12].copy_from_slice(&physical_bytes[..4]);
    }
}

/// Complete a pending truncate on `inode_num` by freeing every data
/// allocation at or past `retain_cutoff`, shrinking the extent tree or
/// indirect-block map accordingly, and recomputing `i_blocks`.
///
/// Supports:
/// - `EXTENTS_FL` inodes with a depth-0 (in-inode root) extent tree.
/// - `EXTENTS_FL` inodes with depth > 0 external extent-tree blocks.
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
        return complete_truncate_deep_extent(ext, overlay, mutator, &dp);
    }

    let plan = plan_inline_extent_truncate(
        &i_block,
        header.eh_entries.get(),
        retain_cutoff,
        retain_cutoff_blocks,
        blocks_per_cluster,
    );
    mutator.free_allocations(overlay, inode_num, &plan.freed_runs)?;
    let surviving_blocks: u64 = plan
        .surviving
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
        write_inline_extent_root(inode_bytes, &plan.surviving, surviving_blocks, block_size);
        Ok(())
    })?;

    Ok(())
}

#[cfg(test)]
#[path = "truncate_tests/mod.rs"]
mod tests;
