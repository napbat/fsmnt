//! Two-phase `EA_INODE` cascade for orphan Level-3. See
//! `docs/superpowers/specs/2026-04-24-fs-ext-orphan-level3-design.md` §2.3.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::error::ExtError;
use crate::ext::Ext;
use crate::inode::InodeFlags;
use crate::io::{Read, Seek};
use crate::orphan::mutator::{AllocationKind, AllocationRun, Mutator, MutatorResult};
use crate::orphan::plan::OrphanStopReason;

#[derive(Debug, Clone, Copy)]
pub(crate) struct EaRef {
    pub host_inode: u32,
    pub value_size: u64,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum EaInodeAction {
    SetRefcount { new_refcount: u64 },
    CascadeFree,
}

#[derive(Debug)]
pub(crate) struct EaInodePlan {
    pub actions: BTreeMap<u32, EaInodeAction>,
}

/// Error type for [`plan_ea_inode_cascade`].
///
/// `Ext` wraps I/O errors from structural reads and apply-phase mutations.
/// `Stop` signals an invariant violation that halts the cascade.
#[derive(Debug)]
pub(crate) enum EaInodePlanError {
    Ext(ExtError),
    Stop(OrphanStopReason),
}

impl From<ExtError> for EaInodePlanError {
    fn from(err: ExtError) -> Self {
        Self::Ext(err)
    }
}

pub(crate) type EaInodePlanResult<T> = core::result::Result<T, EaInodePlanError>;

/// Plan the EA-inode cascade for a set of EA-inode references.
///
/// For each EA inode (in deterministic inode-number order), runs six
/// invariant checks per spec §2.3, then applies the underflow guard
/// and decides between `SetRefcount` or `CascadeFree`.
///
/// Returns `Err(EaInodePlanError::Stop(...))` on the first invariant
/// violation, or `Err(EaInodePlanError::Ext(...))` for I/O errors.
pub(crate) fn plan_ea_inode_cascade<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    ea_refs: &BTreeMap<u32, Vec<EaRef>>,
) -> EaInodePlanResult<EaInodePlan> {
    let mut plan = EaInodePlan {
        actions: BTreeMap::new(),
    };

    for (&ea_inode_num, refs) in ea_refs {
        let first_host = refs.first().map_or(0, |r| r.host_inode);

        // Check 1: structural read — I/O errors bubble as EaInodePlanError::Ext.
        let inode = ext.inode(overlay, ea_inode_num)?;

        // Check 2: EA_INODE_FL must be set.
        if !inode.flags().contains(InodeFlags::EA_INODE_FL) {
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeMissingFlag {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        // Check 3: pre_refcount > 0 on disk.
        let pre_refcount = inode.ea_inode_refcount();
        if pre_refcount == 0 {
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeRefcountZero {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        // Check 4: size agreement — each EaRef's declared value_size must
        // match the EA inode's i_size. First mismatch stops.
        let actual_size = inode.size();
        for r in refs {
            if actual_size != r.value_size {
                return Err(EaInodePlanError::Stop(
                    OrphanStopReason::EaInodeSizeMismatch {
                        host_inode: r.host_inode,
                        ea_inode: ea_inode_num,
                        expected: r.value_size,
                        actual: actual_size,
                    },
                ));
            }
        }

        // Check 5: value-hash (METADATA_CSUM only).
        if ext.has_metadata_csum()
            && !verify_ea_inode_value_hash(ext, overlay, &inode).map_err(EaInodePlanError::Ext)?
        {
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeChecksumInvalid {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        // Check 6 (priority over ibody): external xattr block.
        //
        // Both branches below return `Err(Stop(..))`, so the `> 1`
        // boundary only selects which `OrphanStopReason` variant is
        // reported — the cascade halts (fail-closed) either way. The
        // issue-#120 audit therefore flags `> -> >=` here as a
        // diagnostic-only survivor; see docs/mutation-testing.md.
        if let Some(refcount) = inode
            .ea_inode_xattr_block_refcount(overlay)
            .map_err(EaInodePlanError::Ext)?
        {
            if xattr_block_is_shared(refcount) {
                return Err(EaInodePlanError::Stop(
                    OrphanStopReason::EaInodeSharedXattrBlock {
                        host_inode: first_host,
                        ea_inode: ea_inode_num,
                        xattr_block: inode.file_acl_block(),
                        refcount,
                    },
                ));
            }
            // Any xattr block on an EA inode is a nested reference.
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeNestedReference {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        // Check 7: no ibody xattrs.
        if inode.ea_inode_has_ibody_xattrs() {
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeNestedReference {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        // Underflow guard.
        let count = refs.len() as u64;
        if count > pre_refcount {
            return Err(EaInodePlanError::Stop(
                OrphanStopReason::EaInodeRefcountZero {
                    host_inode: first_host,
                    ea_inode: ea_inode_num,
                },
            ));
        }

        let new_refcount = pre_refcount - count;
        let action = if new_refcount == 0 {
            EaInodeAction::CascadeFree
        } else {
            EaInodeAction::SetRefcount { new_refcount }
        };
        plan.actions.insert(ea_inode_num, action);
    }

    Ok(plan)
}

/// Execute plan actions for the EA inode cascade.
///
/// `SetRefcount` patches the EA inode's refcount bytes in place via
/// `set_ea_inode_refcount_bytes`. `CascadeFree` enumerates the EA inode's
/// owned data blocks via its extent tree, calls `mutator.free_allocations`,
/// clears its inode-bitmap bit, and zeros the inode.
pub(crate) fn apply_ea_inode_plan<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &EaInodePlan,
) -> MutatorResult<()> {
    for (&ea_inode, &action) in &plan.actions {
        match action {
            EaInodeAction::SetRefcount { new_refcount } => {
                mutator.patch_inode_scratch(overlay, ea_inode, |inode_bytes| {
                    crate::inode::set_ea_inode_refcount_bytes(inode_bytes, new_refcount);
                    Ok(())
                })?;
            }
            EaInodeAction::CascadeFree => {
                let inode = ext.inode(overlay, ea_inode)?;
                let runs = enumerate_ea_inode_data_blocks(ext, overlay, &inode, ea_inode)?;
                mutator.free_allocations(overlay, ea_inode, &runs)?;
                mutator.clear_inode_bitmap_bit(overlay, ea_inode, false)?;
                mutator.patch_inode_scratch(overlay, ea_inode, |bytes| {
                    bytes.fill(0);
                    Ok(())
                })?;
            }
        }
    }
    Ok(())
}

/// Enumerate the data blocks owned by an EA inode via its extent tree.
///
/// EA inodes use the standard ext4 extent tree. The depth-0 case is the common
/// shape for EA values that fit in a handful of contiguous extents — a bespoke
/// fast path parses the 60-byte in-inode buffer directly and emits each leaf
/// extent as a `Data` run with `logical_cluster_start = ee_block /
/// blocks_per_cluster`.
///
/// For depth > 0 the walk delegates to
/// `crate::extent::collect_tagged_extent_blocks_into`, which emits leaf
/// extents as `ExtentAllocation::Data` (preserving `ee_block` so the per-leaf
/// logical-cluster mapping survives) and internal extent-tree index blocks as
/// `ExtentAllocation::IndexBlock`. Each tagged entry is then mapped 1:1 to an
/// `AllocationRun`: leaves to `AllocationKind::Data { logical_cluster_start }`
/// and index blocks to `AllocationKind::Metadata`. Tagging index blocks as
/// `Metadata` is required for bigalloc-correct overlap semantics in
/// `Mutator::free_allocations`: under the prior all-`Data` mapping, index
/// blocks falsely registered `logical_cluster_start = 0`, which could either
/// raise spurious `BigallocClusterOverlap` errors or mask genuine cross-leaf
/// physical-cluster collisions.
fn enumerate_ea_inode_data_blocks<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    inode: &crate::inode::ExtInode<'_>,
    ea_inum: u32,
) -> MutatorResult<Vec<AllocationRun>> {
    let i_block = inode.i_block();
    let blocks_per_cluster = u64::from(ext.blocks_per_cluster);

    // Parse the in-inode extent header to detect depth.
    let magic = u16::from_le_bytes([i_block[0], i_block[1]]);
    // If magic is wrong the inode has no extent tree — return empty (no blocks to free).
    // 0xF30A is the standard ext4 extent magic (EXTENT_MAGIC).
    if magic != 0xF30A {
        return Ok(Vec::new());
    }
    let depth = u16::from_le_bytes([i_block[6], i_block[7]]);

    if depth == 0 {
        // Fast path: read leaf entries directly from the in-inode buffer.
        let entries = u16::from_le_bytes([i_block[2], i_block[3]]);
        let mut runs = Vec::with_capacity(entries as usize);
        for i in 0..u32::from(entries) {
            let off = 12 + (i as usize) * 12;
            if off + 12 > i_block.len() {
                break;
            }
            let ee_block = u32::from_le_bytes(i_block[off..off + 4].try_into().unwrap());
            let ee_len_raw = u16::from_le_bytes(i_block[off + 4..off + 6].try_into().unwrap());
            let ee_start_hi = u16::from_le_bytes(i_block[off + 6..off + 8].try_into().unwrap());
            let ee_start_lo = u32::from_le_bytes(i_block[off + 8..off + 12].try_into().unwrap());
            let block_len = if ee_len_raw > 32768 {
                u32::from(ee_len_raw) - 32768
            } else {
                u32::from(ee_len_raw)
            };
            if block_len == 0 {
                continue;
            }
            // `ee_start_hi << 32` and `ee_start_lo` occupy disjoint bit
            // ranges (bits 32..48 vs 0..32), so `|`/`^` are equivalent
            // here — cargo-mutants flags `| -> ^` as an equivalent mutant
            // on this line; see crates/fs-ext/docs/mutation-testing.md.
            let physical_start = combine_48bit_physical(ee_start_hi, ee_start_lo);
            let logical_cluster_start = u64::from(ee_block) / blocks_per_cluster;
            runs.push(AllocationRun {
                physical_start,
                block_len,
                kind: AllocationKind::Data {
                    logical_cluster_start,
                },
            });
        }
        Ok(runs)
    } else {
        // Deep tree: use the tagged walker so internal index blocks are
        // emitted as Metadata and leaf extents preserve their per-leaf
        // logical-cluster mapping. This is the bigalloc-correct shape that
        // `Mutator::free_allocations` expects when it builds `cluster_owners`.
        let mut tagged: Vec<crate::extent::ExtentAllocation> = Vec::new();
        crate::extent::collect_tagged_extent_blocks_into(
            ext,
            overlay,
            ea_inum,
            inode.generation(),
            &i_block,
            &mut tagged,
        )?;
        let mut runs = Vec::with_capacity(tagged.len());
        for entry in tagged {
            match entry {
                crate::extent::ExtentAllocation::Data {
                    physical_start,
                    block_len,
                    logical_block_start,
                } => runs.push(AllocationRun {
                    physical_start,
                    block_len,
                    kind: AllocationKind::Data {
                        logical_cluster_start: u64::from(logical_block_start) / blocks_per_cluster,
                    },
                }),
                crate::extent::ExtentAllocation::IndexBlock(block) => runs.push(AllocationRun {
                    physical_start: block,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                }),
            }
        }
        Ok(runs)
    }
}

/// Read the EA inode's data bytes and verify the CRC32C hash stored in
/// `i_atime` matches `ea_inode_hash(seed, data)`.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, `Err` on I/O.
/// When `i_atime == 0` the hash is absent and the check passes (matches
/// kernel behaviour: a zero stored hash means "not computed").
/// Whether an EA-inode's xattr-block refcount indicates the block is
/// shared with another inode.
///
/// Extracted so `#[cfg_attr(test, mutants::skip)]` applies only to this
/// comparison: both `>` and `>=` branches of `plan_ea_inode_cascade`
/// halt the cascade fail-closed (`EaInodeSharedXattrBlock` vs
/// `EaInodeNestedReference`), so the `> -> >=` mutant is
/// diagnostic-only. See `crates/fs-ext/docs/mutation-testing.md`.
#[cfg_attr(test, mutants::skip)]
fn xattr_block_is_shared(refcount: u32) -> bool {
    refcount > 1
}

/// Combine an extent record's split 48-bit physical-block field
/// (`ee_start_hi` at bits 32..48, `ee_start_lo` at bits 0..32) into a
/// single `u64`.
///
/// Extracted so `#[cfg_attr(test, mutants::skip)]` applies only to the
/// bit-combination expression: the two operands occupy disjoint bit
/// ranges, so `|` and `^` produce identical results — cargo-mutants
/// flags `| -> ^` here as an equivalent mutant. See
/// `crates/fs-ext/docs/mutation-testing.md`.
#[cfg_attr(test, mutants::skip)]
fn combine_48bit_physical(ee_start_hi: u16, ee_start_lo: u32) -> u64 {
    (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo)
}

fn verify_ea_inode_value_hash<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    inode: &crate::inode::ExtInode<'_>,
) -> crate::error::Result<bool> {
    let Some(seed) = ext.checksum_seed() else {
        return Ok(true);
    };
    let stored = inode.raw_i_atime();
    if stored == 0 {
        return Ok(true);
    }
    let data = inode.read_ea_inode_value_bytes(overlay)?;
    let computed = crate::checksum::ea_inode_hash(seed, &data);
    Ok(computed == stored)
}

#[cfg(test)]
#[path = "ea_inode_tests/mod.rs"]
mod tests;
