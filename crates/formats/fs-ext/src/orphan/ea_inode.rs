//! Two-phase EA_INODE cascade for orphan Level-3. See
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
    let seed = match ext.checksum_seed() {
        Some(s) => s,
        None => return Ok(true),
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
mod tests {
    use super::*;

    #[test]
    fn ea_inode_plan_empty_default() {
        let plan = EaInodePlan {
            actions: BTreeMap::new(),
        };
        assert!(plan.actions.is_empty());
    }

    // ---- enumerate_ea_inode_data_blocks: depth-0 fast path ----
    //
    // These tests close the coverage gap surfaced by the issue-#120
    // mutation audit: every surviving mutant was in the depth-0 extent
    // decoder's arithmetic (offset stride, the uninitialized-extent
    // marker subtraction, the 48-bit physical-block recombination, the
    // entry-bounds guard, and the bigalloc cluster division).

    /// One synthetic leaf extent for [`depth0_iblock`].
    struct TestExtent {
        ee_block: u32,
        ee_len: u16,
        ee_start_hi: u16,
        ee_start_lo: u32,
    }

    /// Build a 60-byte `i_block` holding a depth-0 ext4 extent header
    /// followed by `extents` leaf entries. `declared_entries` is written
    /// into `eh_entries` and may exceed `extents.len()` to exercise the
    /// in-buffer bounds guard.
    fn depth0_iblock(extents: &[TestExtent], declared_entries: u16) -> [u8; 60] {
        let mut b = [0u8; 60];
        b[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
        b[2..4].copy_from_slice(&declared_entries.to_le_bytes()); // eh_entries
        b[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
        b[6..8].copy_from_slice(&0u16.to_le_bytes()); // eh_depth = 0
        for (i, e) in extents.iter().enumerate() {
            let off = 12 + i * 12;
            b[off..off + 4].copy_from_slice(&e.ee_block.to_le_bytes());
            b[off + 4..off + 6].copy_from_slice(&e.ee_len.to_le_bytes());
            b[off + 6..off + 8].copy_from_slice(&e.ee_start_hi.to_le_bytes());
            b[off + 8..off + 12].copy_from_slice(&e.ee_start_lo.to_le_bytes());
        }
        b
    }

    /// Construct a synthetic regular-file `RawInode` carrying `i_block`.
    fn ea_raw_inode(i_block: [u8; 60]) -> crate::inode::RawInode {
        use zerocopy::FromZeros;
        let mut raw = crate::inode::RawInode::new_zeroed();
        raw.i_mode = zerocopy::byteorder::U16::new(0x8000); // S_IFREG
        raw.i_block = i_block;
        raw
    }

    fn enumerate_depth0(ext: &Ext, i_block: [u8; 60]) -> Vec<AllocationRun> {
        let inode = crate::inode::ExtInode::from_raw_for_test(ea_raw_inode(i_block), 77);
        // Depth-0 fast path never touches the reader; an empty cursor is fine.
        let mut empty = std::io::Cursor::new(alloc::vec::Vec::<u8>::new());
        enumerate_ea_inode_data_blocks(ext, &mut empty, &inode, 77)
            .expect("depth-0 enumeration must not error")
    }

    #[test]
    fn enumerate_depth0_multiple_extents_decode_distinctly() {
        let ext = Ext::dummy_for_test(); // blocks_per_cluster = 1
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[
                    TestExtent {
                        ee_block: 0,
                        ee_len: 4,
                        ee_start_hi: 0,
                        ee_start_lo: 100,
                    },
                    TestExtent {
                        ee_block: 4,
                        ee_len: 8,
                        ee_start_hi: 0,
                        ee_start_lo: 200,
                    },
                    TestExtent {
                        ee_block: 12,
                        ee_len: 1,
                        ee_start_hi: 0,
                        ee_start_lo: 300,
                    },
                ],
                3,
            ),
        );
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].physical_start, 100);
        assert_eq!(runs[0].block_len, 4);
        assert_eq!(runs[1].physical_start, 200);
        assert_eq!(runs[1].block_len, 8);
        assert_eq!(runs[2].physical_start, 300);
        assert_eq!(runs[2].block_len, 1);
        // blocks_per_cluster == 1, so logical_cluster_start == ee_block.
        for (run, ee_block) in runs.iter().zip([0u64, 4, 12]) {
            match run.kind {
                AllocationKind::Data {
                    logical_cluster_start,
                } => assert_eq!(logical_cluster_start, ee_block),
                AllocationKind::Metadata => panic!("depth-0 leaf must be Data"),
            }
        }
    }

    #[test]
    fn enumerate_depth0_uninitialized_extent_subtracts_marker() {
        let ext = Ext::dummy_for_test();
        // ee_len 32768 + 5 marks an uninitialized extent of 5 real blocks.
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[TestExtent {
                    ee_block: 0,
                    ee_len: 32768 + 5,
                    ee_start_hi: 0,
                    ee_start_lo: 500,
                }],
                1,
            ),
        );
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].block_len, 5, "32773 - 32768 = 5");
        assert_eq!(runs[0].physical_start, 500);
    }

    #[test]
    fn enumerate_depth0_full_initialized_extent_is_not_treated_as_uninitialized() {
        let ext = Ext::dummy_for_test();
        // ee_len exactly 32768 is a *full initialized* extent (the marker
        // boundary is `> 32768`, not `>=`): block_len must stay 32768,
        // not collapse to 0 and get skipped.
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[TestExtent {
                    ee_block: 0,
                    ee_len: 32768,
                    ee_start_hi: 0,
                    ee_start_lo: 700,
                }],
                1,
            ),
        );
        assert_eq!(runs.len(), 1, "a 32768-block initialized extent is kept");
        assert_eq!(runs[0].block_len, 32768);
        assert_eq!(runs[0].physical_start, 700);
    }

    #[test]
    fn enumerate_depth0_recombines_48_bit_physical_block() {
        let ext = Ext::dummy_for_test();
        // ee_start_hi = 1, ee_start_lo = 0x10 → physical = (1 << 32) | 0x10.
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[TestExtent {
                    ee_block: 0,
                    ee_len: 2,
                    ee_start_hi: 1,
                    ee_start_lo: 0x10,
                }],
                1,
            ),
        );
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].physical_start, 0x1_0000_0010);
    }

    #[test]
    fn enumerate_depth0_stops_at_in_buffer_bounds_guard() {
        let ext = Ext::dummy_for_test();
        // eh_entries claims 6, but only 4 extents fit in the 60-byte
        // i_block (header + 4 * 12 = 60). The loop must stop at the
        // fifth slot via the `off + 12 > i_block.len()` guard.
        let extents: Vec<TestExtent> = (0..4)
            .map(|i| TestExtent {
                ee_block: i * 4,
                ee_len: 4,
                ee_start_hi: 0,
                ee_start_lo: 1000 + i,
            })
            .collect();
        let runs = enumerate_depth0(ext, depth0_iblock(&extents, 6));
        assert_eq!(runs.len(), 4, "only the 4 extents that fit are decoded");
        assert_eq!(runs[3].physical_start, 1003);
    }

    #[test]
    fn enumerate_depth0_bigalloc_divides_ee_block_by_cluster_size() {
        let ext = Ext::dummy_for_test_bigalloc(4); // blocks_per_cluster = 4
        // ee_block 20 → logical_cluster_start 20 / 4 = 5.
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[TestExtent {
                    ee_block: 20,
                    ee_len: 4,
                    ee_start_hi: 0,
                    ee_start_lo: 999,
                }],
                1,
            ),
        );
        assert_eq!(runs.len(), 1);
        match runs[0].kind {
            AllocationKind::Data {
                logical_cluster_start,
            } => assert_eq!(logical_cluster_start, 5),
            AllocationKind::Metadata => panic!("depth-0 leaf must be Data"),
        }
    }

    #[test]
    fn enumerate_depth0_zero_length_extent_is_skipped() {
        let ext = Ext::dummy_for_test();
        let runs = enumerate_depth0(
            ext,
            depth0_iblock(
                &[
                    TestExtent {
                        ee_block: 0,
                        ee_len: 0,
                        ee_start_hi: 0,
                        ee_start_lo: 111,
                    },
                    TestExtent {
                        ee_block: 8,
                        ee_len: 2,
                        ee_start_hi: 0,
                        ee_start_lo: 222,
                    },
                ],
                2,
            ),
        );
        assert_eq!(runs.len(), 1, "the zero-length extent is dropped");
        assert_eq!(runs[0].physical_start, 222);
    }

    #[test]
    fn enumerate_non_extent_inode_yields_no_runs() {
        let ext = Ext::dummy_for_test();
        // No 0xF30A magic → inode has no extent tree.
        let runs = enumerate_depth0(ext, [0u8; 60]);
        assert!(runs.is_empty());
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn fixture_available(name: &str) -> bool {
        fixture_path(name).exists()
    }

    fn load_dirty(name: &str) -> Option<(Ext, std::io::Cursor<alloc::vec::Vec<u8>>)> {
        if !fixture_available(name) {
            return None;
        }
        let bytes = std::fs::read(fixture_path(name)).ok()?;
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open_lenient");
        Some((ext, cursor))
    }

    fn build_ea_refs_from_orphan_chain<T: Read + Seek>(
        ext: &Ext,
        overlay: &mut T,
    ) -> BTreeMap<u32, alloc::vec::Vec<EaRef>> {
        let mut map: BTreeMap<u32, alloc::vec::Vec<EaRef>> = BTreeMap::new();

        let head = ext.last_orphan(overlay).expect("read s_last_orphan");
        let mut current = head;
        let mut seen = alloc::collections::BTreeSet::new();

        while current != 0 {
            if !seen.insert(current) {
                break;
            }
            let host = ext.inode(overlay, current).expect("read orphan inode");
            let next = host.raw_i_dtime();

            if let Some(ibody) = host.ibody_xattr_data() {
                collect_ea_refs_from_ibody(ibody, current, &mut map);
            }

            current = next;
        }

        map
    }

    fn collect_ea_refs_from_ibody(
        ibody: &[u8],
        host_inode: u32,
        map: &mut BTreeMap<u32, alloc::vec::Vec<EaRef>>,
    ) {
        if ibody.len() < 8 {
            return;
        }
        let magic = u32::from_le_bytes([ibody[0], ibody[1], ibody[2], ibody[3]]);
        if magic != crate::xattr::XATTR_MAGIC {
            return;
        }

        const ENTRY_SIZE: usize = 16;
        let mut pos = 4usize;
        while pos + 2 <= ibody.len() {
            if ibody[pos] == 0 && ibody[pos + 1] == 0 {
                break;
            }
            if pos + ENTRY_SIZE > ibody.len() {
                break;
            }
            let name_len = ibody[pos] as usize;
            let e_value_inum = u32::from_le_bytes([
                ibody[pos + 4],
                ibody[pos + 5],
                ibody[pos + 6],
                ibody[pos + 7],
            ]);
            let value_size = u32::from_le_bytes([
                ibody[pos + 8],
                ibody[pos + 9],
                ibody[pos + 10],
                ibody[pos + 11],
            ]);
            if e_value_inum != 0 {
                map.entry(e_value_inum).or_default().push(EaRef {
                    host_inode,
                    value_size: u64::from(value_size),
                });
            }
            let name_start = pos + ENTRY_SIZE;
            let next = name_start + name_len;
            pos = (next + 3) & !3;
        }
    }

    #[test]
    fn plan_single_host_cascade_produces_cascade_free_action() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-cascade.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs).expect("plan");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(
            matches!(action, EaInodeAction::CascadeFree),
            "expected CascadeFree, got {action:?}"
        );
    }

    #[test]
    fn plan_multi_host_cascade_produces_cascade_free_action() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-multi.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs).expect("plan");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(
            matches!(action, EaInodeAction::CascadeFree),
            "expected CascadeFree, got {action:?}"
        );
    }

    #[test]
    fn plan_partial_reference_produces_set_refcount() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-partial.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs).expect("plan");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(
            matches!(action, EaInodeAction::SetRefcount { new_refcount: 1 }),
            "expected SetRefcount{{1}}, got {action:?}"
        );
    }

    #[test]
    fn plan_missing_ea_inode_flag_stops_with_missing_flag() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-missing-flag.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeMissingFlag { .. })) => {}
            other => panic!("expected EaInodeMissingFlag stop, got {other:?}"),
        }
    }

    #[test]
    fn plan_size_mismatch_stops() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-size-mismatch.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeSizeMismatch { .. })) => {}
            other => panic!("expected EaInodeSizeMismatch stop, got {other:?}"),
        }
    }

    #[test]
    fn plan_refcount_zero_on_disk_stops() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-refcount-zero.img") else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeRefcountZero { .. })) => {}
            other => panic!("expected EaInodeRefcountZero stop, got {other:?}"),
        }
    }

    #[test]
    fn plan_value_checksum_mismatch_stops() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-checksum-invalid.img")
        else {
            eprintln!("skipping: fixture absent");
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeChecksumInvalid { .. })) => {}
            other => panic!("expected EaInodeChecksumInvalid stop, got {other:?}"),
        }
    }

    fn read_sb_block_from_overlay(
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
    fn apply_cascade_free_zeros_ea_inode_scratch_and_clears_bitmap() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-cascade.img") else {
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs).expect("plan");

        // Find the EA inode number from the plan.
        let (&ea_inum, _) = plan.actions.iter().next().expect("one action");

        let sb_bytes = read_sb_block_from_overlay(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);
        apply_ea_inode_plan(&ext, &mut cursor, &mut mutator, &plan).expect("apply");

        // Verify: EA inode scratch is fully zeroed.
        let mut observed_bytes = [0u8; 128];
        mutator
            .patch_inode_scratch(&mut cursor, ea_inum, |inode_bytes| {
                observed_bytes.copy_from_slice(&inode_bytes[..128]);
                Ok(())
            })
            .expect("read back ea inode scratch");
        assert_eq!(
            observed_bytes, [0u8; 128],
            "EA inode scratch must be zeroed"
        );

        // Verify: at least one block bitmap was scratched (EA data blocks freed).
        assert!(
            mutator.block_bitmap_scratch_count() >= 1,
            "cascade-free must free at least one data block"
        );
    }

    #[test]
    fn plan_ea_inode_with_nested_ibody_xattrs_stops() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-nested-ref.img") else {
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeNestedReference { .. })) => {}
            other => panic!("expected EaInodeNestedReference stop, got {other:?}"),
        }
    }

    #[test]
    fn plan_ea_inode_with_shared_external_xattr_block_stops() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-shared-xattr.img") else {
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs) {
            Err(EaInodePlanError::Stop(OrphanStopReason::EaInodeSharedXattrBlock { .. })) => {}
            other => panic!("expected EaInodeSharedXattrBlock stop, got {other:?}"),
        }
    }

    #[test]
    fn apply_set_refcount_patches_refcount_without_bitmap_changes() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-partial.img") else {
            return;
        };
        let ea_refs = build_ea_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_ea_inode_cascade(&ext, &mut cursor, &ea_refs).expect("plan");

        let (&ea_inum, _) = plan.actions.iter().next().expect("one action");

        let sb_bytes = read_sb_block_from_overlay(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);
        apply_ea_inode_plan(&ext, &mut cursor, &mut mutator, &plan).expect("apply");

        // Verify: refcount in scratch = 1 (was 2, decremented by 1 host).
        // EA refcount encoding: (i_ctime << 32) | osd1. For refcount=1, i_ctime=0, osd1=1.
        let mut observed_ctime = u32::MAX;
        let mut observed_osd1 = u32::MAX;
        mutator
            .patch_inode_scratch(&mut cursor, ea_inum, |inode_bytes| {
                observed_ctime = u32::from_le_bytes(inode_bytes[0x0C..0x10].try_into().unwrap());
                observed_osd1 = u32::from_le_bytes(inode_bytes[0x24..0x28].try_into().unwrap());
                Ok(())
            })
            .expect("read back");
        assert_eq!(observed_ctime, 0, "refcount high 32 bits");
        assert_eq!(observed_osd1, 1, "refcount low 32 bits = 1 after decrement");

        // No data blocks freed — only refcount patched.
        assert_eq!(
            mutator.block_bitmap_scratch_count(),
            0,
            "partial decrement must not free data blocks"
        );
    }

    /// Locks in the bigalloc invariant for depth > 0 EA-inode extent trees:
    /// internal extent-tree index blocks must be emitted as
    /// `AllocationKind::Metadata` (not `Data`), and leaf extents must
    /// preserve their `ee_block`-derived `logical_cluster_start`. Without
    /// this tagging, `Mutator::free_allocations` would either raise a
    /// spurious `BigallocClusterOverlap` (because two index blocks sharing
    /// a physical cluster look like conflicting `Data { logical_cluster: 0
    /// }` runs) or mask a real cross-leaf physical-cluster collision
    /// (because every leaf would degrade to `logical_cluster: 0`).
    ///
    /// The test drives the depth > 0 branch end-to-end: build a synthetic
    /// bigalloc Ext, plant a depth-1 EA inode, enumerate its allocations,
    /// and feed the result to `free_allocations` over a pre-seeded
    /// cluster bitmap. The four-entry expected `AllocationRun` shape
    /// asserts the tagging directly; the post-free bitmap assertions
    /// verify the cluster-granularity bookkeeping is also correct.
    #[test]
    fn enumerate_ea_inode_data_blocks_tags_index_blocks_as_metadata_on_bigalloc_depth1() {
        use crate::checksum::ChecksumState;
        use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
        use crate::orphan::mutator::Mutator;
        use std::io::Cursor;

        const EXTENT_MAGIC: u16 = 0xF30A;
        const BLOCK_SIZE: u64 = 4096;
        const BLOCKS_PER_CLUSTER: u32 = 4;
        const TOTAL_BLOCKS: u64 = 1000;
        const EA_INUM: u32 = 12;

        // Synthetic bigalloc Ext modeled on
        // truncate::tests::ext_for_extent_tests, with cluster_size=16384,
        // blocks_per_cluster=4, BIGALLOC enabled. Inode-table block 3 holds
        // EA inode 12 at byte offset 3*4096 + 11*256 = 15104. Block bitmap
        // is at block 1; nothing in {1, 2, 3..65} collides with the
        // synthetic data/index blocks {100..103, 200, 201, 300..303}.
        let ext = Box::leak(Box::new(crate::ext::Ext {
            inodes_count: 1000,
            blocks_count: TOTAL_BLOCKS,
            block_size: BLOCK_SIZE as u32,
            group_count: 1,
            inodes_per_group: 1000,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                BLOCK_SIZE as u32,
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
            cluster_size: BLOCK_SIZE as u32 * BLOCKS_PER_CLUSTER,
            blocks_per_cluster: BLOCKS_PER_CLUSTER,
            clusters_per_group: 32768 / BLOCKS_PER_CLUSTER,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: IncompatFeatures::empty(),
            ro_compat: RoCompatFeatures::BIGALLOC,
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
        }));
        assert!(ext.has_bigalloc(), "synthetic ext must be bigalloc");

        // Build a depth-1 extent tree directly into the overlay. Root in
        // i_block has two index entries pointing at leaf blocks 200, 201.
        // Leaf A (phys 200): ee_block=0,  ee_len=4, ee_start=100 (data 100..103)
        // Leaf B (phys 201): ee_block=4,  ee_len=4, ee_start=300 (data 300..303)
        let mut i_block = [0u8; 60];
        i_block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        i_block[2..4].copy_from_slice(&2u16.to_le_bytes()); // eh_entries
        i_block[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
        i_block[6..8].copy_from_slice(&1u16.to_le_bytes()); // eh_depth = 1

        // (ei_block, leaf_phys, ee_block, ee_len, ee_start_lo) per index slot.
        // Each leaf hosts exactly one extent — that is sufficient to assert
        // both the IndexBlock tagging and the per-leaf logical_cluster_start.
        struct IndexSlot {
            ei_block: u32,
            leaf_phys: u64,
            ee_block: u32,
            ee_len: u16,
            ee_start_lo: u32,
        }
        let index_entries = [
            IndexSlot {
                ei_block: 0,
                leaf_phys: 200,
                ee_block: 0,
                ee_len: 4,
                ee_start_lo: 100,
            },
            IndexSlot {
                ei_block: 4,
                leaf_phys: 201,
                ee_block: 4,
                ee_len: 4,
                ee_start_lo: 300,
            },
        ];

        let mut disk = alloc::vec![0u8; (TOTAL_BLOCKS * BLOCK_SIZE) as usize];

        for (slot, entry) in index_entries.iter().enumerate() {
            let idx_off = 12 + slot * 12;
            i_block[idx_off..idx_off + 4].copy_from_slice(&entry.ei_block.to_le_bytes());
            i_block[idx_off + 4..idx_off + 8]
                .copy_from_slice(&(entry.leaf_phys as u32).to_le_bytes());

            let base = (entry.leaf_phys * BLOCK_SIZE) as usize;
            disk[base..base + 2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
            disk[base + 2..base + 4].copy_from_slice(&1u16.to_le_bytes());
            disk[base + 4..base + 6].copy_from_slice(&340u16.to_le_bytes());
            let eoff = base + 12;
            disk[eoff..eoff + 4].copy_from_slice(&entry.ee_block.to_le_bytes());
            disk[eoff + 4..eoff + 6].copy_from_slice(&entry.ee_len.to_le_bytes());
            disk[eoff + 8..eoff + 12].copy_from_slice(&entry.ee_start_lo.to_le_bytes());
        }

        // Plant the EA inode bytes at the inode-table slot for EA_INUM.
        // Group 0, index = (12-1) = 11, inode_size = 256.
        let itable_base = (3usize * BLOCK_SIZE as usize) + (11 * 256);
        // i_size_lo at 0x04 — set to 32 KiB (8 data blocks, conceptual EA value).
        disk[itable_base + 0x04..itable_base + 0x08]
            .copy_from_slice(&(8u32 * BLOCK_SIZE as u32).to_le_bytes());
        // i_flags at 0x20 — EA_INODE_FL | EXTENTS_FL.
        let flags_bits = (InodeFlags::EA_INODE_FL | InodeFlags::EXTENTS_FL).bits();
        disk[itable_base + 0x20..itable_base + 0x24].copy_from_slice(&flags_bits.to_le_bytes());
        // i_block at 0x28 (depth-1 root).
        disk[itable_base + 0x28..itable_base + 0x28 + 60].copy_from_slice(&i_block);

        // Pre-seed group-0 block bitmap (block 1) with bits 25, 50, 75 set.
        // Bit n lives in byte n/8 at bit position n%8.
        let bitmap_base = (ext.group_descs[0].block_bitmap * BLOCK_SIZE) as usize;
        for &cluster_bit in &[25u32, 50u32, 75u32] {
            let byte = bitmap_base + (cluster_bit as usize) / 8;
            let mask = 1u8 << (cluster_bit % 8);
            disk[byte] |= mask;
        }

        let mut overlay = Cursor::new(disk);

        // Materialize the inode and enumerate its data blocks.
        let inode = ext.inode(&mut overlay, EA_INUM).expect("read EA inode");
        assert!(
            inode.flags().contains(InodeFlags::EA_INODE_FL),
            "EA_INODE_FL must be set on the planted inode"
        );
        let runs = enumerate_ea_inode_data_blocks(ext, &mut overlay, &inode, EA_INUM)
            .expect("enumerate depth-1 EA inode");

        // The tagged walker emits, per index slot: IndexBlock, then the
        // recursed leaf's Data extent. Two slots → 4 entries.
        assert_eq!(runs.len(), 4, "expected 4 runs (2 index + 2 leaves)");

        match runs[0].kind {
            AllocationKind::Metadata => {}
            other => panic!("runs[0] kind = {other:?}, expected Metadata"),
        }
        assert_eq!(runs[0].physical_start, 200);
        assert_eq!(runs[0].block_len, 1);

        match runs[1].kind {
            AllocationKind::Data {
                logical_cluster_start,
            } => assert_eq!(logical_cluster_start, 0, "leaf-A logical cluster"),
            other => panic!("runs[1] kind = {other:?}, expected Data"),
        }
        assert_eq!(runs[1].physical_start, 100);
        assert_eq!(runs[1].block_len, 4);

        match runs[2].kind {
            AllocationKind::Metadata => {}
            other => panic!("runs[2] kind = {other:?}, expected Metadata"),
        }
        assert_eq!(runs[2].physical_start, 201);
        assert_eq!(runs[2].block_len, 1);

        match runs[3].kind {
            AllocationKind::Data {
                logical_cluster_start,
            } => assert_eq!(logical_cluster_start, 1, "leaf-B logical cluster"),
            other => panic!("runs[3] kind = {other:?}, expected Data"),
        }
        assert_eq!(runs[3].physical_start, 300);
        assert_eq!(runs[3].block_len, 4);

        // Drive the runs through Mutator::free_allocations and assert
        // bigalloc bookkeeping. Unique clusters: {25, 50, 75}; the two
        // index blocks share cluster 50 but are both Metadata so the
        // overlap check skips them by design.
        let sb_bytes = alloc::vec![0u8; BLOCK_SIZE as usize];
        let mut mutator = Mutator::new(ext, &sb_bytes);
        mutator
            .free_allocations(&mut overlay, EA_INUM, &runs)
            .expect("free_allocations must not raise BigallocClusterOverlap");

        assert_eq!(
            mutator.total_clusters_freed_for_test(),
            3,
            "expected 3 unique clusters freed"
        );
        assert_eq!(
            mutator.block_bitmap_scratch_count(),
            1,
            "all freed clusters live in group 0 → exactly one bitmap dirtied"
        );

        let bitmap_scratch = mutator
            .block_scratch_bytes_for_test(ext.group_descs[0].block_bitmap)
            .expect("group-0 bitmap scratch must exist");
        for &cluster_bit in &[25u32, 50u32, 75u32] {
            let byte = (cluster_bit as usize) / 8;
            let mask = 1u8 << (cluster_bit % 8);
            assert_eq!(
                bitmap_scratch[byte] & mask,
                0,
                "cluster {cluster_bit} bit must be cleared after free"
            );
        }
    }
}
