//! Xattr block freeing plan for orphan Level-3. See
//! `docs/superpowers/specs/2026-04-24-fs-ext-orphan-level3-design.md` §2.4.
//!
//! Module name is historical; the scope covers every xattr block
//! referenced by Unlinked hosts regardless of `h_refcount`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::checksum::ChecksumState;
use crate::error::ExtError;
use crate::ext::Ext;
use crate::io::{Read, Seek, SeekFrom};
use crate::orphan::mutator::{AllocationKind, AllocationRun, Mutator, MutatorResult};
use crate::orphan::plan::OrphanStopReason;

/// Maximum legal `h_refcount` for an xattr block.
const EXT4_XATTR_REFCOUNT_MAX: u32 = 0x4000_0000;

/// Whether the read xattr-block buffer is shorter than the 32-byte
/// header.
///
/// Extracted so `#[cfg_attr(test, mutants::skip)]` applies only to this
/// comparison: `Ext::open` validates `block_size` ∈ 1024..=65536, so
/// the buffer is always ≥ 1024 and the guard is unreachable. `<`, `==`,
/// and `<=` all evaluate to `false`, making `< -> ==` and `< -> <=`
/// equivalent mutants here. The guard is kept fail-closed so a future
/// caller passing a short buffer still errors cleanly. See
/// `crates/fs-ext/docs/mutation-testing.md`.
#[cfg_attr(test, mutants::skip)]
fn header_buf_too_short(buf: &[u8]) -> bool {
    buf.len() < 32
}

#[derive(Debug)]
pub(crate) struct SharedXattrPlan {
    pub actions: BTreeMap<u64, SharedXattrAction>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SharedXattrAction {
    SetRefcount { new_refcount: u32 },
    FreeBlock,
}

#[derive(Debug)]
pub(crate) enum SharedXattrPlanError {
    Ext(ExtError),
    Stop(OrphanStopReason),
}

impl From<ExtError> for SharedXattrPlanError {
    fn from(err: ExtError) -> Self {
        Self::Ext(err)
    }
}

pub(crate) type SharedXattrPlanResult<T> = core::result::Result<T, SharedXattrPlanError>;

/// Minimal xattr block header fields needed by the planner.
struct XattrBlockHeader {
    h_refcount: u32,
}

/// Read an xattr block from `overlay`, validate its structure and optional
/// checksum, and return the header fields needed by the planner.
///
/// Returns `Err(ExtError::InvalidXattrBlock)` on any structural failure.
fn read_xattr_block_header<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    block: u64,
    blame_inode: u32,
) -> crate::error::Result<XattrBlockHeader> {
    let block_size = ext.block_size() as usize;
    let offset = block * u64::from(ext.block_size());
    overlay.seek(SeekFrom::Start(offset))?;
    let mut buf = alloc::vec![0u8; block_size];
    overlay.read_exact(&mut buf)?;

    // Defensive guard on the 32-byte header. `buf` is sized to
    // `block_size`, which `Ext::open` validates to be 1024..=65536, so
    // this branch is currently unreachable — the issue-#120 audit
    // flags `< -> ==` / `< -> <=` here as equivalent mutants (all three
    // comparisons are `false` for any real block size). Kept as a
    // fail-closed guard against a future caller passing a short buffer.
    if header_buf_too_short(&buf) {
        return Err(ExtError::InvalidXattrBlock {
            inode: blame_inode,
            reason: "block too short for header",
        });
    }

    let h_magic = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if h_magic != crate::xattr::XATTR_MAGIC {
        return Err(ExtError::InvalidXattrBlock {
            inode: blame_inode,
            reason: "bad xattr block magic",
        });
    }

    let h_refcount = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

    let h_blocks = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if h_blocks != 1 {
        return Err(ExtError::InvalidXattrBlock {
            inode: blame_inode,
            reason: "h_blocks must be 1",
        });
    }

    if ext.has_metadata_csum()
        && ext.checksum_seed().is_some_and(|seed| {
            crate::checksum::verify_xattr_block(seed, block, &buf) == ChecksumState::Invalid
        })
    {
        return Err(ExtError::InvalidXattrBlock {
            inode: blame_inode,
            reason: "checksum invalid",
        });
    }

    Ok(XattrBlockHeader { h_refcount })
}

/// Plan the shared xattr block phase for orphan Level-3.
///
/// For each unique xattr block (in ascending block-number order), reads and
/// validates the block header, then decides between `FreeBlock` (when all
/// references are being removed) and `SetRefcount` (when some remain).
///
/// Returns `Err(Stop(...))` on any invariant violation, or
/// `Err(Ext(...))` on an I/O error.
pub(crate) fn plan_shared_xattr_blocks<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    xattr_refs: &BTreeMap<u64, Vec<u32>>,
) -> SharedXattrPlanResult<SharedXattrPlan> {
    let mut plan = SharedXattrPlan {
        actions: BTreeMap::new(),
    };

    for (&block, hosts) in xattr_refs {
        let blame = hosts.first().copied().unwrap_or(0);

        let header = read_xattr_block_header(ext, overlay, block, blame)
            .map_err(SharedXattrPlanError::Ext)?;

        let h_refcount = header.h_refcount;

        if h_refcount == 0 {
            return Err(SharedXattrPlanError::Stop(
                OrphanStopReason::SharedXattrBlockRefcountZero {
                    inode: blame,
                    xattr_block: block,
                },
            ));
        }

        if h_refcount > EXT4_XATTR_REFCOUNT_MAX {
            return Err(SharedXattrPlanError::Stop(
                OrphanStopReason::SharedXattrBlockRefcountOverflow {
                    inode: blame,
                    xattr_block: block,
                    refcount: h_refcount,
                },
            ));
        }

        let count = u32::try_from(hosts.len()).unwrap_or(u32::MAX);
        if count > h_refcount {
            return Err(SharedXattrPlanError::Stop(
                OrphanStopReason::SharedXattrBlockRefcountZero {
                    inode: blame,
                    xattr_block: block,
                },
            ));
        }

        let new_refcount = h_refcount - count;
        let action = if new_refcount == 0 {
            SharedXattrAction::FreeBlock
        } else {
            SharedXattrAction::SetRefcount { new_refcount }
        };
        plan.actions.insert(block, action);
    }

    Ok(plan)
}

/// Apply a `SharedXattrPlan` to the mutator scratch.
///
/// - `SetRefcount`: patches `h_refcount` at offset 0x04 in the xattr block
///   scratch via `mutator.patch_xattr_block`. `finalize` recomputes `h_checksum`.
/// - `FreeBlock`: routes through `mutator.free_allocations` with a one-block
///   `Metadata` run. Bitmap clear marks the block free; the block content is
///   not rewritten.
pub(crate) fn apply_shared_xattr_plan<T: Read + Seek>(
    _ext: &Ext,
    overlay: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &SharedXattrPlan,
    xattr_refs: &BTreeMap<u64, alloc::vec::Vec<u32>>,
) -> MutatorResult<()> {
    for (&xattr_block, &action) in &plan.actions {
        match action {
            SharedXattrAction::SetRefcount { new_refcount } => {
                mutator.patch_xattr_block(overlay, xattr_block, |buf| {
                    // h_refcount at offset 0x04.
                    buf[0x04..0x08].copy_from_slice(&new_refcount.to_le_bytes());
                    Ok(())
                })?;
            }
            SharedXattrAction::FreeBlock => {
                let witness = xattr_refs
                    .get(&xattr_block)
                    .and_then(|hosts| hosts.first().copied())
                    .unwrap_or(0);
                let runs = [AllocationRun {
                    physical_start: xattr_block,
                    block_len: 1,
                    kind: AllocationKind::Metadata,
                }];
                mutator.free_allocations(overlay, witness, &runs)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name)
    }

    fn fixture_available(name: &str) -> bool {
        fixture_path(name).exists()
    }

    fn load_dirty(name: &str) -> Option<(Ext, fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>)> {
        if !fixture_available(name) {
            return None;
        }
        let bytes = std::fs::read(fixture_path(name)).ok()?;
        let mut cursor = fsmnt_testkit::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open_lenient");
        Some((ext, cursor))
    }

    /// Walk the legacy orphan chain and build a map from xattr block number
    /// to the list of host inode numbers referencing it.
    fn build_xattr_refs_from_orphan_chain<T: Read + Seek>(
        ext: &Ext,
        overlay: &mut T,
    ) -> BTreeMap<u64, alloc::vec::Vec<u32>> {
        let mut map: BTreeMap<u64, alloc::vec::Vec<u32>> = BTreeMap::new();
        let head = Ext::read_last_orphan(overlay).expect("read s_last_orphan");
        let mut current = head;
        let mut seen = alloc::collections::BTreeSet::new();

        while current != 0 {
            if !seen.insert(current) {
                break;
            }
            let host = ext.inode(overlay, current).expect("read orphan inode");
            let next = host.raw_i_dtime();

            let block = host.xattr_block_number();
            if block != 0 {
                map.entry(block).or_default().push(current);
            }

            current = next;
        }

        map
    }

    #[test]
    fn plan_exclusive_refcount_one_produces_free_block() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-shared-xattr-exclusive.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs).expect("plan");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(matches!(action, SharedXattrAction::FreeBlock));
    }

    #[test]
    fn plan_shared_refcount_two_with_one_unlinked_produces_set_refcount_one() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-shared-xattr-shared.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs).expect("plan");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(matches!(
            action,
            SharedXattrAction::SetRefcount { new_refcount: 1 }
        ));
    }

    #[test]
    fn plan_refcount_zero_stops() {
        let Some((ext, mut cursor)) =
            load_dirty("ext4-dirty-orphan-shared-xattr-refcount-zero.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs) {
            Err(SharedXattrPlanError::Stop(OrphanStopReason::SharedXattrBlockRefcountZero {
                ..
            })) => {}
            other => panic!("expected SharedXattrBlockRefcountZero, got {other:?}"),
        }
    }

    #[test]
    fn plan_refcount_overflow_stops() {
        let Some((ext, mut cursor)) =
            load_dirty("ext4-dirty-orphan-shared-xattr-refcount-overflow.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        match plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs) {
            Err(SharedXattrPlanError::Stop(
                OrphanStopReason::SharedXattrBlockRefcountOverflow { refcount, .. },
            )) => {
                assert_eq!(refcount, 0x8000_0000);
            }
            other => panic!("expected SharedXattrBlockRefcountOverflow, got {other:?}"),
        }
    }

    #[test]
    fn plan_count_exceeds_refcount_stops_as_refcount_zero() {
        // Synthetic test: two hosts in the map but xattr block only has refcount=1.
        // Reuse the exclusive fixture (h_refcount=1) and construct xattr_refs with
        // two host inums pointing at the same block.
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-shared-xattr-exclusive.img")
        else {
            return;
        };
        let real_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        let (&block, hosts) = real_refs.iter().next().expect("one block");
        let orphan_host = hosts[0];

        // Build synthetic refs: real orphan host + a fake second host pointing at the same block.
        let mut synthetic = BTreeMap::new();
        synthetic.insert(block, alloc::vec![orphan_host, 99999]);

        match plan_shared_xattr_blocks(&ext, &mut cursor, &synthetic) {
            Err(SharedXattrPlanError::Stop(OrphanStopReason::SharedXattrBlockRefcountZero {
                ..
            })) => {}
            other => {
                panic!("expected SharedXattrBlockRefcountZero (count > refcount), got {other:?}")
            }
        }
    }

    #[test]
    fn shared_xattr_plan_empty_default() {
        let plan = SharedXattrPlan {
            actions: BTreeMap::new(),
        };
        assert!(plan.actions.is_empty());
    }

    fn read_sb_block_from_overlay(
        ext: &Ext,
        cursor: &mut fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>,
    ) -> alloc::vec::Vec<u8> {
        use crate::io::SeekFrom;
        let sb_block: u64 = u64::from(ext.block_size() <= 1024);
        let mut sb_bytes = alloc::vec![0u8; ext.block_size() as usize];
        cursor
            .seek(SeekFrom::Start(sb_block * u64::from(ext.block_size())))
            .expect("seek sb");
        cursor.read_exact(&mut sb_bytes).expect("read sb host");
        sb_bytes
    }

    #[test]
    fn apply_free_block_registers_metadata_run_on_exclusive_fixture() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-shared-xattr-exclusive.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs).expect("plan");

        let sb_bytes = read_sb_block_from_overlay(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);
        apply_shared_xattr_plan(&ext, &mut cursor, &mut mutator, &plan, &xattr_refs)
            .expect("apply");

        // At least one block bitmap was scratched (the xattr block was freed).
        assert!(
            mutator.block_bitmap_scratch_count() >= 1,
            "FreeBlock must dirty a bitmap"
        );
    }

    #[test]
    fn apply_set_refcount_patches_xattr_block_and_does_not_free_it() {
        let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-shared-xattr-shared.img")
        else {
            return;
        };
        let xattr_refs = build_xattr_refs_from_orphan_chain(&ext, &mut cursor);
        let plan = plan_shared_xattr_blocks(&ext, &mut cursor, &xattr_refs).expect("plan");

        let (&xattr_block, _) = plan.actions.iter().next().expect("one action");

        let sb_bytes = read_sb_block_from_overlay(&ext, &mut cursor);
        let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);
        apply_shared_xattr_plan(&ext, &mut cursor, &mut mutator, &plan, &xattr_refs)
            .expect("apply");

        // No block bitmap scratched (SetRefcount is a patch, not a free).
        assert_eq!(
            mutator.block_bitmap_scratch_count(),
            0,
            "SetRefcount must not free blocks"
        );

        // Read back the xattr block scratch: h_refcount at offset 0x04 must be 1.
        let mut observed_refcount = u32::MAX;
        mutator
            .patch_xattr_block(&mut cursor, xattr_block, |buf| {
                observed_refcount = u32::from_le_bytes(buf[0x04..0x08].try_into().unwrap());
                Ok(())
            })
            .expect("read back xattr block scratch");
        assert_eq!(observed_refcount, 1, "h_refcount decremented from 2 to 1");
    }

    /// Build an in-memory image with one xattr block at `block_nr`
    /// carrying the given `h_refcount`. Block size is 4096 (matching
    /// `Ext::dummy_for_test`).
    fn image_with_xattr_block(
        block_nr: u64,
        h_refcount: u32,
    ) -> fsmnt_testkit::Cursor<alloc::vec::Vec<u8>> {
        let block_size = 4096usize;
        let total = ((usize::try_from(block_nr).expect("the test fixture value fits in usize"))
            + 2)
            * block_size;
        let mut bytes = alloc::vec![0u8; total];
        let base =
            (usize::try_from(block_nr).expect("the test fixture value fits in usize")) * block_size;
        bytes[base..base + 4].copy_from_slice(&crate::xattr::XATTR_MAGIC.to_le_bytes());
        bytes[base + 4..base + 8].copy_from_slice(&h_refcount.to_le_bytes());
        bytes[base + 8..base + 12].copy_from_slice(&1u32.to_le_bytes()); // h_blocks = 1
        fsmnt_testkit::Cursor::new(bytes)
    }

    #[test]
    fn plan_refcount_exactly_at_max_is_not_an_overflow() {
        // EXT4_XATTR_REFCOUNT_MAX is the highest *legal* h_refcount, so
        // the overflow guard is `> MAX`, not `>= MAX`. A block sitting
        // exactly at the cap must still plan a SetRefcount, not stop.
        // (Kills the `> -> >=` mutant on the overflow check.)
        let ext = Ext::dummy_for_test();
        let block_nr = 1u64;
        let mut cursor = image_with_xattr_block(block_nr, EXT4_XATTR_REFCOUNT_MAX);

        let mut xattr_refs: BTreeMap<u64, alloc::vec::Vec<u32>> = BTreeMap::new();
        xattr_refs.insert(block_nr, alloc::vec![5u32]);

        let plan =
            plan_shared_xattr_blocks(ext, &mut cursor, &xattr_refs).expect("max refcount is legal");
        assert_eq!(plan.actions.len(), 1);
        let action = plan.actions.values().next().unwrap();
        assert!(
            matches!(
                action,
                SharedXattrAction::SetRefcount { new_refcount }
                    if *new_refcount == EXT4_XATTR_REFCOUNT_MAX - 1
            ),
            "expected SetRefcount(MAX - 1), got {action:?}",
        );
    }

    #[test]
    fn plan_refcount_one_past_max_overflows() {
        // The complement of the boundary test above: MAX + 1 must stop.
        let ext = Ext::dummy_for_test();
        let block_nr = 1u64;
        let mut cursor = image_with_xattr_block(block_nr, EXT4_XATTR_REFCOUNT_MAX + 1);

        let mut xattr_refs: BTreeMap<u64, alloc::vec::Vec<u32>> = BTreeMap::new();
        xattr_refs.insert(block_nr, alloc::vec![5u32]);

        match plan_shared_xattr_blocks(ext, &mut cursor, &xattr_refs) {
            Err(SharedXattrPlanError::Stop(
                OrphanStopReason::SharedXattrBlockRefcountOverflow { refcount, .. },
            )) => assert_eq!(refcount, EXT4_XATTR_REFCOUNT_MAX + 1),
            other => panic!("expected SharedXattrBlockRefcountOverflow, got {other:?}"),
        }
    }
}
