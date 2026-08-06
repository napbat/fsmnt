use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;

use crate::error::ExtError;
use crate::ext::Ext;
use crate::io::{Seek as _, SeekFrom};
use crate::orphan::Mutator;
use std::io::Write as _;

use super::{ExtentSurgeon, ExtentSurgeryOutcome, RawExtent};

const EXTENT_MAGIC: u16 = 0xF30A;
const TEST_INUM: u32 = 12;

#[test]
fn decodes_initialized_extent() {
    let raw = [
        0x34, 0x12, 0x00, 0x00, // ee_block
        0x08, 0x00, // ee_len
        0x00, 0x00, // ee_start_hi
        0x78, 0x56, 0x34, 0x12, // ee_start_lo
    ];

    let extent = RawExtent::from_on_disk(&raw);

    assert_eq!(extent.ee_block, 0x1234);
    assert_eq!(extent.ee_len, 8);
    assert_eq!(extent.ee_pblk, 0x1234_5678);
    assert!(!extent.unwritten);
}

#[test]
fn decodes_unwritten_extent_len_without_high_bit() {
    let raw = [
        0x01, 0x00, 0x00, 0x00, // ee_block
        0x05, 0x80, // ee_len with unwritten bit
        0x00, 0x00, // ee_start_hi
        0x02, 0x00, 0x00, 0x00, // ee_start_lo
    ];

    let extent = RawExtent::from_on_disk(&raw);

    assert_eq!(extent.ee_block, 1);
    assert_eq!(extent.ee_len, 5);
    assert_eq!(extent.ee_pblk, 2);
    assert!(extent.unwritten);
}

#[test]
fn decodes_initialized_max_len_boundary() {
    let raw = [
        0x02, 0x00, 0x00, 0x00, // ee_block
        0x00, 0x80, // initialized max len, not unwritten
        0x00, 0x00, // ee_start_hi
        0x03, 0x00, 0x00, 0x00, // ee_start_lo
    ];

    let extent = RawExtent::from_on_disk(&raw);

    assert_eq!(extent.ee_len, 32768);
    assert!(!extent.unwritten);
}

#[test]
fn composes_48_bit_physical_block() {
    let raw = [
        0x00, 0x00, 0x00, 0x00, // ee_block
        0x01, 0x00, // ee_len
        0x34, 0x12, // ee_start_hi
        0x78, 0x56, 0x34, 0x12, // ee_start_lo
    ];

    let extent = RawExtent::from_on_disk(&raw);

    assert_eq!(extent.ee_pblk, 0x1234_1234_5678);
}

#[test]
fn add_range_inserts_into_empty_inode_root() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(ext, &mut cursor, &mut mutator, TEST_INUM, leaf_root(&[], 4));

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 4, 100, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 4, 100, false)]);
}

#[test]
fn add_range_merges_with_left_neighbor_when_all_four_conditions_hold() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 4, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(4, 2, 104, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 6, 100, false)]);
}

#[test]
fn add_range_does_not_merge_when_unwritten_flag_differs() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 4, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(4, 2, 104, true))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 4, 100, false), (4, 2, 104, true)]);
}

#[test]
fn add_range_grows_full_inode_root_into_index_root_with_new_leaf() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
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

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(40, 1, 200, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(
        u16::from_le_bytes(root[6..8].try_into().unwrap()),
        1,
        "depth"
    );
    assert_eq!(
        u16::from_le_bytes(root[2..4].try_into().unwrap()),
        1,
        "entries"
    );
    let child = index_root_first_child(root);
    assert!(
        finalized_block_bitmap_bit(&delta.blocks, ext, child),
        "new leaf block bitmap bit set"
    );
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, child),
        vec![
            (0, 1, 100, false),
            (10, 1, 110, false),
            (20, 1, 120, false),
            (30, 1, 130, false),
            (40, 1, 200, false),
        ]
    );
    assert!(
        verify_finalized_extent_block(&delta.blocks, ext, TEST_INUM, child),
        "new leaf checksum valid"
    );
}

#[test]
fn add_range_splits_full_external_leaf_when_parent_has_room() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let leaf_block = 220;
    mutator
        .mark_block_range_allocated(&mut cursor, leaf_block, 1)
        .expect("allocate leaf block");
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(
            ext,
            &[
                raw_extent(0, 1, 100, false),
                raw_extent(10, 1, 110, false),
                raw_extent(20, 1, 120, false),
                raw_extent(30, 1, 130, false),
            ],
            4,
            0,
        ),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(40, 1, 200, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(
        u16::from_le_bytes(root[2..4].try_into().unwrap()),
        2,
        "entries"
    );
    let mut all = finalized_extent_block_records(&delta.blocks, leaf_block);
    let new_leaf = index_root_second_child(root);
    all.extend(finalized_extent_block_records(&delta.blocks, new_leaf));
    assert_eq!(
        all,
        vec![
            (0, 1, 100, false),
            (10, 1, 110, false),
            (20, 1, 120, false),
            (30, 1, 130, false),
            (40, 1, 200, false),
        ]
    );
    assert!(finalized_block_bitmap_bit(&delta.blocks, ext, new_leaf));
    assert!(verify_finalized_extent_block(
        &delta.blocks,
        ext,
        TEST_INUM,
        new_leaf
    ));
}

#[test]
fn add_range_splits_index_node_when_parent_index_also_full() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let leaves: [u64; 4] = [221, 222, 223, 224];
    let index_block = 225;
    for &block in &leaves {
        mutator
            .mark_block_range_allocated(&mut cursor, block, 1)
            .expect("allocate leaf");
    }
    mutator
        .mark_block_range_allocated(&mut cursor, index_block, 1)
        .expect("allocate index");
    for (idx, &block) in leaves.iter().enumerate() {
        let base = (u32::try_from(idx).expect("the test fixture value fits in u32")) * 10;
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            block,
            leaf_block_bytes(
                ext,
                &[
                    raw_extent(base, 1, 1000 + u64::from(base), false),
                    raw_extent(base + 2, 1, 1002 + u64::from(base), false),
                    raw_extent(base + 4, 1, 1004 + u64::from(base), false),
                    raw_extent(base + 6, 1, 1006 + u64::from(base), false),
                ],
                4,
                0,
            ),
        );
    }
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_block,
        index_block_bytes(
            ext,
            &[
                (0, leaves[0]),
                (10, leaves[1]),
                (20, leaves[2]),
                (30, leaves[3]),
            ],
            4,
            1,
        ),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, index_block)], 4, 2),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(1, 1, 1900, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
    assert!(records.contains(&(1, 1, 1900, false)), "new extent present");
    assert_eq!(records.len(), 17, "16 original + 1 new extent");
    assert!(records.windows(2).all(|w| w[0].0 < w[1].0), "sorted");
}

#[test]
fn add_range_leaf_split_is_cluster_aligned_under_bigalloc() {
    let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
    let leaf_block = 228;
    // Free a low cluster so the metadata-block allocator finds a slot
    // within the bigalloc fixture's cluster-bitmap window.
    mutator
        .mark_block_range_free(&mut cursor, 400, 4)
        .expect("free cluster");
    mutator
        .mark_block_range_allocated(&mut cursor, leaf_block, 1)
        .expect("allocate leaf");
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(
            ext,
            &[
                raw_extent(0, 1, 100, false),
                raw_extent(10, 1, 200, false),
                raw_extent(20, 1, 300, false),
                raw_extent(30, 1, 400, false),
            ],
            4,
            0,
        ),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(40, 1, 500, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    let new_leaf = index_root_second_child(root);
    assert!(
        new_leaf.is_multiple_of(u64::from(ext.blocks_per_cluster)),
        "allocated metadata block must be cluster-aligned: {new_leaf}"
    );
}

#[test]
fn add_range_returns_requires_metadata_allocation_when_depth_would_exceed_max() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    // depth-5 inline root index -> depth-4..depth-1 external index nodes,
    // each full (4 entries), down to a full leaf. A leaf split must cascade
    // up through every full index node and try to grow the depth-5 root,
    // which would push depth to 6.
    let leaf_block = 240u64;
    let spine: [u64; 4] = [241, 242, 243, 244];
    for &block in spine.iter().chain(core::iter::once(&leaf_block)) {
        mutator
            .mark_block_range_allocated(&mut cursor, block, 1)
            .expect("allocate spine block");
    }
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(
            ext,
            &[
                raw_extent(0, 1, 300, false),
                raw_extent(2, 1, 302, false),
                raw_extent(4, 1, 304, false),
                raw_extent(6, 1, 306, false),
            ],
            4,
            0,
        ),
    );
    // spine[0] is depth-4; spine[3] is depth-1 (children are leaves). Each
    // node's filler entries occupy a per-level numeric band so that keys
    // propagated upward by a split never collide with a parent's keys.
    let stubs = |band: u32| [(band + 1, 300u64), (band + 2, 301u64), (band + 3, 302u64)];
    for (level, &block) in spine.iter().enumerate() {
        let depth = u16::try_from(4 - level ).expect("the test fixture value fits in u16");
        let child = if level + 1 < spine.len() {
            spine[level + 1]
        } else {
            leaf_block
        };
        let band = stubs(((u32::try_from(level).expect("the test fixture value fits in u32")) + 1) * 1_000_000);
        stage_extent_block(
            ext,
            &mut cursor,
            &mut mutator,
            TEST_INUM,
            block,
            index_block_bytes(ext, &[(0, child), band[0], band[1], band[2]], 4, depth),
        );
    }
    let root_band = stubs(9_000_000);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(
            &[(0, spine[0]), root_band[0], root_band[1], root_band[2]],
            4,
            5,
        ),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(1, 1, 500, false))
            .expect("add range")
    };

    // The grow cascade allocated several metadata blocks before reaching
    // the depth-5 root and giving up. `apply.rs::stop_current_tx` rolls
    // those back by dropping the per-transaction mutator, so this outcome
    // never leaves orphan metadata blocks behind.
    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::RequiresMetadataAllocation
    ));
}

#[test]
fn del_range_leaf_split_when_punch_overflows_external_leaf() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let leaf_block = 230;
    mutator
        .mark_block_range_allocated(&mut cursor, leaf_block, 1)
        .expect("allocate leaf");
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(
            ext,
            &[
                raw_extent(0, 2, old_pblk, false),
                raw_extent(10, 2, old_pblk + 10, false),
                raw_extent(20, 10, old_pblk + 20, false),
                raw_extent(40, 2, old_pblk + 40, false),
            ],
            4,
            0,
        ),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 24, 25).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::AppliedNeedsShrink { .. }
    ));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
    assert_eq!(
        records,
        vec![
            (0, 2, old_pblk, false),
            (10, 2, old_pblk + 10, false),
            (20, 4, old_pblk + 20, false),
            (26, 4, old_pblk + 26, false),
            (40, 2, old_pblk + 40, false),
        ]
    );
}

#[test]
fn add_range_remap_to_different_pblk_frees_old_physical_and_updates_extent() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let new_pblk = old_pblk + 32;
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 1, new_pblk, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 1, new_pblk, false)]);
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
}

#[test]
fn add_range_flag_flip_in_place() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 4, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 4, 100, true))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 4, 100, true)]);
}

#[test]
fn add_range_noop_when_already_matches() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 4, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 4, 100, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM);
    assert_eq!(records, vec![(0, 4, 100, false)]);
    assert_eq!(delta.blocks.len(), 1);
}

#[test]
fn add_range_rejects_misaligned_pblk_under_bigalloc() {
    let ext = Ext::dummy_for_test_bigalloc(4);
    let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());
    let sb_host_block = vec![0u8; ext.block_size() as usize].into_boxed_slice();
    let mut mutator = Mutator::new(ext, &sb_host_block);
    let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);

    let outcome = surgeon
        .add_range(TEST_INUM, raw_extent(0, 1, 2, false))
        .expect("add range");

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPblkNotClusterAligned)
    ));
}

#[test]
fn add_range_external_leaf_insert_updates_parent_index_key() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let leaf_block = 200;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(10, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 2, 100, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 0);
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, leaf_block),
        vec![(0, 2, 100, false), (10, 2, 110, false)]
    );
}

#[test]
fn add_range_external_leaf_flag_flip_patches_extent_block() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let leaf_block = 201;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(10, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(10, 2, 110, true))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, leaf_block),
        vec![(10, 2, 110, true)]
    );
}

#[test]
fn add_range_rejects_child_depth_mismatch() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let child_block = 202;
    let grandchild_block = 203;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        grandchild_block,
        leaf_block_bytes(ext, &[], 4, 0),
    );
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        child_block,
        index_block_bytes(ext, &[(0, grandchild_block)], 4, 1),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, child_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 1, 100, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
    ));
}

#[test]
fn add_range_rejects_overlapping_leaf_entries() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(
            &[raw_extent(10, 4, 110, false), raw_extent(12, 2, 120, false)],
            4,
        ),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(20, 1, 200, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
    ));
}

#[test]
fn add_range_rejects_unsorted_leaf_entries() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(
            &[raw_extent(20, 1, 120, false), raw_extent(10, 1, 110, false)],
            4,
        ),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(30, 1, 130, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
    ));
}
