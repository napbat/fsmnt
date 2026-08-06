#[test]
fn add_range_returns_requires_metadata_allocation_when_unmapped_crosses_next_leaf_bound() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let left_leaf = 204;
    let right_leaf = 205;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        left_leaf,
        leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
    );
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        right_leaf,
        leaf_block_bytes(ext, &[raw_extent(20, 2, 120, false)], 4, 0),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(10, left_leaf), (20, right_leaf)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(15, 10, 200, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::RequiresMetadataAllocation
    ));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, left_leaf),
        vec![(10, 2, 110, false)]
    );
}

#[test]
fn add_range_partial_remap_splits_extent_and_frees_only_target_old_physical() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let new_pblk = old_pblk + 32;
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(3, 2, new_pblk, false))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![
            (0, 3, old_pblk, false),
            (3, 2, new_pblk, false),
            (5, 5, old_pblk + 5, false),
        ]
    );
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 3
    ));
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 4
    ));
}

#[test]
fn add_range_partial_flag_flip_splits_extent_without_freeing_physical() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(3, 2, 103, true))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 3, 100, false), (3, 2, 103, true), (5, 5, 105, false),]
    );
    assert_eq!(delta.blocks.len(), 1);
}

#[test]
fn add_range_partial_update_grows_tree_when_split_overflows_full_leaf() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, 100, false)], 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(3, 2, 103, true))
            .expect("add range")
    };

    assert!(matches!(outcome, ExtentSurgeryOutcome::Applied));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
    assert_eq!(
        records,
        vec![(0, 3, 100, false), (3, 2, 103, true), (5, 5, 105, false)]
    );
}

#[test]
fn add_range_maps_checksum_failure_to_failed_outcome() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    assert!(
        ext.checksum_seed().is_some(),
        "ext4.img fixture must exercise metadata checksums"
    );
    let leaf_block = 206;
    write_disk_block(
        ext,
        &mut cursor,
        leaf_block,
        &leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
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
            .add_range(TEST_INUM, raw_extent(10, 2, 110, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentBlockChecksumInvalid)
    ));
}

#[test]
fn add_range_maps_child_out_of_range_to_failed_outcome() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, ext.blocks_count)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 1, 100, false))
            .expect("add range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::SiblingBlockOutOfRange)
    ));
}

#[test]
fn add_range_maps_malformed_root_to_failed_outcome() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let mut root = leaf_root(&[], 4);
    root[0..2].copy_from_slice(&0xBEEFu16.to_le_bytes());
    stage_inode_root(ext, &mut cursor, &mut mutator, TEST_INUM, root);

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
fn add_range_rejects_pblk_before_first_data_block() {
    let (ext, mut cursor, mut mutator) = fixture_mutator_with_first_data_block(10);

    let err = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .add_range(TEST_INUM, raw_extent(0, 1, 1, false))
            .expect_err("pblk before first_data_block must be rejected")
    };

    assert!(matches!(err, ExtError::BlockOutOfRange { block: 1 }));
}

#[test]
fn del_range_removes_logical_range_and_frees_physical() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(
            &[
                raw_extent(0, 2, old_pblk, false),
                raw_extent(10, 2, old_pblk + 10, false),
            ],
            4,
        ),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 12);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(10, 2, old_pblk + 10, false)]
    );
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 1
    ));
}

#[test]
fn del_range_partial_overlap_splits_extent() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 3, 4).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 10);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false),]
    );
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 3
    ));
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 4
    ));
}

#[test]
fn del_range_collapses_emptied_leaf_and_frees_index_block() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let index_block = 210;
    let leaf_block = 211;
    mutator
        .mark_block_range_allocated(&mut cursor, index_block, 1)
        .expect("allocate index block");
    mutator
        .mark_block_range_allocated(&mut cursor, leaf_block, 1)
        .expect("allocate leaf block");
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(ext, &[raw_extent(0, 2, old_pblk, false)], 4, 0),
    );
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_block,
        index_block_bytes(ext, &[(0, leaf_block)], 4, 1),
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
        surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 0);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(u16::from_le_bytes(root[2..4].try_into().unwrap()), 0);
    assert_eq!(u16::from_le_bytes(root[6..8].try_into().unwrap()), 0);
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 1
    ));
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, index_block));
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, leaf_block));
}

#[test]
fn del_range_returns_logical_range_invalid_for_overflow_lblk() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 2, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .del_range(TEST_INUM, u32::MAX, u32::MAX)
            .expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::LogicalRangeInvalid {
            lblk: u32::MAX,
            len: 1
        }
    ));
}

#[test]
fn del_range_returns_explicit_shrink_followup_for_task22() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 2, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 1, 1).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 1);
}

#[test]
fn shrink_inode_lowers_i_size_when_extent_end_is_below() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 5, old_pblk, false)], 4),
    );
    stage_inode_size(
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        u64::from(ext.block_size()) * 8,
    );

    {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        let outcome = surgeon.del_range(TEST_INUM, 3, 4).expect("delete range");
        let end_block_exclusive = shrink_end_block_exclusive(&outcome);
        surgeon
            .shrink_inode(TEST_INUM, end_block_exclusive)
            .expect("shrink inode");
    }

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 3, old_pblk, false)]
    );
    assert_eq!(
        finalized_inode_size(&delta.blocks, ext, TEST_INUM),
        u64::from(ext.block_size()) * 3
    );
}

#[test]
fn shrink_inode_all_extents_deleted_lowers_i_size_to_zero() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 2, old_pblk, false)], 4),
    );
    stage_inode_size(
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        u64::from(ext.block_size()) * 2,
    );

    {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        let outcome = surgeon.del_range(TEST_INUM, 0, 1).expect("delete range");
        let end_block_exclusive = shrink_end_block_exclusive(&outcome);
        assert_eq!(end_block_exclusive, 0);
        surgeon
            .shrink_inode(TEST_INUM, end_block_exclusive)
            .expect("shrink inode");
    }

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![]
    );
    assert_eq!(finalized_inode_size(&delta.blocks, ext, TEST_INUM), 0);
}

#[test]
fn shrink_inode_noop_does_not_create_inode_table_patch() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();

    {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .shrink_inode(TEST_INUM, u32::MAX)
            .expect("shrink inode");
    }

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.blocks.is_empty(),
        "no-op shrink must not stage an inode-table patch"
    );
}

#[test]
fn shrink_inode_truncates_high_i_size_bits() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 2, old_pblk, false)], 4),
    );
    stage_inode_size(&mut cursor, &mut mutator, TEST_INUM, 5 * 1024 * 1024 * 1024);

    {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.shrink_inode(TEST_INUM, 2).expect("shrink inode");
    }

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_size(&delta.blocks, ext, TEST_INUM),
        u64::from(ext.block_size()) * 2
    );
}

#[test]
fn shrink_inode_middle_delete_uses_furthest_extent_end() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let original_size = u64::from(ext.block_size()) * 10;
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, old_pblk, false)], 4),
    );
    stage_inode_size(&mut cursor, &mut mutator, TEST_INUM, original_size);

    {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        let outcome = surgeon.del_range(TEST_INUM, 3, 4).expect("delete range");
        let end_block_exclusive = shrink_end_block_exclusive(&outcome);
        assert_eq!(end_block_exclusive, 10);
        surgeon
            .shrink_inode(TEST_INUM, end_block_exclusive)
            .expect("shrink inode");
    }

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false)]
    );
    assert_eq!(
        finalized_inode_size(&delta.blocks, ext, TEST_INUM),
        original_size
    );
}

#[test]
fn del_range_external_leaf_suffix_updates_parent_index_key() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let leaf_block = 212;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_block,
        leaf_block_bytes(
            ext,
            &[
                raw_extent(10, 4, old_pblk, false),
                raw_extent(20, 2, old_pblk + 20, false),
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
        index_root(&[(10, leaf_block)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 10, 11).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 22);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 12);
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, leaf_block),
        vec![(12, 2, old_pblk + 2, false), (20, 2, old_pblk + 20, false)]
    );
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, old_pblk));
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 1
    ));
}

#[test]
fn del_range_middle_split_grows_tree_when_punch_overflows_full_leaf() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 10, old_pblk, false)], 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 3, 4).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::AppliedNeedsShrink { .. }
    ));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let records = finalized_all_leaf_records(&delta.blocks, ext, TEST_INUM, &mut cursor);
    assert_eq!(
        records,
        vec![(0, 3, old_pblk, false), (5, 5, old_pblk + 5, false)]
    );
}

#[test]
fn del_range_spans_external_leaves_and_frees_each_overlap() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    let old_pblk = first_root_data_block(ext, &mut cursor);
    let second_pblk = old_pblk + 32;
    mutator
        .mark_block_range_allocated(&mut cursor, second_pblk, 3)
        .expect("allocate second data run");
    let left_leaf = 213;
    let right_leaf = 214;
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        left_leaf,
        leaf_block_bytes(ext, &[raw_extent(10, 3, old_pblk, false)], 4, 0),
    );
    stage_extent_block(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        right_leaf,
        leaf_block_bytes(ext, &[raw_extent(20, 3, second_pblk, false)], 4, 0),
    );
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(10, left_leaf), (20, right_leaf)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 12, 20).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 23);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let root = finalized_inode_extent_root(&delta.blocks, ext, TEST_INUM);
    assert_eq!(u32::from_le_bytes(root[12..16].try_into().unwrap()), 10);
    assert_eq!(u32::from_le_bytes(root[24..28].try_into().unwrap()), 21);
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, left_leaf),
        vec![(10, 2, old_pblk, false)]
    );
    assert_eq!(
        finalized_extent_block_records(&delta.blocks, right_leaf),
        vec![(21, 2, second_pblk + 1, false)]
    );
    assert!(!finalized_block_bitmap_bit(
        &delta.blocks,
        ext,
        old_pblk + 2
    ));
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, second_pblk));
}

#[test]
fn del_range_maps_checksum_failure_to_failed_outcome() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    assert!(
        ext.checksum_seed().is_some(),
        "ext4.img fixture must exercise metadata checksums"
    );
    let leaf_block = 215;
    write_disk_block(
        ext,
        &mut cursor,
        leaf_block,
        &leaf_block_bytes(ext, &[raw_extent(10, 2, 110, false)], 4, 0),
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
        surgeon.del_range(TEST_INUM, 10, 11).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentBlockChecksumInvalid)
    ));
}

#[test]
fn del_range_maps_child_out_of_range_to_failed_outcome() {
    let (ext, mut cursor, mut mutator) = fixture_mutator();
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        index_root(&[(0, ext.blocks_count)], 4, 1),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 0, 1).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::SiblingBlockOutOfRange)
    ));
}

#[test]
fn del_range_rejects_overlapping_leaf_entries() {
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
        surgeon.del_range(TEST_INUM, 11, 11).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::ExtentHeaderMalformed)
    ));
}

#[test]
fn del_range_free_failure_does_not_patch_extent_tree_scratch() {
    let (ext, mut cursor, mut mutator) = fixture_mutator_with_first_data_block(10);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 2, 1, false)], 4),
    );

    let err = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon
            .del_range(TEST_INUM, 0, 1)
            .expect_err("free below first_data_block must fail")
    };

    assert!(matches!(err, ExtError::BlockOutOfRange { block: 1 }));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 2, 1, false)]
    );
}

#[test]
fn del_range_bigalloc_rejects_prefix_partial_cluster_without_dirtying() {
    assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(0, 0);
}

#[test]
fn del_range_bigalloc_rejects_suffix_partial_cluster_without_dirtying() {
    assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(3, 3);
}

#[test]
fn del_range_bigalloc_rejects_middle_partial_cluster_without_dirtying() {
    assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(1, 2);
}

#[test]
fn del_range_bigalloc_full_cluster_delete_succeeds() {
    let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(&[raw_extent(0, 4, 100, false)], 4),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 0, 3).expect("delete range")
    };

    assert_del_range_applied_needs_shrink(&outcome, 0);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![]
    );
    assert!(!finalized_block_bitmap_bit(&delta.blocks, ext, 100));
}
