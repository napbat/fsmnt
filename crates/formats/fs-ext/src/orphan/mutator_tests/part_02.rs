#[test]
fn patch_orphan_file_block_records_file_inum_and_generation() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let block: u64 = 300;
    mutator
        .patch_orphan_file_block(&mut cursor, block, 7, 0xCAFE_BABE, |buf| {
            buf[0] ^= 0xFF;
            Ok(())
        })
        .expect("patch orphan-file block");

    let scratch = mutator.blocks.get(&block).expect("scratch present");
    match scratch.class {
        BlockClass::OrphanFileBlock {
            file_inode,
            file_generation,
        } => {
            assert_eq!(file_inode, 7);
            assert_eq!(file_generation, 0xCAFE_BABE);
        }
        _ => panic!("wrong class"),
    }
}

#[test]
fn clear_inode_bitmap_bit_tallies_decrement_and_seeds_bitmap_scratch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .clear_inode_bitmap_bit(&mut cursor, 2, false)
        .expect("clear root inode bitmap bit");

    let group = 0u32;
    let bitmap_block = ext.group_descs
        [usize::try_from(group).expect("the test group index fits in usize")]
    .inode_bitmap;
    assert!(mutator.blocks.contains_key(&bitmap_block));
    let tally = mutator.group_tallies.get(&group).expect("group 0 tally");
    assert_eq!(tally.inodes_freed, 1);
    assert_eq!(tally.dirs_freed, 0);
    assert_eq!(mutator.total_inodes_freed, 1);
}

#[test]
fn clear_inode_bitmap_bit_tallies_dir_when_was_dir_true() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .clear_inode_bitmap_bit(&mut cursor, 2, true)
        .expect("clear root dir inode bitmap bit");

    let tally = mutator.group_tallies.get(&0).expect("group 0 tally");
    assert_eq!(tally.dirs_freed, 1);
}

#[test]
fn clear_inode_bitmap_bit_is_idempotent_when_bit_already_clear() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    // The largest inode number on a clean fs is almost certainly free;
    // its bitmap bit is zero.
    let high = ext.inodes_count;
    mutator
        .clear_inode_bitmap_bit(&mut cursor, high, false)
        .expect("no-op when bit already clear");

    // Either no tally was created, or the existing tally shows zero decrements.
    let group = (high - 1) / ext.inodes_per_group;
    let inodes_freed = mutator
        .group_tallies
        .get(&group)
        .map_or(0, |t| t.inodes_freed);
    assert_eq!(inodes_freed, 0);
    assert_eq!(mutator.total_inodes_freed, 0);
}

#[test]
fn free_allocations_non_bigalloc_clears_bits_and_tallies() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let first_data_block = first_data_block_of_root(&ext, &mut cursor)
        .expect("root inode has at least one data block");

    let runs = [AllocationRun {
        physical_start: first_data_block,
        block_len: 1,
        kind: AllocationKind::Data {
            logical_cluster_start: 0,
        },
    }];
    mutator
        .free_allocations(&mut cursor, 2, &runs)
        .expect("free 1 block");

    assert_eq!(mutator.total_clusters_freed, 1);
    let group = u32::try_from(
        (first_data_block - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group),
    )
    .expect("the test fixture value fits in u32");
    let tally = mutator.group_tallies.get(&group).expect("group tally");
    assert_eq!(tally.clusters_freed, 1);
}

#[test]
fn free_allocations_non_bigalloc_dedupes_and_is_idempotent() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let first_data_block = first_data_block_of_root(&ext, &mut cursor)
        .expect("root inode has at least one data block");

    let runs = [AllocationRun {
        physical_start: first_data_block,
        block_len: 1,
        kind: AllocationKind::Data {
            logical_cluster_start: 0,
        },
    }];
    mutator
        .free_allocations(&mut cursor, 2, &runs)
        .expect("first call");
    mutator
        .free_allocations(&mut cursor, 2, &runs)
        .expect("second call is idempotent");

    // Second call must not double-count.
    assert_eq!(mutator.total_clusters_freed, 1);
}

#[test]
fn free_allocations_bigalloc_detects_logical_cluster_overlap() {
    // Synthetic Ext with blocks_per_cluster = 4 → blocks 0..4 share cluster 0.
    let ext = Ext::dummy_for_test_bigalloc(4);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(ext, &sb_host_block);

    let mut dummy_overlay = fsmnt_testkit::Cursor::new(alloc::vec![0u8; 1 << 20]);

    // Two Data runs: physical block 0 from logical cluster 0,
    // physical block 1 from logical cluster 100. Both blocks live in
    // physical cluster 0 (since blocks_per_cluster=4 and first_data_block=0).
    let runs = [
        AllocationRun {
            physical_start: 0,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        },
        AllocationRun {
            physical_start: 1,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 100,
            },
        },
    ];

    match mutator.free_allocations(&mut dummy_overlay, 42, &runs) {
        Err(MutatorError::BigallocClusterOverlap {
            inode,
            cluster,
            first_block,
            second_block,
        }) => {
            assert_eq!(inode, 42);
            assert_eq!(cluster, 0);
            assert_eq!(first_block, 0);
            assert_eq!(second_block, 1);
        }
        other => panic!("expected BigallocClusterOverlap, got {other:?}"),
    }
}

#[test]
fn free_allocations_bigalloc_same_logical_cluster_no_overlap() {
    // Two Data blocks in the same physical cluster, both from the same
    // logical cluster (legitimate bigalloc layout — should NOT trigger overlap).
    // No bitmap clear happens because group_descs is empty in the synthetic Ext;
    // the method bails on the GroupDescriptor lookup. We only want to verify
    // pass 1 didn't trip BigallocClusterOverlap.
    let ext = Ext::dummy_for_test_bigalloc(4);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(ext, &sb_host_block);

    let mut dummy_overlay = fsmnt_testkit::Cursor::new(alloc::vec![0u8; 1 << 20]);

    let runs = [
        AllocationRun {
            physical_start: 0,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        },
        AllocationRun {
            physical_start: 1,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        },
    ];

    // The error MUST NOT be BigallocClusterOverlap.
    let result = mutator.free_allocations(&mut dummy_overlay, 42, &runs);
    match result {
        Err(MutatorError::BigallocClusterOverlap { .. }) => {
            panic!("same-cluster same-logical-cluster runs must NOT overlap");
        }
        // Either pass 2 fails on empty descriptors or short-circuits cleanly.
        Err(MutatorError::Ext(_)) | Ok(()) => {}
    }
}

/// Walk the root inode's extent tree (logical block 0) and return the physical
/// block number of its first data block. The root directory inode (inum 2) always
/// has at least one allocated data block on a non-empty fixture.
///
/// Uses `crate::extent::resolve_extent` — the same walker used in `ExtFile` —
/// rather than hand-rolling iteration. Logical block 0 is sufficient because
/// the tests only need ONE confirmed-allocated physical block.
fn first_data_block_of_root<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    overlay: &mut T,
) -> Option<u64> {
    use crate::inode::InodeFlags;

    let root = ext.inode(overlay, 2).ok()?;
    // Root must use extents (EXTENTS_FL); inline data is not applicable.
    if !root.flags().contains(InodeFlags::EXTENTS_FL) {
        return None;
    }
    let resolved =
        crate::extent::resolve_extent(ext, overlay, 2, root.generation(), &root.i_block(), 0)
            .ok()??;
    Some(resolved.physical_block)
}

#[test]
fn finalize_produces_delta_with_sb_host_override_when_sb_was_patched() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");

    // Seed sb_host_scratch from the actual on-disk sb-host block (block 0 for 4 KiB fs).
    let sb_host_block_num: u64 = u64::from(ext.block_size() <= 1024);
    let mut sb_bytes = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    cursor
        .seek(crate::io::SeekFrom::Start(
            sb_host_block_num * u64::from(ext.block_size()),
        ))
        .expect("seek sb host");
    cursor.read_exact(&mut sb_bytes).expect("read sb host");

    let mut mutator = Mutator::new(&ext, &sb_bytes);
    mutator
        .patch_superblock_bytes(|buf| {
            // Flip a harmless byte — triggers "sb was patched".
            buf[0x68] ^= 0xFF; // s_hash_seed[0] low byte
            Ok(())
        })
        .expect("patch sb");

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(delta.sb_host_override.is_some());
}

#[test]
fn finalize_preserves_sb_host_override_absent_when_no_sb_patches() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_bytes = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mutator = Mutator::new(&ext, &sb_bytes);
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    // No patches were made → override is None.
    assert!(delta.sb_host_override.is_none());
}

// physical_start = u64::MAX with block_len = 2 forces physical_start + off (off=1)
// to overflow u64, exercising the checked_add guard in Pass 1.
#[test]
fn free_allocations_rejects_overflow_physical_start_plus_len() {
    let ext = Ext::dummy_for_test_bigalloc(1);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(ext, &sb_host_block);
    let mut dummy = fsmnt_testkit::Cursor::new(alloc::vec![0u8; 1 << 20]);
    let runs = [AllocationRun {
        physical_start: u64::MAX,
        block_len: 2,
        kind: AllocationKind::Data {
            logical_cluster_start: 0,
        },
    }];
    match mutator.free_allocations(&mut dummy, 42, &runs) {
        Err(MutatorError::Ext(ExtError::BlockOutOfRange { .. })) => {}
        other => panic!("expected BlockOutOfRange, got {other:?}"),
    }
}

#[test]
fn free_allocations_rejects_physical_block_at_blocks_count() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let runs = [AllocationRun {
        physical_start: ext.blocks_count,
        block_len: 1,
        kind: AllocationKind::Data {
            logical_cluster_start: 0,
        },
    }];

    match mutator.free_allocations(&mut cursor, 42, &runs) {
        Err(MutatorError::Ext(ExtError::BlockOutOfRange { block })) => {
            assert_eq!(block, ext.blocks_count);
        }
        other => panic!("expected BlockOutOfRange at blocks_count, got {other:?}"),
    }
}

#[test]
fn mark_block_range_projection_formula_handles_unaligned_starts() {
    let cases = [
        (0, 4, 0, 4, 0, 1),
        (0, 4, 0, 8, 0, 2),
        (0, 4, 2, 4, 0, 2),
        (0, 4, 4, 4, 1, 1),
        (0, 4, 3, 1, 0, 1),
        (0, 8, 6, 4, 0, 2),
        (0, 1, 100, 50, 100, 50),
        (1, 1, 8192, 1, 8191, 1),
    ];

    for (first_data_block, ratio, pblk, block_len, expected_first, expected_count) in cases {
        let (first, count) =
            project_block_range_to_alloc_units(pblk, block_len, ratio, first_data_block)
                .expect("project");
        assert_eq!(
            first, expected_first,
            "first mismatch on {pblk}+{block_len}/{ratio} first_data_block={first_data_block}"
        );
        assert_eq!(
            count, expected_count,
            "count mismatch on {pblk}+{block_len}/{ratio} first_data_block={first_data_block}"
        );
    }

    assert!(matches!(
        project_block_range_to_alloc_units(0, 0, 1, 1),
        Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: 0 }))
    ));
}

#[test]
fn mark_block_range_free_bigalloc_aligned_one_cluster_changes_one_unit() {
    let ext = synthetic_bigalloc_ext(1, 0, 16, false);
    let mut bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_free(&mut cursor, 0, 4)
        .expect("mark cluster free");
    assert_eq!(changed, 1);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let bitmap = finalized_bitmap(&delta, &ext, 0);
    assert!(!decode_block_bitmap_bit(bitmap, 0));
    let gdt = finalized_gdt_block(&delta, &ext, 0);
    assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 11);
}

#[test]
fn mark_block_range_free_bigalloc_mid_cluster_start_changes_two_units() {
    let ext = synthetic_bigalloc_ext(1, 0, 16, false);
    let mut bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 1, true);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_free(&mut cursor, 2, 4)
        .expect("mark unaligned range free");
    assert_eq!(changed, 2);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let bitmap = finalized_bitmap(&delta, &ext, 0);
    assert!(!decode_block_bitmap_bit(bitmap, 0));
    assert!(!decode_block_bitmap_bit(bitmap, 1));
    let gdt = finalized_gdt_block(&delta, &ext, 0);
    assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 12);
}

#[test]
fn mark_block_range_allocated_inside_already_allocated_cluster_changes_zero() {
    let ext = synthetic_bigalloc_ext(1, 0, 16, false);
    let mut bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 1, true);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_allocated(&mut cursor, 5, 1)
        .expect("mark already allocated subrange");
    assert_eq!(changed, 0);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let bitmap = finalized_bitmap(&delta, &ext, 0);
    assert!(decode_block_bitmap_bit(bitmap, 1));
    let gdt = finalized_gdt_block(&delta, &ext, 0);
    assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 10);
}

#[test]
fn mark_block_range_bigalloc_count_direction_matches_alloc_vs_free() {
    let ext = synthetic_bigalloc_ext(1, 0, 16, false);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];

    let mut free_bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut free_bytes, &ext, 0, 0, true);
    let mut free_cursor = fsmnt_testkit::Cursor::new(free_bytes);
    let mut free_mutator = Mutator::new(&ext, &sb_host_block);
    assert_eq!(
        free_mutator
            .mark_block_range_free(&mut free_cursor, 0, 4)
            .expect("mark free"),
        1
    );
    let free_delta = free_mutator.finalize(&mut free_cursor).expect("finalize");
    assert_eq!(
        decode_bg_free_blocks_count(finalized_gdt_block(&free_delta, &ext, 0), &ext, 0),
        11
    );

    let alloc_bytes = synthetic_overlay(&ext);
    let mut alloc_cursor = fsmnt_testkit::Cursor::new(alloc_bytes);
    let mut alloc_mutator = Mutator::new(&ext, &sb_host_block);
    assert_eq!(
        alloc_mutator
            .mark_block_range_allocated(&mut alloc_cursor, 0, 4)
            .expect("mark allocated"),
        1
    );
    let alloc_delta = alloc_mutator.finalize(&mut alloc_cursor).expect("finalize");
    assert_eq!(
        decode_bg_free_blocks_count(finalized_gdt_block(&alloc_delta, &ext, 0), &ext, 0),
        9
    );
}

#[test]
fn mark_block_range_splits_bigalloc_range_across_group_boundary() {
    let ext = synthetic_bigalloc_ext(2, 1, 16, false);
    let mut bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 3, true);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 1, 0, true);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_free(&mut cursor, 13, 8)
        .expect("mark boundary-spanning range free");
    assert_eq!(changed, 2);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(!decode_block_bitmap_bit(
        finalized_bitmap(&delta, &ext, 0),
        3
    ));
    assert!(!decode_block_bitmap_bit(
        finalized_bitmap(&delta, &ext, 1),
        0
    ));
    let gdt = finalized_gdt_block(&delta, &ext, 0);
    assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 11);
    assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 1), 11);
}

#[test]
fn mark_block_range_finalize_recomputes_bitmap_and_group_descriptor_checksums() {
    let ext = synthetic_bigalloc_ext(1, 0, 16, true);
    let seed = ext.checksum_seed.expect("metadata checksum seed");
    let mut bytes = synthetic_overlay(&ext);
    set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = alloc::vec![0u8; usize::try_from(ext.block_size()).expect("the test block size fits in usize")];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_free(&mut cursor, 0, 4)
        .expect("mark cluster free");
    assert_eq!(changed, 1);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let bitmap = finalized_bitmap(&delta, &ext, 0);
    let desc = finalized_group_desc(&delta, &ext, 0);
    let block_bitmap_csum_lo = read_desc_u16(desc, 0x18);
    let block_bitmap_csum_hi = read_desc_u16(desc, 0x38);

    assert_eq!(
        crate::checksum::verify_bitmap_csum(
            seed,
            bitmap,
            block_bitmap_csum_lo,
            Some(block_bitmap_csum_hi),
        ),
        crate::checksum::ChecksumState::Valid
    );
    assert_eq!(
        crate::checksum::verify_group_descriptor(seed, 0, desc),
        crate::checksum::ChecksumState::Valid
    );
}

#[test]
fn mark_block_range_free_clears_bitmap_bits_and_increments_gdp_count() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

    let first_data_block = first_data_block_of_root(&ext, &mut cursor)
        .expect("root inode has at least one data block");
    let group = u32::try_from(first_data_block / u64::from(ext.blocks_per_group))
        .expect("the test fixture value fits in u32");
    let pre_count = ext.group_descs
        [usize::try_from(group).expect("the test group index fits in usize")]
    .free_blocks_count;
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_free(&mut cursor, first_data_block, 1)
        .expect("mark free");
    assert_eq!(changed, 1);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.sb_host_override.is_none(),
        "fast-commit bitmap primitive must not alter superblock tallies"
    );

    let gdt_block = u64::from(ext.first_data_block)
        + 1
        + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
    let gdt_bytes = delta.blocks.get(&gdt_block).expect("gdt dirtied");
    let updated_gdp_free = decode_bg_free_blocks_count(gdt_bytes, &ext, group);
    assert_eq!(updated_gdp_free, pre_count + 1);

    let bitmap_block = ext.group_descs
        [usize::try_from(group).expect("the test group index fits in usize")]
    .block_bitmap;
    let bitmap_bytes = delta.blocks.get(&bitmap_block).expect("bitmap dirtied");
    let bit_in_group = first_data_block - u64::from(group) * u64::from(ext.blocks_per_group);
    assert!(
        !decode_block_bitmap_bit(bitmap_bytes, bit_in_group),
        "bitmap bit for root data block must be cleared"
    );
}

#[test]
fn mark_block_range_allocated_already_allocated_unit_changes_zero() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

    let first_data_block = first_data_block_of_root(&ext, &mut cursor)
        .expect("root inode has at least one data block");
    let group = u32::try_from(first_data_block / u64::from(ext.blocks_per_group))
        .expect("the test fixture value fits in u32");
    let pre_count = ext.group_descs
        [usize::try_from(group).expect("the test group index fits in usize")]
    .free_blocks_count;
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_allocated(&mut cursor, first_data_block, 1)
        .expect("mark allocated");
    assert_eq!(changed, 0);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(delta.sb_host_override.is_none());
    let gdt_block = u64::from(ext.first_data_block)
        + 1
        + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
    let gdt_bytes = delta.blocks.get(&gdt_block).expect("gdt dirtied");
    let updated_gdp_free = decode_bg_free_blocks_count(gdt_bytes, &ext, group);
    assert_eq!(updated_gdp_free, pre_count);
}

const BLOCK_UNINIT: u16 = 0x0002;

fn ext_with_uninitialized_block_bitmap() -> Ext {
    Ext {
        inodes_count: 64,
        blocks_count: 128,
        block_size: 1024,
        group_count: 1,
        inodes_per_group: 4,
        inode_size: 128,
        first_data_block: 1,
        gdt_layout: crate::block_group::GdtLayout::from_parts(
            1,
            1024,
            64,
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
        blocks_per_group: 64,
        cluster_size: 4096,
        blocks_per_cluster: 4,
        clusters_per_group: 16,
        backup_bgs: [0, 0],
        desc_size: 32,
        incompat: crate::feature_flags::IncompatFeatures::empty(),
        ro_compat: crate::feature_flags::RoCompatFeatures::empty(),
        compat: crate::feature_flags::CompatFeatures::empty(),
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
            inode_table: 8,
            block_bitmap: 5,
            inode_bitmap: 6,
            free_blocks_count: 0,
            free_inodes_count: 0,
            flags: BLOCK_UNINIT,
            checksum: crate::checksum::ChecksumState::Unknown,
        }],
        checksum_seed: None,
        superblock_checksum: crate::checksum::ChecksumState::Unknown,
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
        fscrypt_keys: crate::fscrypt::FscryptKeystore::default(),
    }
}

fn stale_uninitialized_bitmap_cursor() -> fsmnt_testkit::Cursor<alloc::vec::Vec<u8>> {
    let mut bytes = alloc::vec![0u8; 128 * 1024];
    bytes[2 * 1024 + 0x12..2 * 1024 + 0x14].copy_from_slice(&BLOCK_UNINIT.to_le_bytes());
    bytes[5 * 1024..6 * 1024].fill(0xFF);
    fsmnt_testkit::Cursor::new(bytes)
}

#[test]
fn mark_block_range_allocated_initializes_stale_uninit_block_bitmap() {
    let ext = ext_with_uninitialized_block_bitmap();
    let mut cursor = stale_uninitialized_bitmap_cursor();
    let sb_host_block = alloc::vec![
        0u8;
        usize::try_from(ext.block_size()).expect("the test block size fits in usize")
    ];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let changed = mutator
        .mark_block_range_allocated(&mut cursor, 9, 1)
        .expect("mark allocated in initialized uninit group");
    assert_eq!(
        changed, 1,
        "stale all-ones bitmap must be ignored for BLOCK_UNINIT"
    );

    let bitmap = &mutator
        .blocks
        .get(&5)
        .expect("block bitmap scratch")
        .content;
    assert!(decode_block_bitmap_bit(bitmap, 0), "super/GDT cluster");
    assert!(
        decode_block_bitmap_bit(bitmap, 1),
        "bitmap/inode-table cluster"
    );
    assert!(
        decode_block_bitmap_bit(bitmap, 2),
        "requested allocated data cluster"
    );
    assert!(
        !decode_block_bitmap_bit(bitmap, 3),
        "unrequested data cluster"
    );
    assert!(decode_block_bitmap_bit(bitmap, 16), "end-of-group padding");
}

#[test]
fn mark_block_range_allocated_initializes_uninit_group_once_per_mutator() {
    let ext = ext_with_uninitialized_block_bitmap();
    let mut cursor = stale_uninitialized_bitmap_cursor();
    let sb_host_block = alloc::vec![
        0u8;
        usize::try_from(ext.block_size()).expect("the test block size fits in usize")
    ];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let first_changed = mutator
        .mark_block_range_allocated(&mut cursor, 9, 1)
        .expect("mark first allocated unit");
    let second_changed = mutator
        .mark_block_range_allocated(&mut cursor, 13, 1)
        .expect("mark second allocated unit");
    assert_eq!(first_changed + second_changed, 2);

    let bitmap = &mutator
        .blocks
        .get(&5)
        .expect("block bitmap scratch")
        .content;
    assert!(decode_block_bitmap_bit(bitmap, 2), "first allocation bit");
    assert!(decode_block_bitmap_bit(bitmap, 3), "second allocation bit");

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let gdt_bytes = delta.blocks.get(&2).expect("gdt dirtied");
    assert_eq!(
        decode_bg_free_blocks_count(gdt_bytes, &ext, 0),
        12,
        "initialized free count 14 minus two allocated units"
    );
}
