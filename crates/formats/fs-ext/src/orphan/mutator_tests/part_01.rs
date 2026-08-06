use super::*;

#[test]
fn new_mutator_starts_with_empty_scratch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    let mutator = Mutator::new(&ext, &sb_host_block);
    assert!(mutator.blocks.is_empty());
    assert!(mutator.group_tallies.is_empty());
    assert_eq!(mutator.total_clusters_freed, 0);
    assert_eq!(mutator.total_inodes_freed, 0);
    assert_eq!(mutator.sb_host_scratch.len(), ext.block_size() as usize);
}

#[test]
fn patch_superblock_bytes_mutates_sb_host_scratch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let mut sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    sb_host_block[0x1C] = 0xAA;
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    mutator
        .patch_superblock_bytes(|buf| {
            buf[0x1C] = 0xBB;
            Ok(())
        })
        .expect("patch sb");
    assert_eq!(mutator.sb_host_scratch[0x1C], 0xBB);
}

#[test]
fn patch_inode_scratch_seeds_from_overlay_and_records_mutation() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
            inode_bytes[0..2].copy_from_slice(&0u16.to_le_bytes());
            Ok(())
        })
        .expect("patch root inode");

    let (expected_block, _offset, _size) =
        Mutator::inode_table_slot_for_test(&ext, 2).expect("locate inode 2");
    let scratch = mutator
        .blocks
        .get(&expected_block)
        .expect("inode 2 table block present in scratch");
    assert!(matches!(scratch.class, BlockClass::InodeTable { .. }));
    assert!(scratch.mutated_inodes.contains(&2));
}

#[test]
fn patch_inode_scratch_second_patch_sees_first_patch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_inode_scratch(&mut cursor, 2, |bytes| {
            bytes[0x10..0x14].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
            Ok(())
        })
        .expect("first patch");

    let mut observed = 0u32;
    mutator
        .patch_inode_scratch(&mut cursor, 2, |bytes| {
            observed = u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap());
            Ok(())
        })
        .expect("second patch");

    assert_eq!(observed, 0xDEAD_BEEFu32);
}

#[test]
fn adjust_links_count_applies_increment() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    let inum = 2u32;
    let pre = ext
        .inode(&mut cursor, inum)
        .expect("read inode")
        .links_count();

    let result = mutator
        .adjust_inode_links_count(&mut cursor, inum, 1)
        .expect("adjust link count");

    assert_eq!(
        result,
        LinkCountChange::Applied {
            from: pre,
            to: pre + 1,
        }
    );
    assert_eq!(
        scratch_inode_links_count(&mutator, &ext, inum),
        pre + 1,
        "scratch inode bytes must show the incremented count"
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_links_count(&delta, &ext, inum),
        pre + 1,
        "finalized inode bytes must show the incremented count"
    );
}

#[test]
fn adjust_links_count_returns_underflow_without_modifying_bytes() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    let inum = 11u32;
    mutator
        .patch_inode_scratch(&mut cursor, inum, |bytes| {
            bytes[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes());
            Ok(())
        })
        .expect("seed zero link count");

    let result = mutator
        .adjust_inode_links_count(&mut cursor, inum, -1)
        .expect("adjust link count");

    assert_eq!(
        result,
        LinkCountChange::Underflow {
            from: 0,
            would_be_delta: -1,
        }
    );
    assert_eq!(
        scratch_inode_links_count(&mutator, &ext, inum),
        0,
        "underflow must leave scratch inode bytes unchanged"
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_links_count(&delta, &ext, inum),
        0,
        "underflow must leave finalized inode bytes unchanged"
    );
}

#[test]
fn adjust_links_count_underflow_without_existing_scratch_does_not_patch_inode() {
    let mut bytes = crate::test_support::load_clean_ext4_image();
    let mut layout_cursor = fsmnt_testkit::Cursor::new(bytes.clone());
    let ext = Ext::open_lenient(&mut layout_cursor).expect("open ext4.img");
    let inum = 11u32;
    set_inode_links_count_in_image(&mut bytes, &ext, inum, 0);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    let (inode_block, _inode_offset, _inode_size) =
        Mutator::inode_table_slot_for_test(&ext, inum).expect("locate inode");
    let original_block_count = mutator.blocks.len();

    let result = mutator
        .adjust_inode_links_count(&mut cursor, inum, -1)
        .expect("adjust link count");

    assert_eq!(
        result,
        LinkCountChange::Underflow {
            from: 0,
            would_be_delta: -1,
        }
    );
    assert_eq!(
        mutator.blocks.len(),
        original_block_count,
        "underflow without prior scratch must not create any scratch blocks"
    );
    assert!(
        !mutator.blocks.contains_key(&inode_block),
        "underflow must not create an inode-table scratch block"
    );
}

#[test]
fn adjust_links_count_returns_overflow_at_u16_max() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    let inum = 12u32;
    mutator
        .patch_inode_scratch(&mut cursor, inum, |bytes| {
            bytes[0x1A..0x1C].copy_from_slice(&u16::MAX.to_le_bytes());
            Ok(())
        })
        .expect("seed max link count");

    let result = mutator
        .adjust_inode_links_count(&mut cursor, inum, 1)
        .expect("adjust link count");

    assert_eq!(
        result,
        LinkCountChange::Overflow {
            from: u16::MAX,
            would_be_delta: 1,
        }
    );
    assert_eq!(
        scratch_inode_links_count(&mutator, &ext, inum),
        u16::MAX,
        "overflow must leave scratch inode bytes unchanged"
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_links_count(&delta, &ext, inum),
        u16::MAX,
        "overflow must leave finalized inode bytes unchanged"
    );
}

#[test]
fn adjust_links_count_overflow_without_existing_scratch_does_not_patch_inode() {
    let mut bytes = crate::test_support::load_clean_ext4_image();
    let mut layout_cursor = fsmnt_testkit::Cursor::new(bytes.clone());
    let ext = Ext::open_lenient(&mut layout_cursor).expect("open ext4.img");
    let inum = 12u32;
    set_inode_links_count_in_image(&mut bytes, &ext, inum, u16::MAX);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    let (inode_block, _inode_offset, _inode_size) =
        Mutator::inode_table_slot_for_test(&ext, inum).expect("locate inode");
    let original_block_count = mutator.blocks.len();

    let result = mutator
        .adjust_inode_links_count(&mut cursor, inum, 1)
        .expect("adjust link count");

    assert_eq!(
        result,
        LinkCountChange::Overflow {
            from: u16::MAX,
            would_be_delta: 1,
        }
    );
    assert_eq!(
        mutator.blocks.len(),
        original_block_count,
        "overflow without prior scratch must not create any scratch blocks"
    );
    assert!(
        !mutator.blocks.contains_key(&inode_block),
        "overflow must not create an inode-table scratch block"
    );
}

#[test]
fn patch_xattr_block_records_xattr_block_class() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    // Pick any valid block — the mutator doesn't validate content here,
    // only seeds and records the class.
    let block: u64 = 100;
    mutator
        .patch_xattr_block(&mut cursor, block, |buf| {
            buf[0] ^= 0xFF;
            Ok(())
        })
        .expect("patch xattr block");

    let scratch = mutator.blocks.get(&block).expect("scratch present");
    assert!(matches!(scratch.class, BlockClass::XattrBlock));
}

#[test]
fn patch_directory_block_records_directory_block_class() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");

    // Root dir is at block 8 in the standard layout for ext4.img.
    let dir_block = 8u64;
    let parent_inum = 2u32;
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);
    mutator
        .patch_directory_block(&mut cursor, dir_block, parent_inum, |buf| {
            let _ = buf;
            Ok(())
        })
        .expect("patch dir block");

    let scratch = mutator.blocks.get(&dir_block).expect("scratch present");
    assert!(matches!(
        scratch.class,
        BlockClass::DirectoryBlock {
            block,
            parent_inum: 2,
        } if block == dir_block
    ));
}

#[test]
fn dir_append_entry_appends_to_linear_directory() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let original_dir_data = read_block(&ext, &mut cursor, dir_block);
    let original_tail = dir_tail_bytes(&original_dir_data).map(<[u8]>::to_vec);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_append_entry(&mut cursor, parent_inum, 99, b"newfile", 1)
        .expect("append directory entry");
    assert_eq!(outcome, DirReplayOutcome::Applied);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let dir_data = delta
        .blocks
        .get(&dir_block)
        .expect("directory block patched");
    assert!(
        dir_data.windows(7).any(|window| window == b"newfile"),
        "patched directory block must contain the appended name"
    );
    assert_eq!(
        find_raw_dir_entry(dir_data, b"newfile").map(|entry| (entry.inode, entry.file_type)),
        Some((99, 1))
    );
    if let Some(original_tail) = original_tail {
        let tail = dir_tail_bytes(dir_data).expect("dir-tail still present");
        assert_eq!(
            &tail[..8],
            &original_tail[..8],
            "append must preserve the directory checksum tail sentinel"
        );
        if let Some(seed) = ext.checksum_seed() {
            let parent = ext.inode(&mut cursor, parent_inum).expect("read parent");
            assert_eq!(
                crate::checksum::verify_dir_block(
                    seed,
                    parent_inum,
                    parent.generation(),
                    dir_data
                ),
                crate::checksum::ChecksumState::Valid
            );
        }
    }
}

#[test]
fn dir_append_entry_composes_multiple_appends_before_finalize() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    assert_eq!(
        mutator
            .dir_append_entry(&mut cursor, parent_inum, 99, b"first-new", 1)
            .expect("append first entry"),
        DirReplayOutcome::Applied
    );
    assert_eq!(
        mutator
            .dir_append_entry(&mut cursor, parent_inum, 100, b"second-new", 1)
            .expect("append second entry"),
        DirReplayOutcome::Applied
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let dir_data = delta
        .blocks
        .get(&dir_block)
        .expect("directory block patched");
    assert_eq!(
        find_raw_dir_entry(dir_data, b"first-new").map(|entry| (entry.inode, entry.file_type)),
        Some((99, 1)),
        "second append must not overwrite the first appended entry"
    );
    assert_eq!(
        find_raw_dir_entry(dir_data, b"second-new").map(|entry| (entry.inode, entry.file_type)),
        Some((100, 1))
    );
}

#[test]
fn dir_append_entry_rejects_invalid_dir_tail_checksum() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    assert!(
        ext.has_metadata_csum(),
        "test fixture must use metadata checksums"
    );
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let original_dir_data = read_block(&ext, &mut cursor, dir_block);
    let tail = dir_tail_bytes(&original_dir_data).expect("root dir has dir-tail");
    let tail_offset = original_dir_data.len() - tail.len();
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_directory_block(&mut cursor, dir_block, parent_inum, |block| {
            block[tail_offset + 8] ^= 0xFF;
            Ok(())
        })
        .expect("corrupt dir-tail checksum in scratch");

    match mutator.dir_append_entry(&mut cursor, parent_inum, 99, b"newfile", 1) {
        Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry { inode, offset })) => {
            assert_eq!(inode, parent_inum);
            assert_eq!(offset, tail_offset as u64);
        }
        other => panic!("expected structural directory error, got {other:?}"),
    }
}

#[test]
fn dir_append_entry_returns_skipped_htree_for_indexed_directory() {
    let mut bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes.clone());
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    set_inode_flags_in_image(&mut bytes, &ext, 2, crate::inode::InodeFlags::INDEX_FL);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_append_entry(&mut cursor, 2, 99, b"newfile", 1)
        .expect("skip htree directory");
    assert_eq!(outcome, DirReplayOutcome::SkippedHtree);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.blocks.is_empty(),
        "htree skip must not patch directory blocks"
    );
}

#[test]
fn dir_append_entry_observes_parent_flags_from_inode_scratch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let dir_block =
        dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
            let flags_offset = 0x20;
            let existing = u32::from_le_bytes(
                inode_bytes[flags_offset..flags_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            inode_bytes[flags_offset..flags_offset + 4].copy_from_slice(
                &(existing | crate::inode::InodeFlags::INDEX_FL.bits()).to_le_bytes(),
            );
            Ok(())
        })
        .expect("set root INDEX_FL in inode scratch");

    let outcome = mutator
        .dir_append_entry(&mut cursor, 2, 99, b"newfile", 1)
        .expect("skip scratch-indexed directory");
    assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
    assert!(
        !matches!(
            mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
            Some(BlockClass::DirectoryBlock { .. })
        ),
        "htree skip must not patch a directory block"
    );
}

#[test]
fn dir_remove_entry_removes_from_linear_directory() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let original_dir_data = read_block(&ext, &mut cursor, dir_block);
    let original_tail = dir_tail_bytes(&original_dir_data).map(<[u8]>::to_vec);
    let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
        .expect("fixture root has lost+found entry");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_remove_entry(&mut cursor, parent_inum, target.inode, b"lost+found")
        .expect("remove directory entry");
    assert_eq!(outcome, DirReplayOutcome::Applied);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let dir_data = delta
        .blocks
        .get(&dir_block)
        .expect("directory block patched");
    assert_eq!(find_raw_dir_entry(dir_data, b"lost+found"), None);
    if let Some(original_tail) = original_tail {
        let tail = dir_tail_bytes(dir_data).expect("dir-tail still present");
        assert_eq!(
            &tail[..8],
            &original_tail[..8],
            "remove must preserve the directory checksum tail sentinel"
        );
        if let Some(seed) = ext.checksum_seed() {
            let parent = ext.inode(&mut cursor, parent_inum).expect("read parent");
            assert_eq!(
                crate::checksum::verify_dir_block(
                    seed,
                    parent_inum,
                    parent.generation(),
                    dir_data
                ),
                crate::checksum::ChecksumState::Valid
            );
        }
    }
}

#[test]
fn dir_remove_entry_returns_skipped_target_missing_without_patching() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_remove_entry(&mut cursor, 2, 99, b"missing-target")
        .expect("skip missing directory entry");
    assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.blocks.is_empty(),
        "missing target skip must not patch directory blocks"
    );
}

#[test]
fn dir_remove_entry_returns_skipped_when_name_matches_different_inode() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let dir_block =
        dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
    let original_dir_data = read_block(&ext, &mut cursor, dir_block);
    let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
        .expect("fixture root has lost+found entry");
    let wrong_child = 99u32;
    assert_ne!(target.inode, wrong_child);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_remove_entry(&mut cursor, 2, wrong_child, b"lost+found")
        .expect("skip wrong child inode");
    assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.blocks.is_empty(),
        "wrong-inode name match must not patch directory blocks"
    );
}

#[test]
fn dir_remove_entry_returns_skipped_htree_for_indexed_directory() {
    let mut bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes.clone());
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let dir_block =
        dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
    set_inode_flags_in_image(&mut bytes, &ext, 2, crate::inode::InodeFlags::INDEX_FL);
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let outcome = mutator
        .dir_remove_entry(&mut cursor, 2, 11, b"lost+found")
        .expect("skip htree directory");
    assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
    assert!(
        !matches!(
            mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
            Some(BlockClass::DirectoryBlock { .. })
        ),
        "htree skip must not patch a directory block"
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert!(
        delta.blocks.is_empty(),
        "htree skip must not patch directory blocks"
    );
}

#[test]
fn dir_remove_entry_observes_parent_flags_from_inode_scratch() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let dir_block =
        dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
            let flags_offset = 0x20;
            let existing = u32::from_le_bytes(
                inode_bytes[flags_offset..flags_offset + 4]
                    .try_into()
                    .unwrap(),
            );
            inode_bytes[flags_offset..flags_offset + 4].copy_from_slice(
                &(existing | crate::inode::InodeFlags::INDEX_FL.bits()).to_le_bytes(),
            );
            Ok(())
        })
        .expect("set root INDEX_FL in inode scratch");

    let outcome = mutator
        .dir_remove_entry(&mut cursor, 2, 11, b"lost+found")
        .expect("skip scratch-indexed directory");
    assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
    assert!(
        !matches!(
            mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
            Some(BlockClass::DirectoryBlock { .. })
        ),
        "htree skip must not patch a directory block"
    );
}

#[test]
fn dir_remove_entry_composes_with_append_before_finalize() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    assert_eq!(
        mutator
            .dir_append_entry(&mut cursor, parent_inum, 99, b"temporary", 1)
            .expect("append entry"),
        DirReplayOutcome::Applied
    );
    assert_eq!(
        mutator
            .dir_remove_entry(&mut cursor, parent_inum, 99, b"temporary")
            .expect("remove appended entry"),
        DirReplayOutcome::Applied
    );

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let dir_data = delta
        .blocks
        .get(&dir_block)
        .expect("directory block patched");
    assert_eq!(find_raw_dir_entry(dir_data, b"temporary"), None);
}

#[test]
fn dir_remove_entry_clears_inode_for_head_entry_in_later_block() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    let parent_inum = 2u32;
    let first_dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let second_dir_block = first_dir_block + 1;
    let block_size = ext.block_size() as usize;
    let parent_generation = ext
        .inode(&mut cursor, parent_inum)
        .expect("read parent")
        .generation();
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_inode_scratch(&mut cursor, parent_inum, |inode_bytes| {
            inode_bytes[0x04..0x08].copy_from_slice(&(ext.block_size() * 2).to_le_bytes());
            inode_bytes[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
            let extent_len_offset = 0x28 + 12 + 4;
            inode_bytes[extent_len_offset..extent_len_offset + 2]
                .copy_from_slice(&2u16.to_le_bytes());
            Ok(())
        })
        .expect("extend root directory extent in scratch");
    mutator
        .patch_directory_block(&mut cursor, second_dir_block, parent_inum, |block| {
            block.fill(0);
            let tail_offset = block_size - 12;
            write_test_dir_entry(block, 0, 99, u16::try_from(tail_offset).expect("the test fixture value fits in u16"), b"block-head", 1);
            block[tail_offset + 4..tail_offset + 6].copy_from_slice(&12u16.to_le_bytes());
            block[tail_offset + 7] = 0xDE;
            refresh_dir_tail_checksum(
                ext.checksum_seed(),
                parent_inum,
                parent_generation,
                block,
            );
            Ok(())
        })
        .expect("seed synthetic second directory block");

    let outcome = mutator
        .dir_remove_entry(&mut cursor, parent_inum, 99, b"block-head")
        .expect("remove head entry from later block");
    assert_eq!(outcome, DirReplayOutcome::Applied);

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let dir_data = delta
        .blocks
        .get(&second_dir_block)
        .expect("second directory block patched");
    assert_eq!(
        u32::from_le_bytes(dir_data[0..4].try_into().unwrap()),
        0,
        "head-of-block removal must clear the current entry inode"
    );
    assert_eq!(
        u16::from_le_bytes(dir_data[4..6].try_into().unwrap()),
        u16::try_from(block_size - 12 ).expect("the test fixture value fits in u16"),
        "clear-current removal must preserve the entry rec_len"
    );
    assert_eq!(find_raw_dir_entry(dir_data, b"block-head"), None);
}

#[test]
fn dir_remove_entry_rejects_invalid_dir_tail_checksum() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
    assert!(
        ext.has_metadata_csum(),
        "test fixture must use metadata checksums"
    );
    let parent_inum = 2u32;
    let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
        .expect("resolve root directory block");
    let original_dir_data = read_block(&ext, &mut cursor, dir_block);
    let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
        .expect("fixture root has lost+found entry");
    let tail = dir_tail_bytes(&original_dir_data).expect("root dir has dir-tail");
    let tail_offset = original_dir_data.len() - tail.len();
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    mutator
        .patch_directory_block(&mut cursor, dir_block, parent_inum, |block| {
            block[tail_offset + 8] ^= 0xFF;
            Ok(())
        })
        .expect("corrupt dir-tail checksum in scratch");

    match mutator.dir_remove_entry(&mut cursor, parent_inum, target.inode, b"lost+found") {
        Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry { inode, offset })) => {
            assert_eq!(inode, parent_inum);
            assert_eq!(offset, tail_offset as u64);
        }
        other => panic!("expected structural directory error, got {other:?}"),
    }
}

#[test]
fn patch_extent_block_records_owner_inum_and_generation() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let block: u64 = 200;
    mutator
        .patch_extent_block(&mut cursor, block, 42, 0x1234_5678, |buf| {
            buf[0] ^= 0xFF;
            Ok(())
        })
        .expect("patch extent block");

    let scratch = mutator.blocks.get(&block).expect("scratch present");
    match scratch.class {
        BlockClass::ExtentBlock {
            owner_inode,
            owner_generation,
        } => {
            assert_eq!(owner_inode, 42);
            assert_eq!(owner_generation, 0x1234_5678);
        }
        _ => panic!("wrong class"),
    }
}
