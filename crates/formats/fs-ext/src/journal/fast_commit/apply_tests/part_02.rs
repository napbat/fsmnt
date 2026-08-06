#[test]
fn apply_creat_appends_dir_entry_and_increments_links() {
    let (ext, mut cursor) = fixture_ext();
    let parent = 2;
    let child = 20;
    let name = b"fc-created";
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .creat(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.creat, 1);
    assert!(state.plan.warnings.is_empty());
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links + 1
    );
    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
        Some((child, 1))
    );
    assert!(state.modified_inodes.contains(&parent));
    assert!(state.modified_inodes.contains(&child));
}

#[test]
fn apply_creat_with_htree_parent_maintains_index_without_warning() {
    // Issue #116: a CREAT into an htree-indexed parent (inode 21,
    // /htree_dir) is now replayed through the dx-tree instead of
    // emitting a DirectoryReplayFailed { HtreeNotMaintained } warning.
    let (ext, mut cursor) = fixture_ext();
    let parent = 21;
    let child = 20;
    let name = b"fc-htree-add";
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .creat(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.creat, 1);
    assert!(
        state.plan.warnings.is_empty(),
        "htree CREAT must not emit a DirectoryReplayFailed warning"
    );
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links + 1
    );
    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
        Some((child, 1)),
        "the new dentry must be present in the htree parent"
    );
    assert!(
        state.modified_inodes.contains(&parent),
        "the htree parent is now a modified inode"
    );
    assert!(state.modified_inodes.contains(&child));
}

#[test]
fn apply_unlink_with_htree_parent_maintains_index_without_warning() {
    // Issue #116: an UNLINK from an htree-indexed parent removes the
    // dentry through the dx-tree. file_002.txt is inode 23.
    let (ext, mut cursor) = fixture_ext();
    let parent = 21;
    let child = 23;
    let name = b"file_002.txt";

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .unlink(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.unlink, 1);
    assert!(
        state.plan.warnings.is_empty(),
        "htree UNLINK must not emit a DirectoryReplayFailed warning"
    );
    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
        None,
        "the unlinked dentry must be gone from the htree parent"
    );
    assert!(state.modified_inodes.contains(&parent));
}

#[test]
fn apply_creat_with_missing_parent_emits_directory_replay_failed_warning_with_parent_inode_missing()
 {
    let (ext, mut cursor) = fixture_ext();
    let parent = ext.inodes_count + 1;
    let child = 20;

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .creat(parent, child, b"fc-missing-parent")
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.creat, 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::DirectoryReplayFailed {
            parent_inum: parent,
            reason: DirectoryReplayReason::ParentInodeMissing,
        }
    );
    assert!(!state.modified_inodes.contains(&child));
}

#[test]
fn apply_creat_with_link_count_overflow_rolls_back_tx_and_halts() {
    let (ext, mut cursor) = fixture_ext();
    let child = 20;
    set_links_count_in_image(&ext, &mut cursor, child, u16::MAX);
    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .creat(2, child, b"fc-overflow")
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 0);
    assert!(state.composed_overlay.blocks.is_empty());
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::LinkCountOverflow {
            inum,
            current: u16::MAX,
            delta: 1
        }) if *inum == child
    ));
}

#[test]
fn apply_link_increments_link_count_and_appends_entry() {
    let (ext, mut cursor) = fixture_ext();
    let parent = 2;
    let child = 20;
    let name = b"hello-hardlink";
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .link(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.link, 1);
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links + 1
    );
    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
        Some((child, 1))
    );
}

#[test]
fn apply_unlink_removes_entry_and_decrements_links() {
    let (ext, mut cursor) = fixture_ext();
    let parent = 2;
    let child = 20;
    let name = b"hello.txt";
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .unlink(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.unlink, 1);
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links - 1
    );
    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, parent, name),
        None
    );
    assert!(state.modified_inodes.contains(&parent));
    assert!(state.modified_inodes.contains(&child));
}

#[test]
fn apply_unlink_with_target_missing_emits_unlink_target_missing_warning() {
    let (ext, mut cursor) = fixture_ext();
    let child = 20;
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .unlink(2, child, b"missing-link")
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.unlink, 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::UnlinkTargetMissing {
            parent_inum: 2,
            child_inum: child,
        }
    );
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links
    );
    assert!(!state.modified_inodes.contains(&child));
}

#[test]
fn apply_unlink_with_target_missing_prunes_net_neutral_inode_scratch() {
    let (ext, mut cursor) = fixture_ext();
    let child = 20;
    let inode_block = inode_table_block(&ext, child);

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .unlink(2, child, b"missing-link")
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.unlink, 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::UnlinkTargetMissing {
            parent_inum: 2,
            child_inum: child,
        }
    );
    assert!(
        !state.composed_overlay.blocks.contains_key(&inode_block),
        "net-neutral rollback must not emit the inode-table scratch block"
    );
}

#[test]
fn apply_creat_uses_child_mode_from_in_flight_inode_scratch_for_file_type() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let child = 20;
    let name = b"fc-symlink-type";
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, child);
    set_inode_mode(&mut raw, 0xA000 | 0o777);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .inode(child, &raw)
        .creat(2, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(
        raw_dir_entry_from_overlay(&ext, &mut cursor, &state.composed_overlay, 2, name),
        Some((child, 7))
    );
    assert_eq!(state.plan.tag_counts.creat, 1);
}

#[test]
fn apply_creat_parent_precheck_observes_in_flight_inode_scratch_mode() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let parent = 2;
    let child = 20;
    let name = b"fc-parent-now-file";
    let before_links = read_links_count_from_overlay(&ext, &mut cursor, &composed, child);
    let mut raw_parent = raw_inode_from_overlay(&ext, &mut cursor, &composed, parent);
    set_inode_mode(&mut raw_parent, 0x8000 | 0o644);

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .inode(parent, &raw_parent)
        .creat(parent, child, name)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        BS,
        FC_FIRST,
        &scan,
    )
    .expect("apply");

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.inode, 1);
    assert_eq!(state.plan.tag_counts.creat, 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::DirectoryReplayFailed {
            parent_inum: parent,
            reason: DirectoryReplayReason::ParentNotADirectory,
        }
    );
    assert_eq!(
        read_links_count_from_overlay(&ext, &mut cursor, &state.composed_overlay, child),
        before_links
    );
    assert!(!state.modified_inodes.contains(&child));
}

#[test]
fn apply_unlink_with_link_count_underflow_rolls_back_tx_and_halts() {
    let (ext, mut cursor) = fixture_ext();
    let child = 20;
    set_links_count_in_image(&ext, &mut cursor, child, 0);
    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .unlink(2, child, b"hello.txt")
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 0);
    assert!(state.composed_overlay.blocks.is_empty());
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::LinkCountOverflow {
            inum,
            current: 0,
            delta: -1
        }) if *inum == child
    ));
}

mod finalizer {
    use alloc::collections::BTreeSet;

    use super::*;

    fn clear_block_bitmap_bit_in_image(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        pblk: u64,
    ) {
        let group = usize::try_from((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group)
           ).expect("the test fixture value fits in usize");
        let block_in_group =
            (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
        let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
        let bitmap_block = ext.group_descs[group].block_bitmap;
        let byte_offset =
            usize::try_from(bitmap_block).expect("the test fixture value fits in usize") * ext.block_size() as usize + (alloc_unit / 8) as usize;
        let mask = 1u8 << (alloc_unit % 8);
        cursor.get_mut()[byte_offset] &= !mask;
    }

    fn write_disk_block(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        block: u64,
        content: &[u8],
    ) {
        assert_eq!(content.len(), ext.block_size() as usize);
        let offset = usize::try_from(block).expect("the test fixture value fits in usize") * ext.block_size() as usize;
        cursor.get_mut()[offset..offset + content.len()].copy_from_slice(content);
    }

    fn index_root(entries: &[(u32, u64)], max: u16, depth: u16) -> [u8; 60] {
        let mut root = [0u8; 60];
        root[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        root[2..4].copy_from_slice(&(u16::try_from(entries.len()).expect("the test fixture value fits in u16")).to_le_bytes());
        root[4..6].copy_from_slice(&max.to_le_bytes());
        root[6..8].copy_from_slice(&depth.to_le_bytes());
        for (idx, &(logical, child)) in entries.iter().enumerate() {
            write_index_record(&mut root, 12 + idx * 12, logical, child);
        }
        root
    }

    fn leaf_block_bytes(ext: &crate::Ext, extents: &[RawExtent], max: u16) -> Vec<u8> {
        let mut block = alloc::vec![0u8; ext.block_size() as usize];
        block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        block[2..4].copy_from_slice(&(u16::try_from(extents.len()).expect("the test fixture value fits in u16")).to_le_bytes());
        block[4..6].copy_from_slice(&max.to_le_bytes());
        for (idx, extent) in extents.iter().enumerate() {
            write_extent_record(&mut block, 12 + idx * 12, *extent);
        }
        block
    }

    fn write_index_record(buf: &mut [u8], offset: usize, logical: u32, child: u64) {
        buf[offset..offset + 4].copy_from_slice(&logical.to_le_bytes());
        buf[offset + 4..offset + 8].copy_from_slice(&(u32::try_from(child).expect("the test fixture value fits in u32")).to_le_bytes());
        buf[offset + 8..offset + 10].copy_from_slice(&(u16::try_from(child >> 32).expect("the test fixture value fits in u16")).to_le_bytes());
    }

    fn set_inline_data_flag(raw_inode: &mut [u8]) {
        let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
            | crate::inode::InodeFlags::INLINE_DATA_FL.bits();
        raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    }

    fn set_extents_flag(raw_inode: &mut [u8]) {
        let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
            | crate::inode::InodeFlags::EXTENTS_FL.bits();
        raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    }

    fn run_finalizer(
        ext: &crate::Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        mut overlay: BlockOverlay,
        modified_inodes: &BTreeSet<u32>,
        plan: &mut FastCommitPlan,
    ) -> BlockOverlay {
        let sb_host_bytes = overlay.sb_host_block_content.to_vec();
        let mutator = Mutator::new(ext, &sb_host_bytes);
        let mutator = {
            let mut reader = compose_reader(cursor, &overlay);
            finalize_pass(ext, &mut reader, mutator, modified_inodes, plan)
                .expect("pass-C finalizer")
        };
        let delta = {
            let mut reader = compose_reader(cursor, &overlay);
            mutator.finalize(&mut reader).expect("finalize pass-C")
        };
        merge_delta_into_overlay(&mut overlay, delta);
        overlay
    }

    #[test]
    fn finalizer_marks_data_blocks_allocated_for_modified_inodes() {
        let (ext, mut cursor) = fixture_ext();
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
        let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let pblk = first_root_data_block(&ext, &mut cursor) + 32;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 2, pblk, false)], 4));
        set_inode_size(&mut raw, u64::from(BS) * 2);
        write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk + 1);
        assert!(!overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
        assert!(!overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &overlay,
            pblk + 1
        ));

        let mut modified_inodes = BTreeSet::new();
        modified_inodes.insert(inum);
        let mut plan = FastCommitPlan {
            stop: Some(FastCommitStop {
                position: FastCommitPosition {
                    fc_block: FC_FIRST,
                    block_offset: 0,
                    fs_byte_offset: u64::from(FC_FIRST) * u64::from(BS),
                },
                last_committed_tid: Some(TID),
                reason: FastCommitStopReason::RegionExhaustedMidTransaction,
            }),
            ..FastCommitPlan::default()
        };

        let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

        assert!(overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
        assert!(overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &overlay,
            pblk + 1
        ));
        assert_eq!(plan.allocation_units_marked_allocated, 2);
        assert!(plan.stop.is_some(), "pass-C must not clear existing stops");
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn finalizer_marks_internal_index_blocks_allocated() {
        let (mut ext, mut cursor) = fixture_ext();
        ext.checksum_seed = None;
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
        let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let index_block = first_root_data_block(&ext, &mut cursor) + 64;
        let data_pblk = index_block + 4;
        let leaf = leaf_block_bytes(&ext, &[raw_extent(0, 1, data_pblk, false)], 340);
        write_disk_block(&ext, &mut cursor, index_block, &leaf);
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
        set_inode_extent_root(&mut raw, index_root(&[(0, index_block)], 4, 1));
        set_inode_size(&mut raw, u64::from(BS));
        write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, index_block);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, data_pblk);

        let mut modified_inodes = BTreeSet::new();
        modified_inodes.insert(inum);
        let mut plan = FastCommitPlan::default();
        let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

        assert!(overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &overlay,
            index_block
        ));
        assert!(overlay_block_bitmap_bit(
            &ext,
            &mut cursor,
            &overlay,
            data_pblk
        ));
        assert_eq!(plan.allocation_units_marked_allocated, 2);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn finalizer_skips_inline_data_inodes() {
        let (ext, mut cursor) = fixture_ext();
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
        let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
        let inum = 12;
        let pblk = first_root_data_block(&ext, &mut cursor) + 96;
        let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, inum);
        set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, pblk, false)], 4));
        set_inline_data_flag(&mut raw);
        set_inode_size(&mut raw, 0);
        write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);

        let mut modified_inodes = BTreeSet::new();
        modified_inodes.insert(inum);
        let mut plan = FastCommitPlan::default();
        let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

        assert!(!overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
        assert_eq!(plan.allocation_units_marked_allocated, 0);
        assert!(plan.warnings.is_empty());
    }

    #[test]
    fn finalizer_emits_warning_on_corrupt_extent_tree_and_continues_other_inodes() {
        let (ext, mut cursor) = fixture_ext();
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");
        let overlay = classic_overlay_for_fixture(&ext, &mut cursor);
        let corrupt_inum = 12;
        let valid_inum = 13;
        let pblk = first_root_data_block(&ext, &mut cursor) + 128;

        let mut corrupt_raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, corrupt_inum);
        set_inode_mode(&mut corrupt_raw, S_IFREG | 0o644);
        set_extents_flag(&mut corrupt_raw);
        corrupt_raw[0x28..0x2A].copy_from_slice(&0xDEADu16.to_le_bytes());
        write_raw_inode_to_image(&ext, &mut cursor, corrupt_inum, &corrupt_raw);

        let mut valid_raw = raw_inode_from_overlay(&ext, &mut cursor, &overlay, valid_inum);
        set_inode_extent_root(
            &mut valid_raw,
            leaf_root(&[raw_extent(0, 1, pblk, false)], 4),
        );
        set_inode_size(&mut valid_raw, u64::from(BS));
        write_raw_inode_to_image(&ext, &mut cursor, valid_inum, &valid_raw);
        clear_block_bitmap_bit_in_image(&ext, &mut cursor, pblk);

        let modified_inodes = BTreeSet::from([corrupt_inum, valid_inum]);
        let mut plan = FastCommitPlan::default();
        let overlay = run_finalizer(&ext, &mut cursor, overlay, &modified_inodes, &mut plan);

        assert_eq!(plan.warnings.len(), 1);
        assert_eq!(
            plan.warnings[0].kind,
            FastCommitWarningKind::FinalizerExtentWalkFailed { inum: corrupt_inum }
        );
        assert_eq!(plan.warnings[0].occurrences, 1);
        assert!(overlay_block_bitmap_bit(&ext, &mut cursor, &overlay, pblk));
        assert_eq!(plan.allocation_units_marked_allocated, 1);
    }
}
