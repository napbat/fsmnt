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
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size).expect("the test fixture value fits in usize")];

    // Double-indirect 4200: slot 0 → 4201, slot 1 → 4202.
    let base_4200 = usize::try_from(4200u64 * block_size).expect("the test fixture value fits in usize");
    overlay_buf[base_4200..base_4200 + 4].copy_from_slice(&4201u32.to_le_bytes());
    overlay_buf[base_4200 + 4..base_4200 + 8].copy_from_slice(&4202u32.to_le_bytes());

    // Single-indirect 4201: slot 0 → data 5200.
    let base_4201 = usize::try_from(4201u64 * block_size).expect("the test fixture value fits in usize");
    overlay_buf[base_4201..base_4201 + 4].copy_from_slice(&5200u32.to_le_bytes());

    // Single-indirect 4202: slot 0 → data 5201.
    let base_4202 = usize::try_from(4202u64 * block_size).expect("the test fixture value fits in usize");
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

    let target_inum = Ext::read_last_orphan(&mut cursor).expect("read s_last_orphan");
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
/// Root lives in the 60-byte `i_block`:
///   Header: magic=0xF30A, `eh_entries=idx_count`, `eh_max=4`, `eh_depth=1`, `eh_generation=0`
///   Index entries (12 bytes each): (`ei_block`, `leaf_phys_block`)
///
/// Each leaf block is written into the backing buffer at
/// `leaf_phys_block * block_size`.  A leaf block contains:
///   Header: magic, `eh_entries=extents.len()`, `eh_max=340`, `eh_depth=0`, `eh_generation=0`
///   Extent entries: (`ee_block`, `ee_len`, `ee_start_lo`)
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
    i_block[2..4].copy_from_slice(&(u16::try_from(index_entries.len()).expect("the test fixture value fits in u16")).to_le_bytes());
    i_block[4..6].copy_from_slice(&4u16.to_le_bytes());
    i_block[6..8].copy_from_slice(&1u16.to_le_bytes()); // eh_depth = 1
    // eh_generation = 0 (zeroed)

    let mut disk = alloc::vec![0u8; usize::try_from(total_blocks * block_size).expect("the test fixture value fits in usize")];

    for (slot, &(ei_block, leaf_phys, leaf_extents)) in index_entries.iter().enumerate() {
        let idx_off = 12 + slot * 12;
        i_block[idx_off..idx_off + 4].copy_from_slice(&ei_block.to_le_bytes());
        i_block[idx_off + 4..idx_off + 8].copy_from_slice(&(u32::try_from(leaf_phys).expect("the test fixture value fits in u32")).to_le_bytes());
        // ei_leaf_hi = 0

        // Build leaf block at leaf_phys * block_size.
        let base = usize::try_from(leaf_phys * block_size).expect("the test fixture value fits in usize");
        disk[base..base + 2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        disk[base + 2..base + 4].copy_from_slice(&(u16::try_from(leaf_extents.len()).expect("the test fixture value fits in u16")).to_le_bytes());
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

/// Build a minimal `Ext` for extent-tree tests.  `blocks_count` is set large
/// enough for the physical blocks used; `block_size=4096`, no checksums.
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

/// Build `sb_bytes` for use with `Mutator::new` (block-size bytes of zeros).
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
        .copy_from_slice(&(u32::try_from(target_size).expect("the test fixture value fits in u32")).to_le_bytes());

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
    for b in &mut inode_bytes[bitmap_base..bitmap_base + 4096] {
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
        .copy_from_slice(&(u32::try_from(target_size).expect("the test fixture value fits in u32")).to_le_bytes());
    inode_bytes[itable_base + 0x1C..itable_base + 0x20]
        .copy_from_slice(&(20u32 * 8).to_le_bytes());
    let bitmap_base = 4096usize;
    for b in &mut inode_bytes[bitmap_base..bitmap_base + 4096] {
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
    for b in &mut inode_bytes[4096..8192] {
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
    for b in &mut inode_bytes[4096..8192] {
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
    for b in &mut inode_bytes[bitmap_base..bitmap_base + 4096] {
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
