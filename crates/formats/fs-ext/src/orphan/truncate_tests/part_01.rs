use fsmnt_testkit::Cursor;

use super::*;

#[test]
fn retain_cutoff_zero_size_retains_nothing() {
    assert_eq!(retain_cutoff_logical_cluster(0, 4096), 0);
}

#[test]
fn retain_cutoff_one_byte_retains_one_cluster() {
    assert_eq!(retain_cutoff_logical_cluster(1, 4096), 1);
}

#[test]
fn retain_cutoff_exactly_one_cluster_size_retains_one_cluster() {
    assert_eq!(retain_cutoff_logical_cluster(4096, 4096), 1);
}

#[test]
fn retain_cutoff_one_byte_past_cluster_retains_two() {
    assert_eq!(retain_cutoff_logical_cluster(4097, 4096), 2);
}

#[test]
fn retain_cutoff_bigalloc_16k_cluster() {
    assert_eq!(retain_cutoff_logical_cluster(1, 16384), 1);
    assert_eq!(retain_cutoff_logical_cluster(16384, 16384), 1);
    assert_eq!(retain_cutoff_logical_cluster(16385, 16384), 2);
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

fn load_dirty_fixture(name: &str) -> Option<(Ext, fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>)> {
    let bytes = std::fs::read(fixture_path(name)).ok()?;
    let cursor = fsmnt_testkit::Cursor::new(bytes);
    // We need two cursors: one for open_lenient, one for subsequent ops.
    // Reload so we can pass the same cursor to open_lenient and then use it.
    let bytes2 = std::fs::read(fixture_path(name)).ok()?;
    let mut cursor2 = fsmnt_testkit::Cursor::new(bytes2);
    let ext = Ext::open_lenient(&mut cursor2).expect("open_lenient dirty fixture");
    // Rewind so callers start from the beginning.
    cursor2.set_position(0);
    let _ = cursor; // drop the first cursor
    Some((ext, cursor2))
}

fn read_sb_block(
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
fn complete_truncate_to_zero_frees_every_data_block() {
    let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-truncate-unlink.img")
    else {
        eprintln!("skipping: fixture not available");
        return;
    };

    let target_inum = Ext::read_last_orphan(&mut cursor).expect("read s_last_orphan");
    assert_ne!(target_inum, 0, "fixture must have a chain head");

    let sb_bytes = read_sb_block(&ext, &mut cursor);
    let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);

    complete_truncate(&ext, &mut cursor, &mut mutator, target_inum, 0).expect("truncate to 0");

    // At least one block bitmap was dirtied (blocks were freed).
    assert!(
        mutator.block_bitmap_scratch_count() > 0,
        "truncate-to-zero must dirty at least one block bitmap"
    );
}

#[test]
fn complete_truncate_to_zero_rewrites_extent_header_with_zero_entries() {
    let Some((ext, mut cursor)) = load_dirty_fixture("ext4-dirty-orphan-truncate-unlink.img")
    else {
        eprintln!("skipping: fixture not available");
        return;
    };

    let target_inum = Ext::read_last_orphan(&mut cursor).expect("read s_last_orphan");
    assert_ne!(target_inum, 0, "fixture must have a chain head");

    let sb_bytes = read_sb_block(&ext, &mut cursor);
    let mut mutator = crate::orphan::mutator::Mutator::new(&ext, &sb_bytes);

    complete_truncate(&ext, &mut cursor, &mut mutator, target_inum, 0).expect("truncate to 0");

    // Read back the inode table scratch to verify extent header entries = 0.
    // The inode table scratch should have been seeded and mutated.
    // We can verify this via patch_inode_scratch's side effect — the inode's
    // block table block must be in the scratch set.
    // Use a second patch_inode_scratch call to read back the written header.
    let mut observed_entries = 0u16;
    let mut observed_i_blocks = u32::MAX;
    mutator
        .patch_inode_scratch(&mut cursor, target_inum, |inode_bytes| {
            // eh_entries is at offset 0x28 + 2 within inode bytes.
            observed_entries =
                u16::from_le_bytes(inode_bytes[0x28 + 2..0x28 + 4].try_into().unwrap());
            observed_i_blocks = u32::from_le_bytes(inode_bytes[0x1C..0x20].try_into().unwrap());
            Ok(())
        })
        .expect("read back inode scratch");

    assert_eq!(
        observed_entries, 0,
        "truncated inode must have 0 extent entries"
    );
    assert_eq!(
        observed_i_blocks, 0,
        "truncated inode must have i_blocks = 0"
    );
}

// -------------------------------------------------------------------------
// Synthetic indirect-block-map tests
// -------------------------------------------------------------------------

/// Build a synthetic overlay `Cursor<Vec<u8>>` large enough to hold all the
/// blocks referenced in `pointer_map`. Each entry is `(block_num, pointers)`;
/// `pointers` are written as LE u32s at the start of `block_num * block_size`.
///
/// `total_blocks` sets the size of the backing buffer in filesystem blocks.
fn build_synthetic_overlay(
    total_blocks: u64,
    block_size: u64,
    pointer_map: &[(u64, &[u32])],
) -> Cursor<alloc::vec::Vec<u8>> {
    let size = usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize");
    let mut buf = alloc::vec![0u8; size];
    for &(block_num, ptrs) in pointer_map {
        let base = usize::try_from(block_num * block_size ).expect("the test fixture value fits in usize");
        for (i, &p) in ptrs.iter().enumerate() {
            let off = base + i * 4;
            buf[off..off + 4].copy_from_slice(&p.to_le_bytes());
        }
    }
    Cursor::new(buf)
}

/// Build a synthetic `Ext` with `blocks_count` set high enough for our tests.
fn ext_for_indirect_tests(blocks_count: u64) -> &'static Ext {
    use crate::checksum::ChecksumState;
    use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};
    use alloc::boxed::Box;

    let ext = Box::new(Ext {
        inodes_count: 0,
        blocks_count,
        block_size: 4096,
        group_count: 0,
        inodes_per_group: 1,
        inode_size: 256,
        first_data_block: 0,
        gdt_layout: crate::block_group::GdtLayout::from_parts(
            0,
            4096,
            0,
            32,
            0,
            false,
            false,
            false,
            [0, 0],
            0,
            0,
        )
        .expect("test layout"),
        blocks_per_group: 0,
        cluster_size: 4096,
        blocks_per_cluster: 1,
        clusters_per_group: 0,
        backup_bgs: [0, 0],
        desc_size: 0,
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
        group_descs: alloc::vec![],
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
        fscrypt_keys: crate::fscrypt::FscryptKeystore::default(),
    });
    Box::leak(ext)
}

// --- Test 1: direct pointers only, all past cutoff, free all ---

#[test]
fn indirect_truncate_direct_only_past_cutoff_frees_all() {
    // ppb = 4096 / 4 = 1024
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    // Set up 3 direct block pointers in slots 0, 1, 2 at physical blocks
    // 500, 501, 502.
    let mut i_block = [0u8; 60];
    i_block[0..4].copy_from_slice(&500u32.to_le_bytes());
    i_block[4..8].copy_from_slice(&501u32.to_le_bytes());
    i_block[8..12].copy_from_slice(&502u32.to_le_bytes());

    // Cutoff = 0 → free everything.
    let total_blocks = 600u64;
    let mut overlay = build_synthetic_overlay(total_blocks, block_size, &[]);

    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 0).expect("walk");

    // All 3 direct blocks should be freed as Data runs.
    assert_eq!(result.freed_runs.len(), 3, "expected 3 freed runs");
    let phys: alloc::vec::Vec<u64> =
        result.freed_runs.iter().map(|r| r.physical_start).collect();
    assert!(phys.contains(&500));
    assert!(phys.contains(&501));
    assert!(phys.contains(&502));

    // new_i_block should have zeros in the first 12 bytes.
    assert_eq!(&result.new_i_block[0..12], &[0u8; 12]);
    // Indirect slots still zero.
    assert_eq!(&result.new_i_block[48..60], &[0u8; 12]);
}

// --- Test 2: direct pointers, partial cutoff ---

#[test]
fn indirect_truncate_direct_only_mid_cutoff_partial_free() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    // 12 direct pointers at physical blocks 1000..1012.
    let mut i_block = [0u8; 60];
    for slot in 0..12usize {
        let phys = u32::try_from(1000 + slot ).expect("the test fixture value fits in u32");
        i_block[slot * 4..slot * 4 + 4].copy_from_slice(&phys.to_le_bytes());
    }

    // Cutoff = 6 → logical blocks 0..5 kept, 6..11 freed.
    let mut overlay = build_synthetic_overlay(2000, block_size, &[]);
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 6).expect("walk");

    // 6 blocks freed (lblock 6..11).
    assert_eq!(result.freed_runs.len(), 6);

    // Slots 0..5 intact, slots 6..11 zeroed.
    for slot in 0..6usize {
        let phys = u32::from_le_bytes(
            result.new_i_block[slot * 4..slot * 4 + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(phys, u32::try_from(1000 + slot ).expect("the test fixture value fits in u32"), "slot {slot} should survive");
    }
    for slot in 6..12usize {
        let phys = u32::from_le_bytes(
            result.new_i_block[slot * 4..slot * 4 + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(phys, 0, "slot {slot} should be zeroed");
    }
}

// --- Test 3: single indirect, full free, collapses indirect block ---

#[test]
fn indirect_truncate_single_indirect_full_free_and_collapses_indirect_block() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);
    let ppb = block_size / 4; // 1024

    // Single-indirect block at physical block 2000.
    // It contains 3 data pointers at physical blocks 3000, 3001, 3002.
    let mut i_block = [0u8; 60];
    i_block[48..52].copy_from_slice(&2000u32.to_le_bytes());

    let mut ptrs_buf = alloc::vec![0u32; ppb as usize];
    ptrs_buf[0] = 3000;
    ptrs_buf[1] = 3001;
    ptrs_buf[2] = 3002;
    let ptrs_u32: alloc::vec::Vec<u32> = ptrs_buf.clone();

    // Build overlay: place the indirect block at block 2000.
    let total_blocks = 5000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];
    let base = usize::try_from(2000u64 * block_size ).expect("the test fixture value fits in usize");
    for (i, &p) in ptrs_u32.iter().enumerate() {
        overlay_buf[base + i * 4..base + i * 4 + 4].copy_from_slice(&p.to_le_bytes());
    }
    let mut overlay = Cursor::new(overlay_buf);

    // Cutoff = 12 → lblock 12 (first single-indirect slot) and beyond → free all.
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 12).expect("walk");

    // 3 data runs + 1 metadata run for the indirect block itself.
    assert_eq!(result.freed_runs.len(), 4, "3 data + 1 metadata = 4 runs");
    let metadata_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();
    assert_eq!(
        metadata_runs.len(),
        1,
        "indirect block collapsed to 1 metadata run"
    );
    assert_eq!(metadata_runs[0].physical_start, 2000);

    // Single-indirect pointer slot should be zeroed.
    assert_eq!(&result.new_i_block[48..52], &[0u8; 4]);
}

// --- Test 4: single indirect, partial free, keeps indirect block ---

#[test]
fn indirect_truncate_single_indirect_partial_free_keeps_indirect_block() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);
    let ppb = block_size / 4;

    // Single-indirect block at physical block 2100.
    // Slots 0, 1 have data at 3100, 3101; rest zero.
    let mut i_block = [0u8; 60];
    i_block[48..52].copy_from_slice(&2100u32.to_le_bytes());

    let mut overlay_buf = alloc::vec![0u8; usize::try_from(5000u64 * block_size ).expect("the test fixture value fits in usize")];
    let base = usize::try_from(2100u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base..base + 4].copy_from_slice(&3100u32.to_le_bytes());
    overlay_buf[base + 4..base + 8].copy_from_slice(&3101u32.to_le_bytes());
    let mut overlay = Cursor::new(overlay_buf);

    // Cutoff = 13 → lblock 12 (slot 0 in single-indirect = lblock 12) kept,
    //              lblock 13 (slot 1) freed.
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 13).expect("walk");

    // 1 data run for lblock 13.
    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    assert_eq!(data_runs.len(), 1);
    assert_eq!(data_runs[0].physical_start, 3101);

    // No metadata run — indirect block survives (slot 0 still has data).
    let metadata_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();
    assert_eq!(metadata_runs.len(), 0, "indirect block must NOT be freed");

    // Single-indirect pointer slot should still be non-zero.
    let ptr = u32::from_le_bytes(result.new_i_block[48..52].try_into().unwrap());
    assert_eq!(ptr, 2100, "single-indirect slot must be preserved");

    let _ = ppb;
}

// --- Test 5: double indirect, partial free, frees some child indirect blocks ---

#[test]
fn indirect_truncate_double_indirect_partial_free_frees_some_indirects() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);
    let ppb = block_size / 4; // 1024

    // Double-indirect at physical block 4000.
    // Slot 0 → single-indirect at 4001 (covers lblocks 12+ppb .. 12+ppb+ppb-1 = 12+1024..12+2047)
    //   Wait: double-indirect slot 0 covers [12+ppb .. 12+ppb+ppb-1].
    //   Slot 0 contains single-indirect block 4001.
    //   Slot 1 → single-indirect at 4002.
    // The single-indirect blocks each contain one data pointer.
    // 4001 slot 0 → data block 5000
    // 4002 slot 0 → data block 5001
    //
    // Cutoff = 12+ppb+ppb (= 12 + 1024 + 1024 = 2060).
    // Slot 0 of double-indirect covers [12+ppb, 12+ppb+ppb-1] = [1036, 2059] — entirely before cutoff.
    // Slot 1 of double-indirect covers [12+ppb+ppb, 12+ppb+ppb+ppb-1] = [2060, 3083] — all at/past cutoff.

    let cutoff = 12 + ppb + ppb;

    let mut i_block = [0u8; 60];
    i_block[52..56].copy_from_slice(&4000u32.to_le_bytes());

    let total_blocks = 7000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];

    // Double-indirect block 4000: slot 0 → 4001, slot 1 → 4002.
    let base_4000 = usize::try_from(4000u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_4000..base_4000 + 4].copy_from_slice(&4001u32.to_le_bytes());
    overlay_buf[base_4000 + 4..base_4000 + 8].copy_from_slice(&4002u32.to_le_bytes());

    // Single-indirect 4001: slot 0 → data 5000.
    let base_4001 = usize::try_from(4001u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_4001..base_4001 + 4].copy_from_slice(&5000u32.to_le_bytes());

    // Single-indirect 4002: slot 0 → data 5001.
    let base_4002 = usize::try_from(4002u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_4002..base_4002 + 4].copy_from_slice(&5001u32.to_le_bytes());

    let mut overlay = Cursor::new(overlay_buf);

    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

    // Slot 0 of double-indirect is entirely before cutoff → kept, no runs.
    // Slot 1 of double-indirect is entirely at/past cutoff → 1 data run (5001)
    //   + 1 metadata run (4002 single-indirect) + NOT the double-indirect itself
    //   because slot 0 survives.

    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    assert_eq!(data_runs.len(), 1, "only 1 data block freed");
    assert_eq!(data_runs[0].physical_start, 5001);

    let metadata_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();
    assert_eq!(
        metadata_runs.len(),
        1,
        "single-indirect 4002 freed as metadata"
    );
    assert_eq!(metadata_runs[0].physical_start, 4002);

    // Double-indirect pointer (bytes 52..56) preserved — slot 0 still alive.
    let ptr = u32::from_le_bytes(result.new_i_block[52..56].try_into().unwrap());
    assert_eq!(ptr, 4000, "double-indirect slot preserved");
}

// --- Test 6: triple indirect, full free, collapses all three levels ---

#[test]
fn indirect_truncate_triple_indirect_full_free_collapses_all_three_levels() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);
    let ppb = block_size / 4; // 1024

    // Triple-indirect at physical block 6000.
    // first_lblock = 12 + ppb + ppb² = 12 + 1024 + 1048576 = 1049612
    // Cutoff = 1049612 → entire range freed.
    let cutoff = 12 + ppb + ppb * ppb;

    let mut i_block = [0u8; 60];
    i_block[56..60].copy_from_slice(&6000u32.to_le_bytes());

    let total_blocks = 7000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];

    // Triple-indirect 6000: slot 0 → double-indirect at 6001.
    let base_6000 = usize::try_from(6000u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_6000..base_6000 + 4].copy_from_slice(&6001u32.to_le_bytes());

    // Double-indirect 6001: slot 0 → single-indirect at 6002.
    let base_6001 = usize::try_from(6001u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_6001..base_6001 + 4].copy_from_slice(&6002u32.to_le_bytes());

    // Single-indirect 6002: slot 0 → data at 6003.
    let base_6002 = usize::try_from(6002u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_6002..base_6002 + 4].copy_from_slice(&6003u32.to_le_bytes());

    let mut overlay = Cursor::new(overlay_buf);

    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

    // 1 data run (6003) + 3 metadata runs (6002, 6001, 6000).
    assert_eq!(result.freed_runs.len(), 4);

    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    assert_eq!(data_runs.len(), 1);
    assert_eq!(data_runs[0].physical_start, 6003);

    let metadata_phys: alloc::collections::BTreeSet<u64> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .map(|r| r.physical_start)
        .collect();
    assert!(metadata_phys.contains(&6000));
    assert!(metadata_phys.contains(&6001));
    assert!(metadata_phys.contains(&6002));

    // Triple-indirect slot zeroed.
    assert_eq!(&result.new_i_block[56..60], &[0u8; 4]);
}

// --- Test 7: sparse holes preserved ---

#[test]
fn indirect_truncate_sparse_holes_preserved() {
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    // Slots 0 and 2 have data; slot 1 is a sparse hole (zero).
    let mut i_block = [0u8; 60];
    i_block[0..4].copy_from_slice(&700u32.to_le_bytes()); // lblock 0
    // i_block[4..8] left zero → sparse hole at lblock 1
    i_block[8..12].copy_from_slice(&701u32.to_le_bytes()); // lblock 2

    // Cutoff = 5 → all direct blocks kept (lblocks 0, 2 < 5).
    let mut overlay = build_synthetic_overlay(1000, block_size, &[]);
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 5).expect("walk");

    assert_eq!(
        result.freed_runs.len(),
        0,
        "nothing freed when all blocks before cutoff"
    );

    // Verify slot 0 and 2 preserved, slot 1 still zero.
    let p0 = u32::from_le_bytes(result.new_i_block[0..4].try_into().unwrap());
    let p1 = u32::from_le_bytes(result.new_i_block[4..8].try_into().unwrap());
    let p2 = u32::from_le_bytes(result.new_i_block[8..12].try_into().unwrap());
    assert_eq!(p0, 700);
    assert_eq!(p1, 0, "sparse hole must remain zero");
    assert_eq!(p2, 701);
}

// --- Test 8: malformed pointer beyond blocks_count returns error ---

#[test]
fn indirect_truncate_malformed_pointer_beyond_blocks_count_returns_structural_error() {
    let blocks_count = 500u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    // Direct pointer at slot 0 references block 999 which exceeds blocks_count=500.
    let mut i_block = [0u8; 60];
    i_block[0..4].copy_from_slice(&999u32.to_le_bytes());

    let mut overlay = build_synthetic_overlay(1000, block_size, &[]);

    let err = walk_indirect_map(ext, &mut overlay, 1, &i_block, 0)
        .expect_err("must fail on malformed pointer");

    match err {
        ExtError::InvalidIndirectBlock { inode, .. } => {
            assert_eq!(inode, 1);
        }
        other => panic!("expected InvalidIndirectBlock, got {other:?}"),
    }
}

// --- Test 9: sparse holes only → indirect block must collapse ---

#[test]
fn indirect_truncate_sparse_holes_only_collapses_indirect_block() {
    // Single-indirect block at physical 2200.
    // Slots: [10, 0, 11, 0, 12, <rest zero>].
    // Cutoff = 12 → lblocks 12, 13, 14 (slots 0, 1, 2 of single-indirect
    // covering lblocks 12, 13, 14) are all at/past cutoff.
    //
    // After truncation: real pointers 10/11/12 are freed.
    // The remaining slots are all zero (sparse holes).
    // The indirect block itself must be freed (collapsed).
    // any_kept must be false because zero-slots contribute nothing.
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    let mut i_block = [0u8; 60];
    i_block[48..52].copy_from_slice(&2200u32.to_le_bytes());

    let total_blocks = 5000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];
    let base = usize::try_from(2200u64 * block_size ).expect("the test fixture value fits in usize");
    // slots: [10, 0, 11, 0, 12, rest=0]
    overlay_buf[base..base + 4].copy_from_slice(&10u32.to_le_bytes()); // slot 0 → lblock 12
    // slot 1 stays zero (sparse hole)
    overlay_buf[base + 8..base + 12].copy_from_slice(&11u32.to_le_bytes()); // slot 2 → lblock 14
    // slot 3 stays zero
    overlay_buf[base + 16..base + 20].copy_from_slice(&12u32.to_le_bytes()); // slot 4 → lblock 16
    let mut overlay = Cursor::new(overlay_buf);

    // Cutoff = 12 → all of these lblocks are at/past cutoff → all real pointers freed.
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 12).expect("walk");

    // 3 data runs (10, 11, 12) + 1 metadata run (indirect block 2200).
    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    assert_eq!(data_runs.len(), 3, "3 real data blocks freed");

    let metadata_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();
    assert_eq!(
        metadata_runs.len(),
        1,
        "indirect block 2200 must be collapsed (freed), not kept alive by sparse holes"
    );
    assert_eq!(metadata_runs[0].physical_start, 2200);

    // Single-indirect slot must be zeroed.
    assert_eq!(&result.new_i_block[48..52], &[0u8; 4]);
}

// --- Test 10: partial double-indirect surviving_metadata_blocks ---

#[test]
fn indirect_truncate_partial_double_indirect_i_blocks_counts_surviving_metadata() {
    // Double-indirect at physical 4100.
    // Slot 0 → single-indirect 4101 (covers lblocks [12+ppb .. 12+ppb+ppb-1])
    //   4101 slot 0 → data 5100, slot 1 → data 5101, slot 2 → data 5102, slot 3 → data 5103
    // Slot 1 → single-indirect 4102 (covers lblocks [12+ppb+ppb .. 12+ppb+ppb+ppb-1])
    //   4102 slot 0 → data 5104, slot 1 → data 5105, slot 2 → data 5106, slot 3 → data 5107
    // Rest of double-indirect slots zero.
    //
    // Cutoff = 12 + ppb + ppb*ppb + ppb*ppb*ppb  (far beyond everything → nothing freed).
    // All 8 data blocks survive. Both single-indirect blocks survive.
    // The double-indirect block itself survives.
    // surviving_metadata_blocks = 3 (double-indirect + 2 single-indirects).
    // surviving_data_blocks = 8.
    // total = 11.
    //
    // Verify: IndirectTruncateResult.surviving_metadata_blocks == 3.
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);
    let ppb = block_size / 4; // 1024

    let mut i_block = [0u8; 60];
    i_block[52..56].copy_from_slice(&4100u32.to_le_bytes());

    let total_blocks = 8000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];

    // Double-indirect 4100: slot 0 → 4101, slot 1 → 4102.
    let base_4100 = usize::try_from(4100u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base_4100..base_4100 + 4].copy_from_slice(&4101u32.to_le_bytes());
    overlay_buf[base_4100 + 4..base_4100 + 8].copy_from_slice(&4102u32.to_le_bytes());

    // Single-indirect 4101: slots 0..3 → data 5100..5103.
    let base_4101 = usize::try_from(4101u64 * block_size ).expect("the test fixture value fits in usize");
    for i in 0u32..4 {
        let off = base_4101 + (i as usize) * 4;
        overlay_buf[off..off + 4].copy_from_slice(&(5100u32 + i).to_le_bytes());
    }

    // Single-indirect 4102: slots 0..3 → data 5104..5107.
    let base_4102 = usize::try_from(4102u64 * block_size ).expect("the test fixture value fits in usize");
    for i in 0u32..4 {
        let off = base_4102 + (i as usize) * 4;
        overlay_buf[off..off + 4].copy_from_slice(&(5104u32 + i).to_le_bytes());
    }

    let mut overlay = Cursor::new(overlay_buf);

    // Cutoff far past everything → nothing freed.
    let cutoff = 12 + ppb + ppb * ppb + ppb * ppb * ppb;
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, cutoff).expect("walk");

    // No runs freed.
    assert_eq!(result.freed_runs.len(), 0, "nothing should be freed");

    // surviving_metadata_blocks: double-indirect (4100) + 2 single-indirects (4101, 4102) = 3.
    assert_eq!(
        result.surviving_metadata_blocks, 3,
        "must count double-indirect + 2 single-indirect blocks as surviving metadata"
    );

    // Double-indirect pointer preserved.
    let ptr = u32::from_le_bytes(result.new_i_block[52..56].try_into().unwrap());
    assert_eq!(ptr, 4100, "double-indirect slot preserved");

    let _ = ppb;
}

// --- Test 11: partial single-indirect zeros freed child pointers ---

#[test]
fn indirect_truncate_partial_single_indirect_zeros_freed_child_pointers() {
    // Single-indirect block at physical 2300.
    // Slots 0, 1, 2, 3 → data blocks DATA_A=300, DATA_B=301, DATA_C=302, DATA_D=303.
    // Logical blocks 12, 13, 14, 15 respectively.
    // Cutoff = 14 → keep slots 0 and 1 (lblocks 12, 13), free slots 2 and 3 (lblocks 14, 15).
    //
    // Expected:
    // 1. DATA_C (302) and DATA_D (303) appear in freed_runs as Data.
    // 2. surviving_indirect_patches contains (2300, buf) where buf has
    //    slot 0 (300) and slot 1 (301) preserved and slots 2, 3 zeroed.
    // 3. new_i_block[48..52] still points at 2300 (indirect block survives).
    let blocks_count = 100_000u64;
    let ext = ext_for_indirect_tests(blocks_count);
    let block_size = u64::from(ext.block_size);

    let mut i_block = [0u8; 60];
    i_block[48..52].copy_from_slice(&2300u32.to_le_bytes());

    let total_blocks = 5000u64;
    let mut overlay_buf = alloc::vec![0u8; usize::try_from(total_blocks * block_size ).expect("the test fixture value fits in usize")];
    let base = usize::try_from(2300u64 * block_size ).expect("the test fixture value fits in usize");
    overlay_buf[base..base + 4].copy_from_slice(&300u32.to_le_bytes()); // slot 0 → lblock 12
    overlay_buf[base + 4..base + 8].copy_from_slice(&301u32.to_le_bytes()); // slot 1 → lblock 13
    overlay_buf[base + 8..base + 12].copy_from_slice(&302u32.to_le_bytes()); // slot 2 → lblock 14
    overlay_buf[base + 12..base + 16].copy_from_slice(&303u32.to_le_bytes()); // slot 3 → lblock 15
    let mut overlay = Cursor::new(overlay_buf);

    // Cutoff = 14 → keep lblocks 12, 13; free lblocks 14, 15.
    let result = walk_indirect_map(ext, &mut overlay, 1, &i_block, 14).expect("walk");

    // DATA_C and DATA_D freed.
    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    assert_eq!(data_runs.len(), 2, "2 data blocks freed");
    let data_phys: alloc::collections::BTreeSet<u64> =
        data_runs.iter().map(|r| r.physical_start).collect();
    assert!(data_phys.contains(&302), "DATA_C must be freed");
    assert!(data_phys.contains(&303), "DATA_D must be freed");

    // No metadata run — indirect block survives.
    let metadata_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();
    assert_eq!(
        metadata_runs.len(),
        0,
        "indirect block 2300 must not be freed"
    );

    // Indirect block pointer preserved in new_i_block.
    let ptr = u32::from_le_bytes(result.new_i_block[48..52].try_into().unwrap());
    assert_eq!(ptr, 2300, "single-indirect pointer must be preserved");

    // The surviving indirect block patch must be present.
    assert_eq!(
        result.surviving_indirect_patches.len(),
        1,
        "one surviving indirect block patch"
    );
    let (patch_phys, patch_buf) = &result.surviving_indirect_patches[0];
    assert_eq!(*patch_phys, 2300, "patch is for block 2300");

    // Verify: slots 0 and 1 preserved, slots 2 and 3 zeroed.
    let s0 = u32::from_le_bytes(patch_buf[0..4].try_into().unwrap());
    let s1 = u32::from_le_bytes(patch_buf[4..8].try_into().unwrap());
    let s2 = u32::from_le_bytes(patch_buf[8..12].try_into().unwrap());
    let s3 = u32::from_le_bytes(patch_buf[12..16].try_into().unwrap());
    assert_eq!(s0, 300, "slot 0 preserved");
    assert_eq!(s1, 301, "slot 1 preserved");
    assert_eq!(s2, 0, "slot 2 zeroed (freed child pointer)");
    assert_eq!(s3, 0, "slot 3 zeroed (freed child pointer)");
}
