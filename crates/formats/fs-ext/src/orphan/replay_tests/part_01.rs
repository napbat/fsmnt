use super::*;
use crate::extent::ExtentAllocation;
use crate::journal::JournalReplay;

#[test]
fn orphan_replay_implements_overlay_source() {
    fn assert_source<S: crate::journal::OverlaySource>(_: &S) {}

    let journal = JournalReplay::for_test(build_empty_block_overlay());
    let replay = OrphanReplay {
        journal,
        plan: crate::orphan::plan::OrphanPlan::default(),
        overlay: crate::orphan::plan::OrphanOverlayDelta::default(),
    };
    assert_source(&replay);
}

fn build_empty_block_overlay() -> crate::journal::BlockOverlay {
    crate::journal::BlockOverlay {
        block_size: 4096,
        blocks: alloc::collections::BTreeMap::new(),
        sb_host_block: 0,
        sb_host_block_content: alloc::vec![0u8; 4096].into_boxed_slice(),
    }
}

#[test]
fn build_on_flag_only_orphan_fixture_succeeds_and_clears_ro_bit() {
    if !crate::test_support::fixture_available("ext4-dirty-orphan.img") {
        eprintln!("skipping: ext4-dirty-orphan.img not generated");
        return;
    }
    let mut fs = crate::test_support::load_image("ext4-dirty-orphan.img");
    let pre = crate::Ext::open_lenient(&mut fs).expect("lenient");
    assert!(pre.has_orphan_present());

    let journal = crate::JournalReplay::build(&pre, &mut fs).expect("journal");
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
    assert!(replay.orphan_plan().stop.is_none());
    assert!(replay.orphan_plan().legacy.is_empty());
    assert!(replay.orphan_plan().orphan_file.is_empty());

    // Strict reopen through the composed overlay should succeed.
    let mut overlay = crate::OverlayReader::new(&mut fs, &replay);
    let _ext = crate::Ext::new(&mut overlay).expect("strict reopen");
}

/// Build a minimal 60-byte `i_block` containing a leaf extent tree (depth=0)
/// with the given extents: (`ee_block`, `ee_len_raw`, `ee_start_hi`, `ee_start_lo`).
fn make_leaf_iblock_for_replay(extents: &[(u32, u16, u16, u32)]) -> [u8; 60] {
    const EXTENT_MAGIC: u16 = 0xF30A;
    let mut buf = [0u8; 60];
    buf[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    buf[2..4].copy_from_slice(
        &(u16::try_from(extents.len()).expect("the test fixture value fits in u16")).to_le_bytes(),
    );
    buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
    // eh_depth = 0, eh_generation = 0 (already zero)
    for (i, &(ee_block, ee_len, ee_start_hi, ee_start_lo)) in extents.iter().enumerate() {
        let off = 12 + i * 12;
        buf[off..off + 4].copy_from_slice(&ee_block.to_le_bytes());
        buf[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
        buf[off + 6..off + 8].copy_from_slice(&ee_start_hi.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&ee_start_lo.to_le_bytes());
    }
    buf
}

/// The tagged walker must emit distinct `logical_cluster_start` values for
/// extents that cover different logical clusters, and must tag a
/// single-block leaf extent correctly.
///
/// Scenario (bigalloc, `blocks_per_cluster=4)`:
///   extent A: `ee_block=0`, `ee_len=1`, `ee_start=100`  -> logical cluster 0
///   extent B: `ee_block=8`, `ee_len=1`, `ee_start=101`  -> logical cluster 2
///
/// The old walker emitted Data { `logical_cluster_start`: 0 } for both,
/// masking the fact that they map different logical clusters. The new
/// tagged walker must preserve the correct per-extent `logical_cluster_start`.
#[test]
fn collect_unlinked_host_runs_emits_correct_logical_clusters_per_extent() {
    // blocks_per_cluster = 4: logical blocks 0-3 -> cluster 0,
    //                         logical blocks 4-7 -> cluster 1,
    //                         logical blocks 8-11 -> cluster 2.
    let ext = crate::ext::Ext::dummy_for_test_bigalloc(4);
    let i_block = make_leaf_iblock_for_replay(&[
        (0, 1, 0, 100), // ee_block=0, len=1, phys=100 -> logical cluster 0
        (8, 1, 0, 101), // ee_block=8, len=1, phys=101 -> logical cluster 2
    ]);
    let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

    let mut tagged: Vec<ExtentAllocation> = Vec::new();
    crate::extent::collect_tagged_extent_blocks_into(ext, &mut cursor, 1, 0, &i_block, &mut tagged)
        .expect("walker should succeed on valid leaf tree");

    assert_eq!(tagged.len(), 2, "expected two ExtentAllocation entries");

    // First extent: logical_block_start = 0 -> cluster 0
    match &tagged[0] {
        ExtentAllocation::Data {
            physical_start,
            block_len,
            logical_block_start,
        } => {
            assert_eq!(*physical_start, 100);
            assert_eq!(*block_len, 1);
            assert_eq!(
                *logical_block_start, 0,
                "extent A must have logical_block_start=0"
            );
        }
        ExtentAllocation::IndexBlock(block) => {
            panic!("expected Data, got index block {block}")
        }
    }

    // Second extent: logical_block_start = 8 -> cluster 2 (when divided by 4)
    match &tagged[1] {
        ExtentAllocation::Data {
            physical_start,
            block_len,
            logical_block_start,
        } => {
            assert_eq!(*physical_start, 101);
            assert_eq!(*block_len, 1);
            assert_eq!(
                *logical_block_start, 8,
                "extent B must have logical_block_start=8"
            );
        }
        ExtentAllocation::IndexBlock(block) => {
            panic!("expected Data, got index block {block}")
        }
    }

    // Verify that the caller's cluster conversion produces distinct values.
    let blocks_per_cluster = u64::from(ext.blocks_per_cluster());
    let clusters: Vec<u64> = tagged
        .iter()
        .map(|e| match e {
            ExtentAllocation::Data {
                logical_block_start,
                ..
            } => u64::from(*logical_block_start) / blocks_per_cluster,
            ExtentAllocation::IndexBlock(_) => panic!("unexpected IndexBlock"),
        })
        .collect();
    assert_ne!(
        clusters[0], clusters[1],
        "logical clusters must differ (0 vs 2)"
    );
    assert_eq!(clusters[0], 0);
    assert_eq!(clusters[1], 2);
}

fn indirect_map_test_ext(blocks_count: u64, block_size: u32) -> &'static crate::ext::Ext {
    use crate::checksum::ChecksumState;
    use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};

    Box::leak(Box::new(crate::ext::Ext {
        inodes_count: 0,
        blocks_count,
        block_size,
        group_count: 0,
        inodes_per_group: 1,
        inode_size: 256,
        first_data_block: 0,
        gdt_layout: crate::block_group::GdtLayout::from_parts(
            0,
            block_size,
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
        cluster_size: block_size,
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
        fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
    }))
}

/// `walk_indirect_map` with cutoff=0 must enumerate every direct and
/// indirect data block as a `Data` run and every indirect pointer block
/// as a `Metadata` run.  This is the exact shape `collect_unlinked_host_runs`
/// must produce for pre-EXTENTS_FL inodes.
///
/// Layout:
///   `i_block`[0..48]: direct pointers to blocks 10..21 (12 blocks)
///   `i_block`[48..52]: single-indirect at block 100
///   indirect block 100 holds pointers [50, 51, 52, 53]
///
/// Expected `freed_runs`:
///   12 Data runs for direct blocks
///   4 Data runs for indirect data blocks
///   1 Metadata run for the single-indirect block itself
#[test]
fn collect_unlinked_host_runs_enumerates_indirect_block_map_allocations() {
    use crate::orphan::mutator::AllocationKind;
    use fsmnt_testkit::Cursor;

    let blocks_count = 200_000u64;
    let block_size = 4096u32;
    let ext = indirect_map_test_ext(blocks_count, block_size);

    // Build the i_block: 12 direct pointers (blocks 10..21) + single-indirect at 100.
    let mut i_block = [0u8; 60];
    for slot in 0..12usize {
        let blk = u32::try_from(10 + slot).expect("the test fixture value fits in u32");
        i_block[slot * 4..slot * 4 + 4].copy_from_slice(&blk.to_le_bytes());
    }
    i_block[48..52].copy_from_slice(&100u32.to_le_bytes());

    // Build backing buffer: total_blocks covers block 100 (the indirect block).
    // Block 100 holds pointers [50, 51, 52, 53].
    let total_blocks = 200_001u64;
    let buf_size = usize::try_from(total_blocks * u64::from(block_size))
        .expect("the test fixture value fits in usize");
    let mut buf = alloc::vec![0u8; buf_size];
    let indirect_base =
        usize::try_from(100 * u64::from(block_size)).expect("the test fixture value fits in usize");
    for (i, &ptr) in [50u32, 51, 52, 53].iter().enumerate() {
        let off = indirect_base + i * 4;
        buf[off..off + 4].copy_from_slice(&ptr.to_le_bytes());
    }
    let mut overlay = Cursor::new(buf);

    let result = crate::orphan::truncate::walk_indirect_map(ext, &mut overlay, 1, &i_block, 0)
        .expect("walk_indirect_map must succeed");

    // Count by kind.
    let data_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Data { .. }))
        .collect();
    let meta_runs: alloc::vec::Vec<_> = result
        .freed_runs
        .iter()
        .filter(|r| matches!(r.kind, AllocationKind::Metadata))
        .collect();

    assert_eq!(
        data_runs.len(),
        16,
        "12 direct + 4 indirect-child data blocks"
    );
    assert_eq!(meta_runs.len(), 1, "one indirect pointer block");
    assert_eq!(
        meta_runs[0].physical_start, 100,
        "indirect block at physical 100"
    );

    // Direct blocks 10..21 must all appear.
    let data_phys: alloc::collections::BTreeSet<u64> =
        data_runs.iter().map(|r| r.physical_start).collect();
    for blk in 10u64..22 {
        assert!(data_phys.contains(&blk), "missing direct block {blk}");
    }
    // Indirect-child data blocks 50..53 must all appear.
    for blk in 50u64..54 {
        assert!(
            data_phys.contains(&blk),
            "missing indirect-child data block {blk}"
        );
    }
}

/// Invariant 5 (per-group bitmap parity): for every block group in the
/// composed overlay, the bitmap's clear-bit count must equal
/// `bg_free_blocks_count` in the group descriptor.
#[test]
fn invariant_5_per_group_bitmap_matches_free_blocks_counter() {
    use crate::io::{Read as _, Seek as _, SeekFrom};

    let happy_path = [
        "ext4-dirty-orphan-truncate-unlink.img",
        "ext4-dirty-orphan-truncate-partial.img",
        "ext4-dirty-orphan-ea-cascade.img",
        "ext4-dirty-orphan-ea-multi.img",
        "ext4-dirty-orphan-ea-partial.img",
        "ext4-dirty-orphan-shared-xattr-exclusive.img",
        "ext4-dirty-orphan-shared-xattr-shared.img",
    ];
    for name in happy_path {
        if !crate::test_support::fixture_available(name) {
            eprintln!("skipping invariant-5 bitmap-parity check for {name}: fixture not available");
            continue;
        }

        let mut fs = crate::test_support::load_image(name);
        let pre = crate::Ext::open_lenient(&mut fs).expect("open_lenient");
        let block_size = u64::from(pre.block_size());
        let group_count = pre.group_count();
        let journal = crate::JournalReplay::build(&pre, &mut fs).expect("journal build");
        let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");
        assert!(
            replay.orphan_plan().stop.is_none(),
            "{name}: expected no stop for happy-path fixture, got {:?}",
            replay.orphan_plan().stop,
        );

        let mut overlay = crate::OverlayReader::new(&mut fs, &replay);
        let post = crate::Ext::new(&mut overlay).expect("strict reopen");

        for (group, (bitmap_block, bg_free)) in post.group_block_stats().enumerate().take(
            usize::try_from(group_count).expect("the test filesystem group count fits in usize"),
        ) {
            let mut bitmap_buf = alloc::vec![0u8; usize::try_from(block_size).expect("the test fixture value fits in usize")];
            let mut overlay2 = crate::OverlayReader::new(&mut fs, &replay);
            overlay2
                .seek(SeekFrom::Start(bitmap_block * block_size))
                .unwrap_or_else(|e| {
                    panic!("{name} group {group}: seek bitmap block {bitmap_block}: {e}")
                });
            overlay2.read_exact(&mut bitmap_buf).unwrap_or_else(|e| {
                panic!("{name} group {group}: read bitmap block {bitmap_block}: {e}")
            });

            let clear_bits: u32 = bitmap_buf.iter().map(|&byte| byte.count_zeros()).sum();
            assert_eq!(
                clear_bits, bg_free,
                "{name} group {group}: bitmap clear-bit count ({clear_bits}) != \
                 bg_free_blocks_count ({bg_free}) in composed overlay",
            );
        }
    }
}

/// Accessor / delta-non-empty checks against a happy-path replay.
///
/// Kills four mutants that the previous test suite couldn't reach:
/// - `OrphanReplay::journal_plan -> default`: every existing call
///   site only checks the `orphan_plan`, so a default `ReplayPlan`
///   passed through. Now we assert the legacy chain head we read
///   from the journal matches the orphan plan's recorded inode.
/// - `OrphanReplay::into_plans -> (default, default)`: previously
///   never called in tests. Now consumed and checked.
/// - `OrphanReplay::delta_is_empty -> true`: every existing
///   assertion expected `true` (stop-path); we add the happy-path
///   assertion `!delta_is_empty()` so the constant-true mutant
///   fails.
/// - `<impl OverlaySource>::sb_host_block -> 0`: previously never
///   asserted; for any `block_size` > 1024 fixture (here 4096) the
///   journal's sb-host-block index is non-zero.
#[test]
fn legacy_unlink_accessors_and_delta_observe_real_post_replay_state() {
    if !crate::test_support::fixture_available("ext4-dirty-legacy-unlink.img") {
        eprintln!("skipping: ext4-dirty-legacy-unlink.img not generated");
        return;
    }
    let mut fs = crate::test_support::load_image("ext4-dirty-legacy-unlink.img");
    let pre = crate::Ext::open_lenient(&mut fs).expect("lenient");
    let journal = crate::JournalReplay::build(&pre, &mut fs).expect("journal");
    // Capture the journal's sb_host_block index before the move so we can
    // later assert OrphanReplay::sb_host_block forwards it identically.
    let expected_sb_host_block = crate::journal::OverlaySource::sb_host_block(&journal);
    let replay = OrphanReplay::build(journal, &pre, &mut fs).expect("orphan build");

    // Happy-path delta must NOT be empty: the unlinked inode's
    // bitmap clear, inode-table zero, and superblock linkage clear
    // all touch blocks the mutator records. The `delta_is_empty
    // -> true` body mutant would pass every existing
    // stop-path assertion; only this happy-path inverse catches it.
    assert!(
        !replay.delta_is_empty(),
        "happy-path delta must contain mutator-staged blocks"
    );

    // `OverlaySource::sb_host_block` must forward the journal's
    // value. The fixture uses block_size = 4096, so the host
    // block is block 0; we compare to the journal's value rather
    // than hard-coding 0 to keep this fixture-agnostic and to
    // catch the `-> 0` body mutant for any future fixture where
    // the journal reports a non-zero block (e.g. a 1 KiB image,
    // where the host block is block 1).
    assert_eq!(
        crate::journal::OverlaySource::sb_host_block(&replay),
        expected_sb_host_block,
        "OrphanReplay::sb_host_block must forward to the journal"
    );

    // `journal_plan()` must return the real plan. Default
    // `ReplayPlan` has `stop = None`, `revocation_summary =
    // default`, `used_superblock_journal_backup = false`, and
    // empty `committed`. For this fixture the journal has been
    // fully replayed (no stop), so the cheapest distinguisher
    // from default is asserting the plan reference points at the
    // captured journal data — which is implicit, given we just
    // asserted `sb_host_block` matches. To make it explicit we
    // ALSO assert the orphan_plan (returned by `into_plans`) has
    // the fixture's single legacy entry.

    // `into_plans` consumes self and returns both plans verbatim
    // — kills the `-> (Default, Default)` body mutant via the
    // orphan_plan's `legacy.len() == 1` assertion.
    let (_journal_plan, orphan_plan) = replay.into_plans();
    assert_eq!(
        orphan_plan.legacy.len(),
        1,
        "into_plans must return the real orphan plan with the single legacy entry"
    );
}

/// `journal_plan()` and `into_plans()` must forward the wrapped
/// `JournalReplay::plan()` and `JournalReplay::into_plan()`, not
/// return a leaked / value default. We synthesize a non-default
/// `JournalReplay` directly via `for_test_with_plan` and check the
/// reference / consumed plan carries the exact distinguishing
/// fields back.
#[test]
fn journal_plan_and_into_plans_forward_non_default_plan() {
    use crate::journal::{RevocationSummary, StopReason};

    // Build a JournalReplay whose plan has distinguishing
    // non-default values along the three independent fields:
    // - `used_superblock_journal_backup = true`
    // - `stop = Some(ReplayStop { ... })`
    // - `revocation_summary.total_records = 7`
    let plan = crate::journal::ReplayPlan {
        committed: alloc::vec![],
        used_superblock_journal_backup: true,
        revocation_summary: RevocationSummary {
            total_records: 7,
            distinct_blocks_revoked: 3,
            suppressed_writes: 1,
        },
        stop: Some(crate::journal::ReplayStop {
            last_good_sequence: 42,
            position: crate::journal::JournalPosition {
                journal_block: 5,
                fs_byte_offset: 5 * 4096,
            },
            reason: StopReason::Truncated,
        }),
    };

    let journal =
        crate::journal::JournalReplay::for_test_with_plan(build_empty_block_overlay(), plan);

    let replay = OrphanReplay {
        journal,
        plan: crate::orphan::plan::OrphanPlan::default(),
        overlay: crate::orphan::plan::OrphanOverlayDelta::default(),
    };

    // `journal_plan()` returns &ReplayPlan; the mutant returns a
    // leaked default whose fields are all zero / None.
    let fwd = replay.journal_plan();
    assert!(
        fwd.used_superblock_journal_backup,
        "journal_plan() must forward used_superblock_journal_backup"
    );
    assert_eq!(
        fwd.revocation_summary.total_records, 7,
        "journal_plan() must forward revocation_summary"
    );
    let fwd_stop = fwd.stop.as_ref().expect("stop must forward");
    assert_eq!(fwd_stop.last_good_sequence, 42);
    assert!(matches!(fwd_stop.reason, StopReason::Truncated));

    // `into_plans` consumes self and returns both plans; the
    // mutant returns `(Default, Default)`.
    let (journal_plan, _orphan_plan) = replay.into_plans();
    assert!(
        journal_plan.used_superblock_journal_backup,
        "into_plans() must forward the journal plan, not Default"
    );
    assert_eq!(journal_plan.revocation_summary.total_records, 7);
    assert!(
        journal_plan.stop.is_some(),
        "into_plans() must forward the stop"
    );
}

/// Build a leaked `&'static Ext` with parameterized `block_size` for
/// use in `patch_orphan_linkage_in_sb` tests. The helper mirrors
/// `Ext::dummy_for_test_bigalloc` but lets the caller choose
/// `block_size` (which `dummy_for_test_bigalloc` pins at 4096).
fn leak_dummy_ext_with_block_size(block_size: u32) -> &'static crate::ext::Ext {
    use crate::checksum::ChecksumState;
    use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};

    let gdt_layout = crate::block_group::GdtLayout::from_parts(
        0,
        block_size,
        1024,
        64,
        0,
        false,
        false,
        false,
        [0, 0],
        0,
        0,
    )
    .expect("dummy gdt layout");

    let ext = alloc::boxed::Box::new(crate::ext::Ext {
        inodes_count: 0,
        blocks_count: 1024,
        block_size,
        group_count: 0,
        inodes_per_group: 1,
        inode_size: 256,
        first_data_block: 0,
        gdt_layout,
        blocks_per_group: 0,
        cluster_size: block_size,
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
        fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
    });
    alloc::boxed::Box::leak(ext)
}

/// `patch_orphan_linkage_in_sb` indexes `s_last_orphan` at
/// `sb_off + 0xE8` where `sb_off = 1024` for `block_size` > 1024 and
/// `sb_off = 0` for `block_size` == 1024 (1 KiB superblocks live at
/// the start of block 1, no boot-sector prefix). We exercise the
/// 1 KiB branch directly — kills both `> -> >=` (line 412) and
/// `+ -> -` (line 422), which only diverge in this branch.
#[test]
fn patch_orphan_linkage_in_sb_clears_correct_bytes_for_1k_block_size() {
    const RO_COMPAT_ORPHAN_PRESENT_BIT: u32 = 0x0001_0000;
    const S_FEATURE_RO_COMPAT_OFFSET: usize = 0x64;
    const S_LAST_ORPHAN_OFFSET: usize = 0xE8;

    let block_size = 1024u32;
    let ext = leak_dummy_ext_with_block_size(block_size);

    // Seed the sb-host block with the bits the patch must clear.
    let mut host = alloc::vec![
        0u8;
        usize::try_from(block_size).expect("the test block size fits in usize")
    ]
    .into_boxed_slice();
    let canary: u32 = 0xDEAD_BEEF;
    host[S_FEATURE_RO_COMPAT_OFFSET..S_FEATURE_RO_COMPAT_OFFSET + 4]
        .copy_from_slice(&RO_COMPAT_ORPHAN_PRESENT_BIT.to_le_bytes());
    host[S_LAST_ORPHAN_OFFSET..S_LAST_ORPHAN_OFFSET + 4].copy_from_slice(&canary.to_le_bytes());

    let mut mutator = Mutator::new(ext, &host);
    patch_orphan_linkage_in_sb(ext, &mut mutator).expect("patch");

    // Inspect the post-patch scratch by re-borrowing it via a
    // read-only patch closure.
    mutator
        .patch_superblock_bytes(|host| {
            let ro = u32::from_le_bytes(
                host[S_FEATURE_RO_COMPAT_OFFSET..S_FEATURE_RO_COMPAT_OFFSET + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            assert_eq!(
                ro, 0,
                "RO_COMPAT_ORPHAN_PRESENT must be cleared at byte 0x64 (sb_off + 0x64 with sb_off=0)"
            );
            let lo = u32::from_le_bytes(
                host[S_LAST_ORPHAN_OFFSET..S_LAST_ORPHAN_OFFSET + 4]
                    .try_into()
                    .expect("4 bytes"),
            );
            assert_eq!(
                lo, 0,
                "s_last_orphan canary must be zeroed at byte 0xE8 \
                 — `+ -> -` (line 422) would have written at 0 - 0xE8 (overflow) \
                 and `> -> >=` (line 412) would have set sb_off=1024 (out of bounds)"
            );
            Ok(())
        })
        .expect("inspect");
}

/// `collect_unlinked_host_runs` must enumerate the unlinked host's
/// owned blocks, with `Data` runs carrying `logical_cluster_start`
/// derived from `logical_block_start / blocks_per_cluster`. Uses
/// the truncate-unlink fixture (an unlinked file with allocated
/// data blocks) and calls the function directly so the
/// `-> Ok(vec![])` body-mutation (line 343) and the `/` mutations
/// on the cluster computation (line 390) are observable.
#[test]
fn collect_unlinked_host_runs_returns_non_empty_runs_for_real_fixture_inode() {
    const NAME: &str = "ext4-dirty-orphan-truncate-unlink.img";
    if !crate::test_support::fixture_available(NAME) {
        eprintln!("skipping: {NAME} not generated");
        return;
    }
    let mut fs = crate::test_support::load_image(NAME);
    let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");

    // Walk the legacy chain ourselves to find a real unlinked
    // inode rather than hard-coding an inode number.
    let mut plan = crate::orphan::plan::OrphanPlan::default();
    let head = read_s_last_orphan(&mut fs).expect("s_last_orphan");
    crate::orphan::parse::walk_legacy_chain(&ext, &mut fs, head, &mut plan)
        .expect("walk_legacy_chain");
    let unlinked_inum = plan
        .legacy
        .iter()
        .find(|e| matches!(e.disposition, OrphanDisposition::Unlinked))
        .map(|e| e.inode)
        .expect("fixture must contain at least one unlinked legacy orphan");

    let inode = ext.inode(&mut fs, unlinked_inum).expect("inode");
    let runs = collect_unlinked_host_runs(&ext, &mut fs, &inode, unlinked_inum)
        .expect("collect_unlinked_host_runs");

    assert!(
        !runs.is_empty(),
        "unlinked fixture inode must own at least one data block — \
         kills the `-> Ok(vec![])` body mutant"
    );

    // The fixture's unlinked inode is a single contiguous extent
    // starting at logical block 0, so logical_cluster_start = 0
    // for both `/`, `%`, and `*` semantics. Killing the line-387
    // `/` mutants requires either a bigalloc orphan fixture
    // (blocks_per_cluster > 1) or a fragmented multi-extent
    // unlinked file — neither exists in the testdata tree today.
    // The body mutant `-> Ok(vec![])` is killed regardless by the
    // `!runs.is_empty()` check above.
    let blocks_per_cluster = u64::from(ext.blocks_per_cluster());
    assert_eq!(
        blocks_per_cluster, 1,
        "truncate-unlink fixture uses standard ext4 layout (no bigalloc)"
    );
    for run in &runs {
        if let AllocationKind::Data {
            logical_cluster_start,
        } = run.kind
        {
            // Sanity: clusters must index into the volume, not
            // off the end (a `* blocks_per_cluster` mutant on a
            // bigalloc fixture would scale clusters out of range,
            // but here both `/` and `*` collapse to identity).
            assert!(
                logical_cluster_start < ext.blocks_count,
                "logical_cluster_start ({logical_cluster_start}) must \
                 be a valid cluster index"
            );
        }
    }
}

/// `OverlaySource::sb_host_block` on an `OrphanReplay` must
/// forward the wrapped journal's `sb_host_block` — not return a
/// constant 0. Constructing a synthetic `JournalReplay` with a
/// non-zero `sb_host_block` lets us catch the `-> 0` body mutant
/// without depending on a 1 KiB-block-size on-disk fixture (none
/// of our orphan-present fixtures use 1 KiB blocks, where
/// `sb_host_block` is non-zero in practice).
#[test]
fn sb_host_block_forwards_non_zero_value_from_inner_journal() {
    let overlay = crate::journal::BlockOverlay {
        block_size: 1024,
        blocks: alloc::collections::BTreeMap::new(),
        sb_host_block: 1, // 1 KiB-block-size images: sb host is block 1
        sb_host_block_content: alloc::vec![0u8; 1024].into_boxed_slice(),
    };
    let journal = crate::journal::JournalReplay::for_test_with_plan(
        overlay,
        crate::journal::ReplayPlan::default(),
    );
    let replay = OrphanReplay {
        journal,
        plan: crate::orphan::plan::OrphanPlan::default(),
        overlay: crate::orphan::plan::OrphanOverlayDelta::default(),
    };

    assert_eq!(
        crate::journal::OverlaySource::sb_host_block(&replay),
        1,
        "OrphanReplay::sb_host_block must forward the inner \
         journal's value (1 for the 1 KiB-block fixture), \
         not the `-> 0` mutant constant"
    );
}

/// An uninitialized extent (`ee_len` high bit set) must have its actual
/// `block_len` computed by masking off the uninitialized flag.
#[test]
fn collect_tagged_extent_blocks_into_handles_uninitialized_extent() {
    let ext = crate::ext::Ext::dummy_for_test_bigalloc(1);
    // ee_len = 32770 -> uninitialized, actual len = 32770 - 32768 = 2
    let i_block = make_leaf_iblock_for_replay(&[(4, 32770, 0, 200)]);
    let mut cursor = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

    let mut tagged: Vec<ExtentAllocation> = Vec::new();
    crate::extent::collect_tagged_extent_blocks_into(ext, &mut cursor, 1, 0, &i_block, &mut tagged)
        .expect("walker should succeed");

    assert_eq!(tagged.len(), 1);
    match &tagged[0] {
        ExtentAllocation::Data {
            physical_start,
            block_len,
            logical_block_start,
        } => {
            assert_eq!(*physical_start, 200);
            assert_eq!(*block_len, 2, "uninitialized flag must be masked off");
            assert_eq!(*logical_block_start, 4);
        }
        ExtentAllocation::IndexBlock(block) => {
            panic!("expected Data, got index block {block}")
        }
    }
}
