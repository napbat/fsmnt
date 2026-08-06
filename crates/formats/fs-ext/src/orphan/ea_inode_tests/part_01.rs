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
#[allow(
    clippy::struct_field_names,
    reason = "test fields mirror the ext4 ee_* extent record layout byte-for-byte"
)]
struct TestExtent {
    ee_block: u32,
    ee_len: u16,
    ee_start_hi: u16,
    ee_start_lo: u32,
}

const EA_XATTR_ENTRY_SIZE: usize = 16;

struct DepthOneIndexSlot {
    ei_block: u32,
    leaf_phys: u64,
    ee_block: u32,
    ee_len: u16,
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
    let mut empty = fsmnt_testkit::Cursor::new(alloc::vec::Vec::<u8>::new());
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

fn load_dirty(name: &str) -> Option<(Ext, fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>)> {
    if !fixture_available(name) {
        return None;
    }
    let bytes = std::fs::read(fixture_path(name)).ok()?;
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::open_lenient(&mut cursor).expect("open_lenient");
    Some((ext, cursor))
}

fn build_ea_refs_from_orphan_chain<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
) -> BTreeMap<u32, alloc::vec::Vec<EaRef>> {
    let mut map: BTreeMap<u32, alloc::vec::Vec<EaRef>> = BTreeMap::new();

    let head = Ext::read_last_orphan(overlay).expect("read s_last_orphan");
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

    let mut pos = 4usize;
    while pos + 2 <= ibody.len() {
        if ibody[pos] == 0 && ibody[pos + 1] == 0 {
            break;
        }
        if pos + EA_XATTR_ENTRY_SIZE > ibody.len() {
            break;
        }
        let name_len = usize::from(ibody[pos]);
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
        let name_start = pos + EA_XATTR_ENTRY_SIZE;
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
    let Some((ext, mut cursor)) = load_dirty("ext4-dirty-orphan-ea-checksum-invalid.img") else {
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
    cursor: &mut fsmnt_testkit::Cursor<alloc::vec::Vec<u8>>,
) -> alloc::vec::Vec<u8> {
    use crate::io::SeekFrom;
    let sb_block: u64 = u64::from(ext.block_size() <= 1024);
    let mut sb_bytes = alloc::vec![
        0u8;
        usize::try_from(ext.block_size()).expect("the test block size fits in usize")
    ];
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

const DEPTH_ONE_EXTENT_MAGIC: u16 = 0xF30A;
const DEPTH_ONE_BLOCK_SIZE: u64 = 4096;
const DEPTH_ONE_BLOCKS_PER_CLUSTER: u32 = 4;
const DEPTH_ONE_TOTAL_BLOCKS: u64 = 1000;
const DEPTH_ONE_EA_INUM: u32 = 12;

fn depth_one_bigalloc_ext() -> &'static Ext {
    use crate::checksum::ChecksumState;
    use crate::feature_flags::{CompatFeatures, IncompatFeatures, RoCompatFeatures};

    Box::leak(Box::new(crate::ext::Ext {
        inodes_count: 1000,
        blocks_count: DEPTH_ONE_TOTAL_BLOCKS,
        block_size: u32::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test block size fits in u32"),
        group_count: 1,
        inodes_per_group: 1000,
        inode_size: 256,
        first_data_block: 0,
        gdt_layout: crate::block_group::GdtLayout::from_parts(
            0,
            u32::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test block size fits in u32"),
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
        cluster_size: u32::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test block size fits in u32")
            * DEPTH_ONE_BLOCKS_PER_CLUSTER,
        blocks_per_cluster: DEPTH_ONE_BLOCKS_PER_CLUSTER,
        clusters_per_group: 32768 / DEPTH_ONE_BLOCKS_PER_CLUSTER,
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
    }))
}

fn depth_one_bigalloc_overlay(ext: &Ext) -> fsmnt_testkit::Cursor<alloc::vec::Vec<u8>> {
    let mut i_block = [0u8; 60];
    i_block[0..2].copy_from_slice(&DEPTH_ONE_EXTENT_MAGIC.to_le_bytes());
    i_block[2..4].copy_from_slice(&2u16.to_le_bytes());
    i_block[4..6].copy_from_slice(&4u16.to_le_bytes());
    i_block[6..8].copy_from_slice(&1u16.to_le_bytes());

    let index_entries = [
        DepthOneIndexSlot {
            ei_block: 0,
            leaf_phys: 200,
            ee_block: 0,
            ee_len: 4,
            ee_start_lo: 100,
        },
        DepthOneIndexSlot {
            ei_block: 4,
            leaf_phys: 201,
            ee_block: 4,
            ee_len: 4,
            ee_start_lo: 300,
        },
    ];

    let disk_len = usize::try_from(DEPTH_ONE_TOTAL_BLOCKS * DEPTH_ONE_BLOCK_SIZE)
        .expect("the test disk length fits in usize");
    let mut disk = alloc::vec![0u8; disk_len];
    for (slot, entry) in index_entries.iter().enumerate() {
        let idx_off = 12 + slot * 12;
        i_block[idx_off..idx_off + 4].copy_from_slice(&entry.ei_block.to_le_bytes());
        i_block[idx_off + 4..idx_off + 8].copy_from_slice(
            &u32::try_from(entry.leaf_phys)
                .expect("the test leaf address fits in u32")
                .to_le_bytes(),
        );

        let base = usize::try_from(entry.leaf_phys * DEPTH_ONE_BLOCK_SIZE)
            .expect("the test leaf offset fits in usize");
        disk[base..base + 2].copy_from_slice(&DEPTH_ONE_EXTENT_MAGIC.to_le_bytes());
        disk[base + 2..base + 4].copy_from_slice(&1u16.to_le_bytes());
        disk[base + 4..base + 6].copy_from_slice(&340u16.to_le_bytes());
        let extent_offset = base + 12;
        disk[extent_offset..extent_offset + 4].copy_from_slice(&entry.ee_block.to_le_bytes());
        disk[extent_offset + 4..extent_offset + 6].copy_from_slice(&entry.ee_len.to_le_bytes());
        disk[extent_offset + 8..extent_offset + 12]
            .copy_from_slice(&entry.ee_start_lo.to_le_bytes());
    }

    let block_size =
        usize::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test block size fits in usize");
    let inode_table_base = 3 * block_size + 11 * 256;
    disk[inode_table_base + 0x04..inode_table_base + 0x08].copy_from_slice(
        &(8u32 * u32::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test block size fits in u32"))
            .to_le_bytes(),
    );
    let flags_bits = (InodeFlags::EA_INODE_FL | InodeFlags::EXTENTS_FL).bits();
    disk[inode_table_base + 0x20..inode_table_base + 0x24]
        .copy_from_slice(&flags_bits.to_le_bytes());
    disk[inode_table_base + 0x28..inode_table_base + 0x28 + 60].copy_from_slice(&i_block);

    let bitmap_base = usize::try_from(ext.group_descs[0].block_bitmap * DEPTH_ONE_BLOCK_SIZE)
        .expect("the test bitmap offset fits in usize");
    for &cluster_bit in &[25u32, 50u32, 75u32] {
        let bit = usize::try_from(cluster_bit).expect("the test cluster bit fits in usize");
        disk[bitmap_base + bit / 8] |= 1u8 << (cluster_bit % 8);
    }

    fsmnt_testkit::Cursor::new(disk)
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
    use crate::orphan::mutator::Mutator;

    // Synthetic bigalloc Ext modeled on
    // truncate::tests::ext_for_extent_tests, with cluster_size=16384,
    // blocks_per_cluster=4, BIGALLOC enabled. Inode-table block 3 holds
    // EA inode 12 at byte offset 3*4096 + 11*256 = 15104. Block bitmap
    // is at block 1; nothing in {1, 2, 3..65} collides with the
    // synthetic data/index blocks {100..103, 200, 201, 300..303}.
    let ext = depth_one_bigalloc_ext();
    assert!(ext.has_bigalloc(), "synthetic ext must be bigalloc");

    let mut overlay = depth_one_bigalloc_overlay(ext);

    // Materialize the inode and enumerate its data blocks.
    let inode = ext
        .inode(&mut overlay, DEPTH_ONE_EA_INUM)
        .expect("read EA inode");
    assert!(
        inode.flags().contains(InodeFlags::EA_INODE_FL),
        "EA_INODE_FL must be set on the planted inode"
    );
    let runs = enumerate_ea_inode_data_blocks(ext, &mut overlay, &inode, DEPTH_ONE_EA_INUM)
        .expect("enumerate depth-1 EA inode");

    // The tagged walker emits, per index slot: IndexBlock, then the
    // recursed leaf's Data extent. Two slots → 4 entries.
    assert_eq!(runs.len(), 4, "expected 4 runs (2 index + 2 leaves)");

    match runs[0].kind {
        AllocationKind::Metadata => {}
        AllocationKind::Data { .. } => panic!("runs[0] kind was Data, expected Metadata"),
    }
    assert_eq!(runs[0].physical_start, 200);
    assert_eq!(runs[0].block_len, 1);

    match runs[1].kind {
        AllocationKind::Data {
            logical_cluster_start,
        } => assert_eq!(logical_cluster_start, 0, "leaf-A logical cluster"),
        AllocationKind::Metadata => panic!("runs[1] kind was Metadata, expected Data"),
    }
    assert_eq!(runs[1].physical_start, 100);
    assert_eq!(runs[1].block_len, 4);

    match runs[2].kind {
        AllocationKind::Metadata => {}
        AllocationKind::Data { .. } => panic!("runs[2] kind was Data, expected Metadata"),
    }
    assert_eq!(runs[2].physical_start, 201);
    assert_eq!(runs[2].block_len, 1);

    match runs[3].kind {
        AllocationKind::Data {
            logical_cluster_start,
        } => assert_eq!(logical_cluster_start, 1, "leaf-B logical cluster"),
        AllocationKind::Metadata => panic!("runs[3] kind was Metadata, expected Data"),
    }
    assert_eq!(runs[3].physical_start, 300);
    assert_eq!(runs[3].block_len, 4);

    // Drive the runs through Mutator::free_allocations and assert
    // bigalloc bookkeeping. Unique clusters: {25, 50, 75}; the two
    // index blocks share cluster 50 but are both Metadata so the
    // overlap check skips them by design.
    let sb_bytes = alloc::vec![0u8; usize::try_from(DEPTH_ONE_BLOCK_SIZE).expect("the test fixture value fits in usize")];
    let mut mutator = Mutator::new(ext, &sb_bytes);
    mutator
        .free_allocations(&mut overlay, DEPTH_ONE_EA_INUM, &runs)
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
        let byte = usize::try_from(cluster_bit).expect("the test cluster bit fits in usize") / 8;
        let mask = 1u8 << (cluster_bit % 8);
        assert_eq!(
            bitmap_scratch[byte] & mask,
            0,
            "cluster {cluster_bit} bit must be cleared after free"
        );
    }
}
