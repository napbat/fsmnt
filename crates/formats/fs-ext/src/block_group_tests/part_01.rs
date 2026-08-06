use super::*;

#[test]
fn raw_group_desc32_size() {
    assert_eq!(core::mem::size_of::<RawGroupDesc32>(), 32);
}

#[test]
fn raw_group_desc64_ext_size() {
    assert_eq!(core::mem::size_of::<RawGroupDesc64Ext>(), 32);
}

#[test]
fn combine_u64_works() {
    assert_eq!(combine_u64(0xDEAD_BEEF, 0x0000_0001), 0x0000_0001_DEAD_BEEF);
    assert_eq!(combine_u64(42, 0), 42);
}

#[test]
fn group_has_super_uses_sparse_super2_backup_groups() {
    let ext = ext_for_free_clusters_test(
        CompatFeatures::SPARSE_SUPER2,
        RoCompatFeatures::empty(),
        0,
        [5, 9],
    );

    assert!(group_has_super(&ext, 0));
    assert!(group_has_super(&ext, 5));
    assert!(group_has_super(&ext, 9));
    assert!(!group_has_super(&ext, 1));
    assert!(!group_has_super(&ext, 3));
    assert!(!group_has_super(&ext, 7));
}

#[test]
fn free_clusters_after_init_subtracts_reserved_gdt_blocks() {
    let without_reserved = ext_for_free_clusters_test(
        CompatFeatures::empty(),
        RoCompatFeatures::empty(),
        0,
        [0, 0],
    );
    let with_reserved = ext_for_free_clusters_test(
        CompatFeatures::empty(),
        RoCompatFeatures::empty(),
        2,
        [0, 0],
    );
    let gdp = GroupDescriptor {
        inode_table: 20,
        block_bitmap: 10,
        inode_bitmap: 11,
        free_blocks_count: 0,
        free_inodes_count: 0,
        flags: 0,
        checksum: crate::checksum::ChecksumState::Unknown,
    };

    assert_eq!(
        free_clusters_after_init(&with_reserved, 0, &gdp),
        free_clusters_after_init(&without_reserved, 0, &gdp) - 2
    );
}

#[test]
fn free_clusters_after_init_counts_reserved_clusters_relative_to_group() {
    let ext = Ext {
        inodes_count: 64,
        blocks_count: 1024,
        block_size: 1024,
        group_count: 16,
        inodes_per_group: 4,
        inode_size: 128,
        first_data_block: 1,
        gdt_layout: GdtLayout::from_parts(
            1,
            1024,
            64,
            32,
            0,
            false,
            false,
            false,
            [0, 0],
            16,
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
        fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
    };
    let gdp = GroupDescriptor {
        inode_table: 9,
        block_bitmap: 3,
        inode_bitmap: 4,
        free_blocks_count: 0,
        free_inodes_count: 0,
        flags: 0,
        checksum: crate::checksum::ChecksumState::Unknown,
    };

    assert_eq!(
        free_clusters_after_init(&ext, 0, &gdp),
        14,
        "metadata at absolute blocks 1,2,3,4,9 occupies local clusters 0 and 2"
    );
}

fn ext_for_free_clusters_test(
    compat: CompatFeatures,
    ro_compat: RoCompatFeatures,
    reserved_gdt_blocks: u16,
    backup_bgs: [u32; 2],
) -> Ext {
    let sparse_super = ro_compat.contains(RoCompatFeatures::SPARSE_SUPER);
    let sparse_super2 = compat.contains(CompatFeatures::SPARSE_SUPER2);
    Ext {
        inodes_count: 64,
        blocks_count: 1024,
        block_size: 1024,
        group_count: 16,
        inodes_per_group: 4,
        inode_size: 128,
        first_data_block: 1,
        gdt_layout: GdtLayout::from_parts(
            1,
            1024,
            64,
            32,
            0,
            false,
            sparse_super,
            sparse_super2,
            backup_bgs,
            16,
            reserved_gdt_blocks,
        )
        .expect("test layout"),
        blocks_per_group: 64,
        cluster_size: 1024,
        blocks_per_cluster: 1,
        clusters_per_group: 64,
        backup_bgs,
        desc_size: 32,
        incompat: crate::feature_flags::IncompatFeatures::empty(),
        ro_compat,
        compat,
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
        fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
    }
}

#[test]
fn gdt_layout_assembles_classical_layout() {
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 4096,
        desc_size: 64,
        first_data_block: 0,
        blocks_per_group: 32_768,
        group_count: 4,
        first_meta_bg: 0,
        meta_bg: false,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 7,
    })
    .expect("classical layout must validate");

    assert_eq!(layout.first_data_block(), 0);
    assert_eq!(layout.block_size(), 4096);
    assert_eq!(layout.desc_per_block(), 64);
    assert_eq!(layout.first_meta_bg(), 0);
    assert!(!layout.meta_bg());
    assert_eq!(layout.total_desc_blocks(), 1);
}

#[test]
fn gdt_layout_rejects_desc_size_below_32() {
    let err = build_layout(GdtLayoutTestSpec {
        desc_size: 16,
        ..GdtLayoutTestSpec::classical_4k_64bit()
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            ExtError::InvalidSuperblock { reason }
                if reason == "s_desc_size is below 32-byte RawGroupDesc32"
        ),
        "got {err:?}"
    );
}

#[test]
fn gdt_layout_rejects_desc_size_exceeds_block_size() {
    let err = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 2048,
        ..GdtLayoutTestSpec::classical_4k_64bit()
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            ExtError::InvalidSuperblock { reason }
                if reason == "desc_size exceeds block_size"
        ),
        "got {err:?}"
    );
}

#[test]
fn gdt_layout_rejects_block_size_not_multiple_of_desc_size() {
    let err = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 96, // 1024 % 96 != 0
        ..GdtLayoutTestSpec::classical_4k_64bit()
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            ExtError::InvalidSuperblock { reason }
                if reason == "block_size is not a multiple of desc_size"
        ),
        "got {err:?}"
    );
}

#[test]
fn gdt_layout_rejects_first_meta_bg_exceeds_total_desc_blocks() {
    let err = build_layout(GdtLayoutTestSpec {
        meta_bg: true,
        first_meta_bg: 10, // total_desc_blocks = 1, so 10 > 1
        ..GdtLayoutTestSpec::classical_4k_64bit()
    })
    .unwrap_err();
    assert!(
        matches!(
            err,
            ExtError::InvalidSuperblock { reason }
                if reason == "s_first_meta_bg exceeds descriptor block count"
        ),
        "got {err:?}"
    );
}

#[derive(Clone, Copy)]
struct GdtLayoutTestSpec {
    block_size: u32,
    desc_size: u16,
    first_data_block: u32,
    blocks_per_group: u32,
    group_count: u32,
    first_meta_bg: u32,
    meta_bg: bool,
    sparse_super: bool,
    sparse_super2: bool,
    backup_bgs: [u32; 2],
    reserved_gdt_blocks: u16,
}

impl GdtLayoutTestSpec {
    fn classical_4k_64bit() -> Self {
        Self {
            block_size: 4096,
            desc_size: 64,
            first_data_block: 0,
            blocks_per_group: 32_768,
            group_count: 4,
            first_meta_bg: 0,
            meta_bg: false,
            sparse_super: true,
            sparse_super2: false,
            backup_bgs: [0, 0],
            reserved_gdt_blocks: 0,
        }
    }
}

fn build_layout(spec: GdtLayoutTestSpec) -> Result<GdtLayout> {
    GdtLayout::from_parts(
        spec.first_data_block,
        spec.block_size,
        spec.blocks_per_group,
        spec.desc_size,
        spec.first_meta_bg,
        spec.meta_bg,
        spec.sparse_super,
        spec.sparse_super2,
        spec.backup_bgs,
        spec.group_count,
        spec.reserved_gdt_blocks,
    )
}

#[test]
fn descriptor_block_loc_classical() {
    // first_data_block=1, classical layout.
    // desc_block_nr 0 → block 2, desc_block_nr 3 → block 5.
    let layout = build_layout(GdtLayoutTestSpec {
        first_data_block: 1,
        meta_bg: false,
        group_count: 256,
        ..GdtLayoutTestSpec::classical_4k_64bit()
    })
    .unwrap();
    assert_eq!(descriptor_block_loc(&layout, 0), 2);
    assert_eq!(descriptor_block_loc(&layout, 3), 5);
}

#[test]
fn descriptor_block_loc_meta_bg_pure() {
    // 1 KiB blocks, 32-byte descs, desc_per_block = 32.
    // blocks_per_group = 1024.
    // first_data_block = 1, meta_bg = true, first_meta_bg = 0.
    // For desc_block_nr 0: metagroup 0, first_bg = 0,
    //   metagroup_first_block = 1, group_has_super(0) = true → +1 → block 2.
    // For desc_block_nr 1: metagroup 1, first_bg = 32,
    //   metagroup_first_block = 1 + 32*1024 = 32_769,
    //   group_has_super(32) = false (not 0/1/power of 3,5,7) → +0 → 32_769.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 0,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    assert_eq!(descriptor_block_loc(&layout, 0), 2);
    assert_eq!(descriptor_block_loc(&layout, 1), 32_769);
}

#[test]
fn descriptor_block_loc_meta_bg_mixed() {
    // first_meta_bg = 1: desc_block_nr 0 classical, desc_block_nr 1 meta_bg.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 1,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    // Classical for desc_block_nr 0: first_data_block + 1 + 0 = 2.
    assert_eq!(descriptor_block_loc(&layout, 0), 2);
    // META_BG for desc_block_nr 1: same as meta_bg_pure case above.
    assert_eq!(descriptor_block_loc(&layout, 1), 32_769);
}

#[test]
fn descriptor_block_loc_1k_quirk_first_data_block_zero() {
    // 1 KiB blocks + first_data_block = 0 + meta_bg + first_meta_bg = 0
    // + desc_block_nr = 0: +1 quirk applies.
    // Without quirk: metagroup_first_block = 0, has_super(0) = true → 1.
    // With quirk: 1 + 1 = 2.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 0,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 0,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    assert_eq!(descriptor_block_loc(&layout, 0), 2);
}

#[test]
fn read_descriptor_block_maps_eof_to_contextual_error() {
    use crate::io::SeekFrom;
    let mut cursor = std::io::Cursor::new(vec![0u8; 100]);
    cursor.seek(SeekFrom::Start(50)).unwrap();
    let mut buf = [0u8; 64];
    let err = read_descriptor_block(&mut cursor, &mut buf).unwrap_err();
    assert!(
        matches!(
            err,
            ExtError::UnexpectedEof {
                context: "group descriptor block",
                offset: 50
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn read_descriptor_block_succeeds_when_data_available() {
    use std::io::Seek;
    let mut cursor = std::io::Cursor::new(vec![0xABu8; 100]);
    let mut buf = [0u8; 64];
    read_descriptor_block(&mut cursor, &mut buf).unwrap();
    assert!(buf.iter().all(|&b| b == 0xAB));
    assert_eq!(cursor.stream_position().unwrap(), 64);
}

#[test]
fn descriptor_block_loc_metagroup_first_bg_no_sparse_super() {
    // 4 KiB blocks, desc_per_block = 64, blocks_per_group = 32_768.
    // Metagroup 1's first BG = 64. group_has_super(64) is false
    // (not 0, 1, or power of 3/5/7).
    // metagroup_first_block = 1 + 64*32_768 = 2_097_153 → no +1 → 2_097_153.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 4096,
        desc_size: 64,
        first_data_block: 1,
        blocks_per_group: 32_768,
        group_count: 256, // 4 desc_blocks
        first_meta_bg: 0,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    assert_eq!(descriptor_block_loc(&layout, 1), 2_097_153);
}

#[test]
fn read_group_descriptors_returns_vec_in_group_order_under_mixed_mode() {
    // Layout: 1 KiB blocks, 32-byte descs, desc_per_block = 32.
    // group_count = 64 → total_desc_blocks = 2.
    // first_meta_bg = 1 → desc block 0 classical, desc block 1 META_BG.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 1,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();

    // Build an image large enough to include both GDT block locations.
    // Classical desc block 0 at block 2 (offset 2048).
    // META_BG desc block 1 at block 32_769 (offset 33_555_456 ≈ 32 MiB).
    let block_size = layout.block_size() as usize;
    let total_blocks = 32_770usize;
    let mut image = alloc::vec![0u8; total_blocks * block_size];

    // Sentinel: write a recognizable bg_block_bitmap_lo into each descriptor slot.
    // bg_block_bitmap_lo lives at byte offset 0 in RawGroupDesc32.
    write_sentinel_descriptors(&mut image, &layout);

    let mut cursor = std::io::Cursor::new(image);
    let descs = read_group_descriptors(
        &mut cursor,
        &layout,
        /* is_64bit */ false,
        /* checksum_seed */ None,
    )
    .expect("read descriptors");

    assert_eq!(descs.len(), layout.group_count() as usize);
    for (group, desc) in descs.iter().enumerate() {
        // Each test descriptor's bg_block_bitmap_lo == group sentinel.
        assert_eq!(
            desc.block_bitmap, group as u64,
            "group {group} sentinel mismatch"
        );
    }
}

fn write_sentinel_descriptors(image: &mut [u8], layout: &GdtLayout) {
    let block_size = layout.block_size() as usize;
    let desc_size = layout.desc_size() as usize;
    let dpb = layout.desc_per_block() as usize;
    for desc_block_nr in 0..layout.total_desc_blocks() {
        let block = usize::try_from(descriptor_block_loc(layout, desc_block_nr)).expect("the test fixture value fits in usize");
        let block_off = block * block_size;
        for desc_idx in 0..dpb {
            let group = (desc_block_nr as usize) * dpb + desc_idx;
            if group >= layout.group_count() as usize {
                break;
            }
            let desc_off = block_off + desc_idx * desc_size;
            // bg_block_bitmap_lo at offset 0, little-endian u32.
            image[desc_off..desc_off + 4].copy_from_slice(&(u32::try_from(group).expect("the test fixture value fits in u32")).to_le_bytes());
        }
    }
}

#[test]
fn reserve_classical_only_matches_legacy_span() {
    // Group 0 with sparse-super: reserves 1 superblock + total_desc_blocks
    // contiguous GDT blocks + reserved_gdt_blocks at group_first + 1.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 4096,
        desc_size: 64,
        first_data_block: 0,
        blocks_per_group: 32_768,
        group_count: 4, // total_desc_blocks = 1
        first_meta_bg: 0,
        meta_bg: false,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 7,
    })
    .unwrap();
    let mut reserved = alloc::collections::BTreeSet::new();
    reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
    // 1 contiguous GDT block + 7 reserved_gdt_blocks = 8 blocks.
    assert_eq!(reserved.len(), 8);
    // Starting at group_first + 1 = 1.
    assert_eq!(reserved.iter().min().copied(), Some(1));
    assert_eq!(reserved.iter().max().copied(), Some(8));
}

#[test]
fn reserve_meta_bg_pure_reserves_one_block_per_metagroup_position() {
    // 1 KiB blocks, 32-byte descs, desc_per_block = 32, blocks_per_group = 1024.
    // group_count = 64 → 2 metagroups.
    // Metagroup 0: BGs 0, 1, 31 host primary/backup1/backup2 GDT.
    // For group 0 (sparse-super): reserve 1 GDT block at descriptor_block_loc(0).
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 0,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    let mut reserved = alloc::collections::BTreeSet::new();
    reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
    // Pure META_BG, no classical span. Group 0 hosts metagroup 0's primary.
    assert_eq!(reserved.len(), 1);
    assert!(reserved.contains(&descriptor_block_loc(&layout, 0)));

    // Regression: group 32 is the primary host for metagroup 1 but is not a
    // sparse-super group. The caller must reserve META_BG primary blocks even
    // when group_has_super(group) is false.
    reserved.clear();
    reserve_gdt_blocks_resident_in_group(&layout, 32, &mut reserved);
    assert_eq!(reserved.len(), 1);
    assert!(reserved.contains(&descriptor_block_loc(&layout, 1)));

    // Backup1 of metagroup 0: group 1 (sparse-super). primary_bg+1 = 1.
    reserved.clear();
    reserve_gdt_blocks_resident_in_group(&layout, 1, &mut reserved);
    assert_eq!(reserved.len(), 1);
    assert!(
        reserved.contains(&1026),
        "group 1 backup1: bg_first(1025) + has_super(1) = 1026"
    );

    // Backup2 of metagroup 0: group 31 (non-sparse-super). primary_bg+dpb-1 = 31.
    reserved.clear();
    reserve_gdt_blocks_resident_in_group(&layout, 31, &mut reserved);
    assert_eq!(reserved.len(), 1);
    assert!(
        reserved.contains(&31_745),
        "group 31 backup2: bg_first(31745) + has_super(0) = 31745"
    );
}

#[test]
fn reserve_meta_bg_mixed_classical_prefix_uses_first_meta_bg_count() {
    // first_meta_bg = 1: classical-prefix span = 1 contiguous GDT block.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 64,
        first_meta_bg: 1,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 3,
    })
    .unwrap();
    let mut reserved = alloc::collections::BTreeSet::new();
    reserve_gdt_blocks_resident_in_group(&layout, 0, &mut reserved);
    // Group 0 (sparse-super): 1 classical GDT block + 3 reserved = 4 blocks
    // contiguous starting at group_first + 1 = 2.
    assert!(reserved.contains(&2));
    assert!(reserved.contains(&3));
    assert!(reserved.contains(&4));
    assert!(reserved.contains(&5));
    assert_eq!(reserved.len(), 4);
}

#[test]
fn reserve_meta_bg_partial_last_metagroup_dedupes_backups() {
    // group_count = 33 → metagroup 1 has only 1 BG (group 32).
    // Primary, backup1 (group 33 → clamped to 32), backup2 (group 32) all collapse.
    let layout = build_layout(GdtLayoutTestSpec {
        block_size: 1024,
        desc_size: 32,
        first_data_block: 1,
        blocks_per_group: 1024,
        group_count: 33,
        first_meta_bg: 0,
        meta_bg: true,
        sparse_super: true,
        sparse_super2: false,
        backup_bgs: [0, 0],
        reserved_gdt_blocks: 0,
    })
    .unwrap();
    let mut reserved = alloc::collections::BTreeSet::new();
    reserve_gdt_blocks_resident_in_group(&layout, 32, &mut reserved);
    // Group 32 hosts metagroup 1's primary; backup positions collapse onto it.
    assert_eq!(reserved.len(), 1);
    assert!(reserved.contains(&(1u64 + 32 * 1024)));
}
