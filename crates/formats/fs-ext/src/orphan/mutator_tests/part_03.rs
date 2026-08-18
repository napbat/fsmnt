#[test]
fn free_allocations_finalize_updates_superblock_free_count() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

    let first_data_block = first_data_block_of_root(&ext, &mut cursor)
        .expect("root inode has at least one data block");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let pre_sb_free = decode_sb_free_blocks_count(&sb_host_block, &ext);
    let mut mutator = Mutator::new(&ext, &sb_host_block);

    let runs = [AllocationRun {
        physical_start: first_data_block,
        block_len: 1,
        kind: AllocationKind::Data {
            logical_cluster_start: 0,
        },
    }];
    mutator
        .free_allocations(&mut cursor, 2, &runs)
        .expect("free allocation");

    let delta = mutator.finalize(&mut cursor).expect("finalize");
    let sb_override = delta
        .sb_host_override
        .expect("orphan free_allocations updates sb tallies");
    assert_eq!(
        decode_sb_free_blocks_count(&sb_override, &ext),
        pre_sb_free + 1
    );
}

fn read_sb_block<T: crate::io::Read + crate::io::Seek>(ext: &Ext, fs: &mut T) -> Box<[u8]> {
    let sb_host_block_num: u64 = u64::from(ext.block_size() <= 1024);
    let mut sb_bytes = alloc::vec![0u8; ext.block_size() as usize].into_boxed_slice();
    fs.seek(crate::io::SeekFrom::Start(
        sb_host_block_num * u64::from(ext.block_size()),
    ))
    .expect("seek sb host");
    fs.read_exact(&mut sb_bytes).expect("read sb host");
    sb_bytes
}

fn dir_physical_block<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut T,
    inum: u32,
    logical_block: u32,
) -> crate::error::Result<u64> {
    let inode = ext.inode(fs, inum)?;
    let i_block = inode.i_block();
    if inode.flags().contains(crate::inode::InodeFlags::EXTENTS_FL) {
        let extent = crate::extent::resolve_extent(
            ext,
            fs,
            inum,
            inode.generation(),
            &i_block,
            logical_block,
        )?
        .ok_or(crate::error::ExtError::BlockOutOfRange {
            block: u64::from(logical_block),
        })?;
        Ok(extent.physical_block + u64::from(logical_block - extent.logical_block))
    } else {
        crate::block_map::resolve_block_map(ext, fs, &i_block, logical_block)?.ok_or(
            crate::error::ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            },
        )
    }
}

fn read_block<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut T,
    block: u64,
) -> alloc::vec::Vec<u8> {
    let mut buf = alloc::vec![0u8; ext.block_size() as usize];
    fs.seek(crate::io::SeekFrom::Start(
        block * u64::from(ext.block_size()),
    ))
    .expect("seek block");
    fs.read_exact(&mut buf).expect("read block");
    buf
}

fn scratch_inode_links_count(mutator: &Mutator<'_>, ext: &Ext, inum: u32) -> u16 {
    let (inode_block, inode_offset, inode_size) =
        Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
    let scratch = mutator
        .blocks
        .get(&inode_block)
        .expect("inode table block present in scratch");
    read_le_u16(
        &scratch.content[inode_offset..inode_offset + inode_size],
        0x1A,
    )
}

fn finalized_inode_links_count(
    delta: &crate::orphan::plan::OrphanOverlayDelta,
    ext: &Ext,
    inum: u32,
) -> u16 {
    let (inode_block, inode_offset, inode_size) =
        Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
    let block = delta
        .blocks
        .get(&inode_block)
        .expect("inode table block finalized");
    read_le_u16(&block[inode_offset..inode_offset + inode_size], 0x1A)
}

fn set_inode_links_count_in_image(image: &mut [u8], ext: &Ext, inum: u32, links_count: u16) {
    let (inode_block, inode_offset, _inode_size) =
        Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
    let links_offset = usize::try_from(inode_block).expect("the test fixture value fits in usize") * ext.block_size() as usize + inode_offset + 0x1A;
    image[links_offset..links_offset + 2].copy_from_slice(&links_count.to_le_bytes());
}

fn dir_tail_bytes(block: &[u8]) -> Option<&[u8]> {
    if block.len() < 12 {
        return None;
    }
    let tail = &block[block.len() - 12..];
    let inode = u32::from_le_bytes(tail[0..4].try_into().unwrap());
    let rec_len = u16::from_le_bytes(tail[4..6].try_into().unwrap());
    (inode == 0 && rec_len == 12 && tail[6] == 0 && tail[7] == 0xDE).then_some(tail)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawDirEntryForTest {
    inode: u32,
    file_type: u8,
}

fn find_raw_dir_entry(block: &[u8], name: &[u8]) -> Option<RawDirEntryForTest> {
    let usable_end = dir_tail_bytes(block).map_or(block.len(), |tail| block.len() - tail.len());
    let mut offset = 0usize;
    while offset + 8 <= usable_end {
        let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
        if rec_len < 8 || rec_len % 4 != 0 {
            return None;
        }
        let name_len = usize::from(block[offset + 6]);
        let file_type = block[offset + 7];
        let next = offset + usize::from(rec_len);
        if next > usable_end || offset + 8 + name_len > next {
            return None;
        }
        if inode != 0 && &block[offset + 8..offset + 8 + name_len] == name {
            return Some(RawDirEntryForTest { inode, file_type });
        }
        offset = next;
    }
    None
}

fn write_test_dir_entry(
    block: &mut [u8],
    offset: usize,
    inode: u32,
    rec_len: u16,
    name: &[u8],
    file_type: u8,
) {
    block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
    block[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
    block[offset + 6] = (name.len()).to_le_bytes()[0];
    block[offset + 7] = file_type;
    block[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
}

fn set_inode_flags_in_image(
    image: &mut [u8],
    ext: &Ext,
    inum: u32,
    flags: crate::inode::InodeFlags,
) {
    let (inode_block, inode_offset, _inode_size) =
        Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
    let flags_offset = usize::try_from(inode_block).expect("the test fixture value fits in usize") * ext.block_size() as usize + inode_offset + 0x20;
    let existing =
        u32::from_le_bytes(image[flags_offset..flags_offset + 4].try_into().unwrap());
    image[flags_offset..flags_offset + 4]
        .copy_from_slice(&(existing | flags.bits()).to_le_bytes());
}

fn synthetic_bigalloc_ext(
    group_count: u32,
    first_data_block: u32,
    blocks_per_group: u32,
    metadata_csum: bool,
) -> Ext {
    let desc_size = if metadata_csum { 64 } else { 32 };
    let mut ro_compat = crate::feature_flags::RoCompatFeatures::BIGALLOC;
    if metadata_csum {
        ro_compat |= crate::feature_flags::RoCompatFeatures::METADATA_CSUM;
    }
    let group_descs = (0..group_count)
        .map(|group| crate::block_group::GroupDescriptor {
            block_bitmap: 20 + u64::from(group) * 3,
            inode_bitmap: 21 + u64::from(group) * 3,
            inode_table: 22 + u64::from(group) * 3,
            free_blocks_count: 10,
            free_inodes_count: 0,
            flags: 0,
            checksum: crate::checksum::ChecksumState::Unknown,
        })
        .collect();

    Ext {
        inodes_count: 64,
        blocks_count: u64::from(first_data_block)
            .saturating_add(u64::from(group_count) * u64::from(blocks_per_group))
            .max(128),
        block_size: 1024,
        group_count,
        inodes_per_group: 4,
        inode_size: 128,
        first_data_block,
        gdt_layout: crate::block_group::GdtLayout::from_parts(
            first_data_block,
            1024,
            blocks_per_group,
            desc_size,
            0,
            false,
            false,
            false,
            [0, 0],
            group_count,
            0,
        )
        .expect("test layout"),
        blocks_per_group,
        cluster_size: 4096,
        blocks_per_cluster: 4,
        clusters_per_group: blocks_per_group / 4,
        backup_bgs: [0, 0],
        desc_size,
        incompat: crate::feature_flags::IncompatFeatures::empty(),
        ro_compat,
        compat: crate::feature_flags::CompatFeatures::empty(),
        journal_inum: 0,
        journal_uuid: [0u8; 16],
        orphan_file_inum: 0,
        usr_quota_inum: 0,
        grp_quota_inum: 0,
        prj_quota_inum: 0,
        is_64bit: metadata_csum,
        uuid: [0xA5u8; 16],
        hash_seed: [0u32; 4],
        group_descs,
        checksum_seed: metadata_csum.then_some(0x1234_5678),
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

fn synthetic_overlay(ext: &Ext) -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec![0u8; usize::try_from(ext.blocks_count).expect("the test fixture value fits in usize") * ext.block_size() as usize];
    for group in 0..ext.group_count {
        let desc_offset = gdt_desc_byte_offset(ext, group);
        let desc = &mut bytes[desc_offset..desc_offset + usize::from(ext.desc_size)];
        let gdp = &ext.group_descs[group as usize];
        desc[0x00..0x04].copy_from_slice(&(u32::try_from(gdp.block_bitmap).expect("the test fixture value fits in u32")).to_le_bytes());
        desc[0x04..0x08].copy_from_slice(&(u32::try_from(gdp.inode_bitmap).expect("the test fixture value fits in u32")).to_le_bytes());
        desc[0x08..0x0C].copy_from_slice(&(u32::try_from(gdp.inode_table).expect("the test fixture value fits in u32")).to_le_bytes());
        desc[0x0C..0x0E].copy_from_slice(&(u16::try_from(gdp.free_blocks_count).expect("the test fixture value fits in u16")).to_le_bytes());
        desc[0x0E..0x10].copy_from_slice(&(u16::try_from(gdp.free_inodes_count).expect("the test fixture value fits in u16")).to_le_bytes());
        desc[0x12..0x14].copy_from_slice(&gdp.flags.to_le_bytes());
        if ext.desc_size >= 64 {
            desc[0x2C..0x2E]
                .copy_from_slice(&((gdp.free_blocks_count >> 16) as u16).to_le_bytes());
            desc[0x2E..0x30]
                .copy_from_slice(&((gdp.free_inodes_count >> 16) as u16).to_le_bytes());
        }
    }
    bytes
}

fn set_synthetic_bitmap_bit(
    bytes: &mut [u8],
    ext: &Ext,
    group: u32,
    bit: u64,
    allocated: bool,
) {
    let block = ext.group_descs[group as usize].block_bitmap;
    let byte_offset = usize::try_from(block).expect("the test fixture value fits in usize") * ext.block_size() as usize + (bit / 8) as usize;
    let mask = 1u8 << (bit % 8);
    if allocated {
        bytes[byte_offset] |= mask;
    } else {
        bytes[byte_offset] &= !mask;
    }
}

fn finalized_gdt_block<'a>(
    delta: &'a crate::orphan::plan::OrphanOverlayDelta,
    ext: &Ext,
    group: u32,
) -> &'a [u8] {
    let gdt_block = u64::from(ext.first_data_block)
        + 1
        + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
    delta.blocks.get(&gdt_block).expect("gdt dirtied")
}

fn finalized_group_desc<'a>(
    delta: &'a crate::orphan::plan::OrphanOverlayDelta,
    ext: &Ext,
    group: u32,
) -> &'a [u8] {
    let gdt = finalized_gdt_block(delta, ext, group);
    let offset =
        usize::try_from(u64::from(group) * u64::from(ext.desc_size) % u64::from(ext.block_size)).expect("the test fixture value fits in usize");
    &gdt[offset..offset + usize::from(ext.desc_size)]
}

fn finalized_bitmap<'a>(
    delta: &'a crate::orphan::plan::OrphanOverlayDelta,
    ext: &Ext,
    group: u32,
) -> &'a [u8] {
    let bitmap_block = ext.group_descs[group as usize].block_bitmap;
    delta.blocks.get(&bitmap_block).expect("bitmap dirtied")
}

fn gdt_desc_byte_offset(ext: &Ext, group: u32) -> usize {
    usize::try_from((u64::from(ext.first_data_block) + 1) * u64::from(ext.block_size)
        + u64::from(group) * u64::from(ext.desc_size)).expect("the test fixture value fits in usize")
}

fn decode_bg_free_blocks_count(gdt_block_bytes: &[u8], ext: &Ext, group: u32) -> u32 {
    let byte_offset = (u64::from(group) * u64::from(ext.desc_size)) % u64::from(ext.block_size);
    let desc =
        &gdt_block_bytes[usize::try_from(byte_offset).expect("the test fixture value fits in usize")..usize::try_from(byte_offset).expect("the test fixture value fits in usize") + ext.desc_size as usize];
    let lo = u32::from(u16::from_le_bytes(desc[0x0C..0x0E].try_into().unwrap()));
    let hi = if ext.desc_size >= 64 {
        u32::from(u16::from_le_bytes(desc[0x2C..0x2E].try_into().unwrap()))
    } else {
        0
    };
    (hi << 16) | lo
}

fn decode_sb_free_blocks_count(sb_host_bytes: &[u8], ext: &Ext) -> u64 {
    let sb_offset = if ext.block_size() > 1024 { 1024 } else { 0 };
    let lo = u32::from_le_bytes(
        sb_host_bytes[sb_offset + 0x0C..sb_offset + 0x10]
            .try_into()
            .unwrap(),
    );
    let hi = if ext.is_64bit {
        u32::from_le_bytes(
            sb_host_bytes[sb_offset + 0x150..sb_offset + 0x154]
                .try_into()
                .unwrap(),
        )
    } else {
        0
    };
    (u64::from(hi) << 32) | u64::from(lo)
}

fn decode_block_bitmap_bit(bitmap_bytes: &[u8], bit: u64) -> bool {
    let byte = (bit / 8) as usize;
    let mask = 1u8 << (bit % 8);
    bitmap_bytes[byte] & mask != 0
}

#[test]
fn block_class_group_descriptor_carries_desc_block_nr() {
    // Constructing the variant requires the new field.
    let class = BlockClass::GroupDescriptor { desc_block_nr: 7 };
    if let BlockClass::GroupDescriptor { desc_block_nr } = class {
        assert_eq!(desc_block_nr, 7);
    } else {
        panic!("variant mismatch");
    }
}

#[test]
fn group_desc_slot_classical_unchanged() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = crate::Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host = alloc::vec![0u8; ext.block_size() as usize];
    let mutator = Mutator::new(&ext, &sb_host);

    // Classical layout: gdt_block = first_data_block + 1 + group / desc_per_block.
    let (gdt_block, _, _) = mutator.group_desc_slot(0).expect("group 0 slot");
    let expected = u64::from(ext.first_data_block) + 1;
    assert_eq!(gdt_block, expected);
}

#[test]
fn descriptor_recompute_uses_block_class_metadata_not_arithmetic() {
    if !crate::test_support::fixture_available("ext4-meta-bg.img") {
        eprintln!("skipping: ext4-meta-bg.img fixture not generated");
        return;
    }
    let mut cursor = crate::test_support::load_image("ext4-meta-bg.img");
    let ext = crate::Ext::new(&mut cursor).expect("open ext4-meta-bg.img");
    let dpb = ext.gdt_layout.desc_per_block();
    let group = dpb; // first group of metagroup 1 — in the META_BG range.
    if group >= ext.group_count() {
        eprintln!("skipping: fixture too small");
        return;
    }

    let sb_host = alloc::vec![0u8; ext.block_size() as usize];
    let mut mutator = Mutator::new(&ext, &sb_host);

    // Mark a block in `group` free to dirty that group's GDT descriptor.
    let group_first =
        u64::from(ext.first_data_block) + u64::from(group) * u64::from(ext.blocks_per_group);
    mutator
        .mark_block_range_free(&mut cursor, group_first + 100, 1)
        .expect("mark free");

    let delta = mutator.finalize(&mut cursor).expect("finalize");

    // The META_BG GDT block for `group` must appear in the overlay.
    let expected_gdt_block =
        crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group);
    let bytes = delta
        .blocks
        .get(&expected_gdt_block)
        .expect("META_BG GDT block must be patched");

    // The recomputed CRC for `group` must validate.
    let csum_seed = ext
        .checksum_seed()
        .expect("metadata_csum must be on for this fixture");
    let desc_idx = (group % dpb) as usize;
    let desc_size = usize::from(ext.desc_size);
    let off = desc_idx * desc_size;
    let state = crate::checksum::verify_group_descriptor(
        csum_seed,
        group,
        &bytes[off..off + desc_size],
    );
    assert!(
        matches!(state, crate::checksum::ChecksumState::Valid),
        "recomputed CRC must validate, got {state:?}"
    );
}

#[test]
fn group_desc_slot_meta_bg_pure_uses_descriptor_block_for_group() {
    if !crate::test_support::fixture_available("ext4-meta-bg.img") {
        eprintln!("skipping: ext4-meta-bg.img fixture not generated");
        return;
    }
    let mut cursor = crate::test_support::load_image("ext4-meta-bg.img");
    let ext = crate::Ext::new(&mut cursor).expect("open ext4-meta-bg.img");
    assert!(ext.is_meta_bg());

    let sb_host = alloc::vec![0u8; ext.block_size() as usize];
    let mutator = Mutator::new(&ext, &sb_host);

    // Pick a group in the META_BG range (any group in metagroup >= 1).
    let dpb = ext.gdt_layout.desc_per_block();
    let group_in_meta_bg = dpb; // first group of metagroup 1.
    if group_in_meta_bg >= ext.group_count() {
        eprintln!("skipping: fixture too small for META_BG range");
        return;
    }
    let (gdt_block, _, _) = mutator.group_desc_slot(group_in_meta_bg).expect("slot");

    // Expected via the new helper; must NOT match classical formula.
    let expected =
        crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group_in_meta_bg);
    let classical =
        u64::from(ext.first_data_block) + 1 + u64::from(group_in_meta_bg) / u64::from(dpb);
    assert_eq!(gdt_block, expected);
    assert_ne!(
        gdt_block, classical,
        "META_BG block must not equal classical formula"
    );
}

#[test]
fn group_desc_slot_meta_bg_mixed() {
    if !crate::test_support::fixture_available("ext4-meta-bg.img") {
        eprintln!("skipping: ext4-meta-bg.img fixture not generated");
        return;
    }
    let mut bytes = crate::test_support::load_image("ext4-meta-bg.img").into_inner();

    // Patch s_first_meta_bg = 1 to enable mixed mode: groups in metagroup 0
    // use the classical GDT layout, groups >= dpb use the META_BG layout.
    let s_first_meta_bg_offset = 1024 + 0x104;
    bytes[s_first_meta_bg_offset..s_first_meta_bg_offset + 4]
        .copy_from_slice(&1u32.to_le_bytes());
    let sb: &[u8; 1024] = (&bytes[1024..2048]).try_into().unwrap();
    let new_csum = crate::checksum::compute_superblock_csum(sb);
    bytes[1024 + 0x3FC..1024 + 0x400].copy_from_slice(&new_csum.to_le_bytes());

    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = crate::Ext::new(&mut cursor).expect("open mixed-mode patch");
    assert!(ext.is_meta_bg());
    assert_eq!(ext.gdt_layout.first_meta_bg(), 1);

    let sb_host = alloc::vec![0u8; ext.block_size() as usize];
    let mutator = Mutator::new(&ext, &sb_host);

    // Group 0 is in the classical prefix (desc_block_nr 0 < first_meta_bg=1).
    let (gdt_block_classical, _, _) = mutator.group_desc_slot(0).expect("slot 0");
    let expected_classical = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, 0);
    assert_eq!(gdt_block_classical, expected_classical);

    // Group dpb is the first group in metagroup 1 (META_BG range).
    let dpb = ext.gdt_layout.desc_per_block();
    if dpb >= ext.group_count() {
        eprintln!("skipping mixed-mode META_BG branch: fixture too small");
        return;
    }
    let (gdt_block_meta_bg, _, _) = mutator.group_desc_slot(dpb).expect("slot dpb");
    let expected_meta_bg = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, dpb);
    assert_eq!(gdt_block_meta_bg, expected_meta_bg);

    // Mixed-mode produces different GDT block addresses for the two groups.
    assert_ne!(
        gdt_block_classical, gdt_block_meta_bg,
        "mixed-mode classical and META_BG groups must resolve to different GDT blocks"
    );
}
