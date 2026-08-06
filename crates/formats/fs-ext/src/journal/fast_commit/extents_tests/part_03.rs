#[test]
fn del_range_bigalloc_rejects_full_cluster_delete_with_same_cluster_survivor() {
    let (ext, mut cursor, mut mutator) = fixture_bigalloc_mutator(4);
    stage_inode_root(
        ext,
        &mut cursor,
        &mut mutator,
        TEST_INUM,
        leaf_root(
            &[raw_extent(0, 4, 100, false), raw_extent(10, 1, 102, false)],
            4,
        ),
    );

    let outcome = {
        let mut surgeon = ExtentSurgeon::new(ext, &mut cursor, &mut mutator);
        surgeon.del_range(TEST_INUM, 0, 3).expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPartialClusterDelRange)
    ));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 4, 100, false), (10, 1, 102, false)]
    );
}

#[test]
fn extent_len_encoding_boundaries_match_ext4_encoding() {
    assert_eq!(
        super::encode_extent_len(32768, false, TEST_INUM).expect("initialized max"),
        32768
    );
    assert_eq!(
        super::encode_extent_len(32767, true, TEST_INUM).expect("unwritten max"),
        65535
    );
    assert!(matches!(
        super::encode_extent_len(32768, true, TEST_INUM),
        Err(ExtError::InvalidExtentHeader { inode: TEST_INUM })
    ));
}

fn fixture_mutator() -> (&'static Ext, fsmnt_testkit::Cursor<Vec<u8>>, Mutator<'static>) {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4.img");
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let ext = Box::leak(Box::new(ext));
    let mutator = Mutator::new(ext, &sb_host_block);
    (ext, cursor, mutator)
}

fn fixture_mutator_with_first_data_block(
    first_data_block: u32,
) -> (&'static Ext, fsmnt_testkit::Cursor<Vec<u8>>, Mutator<'static>) {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4.img");
    ext.first_data_block = first_data_block;
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let ext = Box::leak(Box::new(ext));
    let mutator = Mutator::new(ext, &sb_host_block);
    (ext, cursor, mutator)
}

fn fixture_bigalloc_mutator(
    blocks_per_cluster: u32,
) -> (&'static Ext, fsmnt_testkit::Cursor<Vec<u8>>, Mutator<'static>) {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4.img");
    ext.ro_compat
        .insert(crate::feature_flags::RoCompatFeatures::BIGALLOC);
    ext.blocks_per_cluster = blocks_per_cluster;
    ext.cluster_size = ext.block_size * blocks_per_cluster;
    ext.clusters_per_group = ext.blocks_per_group / blocks_per_cluster;
    let sb_host_block = read_sb_block(&ext, &mut cursor);
    let ext = Box::leak(Box::new(ext));
    let mutator = Mutator::new(ext, &sb_host_block);
    (ext, cursor, mutator)
}

fn assert_del_range_applied_needs_shrink(
    outcome: &ExtentSurgeryOutcome,
    expected_end_block_exclusive: u32,
) {
    assert_eq!(shrink_end_block_exclusive(outcome), expected_end_block_exclusive);
}

fn shrink_end_block_exclusive(outcome: &ExtentSurgeryOutcome) -> u32 {
    let ExtentSurgeryOutcome::AppliedNeedsShrink {
        end_block_exclusive,
    } = outcome
    else {
        panic!("unexpected outcome: {outcome:?}");
    };
    *end_block_exclusive
}

fn assert_bigalloc_partial_cluster_delete_rejected_without_dirtying(
    lblk_start: u32,
    lblk_end_inclusive: u32,
) {
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
        surgeon
            .del_range(TEST_INUM, lblk_start, lblk_end_inclusive)
            .expect("delete range")
    };

    assert!(matches!(
        outcome,
        ExtentSurgeryOutcome::Failed(super::ExtentReplayReason::BigallocPartialClusterDelRange)
    ));
    let delta = mutator.finalize(&mut cursor).expect("finalize");
    assert_eq!(
        finalized_inode_extent_records(&delta.blocks, ext, TEST_INUM),
        vec![(0, 4, 100, false)]
    );
    assert!(
        !delta.blocks.contains_key(&ext.group_descs[0].block_bitmap),
        "partial-cluster failure must happen before bitmap scratch is staged"
    );
}

fn raw_extent(ee_block: u32, ee_len: u16, ee_pblk: u64, unwritten: bool) -> RawExtent {
    RawExtent {
        ee_block,
        ee_len,
        ee_pblk,
        unwritten,
    }
}

fn leaf_root(extents: &[RawExtent], max: u16) -> [u8; 60] {
    let mut root = [0u8; 60];
    root[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    root[2..4].copy_from_slice(&(u16::try_from(extents.len()).expect("the test fixture value fits in u16")).to_le_bytes());
    root[4..6].copy_from_slice(&max.to_le_bytes());
    for (idx, extent) in extents.iter().enumerate() {
        write_extent_record(&mut root, 12 + idx * 12, *extent);
    }
    root
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

fn leaf_block_bytes(ext: &Ext, extents: &[RawExtent], max: u16, depth: u16) -> Vec<u8> {
    let mut block = vec![0u8; ext.block_size() as usize];
    block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    block[2..4].copy_from_slice(&(u16::try_from(extents.len()).expect("the test fixture value fits in u16")).to_le_bytes());
    block[4..6].copy_from_slice(&max.to_le_bytes());
    block[6..8].copy_from_slice(&depth.to_le_bytes());
    for (idx, extent) in extents.iter().enumerate() {
        write_extent_record(&mut block, 12 + idx * 12, *extent);
    }
    block
}

fn index_block_bytes(ext: &Ext, entries: &[(u32, u64)], max: u16, depth: u16) -> Vec<u8> {
    let mut block = vec![0u8; ext.block_size() as usize];
    block[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
    block[2..4].copy_from_slice(&(u16::try_from(entries.len()).expect("the test fixture value fits in u16")).to_le_bytes());
    block[4..6].copy_from_slice(&max.to_le_bytes());
    block[6..8].copy_from_slice(&depth.to_le_bytes());
    for (idx, &(logical, child)) in entries.iter().enumerate() {
        write_index_record(&mut block, 12 + idx * 12, logical, child);
    }
    block
}

fn write_extent_record(buf: &mut [u8], offset: usize, extent: RawExtent) {
    buf[offset..offset + 4].copy_from_slice(&extent.ee_block.to_le_bytes());
    buf[offset + 4..offset + 6].copy_from_slice(&encoded_len(extent).to_le_bytes());
    buf[offset + 6..offset + 8].copy_from_slice(&(u16::try_from(extent.ee_pblk >> 32).expect("the test fixture value fits in u16")).to_le_bytes());
    buf[offset + 8..offset + 12].copy_from_slice(&(u32::try_from(extent.ee_pblk).expect("the test fixture value fits in u32")).to_le_bytes());
}

fn write_index_record(buf: &mut [u8], offset: usize, logical: u32, child: u64) {
    buf[offset..offset + 4].copy_from_slice(&logical.to_le_bytes());
    buf[offset + 4..offset + 8].copy_from_slice(&(u32::try_from(child).expect("the test fixture value fits in u32")).to_le_bytes());
    buf[offset + 8..offset + 10].copy_from_slice(&(u16::try_from(child >> 32).expect("the test fixture value fits in u16")).to_le_bytes());
}

fn encoded_len(extent: RawExtent) -> u16 {
    if extent.unwritten {
        extent.ee_len + 32768
    } else {
        extent.ee_len
    }
}

fn stage_inode_root<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    cursor: &mut T,
    mutator: &mut Mutator<'_>,
    inum: u32,
    root: [u8; 60],
) {
    assert!(inum <= ext.inodes_count);
    mutator
        .patch_inode_scratch(cursor, inum, |inode_bytes| {
            inode_bytes[0x00..0x02].copy_from_slice(&0x81A4u16.to_le_bytes());
            let flags = u32::from_le_bytes(inode_bytes[0x20..0x24].try_into().unwrap())
                | crate::inode::InodeFlags::EXTENTS_FL.bits();
            inode_bytes[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
            inode_bytes[0x28..0x28 + 60].copy_from_slice(&root);
            Ok(())
        })
        .expect("stage inode root");
}

fn stage_inode_size<T: crate::io::Read + crate::io::Seek>(
    cursor: &mut T,
    mutator: &mut Mutator<'_>,
    inum: u32,
    size: u64,
) {
    mutator
        .patch_inode_scratch(cursor, inum, |inode_bytes| {
            let size_bytes = size.to_le_bytes();
            inode_bytes[0x04..0x08].copy_from_slice(&size_bytes[..4]);
            inode_bytes[0x6C..0x70].copy_from_slice(&size_bytes[4..]);
            Ok(())
        })
        .expect("stage inode size");
}

fn stage_extent_block<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    cursor: &mut T,
    mutator: &mut Mutator<'_>,
    inum: u32,
    block: u64,
    content: impl AsRef<[u8]>,
) {
    let content = content.as_ref();
    assert_eq!(content.len(), ext.block_size() as usize);
    mutator
        .patch_extent_block(cursor, block, inum, 0, |block_bytes| {
            block_bytes.copy_from_slice(content);
            Ok(())
        })
        .expect("stage extent block");
}

fn write_disk_block(
    ext: &Ext,
    cursor: &mut fsmnt_testkit::Cursor<Vec<u8>>,
    block: u64,
    content: &[u8],
) {
    assert_eq!(content.len(), ext.block_size() as usize);
    cursor
        .seek(SeekFrom::Start(block * u64::from(ext.block_size())))
        .expect("seek disk block");
    cursor.write_all(content).expect("write disk block");
}

fn finalized_inode_extent_root<'a>(
    blocks: &'a BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    inum: u32,
) -> &'a [u8] {
    let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
    &inode_bytes[0x28..0x28 + 60]
}

fn finalized_inode_extent_records(
    blocks: &BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    inum: u32,
) -> Vec<(u32, u16, u64, bool)> {
    let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
    let root = &inode_bytes[0x28..0x28 + 60];
    let entries = u16::from_le_bytes(root[2..4].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for idx in 0..entries {
        let off = 12 + idx * 12;
        let ee_block = u32::from_le_bytes(root[off..off + 4].try_into().unwrap());
        let ee_len_raw = u16::from_le_bytes(root[off + 4..off + 6].try_into().unwrap());
        let unwritten = ee_len_raw > 32768;
        let ee_len = if unwritten {
            ee_len_raw - 32768
        } else {
            ee_len_raw
        };
        let hi = u16::from_le_bytes(root[off + 6..off + 8].try_into().unwrap());
        let lo = u32::from_le_bytes(root[off + 8..off + 12].try_into().unwrap());
        let pblk = (u64::from(hi) << 32) | u64::from(lo);
        out.push((ee_block, ee_len, pblk, unwritten));
    }
    out
}

fn finalized_inode_size(blocks: &BTreeMap<u64, Box<[u8]>>, ext: &Ext, inum: u32) -> u64 {
    let inode_bytes = finalized_inode_bytes(blocks, ext, inum);
    let lo = u32::from_le_bytes(inode_bytes[0x04..0x08].try_into().unwrap());
    let hi = u32::from_le_bytes(inode_bytes[0x6C..0x70].try_into().unwrap());
    u64::from(lo) | (u64::from(hi) << 32)
}

fn finalized_inode_bytes<'a>(
    blocks: &'a BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    inum: u32,
) -> &'a [u8] {
    let (block, offset, size) = inode_table_slot(ext, inum);
    let block_bytes = blocks.get(&block).expect("inode table block finalized");
    &block_bytes[offset..offset + size]
}

fn inode_table_slot(ext: &Ext, inum: u32) -> (u64, usize, usize) {
    let group = (inum - 1) / ext.inodes_per_group;
    let index_in_group = u64::from((inum - 1) % ext.inodes_per_group);
    let inode_size = u64::from(ext.inode_size());
    let byte_in_table = index_in_group * inode_size;
    let block_size = u64::from(ext.block_size());
    let table_block = ext.group_descs[group as usize].inode_table;
    let block = table_block + byte_in_table / block_size;
    let offset = usize::try_from(byte_in_table % block_size).expect("the test fixture value fits in usize");
    (block, offset, usize::try_from(inode_size).expect("the test fixture value fits in usize"))
}

fn finalized_block_bitmap_bit(blocks: &BTreeMap<u64, Box<[u8]>>, ext: &Ext, pblk: u64) -> bool {
    let group =
        usize::try_from((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group)).expect("the test fixture value fits in usize");
    let bitmap_block = ext.group_descs[group].block_bitmap;
    let bitmap = blocks.get(&bitmap_block).expect("bitmap block finalized");
    let block_in_group =
        (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
    let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
    let byte = (alloc_unit / 8) as usize;
    let bit = (alloc_unit % 8) as u8;
    bitmap[byte] & (1u8 << bit) != 0
}

fn finalized_extent_block_records(
    blocks: &BTreeMap<u64, Box<[u8]>>,
    block: u64,
) -> Vec<(u32, u16, u64, bool)> {
    let block_bytes = blocks.get(&block).expect("extent block finalized");
    decoded_extent_records(block_bytes)
}

fn index_child(node: &[u8], idx: usize) -> u64 {
    let off = 12 + idx * 12;
    let lo = u32::from_le_bytes(node[off + 4..off + 8].try_into().unwrap());
    let hi = u16::from_le_bytes(node[off + 8..off + 10].try_into().unwrap());
    (u64::from(hi) << 32) | u64::from(lo)
}

fn index_root_first_child(root: &[u8]) -> u64 {
    index_child(root, 0)
}

fn index_root_second_child(root: &[u8]) -> u64 {
    index_child(root, 1)
}

fn verify_finalized_extent_block(
    blocks: &BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    inum: u32,
    block: u64,
) -> bool {
    let Some(seed) = ext.checksum_seed() else {
        return true;
    };
    let block_bytes = blocks.get(&block).expect("extent block finalized");
    crate::checksum::verify_extent_block(seed, inum, 0, block_bytes)
        == crate::checksum::ChecksumState::Valid
}

/// Walk the finalized extent tree (inode root + external blocks) and
/// collect every leaf extent record, sorted by logical block.
fn finalized_all_leaf_records<T: crate::io::Read + crate::io::Seek>(
    blocks: &BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    inum: u32,
    cursor: &mut T,
) -> Vec<(u32, u16, u64, bool)> {
    let root = finalized_inode_extent_root(blocks, ext, inum).to_vec();
    let mut out = Vec::new();
    collect_leaf_records(blocks, ext, &root, cursor, &mut out);
    out.sort_by_key(|record| record.0);
    out
}

fn collect_leaf_records<T: crate::io::Read + crate::io::Seek>(
    blocks: &BTreeMap<u64, Box<[u8]>>,
    ext: &Ext,
    node: &[u8],
    cursor: &mut T,
    out: &mut Vec<(u32, u16, u64, bool)>,
) {
    let depth = u16::from_le_bytes(node[6..8].try_into().unwrap());
    let entries = u16::from_le_bytes(node[2..4].try_into().unwrap()) as usize;
    if depth == 0 {
        out.extend(decoded_extent_records(node));
        return;
    }
    for idx in 0..entries {
        let child = index_child(node, idx);
        let child_bytes = blocks.get(&child).cloned().unwrap_or_else(|| {
            let mut buf = vec![0u8; ext.block_size() as usize];
            cursor
                .seek(SeekFrom::Start(child * u64::from(ext.block_size())))
                .expect("seek child");
            cursor.read_exact(&mut buf).expect("read child");
            buf.into_boxed_slice()
        });
        collect_leaf_records(blocks, ext, &child_bytes, cursor, out);
    }
}

fn decoded_extent_records(node: &[u8]) -> Vec<(u32, u16, u64, bool)> {
    let entries = u16::from_le_bytes(node[2..4].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for idx in 0..entries {
        let off = 12 + idx * 12;
        let ee_block = u32::from_le_bytes(node[off..off + 4].try_into().unwrap());
        let ee_len_raw = u16::from_le_bytes(node[off + 4..off + 6].try_into().unwrap());
        let unwritten = ee_len_raw > 32768;
        let ee_len = if unwritten {
            ee_len_raw - 32768
        } else {
            ee_len_raw
        };
        let hi = u16::from_le_bytes(node[off + 6..off + 8].try_into().unwrap());
        let lo = u32::from_le_bytes(node[off + 8..off + 12].try_into().unwrap());
        let pblk = (u64::from(hi) << 32) | u64::from(lo);
        out.push((ee_block, ee_len, pblk, unwritten));
    }
    out
}

fn first_root_data_block<T: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    cursor: &mut T,
) -> u64 {
    let inode = ext.inode(cursor, 2).expect("root inode");
    let i_block = inode.i_block();
    crate::extent::resolve_extent(ext, cursor, 2, inode.generation(), &i_block, 0)
        .expect("resolve root extent")
        .expect("root extent")
        .physical_block
}

fn read_sb_block<T: crate::io::Read + crate::io::Seek>(ext: &Ext, fs: &mut T) -> Box<[u8]> {
    let sb_host_block_num: u64 = u64::from(ext.block_size() <= 1024);
    let mut sb_bytes = vec![0u8; ext.block_size() as usize].into_boxed_slice();
    fs.seek(SeekFrom::Start(
        sb_host_block_num * u64::from(ext.block_size()),
    ))
    .expect("seek sb host");
    fs.read_exact(&mut sb_bytes).expect("read sb host");
    sb_bytes
}
