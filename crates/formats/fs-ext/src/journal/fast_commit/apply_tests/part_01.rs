use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fs_common::iter::FsTryIterator;

use crate::io::{Read, Seek, SeekFrom};
use crate::journal::fast_commit::extents::RawExtent;
use crate::journal::fast_commit::parse::scan_fc_region;
use crate::journal::fast_commit::test_support::{FcTxBuilder, fc_region};
use crate::journal::fast_commit::tlv::FC_TAG_INODE;
use crate::journal::replay::BlockOverlay;
use crate::journal::{DirectoryReplayReason, ExtentReplayReason, FastCommitStopReason};

use super::*;

const BS: u32 = 4096;
const FC_FIRST: u32 = 100;
const TID: u32 = 100;
const EXTENT_MAGIC: u16 = 0xF30A;

fn classic_overlay_for_fixture(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
) -> BlockOverlay {
    let block_size = ext.block_size();
    let sb_host_block = u64::from(block_size <= 1024);
    cursor
        .seek(SeekFrom::Start(sb_host_block * u64::from(block_size)))
        .expect("seek sb host block");
    let mut sb_host_content = alloc::vec![0u8; block_size as usize];
    cursor
        .read_exact(&mut sb_host_content)
        .expect("read sb host block");
    BlockOverlay {
        block_size,
        blocks: BTreeMap::new(),
        sb_host_block,
        sb_host_block_content: sb_host_content.into_boxed_slice(),
    }
}

fn fixture_ext() -> (crate::Ext, std::io::Cursor<Vec<u8>>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(path).expect("read ext4 fixture");
    let mut cursor = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
    (ext, cursor)
}

fn raw_inode_from_overlay(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    inum: u32,
) -> Vec<u8> {
    let group = (inum - 1) / ext.inodes_per_group;
    let index = (inum - 1) % ext.inodes_per_group;
    let table_block = ext.group_descs[group as usize].inode_table;
    let byte_offset = table_block * u64::from(ext.block_size())
        + u64::from(index) * u64::from(ext.inode_size());
    let mut reader = compose_reader(cursor, overlay);
    reader
        .seek(SeekFrom::Start(byte_offset))
        .expect("seek raw inode");
    let mut bytes = alloc::vec![0u8; usize::from(ext.inode_size())];
    reader.read_exact(&mut bytes).expect("read raw inode");
    bytes
}

fn read_links_count_from_overlay(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    inum: u32,
) -> u16 {
    let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
    u16::from_le_bytes(inode[0x1A..0x1C].try_into().unwrap())
}

fn inode_byte_offset(ext: &crate::Ext, inum: u32, inode_relative_offset: usize) -> usize {
    let group = (inum - 1) / ext.inodes_per_group;
    let index = (inum - 1) % ext.inodes_per_group;
    let table_block = ext.group_descs[group as usize].inode_table;
    usize::try_from(table_block).expect("the test fixture value fits in usize") * ext.block_size() as usize
        + index as usize * usize::from(ext.inode_size())
        + inode_relative_offset
}

fn set_links_count_in_image(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    inum: u32,
    links_count: u16,
) {
    let offset = inode_byte_offset(ext, inum, 0x1A);
    cursor.get_mut()[offset..offset + 2].copy_from_slice(&links_count.to_le_bytes());
}

fn write_raw_inode_to_image(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    inum: u32,
    raw_inode: &[u8],
) {
    let offset = inode_byte_offset(ext, inum, 0);
    let len = usize::from(ext.inode_size());
    assert_eq!(raw_inode.len(), len);
    cursor.get_mut()[offset..offset + len].copy_from_slice(raw_inode);
}

fn set_inode_mode(raw_inode: &mut [u8], mode: u16) {
    raw_inode[0..2].copy_from_slice(&mode.to_le_bytes());
}

fn set_inode_size(raw_inode: &mut [u8], size: u64) {
    raw_inode[0x04..0x08].copy_from_slice(&(u32::try_from(size).expect("the test fixture value fits in u32")).to_le_bytes());
    raw_inode[0x6C..0x70].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
}

fn set_inode_extent_root(raw_inode: &mut [u8], root: [u8; 60]) {
    set_inode_mode(raw_inode, S_IFREG | 0o644);
    let flags = u32::from_le_bytes(raw_inode[0x20..0x24].try_into().unwrap())
        | crate::inode::InodeFlags::EXTENTS_FL.bits();
    raw_inode[0x20..0x24].copy_from_slice(&flags.to_le_bytes());
    raw_inode[0x28..0x28 + 60].copy_from_slice(&root);
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

fn write_extent_record(buf: &mut [u8], offset: usize, extent: RawExtent) {
    buf[offset..offset + 4].copy_from_slice(&extent.ee_block.to_le_bytes());
    buf[offset + 4..offset + 6].copy_from_slice(&encoded_len(extent).to_le_bytes());
    buf[offset + 6..offset + 8].copy_from_slice(&(u16::try_from(extent.ee_pblk >> 32 ).expect("the test fixture value fits in u16")).to_le_bytes());
    buf[offset + 8..offset + 12].copy_from_slice(&(u32::try_from(extent.ee_pblk).expect("the test fixture value fits in u32")).to_le_bytes());
}

fn encoded_len(extent: RawExtent) -> u16 {
    if extent.unwritten {
        extent.ee_len + 32768
    } else {
        extent.ee_len
    }
}

fn inode_extent_records(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    inum: u32,
) -> Vec<(u32, u16, u64, bool)> {
    let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
    decoded_extent_records(&inode[0x28..0x28 + 60])
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
        out.push((
            ee_block,
            ee_len,
            (u64::from(hi) << 32) | u64::from(lo),
            unwritten,
        ));
    }
    out
}

fn inode_size_from_overlay(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    inum: u32,
) -> u64 {
    let inode = raw_inode_from_overlay(ext, cursor, overlay, inum);
    let lo = u32::from_le_bytes(inode[0x04..0x08].try_into().unwrap());
    let hi = u32::from_le_bytes(inode[0x6C..0x70].try_into().unwrap());
    u64::from(lo) | (u64::from(hi) << 32)
}

fn overlay_block_bitmap_bit(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    pblk: u64,
) -> bool {
    let group =
        usize::try_from((pblk - u64::from(ext.first_data_block)) / u64::from(ext.blocks_per_group) ).expect("the test fixture value fits in usize");
    let bitmap_block = ext.group_descs[group].block_bitmap;
    let bitmap = if let Some(block) = overlay.blocks.get(&bitmap_block) {
        block.to_vec()
    } else {
        let mut bytes = alloc::vec![0u8; ext.block_size() as usize];
        cursor
            .seek(SeekFrom::Start(bitmap_block * u64::from(ext.block_size())))
            .expect("seek bitmap");
        cursor.read_exact(&mut bytes).expect("read bitmap");
        bytes
    };
    let block_in_group =
        (pblk - u64::from(ext.first_data_block)) % u64::from(ext.blocks_per_group);
    let alloc_unit = block_in_group / u64::from(ext.blocks_per_cluster);
    let byte = (alloc_unit / 8) as usize;
    let bit = (alloc_unit % 8) as u8;
    bitmap[byte] & (1u8 << bit) != 0
}

fn first_root_data_block<T: Read + Seek>(ext: &crate::Ext, cursor: &mut T) -> u64 {
    let inode = ext.inode(cursor, 2).expect("root inode");
    let i_block = inode.i_block();
    crate::extent::resolve_extent(ext, cursor, 2, inode.generation(), &i_block, 0)
        .expect("resolve root extent")
        .expect("root extent")
        .physical_block
}

fn inode_table_block(ext: &crate::Ext, inum: u32) -> u64 {
    let group = (inum - 1) / ext.inodes_per_group;
    let index = (inum - 1) % ext.inodes_per_group;
    let table_block = ext.group_descs[group as usize].inode_table;
    table_block + (u64::from(index) * u64::from(ext.inode_size())) / u64::from(ext.block_size())
}

fn raw_dir_entry_from_overlay(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    overlay: &BlockOverlay,
    parent: u32,
    name: &[u8],
) -> Option<(u32, u8)> {
    let mut reader = compose_reader(cursor, overlay);
    let mut dir = ext.directory_at(parent);
    let mut iter = dir.raw_entries(&mut reader).expect("raw directory entries");
    while let Some(entry) = iter.try_next(&mut reader).expect("read raw dir entry") {
        if entry.name_bytes() == name {
            return Some((entry.inode_number(), entry.file_type()));
        }
    }
    None
}

fn apply_single_tx(
    ext: &crate::Ext,
    cursor: &mut std::io::Cursor<Vec<u8>>,
    tx: Vec<u8>,
) -> ApplyState {
    let composed = classic_overlay_for_fixture(ext, cursor);
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    assert!(scan.stop.is_none());
    apply_pass(ext, cursor, composed, &block_refs, BS, FC_FIRST, &scan).expect("apply")
}

fn split_tx_across_blocks(tx: &[u8], block_size: usize) -> Vec<Vec<u8>> {
    tx.chunks(block_size).map(<[u8]>::to_vec).collect()
}

#[test]
fn apply_head_tail_only_increments_transactions_replayed() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);

    let tx = FcTxBuilder::new(TID).head(0).build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    assert!(scan.stop.is_none());

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
    assert_eq!(state.plan.last_committed_tid, Some(TID));
    assert!(state.plan.stop.is_none());
    assert!(state.modified_inodes.is_empty());
    assert!(state.composed_overlay.blocks.is_empty());
}

#[test]
fn apply_pass_propagates_scan_stop_after_committing_prior_txs() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);

    let tx1 = FcTxBuilder::new(TID).head(0).build();
    let tx2 = FcTxBuilder::new(TID).head(0).build();
    let tx3 = FcTxBuilder::new(TID).head(0).build_with_bad_crc();
    let blocks = fc_region(alloc::vec![tx1, tx2, tx3], 8, BS);
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

    assert_eq!(state.plan.transactions_replayed, 2);
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::TailChecksumInvalid { .. }),
    ));
}

#[test]
fn apply_inode_record_overwrites_inode_bytes() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 2;
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    raw[0] ^= 0xFF;
    raw[1] ^= 0x0F;
    raw[40..48].copy_from_slice(b"fcinode!");

    let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
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
    let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

    assert_eq!(&after[0..2], &raw[0..2]);
    assert_eq!(&after[40..48], b"fcinode!");
    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.inode, 1);
    assert_eq!(state.plan.inodes_modified, 1);
    assert!(state.modified_inodes.contains(&inum));
}

#[test]
fn apply_inode_record_preserves_tail_bytes_when_record_is_128_and_inode_size_is_256() {
    let (ext, mut cursor) = fixture_ext();
    assert_eq!(ext.inode_size(), 256);
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 2;
    let before = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    let mut raw = before[..128].to_vec();
    raw[0] ^= 0xFF;
    raw[40..48].copy_from_slice(b"prefix!!");

    let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
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
    let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

    assert_eq!(&after[0..1], &raw[0..1]);
    assert_eq!(&after[40..48], b"prefix!!");
    assert_eq!(&after[128..130], &before[128..130]);
    assert_eq!(&after[132..], &before[132..]);
}

#[test]
fn apply_inode_record_with_oor_inum_emits_warning_and_continues() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let oor_inum = ext.inodes_count + 1;

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .inode(oor_inum, &[0xA5; 128])
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
    assert_eq!(state.plan.warnings.len(), 1);
    assert_eq!(state.plan.warnings[0].current_tid, Some(TID));
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::InodeOutOfRange { inum: oor_inum }
    );
    assert!(state.modified_inodes.is_empty());
}

#[test]
fn apply_inode_record_with_invalid_length_emits_malformed_record_stop() {
    let (ext, mut cursor) = fixture_ext();
    assert_eq!(ext.inode_size(), 256);
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);

    let tx = FcTxBuilder::new(TID).head(0).inode(2, &[0xCC; 512]).build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    assert!(scan.stop.is_none());

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

    assert_eq!(state.plan.transactions_replayed, 0);
    assert!(state.composed_overlay.blocks.is_empty());
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::MalformedRecord {
            tag: FC_TAG_INODE,
            fc_len: 516,
            reason: "inode raw_inode length out of [128, s_inode_size]",
        })
    ));
}

#[test]
fn apply_inode_record_crossing_block_boundary_commits() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 2;
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    raw[0] ^= 0xFF;
    raw[40..48].copy_from_slice(b"crossing");

    let tx = FcTxBuilder::new(TID).head(0).inode(inum, &raw).build();
    let blocks = split_tx_across_blocks(&tx, 80);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, 80, FC_FIRST, TID);
    assert!(scan.stop.is_none());

    let state = apply_pass(
        &ext,
        &mut cursor,
        composed,
        &block_refs,
        80,
        FC_FIRST,
        &scan,
    )
    .expect("apply");
    let after = raw_inode_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum);

    assert_eq!(state.plan.transactions_replayed, 1);
    assert_eq!(state.plan.tag_counts.inode, 1);
    assert_eq!(&after[0..1], &raw[0..1]);
    assert_eq!(&after[40..48], b"crossing");
}

#[test]
fn apply_inode_record_with_oor_inum_and_invalid_length_stops_malformed() {
    let (ext, mut cursor) = fixture_ext();
    assert_eq!(ext.inode_size(), 256);
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let oor_inum = ext.inodes_count + 1;

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .inode(oor_inum, &[0xDD; 512])
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, BS);
    let block_refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
    let scan = scan_fc_region(&block_refs, BS, FC_FIRST, TID);
    assert!(scan.stop.is_none());

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

    assert_eq!(state.plan.transactions_replayed, 0);
    assert!(state.plan.warnings.is_empty());
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::MalformedRecord {
            tag: FC_TAG_INODE,
            fc_len: 516,
            reason: "inode raw_inode length out of [128, s_inode_size]",
        })
    ));
}

#[test]
fn apply_add_range_inserts_extent_and_records_modified_inode() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 12;
    let old_pblk = first_root_data_block(&ext, &mut cursor);
    let new_pblk = old_pblk + 32;
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
    set_inode_size(&mut raw, u64::from(BS));

    let tx = FcTxBuilder::new(TID)
        .head(0)
        .inode(inum, &raw)
        .add_range(inum, 0, 1, new_pblk, false)
        .build();
    let state = apply_single_tx(&ext, &mut cursor, tx);

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.inode, 1);
    assert_eq!(state.plan.tag_counts.add_range, 1);
    assert_eq!(state.plan.allocation_units_marked_free, 1);
    assert!(state.modified_inodes.contains(&inum));
    assert_eq!(
        inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
        vec![(0, 1, new_pblk, false)]
    );
    assert!(!overlay_block_bitmap_bit(
        &ext,
        &mut cursor,
        &state.composed_overlay,
        old_pblk
    ));
}

#[test]
fn apply_add_range_with_oor_inum_emits_warning() {
    let (ext, mut cursor) = fixture_ext();
    let oor_inum = ext.inodes_count + 1;
    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .add_range(oor_inum, 0, 1, 100, false)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.add_range, 1);
    assert_eq!(state.plan.warnings.len(), 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::InodeOutOfRange { inum: oor_inum }
    );
    assert!(state.modified_inodes.is_empty());
}

#[test]
fn apply_add_range_with_oor_pblk_emits_physical_block_out_of_range_warning() {
    let (ext, mut cursor) = fixture_ext();
    let inum = 12;
    let pblk = ext.blocks_count;
    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .add_range(inum, 0, 1, pblk, false)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.add_range, 1);
    assert_eq!(state.plan.warnings.len(), 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::PhysicalBlockOutOfRange { inum, pblk, len: 1 }
    );
    assert!(state.modified_inodes.is_empty());
}

#[test]
fn apply_add_range_grows_full_inode_root_instead_of_halting() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 12;
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    set_inode_extent_root(
        &mut raw,
        leaf_root(
            &[
                raw_extent(0, 1, 100, false),
                raw_extent(10, 1, 110, false),
                raw_extent(20, 1, 120, false),
                raw_extent(30, 1, 130, false),
            ],
            4,
        ),
    );
    set_inode_size(&mut raw, u64::from(BS));

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .inode(inum, &raw)
            .add_range(inum, 40, 1, 200, false)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.add_range, 1);
    assert!(state.modified_inodes.contains(&inum));
    assert_eq!(state.plan.allocation_units_marked_allocated, 1);
}

#[test]
fn apply_add_range_failed_extent_surgery_rolls_back_and_halts() {
    let (mut ext, mut cursor) = fixture_ext();
    ext.blocks_per_cluster = 4;
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 12;
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    set_inode_extent_root(&mut raw, leaf_root(&[], 4));
    set_inode_size(&mut raw, u64::from(BS));

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .inode(inum, &raw)
            .add_range(inum, 0, 1, 101, false)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 0);
    assert!(state.composed_overlay.blocks.is_empty());
    assert!(state.modified_inodes.is_empty());
    assert_eq!(state.plan.tag_counts.add_range, 0);
    assert!(matches!(
        state.plan.stop.as_ref().map(|s| &s.reason),
        Some(FastCommitStopReason::ExtentReplayFailed {
            inum: stopped,
            reason: ExtentReplayReason::BigallocPblkNotClusterAligned,
        }) if *stopped == inum
    ));
}

#[test]
fn apply_del_range_removes_logical_and_frees_physical() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 12;
    let old_pblk = first_root_data_block(&ext, &mut cursor);
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
    set_inode_size(&mut raw, u64::from(BS));

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .inode(inum, &raw)
            .del_range(inum, 0, 1)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.inode, 1);
    assert_eq!(state.plan.tag_counts.del_range, 1);
    assert_eq!(state.plan.allocation_units_marked_free, 1);
    assert!(state.modified_inodes.contains(&inum));
    assert_eq!(
        inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
        Vec::<(u32, u16, u64, bool)>::new()
    );
    assert_eq!(
        inode_size_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum),
        0
    );
    assert!(!overlay_block_bitmap_bit(
        &ext,
        &mut cursor,
        &state.composed_overlay,
        old_pblk
    ));
}

#[test]
fn apply_del_range_inside_sparse_hole_does_not_shrink_or_mark_modified() {
    let (ext, mut cursor) = fixture_ext();
    let composed = classic_overlay_for_fixture(&ext, &mut cursor);
    let inum = 12;
    let old_pblk = first_root_data_block(&ext, &mut cursor);
    let mut raw = raw_inode_from_overlay(&ext, &mut cursor, &composed, inum);
    set_inode_extent_root(&mut raw, leaf_root(&[raw_extent(0, 1, old_pblk, false)], 4));
    set_inode_size(&mut raw, u64::from(BS) * 10);
    write_raw_inode_to_image(&ext, &mut cursor, inum, &raw);

    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID).head(0).del_range(inum, 5, 2).build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.inode, 0);
    assert_eq!(state.plan.tag_counts.del_range, 1);
    assert_eq!(state.plan.allocation_units_marked_free, 0);
    assert!(
        !state.modified_inodes.contains(&inum),
        "no-op hole delete must not add a modified inode solely for DEL_RANGE"
    );
    assert_eq!(
        inode_extent_records(&ext, &mut cursor, &state.composed_overlay, inum),
        vec![(0, 1, old_pblk, false)]
    );
    assert_eq!(
        inode_size_from_overlay(&ext, &mut cursor, &state.composed_overlay, inum),
        u64::from(BS) * 10
    );
}

#[test]
fn apply_del_range_with_logical_overflow_emits_logical_range_invalid_warning() {
    let (ext, mut cursor) = fixture_ext();
    let inum = 12;
    let state = apply_single_tx(
        &ext,
        &mut cursor,
        FcTxBuilder::new(TID)
            .head(0)
            .del_range(inum, u32::MAX, 2)
            .build(),
    );

    assert_eq!(state.plan.transactions_replayed, 1);
    assert!(state.plan.stop.is_none());
    assert_eq!(state.plan.tag_counts.del_range, 1);
    assert_eq!(state.plan.warnings.len(), 1);
    assert_eq!(
        state.plan.warnings[0].kind,
        FastCommitWarningKind::LogicalRangeInvalid {
            inum,
            lblk: u32::MAX,
            len: 2,
        }
    );
    assert!(state.modified_inodes.is_empty());
}
