//! Integration tests for the vfsv1 quota-tree reader.
//!
//! Uses `ext4-quota.img`, a fixture built by `gen-fixtures.sh` with
//! `mkfs.ext4 -O quota` plus a Python patcher that injects extra dqblk
//! records into the user and group leaf blocks.

mod support;

use fs_ext::{Ext, ExtError, QuotaKind, QuotaRecord};

const FIXTURE: &str = "ext4-quota.img";

fn fixture_available(name: &str) -> bool {
    fsmnt_testkit::fixture_path(env!("CARGO_MANIFEST_DIR"), format!("testdata/{name}")).exists()
}

fn collect_quota(name: &str, kind: QuotaKind) -> Vec<QuotaRecord> {
    let (ext, mut fs) = support::open_ext(name);
    ext.quota(&mut fs, kind)
        .expect("open quota tree")
        .map(|r| r.expect("decode record"))
        .collect()
}

#[test]
fn fixture_exposes_all_three_quota_inums() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let (ext, _fs) = support::open_ext(FIXTURE);
    assert_ne!(ext.usr_quota_inum(), 0);
    assert_ne!(ext.grp_quota_inum(), 0);
    assert_ne!(ext.prj_quota_inum(), 0);
}

#[test]
fn user_quota_iterator_yields_root_and_patched_records() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let mut records = collect_quota(FIXTURE, QuotaKind::User);
    records.sort_by_key(|r| r.id);

    assert_eq!(records.len(), 3, "expected root + UID 1000 + UID 1001");

    let root = &records[0];
    assert_eq!(root.id, 0);
    // mkfs always charges the root user with the lost+found dir + the
    // quota inodes themselves at fs creation.
    assert!(
        root.inodes_used > 0,
        "root must have non-zero inode usage, got {}",
        root.inodes_used
    );
    assert!(
        root.bytes_used > 0,
        "root must have non-zero space usage, got {}",
        root.bytes_used
    );

    let uid1000 = &records[1];
    assert_eq!(uid1000.id, 1000);
    assert_eq!(uid1000.inodes_used, 5);
    assert_eq!(uid1000.bytes_used, 12_345_678);
    // Patcher writes 1024 / 2048 in 1024-byte quota blocks; reader
    // converts to bytes (1 MiB / 2 MiB).
    assert_eq!(uid1000.bytes_soft_limit, 1_048_576);
    assert_eq!(uid1000.bytes_hard_limit, 2_097_152);
    assert_eq!(uid1000.inodes_soft_limit, 0);
    assert_eq!(uid1000.inodes_hard_limit, 0);

    let uid1001 = &records[2];
    assert_eq!(uid1001.id, 1001);
    assert_eq!(uid1001.inodes_used, 1);
    assert_eq!(uid1001.bytes_used, 4096);
}

#[test]
fn group_quota_iterator_yields_root_and_patched_records() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let mut records = collect_quota(FIXTURE, QuotaKind::Group);
    records.sort_by_key(|r| r.id);

    assert_eq!(records.len(), 3, "expected root + GID 2000 + GID 2001");

    let gid2000 = records.iter().find(|r| r.id == 2000).expect("GID 2000");
    assert_eq!(gid2000.inodes_used, 2);
    assert_eq!(gid2000.bytes_used, 8192);
    assert_eq!(gid2000.inodes_soft_limit, 10);
    assert_eq!(gid2000.inodes_hard_limit, 20);

    let gid2001 = records.iter().find(|r| r.id == 2001).expect("GID 2001");
    assert_eq!(gid2001.inodes_used, 3);
    assert_eq!(gid2001.bytes_used, 12288);
}

#[test]
fn project_quota_iterator_yields_root_record_only() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let records = collect_quota(FIXTURE, QuotaKind::Project);
    assert_eq!(records.len(), 1);
    let root = &records[0];
    assert_eq!(root.id, 0);
    assert!(root.inodes_used > 0);
}

#[test]
fn quota_inum_zero_returns_empty_iterator_without_error() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    // Patch a copy of the fixture so s_usr_quota_inum is zeroed.
    let mut fs = support::load_image(FIXTURE);
    support::patch_superblock_u32(&mut fs, 0x240, 0);
    let ext = Ext::open_lenient(&mut fs).expect("open lenient after sb patch");
    let records: Vec<_> = ext
        .quota(&mut fs, QuotaKind::User)
        .expect("inum=0 must not error")
        .collect();
    assert!(records.is_empty(), "inum=0 must yield zero records");
}

#[test]
fn corrupt_magic_yields_structured_error() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let mut fs = support::load_image(FIXTURE);
    let usr_inum = {
        let buf = fs.get_ref();
        u32::from_le_bytes(buf[1024 + 0x240..1024 + 0x244].try_into().unwrap())
    };
    let inode_offset = locate_inode_offset(fs.get_ref(), usr_inum);
    let magic_offset = quota_file_byte_image_offset(fs.get_ref(), inode_offset, 0);
    {
        let buf = fs.get_mut();
        buf[magic_offset..magic_offset + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    }

    let ext = Ext::open_lenient(&mut fs).expect("open lenient after magic patch");
    let mut iter = ext.quota(&mut fs, QuotaKind::User).map(|_| ());
    match iter {
        Err(ExtError::InvalidQuotaFile {
            reason: "magic mismatch",
            ..
        }) => {}
        other => panic!("expected InvalidQuotaFile/magic mismatch, got {other:?}"),
    }
    // Avoid unused mut warning when above arm matches without mutation.
    let _ = &mut iter;
}

#[test]
fn corrupt_tree_pointer_yields_structured_error() {
    if !fixture_available(FIXTURE) {
        eprintln!("skipping: {FIXTURE} not generated");
        return;
    }
    let mut fs = support::load_image(FIXTURE);
    let usr_inum = {
        let buf = fs.get_ref();
        u32::from_le_bytes(buf[1024 + 0x240..1024 + 0x244].try_into().unwrap())
    };
    let inode_offset = locate_inode_offset(fs.get_ref(), usr_inum);
    // Quota block 1 lives in the first fs block of the data extent at
    // file offset 1024. Its physical block need not be contiguous with
    // quota block 0.
    // Patch the first u32 of quota block 1 to point to an out-of-range
    // tree-block number.
    let qblock1_off = quota_file_byte_image_offset(fs.get_ref(), inode_offset, 1024);
    {
        let buf = fs.get_mut();
        buf[qblock1_off..qblock1_off + 4].copy_from_slice(&999u32.to_le_bytes());
    }

    let ext = Ext::open_lenient(&mut fs).expect("open lenient after tree patch");
    let err = ext.quota(&mut fs, QuotaKind::User).err();
    match err {
        Some(ExtError::InvalidQuotaFile {
            reason: "tree pointer exceeds dqi_blocks",
            ..
        }) => {}
        other => panic!("expected tree-pointer error, got {other:?}"),
    }
}

// --- helpers --------------------------------------------------------

fn block_size(buf: &[u8]) -> u32 {
    let log = u32::from_le_bytes(buf[1024 + 0x18..1024 + 0x1C].try_into().unwrap());
    1024u32 << log
}

fn locate_inode_offset(buf: &[u8], inum: u32) -> usize {
    let inodes_per_group = u32::from_le_bytes(buf[1024 + 0x28..1024 + 0x2C].try_into().unwrap());
    let inode_size = u16::from_le_bytes(buf[1024 + 0x58..1024 + 0x5A].try_into().unwrap());
    let bs = usize::try_from(block_size(buf)).expect("fixture block size fits usize");
    let group = (inum - 1) / inodes_per_group;
    let index_in_group = (inum - 1) % inodes_per_group;
    let incompat = u32::from_le_bytes(buf[1024 + 0x60..1024 + 0x64].try_into().unwrap());
    let desc_size = if (incompat & 0x80) != 0 { 64 } else { 32 };
    let first_data_block = u32::from_le_bytes(buf[1024 + 0x14..1024 + 0x18].try_into().unwrap());
    let gdt_block_base =
        usize::try_from(first_data_block + 1).expect("fixture GDT block fits usize") * bs;
    let gdt_offset = usize::try_from(group).expect("fixture group fits usize") * desc_size;
    let inode_table_lo = u32::from_le_bytes(
        buf[gdt_block_base + gdt_offset + 8..gdt_block_base + gdt_offset + 12]
            .try_into()
            .unwrap(),
    );
    usize::try_from(inode_table_lo).expect("fixture inode-table block fits usize") * bs
        + usize::try_from(index_in_group).expect("fixture inode index fits usize")
            * usize::from(inode_size)
}

fn quota_file_byte_image_offset(buf: &[u8], inode_off: usize, file_offset: usize) -> usize {
    // i_block at inode-relative offset 0x28; extent header + extent records.
    let i_block = &buf[inode_off + 0x28..inode_off + 0x28 + 60];
    let magic = u16::from_le_bytes(i_block[0..2].try_into().unwrap());
    assert_eq!(magic, 0xF30A, "expected ext4 extent magic");
    let entries = u16::from_le_bytes(i_block[2..4].try_into().unwrap());
    let depth = u16::from_le_bytes(i_block[6..8].try_into().unwrap());
    assert_eq!(depth, 0, "expected depth-zero quota inode");

    let fs_block_size = usize::try_from(block_size(buf)).expect("fixture block size fits usize");
    let logical_block =
        u32::try_from(file_offset / fs_block_size).expect("fixture logical block fits u32");
    let block_offset = file_offset % fs_block_size;

    for index in 0..usize::from(entries) {
        let extent_offset = 12 + index * 12;
        let ee_block = u32::from_le_bytes(
            i_block[extent_offset..extent_offset + 4]
                .try_into()
                .unwrap(),
        );
        let raw_len = u16::from_le_bytes(
            i_block[extent_offset + 4..extent_offset + 6]
                .try_into()
                .unwrap(),
        );
        let extent_len = if raw_len > 0x8000 {
            u32::from(raw_len - 0x8000)
        } else {
            u32::from(raw_len)
        };
        let Some(logical_end) = ee_block.checked_add(extent_len) else {
            continue;
        };
        if !(ee_block..logical_end).contains(&logical_block) {
            continue;
        }

        let ee_start_hi = u16::from_le_bytes(
            i_block[extent_offset + 6..extent_offset + 8]
                .try_into()
                .unwrap(),
        );
        let ee_start_lo = u32::from_le_bytes(
            i_block[extent_offset + 8..extent_offset + 12]
                .try_into()
                .unwrap(),
        );
        let physical_start = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);
        let physical_block = physical_start + u64::from(logical_block - ee_block);
        return usize::try_from(physical_block)
            .expect("fixture physical block fits usize")
            .checked_mul(fs_block_size)
            .and_then(|offset| offset.checked_add(block_offset))
            .expect("fixture image offset fits usize");
    }

    panic!("quota fixture byte offset {file_offset} is not extent-mapped");
}
