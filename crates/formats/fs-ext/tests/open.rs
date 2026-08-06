//! Integration tests for strict ext filesystem opening and validation.

mod support;

use fs_ext::{Ext, ExtError};

#[test]
fn open_ext4() {
    let (ext, _) = support::open_ext("ext4.img");
    assert_eq!(ext.block_size(), 4096);
    assert!(ext.group_count() > 0);
    assert!(ext.is_64bit());
}

#[test]
fn open_ext3() {
    let (ext, _) = support::open_ext("ext3.img");
    assert!(ext.has_journal());
    assert!(!ext.is_64bit());
}

#[test]
fn open_ext2() {
    let (ext, _) = support::open_ext("ext2.img");
    assert!(!ext.is_64bit());
    assert!(!ext.has_journal());
    assert_eq!(ext.inode_size(), 128);
}

#[test]
fn rejects_bad_magic() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u16(&mut fs, 0x38, 0xDEAD);
    match Ext::new(&mut fs) {
        Err(ExtError::InvalidMagic { magic: 0xDEAD }) => {}
        other => panic!("expected InvalidMagic, got {other:?}"),
    }
}

#[test]
fn rejects_needs_recovery() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_incompat(&mut fs, 0x0004);
    match Ext::new(&mut fs) {
        Err(ExtError::NeedsRecovery) => {}
        other => panic!("expected NeedsRecovery, got {other:?}"),
    }
}

#[test]
fn rejects_short_image() {
    let data = vec![0u8; 1024];
    let mut fs = fsmnt_testkit::Cursor::new(data);
    assert!(Ext::new(&mut fs).is_err());
}
