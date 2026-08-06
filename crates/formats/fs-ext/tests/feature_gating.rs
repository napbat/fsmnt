//! Integration tests for rejecting unsupported ext filesystem feature combinations.

mod support;

#[test]
fn rejects_journal_device() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_incompat(&mut fs, 0x0008);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::UnsupportedJournalDevice) => {}
        other => panic!("expected UnsupportedJournalDevice, got {other:?}"),
    }
}

#[test]
fn rejects_unknown_incompat_on_real_image() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_incompat(&mut fs, 0x8000_0000);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::UnsupportedIncompatFeature { .. }) => {}
        other => panic!("expected UnsupportedIncompatFeature, got {other:?}"),
    }
}

#[test]
fn rejects_64bit_with_small_desc_size() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u16(&mut fs, 0xFE, 32);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidDescriptorSize { size: 32 }) => {}
        other => panic!("expected InvalidDescriptorSize, got {other:?}"),
    }
}

#[test]
fn rejects_zero_blocks_per_group() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u32(&mut fs, 0x20, 0);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidSuperblock { .. }) => {}
        other => panic!("expected InvalidSuperblock, got {other:?}"),
    }
}

#[test]
fn rejects_zero_inodes_per_group() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u32(&mut fs, 0x28, 0);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidSuperblock { .. }) => {}
        other => panic!("expected InvalidSuperblock, got {other:?}"),
    }
}

#[test]
fn rejects_invalid_inode_size() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u16(&mut fs, 0x58, 100);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidInodeSize { raw: 100 }) => {}
        other => panic!("expected InvalidInodeSize, got {other:?}"),
    }
}

#[test]
fn rejects_short_image() {
    let data = vec![0u8; 1024];
    let mut fs = fsmnt_testkit::Cursor::new(data);
    assert!(fs_ext::Ext::new(&mut fs).is_err());
}
