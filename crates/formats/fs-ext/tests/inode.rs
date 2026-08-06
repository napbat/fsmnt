//! Integration tests for inode decoding across ext2, ext3, and ext4.

mod support;

use fs_ext::ExtError;

#[test]
fn read_root_inode_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.is_directory());
    assert_eq!(root.mode() & 0xF000, 0x4000);
    assert!(root.links_count() >= 2);
    assert_eq!(root.inode_number(), 2);
}

#[test]
fn read_root_inode_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.is_directory());
    assert!(root.links_count() >= 2);
}

#[test]
fn read_root_inode_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.is_directory());
}

#[test]
fn inode_zero_is_out_of_range() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    match ext.inode(&mut fs, 0) {
        Err(ExtError::InodeOutOfRange { inode: 0 }) => {}
        other => panic!("expected InodeOutOfRange(0), got {other:?}"),
    }
}

#[test]
fn inode_past_count_is_out_of_range() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    match ext.inode(&mut fs, u32::MAX) {
        Err(ExtError::InodeOutOfRange { .. }) => {}
        other => panic!("expected InodeOutOfRange, got {other:?}"),
    }
}

#[test]
fn root_inode_timestamp_is_nonzero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.ctime().seconds > 0, "ctime should be > 0");
    assert!(root.mtime().seconds > 0, "mtime should be > 0");
}

#[test]
fn root_inode_dtime_is_zero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert_eq!(root.dtime().seconds, 0, "root dir should not be deleted");
}

#[test]
fn root_inode_is_not_regular_file_or_symlink() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(!root.is_regular_file());
    assert!(!root.is_symlink());
}

#[test]
fn root_inode_size_is_nonzero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.size() > 0, "root directory should have nonzero size");
}

#[test]
fn ext2_root_timestamp_nonzero() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.ctime().seconds > 0, "ext2 root ctime should be > 0");
    assert_eq!(
        root.ctime().nanoseconds,
        0,
        "base timestamps have no nanoseconds"
    );
}
