mod common;

#[test]
fn read_short_symlink_ext4() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 524).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn read_short_symlink_ext3() {
    let (ext, mut fs) = common::open_ext("ext3.img");
    let inode = ext.inode(&mut fs, 522).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn read_short_symlink_ext2() {
    let (ext, mut fs) = common::open_ext("ext2.img");
    let inode = ext.inode(&mut fs, 20).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn read_long_symlink_ext4() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 522).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(target.len(), 75);
    assert_eq!(
        &target,
        b"/subdir/nested.txt/padding-to-exceed-sixty-bytes-threshold-for-slow-symlink"
    );
}

#[test]
fn read_long_symlink_ext3() {
    let (ext, mut fs) = common::open_ext("ext3.img");
    let inode = ext.inode(&mut fs, 521).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(target.len(), 75);
    assert_eq!(
        &target,
        b"/subdir/nested.txt/padding-to-exceed-sixty-bytes-threshold-for-slow-symlink"
    );
}

#[test]
fn symlink_is_not_file_or_directory() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 524).unwrap();
    assert!(inode.is_symlink());
    assert!(!inode.is_directory());
    assert!(!inode.is_regular_file());
}
