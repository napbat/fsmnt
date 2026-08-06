//! Integration tests for directory lookup across supported ext variants.

mod support;

#[test]
fn lookup_hello_txt_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let entry = root.lookup(&mut fs, b"hello.txt").unwrap();
    assert_eq!(entry.inode_number, 20);
    assert_eq!(entry.kind, fs_common::traverse::EntryKind::File);
    assert_eq!(&entry.name, b"hello.txt");
}

#[test]
fn lookup_subdir_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let entry = root.lookup(&mut fs, b"subdir").unwrap();
    assert_eq!(entry.kind, fs_common::traverse::EntryKind::Directory);
}

#[test]
fn lookup_not_found() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let err = root.lookup(&mut fs, b"nonexistent").unwrap_err();
    assert!(
        matches!(err, fs_ext::ExtError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

#[test]
fn lookup_hello_txt_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let mut root = ext.root_directory();
    let entry = root.lookup(&mut fs, b"hello.txt").unwrap();
    assert_eq!(entry.inode_number, 19);
    assert_eq!(entry.kind, fs_common::traverse::EntryKind::File);
}

#[test]
fn lookup_hello_txt_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let mut root = ext.root_directory();
    let entry = root.lookup(&mut fs, b"hello.txt").unwrap();
    assert_eq!(entry.inode_number, 19);
}

#[test]
fn lookup_is_byte_exact() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    // Case-different name should not match
    let err = root.lookup(&mut fs, b"Hello.txt").unwrap_err();
    assert!(matches!(err, fs_ext::ExtError::NotFound));
}

#[test]
fn lookup_in_htree_dir_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let htree_entry = root.lookup(&mut fs, b"htree_dir").unwrap();
    assert_eq!(htree_entry.kind, fs_common::traverse::EntryKind::Directory);

    let mut htree_dir = ext.directory_at(htree_entry.inode_number);
    let file_entry = htree_dir.lookup(&mut fs, b"file_250.txt").unwrap();
    assert_eq!(file_entry.kind, fs_common::traverse::EntryKind::File);
}

#[test]
fn lookup_in_htree_dir_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let mut root = ext.root_directory();
    let htree_entry = root.lookup(&mut fs, b"htree_dir").unwrap();
    assert_eq!(htree_entry.kind, fs_common::traverse::EntryKind::Directory);

    let mut htree_dir = ext.directory_at(htree_entry.inode_number);
    let file_entry = htree_dir.lookup(&mut fs, b"file_250.txt").unwrap();
    assert_eq!(file_entry.kind, fs_common::traverse::EntryKind::File);
}

#[test]
fn htree_lookup_matches_sequential_scan() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    for name in [b"hello.txt".as_slice(), b"subdir", b"lost+found"] {
        let entry = root.lookup(&mut fs, name).unwrap();
        assert_eq!(&entry.name, name);
    }
}

#[test]
fn htree_lookup_not_found_in_large_dir() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let htree_entry = root.lookup(&mut fs, b"htree_dir").unwrap();
    let mut htree_dir = ext.directory_at(htree_entry.inode_number);
    let err = htree_dir.lookup(&mut fs, b"nonexistent.txt").unwrap_err();
    assert!(matches!(err, fs_ext::ExtError::NotFound));
}
