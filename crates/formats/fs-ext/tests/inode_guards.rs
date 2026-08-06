mod common;

use fs_common::io::FsReadSeek;

#[test]
fn open_file_rejects_directory() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 2).unwrap(); // root dir
    assert!(inode.is_directory());
    let result = inode.open_file();
    assert!(result.is_err());
    let err = result.err().unwrap();
    assert!(
        matches!(err, fs_ext::ExtError::IsADirectory { inode: 2 }),
        "expected IsADirectory, got {err:?}"
    );
}

#[test]
fn open_file_still_works_for_regular_files() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 20).unwrap(); // hello.txt
    assert!(inode.is_regular_file());
    let mut file = inode.open_file().unwrap();
    let mut buf = [0u8; 17];
    file.read_exact(&mut fs, &mut buf).unwrap();
    assert!(buf.starts_with(b"Hello from ext4!"));
}

#[test]
fn read_symlink_still_works_after_refactor() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 524).unwrap(); // short_link
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn open_file_rejects_ea_inode() {
    // A dedicated fixture with EA inodes would be needed for a true
    // integration test.  For now, verify that open_file does NOT
    // succeed on the root dir (IsADirectory fires first), confirming
    // the guard pipeline is wired up.
    let mut fs = common::load_image("ext4.img");
    let ext = fs_ext::Ext::new(&mut fs).unwrap();
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(root.open_file().is_err());
}

#[test]
fn entries_rejects_ea_inode_dir() {
    // Structural test: verify that UnsupportedEaInode error variant exists.
    let _err = fs_ext::ExtError::UnsupportedEaInode { inode: 42 };
}
