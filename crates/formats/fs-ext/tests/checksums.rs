//! Integration tests for ext filesystem metadata checksum validation.

mod support;

use fs_common::io::FsReadSeek;
use fs_common::iter::FsTryIterator;
use fs_common::traverse::FsDirectory;

/// Look up a root-level entry and return its inode number.
fn lookup_inode(ext: &fs_ext::Ext, fs: &mut fsmnt_testkit::Cursor<Vec<u8>>, name: &[u8]) -> u32 {
    let mut dir = ext.root_directory();
    let entry = dir.lookup(fs, name).unwrap();
    entry.inode_number
}

#[test]
fn read_file_validates_extent_checksums() {
    // Reading a block-backed file exercises extent resolution.
    // If checksums were wrong, the read would fail.
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"hello.txt");
    let inode = ext.inode(&mut fs, ino).unwrap();
    let mut file = inode.open_file().unwrap();
    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert!(n > 0, "should read some bytes from hello.txt");
}

#[test]
fn directory_traversal_validates_dir_checksums() {
    // Listing root directory exercises directory block reading.
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut entries = root.entries(&mut fs).unwrap();
    let mut count = 0;
    while let Some(_entry) = entries.try_next(&mut fs).unwrap() {
        count += 1;
    }
    assert!(count > 0, "root directory should have entries");
}

#[test]
fn htree_lookup_validates_dx_checksums() {
    // The htree_dir directory has 500 files, triggering htree
    // lookup. A successful lookup means dx node checksums passed.
    let (ext, mut fs) = support::open_ext("ext4.img");
    let ino = lookup_inode(&ext, &mut fs, b"htree_dir");
    let mut dir = ext.directory_at(ino);
    let entry = dir.lookup(&mut fs, b"file_250.txt").unwrap();
    assert!(entry.inode_number > 0);
}

#[test]
fn ext3_no_checksums_still_works() {
    // ext3.img has no METADATA_CSUM -- all checksums should be
    // Unknown (skipped). Operations should succeed.
    let (ext, mut fs) = support::open_ext("ext3.img");
    let mut root = ext.root_directory();
    let entry = root.lookup(&mut fs, b"hello.txt").unwrap();
    let inode = ext.inode(&mut fs, entry.inode_number).unwrap();
    assert!(inode.size() > 0);
}

#[test]
fn htree_leaf_missing_tail_is_rejected() {
    const BLOCK_SIZE: usize = 4096;
    const DIR_ENTRY_TAIL_FILE_TYPE_OFF: usize = BLOCK_SIZE - 5;
    // Physical blocks backing /htree_dir's four htree leaves in the pinned
    // ext4.img fixture (logical 1..=4; logical 0 is the dx_root at 1331):
    //   (1) 1535, (2) 1740, (3..=4) 1839..=1840.
    // Confirm with `debugfs -R "dump_extents /htree_dir" ext4.img`. Corrupting
    // every leaf's tail file_type byte ensures the lookup routes into a leaf
    // whose tail signature fails validation regardless of which leaf the
    // target filename's hash happens to land in on the current fixture.
    const HTREE_LEAF_PHYS_BLOCKS: [usize; 4] = [1535, 1740, 1839, 1840];

    let mut fs = support::load_image("ext4.img");
    for pb in HTREE_LEAF_PHYS_BLOCKS {
        fs.get_mut()[pb * BLOCK_SIZE + DIR_ENTRY_TAIL_FILE_TYPE_OFF] = 0;
    }

    let ext = fs_ext::Ext::new(&mut fs).unwrap();
    let mut root = ext.root_directory();
    let htree_entry = root.lookup(&mut fs, b"htree_dir").unwrap();

    let mut htree_dir = ext.directory_at(htree_entry.inode_number);
    let err = htree_dir.lookup(&mut fs, b"file_250.txt").unwrap_err();
    assert!(
        matches!(err, fs_ext::ExtError::InvalidDirectoryEntry { .. }),
        "expected InvalidDirectoryEntry, got {err:?}"
    );
}
