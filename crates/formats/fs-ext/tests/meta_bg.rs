//! Integration tests for ext4 `META_BG` descriptor layouts.

use fs_common::io::FsReadSeek;
use fs_ext::ChecksumState;

#[test]
fn opens_meta_bg_image_and_reads_files() {
    let Some(bytes) = fsmnt_testkit::read_optional_fixture(
        env!("CARGO_MANIFEST_DIR"),
        "testdata/ext4-meta-bg.img",
    ) else {
        eprintln!("skipping: ext4-meta-bg.img fixture not generated");
        return;
    };
    let mut cursor = fsmnt_testkit::Cursor::new(bytes);
    let ext = fs_ext::Ext::new(&mut cursor).expect("open ext4-meta-bg.img");

    assert!(ext.is_meta_bg(), "fixture must have META_BG enabled");
    assert!(
        ext.total_desc_blocks() >= 2,
        "fixture must span >= 2 metagroups to exercise META_BG GDT load"
    );

    for csum in ext.group_checksums() {
        assert!(
            matches!(csum, ChecksumState::Valid),
            "descriptor checksum: {csum:?}"
        );
    }

    let mut root = ext.root_directory();
    let hello = root
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup hello");
    let hello_inode = ext
        .inode(&mut cursor, hello.inode_number)
        .expect("hello inode");
    let mut hello_file = hello_inode.open_file().expect("hello file");
    let mut hello_buf = [0u8; 64];
    let n = hello_file
        .read(&mut cursor, &mut hello_buf)
        .expect("read hello");
    assert_eq!(&hello_buf[..n], b"Hello from ext4-meta-bg!\n");

    let subdir_entry = root.lookup(&mut cursor, b"subdir").expect("lookup subdir");
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup nested");
    let nested_inode = ext
        .inode(&mut cursor, nested.inode_number)
        .expect("nested inode");
    let mut nested_file = nested_inode.open_file().expect("nested file");
    let mut nested_buf = [0u8; 32];
    let n = nested_file
        .read(&mut cursor, &mut nested_buf)
        .expect("read nested");
    assert_eq!(&nested_buf[..n], b"Nested file\n");
}
