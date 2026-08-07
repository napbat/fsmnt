//! Integration tests for malformed and boundary-condition ext images.

mod support;

use fsmnt_parser_core::io::FsReadSeek;

#[test]
fn corrupted_superblock_rejects_cleanly() {
    let data = vec![0u8; 4096];
    let mut fs = fsmnt_testkit::Cursor::new(data);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidMagic { .. } | fs_ext::ExtError::UnexpectedEof { .. }) => {}
        other => panic!("expected clean rejection, got {other:?}"),
    }
}

#[test]
fn reading_at_eof_returns_zero_bytes() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, 20).unwrap(); // hello.txt, 17 bytes
    let mut file = inode.open_file().unwrap();
    file.seek(&mut fs, fs_ext::io::SeekFrom::End(0)).unwrap();
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 0, "reading at EOF should return 0 bytes");
}

#[test]
fn rejects_block_size_too_large() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u32(&mut fs, 0x18, 7);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidBlockSize { raw: 7 }) => {}
        other => panic!("expected InvalidBlockSize, got {other:?}"),
    }
}

#[test]
fn rejects_blocks_count_le_first_data_block() {
    let mut fs = support::load_image("ext4.img");
    support::patch_superblock_u32(&mut fs, 0x04, 0);
    match fs_ext::Ext::new(&mut fs) {
        Err(fs_ext::ExtError::InvalidSuperblock { .. }) => {}
        other => panic!("expected InvalidSuperblock, got {other:?}"),
    }
}
