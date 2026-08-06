//! Integration tests for reading and seeking through ext file data.

mod support;

use fsmnt_testkit::Cursor;

use fs_common::io::{FsReadSeek, SeekFrom};
use fs_ext::ExtFile;

type Fs = Cursor<Vec<u8>>;

/// Helper: get the stream position without ambiguity.
fn pos(file: &ExtFile<'_>) -> u64 {
    FsReadSeek::<Fs>::stream_position(file)
}

// Inode numbers determined via debugfs.
// ext4 has htree_dir inserted before hello.txt in inode allocation order,
// so hello.txt lands at a higher inode number than ext2/ext3.
const HELLO_TXT_INO_EXT4: u32 = 20;
const HELLO_TXT_INO_EXT23: u32 = 19;
const SPARSE_FILE_INO: u32 = 525; // ext4 only

// ---- ext4 (extent-based) ------------------------------------------------

#[test]
fn read_file_from_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    assert!(inode.is_regular_file());
    assert_eq!(inode.size(), 17);

    let mut file = inode.open_file().unwrap();
    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"Hello from ext4!\n");
}

// ---- ext2 (block map) ---------------------------------------------------

#[test]
fn read_file_from_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT23).unwrap();
    assert!(inode.is_regular_file());
    assert_eq!(inode.size(), 17);

    let mut file = inode.open_file().unwrap();
    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"Hello from ext2!\n");
}

// ---- ext3 (block map, journaled) ----------------------------------------

#[test]
fn read_file_from_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT23).unwrap();
    assert!(inode.is_regular_file());

    let mut file = inode.open_file().unwrap();
    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"Hello from ext3!\n");
}

// ---- seek tests ---------------------------------------------------------

#[test]
fn seek_start_and_read() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let p = file.seek(&mut fs, SeekFrom::Start(6)).unwrap();
    assert_eq!(p, 6);
    assert_eq!(pos(&file), 6);

    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"from ext4!\n");
}

#[test]
fn seek_current_forward_and_back() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 5];
    file.read_exact(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf, b"Hello");
    assert_eq!(pos(&file), 5);

    let p = file.seek(&mut fs, SeekFrom::Current(-5)).unwrap();
    assert_eq!(p, 0);

    let mut buf2 = [0u8; 5];
    file.read_exact(&mut fs, &mut buf2).unwrap();
    assert_eq!(&buf2, b"Hello");
}

#[test]
fn seek_end() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    // Seek to 4 bytes before end: 17 - 4 = 13 -> "t4!\n"
    let p = file.seek(&mut fs, SeekFrom::End(-4)).unwrap();
    assert_eq!(p, 13);

    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"t4!\n");
}

#[test]
fn seek_past_eof_returns_zero_bytes() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let p = file.seek(&mut fs, SeekFrom::Start(1000)).unwrap();
    assert_eq!(p, 1000);

    let mut buf = [0u8; 16];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn seek_to_negative_position_fails() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let result = file.seek(&mut fs, SeekFrom::Current(-1));
    assert!(result.is_err());
}

// ---- empty / zero-length reads ------------------------------------------

#[test]
fn read_into_empty_buffer_returns_zero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 0];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 0);
    assert_eq!(pos(&file), 0);
}

// ---- sparse file holes are zero -----------------------------------------

#[test]
fn sparse_file_holes_are_zero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, SPARSE_FILE_INO).unwrap();
    assert!(inode.is_regular_file());
    assert_eq!(inode.size(), 8292);

    let mut file = inode.open_file().unwrap();

    // The sparse_file has blockcount=0, all blocks are holes.
    let mut buf = [0xFFu8; 100];
    let mut total = 0;
    while total < 100 {
        let n = file.read(&mut fs, &mut buf[total..]).unwrap();
        assert!(n > 0, "unexpected EOF at offset {total}");
        total += n;
    }
    assert!(buf.iter().all(|&b| b == 0), "hole bytes should be zero");

    // Seek into middle of file (within a hole) and verify zeros.
    file.seek(&mut fs, SeekFrom::Start(4096)).unwrap();
    let mut mid_buf = [0xFFu8; 64];
    total = 0;
    while total < 64 {
        let n = file.read(&mut fs, &mut mid_buf[total..]).unwrap();
        assert!(n > 0, "unexpected EOF at offset {}", 4096 + total);
        total += n;
    }
    assert!(
        mid_buf.iter().all(|&b| b == 0),
        "mid-file hole bytes should be zero"
    );
}

// ---- FsReadSeek trait: len / is_empty -----------------------------------

#[test]
fn file_len_and_is_empty() {
    let (ext, mut fs) = support::open_ext("ext4.img");

    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let file = inode.open_file().unwrap();
    assert_eq!(FsReadSeek::<Fs>::len(&file), 17);
    assert!(!FsReadSeek::<Fs>::is_empty(&file));
}

// ---- multi-block sequential read ----------------------------------------

#[test]
fn sequential_read_accumulates_full_file() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, HELLO_TXT_INO_EXT4).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut result = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = file.read(&mut fs, &mut byte).unwrap();
        if n == 0 {
            break;
        }
        result.push(byte[0]);
    }
    assert_eq!(result, b"Hello from ext4!\n");
}
