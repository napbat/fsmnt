//! Integration tests for ext4 inline files, directories, and symbolic links.

mod support;

use fsmnt_testkit::Cursor;

use fsmnt_parser_core::io::{FsReadSeek, SeekFrom};
use fsmnt_parser_core::iter::FsTryIterator;
use fsmnt_parser_core::traverse::FsDirectory;

type Fs = Cursor<Vec<u8>>;

/// Inode numbers from debugfs (ext4.img).
const INLINE_SHORT_INO: u32 = 528;
const INLINE_OVERFLOW_INO: u32 = 529;
const INLINE_SYMLINK_INO: u32 = 530;

// ---- InlineShort: 40-byte file in i_block ----------------------------

#[test]
fn inline_short_read_full() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    assert!(inode.is_regular_file());
    assert_eq!(inode.size(), 40);

    let mut file = inode.open_file().unwrap();
    assert_eq!(FsReadSeek::<Fs>::len(&file), 40);

    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 40);

    let expected = b"==000000000000000000000000000000000000==";
    assert_eq!(&buf[..n], expected.as_slice());
}

#[test]
fn inline_short_read_partial() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    // Read only 10 bytes from start
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 10);
    assert_eq!(&buf[..n], b"==00000000");
    assert_eq!(FsReadSeek::<Fs>::stream_position(&file), 10);
}

#[test]
fn inline_short_seek_and_read() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    // Seek to offset 38, read last 2 bytes
    file.seek(&mut fs, SeekFrom::Start(38)).unwrap();
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf[..n], b"==");
}

#[test]
fn inline_short_seek_past_eof() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    file.seek(&mut fs, SeekFrom::Start(100)).unwrap();
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn inline_short_seek_end() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let pos = file.seek(&mut fs, SeekFrom::End(-2)).unwrap();
    assert_eq!(pos, 38);
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf[..n], b"==");
}

#[test]
fn inline_short_read_exact() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 40];
    file.read_exact(&mut fs, &mut buf).unwrap();
    let expected = b"==000000000000000000000000000000000000==";
    assert_eq!(&buf, expected.as_slice());
}

#[test]
fn inline_short_empty_buf_returns_zero() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SHORT_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 0];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 0);
}

// ---- InlineOverflow: 100-byte file, 60 in i_block + 40 overflow -----

#[test]
fn inline_overflow_read_full() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    assert!(inode.is_regular_file());
    assert_eq!(inode.size(), 100);

    let mut file = inode.open_file().unwrap();
    assert_eq!(FsReadSeek::<Fs>::len(&file), 100);

    let mut buf = [0u8; 128];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 100);

    let expected: Vec<u8> = b"OVER".repeat(25);
    assert_eq!(&buf[..n], expected.as_slice());
}

#[test]
fn inline_overflow_read_across_boundary() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    // Seek to offset 58 (2 bytes in i_block, then overflow)
    file.seek(&mut fs, SeekFrom::Start(58)).unwrap();
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 10);
    // bytes 58..68 from "OVER" * 25
    let full: Vec<u8> = b"OVER".repeat(25);
    assert_eq!(&buf[..n], &full[58..68]);
}

#[test]
fn inline_overflow_read_only_overflow_region() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    // Seek past i_block into overflow region
    file.seek(&mut fs, SeekFrom::Start(60)).unwrap();
    let mut buf = [0u8; 40];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 40);
    let full: Vec<u8> = b"OVER".repeat(25);
    assert_eq!(&buf[..n], &full[60..100]);
}

#[test]
fn inline_overflow_partial_read() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 8];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 8);
    assert_eq!(&buf, b"OVEROVER");
}

#[test]
fn inline_overflow_seek_end() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let pos = file.seek(&mut fs, SeekFrom::End(-4)).unwrap();
    assert_eq!(pos, 96);
    let mut buf = [0u8; 10];
    let n = file.read(&mut fs, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf[..n], b"OVER");
}

#[test]
fn inline_overflow_sequential_byte_read() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
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
    let expected: Vec<u8> = b"OVER".repeat(25);
    assert_eq!(result, expected);
}

#[test]
fn inline_overflow_read_exact() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    let mut file = inode.open_file().unwrap();

    let mut buf = [0u8; 100];
    file.read_exact(&mut fs, &mut buf).unwrap();
    let expected: Vec<u8> = b"OVER".repeat(25);
    assert_eq!(buf.as_slice(), expected.as_slice());
}

// ---- Malformed inline data ------------------------------------------

#[test]
fn malformed_inline_overflow_returns_error() {
    let mut fs = support::load_image("ext4.img");
    let ext = fs_ext::Ext::new(&mut fs).unwrap();

    // Verify the valid inode works first.
    let inode = ext.inode(&mut fs, INLINE_OVERFLOW_INO).unwrap();
    assert!(inode.open_file().is_ok());

    // Compute the on-disk byte offset for inode 528's xattr region.
    // inode_size=256, i_extra_isize=32 → xattr magic at offset 128+32=160
    // from the start of the inode on disk. The inode table offset
    // is deterministic for the ext4.img fixture.
    let ino = INLINE_OVERFLOW_INO;
    let inodes_per_group = 1024u32; // from ext4.img superblock
    let group = (ino - 1) / inodes_per_group;
    let index = (ino - 1) % inodes_per_group;
    let inode_size = 256u64;
    let block_size = 4096u64;

    // Read inode table block from group descriptor.
    let buf = fs.get_ref();
    let desc_off = usize::try_from(block_size + u64::from(group) * 64)
        .expect("fixture descriptor offset fits usize");
    let inode_table_lo = u32::from_le_bytes(buf[desc_off + 8..desc_off + 12].try_into().unwrap());
    let inode_table_hi = u32::from_le_bytes(buf[desc_off + 40..desc_off + 44].try_into().unwrap());
    let table_block = u64::from(inode_table_lo) | (u64::from(inode_table_hi) << 32);
    let inode_off = usize::try_from(table_block * block_size + u64::from(index) * inode_size)
        .expect("fixture inode offset fits usize");

    // Corrupt the xattr magic (at inode_off + 128 + 32 = inode_off + 160).
    let xattr_magic_off = inode_off + 160;
    let image = fs.get_mut();
    image[xattr_magic_off..xattr_magic_off + 4].copy_from_slice(&[0; 4]);

    // Re-read the inode — it should parse as Invalid inline state.
    let inode = ext.inode(&mut fs, ino).unwrap();
    match inode.open_file() {
        Err(fs_ext::ExtError::InvalidInlineData { inode: n }) => {
            assert_eq!(n, ino);
        }
        Ok(_) => panic!("expected InvalidInlineData, got Ok"),
        Err(other) => panic!("expected InvalidInlineData, got {other:?}"),
    }
}

// ---- Inline symlink tests -------------------------------------------

/// Short symlink (size <= 60) still reads from `i_block` directly.
/// This test uses the existing ext4 short symlink inode to confirm
/// the size <= 60 branch is unaffected by the three-way dispatch.
#[test]
fn inline_symlink_short_still_works() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    // inode 524: short symlink "hello.txt" (9 bytes) — from symlinks.rs
    let inode = ext.inode(&mut fs, 524).unwrap();
    assert!(inode.is_symlink());
    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(&target, b"hello.txt");
}

/// Inline overflow symlink: 69-byte target stored 60 bytes in `i_block`
/// and 9 bytes in the system.data xattr overflow region.
#[test]
fn inline_symlink_overflow_reads_correctly() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let inode = ext.inode(&mut fs, INLINE_SYMLINK_INO).unwrap();
    assert!(inode.is_symlink());
    assert_eq!(inode.size(), 69);

    let target = inode.read_symlink(&mut fs).unwrap();
    assert_eq!(target.len(), 69);
    assert_eq!(
        target,
        b"/some/very/long/path/that/exceeds/sixty/bytes/for-inline-symlink-test".to_vec()
    );
}

// ---- Inline directory tests -------------------------------------------

/// Inode 531: inline directory containing "tiny.txt".
/// Note: inode 531 (not 530) because multiblock.bin was inserted into ext4.img
/// before the inline fixtures, shifting all subsequent inode allocations by one.
const INLINE_DIR_INO: u32 = 531;

/// List entries in an inline directory.
#[test]
fn inline_directory_list_entries() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut dir = ext.directory_at(INLINE_DIR_INO);
    let mut iter = dir.entries(&mut fs).unwrap();
    let mut names = Vec::new();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    }
    assert!(
        names.contains(&"tiny.txt".to_string()),
        "expected tiny.txt in inline dir, got {names:?}"
    );
    // . and .. are skipped by parse_next_entry
    assert!(!names.contains(&".".to_string()));
    assert!(!names.contains(&"..".to_string()));
}

/// Look up an entry by name in an inline directory.
#[test]
fn inline_directory_lookup() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut dir = ext.directory_at(INLINE_DIR_INO);
    let entry = dir.lookup(&mut fs, b"tiny.txt").unwrap();
    assert_eq!(
        entry.kind,
        fsmnt_parser_core::traverse::EntryKind::File,
        "tiny.txt should be a file"
    );
    assert_eq!(&entry.name, b"tiny.txt");
}

/// Lookup of a name not present in the inline directory returns `NotFound`.
#[test]
fn inline_directory_lookup_not_found() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut dir = ext.directory_at(INLINE_DIR_INO);
    let err = dir.lookup(&mut fs, b"nonexistent").unwrap_err();
    assert!(
        matches!(err, fs_ext::ExtError::NotFound),
        "expected NotFound, got {err:?}"
    );
}

/// Corrupting the overflow xattr on an inline directory that needs
/// overflow produces `InvalidInlineData`.
#[test]
fn inline_directory_malformed_overflow_returns_error() {
    let mut fs = support::load_image("ext4.img");
    let ext = fs_ext::Ext::new(&mut fs).unwrap();

    // First verify the directory works uncorrupted.
    let inode = ext.inode(&mut fs, INLINE_DIR_INO).unwrap();
    assert!(inode.is_directory());

    // If the inline directory doesn't need overflow, we can still
    // test that corrupting the xattr magic on an overflow-requiring
    // inline directory produces the error. For this, we artificially
    // inflate i_size past 60 so overflow is required, then corrupt
    // the xattr magic.
    let ino = INLINE_DIR_INO;
    let inodes_per_group = 1024u32;
    let group = (ino - 1) / inodes_per_group;
    let index = (ino - 1) % inodes_per_group;
    let inode_size = 256u64;
    let block_size = 4096u64;

    let buf = fs.get_ref();
    let desc_off = usize::try_from(block_size + u64::from(group) * 64)
        .expect("fixture descriptor offset fits usize");
    let inode_table_lo = u32::from_le_bytes(buf[desc_off + 8..desc_off + 12].try_into().unwrap());
    let inode_table_hi = u32::from_le_bytes(buf[desc_off + 40..desc_off + 44].try_into().unwrap());
    let table_block = u64::from(inode_table_lo) | (u64::from(inode_table_hi) << 32);
    let inode_off = usize::try_from(table_block * block_size + u64::from(index) * inode_size)
        .expect("fixture inode offset fits usize");

    let image = fs.get_mut();
    // Set i_size to 64 (> 60 threshold) to force overflow.
    image[inode_off + 4..inode_off + 8].copy_from_slice(&64u32.to_le_bytes());
    // Corrupt the xattr magic (at inode_off + 160).
    let xattr_magic_off = inode_off + 160;
    image[xattr_magic_off..xattr_magic_off + 4].copy_from_slice(&[0; 4]);

    // Re-open the filesystem and try to list the directory.
    let ext = fs_ext::Ext::new(&mut fs).unwrap();
    let mut dir = ext.directory_at(ino);
    match dir.entries(&mut fs) {
        Err(fs_ext::ExtError::InvalidInlineData { inode: n }) => {
            assert_eq!(n, ino);
        }
        Ok(_) => panic!("expected InvalidInlineData, got Ok"),
        Err(other) => panic!("expected InvalidInlineData, got {other:?}"),
    }
}

/// Malformed inline overflow symlink: corrupt the xattr magic so
/// `find_system_data()` fails, causing `inline_state` to become Invalid,
/// which `read_symlink()` must surface as `InvalidInlineData`.
#[test]
fn inline_symlink_malformed_overflow_returns_invalid_inline_data() {
    let mut fs = support::load_image("ext4.img");
    let ext = fs_ext::Ext::new(&mut fs).unwrap();

    // Verify the valid inode reads correctly first.
    let inode = ext.inode(&mut fs, INLINE_SYMLINK_INO).unwrap();
    assert!(inode.read_symlink(&mut fs).is_ok());

    // Compute the on-disk byte offset for inode 529's xattr region.
    // inode_size=256, i_extra_isize=32 → xattr magic at inode_offset + 160.
    let ino = INLINE_SYMLINK_INO;
    let inodes_per_group = 1024u32;
    let group = (ino - 1) / inodes_per_group;
    let index = (ino - 1) % inodes_per_group;
    let inode_size = 256u64;
    let block_size = 4096u64;

    let buf = fs.get_ref();
    let desc_off = usize::try_from(block_size + u64::from(group) * 64)
        .expect("fixture descriptor offset fits usize");
    let inode_table_lo = u32::from_le_bytes(buf[desc_off + 8..desc_off + 12].try_into().unwrap());
    let inode_table_hi = u32::from_le_bytes(buf[desc_off + 40..desc_off + 44].try_into().unwrap());
    let table_block = u64::from(inode_table_lo) | (u64::from(inode_table_hi) << 32);
    let inode_off = usize::try_from(table_block * block_size + u64::from(index) * inode_size)
        .expect("fixture inode offset fits usize");

    // Corrupt the xattr magic (at inode_off + 128 + 32 = inode_off + 160).
    let xattr_magic_off = inode_off + 160;
    let image = fs.get_mut();
    image[xattr_magic_off..xattr_magic_off + 4].copy_from_slice(&[0; 4]);

    // Re-read the inode — inline_state becomes Invalid, so read_symlink
    // must return InvalidInlineData.
    let inode = ext.inode(&mut fs, ino).unwrap();
    match inode.read_symlink(&mut fs) {
        Err(fs_ext::ExtError::InvalidInlineData { inode: n }) => {
            assert_eq!(n, ino);
        }
        Ok(_) => panic!("expected InvalidInlineData, got Ok"),
        Err(other) => panic!("expected InvalidInlineData, got {other:?}"),
    }
}
