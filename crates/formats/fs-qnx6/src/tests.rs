//! End-to-end parser coverage over the shared synthetic QNX6 image.

use fsmnt_testkit::qnx6::{
    self, BLOCK_SIZE, FixtureByteOrder, HELLO_DATA, INDIRECT_FILE_SIZE, INNER_DATA, LONG_DATA,
    LONG_NAME, PRIMARY_SUPERBLOCK_OFFSET, SECONDARY_SUPERBLOCK_OFFSET, SPARSE_FILE_SIZE, VOLUME_ID,
};
use fsmnt_testkit::{CountingReader, Cursor};

use crate::{ByteOrder, Qnx6, Qnx6Error, SuperblockCopy};

fn open(order: FixtureByteOrder) -> Qnx6<Cursor<Vec<u8>>> {
    Qnx6::new(Cursor::new(qnx6::image(order, 1, 2))).expect("open synthetic QNX6")
}

#[test]
fn newest_snapshot_opens_and_exposes_geometry() {
    let volume = open(FixtureByteOrder::Little);
    assert_eq!(volume.active_copy(), SuperblockCopy::Secondary);
    assert!(volume.primary_copy_valid());
    assert!(volume.secondary_copy_valid());
    assert_eq!(volume.superblock().serial(), 2);
    assert_eq!(volume.superblock().byte_order(), ByteOrder::Little);
    assert_eq!(
        volume.superblock().block_size(),
        u32::try_from(BLOCK_SIZE).expect("fixture block size fits u32")
    );
    assert_eq!(volume.superblock().volume_id(), &VOLUME_ID);
    assert_eq!(
        volume.secondary_superblock_offset(),
        SECONDARY_SUPERBLOCK_OFFSET as u64
    );
    assert_eq!(
        volume.superblock().volume_size().expect("volume size"),
        qnx6::VOLUME_SIZE as u64
    );
}

#[test]
fn lists_short_and_long_names_and_nested_directories() {
    let mut volume = open(FixtureByteOrder::Little);
    let root = volume.root_inode().expect("root inode");
    let entries = volume.read_directory(&root).expect("root directory");
    let names = entries
        .iter()
        .map(|entry| String::from_utf8_lossy(entry.name()).into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            ".",
            "..",
            "hello.txt",
            "subdir",
            LONG_NAME,
            "indirect.bin",
            "sparse.bin"
        ]
    );
    let long = entries
        .iter()
        .find(|entry| entry.name() == LONG_NAME.as_bytes())
        .expect("long entry");
    assert_eq!(long.long_name_index(), Some(0));
    assert_eq!(long.long_name_checksum_valid(), Some(true));

    let inner = volume
        .resolve_path(b"/subdir/inner.txt")
        .expect("nested path");
    assert_eq!(volume.read_file(&inner).expect("inner data"), INNER_DATA);
}

#[test]
fn reads_direct_and_long_named_files() {
    let mut volume = open(FixtureByteOrder::Little);
    let hello = volume.resolve_path(b"hello.txt").expect("hello inode");
    assert_eq!(volume.read_file(&hello).expect("hello data"), HELLO_DATA);
    let long = volume
        .resolve_path(LONG_NAME.as_bytes())
        .expect("long-name inode");
    assert_eq!(volume.read_file(&long).expect("long data"), LONG_DATA);
}

#[test]
fn walks_an_indirect_pointer_level() {
    let mut volume = open(FixtureByteOrder::Little);
    let inode = volume
        .resolve_path(b"indirect.bin")
        .expect("indirect inode");
    let data = volume.read_file(&inode).expect("indirect data");
    assert_eq!(data.len(), INDIRECT_FILE_SIZE);
    for block in 0..17_usize {
        assert!(
            data[block * BLOCK_SIZE..(block + 1) * BLOCK_SIZE]
                .iter()
                .all(|byte| *byte == u8::try_from(block).expect("fixture block fits u8")),
            "data block {block} came from the wrong pointer"
        );
    }
}

#[test]
fn sequential_reads_cache_the_indirect_pointer_block() {
    let reader = CountingReader::new(Cursor::new(qnx6::image(FixtureByteOrder::Little, 1, 2)));
    let mut volume = Qnx6::new(reader).expect("open synthetic QNX6");
    let inode = volume
        .resolve_path(b"indirect.bin")
        .expect("indirect inode");
    volume.reader_mut().reset_stats();

    let data = volume.read_file(&inode).expect("indirect data");
    assert_eq!(data.len(), INDIRECT_FILE_SIZE);
    let stats = volume.reader().stats();
    assert_eq!(
        stats.read_calls(),
        18,
        "17 data blocks plus one pointer block"
    );
    assert_eq!(
        stats.bytes_read(),
        u64::try_from(INDIRECT_FILE_SIZE + BLOCK_SIZE).expect("fixture byte count fits u64")
    );

    volume.reader_mut().reset_stats();
    let mut range = [0_u8; 8];
    volume
        .read_file_range(&inode, BLOCK_SIZE as u64 - 3, &mut range)
        .expect("cached cross-block read");
    let cached_stats = volume.reader().stats();
    assert_eq!(
        cached_stats.read_calls(),
        2,
        "only the two data blocks remain"
    );
    assert_eq!(cached_stats.bytes_read(), 8);
}

#[test]
fn walks_the_maximum_five_indirect_levels() {
    let mut bytes = qnx6::image(FixtureByteOrder::Little, 1, 2);
    let inode_two = qnx6::DATA_AREA_OFFSET + 128;
    bytes[inode_two + 36..inode_two + 40].copy_from_slice(&28_u32.to_le_bytes());
    bytes[inode_two + 100] = 5;
    for (pointer_block, target_block) in [(28_u32, 29_u32), (29, 30), (30, 31), (31, 32), (32, 5)] {
        let pointer = qnx6::DATA_AREA_OFFSET
            + usize::try_from(pointer_block).expect("fixture block fits usize") * BLOCK_SIZE;
        bytes[pointer..pointer + 4].copy_from_slice(&target_block.to_le_bytes());
    }

    let mut volume = Qnx6::new(Cursor::new(bytes)).expect("open five-level fixture");
    let hello = volume.resolve_path(b"hello.txt").expect("hello inode");
    assert_eq!(volume.read_file(&hello).expect("hello data"), HELLO_DATA);
}

#[test]
fn sparse_pointers_read_as_zeroes() {
    let mut volume = open(FixtureByteOrder::Little);
    let inode = volume.resolve_path(b"sparse.bin").expect("sparse inode");
    let data = volume.read_file(&inode).expect("sparse data");
    assert_eq!(data.len(), SPARSE_FILE_SIZE);
    assert!(data[..BLOCK_SIZE].iter().all(|byte| *byte == b'A'));
    assert!(
        data[BLOCK_SIZE..2 * BLOCK_SIZE]
            .iter()
            .all(|byte| *byte == 0)
    );
    assert!(data[2 * BLOCK_SIZE..].iter().all(|byte| *byte == b'C'));
}

#[test]
fn ranged_reads_cross_blocks_and_stop_at_eof() {
    let mut volume = open(FixtureByteOrder::Little);
    let inode = volume
        .resolve_path(b"indirect.bin")
        .expect("indirect inode");
    let mut bytes = [0_u8; 8];
    assert_eq!(
        volume
            .read_file_range(&inode, BLOCK_SIZE as u64 - 3, &mut bytes)
            .expect("cross-block range"),
        bytes.len()
    );
    assert_eq!(&bytes[..3], [0; 3]);
    assert_eq!(&bytes[3..], [1; 5]);
    assert_eq!(
        volume
            .read_file_range(&inode, INDIRECT_FILE_SIZE as u64, &mut bytes)
            .expect("EOF range"),
        0
    );
}

#[test]
fn big_endian_volume_uses_the_same_traversal() {
    let mut volume = open(FixtureByteOrder::Big);
    assert_eq!(volume.superblock().byte_order(), ByteOrder::Big);
    let hello = volume.resolve_path(b"hello.txt").expect("big-endian path");
    assert_eq!(
        volume.read_file(&hello).expect("big-endian data"),
        HELLO_DATA
    );
}

#[test]
fn one_damaged_copy_falls_back_to_the_other() {
    let mut bad_primary = qnx6::image(FixtureByteOrder::Little, 1, 2);
    bad_primary[PRIMARY_SUPERBLOCK_OFFSET + 4] ^= 0x01;
    let primary_fallback = Qnx6::new(Cursor::new(bad_primary)).expect("secondary survives");
    assert!(!primary_fallback.primary_copy_valid());
    assert!(primary_fallback.secondary_copy_valid());
    assert_eq!(primary_fallback.active_copy(), SuperblockCopy::Secondary);

    let mut bad_secondary = qnx6::image(FixtureByteOrder::Little, 1, 2);
    bad_secondary[SECONDARY_SUPERBLOCK_OFFSET + 4] ^= 0x01;
    let secondary_fallback = Qnx6::new(Cursor::new(bad_secondary)).expect("primary survives");
    assert!(secondary_fallback.primary_copy_valid());
    assert!(!secondary_fallback.secondary_copy_valid());
    assert_eq!(secondary_fallback.active_copy(), SuperblockCopy::Primary);
}

#[test]
fn rejects_two_damaged_copies() {
    let mut bytes = qnx6::image(FixtureByteOrder::Little, 1, 2);
    bytes[PRIMARY_SUPERBLOCK_OFFSET] = 0;
    bytes[SECONDARY_SUPERBLOCK_OFFSET] = 0;
    assert!(matches!(
        Qnx6::new(Cursor::new(bytes)),
        Err(Qnx6Error::NoValidSuperblock)
    ));
}

#[test]
fn a_tail_record_must_agree_that_it_is_the_secondary_copy() {
    let original = qnx6::image(FixtureByteOrder::Little, 1, 2);
    let mut bytes = vec![0_u8; qnx6::VOLUME_SIZE + BLOCK_SIZE];
    bytes[..original.len()].copy_from_slice(&original);
    bytes[PRIMARY_SUPERBLOCK_OFFSET] = 0;
    let shifted_secondary = bytes.len() - 0x1000;
    bytes[shifted_secondary..shifted_secondary + 512]
        .copy_from_slice(&original[SECONDARY_SUPERBLOCK_OFFSET..SECONDARY_SUPERBLOCK_OFFSET + 512]);

    assert!(matches!(
        Qnx6::new(Cursor::new(bytes)),
        Err(Qnx6Error::NoValidSuperblock)
    ));
}

#[test]
fn rejects_checksummed_copies_with_conflicting_geometry() {
    let mut bytes = qnx6::image(FixtureByteOrder::Little, 1, 2);
    let count = 63_u32.to_le_bytes();
    bytes[SECONDARY_SUPERBLOCK_OFFSET + 60..SECONDARY_SUPERBLOCK_OFFSET + 64]
        .copy_from_slice(&count);
    qnx6::refresh_superblock_checksum(
        &mut bytes,
        SECONDARY_SUPERBLOCK_OFFSET,
        FixtureByteOrder::Little,
    );
    assert!(matches!(
        Qnx6::new(Cursor::new(bytes)),
        Err(Qnx6Error::ConflictingSuperblocks)
    ));
}

#[test]
fn invalid_file_block_pointer_is_reported_on_read() {
    let mut bytes = qnx6::image(FixtureByteOrder::Little, 1, 2);
    let inode_two_pointer = qnx6::DATA_AREA_OFFSET + 128 + 36;
    bytes[inode_two_pointer..inode_two_pointer + 4].copy_from_slice(&99_u32.to_le_bytes());
    let mut volume = Qnx6::new(Cursor::new(bytes)).expect("root is still valid");
    let hello = volume.resolve_path(b"hello.txt").expect("hello inode");
    assert!(matches!(
        volume.read_file(&hello),
        Err(Qnx6Error::InvalidBlockPointer { block: 99, .. })
    ));
}
