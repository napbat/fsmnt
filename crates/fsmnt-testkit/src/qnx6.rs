//! Synthetic QNX6 volume builder for cross-crate integration tests.

use fsmnt_parser_core::boot_sector::qnx6::{SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE};

/// Byte order used by the synthetic filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureByteOrder {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

/// Offset of the first superblock record.
pub const PRIMARY_SUPERBLOCK_OFFSET: usize = 0x2000;

/// Offset of filesystem block zero.
pub const DATA_AREA_OFFSET: usize = 0x3000;

/// Logical block size used by the fixture.
pub const BLOCK_SIZE: usize = 512;

/// Number of filesystem blocks in the fixture.
pub const BLOCK_COUNT: usize = 64;

/// Offset of the second superblock record.
pub const SECONDARY_SUPERBLOCK_OFFSET: usize = DATA_AREA_OFFSET + BLOCK_COUNT * BLOCK_SIZE;

/// Complete fixture volume length.
pub const VOLUME_SIZE: usize = SECONDARY_SUPERBLOCK_OFFSET + 0x1000;

/// Fixed volume identifier written to both snapshots.
pub const VOLUME_ID: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x80, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
];

/// Contents of `/hello.txt`.
pub const HELLO_DATA: &[u8] = b"hello from qnx6\n";

/// Contents of `/subdir/inner.txt`.
pub const INNER_DATA: &[u8] = b"inside the subdirectory\n";

/// Long filename stored through the separate name tree.
pub const LONG_NAME: &str = "this-is-a-very-long-qnx6-filename.txt";

/// Contents of the long-named file.
pub const LONG_DATA: &[u8] = b"long filename payload\n";

/// Size of the file whose data uses one indirect pointer level.
pub const INDIRECT_FILE_SIZE: usize = 17 * BLOCK_SIZE;

/// Size of the three-block sparse file.
pub const SPARSE_FILE_SIZE: usize = 3 * BLOCK_SIZE;

const INODE_SIZE: usize = 128;
const INODE_COUNT: u32 = 8;
const UNUSED_BLOCK: u32 = u32::MAX;
const ROOT_DIRECTORY_BLOCK: u32 = 3;
const SUBDIRECTORY_BLOCK: u32 = 4;

/// Build a complete two-snapshot QNX6 volume.
///
/// The image exercises inline and long directory names, nested directories,
/// a 17-block indirect file, and a sparse file with an unallocated middle
/// block. `primary_serial` and `secondary_serial` control which otherwise
/// equivalent snapshot wins during opening.
#[must_use]
pub fn image(byte_order: FixtureByteOrder, primary_serial: u64, secondary_serial: u64) -> Vec<u8> {
    let mut image = vec![0_u8; VOLUME_SIZE];
    write_inode_table(&mut image, byte_order);
    write_directories(&mut image, byte_order);
    write_file_data(&mut image, byte_order);
    let roots = FixtureRoots::new();
    write_superblock(
        &mut image[PRIMARY_SUPERBLOCK_OFFSET..PRIMARY_SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE],
        byte_order,
        primary_serial,
        &roots,
    );
    write_superblock(
        &mut image[SECONDARY_SUPERBLOCK_OFFSET..SECONDARY_SUPERBLOCK_OFFSET + SUPERBLOCK_SIZE],
        byte_order,
        secondary_serial,
        &roots,
    );
    image
}

/// Recalculate the checksum after a test mutates a synthetic superblock.
///
/// # Panics
///
/// Panics if `offset` does not name a complete 512-byte record in `image`.
pub fn refresh_superblock_checksum(image: &mut [u8], offset: usize, byte_order: FixtureByteOrder) {
    let superblock = &mut image[offset..offset + SUPERBLOCK_SIZE];
    let checksum = crc32(&superblock[8..]);
    put_u32(superblock, 4, checksum, byte_order);
}

/// Fill one filesystem data block with `value`.
fn fill_block(image: &mut [u8], block: u32, value: u8) {
    let start = block_offset(block);
    image[start..start + BLOCK_SIZE].fill(value);
}

/// Copy bytes into one filesystem data block.
fn copy_to_block(image: &mut [u8], block: u32, bytes: &[u8]) {
    let start = block_offset(block);
    image[start..start + bytes.len()].copy_from_slice(bytes);
}

/// Absolute byte offset of a filesystem block.
fn block_offset(block: u32) -> usize {
    DATA_AREA_OFFSET + usize::try_from(block).expect("fixture block fits usize") * BLOCK_SIZE
}

/// Metadata roots written into both snapshot copies.
struct FixtureRoots {
    inode: Root,
    bitmap: Root,
    long_name: Root,
    unknown: Root,
}

impl FixtureRoots {
    fn new() -> Self {
        Self {
            inode: Root::new(u64::from(INODE_COUNT) * INODE_SIZE as u64, &[0, 1], 0),
            bitmap: Root::new(0, &[], 0),
            long_name: Root::new(BLOCK_SIZE as u64, &[2], 0),
            unknown: Root::new(0, &[], 0),
        }
    }
}

/// One root node before byte encoding.
struct Root {
    size: u64,
    pointers: [u32; 16],
    levels: u8,
}

impl Root {
    fn new(size: u64, used_pointers: &[u32], levels: u8) -> Self {
        let mut pointers = [UNUSED_BLOCK; 16];
        pointers[..used_pointers.len()].copy_from_slice(used_pointers);
        Self {
            size,
            pointers,
            levels,
        }
    }
}

/// Encode both blocks of the inode-table metadata file.
fn write_inode_table(image: &mut [u8], order: FixtureByteOrder) {
    let mut table = [0_u8; INODE_SIZE * 8];
    write_inode(
        &mut table,
        1,
        7 * 32,
        0o040_755,
        0,
        &[ROOT_DIRECTORY_BLOCK],
        1,
        order,
    );
    write_inode(
        &mut table,
        2,
        HELLO_DATA.len(),
        0o100_644,
        0,
        &[5],
        3,
        order,
    );
    write_inode(
        &mut table,
        3,
        3 * 32,
        0o040_755,
        0,
        &[SUBDIRECTORY_BLOCK],
        1,
        order,
    );
    write_inode(
        &mut table,
        4,
        INNER_DATA.len(),
        0o100_400,
        0,
        &[6],
        3,
        order,
    );
    write_inode(&mut table, 5, LONG_DATA.len(), 0o100_444, 0, &[7], 3, order);
    write_inode(
        &mut table,
        6,
        INDIRECT_FILE_SIZE,
        0o100_644,
        1,
        &[8],
        3,
        order,
    );
    write_inode(
        &mut table,
        7,
        SPARSE_FILE_SIZE,
        0o100_644,
        0,
        &[26, UNUSED_BLOCK, 27],
        3,
        order,
    );
    copy_to_block(image, 0, &table[..BLOCK_SIZE]);
    copy_to_block(image, 1, &table[BLOCK_SIZE..]);
}

/// Encode one inode record.
#[allow(
    clippy::too_many_arguments,
    reason = "the helper names the independent fields a synthetic inode must control"
)]
fn write_inode(
    table: &mut [u8],
    number: usize,
    size: usize,
    mode: u16,
    levels: u8,
    used_pointers: &[u32],
    status: u8,
    order: FixtureByteOrder,
) {
    let start = (number - 1) * INODE_SIZE;
    let inode = &mut table[start..start + INODE_SIZE];
    put_u64(
        inode,
        0,
        u64::try_from(size).expect("fixture size fits u64"),
        order,
    );
    put_u32(inode, 8, 1000, order);
    put_u32(inode, 12, 1000, order);
    for offset in [16, 20, 24, 28] {
        put_u32(inode, offset, 1_700_000_000, order);
    }
    put_u16(inode, 32, mode, order);
    for index in 0..16 {
        put_u32(inode, 36 + index * 4, UNUSED_BLOCK, order);
    }
    for (index, pointer) in used_pointers.iter().copied().enumerate() {
        put_u32(inode, 36 + index * 4, pointer, order);
    }
    inode[100] = levels;
    inode[101] = status;
}

/// Encode root and nested directory files plus the long-name metadata block.
fn write_directories(image: &mut [u8], order: FixtureByteOrder) {
    let root = block_offset(ROOT_DIRECTORY_BLOCK);
    for (index, record) in [
        short_entry(1, b".", order),
        short_entry(1, b"..", order),
        short_entry(2, b"hello.txt", order),
        short_entry(3, b"subdir", order),
        long_entry(5, 0, LONG_NAME.as_bytes(), order),
        short_entry(6, b"indirect.bin", order),
        short_entry(7, b"sparse.bin", order),
    ]
    .iter()
    .enumerate()
    {
        image[root + index * 32..root + (index + 1) * 32].copy_from_slice(record);
    }

    let subdir = block_offset(SUBDIRECTORY_BLOCK);
    for (index, record) in [
        short_entry(3, b".", order),
        short_entry(1, b"..", order),
        short_entry(4, b"inner.txt", order),
    ]
    .iter()
    .enumerate()
    {
        image[subdir + index * 32..subdir + (index + 1) * 32].copy_from_slice(record);
    }

    let long_name = block_offset(2);
    put_u16(
        image,
        long_name,
        u16::try_from(LONG_NAME.len()).expect("fixture name fits u16"),
        order,
    );
    image[long_name + 2..long_name + 2 + LONG_NAME.len()].copy_from_slice(LONG_NAME.as_bytes());
}

/// Encode all regular-file data and the one-level pointer block.
fn write_file_data(image: &mut [u8], order: FixtureByteOrder) {
    copy_to_block(image, 5, HELLO_DATA);
    copy_to_block(image, 6, INNER_DATA);
    copy_to_block(image, 7, LONG_DATA);

    let pointers = block_offset(8);
    for index in 0..17_u32 {
        put_u32(
            image,
            pointers + usize::try_from(index).expect("fixture index fits usize") * 4,
            9 + index,
            order,
        );
        fill_block(
            image,
            9 + index,
            u8::try_from(index).expect("fixture byte fits u8"),
        );
    }
    fill_block(image, 26, b'A');
    fill_block(image, 27, b'C');
}

/// Construct an inline directory record.
fn short_entry(inode: u32, name: &[u8], order: FixtureByteOrder) -> [u8; 32] {
    let mut record = [0_u8; 32];
    put_u32(&mut record, 0, inode, order);
    record[4] = u8::try_from(name.len()).expect("fixture short name fits u8");
    record[5..5 + name.len()].copy_from_slice(name);
    record
}

/// Construct a directory record backed by the long-name tree.
fn long_entry(inode: u32, index: u32, name: &[u8], order: FixtureByteOrder) -> [u8; 32] {
    let mut record = [0_u8; 32];
    put_u32(&mut record, 0, inode, order);
    record[4] = 0xff;
    put_u32(&mut record, 8, index, order);
    put_u32(&mut record, 12, long_name_checksum(name), order);
    record
}

/// Encode one standard QNX6 superblock.
fn write_superblock(
    superblock: &mut [u8],
    order: FixtureByteOrder,
    serial: u64,
    roots: &FixtureRoots,
) {
    put_u32(superblock, 0, SUPERBLOCK_MAGIC, order);
    put_u64(superblock, 8, serial, order);
    put_u32(superblock, 16, 1_600_000_000, order);
    put_u32(superblock, 20, 1_700_000_000, order);
    put_u32(superblock, 24, 0x100, order);
    put_u16(superblock, 28, 4, order);
    put_u16(superblock, 30, 3, order);
    superblock[32..48].copy_from_slice(&VOLUME_ID);
    put_u32(
        superblock,
        48,
        u32::try_from(BLOCK_SIZE).expect("block size fits u32"),
        order,
    );
    put_u32(superblock, 52, INODE_COUNT, order);
    put_u32(superblock, 56, 1, order);
    put_u32(
        superblock,
        60,
        u32::try_from(BLOCK_COUNT).expect("block count fits u32"),
        order,
    );
    put_u32(superblock, 64, 30, order);
    put_u32(superblock, 68, 4, order);
    write_root(superblock, 72, &roots.inode, order);
    write_root(superblock, 152, &roots.bitmap, order);
    write_root(superblock, 232, &roots.long_name, order);
    write_root(superblock, 312, &roots.unknown, order);
    let checksum = crc32(&superblock[8..]);
    put_u32(superblock, 4, checksum, order);
}

/// Encode one 80-byte metadata-root descriptor.
fn write_root(superblock: &mut [u8], offset: usize, root: &Root, order: FixtureByteOrder) {
    put_u64(superblock, offset, root.size, order);
    for (index, pointer) in root.pointers.iter().copied().enumerate() {
        put_u32(superblock, offset + 8 + index * 4, pointer, order);
    }
    superblock[offset + 72] = root.levels;
}

/// Long-name checksum stored in a directory record.
fn long_name_checksum(name: &[u8]) -> u32 {
    let mut checksum = 0_u32;
    for &byte in name {
        let low_bit = checksum & 1;
        checksum = (checksum >> 1).wrapping_add(u32::from(byte));
        if low_bit != 0 {
            checksum ^= 0x8000_0000;
        }
    }
    checksum
}

/// Non-reflected QNX6 superblock CRC-32.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x04C1_1DB7
            };
        }
    }
    crc
}

/// Store one integer in the fixture's byte order.
fn put_u16(bytes: &mut [u8], offset: usize, value: u16, order: FixtureByteOrder) {
    let encoded = match order {
        FixtureByteOrder::Little => value.to_le_bytes(),
        FixtureByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 2].copy_from_slice(&encoded);
}

/// Store one integer in the fixture's byte order.
fn put_u32(bytes: &mut [u8], offset: usize, value: u32, order: FixtureByteOrder) {
    let encoded = match order {
        FixtureByteOrder::Little => value.to_le_bytes(),
        FixtureByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 4].copy_from_slice(&encoded);
}

/// Store one integer in the fixture's byte order.
fn put_u64(bytes: &mut [u8], offset: usize, value: u64, order: FixtureByteOrder) {
    let encoded = match order {
        FixtureByteOrder::Little => value.to_le_bytes(),
        FixtureByteOrder::Big => value.to_be_bytes(),
    };
    bytes[offset..offset + 8].copy_from_slice(&encoded);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_has_both_checksummed_magic_records() {
        for order in [FixtureByteOrder::Little, FixtureByteOrder::Big] {
            let image = image(order, 1, 2);
            let expected = match order {
                FixtureByteOrder::Little => SUPERBLOCK_MAGIC.to_le_bytes(),
                FixtureByteOrder::Big => SUPERBLOCK_MAGIC.to_be_bytes(),
            };
            assert_eq!(
                image[PRIMARY_SUPERBLOCK_OFFSET..PRIMARY_SUPERBLOCK_OFFSET + 4],
                expected
            );
            assert_eq!(
                image[SECONDARY_SUPERBLOCK_OFFSET..SECONDARY_SUPERBLOCK_OFFSET + 4],
                expected
            );
        }
    }
}
