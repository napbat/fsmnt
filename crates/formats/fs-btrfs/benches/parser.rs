//! Microbenchmarks for validated Btrfs on-disk records.

use std::sync::LazyLock;

use divan::{Bencher, black_box};
use fs_btrfs::ChecksumType;
use fs_btrfs::fuzzing;

static SUPERBLOCK: LazyLock<[u8; 4096]> =
    LazyLock::new(|| fuzzing::canonical_superblock(ChecksumType::Crc32c));
static TREE_BLOCK: LazyLock<Vec<u8>> =
    LazyLock::new(|| fuzzing::canonical_tree_block(ChecksumType::Crc32c));
static INODE_ITEM: LazyLock<[u8; 160]> = LazyLock::new(fuzzing::canonical_inode_item);
static ROOT_ITEM: LazyLock<[u8; 439]> = LazyLock::new(fuzzing::canonical_root_item);
static FILE_EXTENT: LazyLock<[u8; 53]> = LazyLock::new(fuzzing::canonical_regular_file_extent);
static SYSTEM_CHUNK: LazyLock<Vec<u8>> =
    LazyLock::new(|| fuzzing::canonical_system_chunk_array(4096));
static DIRECTORY_ITEM: LazyLock<(Vec<u8>, u64)> =
    LazyLock::new(|| fuzzing::canonical_directory_item(fuzzing::DirectoryItemKind::Index));

fn main() {
    divan::main();
}

#[divan::bench]
fn parse_superblock(bencher: Bencher<'_, '_>) {
    bencher.bench(|| black_box(fuzzing::parse_superblock(black_box(SUPERBLOCK.as_slice()))));
}

#[divan::bench]
fn parse_tree_block(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_self_describing_tree_block(
            black_box(TREE_BLOCK.as_slice()),
            ChecksumType::Crc32c,
            4096,
        ))
    });
}

#[divan::bench]
fn parse_inode_item(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_inode(
            black_box(INODE_ITEM.as_slice()),
            256,
            0,
            1,
        ))
    });
}

#[divan::bench]
fn parse_file_extent(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_file_extent(
            black_box(FILE_EXTENT.as_slice()),
            256,
            0,
            4096,
        ))
    });
}

#[divan::bench]
fn parse_system_chunk(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_system_chunk_array(
            black_box(SYSTEM_CHUNK.as_slice()),
            4096,
            0,
        ))
    });
}

#[divan::bench]
fn parse_root_item(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_root_item(
            black_box(ROOT_ITEM.as_slice()),
            5,
            0,
            4096,
            1,
        ))
    });
}

#[divan::bench]
fn parse_directory_item(bencher: Bencher<'_, '_>) {
    bencher.bench(|| {
        black_box(fuzzing::parse_directory_item(
            black_box(DIRECTORY_ITEM.0.as_slice()),
            256,
            fuzzing::DirectoryItemKind::Index,
            DIRECTORY_ITEM.1,
        ))
    });
}
