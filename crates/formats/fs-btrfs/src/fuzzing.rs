//! Narrow, typed entry points for parser fuzzing and microbenchmarks.

use alloc::vec::Vec;

use crate::checksum::ChecksumType;
use crate::chunk::{ChunkMapping, parse_system_chunks};
use crate::file::decompress;
use crate::item::{
    BtrfsInode, Compression, FileExtent, RootItem, canonical_directory, canonical_inode,
    canonical_regular_extent, canonical_root, parse_directory_entries,
};
use crate::superblock::normalize_for_fuzzing;
use crate::tree::{TreeBlock, canonical_leaf, parse_self_describing, recompute_checksum};
use crate::{BtrfsSuperblock, DiskKey, SUPERBLOCK_SIZE};

/// Compression selector understood by the extent decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompressionAlgorithm {
    /// Uncompressed bytes.
    None,
    /// DEFLATE/zlib.
    Zlib,
    /// Btrfs-framed LZO.
    Lzo,
    /// Zstandard.
    Zstd,
}

impl CompressionAlgorithm {
    const fn internal(self) -> Compression {
        match self {
            Self::None => Compression::None,
            Self::Zlib => Compression::Zlib,
            Self::Lzo => Compression::Lzo,
            Self::Zstd => Compression::Zstd,
        }
    }
}

/// Directory record layout selected by a tree key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryItemKind {
    /// Name-hashed directory item.
    Hashed,
    /// Directory item ordered by insertion index.
    Index,
}

impl DirectoryItemKind {
    const fn key_type(self) -> u8 {
        match self {
            Self::Hashed => crate::item::DIR_ITEM_KEY,
            Self::Index => crate::item::DIR_INDEX_KEY,
        }
    }
}

/// Exercise primary-superblock parsing and report whether the bytes were valid.
#[must_use]
pub fn parse_superblock(data: &[u8]) -> bool {
    BtrfsSuperblock::from_primary_bytes(data).is_ok()
}

/// Normalize mutable bytes into a checksummed, structurally reachable
/// superblock while preserving unconstrained fields for mutation.
#[must_use]
pub fn normalize_superblock(
    data: &mut [u8],
    checksum_type: ChecksumType,
    sector_size: u32,
) -> bool {
    normalize_for_fuzzing(data, checksum_type, sector_size)
}

/// Construct the canonical valid superblock used by benchmarks and seed tools.
#[must_use]
pub fn canonical_superblock(checksum_type: ChecksumType) -> [u8; SUPERBLOCK_SIZE] {
    let mut data = [0_u8; SUPERBLOCK_SIZE];
    let normalized = normalize_superblock(&mut data, checksum_type, 4096);
    debug_assert!(normalized);
    data
}

/// Construct one valid single-device SYSTEM chunk-array entry.
#[must_use]
pub fn canonical_system_chunk_array(sector_size: u32) -> Vec<u8> {
    crate::chunk::canonical_system_chunk(0x10_0000, sector_size, 1, [0x33; 16]).to_vec()
}

/// Exercise one chunk item with an explicit superblock validation context.
#[must_use]
pub fn parse_chunk(logical: u64, data: &[u8], sector_size: u32, incompat_flags: u64) -> bool {
    ChunkMapping::parse(logical, data, sector_size, incompat_flags).is_ok()
}

/// Exercise the serialized system-chunk array parser.
#[must_use]
pub fn parse_system_chunk_array(data: &[u8], sector_size: u32, incompat_flags: u64) -> bool {
    parse_system_chunks(data, sector_size, incompat_flags).is_ok()
}

/// Exercise a checksummed B-tree block with an explicit external context.
#[must_use]
pub fn parse_tree_block(
    data: &[u8],
    logical: u64,
    level: u8,
    tree_uuid: &[u8; 16],
    checksum_type: ChecksumType,
    sector_size: u32,
) -> bool {
    TreeBlock::parse(data, logical, level, tree_uuid, checksum_type, sector_size).is_ok()
}

/// Exercise a tree block using context decoded from its typed header.
#[must_use]
pub fn parse_self_describing_tree_block(
    data: &[u8],
    checksum_type: ChecksumType,
    sector_size: u32,
) -> bool {
    parse_self_describing(data, checksum_type, sector_size).is_ok()
}

/// Recompute a tree block's checksum after a fuzzer mutation.
#[must_use]
pub fn rechecksum_tree_block(data: &mut [u8], checksum_type: ChecksumType) -> bool {
    recompute_checksum(data, checksum_type)
}

/// Construct a canonical one-item leaf for benchmarks and seed tools.
#[must_use]
pub fn canonical_tree_block(checksum_type: ChecksumType) -> Vec<u8> {
    canonical_leaf(checksum_type)
}

/// Exercise inode-item parsing with a supplied key and transaction generation.
#[must_use]
pub fn parse_inode(data: &[u8], object_id: u64, key_offset: u64, super_generation: u64) -> bool {
    BtrfsInode::parse(
        DiskKey {
            object_id,
            item_type: crate::item::INODE_ITEM_KEY,
            offset: key_offset,
        },
        data,
        super_generation,
    )
    .is_ok()
}

/// Construct a canonical regular-file inode item.
#[must_use]
pub fn canonical_inode_item() -> [u8; 160] {
    canonical_inode()
}

/// Construct a canonical modern root item.
#[must_use]
pub fn canonical_root_item() -> [u8; 439] {
    canonical_root()
}

/// Exercise root-item parsing with its superblock geometry.
#[must_use]
pub fn parse_root_item(
    data: &[u8],
    object_id: u64,
    key_offset: u64,
    sector_size: u32,
    super_generation: u64,
) -> bool {
    RootItem::parse(
        DiskKey {
            object_id,
            item_type: crate::item::ROOT_ITEM_KEY,
            offset: key_offset,
        },
        data,
        sector_size,
        super_generation,
    )
    .is_ok()
}

/// Exercise a directory item or directory-index item parser.
#[must_use]
pub fn parse_directory_item(
    data: &[u8],
    object_id: u64,
    kind: DirectoryItemKind,
    key_offset: u64,
) -> bool {
    parse_directory_entries(
        DiskKey {
            object_id,
            item_type: kind.key_type(),
            offset: key_offset,
        },
        data,
    )
    .is_ok()
}

/// Construct a canonical directory record and its required key offset.
#[must_use]
pub fn canonical_directory_item(kind: DirectoryItemKind) -> (Vec<u8>, u64) {
    canonical_directory(kind.key_type())
}

/// Exercise a file-extent item parser with a supplied sector size.
#[must_use]
pub fn parse_file_extent(data: &[u8], object_id: u64, key_offset: u64, sector_size: u32) -> bool {
    FileExtent::parse(
        DiskKey {
            object_id,
            item_type: crate::item::EXTENT_DATA_KEY,
            offset: key_offset,
        },
        data,
        sector_size,
    )
    .is_ok()
}

/// Construct a canonical aligned regular file extent.
#[must_use]
pub fn canonical_regular_file_extent() -> [u8; 53] {
    canonical_regular_extent()
}

/// Exercise one compression decoder with a bounded requested output length.
#[must_use]
pub fn decompress_extent(
    data: &[u8],
    compression: CompressionAlgorithm,
    output_length: u32,
    sector_size: u32,
) -> bool {
    decompress(
        data,
        compression.internal(),
        u64::from(output_length),
        sector_size,
    )
    .is_ok()
}
