//! Structure-aware fuzz target for the Btrfs metadata and extent parsers.

#![no_main]

use fs_btrfs::fuzzing::{self, CompressionAlgorithm, DirectoryItemKind};
use fs_btrfs::{ChecksumType, SUPERBLOCK_SIZE};
use libfuzzer_sys::fuzz_target;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned};

#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C)]
struct RawControl {
    operation: u8,
    checksum: u8,
    sector_size: u8,
    compression: u8,
    directory_kind: u8,
    _reserved: u8,
    mutation_offset: U16<LE>,
    object_id: U64<LE>,
    key_offset: U64<LE>,
    generation: U64<LE>,
    incompat_flags: U64<LE>,
    output_length: U32<LE>,
}

const CONTROL_SIZE: usize = core::mem::size_of::<RawControl>();
const _: [(); 44] = [(); CONTROL_SIZE];

#[derive(Clone, Copy)]
enum Operation {
    RawSuperblock,
    NormalizedSuperblock,
    RawChunk,
    SystemChunkArray,
    CanonicalSystemChunkArray,
    RawTree,
    ChecksummedTree,
    CanonicalTree,
    RawInode,
    CanonicalInode,
    RootItem,
    CanonicalRootItem,
    DirectoryItem,
    CanonicalDirectoryItem,
    RawFileExtent,
    CanonicalFileExtent,
    Decompress,
}

impl Operation {
    const fn from_raw(value: u8) -> Self {
        match value % 17 {
            0 => Self::RawSuperblock,
            1 => Self::NormalizedSuperblock,
            2 => Self::RawChunk,
            3 => Self::SystemChunkArray,
            4 => Self::CanonicalSystemChunkArray,
            5 => Self::RawTree,
            6 => Self::ChecksummedTree,
            7 => Self::CanonicalTree,
            8 => Self::RawInode,
            9 => Self::CanonicalInode,
            10 => Self::RootItem,
            11 => Self::CanonicalRootItem,
            12 => Self::DirectoryItem,
            13 => Self::CanonicalDirectoryItem,
            14 => Self::RawFileExtent,
            15 => Self::CanonicalFileExtent,
            _ => Self::Decompress,
        }
    }
}

const fn checksum_type(value: u8) -> ChecksumType {
    match value % 4 {
        0 => ChecksumType::Crc32c,
        1 => ChecksumType::XxHash64,
        2 => ChecksumType::Sha256,
        _ => ChecksumType::Blake2b256,
    }
}

const fn sector_size(value: u8) -> u32 {
    match value % 5 {
        0 => 4096,
        1 => 8192,
        2 => 16_384,
        3 => 32_768,
        _ => 65_536,
    }
}

const fn compression(value: u8) -> CompressionAlgorithm {
    match value % 4 {
        0 => CompressionAlgorithm::None,
        1 => CompressionAlgorithm::Zlib,
        2 => CompressionAlgorithm::Lzo,
        _ => CompressionAlgorithm::Zstd,
    }
}

const fn directory_kind(value: u8) -> DirectoryItemKind {
    if value.is_multiple_of(2) {
        DirectoryItemKind::Hashed
    } else {
        DirectoryItemKind::Index
    }
}

fn xor_mutation(target: &mut [u8], start: u16, mutation: &[u8]) {
    if target.is_empty() {
        return;
    }
    let start = usize::from(start) % target.len();
    for (index, byte) in mutation.iter().enumerate() {
        let position = (start + index) % target.len();
        target[position] ^= byte;
    }
}

fn exercise(control: &RawControl, payload: &[u8]) -> bool {
    let operation = Operation::from_raw(control.operation);
    let checksum_type = checksum_type(control.checksum);
    let sector_size = sector_size(control.sector_size);
    let object_id = control.object_id.get();
    let key_offset = control.key_offset.get();
    let generation = control.generation.get();
    let incompat_flags = control.incompat_flags.get();

    match operation {
        Operation::RawSuperblock => fuzzing::parse_superblock(payload),
        Operation::NormalizedSuperblock => {
            let mut data = [0_u8; SUPERBLOCK_SIZE];
            let copied = payload.len().min(data.len());
            data[..copied].copy_from_slice(&payload[..copied]);
            fuzzing::normalize_superblock(&mut data, checksum_type, sector_size)
                && fuzzing::parse_superblock(&data)
        }
        Operation::RawChunk => {
            fuzzing::parse_chunk(key_offset, payload, sector_size, incompat_flags)
        }
        Operation::SystemChunkArray => {
            fuzzing::parse_system_chunk_array(payload, sector_size, incompat_flags)
        }
        Operation::CanonicalSystemChunkArray => {
            let mut data = fuzzing::canonical_system_chunk_array(sector_size);
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::parse_system_chunk_array(&data, sector_size, incompat_flags)
        }
        Operation::RawTree => {
            fuzzing::parse_self_describing_tree_block(payload, checksum_type, sector_size)
        }
        Operation::ChecksummedTree => {
            let mut data = payload.to_vec();
            fuzzing::rechecksum_tree_block(&mut data, checksum_type)
                && fuzzing::parse_self_describing_tree_block(&data, checksum_type, sector_size)
        }
        Operation::CanonicalTree => {
            let mut data = fuzzing::canonical_tree_block(checksum_type);
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::rechecksum_tree_block(&mut data, checksum_type)
                && fuzzing::parse_self_describing_tree_block(&data, checksum_type, 4096)
        }
        Operation::RawInode => fuzzing::parse_inode(payload, object_id, key_offset, generation),
        Operation::CanonicalInode => {
            let mut data = fuzzing::canonical_inode_item();
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::parse_inode(&data, 256, 0, generation)
        }
        Operation::RootItem => {
            fuzzing::parse_root_item(payload, object_id, key_offset, sector_size, generation)
        }
        Operation::CanonicalRootItem => {
            let mut data = fuzzing::canonical_root_item();
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::parse_root_item(&data, 5, 0, 4096, 1)
        }
        Operation::DirectoryItem => fuzzing::parse_directory_item(
            payload,
            object_id,
            directory_kind(control.directory_kind),
            key_offset,
        ),
        Operation::CanonicalDirectoryItem => {
            let kind = directory_kind(control.directory_kind);
            let (mut data, key_offset) = fuzzing::canonical_directory_item(kind);
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::parse_directory_item(&data, 256, kind, key_offset)
        }
        Operation::RawFileExtent => {
            fuzzing::parse_file_extent(payload, object_id, key_offset, sector_size)
        }
        Operation::CanonicalFileExtent => {
            let mut data = fuzzing::canonical_regular_file_extent();
            xor_mutation(&mut data, control.mutation_offset.get(), payload);
            fuzzing::parse_file_extent(&data, 256, 0, 4096)
        }
        Operation::Decompress => fuzzing::decompress_extent(
            payload,
            compression(control.compression),
            control.output_length.get().min(1_048_576),
            sector_size,
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(control_bytes) = data.get(..CONTROL_SIZE) else {
        return;
    };
    let Some(payload) = data.get(CONTROL_SIZE..) else {
        return;
    };
    let Ok(control) = RawControl::ref_from_bytes(control_bytes) else {
        return;
    };
    core::hint::black_box(exercise(control, payload));
});
