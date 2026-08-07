//! B-tree block headers, leaf items, and internal pointers.

use alloc::vec::Vec;

use crate::bytes::slice;
use crate::checksum::ChecksumType;
use crate::item::{CHUNK_TREE_OBJECT_ID, FS_TREE_OBJECT_ID, ROOT_TREE_OBJECT_ID};
use crate::key::{DiskKey, RawDiskKey};
use crate::{BtrfsError, Result};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U32, U64, Unaligned,
};

const HEADER_FLAG_WRITTEN: u64 = 1;
const MAX_TREE_LEVEL: u8 = 8;
const EXTENT_TREE_OBJECT_ID: u64 = 2;
const DEVICE_TREE_OBJECT_ID: u64 = 4;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawTreeHeader {
    checksum: [u8; 32],
    fsid: [u8; 16],
    logical: U64<LE>,
    flags: U64<LE>,
    _chunk_tree_uuid: [u8; 16],
    generation: U64<LE>,
    owner: U64<LE>,
    item_count: U32<LE>,
    level: u8,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawLeafItem {
    key: RawDiskKey,
    data_offset: U32<LE>,
    data_size: U32<LE>,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawNodePointer {
    key: RawDiskKey,
    logical: U64<LE>,
    generation: U64<LE>,
}

const HEADER_SIZE: usize = core::mem::size_of::<RawTreeHeader>();
const LEAF_ITEM_SIZE: usize = core::mem::size_of::<RawLeafItem>();
const NODE_POINTER_SIZE: usize = core::mem::size_of::<RawNodePointer>();
const _: [(); 101] = [(); HEADER_SIZE];
const _: [(); 25] = [(); LEAF_ITEM_SIZE];
const _: [(); 33] = [(); NODE_POINTER_SIZE];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TreeRoot {
    pub(crate) tree_id: u64,
    pub(crate) logical: u64,
    pub(crate) level: u8,
    pub(crate) expected_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TreeItem {
    pub(crate) key: DiskKey,
    pub(crate) data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NodePointer {
    pub(crate) key: DiskKey,
    pub(crate) logical: u64,
    pub(crate) generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum TreeBlock {
    Leaf {
        logical: u64,
        generation: u64,
        owner: u64,
        items: Vec<TreeItem>,
    },
    Node {
        logical: u64,
        generation: u64,
        owner: u64,
        level: u8,
        pointers: Vec<NodePointer>,
    },
}

impl TreeBlock {
    pub(crate) fn parse(
        data: &[u8],
        logical: u64,
        expected_level: u8,
        tree_uuid: &[u8; 16],
        checksum_type: ChecksumType,
        sector_size: u32,
    ) -> Result<Self> {
        if data.len() < HEADER_SIZE {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }
        if !checksum_type.verify(&data[..32], &data[32..]) {
            return Err(BtrfsError::InvalidChecksum {
                structure: "tree block",
                logical,
            });
        }
        let header = RawTreeHeader::ref_from_bytes(&data[..HEADER_SIZE])
            .map_err(|_| BtrfsError::MalformedTreeBlock { logical })?;
        if header.fsid != *tree_uuid
            || header.logical.get() != logical
            || header.level != expected_level
            || expected_level >= MAX_TREE_LEVEL
            || header.flags.get() & HEADER_FLAG_WRITTEN == 0
            || header.owner.get() == 0
        {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }

        let generation = header.generation.get();
        let owner = header.owner.get();
        let item_count =
            usize::try_from(header.item_count.get()).map_err(|_| BtrfsError::IntegerOverflow)?;
        if expected_level == 0 {
            if item_count == 0 && requires_nonempty_leaf(owner) {
                return Err(BtrfsError::MalformedTreeBlock { logical });
            }
            Self::parse_leaf(data, logical, generation, owner, item_count)
        } else {
            Self::parse_node(
                data,
                logical,
                generation,
                owner,
                expected_level,
                item_count,
                sector_size,
            )
        }
    }

    fn parse_leaf(
        data: &[u8],
        logical: u64,
        generation: u64,
        owner: u64,
        item_count: usize,
    ) -> Result<Self> {
        let table_size = item_count
            .checked_mul(LEAF_ITEM_SIZE)
            .and_then(|size| HEADER_SIZE.checked_add(size))
            .ok_or(BtrfsError::IntegerOverflow)?;
        if table_size > data.len() {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }

        let mut expected_data_end = data.len() - HEADER_SIZE;
        let mut items = Vec::with_capacity(item_count);
        for index in 0..item_count {
            let position = item_position(index, LEAF_ITEM_SIZE)?;
            let raw = RawLeafItem::ref_from_bytes(slice(data, position, LEAF_ITEM_SIZE)?)
                .map_err(|_| BtrfsError::MalformedTreeBlock { logical })?;
            let key = raw.key.to_disk_key();
            let relative_data_offset =
                usize::try_from(raw.data_offset.get()).map_err(|_| BtrfsError::IntegerOverflow)?;
            let data_offset = HEADER_SIZE
                .checked_add(relative_data_offset)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let data_size =
                usize::try_from(raw.data_size.get()).map_err(|_| BtrfsError::IntegerOverflow)?;
            let relative_item_end = relative_data_offset
                .checked_add(data_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let item_end = data_offset
                .checked_add(data_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            if relative_item_end != expected_data_end
                || data_offset < table_size
                || item_end > data.len()
            {
                return Err(BtrfsError::MalformedTreeBlock { logical });
            }
            expected_data_end = relative_data_offset;
            items.push(TreeItem {
                key,
                data: slice(data, data_offset, data_size)?.to_vec(),
            });
        }
        validate_sorted_keys(items.iter().map(|item| item.key), logical)?;

        Ok(Self::Leaf {
            logical,
            generation,
            owner,
            items,
        })
    }

    fn parse_node(
        data: &[u8],
        logical: u64,
        generation: u64,
        owner: u64,
        level: u8,
        item_count: usize,
        sector_size: u32,
    ) -> Result<Self> {
        let table_end = item_count
            .checked_mul(NODE_POINTER_SIZE)
            .and_then(|size| HEADER_SIZE.checked_add(size))
            .ok_or(BtrfsError::IntegerOverflow)?;
        if item_count == 0 || table_end > data.len() {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }

        let mut pointers = Vec::with_capacity(item_count);
        for index in 0..item_count {
            let position = item_position(index, NODE_POINTER_SIZE)?;
            let raw = RawNodePointer::ref_from_bytes(slice(data, position, NODE_POINTER_SIZE)?)
                .map_err(|_| BtrfsError::MalformedTreeBlock { logical })?;
            let pointer = NodePointer {
                key: raw.key.to_disk_key(),
                logical: raw.logical.get(),
                generation: raw.generation.get(),
            };
            if pointer.logical == 0 || !pointer.logical.is_multiple_of(u64::from(sector_size)) {
                return Err(BtrfsError::MalformedTreeBlock { logical });
            }
            pointers.push(pointer);
        }
        validate_sorted_keys(pointers.iter().map(|pointer| pointer.key), logical)?;

        Ok(Self::Node {
            logical,
            generation,
            owner,
            level,
            pointers,
        })
    }

    pub(crate) fn first_key(&self) -> Option<DiskKey> {
        match self {
            Self::Leaf { items, .. } => items.first().map(|item| item.key),
            Self::Node { pointers, .. } => pointers.first().map(|pointer| pointer.key),
        }
    }
}

const fn requires_nonempty_leaf(owner: u64) -> bool {
    matches!(
        owner,
        ROOT_TREE_OBJECT_ID
            | EXTENT_TREE_OBJECT_ID
            | CHUNK_TREE_OBJECT_ID
            | DEVICE_TREE_OBJECT_ID
            | FS_TREE_OBJECT_ID
    )
}

fn item_position(index: usize, item_size: usize) -> Result<usize> {
    index
        .checked_mul(item_size)
        .and_then(|offset| HEADER_SIZE.checked_add(offset))
        .ok_or(BtrfsError::IntegerOverflow)
}

fn validate_sorted_keys(keys: impl IntoIterator<Item = DiskKey>, logical: u64) -> Result<()> {
    let mut previous = None;
    for key in keys {
        if previous.is_some_and(|previous_key| previous_key >= key) {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }
        previous = Some(key);
    }
    Ok(())
}

#[cfg(feature = "fuzzing")]
pub(crate) fn parse_self_describing(
    data: &[u8],
    checksum_type: ChecksumType,
    sector_size: u32,
) -> Result<TreeBlock> {
    let header = RawTreeHeader::ref_from_bytes(
        data.get(..HEADER_SIZE)
            .ok_or(BtrfsError::MalformedTreeBlock { logical: 0 })?,
    )
    .map_err(|_| BtrfsError::MalformedTreeBlock { logical: 0 })?;
    TreeBlock::parse(
        data,
        header.logical.get(),
        header.level,
        &header.fsid,
        checksum_type,
        sector_size,
    )
}

#[cfg(feature = "fuzzing")]
pub(crate) fn recompute_checksum(data: &mut [u8], checksum_type: ChecksumType) -> bool {
    if data.len() < HEADER_SIZE {
        return false;
    }
    let checksum = checksum_type.compute(&data[32..]);
    let Ok(header) = RawTreeHeader::mut_from_bytes(&mut data[..HEADER_SIZE]) else {
        return false;
    };
    header.checksum = checksum;
    true
}

#[cfg(feature = "fuzzing")]
pub(crate) fn canonical_leaf(checksum_type: ChecksumType) -> Vec<u8> {
    const NODE_SIZE: usize = 4096;
    const PAYLOAD: &[u8] = b"data";
    let logical = 0x10_0000;
    let mut data = alloc::vec![0_u8; NODE_SIZE];
    let header = RawTreeHeader {
        checksum: [0; 32],
        fsid: [0x5a; 16],
        logical: U64::new(logical),
        flags: U64::new(HEADER_FLAG_WRITTEN),
        _chunk_tree_uuid: [0; 16],
        generation: U64::new(1),
        owner: U64::new(FS_TREE_OBJECT_ID),
        item_count: U32::new(1),
        level: 0,
    };
    data[..HEADER_SIZE].copy_from_slice(header.as_bytes());

    let relative_offset = NODE_SIZE - HEADER_SIZE - PAYLOAD.len();
    let item = RawLeafItem {
        key: DiskKey {
            object_id: 256,
            item_type: 250,
            offset: 0,
        }
        .into(),
        data_offset: U32::new(u32::try_from(relative_offset).expect("canonical node fits u32")),
        data_size: U32::new(u32::try_from(PAYLOAD.len()).expect("canonical payload fits u32")),
    };
    data[HEADER_SIZE..HEADER_SIZE + LEAF_ITEM_SIZE].copy_from_slice(item.as_bytes());
    data[NODE_SIZE - PAYLOAD.len()..].copy_from_slice(PAYLOAD);
    let recomputed = recompute_checksum(&mut data, checksum_type);
    debug_assert!(recomputed);
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_SIZE: usize = 4096;
    const UUID: [u8; 16] = [0x5a; 16];

    fn header(data: &mut [u8], logical: u64, items: u32, level: u8) {
        let header = RawTreeHeader {
            checksum: [0; 32],
            fsid: UUID,
            logical: U64::new(logical),
            flags: U64::new(HEADER_FLAG_WRITTEN),
            _chunk_tree_uuid: [0; 16],
            generation: U64::new(7),
            owner: U64::new(5),
            item_count: U32::new(items),
            level,
        };
        data[..HEADER_SIZE].copy_from_slice(header.as_bytes());
    }

    fn leaf_item(data: &mut [u8], index: usize, key: DiskKey, offset: u32, size: u32) {
        let item = RawLeafItem {
            key: key.into(),
            data_offset: U32::new(offset),
            data_size: U32::new(size),
        };
        let position = item_position(index, LEAF_ITEM_SIZE).expect("item position");
        data[position..position + LEAF_ITEM_SIZE].copy_from_slice(item.as_bytes());
    }

    fn node_pointer(data: &mut [u8], index: usize, key: DiskKey, logical: u64, generation: u64) {
        let pointer = RawNodePointer {
            key: key.into(),
            logical: U64::new(logical),
            generation: U64::new(generation),
        };
        let position = item_position(index, NODE_POINTER_SIZE).expect("pointer position");
        data[position..position + NODE_POINTER_SIZE].copy_from_slice(pointer.as_bytes());
    }

    fn checksum(data: &mut [u8]) {
        let digest = ChecksumType::Crc32c.compute(&data[32..]);
        data[..32].copy_from_slice(&digest);
    }

    #[test]
    fn parses_leaf_items_and_owned_data() {
        let logical = 0x20_0000;
        let mut data = alloc::vec![0_u8; NODE_SIZE];
        header(&mut data, logical, 2, 0);
        let first = DiskKey {
            object_id: 256,
            item_type: 1,
            offset: 0,
        };
        let second = DiskKey {
            object_id: 256,
            item_type: 108,
            offset: 0,
        };
        leaf_item(&mut data, 0, first, 3991, 4);
        leaf_item(&mut data, 1, second, 3988, 3);
        data[4092..4096].copy_from_slice(b"meta");
        data[4089..4092].copy_from_slice(b"abc");
        checksum(&mut data);

        let block = TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c, 4096)
            .expect("valid leaf");
        let TreeBlock::Leaf { items, .. } = block else {
            panic!("leaf expected");
        };
        assert_eq!(items[0].key, first);
        assert_eq!(items[0].data, b"meta");
        assert_eq!(items[1].key, second);
        assert_eq!(items[1].data, b"abc");
    }

    #[test]
    fn rejects_unsorted_leaf_keys() {
        let logical = 0x20_0000;
        let mut data = alloc::vec![0_u8; NODE_SIZE];
        header(&mut data, logical, 2, 0);
        let later = DiskKey {
            object_id: 300,
            item_type: 1,
            offset: 0,
        };
        let earlier = DiskKey {
            object_id: 200,
            item_type: 1,
            offset: 0,
        };
        leaf_item(&mut data, 0, later, 3994, 1);
        leaf_item(&mut data, 1, earlier, 3993, 1);
        checksum(&mut data);

        assert!(matches!(
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c, 4096),
            Err(BtrfsError::MalformedTreeBlock { .. })
        ));
    }

    #[test]
    fn checksum_covers_every_byte_after_header_checksum() {
        let logical = 0x20_0000;
        let mut data = alloc::vec![0_u8; NODE_SIZE];
        header(&mut data, logical, 0, 0);
        checksum(&mut data);
        data[NODE_SIZE - 1] ^= 1;

        assert!(matches!(
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c, 4096),
            Err(BtrfsError::InvalidChecksum { .. })
        ));
    }

    #[test]
    fn rejects_leaf_payload_holes_and_unwritten_blocks() {
        let logical = 0x20_0000;
        let mut data = alloc::vec![0_u8; NODE_SIZE];
        header(&mut data, logical, 1, 0);
        let key = DiskKey {
            object_id: 256,
            item_type: 1,
            offset: 0,
        };
        leaf_item(&mut data, 0, key, 3990, 4);
        checksum(&mut data);
        assert!(matches!(
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c, 4096),
            Err(BtrfsError::MalformedTreeBlock { .. })
        ));

        header(&mut data, logical, 0, 0);
        let header = RawTreeHeader::mut_from_bytes(&mut data[..HEADER_SIZE]).expect("tree header");
        header.flags = U64::new(0);
        checksum(&mut data);
        assert!(matches!(
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c, 4096),
            Err(BtrfsError::MalformedTreeBlock { .. })
        ));
    }

    #[test]
    fn rejects_unaligned_node_pointers() {
        let logical = 0x20_0000;
        let mut data = alloc::vec![0_u8; NODE_SIZE];
        header(&mut data, logical, 1, 1);
        let key = DiskKey {
            object_id: 256,
            item_type: 1,
            offset: 0,
        };
        node_pointer(&mut data, 0, key, 0x30_0001, 7);
        checksum(&mut data);

        assert!(matches!(
            TreeBlock::parse(&data, logical, 1, &UUID, ChecksumType::Crc32c, 4096),
            Err(BtrfsError::MalformedTreeBlock { .. })
        ));
    }
}
