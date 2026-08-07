//! B-tree block headers, leaf items, and internal pointers.

use alloc::vec::Vec;

use crate::bytes::{array, slice, u32_at, u64_at};
use crate::checksum::ChecksumType;
use crate::key::{DISK_KEY_SIZE, DiskKey};
use crate::{BtrfsError, Result};

const HEADER_SIZE: usize = 101;
const LEAF_ITEM_SIZE: usize = 25;
const NODE_POINTER_SIZE: usize = 33;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TreeRoot {
    pub(crate) tree_id: u64,
    pub(crate) logical: u64,
    pub(crate) level: u8,
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
        if &array::<16>(data, 32)? != tree_uuid
            || u64_at(data, 48)? != logical
            || data[100] != expected_level
        {
            return Err(BtrfsError::MalformedTreeBlock { logical });
        }

        let generation = u64_at(data, 80)?;
        let owner = u64_at(data, 88)?;
        let item_count =
            usize::try_from(u32_at(data, 96)?).map_err(|_| BtrfsError::IntegerOverflow)?;
        if expected_level == 0 {
            Self::parse_leaf(data, logical, generation, owner, item_count)
        } else {
            Self::parse_node(data, logical, generation, owner, expected_level, item_count)
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

        let mut items = Vec::with_capacity(item_count);
        for index in 0..item_count {
            let position = item_position(index, LEAF_ITEM_SIZE)?;
            let key = DiskKey::parse(slice(data, position, DISK_KEY_SIZE)?)?;
            let relative_data_offset = usize::try_from(u32_at(data, position + 17)?)
                .map_err(|_| BtrfsError::IntegerOverflow)?;
            let data_offset = HEADER_SIZE
                .checked_add(relative_data_offset)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let data_size = usize::try_from(u32_at(data, position + 21)?)
                .map_err(|_| BtrfsError::IntegerOverflow)?;
            let item_end = data_offset
                .checked_add(data_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            if data_offset < table_size || item_end > data.len() {
                return Err(BtrfsError::MalformedTreeBlock { logical });
            }
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
            let pointer = NodePointer {
                key: DiskKey::parse(slice(data, position, DISK_KEY_SIZE)?)?,
                logical: u64_at(data, position + 17)?,
                generation: u64_at(data, position + 25)?,
            };
            if pointer.logical == 0 {
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

#[cfg(test)]
mod tests {
    use super::*;

    const NODE_SIZE: usize = 4096;
    const UUID: [u8; 16] = [0x5a; 16];

    fn key_bytes(key: DiskKey) -> [u8; DISK_KEY_SIZE] {
        let mut bytes = [0_u8; DISK_KEY_SIZE];
        bytes[..8].copy_from_slice(&key.object_id.to_le_bytes());
        bytes[8] = key.item_type;
        bytes[9..].copy_from_slice(&key.offset.to_le_bytes());
        bytes
    }

    fn header(data: &mut [u8], logical: u64, items: u32, level: u8) {
        data[32..48].copy_from_slice(&UUID);
        data[48..56].copy_from_slice(&logical.to_le_bytes());
        data[80..88].copy_from_slice(&7_u64.to_le_bytes());
        data[88..96].copy_from_slice(&5_u64.to_le_bytes());
        data[96..100].copy_from_slice(&items.to_le_bytes());
        data[100] = level;
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
        data[101..118].copy_from_slice(&key_bytes(first));
        data[118..122].copy_from_slice(&3991_u32.to_le_bytes());
        data[122..126].copy_from_slice(&4_u32.to_le_bytes());
        data[126..143].copy_from_slice(&key_bytes(second));
        data[143..147].copy_from_slice(&3988_u32.to_le_bytes());
        data[147..151].copy_from_slice(&3_u32.to_le_bytes());
        data[4092..4096].copy_from_slice(b"meta");
        data[4089..4092].copy_from_slice(b"abc");
        checksum(&mut data);

        let block =
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c).expect("valid leaf");
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
        data[101..118].copy_from_slice(&key_bytes(later));
        data[118..122].copy_from_slice(&3994_u32.to_le_bytes());
        data[122..126].copy_from_slice(&1_u32.to_le_bytes());
        data[126..143].copy_from_slice(&key_bytes(earlier));
        data[143..147].copy_from_slice(&3993_u32.to_le_bytes());
        data[147..151].copy_from_slice(&1_u32.to_le_bytes());
        checksum(&mut data);

        assert!(matches!(
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c),
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
            TreeBlock::parse(&data, logical, 0, &UUID, ChecksumType::Crc32c),
            Err(BtrfsError::InvalidChecksum { .. })
        ));
    }
}
