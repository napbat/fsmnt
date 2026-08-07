//! Ordered keys used by every Btrfs tree.

use crate::bytes::u64_at;
use crate::{BtrfsError, Result};

/// Serialized size of a Btrfs disk key.
pub const DISK_KEY_SIZE: usize = 17;

/// Key ordering one item within a Btrfs tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiskKey {
    /// Object identifier, such as an inode or tree ID.
    pub object_id: u64,
    /// Item type discriminator.
    pub item_type: u8,
    /// Type-specific offset.
    pub offset: u64,
}

impl DiskKey {
    /// Smallest key with the selected object ID and item type.
    #[must_use]
    pub const fn range_start(object_id: u64, item_type: u8) -> Self {
        Self {
            object_id,
            item_type,
            offset: 0,
        }
    }

    /// Largest key with the selected object ID and item type.
    #[must_use]
    pub const fn range_end(object_id: u64, item_type: u8) -> Self {
        Self {
            object_id,
            item_type,
            offset: u64::MAX,
        }
    }

    pub(crate) fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DISK_KEY_SIZE {
            return Err(BtrfsError::BufferTooSmall {
                expected: DISK_KEY_SIZE,
                actual: data.len(),
            });
        }
        Ok(Self {
            object_id: u64_at(data, 0)?,
            item_type: data[8],
            offset: u64_at(data, 9)?,
        })
    }
}
