//! Ordered keys used by every Btrfs tree.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U64, Unaligned};

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct RawDiskKey {
    pub(crate) object_id: U64<LE>,
    pub(crate) item_type: u8,
    pub(crate) offset: U64<LE>,
}

/// Serialized size of a Btrfs disk key.
pub const DISK_KEY_SIZE: usize = core::mem::size_of::<RawDiskKey>();

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
}

impl RawDiskKey {
    pub(crate) const fn to_disk_key(self) -> DiskKey {
        DiskKey {
            object_id: self.object_id.get(),
            item_type: self.item_type,
            offset: self.offset.get(),
        }
    }
}

impl From<DiskKey> for RawDiskKey {
    fn from(key: DiskKey) -> Self {
        Self {
            object_id: U64::new(key.object_id),
            item_type: key.item_type,
            offset: U64::new(key.offset),
        }
    }
}
