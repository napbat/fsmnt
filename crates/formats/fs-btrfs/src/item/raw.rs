//! Exact byte layouts for fixed-size Btrfs metadata records.

use crate::key::RawDiskKey;
use zerocopy::{
    FromBytes, I64, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned,
};

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawTimespec {
    pub(super) seconds: I64<LE>,
    pub(super) nanoseconds: U32<LE>,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawInodeItem {
    pub(super) generation: U64<LE>,
    pub(super) trans_id: U64<LE>,
    pub(super) size: U64<LE>,
    pub(super) allocated_bytes: U64<LE>,
    pub(super) _block_group: U64<LE>,
    pub(super) link_count: U32<LE>,
    pub(super) user_id: U32<LE>,
    pub(super) group_id: U32<LE>,
    pub(super) mode: U32<LE>,
    pub(super) _device: U64<LE>,
    pub(super) flags: U64<LE>,
    pub(super) _sequence: U64<LE>,
    pub(super) _reserved: [U64<LE>; 4],
    pub(super) accessed: RawTimespec,
    pub(super) changed: RawTimespec,
    pub(super) modified: RawTimespec,
    pub(super) created: RawTimespec,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawRootItemLegacy {
    pub(super) _inode: RawInodeItem,
    pub(super) generation: U64<LE>,
    pub(super) _root_directory_id: U64<LE>,
    pub(super) logical: U64<LE>,
    pub(super) _byte_limit: U64<LE>,
    pub(super) _bytes_used: U64<LE>,
    pub(super) last_snapshot: U64<LE>,
    pub(super) flags: U64<LE>,
    pub(super) _references: U32<LE>,
    pub(super) drop_progress: RawDiskKey,
    pub(super) drop_level: u8,
    pub(super) level: u8,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawRootItemExtension {
    pub(super) generation: U64<LE>,
    pub(super) _uuid: [u8; 16],
    pub(super) _parent_uuid: [u8; 16],
    pub(super) _received_uuid: [u8; 16],
    pub(super) _changed_transaction_id: U64<LE>,
    pub(super) _created_transaction_id: U64<LE>,
    pub(super) _sent_transaction_id: U64<LE>,
    pub(super) _received_transaction_id: U64<LE>,
    pub(super) _changed: RawTimespec,
    pub(super) _created: RawTimespec,
    pub(super) _sent: RawTimespec,
    pub(super) _received: RawTimespec,
    pub(super) _reserved: [U64<LE>; 8],
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawRootItem {
    pub(super) legacy: RawRootItemLegacy,
    pub(super) extension: RawRootItemExtension,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawDirectoryItemHeader {
    pub(super) location: RawDiskKey,
    pub(super) transaction_id: U64<LE>,
    pub(super) data_length: U16<LE>,
    pub(super) name_length: U16<LE>,
    pub(super) file_type: u8,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawFileExtentHeader {
    pub(super) _generation: U64<LE>,
    pub(super) ram_bytes: U64<LE>,
    pub(super) compression: u8,
    pub(super) encryption: u8,
    pub(super) other_encoding: U16<LE>,
    pub(super) kind: u8,
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(super) struct RawFileExtentRegular {
    pub(super) header: RawFileExtentHeader,
    pub(super) disk_logical: U64<LE>,
    pub(super) disk_bytes: U64<LE>,
    pub(super) extent_offset: U64<LE>,
    pub(super) logical_bytes: U64<LE>,
}

pub(super) const INODE_ITEM_SIZE: usize = core::mem::size_of::<RawInodeItem>();
pub(super) const ROOT_ITEM_LEGACY_SIZE: usize = core::mem::size_of::<RawRootItemLegacy>();
pub(super) const ROOT_ITEM_SIZE: usize = core::mem::size_of::<RawRootItem>();
pub(super) const DIR_ITEM_HEADER_SIZE: usize = core::mem::size_of::<RawDirectoryItemHeader>();
pub(super) const FILE_EXTENT_INLINE_HEADER_SIZE: usize =
    core::mem::size_of::<RawFileExtentHeader>();
pub(super) const FILE_EXTENT_REGULAR_SIZE: usize = core::mem::size_of::<RawFileExtentRegular>();

const _: [(); 12] = [(); core::mem::size_of::<RawTimespec>()];
const _: [(); 160] = [(); INODE_ITEM_SIZE];
const _: [(); 239] = [(); ROOT_ITEM_LEGACY_SIZE];
const _: [(); 200] = [(); core::mem::size_of::<RawRootItemExtension>()];
const _: [(); 439] = [(); ROOT_ITEM_SIZE];
const _: [(); 30] = [(); DIR_ITEM_HEADER_SIZE];
const _: [(); 21] = [(); FILE_EXTENT_INLINE_HEADER_SIZE];
const _: [(); 53] = [(); FILE_EXTENT_REGULAR_SIZE];
