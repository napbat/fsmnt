//! Typed metadata items stored in root and filesystem trees.

mod raw;

use alloc::vec::Vec;

use self::raw::{
    DIR_ITEM_HEADER_SIZE, FILE_EXTENT_INLINE_HEADER_SIZE, FILE_EXTENT_REGULAR_SIZE,
    INODE_ITEM_SIZE, ROOT_ITEM_LEGACY_SIZE, ROOT_ITEM_SIZE, RawDirectoryItemHeader,
    RawFileExtentHeader, RawFileExtentRegular, RawInodeItem, RawRootItem, RawRootItemLegacy,
    RawTimespec,
};
use crate::bytes::slice;
use crate::key::DiskKey;
use crate::{BtrfsError, Result};
use zerocopy::FromBytes;
#[cfg(any(test, feature = "fuzzing"))]
use zerocopy::IntoBytes;

pub(crate) const ROOT_TREE_OBJECT_ID: u64 = 1;
pub(crate) const CHUNK_TREE_OBJECT_ID: u64 = 3;
pub(crate) const FS_TREE_OBJECT_ID: u64 = 5;
pub(crate) const CHECKSUM_TREE_OBJECT_ID: u64 = 7;
pub(crate) const ROOT_TREE_DIR_OBJECT_ID: u64 = 6;
pub(crate) const FIRST_FREE_OBJECT_ID: u64 = 256;
const LAST_FREE_OBJECT_ID: u64 = u64::MAX - 255;
const FREE_INODE_OBJECT_ID: u64 = u64::MAX - 11;

pub(crate) const INODE_ITEM_KEY: u8 = 1;
pub(crate) const DIR_ITEM_KEY: u8 = 84;
pub(crate) const DIR_INDEX_KEY: u8 = 96;
pub(crate) const EXTENT_DATA_KEY: u8 = 108;
pub(crate) const EXTENT_CHECKSUM_KEY: u8 = 128;
pub(crate) const ROOT_ITEM_KEY: u8 = 132;
pub(crate) const EXTENT_CHECKSUM_OBJECT_ID: u64 = u64::MAX - 9;

const INODE_NO_DATA_SUM: u64 = 1;
const INODE_INCOMPAT_FLAG_MASK: u64 = 0x8000_0fff;
const MODE_TYPE_MASK: u32 = 0o170_000;
const MODE_VALID_MASK: u32 = MODE_TYPE_MASK | 0o7_777;
const MAX_NAME_LENGTH: usize = 255;
const MAX_TREE_LEVEL: u8 = 8;
const ROOT_FLAG_READ_ONLY: u64 = 1;
const ROOT_FLAG_DEAD: u64 = 1_u64 << 48;
const ROOT_FLAG_MASK: u64 = ROOT_FLAG_READ_ONLY | ROOT_FLAG_DEAD;

/// Btrfs timestamp with nanosecond precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsTimestamp {
    seconds: i64,
    nanoseconds: u32,
}

impl BtrfsTimestamp {
    /// Signed seconds from the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Fractional nanoseconds within the second.
    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }

    fn parse(raw: RawTimespec, key: DiskKey) -> Result<Self> {
        let seconds = raw.seconds.get();
        let nanoseconds = raw.nanoseconds.get();
        if nanoseconds >= 1_000_000_000 {
            return Err(malformed(key));
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }
}

/// Kind of inode or directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BtrfsFileType {
    /// The directory entry did not record a useful type.
    Unknown,
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Character device.
    CharacterDevice,
    /// Block device.
    BlockDevice,
    /// Named pipe.
    Fifo,
    /// Unix-domain socket.
    Socket,
    /// Symbolic link.
    SymbolicLink,
}

impl BtrfsFileType {
    pub(crate) const fn from_dir_type(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::RegularFile),
            2 => Some(Self::Directory),
            3 => Some(Self::CharacterDevice),
            4 => Some(Self::BlockDevice),
            5 => Some(Self::Fifo),
            6 => Some(Self::Socket),
            7 => Some(Self::SymbolicLink),
            _ => None,
        }
    }

    fn from_mode(mode: u32) -> Self {
        match mode & 0o170_000 {
            0o100_000 => Self::RegularFile,
            0o040_000 => Self::Directory,
            0o020_000 => Self::CharacterDevice,
            0o060_000 => Self::BlockDevice,
            0o010_000 => Self::Fifo,
            0o140_000 => Self::Socket,
            0o120_000 => Self::SymbolicLink,
            _ => Self::Unknown,
        }
    }

    /// Whether this kind represents a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory)
    }

    /// Whether this kind carries readable file bytes.
    #[must_use]
    pub const fn has_file_data(self) -> bool {
        matches!(self, Self::RegularFile | Self::SymbolicLink)
    }

    /// Whether this kind represents a symbolic link.
    #[must_use]
    pub const fn is_symbolic_link(self) -> bool {
        matches!(self, Self::SymbolicLink)
    }
}

/// Canonical inode metadata from a filesystem tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsInode {
    generation: u64,
    size: u64,
    allocated_bytes: u64,
    link_count: u32,
    user_id: u32,
    group_id: u32,
    mode: u32,
    flags: u64,
    accessed: BtrfsTimestamp,
    changed: BtrfsTimestamp,
    modified: BtrfsTimestamp,
    created: BtrfsTimestamp,
}

impl BtrfsInode {
    pub(crate) fn parse(key: DiskKey, data: &[u8], super_generation: u64) -> Result<Self> {
        if key.item_type != INODE_ITEM_KEY
            || !valid_inode_object_id(key.object_id)
            || key.offset != 0
            || data.len() != INODE_ITEM_SIZE
        {
            return Err(malformed(key));
        }
        let raw = RawInodeItem::ref_from_bytes(data).map_err(|_| malformed(key))?;
        let maximum_generation = super_generation.saturating_add(1);
        let generation = raw.generation.get();
        let trans_id = raw.trans_id.get();
        let link_count = raw.link_count.get();
        let mode = raw.mode.get();
        let flags = raw.flags.get();
        let file_type = BtrfsFileType::from_mode(mode);
        if generation > maximum_generation
            || trans_id > maximum_generation
            || mode & !MODE_VALID_MASK != 0
            || file_type == BtrfsFileType::Unknown
            || (file_type == BtrfsFileType::Directory && link_count > 1)
            || flags & u64::from(u32::MAX) & !INODE_INCOMPAT_FLAG_MASK != 0
        {
            return Err(malformed(key));
        }
        Ok(Self {
            generation,
            size: raw.size.get(),
            allocated_bytes: raw.allocated_bytes.get(),
            link_count,
            user_id: raw.user_id.get(),
            group_id: raw.group_id.get(),
            mode,
            flags,
            accessed: BtrfsTimestamp::parse(raw.accessed, key)?,
            changed: BtrfsTimestamp::parse(raw.changed, key)?,
            modified: BtrfsTimestamp::parse(raw.modified, key)?,
            created: BtrfsTimestamp::parse(raw.created, key)?,
        })
    }

    /// Transaction generation that created this inode version.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Logical length in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Number of physical bytes allocated to the inode.
    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes
    }

    /// Hard-link count.
    #[must_use]
    pub const fn link_count(&self) -> u32 {
        self.link_count
    }

    /// POSIX user identifier.
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }

    /// POSIX group identifier.
    #[must_use]
    pub const fn group_id(&self) -> u32 {
        self.group_id
    }

    /// POSIX mode including file-kind and permission bits.
    #[must_use]
    pub const fn mode(&self) -> u32 {
        self.mode
    }

    /// Filesystem-specific inode flags.
    #[must_use]
    pub const fn flags(&self) -> u64 {
        self.flags
    }

    /// Whether regular extents are covered by checksum-tree items.
    #[must_use]
    pub const fn has_data_checksums(&self) -> bool {
        self.flags & INODE_NO_DATA_SUM == 0
    }

    /// File kind derived from the mode bits.
    #[must_use]
    pub fn file_type(&self) -> BtrfsFileType {
        BtrfsFileType::from_mode(self.mode)
    }

    /// Last-access timestamp.
    #[must_use]
    pub const fn accessed(&self) -> BtrfsTimestamp {
        self.accessed
    }

    /// Last metadata-change timestamp.
    #[must_use]
    pub const fn changed(&self) -> BtrfsTimestamp {
        self.changed
    }

    /// Last content-modification timestamp.
    #[must_use]
    pub const fn modified(&self) -> BtrfsTimestamp {
        self.modified
    }

    /// Creation timestamp.
    #[must_use]
    pub const fn created(&self) -> BtrfsTimestamp {
        self.created
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RootItem {
    pub(crate) key_offset: u64,
    pub(crate) generation: u64,
    pub(crate) logical: u64,
    pub(crate) flags: u64,
    pub(crate) level: u8,
}

impl RootItem {
    pub(crate) fn parse(
        key: DiskKey,
        data: &[u8],
        sector_size: u32,
        super_generation: u64,
    ) -> Result<Self> {
        if key.item_type != ROOT_ITEM_KEY
            || key.object_id == 0
            || sector_size == 0
            || !matches!(data.len(), ROOT_ITEM_LEGACY_SIZE | ROOT_ITEM_SIZE)
        {
            return Err(malformed(key));
        }
        let raw = RawRootItemLegacy::ref_from_bytes(&data[..ROOT_ITEM_LEGACY_SIZE])
            .map_err(|_| malformed(key))?;
        let maximum_generation = super_generation.saturating_add(1);
        let generation = raw.generation.get();
        let logical = raw.logical.get();
        let last_snapshot = raw.last_snapshot.get();
        let flags = raw.flags.get();
        let drop_progress_object_id = raw.drop_progress.object_id.get();
        let drop_level = raw.drop_level;
        let level = raw.level;
        let generation_v2 = if data.len() == ROOT_ITEM_SIZE {
            RawRootItem::ref_from_bytes(data)
                .map_err(|_| malformed(key))?
                .extension
                .generation
                .get()
        } else {
            0
        };
        if generation > maximum_generation
            || generation_v2 > maximum_generation
            || last_snapshot > maximum_generation
            || logical == 0
            || !logical.is_multiple_of(u64::from(sector_size))
            || level >= MAX_TREE_LEVEL
            || drop_level >= MAX_TREE_LEVEL
            || (drop_progress_object_id != 0 && drop_level == 0)
            || flags & !ROOT_FLAG_MASK != 0
        {
            return Err(malformed(key));
        }
        Ok(Self {
            key_offset: key.offset,
            generation,
            logical,
            flags,
            level,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawDirectoryEntry {
    pub(crate) location: DiskKey,
    pub(crate) trans_id: u64,
    pub(crate) file_type: BtrfsFileType,
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

pub(crate) fn parse_directory_entries(key: DiskKey, data: &[u8]) -> Result<Vec<RawDirectoryEntry>> {
    if !valid_inode_object_id(key.object_id)
        || !matches!(key.item_type, DIR_ITEM_KEY | DIR_INDEX_KEY)
    {
        return Err(malformed(key));
    }
    let mut entries = Vec::new();
    let mut position = 0_usize;
    while position < data.len() {
        let header_end = position
            .checked_add(DIR_ITEM_HEADER_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if header_end > data.len() {
            return Err(malformed(key));
        }
        let raw =
            RawDirectoryItemHeader::ref_from_bytes(slice(data, position, DIR_ITEM_HEADER_SIZE)?)
                .map_err(|_| malformed(key))?;
        let location = raw.location.to_disk_key();
        let data_length = usize::from(raw.data_length.get());
        let name_length = usize::from(raw.name_length.get());
        let file_type = BtrfsFileType::from_dir_type(raw.file_type)
            .filter(|file_type| *file_type != BtrfsFileType::Unknown)
            .ok_or_else(|| malformed(key))?;
        let name_start = header_end;
        let data_start = name_start
            .checked_add(name_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let entry_end = data_start
            .checked_add(data_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if name_length == 0
            || name_length > MAX_NAME_LENGTH
            || data_length != 0
            || entry_end > data.len()
            || !valid_directory_location(location)
        {
            return Err(malformed(key));
        }
        let name = slice(data, name_start, name_length)?;
        if key.item_type == DIR_ITEM_KEY && key.offset != name_hash(name) {
            return Err(malformed(key));
        }
        entries.push(RawDirectoryEntry {
            location,
            trans_id: raw.transaction_id.get(),
            file_type,
            name: name.to_vec(),
            data: slice(data, data_start, data_length)?.to_vec(),
        });
        position = entry_end;
    }
    Ok(entries)
}

fn valid_directory_location(location: DiskKey) -> bool {
    match location.item_type {
        ROOT_ITEM_KEY => {
            valid_filesystem_tree_id(location.object_id) && location.offset == u64::MAX
        }
        INODE_ITEM_KEY | 0 => valid_inode_object_id(location.object_id) && location.offset == 0,
        _ => false,
    }
}

const fn valid_inode_object_id(object_id: u64) -> bool {
    object_id == ROOT_TREE_DIR_OBJECT_ID
        || object_id == FREE_INODE_OBJECT_ID
        || (object_id >= FIRST_FREE_OBJECT_ID && object_id <= LAST_FREE_OBJECT_ID)
}

pub(crate) const fn valid_filesystem_tree_id(object_id: u64) -> bool {
    object_id == FS_TREE_OBJECT_ID
        || (object_id >= FIRST_FREE_OBJECT_ID && object_id <= LAST_FREE_OBJECT_ID)
}

fn name_hash(name: &[u8]) -> u64 {
    u64::from(!crc32c::crc32c_append(1, name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Compression {
    None,
    Zlib,
    Lzo,
    Zstd,
}

impl Compression {
    fn from_raw(value: u8, key: DiskKey) -> Result<Self> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Zlib),
            2 => Ok(Self::Lzo),
            3 => Ok(Self::Zstd),
            _ => Err(malformed(key)),
        }
    }

    pub(crate) const fn raw(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Zlib => 1,
            Self::Lzo => 2,
            Self::Zstd => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExtentKind {
    Inline,
    Regular,
    Preallocated,
}

impl ExtentKind {
    const fn from_raw(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Inline),
            1 => Some(Self::Regular),
            2 => Some(Self::Preallocated),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileExtent {
    pub(crate) file_offset: u64,
    pub(crate) ram_bytes: u64,
    pub(crate) compression: Compression,
    pub(crate) kind: ExtentKind,
    pub(crate) inline_data: Vec<u8>,
    pub(crate) disk_logical: u64,
    pub(crate) disk_bytes: u64,
    pub(crate) extent_offset: u64,
    pub(crate) logical_bytes: u64,
}

impl FileExtent {
    pub(crate) fn parse(key: DiskKey, data: &[u8], sector_size: u32) -> Result<Self> {
        if key.item_type != EXTENT_DATA_KEY
            || !valid_inode_object_id(key.object_id)
            || sector_size == 0
            || !key.offset.is_multiple_of(u64::from(sector_size))
            || data.len() < FILE_EXTENT_INLINE_HEADER_SIZE
        {
            return Err(malformed(key));
        }
        let raw = RawFileExtentHeader::ref_from_bytes(&data[..FILE_EXTENT_INLINE_HEADER_SIZE])
            .map_err(|_| malformed(key))?;
        let compression = Compression::from_raw(raw.compression, key)?;
        let encryption = raw.encryption;
        let other_encoding = raw.other_encoding.get();
        if encryption != 0 || other_encoding != 0 {
            return Err(BtrfsError::UnsupportedExtentEncoding {
                compression: raw.compression,
                encryption,
                other_encoding,
            });
        }

        let kind = ExtentKind::from_raw(raw.kind).ok_or_else(|| malformed(key))?;
        let mut extent = Self {
            file_offset: key.offset,
            ram_bytes: raw.ram_bytes.get(),
            compression,
            kind,
            inline_data: Vec::new(),
            disk_logical: 0,
            disk_bytes: 0,
            extent_offset: 0,
            logical_bytes: 0,
        };
        if kind == ExtentKind::Inline {
            if key.offset != 0 {
                return Err(malformed(key));
            }
            if compression == Compression::None {
                let inline_length =
                    usize::try_from(extent.ram_bytes).map_err(|_| malformed(key))?;
                let expected_size = FILE_EXTENT_INLINE_HEADER_SIZE
                    .checked_add(inline_length)
                    .ok_or_else(|| malformed(key))?;
                if data.len() != expected_size {
                    return Err(malformed(key));
                }
            }
            extent.inline_data = data[FILE_EXTENT_INLINE_HEADER_SIZE..].to_vec();
            extent.logical_bytes = extent.ram_bytes;
            return Ok(extent);
        }
        if data.len() != FILE_EXTENT_REGULAR_SIZE {
            return Err(malformed(key));
        }
        let raw = RawFileExtentRegular::ref_from_bytes(data).map_err(|_| malformed(key))?;
        extent.disk_logical = raw.disk_logical.get();
        extent.disk_bytes = raw.disk_bytes.get();
        extent.extent_offset = raw.extent_offset.get();
        extent.logical_bytes = raw.logical_bytes.get();
        let sector_size = u64::from(sector_size);
        if [
            extent.ram_bytes,
            extent.disk_logical,
            extent.disk_bytes,
            extent.extent_offset,
            extent.logical_bytes,
        ]
        .into_iter()
        .any(|value| !value.is_multiple_of(sector_size))
            || key.offset.checked_add(extent.logical_bytes).is_none()
            || extent
                .extent_offset
                .checked_add(extent.logical_bytes)
                .is_none_or(|end| end > extent.ram_bytes)
        {
            return Err(malformed(key));
        }
        Ok(extent)
    }

    pub(crate) fn file_range_end(&self, sector_size: u32) -> Result<u64> {
        let sector_size = u64::from(sector_size);
        let length = if self.kind == ExtentKind::Inline {
            self.ram_bytes
                .checked_add(sector_size - 1)
                .ok_or(BtrfsError::IntegerOverflow)?
                / sector_size
                * sector_size
        } else {
            self.logical_bytes
        };
        self.file_offset
            .checked_add(length)
            .ok_or(BtrfsError::IntegerOverflow)
    }
}

fn malformed(key: DiskKey) -> BtrfsError {
    BtrfsError::MalformedItem {
        object_id: key.object_id,
        item_type: key.item_type,
        offset: key.offset,
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn canonical_inode() -> [u8; INODE_ITEM_SIZE] {
    let mut data = [0_u8; INODE_ITEM_SIZE];
    let raw = RawInodeItem::mut_from_bytes(&mut data)
        .expect("canonical inode has the exact on-disk size");
    raw.mode = zerocopy::U32::new(0o100_644);
    data
}

#[cfg(feature = "fuzzing")]
pub(crate) fn canonical_regular_extent() -> [u8; FILE_EXTENT_REGULAR_SIZE] {
    let mut data = [0_u8; FILE_EXTENT_REGULAR_SIZE];
    let raw = RawFileExtentRegular::mut_from_bytes(&mut data)
        .expect("canonical extent has the exact on-disk size");
    raw.header.ram_bytes = zerocopy::U64::new(4096);
    raw.header.kind = 1;
    raw.disk_logical = zerocopy::U64::new(8192);
    raw.disk_bytes = zerocopy::U64::new(4096);
    raw.logical_bytes = zerocopy::U64::new(4096);
    data
}

#[cfg(feature = "fuzzing")]
pub(crate) fn canonical_root() -> [u8; ROOT_ITEM_SIZE] {
    let mut data = [0_u8; ROOT_ITEM_SIZE];
    let raw =
        RawRootItem::mut_from_bytes(&mut data).expect("canonical root has the exact on-disk size");
    raw.legacy.generation = zerocopy::U64::new(1);
    raw.legacy.logical = zerocopy::U64::new(0x10_0000);
    raw.extension.generation = zerocopy::U64::new(1);
    data
}

#[cfg(feature = "fuzzing")]
pub(crate) fn canonical_directory(item_type: u8) -> (Vec<u8>, u64) {
    const NAME: &[u8] = b"entry";
    let key_offset = if item_type == DIR_ITEM_KEY {
        name_hash(NAME)
    } else {
        2
    };
    let raw = RawDirectoryItemHeader {
        location: DiskKey {
            object_id: FIRST_FREE_OBJECT_ID + 1,
            item_type: INODE_ITEM_KEY,
            offset: 0,
        }
        .into(),
        transaction_id: zerocopy::U64::new(1),
        data_length: zerocopy::U16::new(0),
        name_length: zerocopy::U16::new(
            u16::try_from(NAME.len()).expect("canonical directory name fits u16"),
        ),
        file_type: 1,
    };
    let mut data = Vec::with_capacity(DIR_ITEM_HEADER_SIZE + NAME.len());
    data.extend_from_slice(raw.as_bytes());
    data.extend_from_slice(NAME);
    (data, key_offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{I64, IntoBytes, U16, U32, U64};

    fn valid_inode_data() -> [u8; INODE_ITEM_SIZE] {
        let mut data = [0_u8; INODE_ITEM_SIZE];
        RawInodeItem::mut_from_bytes(&mut data)
            .expect("inode layout")
            .mode = U32::new(0o100_644);
        data
    }

    fn valid_regular_extent() -> [u8; FILE_EXTENT_REGULAR_SIZE] {
        let mut data = [0_u8; FILE_EXTENT_REGULAR_SIZE];
        let raw = RawFileExtentRegular::mut_from_bytes(&mut data).expect("extent layout");
        raw.header.ram_bytes = U64::new(4096);
        raw.header.kind = 1;
        raw.disk_logical = U64::new(8192);
        raw.disk_bytes = U64::new(4096);
        raw.logical_bytes = U64::new(4096);
        data
    }

    fn directory_item(name: &[u8], object_id: u64) -> Vec<u8> {
        let header = RawDirectoryItemHeader {
            location: DiskKey::range_start(object_id, INODE_ITEM_KEY).into(),
            transaction_id: U64::new(7),
            data_length: U16::new(0),
            name_length: U16::new(u16::try_from(name.len()).expect("short name")),
            file_type: 1,
        };
        let mut data = header.as_bytes().to_vec();
        data.extend_from_slice(name);
        data
    }

    #[test]
    fn inode_parser_preserves_signed_timestamps() {
        let key = DiskKey::range_start(256, INODE_ITEM_KEY);
        let mut data = valid_inode_data();
        let raw = RawInodeItem::mut_from_bytes(&mut data).expect("inode layout");
        raw.size = U64::new(123);
        raw.accessed.seconds = I64::new(-1);
        raw.accessed.nanoseconds = U32::new(999_999_999);
        let inode = BtrfsInode::parse(key, &data, 0).expect("inode");

        assert_eq!(inode.size(), 123);
        assert_eq!(inode.file_type(), BtrfsFileType::RegularFile);
        assert_eq!(inode.accessed().seconds(), -1);
        assert_eq!(inode.accessed().nanoseconds(), 999_999_999);
    }

    #[test]
    fn inode_parser_rejects_future_invalid_or_extended_items() {
        let key = DiskKey::range_start(256, INODE_ITEM_KEY);
        let mut data = valid_inode_data();

        RawInodeItem::mut_from_bytes(&mut data)
            .expect("inode layout")
            .generation = U64::new(2);
        assert!(BtrfsInode::parse(key, &data, 0).is_err());

        let raw = RawInodeItem::mut_from_bytes(&mut data).expect("inode layout");
        raw.generation = U64::new(0);
        raw.mode = U32::new(u32::MAX);
        assert!(BtrfsInode::parse(key, &data, 0).is_err());

        let mut extended = valid_inode_data().to_vec();
        extended.push(0);
        assert!(BtrfsInode::parse(key, &extended, 0).is_err());
    }

    #[test]
    fn parses_colliding_directory_items_in_sequence() {
        let key = DiskKey {
            object_id: 256,
            item_type: DIR_ITEM_KEY,
            offset: name_hash(b"one"),
        };
        let mut data = Vec::new();
        for object_id in [300_u64, 301] {
            data.extend_from_slice(&directory_item(b"one", object_id));
        }
        let entries = parse_directory_entries(key, &data).expect("directory items");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].location.object_id, 300);
        assert_eq!(entries[0].name, b"one");
        assert_eq!(entries[1].location.object_id, 301);
        assert_eq!(entries[1].name, b"one");
    }

    #[test]
    fn directory_items_validate_name_hash_type_and_lengths() {
        assert_eq!(name_hash(b"mouton"), 3_786_996_654);

        let key = DiskKey {
            object_id: 256,
            item_type: DIR_ITEM_KEY,
            offset: name_hash(b"name"),
        };
        let mut data = directory_item(b"name", 300);
        parse_directory_entries(key, &data).expect("valid directory item");

        let wrong_hash = DiskKey { offset: 0, ..key };
        assert!(parse_directory_entries(wrong_hash, &data).is_err());

        RawDirectoryItemHeader::mut_from_bytes(&mut data[..DIR_ITEM_HEADER_SIZE])
            .expect("directory item layout")
            .file_type = 0;
        assert!(parse_directory_entries(key, &data).is_err());
        let raw = RawDirectoryItemHeader::mut_from_bytes(&mut data[..DIR_ITEM_HEADER_SIZE])
            .expect("directory item layout");
        raw.file_type = 1;
        raw.data_length = U16::new(1);
        assert!(parse_directory_entries(key, &data).is_err());
    }

    #[test]
    fn inline_extent_data_starts_after_encoding_header() {
        let key = DiskKey {
            object_id: 300,
            item_type: EXTENT_DATA_KEY,
            offset: 0,
        };
        let header = RawFileExtentHeader {
            _generation: U64::new(0),
            ram_bytes: U64::new(5),
            compression: 0,
            encryption: 0,
            other_encoding: U16::new(0),
            kind: 0,
        };
        let mut data = header.as_bytes().to_vec();
        data.extend_from_slice(b"hello");

        let extent = FileExtent::parse(key, &data, 4096).expect("inline extent");
        assert_eq!(extent.file_offset, 0);
        assert_eq!(extent.ram_bytes, 5);
        assert_eq!(extent.inline_data, b"hello");
    }

    #[test]
    fn regular_extents_require_exact_aligned_bounded_fields() {
        let key = DiskKey {
            object_id: 300,
            item_type: EXTENT_DATA_KEY,
            offset: 0,
        };
        let data = valid_regular_extent();
        FileExtent::parse(key, &data, 4096).expect("valid regular extent");

        let mut extended = data.to_vec();
        extended.push(0);
        assert!(FileExtent::parse(key, &extended, 4096).is_err());

        let mut unaligned = data;
        RawFileExtentRegular::mut_from_bytes(&mut unaligned)
            .expect("extent layout")
            .disk_logical = U64::new(8193);
        assert!(FileExtent::parse(key, &unaligned, 4096).is_err());

        let mut out_of_range = data;
        RawFileExtentRegular::mut_from_bytes(&mut out_of_range)
            .expect("extent layout")
            .logical_bytes = U64::new(8192);
        assert!(FileExtent::parse(key, &out_of_range, 4096).is_err());
    }

    #[test]
    fn root_items_require_known_sizes_generations_and_geometry() {
        let key = DiskKey {
            object_id: FS_TREE_OBJECT_ID,
            item_type: ROOT_ITEM_KEY,
            offset: 0,
        };
        let mut data = [0_u8; ROOT_ITEM_SIZE];
        let raw = RawRootItem::mut_from_bytes(&mut data).expect("root item layout");
        raw.legacy.generation = U64::new(1);
        raw.legacy.logical = U64::new(4096);
        raw.extension.generation = U64::new(1);
        let root = RootItem::parse(key, &data, 4096, 1).expect("valid root item");
        assert_eq!(root.key_offset, 0);

        RawRootItem::mut_from_bytes(&mut data)
            .expect("root item layout")
            .legacy
            .logical = U64::new(4097);
        assert!(RootItem::parse(key, &data, 4096, 1).is_err());
        RawRootItem::mut_from_bytes(&mut data)
            .expect("root item layout")
            .legacy
            .logical = U64::new(4096);

        RawRootItem::mut_from_bytes(&mut data)
            .expect("root item layout")
            .legacy
            .flags = U64::new(2);
        assert!(RootItem::parse(key, &data, 4096, 1).is_err());
        assert!(RootItem::parse(key, &data[..ROOT_ITEM_LEGACY_SIZE - 1], 4096, 1).is_err());
    }
}
