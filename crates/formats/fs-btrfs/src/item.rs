//! Typed metadata items stored in root and filesystem trees.

use alloc::vec::Vec;

use crate::bytes::{i64_at, slice, u16_at, u32_at, u64_at};
use crate::key::DiskKey;
use crate::{BtrfsError, Result};

pub(crate) const ROOT_TREE_OBJECT_ID: u64 = 1;
pub(crate) const CHUNK_TREE_OBJECT_ID: u64 = 3;
pub(crate) const FS_TREE_OBJECT_ID: u64 = 5;
pub(crate) const CHECKSUM_TREE_OBJECT_ID: u64 = 7;
pub(crate) const ROOT_TREE_DIR_OBJECT_ID: u64 = 6;
pub(crate) const FIRST_FREE_OBJECT_ID: u64 = 256;

pub(crate) const INODE_ITEM_KEY: u8 = 1;
pub(crate) const DIR_ITEM_KEY: u8 = 84;
pub(crate) const DIR_INDEX_KEY: u8 = 96;
pub(crate) const EXTENT_DATA_KEY: u8 = 108;
pub(crate) const EXTENT_CHECKSUM_KEY: u8 = 128;
pub(crate) const ROOT_ITEM_KEY: u8 = 132;
pub(crate) const EXTENT_CHECKSUM_OBJECT_ID: u64 = u64::MAX - 9;

const INODE_NO_DATA_SUM: u64 = 1;

const INODE_ITEM_SIZE: usize = 160;
const ROOT_ITEM_MINIMUM_SIZE: usize = 239;
const DIR_ITEM_HEADER_SIZE: usize = 30;
const FILE_EXTENT_INLINE_HEADER_SIZE: usize = 21;
const FILE_EXTENT_REGULAR_SIZE: usize = 53;

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

    fn parse(data: &[u8], offset: usize, key: DiskKey) -> Result<Self> {
        let seconds = i64_at(data, offset).map_err(|_| malformed(key))?;
        let nanoseconds = u32_at(data, offset + 8).map_err(|_| malformed(key))?;
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
    pub(crate) fn parse(key: DiskKey, data: &[u8]) -> Result<Self> {
        if data.len() < INODE_ITEM_SIZE {
            return Err(malformed(key));
        }
        Ok(Self {
            generation: u64_at(data, 0)?,
            size: u64_at(data, 16)?,
            allocated_bytes: u64_at(data, 24)?,
            link_count: u32_at(data, 40)?,
            user_id: u32_at(data, 44)?,
            group_id: u32_at(data, 48)?,
            mode: u32_at(data, 52)?,
            flags: u64_at(data, 64)?,
            accessed: BtrfsTimestamp::parse(data, 112, key)?,
            changed: BtrfsTimestamp::parse(data, 124, key)?,
            modified: BtrfsTimestamp::parse(data, 136, key)?,
            created: BtrfsTimestamp::parse(data, 148, key)?,
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
    pub(crate) generation: u64,
    pub(crate) logical: u64,
    pub(crate) flags: u64,
    pub(crate) level: u8,
}

impl RootItem {
    pub(crate) fn parse(key: DiskKey, data: &[u8]) -> Result<Self> {
        if data.len() < ROOT_ITEM_MINIMUM_SIZE {
            return Err(malformed(key));
        }
        let logical = u64_at(data, 176)?;
        let level = data[238];
        if logical == 0 || level >= 8 {
            return Err(malformed(key));
        }
        Ok(Self {
            generation: u64_at(data, 160)?,
            logical,
            flags: u64_at(data, 208)?,
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
    let mut entries = Vec::new();
    let mut position = 0_usize;
    while position < data.len() {
        let header_end = position
            .checked_add(DIR_ITEM_HEADER_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if header_end > data.len() {
            return Err(malformed(key));
        }
        let location = DiskKey::parse(slice(data, position, 17)?)?;
        let data_length = usize::from(u16_at(data, position + 25)?);
        let name_length = usize::from(u16_at(data, position + 27)?);
        let file_type =
            BtrfsFileType::from_dir_type(data[position + 29]).ok_or_else(|| malformed(key))?;
        let name_start = header_end;
        let data_start = name_start
            .checked_add(name_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let entry_end = data_start
            .checked_add(data_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if name_length == 0 || entry_end > data.len() {
            return Err(malformed(key));
        }
        entries.push(RawDirectoryEntry {
            location,
            trans_id: u64_at(data, position + 17)?,
            file_type,
            name: slice(data, name_start, name_length)?.to_vec(),
            data: slice(data, data_start, data_length)?.to_vec(),
        });
        position = entry_end;
    }
    Ok(entries)
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
    pub(crate) fn parse(key: DiskKey, data: &[u8]) -> Result<Self> {
        if data.len() < FILE_EXTENT_INLINE_HEADER_SIZE {
            return Err(malformed(key));
        }
        let compression = Compression::from_raw(data[16], key)?;
        let encryption = data[17];
        let other_encoding = u16_at(data, 18)?;
        if encryption != 0 || other_encoding != 0 {
            return Err(BtrfsError::UnsupportedExtentEncoding {
                compression: data[16],
                encryption,
                other_encoding,
            });
        }

        let kind = match data[20] {
            0 => ExtentKind::Inline,
            1 => ExtentKind::Regular,
            2 => ExtentKind::Preallocated,
            _ => return Err(malformed(key)),
        };
        let mut extent = Self {
            file_offset: key.offset,
            ram_bytes: u64_at(data, 8)?,
            compression,
            kind,
            inline_data: Vec::new(),
            disk_logical: 0,
            disk_bytes: 0,
            extent_offset: 0,
            logical_bytes: 0,
        };
        if kind == ExtentKind::Inline {
            extent.inline_data = data[FILE_EXTENT_INLINE_HEADER_SIZE..].to_vec();
            extent.logical_bytes = extent.ram_bytes;
            return Ok(extent);
        }
        if data.len() < FILE_EXTENT_REGULAR_SIZE {
            return Err(malformed(key));
        }
        extent.disk_logical = u64_at(data, 21)?;
        extent.disk_bytes = u64_at(data, 29)?;
        extent.extent_offset = u64_at(data, 37)?;
        extent.logical_bytes = u64_at(data, 45)?;
        Ok(extent)
    }
}

fn malformed(key: DiskKey) -> BtrfsError {
    BtrfsError::MalformedItem {
        object_id: key.object_id,
        item_type: key.item_type,
        offset: key.offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inode_parser_preserves_signed_timestamps() {
        let key = DiskKey::range_start(256, INODE_ITEM_KEY);
        let mut data = [0_u8; INODE_ITEM_SIZE];
        data[16..24].copy_from_slice(&123_u64.to_le_bytes());
        data[52..56].copy_from_slice(&0o100_644_u32.to_le_bytes());
        data[112..120].copy_from_slice(&(-1_i64).to_le_bytes());
        data[120..124].copy_from_slice(&999_999_999_u32.to_le_bytes());
        let inode = BtrfsInode::parse(key, &data).expect("inode");

        assert_eq!(inode.size(), 123);
        assert_eq!(inode.file_type(), BtrfsFileType::RegularFile);
        assert_eq!(inode.accessed().seconds(), -1);
        assert_eq!(inode.accessed().nanoseconds(), 999_999_999);
    }

    #[test]
    fn parses_colliding_directory_items_in_sequence() {
        let key = DiskKey::range_start(256, DIR_ITEM_KEY);
        let mut data = Vec::new();
        for (name, object_id) in [(b"one".as_slice(), 300_u64), (b"two".as_slice(), 301)] {
            data.extend_from_slice(&object_id.to_le_bytes());
            data.push(INODE_ITEM_KEY);
            data.extend_from_slice(&0_u64.to_le_bytes());
            data.extend_from_slice(&7_u64.to_le_bytes());
            data.extend_from_slice(&0_u16.to_le_bytes());
            data.extend_from_slice(&u16::try_from(name.len()).expect("short name").to_le_bytes());
            data.push(1);
            data.extend_from_slice(name);
        }
        let entries = parse_directory_entries(key, &data).expect("directory items");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].location.object_id, 300);
        assert_eq!(entries[0].name, b"one");
        assert_eq!(entries[1].location.object_id, 301);
        assert_eq!(entries[1].name, b"two");
    }

    #[test]
    fn inline_extent_data_starts_after_encoding_header() {
        let key = DiskKey {
            object_id: 300,
            item_type: EXTENT_DATA_KEY,
            offset: 4096,
        };
        let mut data = alloc::vec![0_u8; FILE_EXTENT_INLINE_HEADER_SIZE];
        data[8..16].copy_from_slice(&5_u64.to_le_bytes());
        data[20] = 0;
        data.extend_from_slice(b"hello");

        let extent = FileExtent::parse(key, &data).expect("inline extent");
        assert_eq!(extent.file_offset, 4096);
        assert_eq!(extent.ram_bytes, 5);
        assert_eq!(extent.inline_data, b"hello");
    }
}
