//! Directory-item parsing and allocation-free hashed lookup.

use alloc::vec::Vec;

use zerocopy::FromBytes;

use super::raw::{DIR_ITEM_HEADER_SIZE, RawDirectoryItemHeader};
use super::{
    BtrfsFileType, DIR_INDEX_KEY, DIR_ITEM_KEY, MAX_NAME_LENGTH, malformed,
    valid_directory_location, valid_inode_object_id,
};
use crate::bytes::slice;
use crate::{BtrfsError, DiskKey, Result};

/// Parsed directory record retained by an actual directory listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RawDirectoryEntry {
    pub(crate) location: DiskKey,
    pub(crate) trans_id: u64,
    pub(crate) file_type: BtrfsFileType,
    pub(crate) name: Vec<u8>,
}

/// Allocation-free result of looking up one hashed directory name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryLookup {
    pub(crate) location: DiskKey,
    pub(crate) file_type: BtrfsFileType,
}

struct BorrowedDirectoryEntry<'a> {
    location: DiskKey,
    trans_id: u64,
    file_type: BtrfsFileType,
    name: &'a [u8],
}

/// Parse every record in one directory item for a full listing.
pub(crate) fn parse_directory_entries(key: DiskKey, data: &[u8]) -> Result<Vec<RawDirectoryEntry>> {
    validate_key(key)?;
    let mut entries = Vec::new();
    let mut position = 0;
    while position < data.len() {
        let (entry, next) = parse_entry(key, data, position)?;
        entries.push(RawDirectoryEntry {
            location: entry.location,
            trans_id: entry.trans_id,
            file_type: entry.file_type,
            name: entry.name.to_vec(),
        });
        position = next;
    }
    Ok(entries)
}

/// Find one byte-exact name inside its hashed directory item.
///
/// Only collision records preceding the match are parsed, and no filename
/// storage is allocated.
pub(crate) fn find_directory_entry(
    key: DiskKey,
    data: &[u8],
    name: &[u8],
) -> Result<Option<DirectoryLookup>> {
    validate_key(key)?;
    if key.item_type == DIR_ITEM_KEY && key.offset != name_hash(name) {
        return Ok(None);
    }
    let mut position = 0;
    while position < data.len() {
        let (entry, next) = parse_entry(key, data, position)?;
        if entry.name == name {
            return Ok(Some(DirectoryLookup {
                location: entry.location,
                file_type: entry.file_type,
            }));
        }
        position = next;
    }
    Ok(None)
}

/// Btrfs's CRC32C filename hash used as the `DIR_ITEM` key offset.
pub(crate) fn name_hash(name: &[u8]) -> u64 {
    u64::from(!crc32c::crc32c_append(1, name))
}

fn validate_key(key: DiskKey) -> Result<()> {
    if !valid_inode_object_id(key.object_id)
        || !matches!(key.item_type, DIR_ITEM_KEY | DIR_INDEX_KEY)
    {
        return Err(malformed(key));
    }
    Ok(())
}

fn parse_entry(
    key: DiskKey,
    data: &[u8],
    position: usize,
) -> Result<(BorrowedDirectoryEntry<'_>, usize)> {
    let header_end = position
        .checked_add(DIR_ITEM_HEADER_SIZE)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if header_end > data.len() {
        return Err(malformed(key));
    }
    let raw = RawDirectoryItemHeader::ref_from_bytes(slice(data, position, DIR_ITEM_HEADER_SIZE)?)
        .map_err(|_| malformed(key))?;
    let location = raw.location.to_disk_key();
    let data_length = usize::from(raw.data_length.get());
    let name_length = usize::from(raw.name_length.get());
    let file_type = BtrfsFileType::from_dir_type(raw.file_type)
        .filter(|file_type| *file_type != BtrfsFileType::Unknown)
        .ok_or_else(|| malformed(key))?;
    let data_start = header_end
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
    let name = slice(data, header_end, name_length)?;
    if key.item_type == DIR_ITEM_KEY && key.offset != name_hash(name) {
        return Err(malformed(key));
    }
    Ok((
        BorrowedDirectoryEntry {
            location,
            trans_id: raw.transaction_id.get(),
            file_type,
            name,
        },
        entry_end,
    ))
}
