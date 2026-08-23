//! QNX6 directory traversal and paired-snapshot tombstone recovery.

use alloc::vec;
use alloc::vec::Vec;

use super::{
    DIRECTORY_ENTRY_BYTES, DIRECTORY_ENTRY_SIZE, DirectoryListing, DirectoryRecord,
    DirectoryRecordName, DirectoryTombstone, LONG_NAME_MARKER, LONG_NAME_MAX, Qnx6,
    Qnx6DirectoryEntry, SHORT_NAME_MAX,
};
use crate::io::{Read, Seek};
use crate::tree::TreeDescriptor;
use crate::{Qnx6Error, Qnx6Inode, Result, SuperblockCopy};

impl<R: Read + Seek> Qnx6<R> {
    /// Resolve a slash-separated byte path from the root inode.
    ///
    /// Empty components and `.` are ignored. `..` is resolved through the
    /// directory's own entry, so root confinement follows the on-disk tree.
    ///
    /// # Errors
    ///
    /// Returns [`Qnx6Error::NotFound`] for an absent component and propagates
    /// directory, inode, pointer, and I/O errors.
    pub fn resolve_path(&mut self, path: &[u8]) -> Result<Qnx6Inode> {
        let mut current = self.root_inode()?;
        for component in path
            .split(|byte| *byte == b'/')
            .filter(|component| !component.is_empty() && *component != b".")
        {
            current = self.lookup(&current, component)?;
        }
        Ok(current)
    }

    /// Look up one exact, case-sensitive name in a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if `directory` is not a directory, the name is not
    /// present, or directory/inode data cannot be read.
    pub fn lookup(&mut self, directory: &Qnx6Inode, name: &[u8]) -> Result<Qnx6Inode> {
        let recover =
            directory.snapshot() == self.active_copy && self.recovery_snapshot().is_some();
        let (found, tombstones) = self.lookup_in_snapshot(directory, name, recover)?;
        if let Some(inode) = found {
            return Ok(inode);
        }
        if tombstones.is_empty() {
            return Err(Qnx6Error::NotFound);
        }
        let Some(alternate_directory) = self.alternate_directory(directory) else {
            return Err(Qnx6Error::NotFound);
        };
        self.lookup_recovered(&alternate_directory, name, &tombstones)
            .ok()
            .flatten()
            .ok_or(Qnx6Error::NotFound)
    }

    fn lookup_in_snapshot(
        &mut self,
        directory: &Qnx6Inode,
        name: &[u8],
        collect_tombstones: bool,
    ) -> Result<(Option<Qnx6Inode>, Vec<DirectoryTombstone>)> {
        let count = Self::directory_entry_count(directory)?;
        let descriptor = *directory.tree();
        let snapshot = directory.snapshot();
        let mut tombstones = Vec::new();
        for index in 0..count {
            let offset = index
                .checked_mul(DIRECTORY_ENTRY_SIZE)
                .ok_or(Qnx6Error::Overflow("directory entry offset"))?;
            let mut record = [0_u8; DIRECTORY_ENTRY_BYTES];
            self.read_tree_exact(&descriptor, offset, &mut record)?;
            let Some(parsed) = self.parse_directory_record(&record, offset, snapshot)? else {
                continue;
            };
            if parsed.inode == 0 {
                if collect_tombstones {
                    tombstones
                        .try_reserve(1)
                        .map_err(|_| Qnx6Error::AllocationFailed)?;
                    tombstones.push(DirectoryTombstone::new(offset, parsed.name)?);
                }
                continue;
            }
            if self.directory_name_matches(snapshot, parsed.name, name)? {
                return Ok((
                    Some(self.inode_from_snapshot(snapshot, parsed.inode)?),
                    tombstones,
                ));
            }
        }
        Ok((None, tombstones))
    }

    fn lookup_recovered(
        &mut self,
        directory: &Qnx6Inode,
        name: &[u8],
        tombstones: &[DirectoryTombstone],
    ) -> Result<Option<Qnx6Inode>> {
        let count = Self::directory_entry_count(directory)?;
        let descriptor = *directory.tree();
        let snapshot = directory.snapshot();
        for index in 0..count {
            let offset = index
                .checked_mul(DIRECTORY_ENTRY_SIZE)
                .ok_or(Qnx6Error::Overflow("directory entry offset"))?;
            let mut record = [0_u8; DIRECTORY_ENTRY_BYTES];
            self.read_tree_exact(&descriptor, offset, &mut record)?;
            let Some(parsed) = self.parse_directory_record(&record, offset, snapshot)? else {
                continue;
            };
            if parsed.inode == 0
                || !tombstones
                    .iter()
                    .any(|tombstone| tombstone.matches(offset, parsed.name))
            {
                continue;
            }
            if self.directory_name_matches(snapshot, parsed.name, name)? {
                return self.inode_from_snapshot(snapshot, parsed.inode).map(Some);
            }
        }
        Ok(None)
    }

    /// Read all visible name records in a directory, including `.` and `..`.
    ///
    /// When the newest snapshot contains a tombstone and the other valid
    /// snapshot still has the matching live record, the older name is
    /// recovered and [`Qnx6DirectoryEntry::is_deleted`] returns `true`.
    ///
    /// # Errors
    ///
    /// Returns an error when the inode is not a directory or when any fixed
    /// record, long-name block, pointer, or source read is invalid.
    pub fn read_directory(&mut self, inode: &Qnx6Inode) -> Result<Vec<Qnx6DirectoryEntry>> {
        let deleted = inode.snapshot() != self.active_copy;
        let recover = !deleted && self.recovery_snapshot().is_some();
        let DirectoryListing {
            mut entries,
            tombstones,
        } = self.read_directory_snapshot(inode, recover, deleted)?;
        if tombstones.is_empty() {
            return Ok(entries);
        }
        let Some(alternate_directory) = self.alternate_directory(inode) else {
            return Ok(entries);
        };
        let Ok(recovered) = self.read_directory_snapshot(&alternate_directory, false, true) else {
            return Ok(entries);
        };
        for entry in recovered.entries {
            if !tombstones
                .iter()
                .any(|tombstone| entry.matches_tombstone(tombstone))
                || entries.iter().any(|active| active.name == entry.name)
            {
                continue;
            }
            entries
                .try_reserve(1)
                .map_err(|_| Qnx6Error::AllocationFailed)?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn read_directory_snapshot(
        &mut self,
        inode: &Qnx6Inode,
        collect_tombstones: bool,
        deleted: bool,
    ) -> Result<DirectoryListing> {
        let count = Self::directory_entry_count(inode)?;
        let capacity =
            usize::try_from(count).map_err(|_| Qnx6Error::ObjectTooLarge(inode.size()))?;
        let mut entries = Vec::new();
        entries
            .try_reserve(capacity)
            .map_err(|_| Qnx6Error::AllocationFailed)?;
        let mut tombstones = Vec::new();
        let descriptor = *inode.tree();
        let snapshot = inode.snapshot();
        for index in 0..count {
            let offset = index
                .checked_mul(DIRECTORY_ENTRY_SIZE)
                .ok_or(Qnx6Error::Overflow("directory entry offset"))?;
            let mut record = [0_u8; DIRECTORY_ENTRY_BYTES];
            self.read_tree_exact(&descriptor, offset, &mut record)?;
            let Some(parsed) = self.parse_directory_record(&record, offset, snapshot)? else {
                continue;
            };
            if parsed.inode == 0 {
                if collect_tombstones {
                    tombstones
                        .try_reserve(1)
                        .map_err(|_| Qnx6Error::AllocationFailed)?;
                    tombstones.push(DirectoryTombstone::new(offset, parsed.name)?);
                }
                continue;
            }
            entries.push(self.directory_entry_from_record(parsed, offset, snapshot, deleted)?);
        }
        Ok(DirectoryListing {
            entries,
            tombstones,
        })
    }

    fn alternate_directory(&mut self, directory: &Qnx6Inode) -> Option<Qnx6Inode> {
        if directory.snapshot() != self.active_copy {
            return None;
        }
        let snapshot = self.recovery_snapshot()?;
        let alternate = self
            .inode_from_snapshot(snapshot, directory.number())
            .ok()?;
        (alternate.file_type().is_directory()
            && alternate.created_time() == directory.created_time())
        .then_some(alternate)
    }

    fn directory_name_matches(
        &mut self,
        snapshot: SuperblockCopy,
        record_name: DirectoryRecordName<'_>,
        name: &[u8],
    ) -> Result<bool> {
        match record_name {
            DirectoryRecordName::Short(candidate) => Ok(candidate == name),
            DirectoryRecordName::Long { index, .. } => {
                let (long_name_tree, name_offset, length) =
                    self.long_name_location(snapshot, index)?;
                let mut candidate = [0_u8; 510];
                self.read_metadata_exact(
                    &long_name_tree,
                    "long-filename",
                    name_offset,
                    &mut candidate[..length],
                )?;
                Ok(candidate[..length] == *name)
            }
        }
    }

    fn directory_entry_from_record(
        &mut self,
        parsed: DirectoryRecord<'_>,
        offset: u64,
        snapshot: SuperblockCopy,
        deleted: bool,
    ) -> Result<Qnx6DirectoryEntry> {
        let inode = parsed.inode;
        match parsed.name {
            DirectoryRecordName::Short(bytes) => {
                let mut name = Vec::new();
                name.try_reserve_exact(bytes.len())
                    .map_err(|_| Qnx6Error::AllocationFailed)?;
                name.extend_from_slice(bytes);
                Ok(Qnx6DirectoryEntry {
                    inode,
                    name,
                    long_name_index: None,
                    long_name_checksum_valid: None,
                    stored_long_name_checksum: None,
                    record_offset: offset,
                    snapshot,
                    deleted,
                })
            }
            DirectoryRecordName::Long {
                index,
                stored_checksum,
            } => {
                let name = self.read_long_name(snapshot, index)?;
                let checksum_valid = long_name_checksum(&name) == stored_checksum;
                Ok(Qnx6DirectoryEntry {
                    inode,
                    name,
                    long_name_index: Some(index),
                    long_name_checksum_valid: Some(checksum_valid),
                    stored_long_name_checksum: Some(stored_checksum),
                    record_offset: offset,
                    snapshot,
                    deleted,
                })
            }
        }
    }

    fn directory_entry_count(inode: &Qnx6Inode) -> Result<u64> {
        if !inode.file_type().is_directory() {
            return Err(Qnx6Error::NotADirectory(inode.number()));
        }
        if !inode.size().is_multiple_of(DIRECTORY_ENTRY_SIZE) {
            return Err(Qnx6Error::InvalidDirectoryEntry {
                offset: inode.size() - inode.size() % DIRECTORY_ENTRY_SIZE,
                reason: "directory size is not a multiple of 32 bytes",
            });
        }
        Ok(inode.size() / DIRECTORY_ENTRY_SIZE)
    }

    fn parse_directory_record<'record>(
        &self,
        record: &'record [u8; DIRECTORY_ENTRY_BYTES],
        offset: u64,
        snapshot: SuperblockCopy,
    ) -> Result<Option<DirectoryRecord<'record>>> {
        let superblock = self.superblock_for(snapshot)?;
        let order = superblock.byte_order();
        let inode = order.read_u32(record, 0);
        let size = record[4];
        if size == 0 {
            return Ok(None);
        }
        if inode > superblock.num_inodes() {
            return Err(Qnx6Error::InvalidDirectoryEntry {
                offset,
                reason: "inode number exceeds the superblock inode count",
            });
        }
        let name = if size <= SHORT_NAME_MAX {
            let end = 5 + usize::from(size);
            DirectoryRecordName::Short(&record[5..end])
        } else if size == LONG_NAME_MARKER {
            DirectoryRecordName::Long {
                index: order.read_u32(record, 8),
                stored_checksum: order.read_u32(record, 12),
            }
        } else if inode == 0 {
            return Ok(None);
        } else {
            return Err(Qnx6Error::InvalidDirectoryEntry {
                offset,
                reason: "name length is neither inline nor the long-name marker",
            });
        };
        Ok(Some(DirectoryRecord { inode, name }))
    }

    fn read_long_name(&mut self, snapshot: SuperblockCopy, index: u32) -> Result<Vec<u8>> {
        let (descriptor, offset, length) = self.long_name_location(snapshot, index)?;
        let mut name = vec![0_u8; length];
        self.read_metadata_exact(&descriptor, "long-filename", offset, &mut name)?;
        Ok(name)
    }

    fn long_name_location(
        &mut self,
        snapshot: SuperblockCopy,
        index: u32,
    ) -> Result<(TreeDescriptor, u64, usize)> {
        let superblock = self.superblock_for(snapshot)?;
        let block_size = u64::from(superblock.block_size());
        let offset = u64::from(index)
            .checked_mul(block_size)
            .ok_or(Qnx6Error::Overflow("long-filename offset"))?;
        let descriptor = *superblock.long_name_root().tree();
        let order = superblock.byte_order();
        let mut length_bytes = [0_u8; 2];
        self.read_metadata_exact(&descriptor, "long-filename", offset, &mut length_bytes)?;
        let length = order.read_u16(&length_bytes, 0);
        if length > LONG_NAME_MAX || u64::from(length) + 2 > block_size {
            return Err(Qnx6Error::InvalidLongName { index, length });
        }
        Ok((descriptor, offset + 2, usize::from(length)))
    }

    fn read_metadata_exact(
        &mut self,
        descriptor: &TreeDescriptor,
        tree: &'static str,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        let length =
            u64::try_from(buffer.len()).map_err(|_| Qnx6Error::ObjectTooLarge(u64::MAX))?;
        let end = offset
            .checked_add(length)
            .ok_or(Qnx6Error::Overflow("metadata read end"))?;
        if end > descriptor.size() {
            return Err(Qnx6Error::MetadataTooShort { tree, offset, end });
        }
        self.read_tree_exact(descriptor, offset, buffer)
    }
}

/// Checksum used by QNX6 long-name directory records.
fn long_name_checksum(name: &[u8]) -> u32 {
    let mut checksum = 0_u32;
    for &byte in name {
        let low_bit = checksum & 1;
        checksum = (checksum >> 1).wrapping_add(u32::from(byte));
        if low_bit != 0 {
            checksum ^= 0x8000_0000;
        }
    }
    checksum
}
