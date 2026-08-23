//! Reader-backed QNX6 filesystem traversal.

mod directory;

use alloc::vec::Vec;
use fsmnt_parser_core::io::BlockCache;

use crate::inode::QNX6_INODE_SIZE;
use crate::io::{Read, Seek, SeekFrom};
use crate::superblock::{
    QNX6_BOOT_AREA_SIZE, QNX6_DATA_AREA_OFFSET, QNX6_MAX_LEVELS, QNX6_SUPERBLOCK_AREA_SIZE,
    QNX6_SUPERBLOCK_SIZE, QNX6_UNUSED_BLOCK,
};
use crate::tree::TreeDescriptor;
use crate::{QNX6_ROOT_INODE, Qnx6Error, Qnx6Inode, Qnx6Superblock, Result, SuperblockCopy};

/// Size of a fixed QNX6 directory record.
const DIRECTORY_ENTRY_SIZE: u64 = 0x20;

/// In-memory size of the same fixed directory record.
const DIRECTORY_ENTRY_BYTES: usize = 0x20;

/// Maximum inline filename length.
const SHORT_NAME_MAX: u8 = 27;

/// Marker stored in a directory record whose name lives in the long-name tree.
const LONG_NAME_MARKER: u8 = 0xff;

/// Maximum QNX6 filename length in bytes.
const LONG_NAME_MAX: u16 = 510;

#[derive(Clone, Copy)]
enum DirectoryRecordName<'record> {
    Short(&'record [u8]),
    Long { index: u32, stored_checksum: u32 },
}

#[derive(Clone, Copy)]
struct DirectoryRecord<'record> {
    inode: u32,
    name: DirectoryRecordName<'record>,
}

enum OwnedDirectoryRecordName {
    Short(Vec<u8>),
    Long { index: u32, stored_checksum: u32 },
}

struct DirectoryTombstone {
    offset: u64,
    name: OwnedDirectoryRecordName,
}

impl DirectoryTombstone {
    fn new(offset: u64, name: DirectoryRecordName<'_>) -> Result<Self> {
        let name = match name {
            DirectoryRecordName::Short(bytes) => {
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| Qnx6Error::AllocationFailed)?;
                owned.extend_from_slice(bytes);
                OwnedDirectoryRecordName::Short(owned)
            }
            DirectoryRecordName::Long {
                index,
                stored_checksum,
            } => OwnedDirectoryRecordName::Long {
                index,
                stored_checksum,
            },
        };
        Ok(Self { offset, name })
    }

    fn matches(&self, offset: u64, name: DirectoryRecordName<'_>) -> bool {
        if self.offset != offset {
            return false;
        }
        match (&self.name, name) {
            (OwnedDirectoryRecordName::Short(left), DirectoryRecordName::Short(right)) => {
                left == right
            }
            (
                OwnedDirectoryRecordName::Long {
                    index: left_index,
                    stored_checksum: left_checksum,
                },
                DirectoryRecordName::Long {
                    index: right_index,
                    stored_checksum: right_checksum,
                },
            ) => left_index == &right_index && left_checksum == &right_checksum,
            _ => false,
        }
    }
}

struct DirectoryListing {
    entries: Vec<Qnx6DirectoryEntry>,
    tombstones: Vec<DirectoryTombstone>,
}

/// A directory name and the inode to which it points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qnx6DirectoryEntry {
    inode: u32,
    name: Vec<u8>,
    long_name_index: Option<u32>,
    long_name_checksum_valid: Option<bool>,
    stored_long_name_checksum: Option<u32>,
    record_offset: u64,
    snapshot: SuperblockCopy,
    deleted: bool,
}

impl Qnx6DirectoryEntry {
    /// Inode number referenced by this name.
    #[must_use]
    pub const fn inode(&self) -> u32 {
        self.inode
    }

    /// Filename bytes, encoded as UTF-8 by conforming QNX6 volumes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Consume the entry and return its filename allocation.
    #[must_use]
    pub fn into_name(self) -> Vec<u8> {
        self.name
    }

    /// Index in the long-filename metadata file, for a non-inline name.
    #[must_use]
    pub const fn long_name_index(&self) -> Option<u32> {
        self.long_name_index
    }

    /// Whether a long name matched the checksum in its directory record.
    ///
    /// Inline names return `None`; a mismatch is reported without dropping
    /// the name so forensic callers can still traverse damaged media.
    #[must_use]
    pub const fn long_name_checksum_valid(&self) -> Option<bool> {
        self.long_name_checksum_valid
    }

    /// Whether this name was tombstoned in the newest snapshot and recovered
    /// from the other valid Power-Safe snapshot.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        self.deleted
    }

    fn matches_tombstone(&self, tombstone: &DirectoryTombstone) -> bool {
        let name = self.long_name_index.map_or_else(
            || DirectoryRecordName::Short(&self.name),
            |index| DirectoryRecordName::Long {
                index,
                stored_checksum: self.stored_long_name_checksum.unwrap_or_default(),
            },
        );
        tombstone.matches(self.record_offset, name)
    }
}

/// A mounted read-only view of the newest valid QNX6 snapshot.
pub struct Qnx6<R: Read + Seek> {
    reader: R,
    pointer_cache: Vec<BlockCache>,
    superblock: Qnx6Superblock,
    active_copy: SuperblockCopy,
    alternate: Option<(SuperblockCopy, Qnx6Superblock)>,
    primary_valid: bool,
    secondary_valid: bool,
    secondary_offset: u64,
    source_length: u64,
}

impl<R: Read + Seek> Qnx6<R> {
    /// Open a normal QNX6 Power-Safe volume.
    ///
    /// Both checksummed superblocks are considered. When both are valid,
    /// the one with the greater 64-bit serial number supplies every metadata
    /// root. A single surviving copy is sufficient for a read-only view.
    ///
    /// # Errors
    ///
    /// Returns an error when neither copy validates, valid copies disagree
    /// on immutable geometry, or the selected snapshot cannot produce a
    /// directory root inode.
    pub fn new(mut reader: R) -> Result<Self> {
        let source_length = reader.seek(SeekFrom::End(0))?;
        let primary = read_superblock(&mut reader, QNX6_BOOT_AREA_SIZE).ok();
        let secondary_offset = match &primary {
            Some(superblock) => superblock.secondary_offset()?,
            None => source_length
                .checked_sub(QNX6_SUPERBLOCK_AREA_SIZE)
                .ok_or(Qnx6Error::NoValidSuperblock)?,
        };
        let mut secondary = read_superblock(&mut reader, secondary_offset).ok();
        if primary.is_none()
            && secondary.as_ref().is_some_and(|superblock| {
                superblock.secondary_offset().ok() != Some(secondary_offset)
            })
        {
            // With no primary geometry, the source end is only a candidate
            // location. A standalone valid record whose own block count
            // places it elsewhere is not this volume's trailing snapshot.
            secondary = None;
        }

        if let (Some(first), Some(second)) = (&primary, &secondary)
            && !first.immutable_geometry_matches(second)
        {
            return Err(Qnx6Error::ConflictingSuperblocks);
        }

        let primary_valid = primary.is_some();
        let secondary_valid = secondary.is_some();
        let (superblock, active_copy, alternate) = match (primary, secondary) {
            (Some(first), Some(second)) if first.serial() >= second.serial() => (
                first,
                SuperblockCopy::Primary,
                Some((SuperblockCopy::Secondary, second)),
            ),
            (Some(first), Some(second)) => (
                second,
                SuperblockCopy::Secondary,
                Some((SuperblockCopy::Primary, first)),
            ),
            (None, Some(second)) => (second, SuperblockCopy::Secondary, None),
            (Some(first), None) => (first, SuperblockCopy::Primary, None),
            (None, None) => return Err(Qnx6Error::NoValidSuperblock),
        };

        let block_size = usize::try_from(superblock.block_size())
            .map_err(|_| Qnx6Error::Overflow("pointer block size"))?;
        let pointer_cache = (0..QNX6_MAX_LEVELS)
            .map(|_| BlockCache::new(block_size))
            .collect();
        let mut filesystem = Self {
            reader,
            pointer_cache,
            superblock,
            active_copy,
            alternate,
            primary_valid,
            secondary_valid,
            secondary_offset,
            source_length,
        };
        if !filesystem.root_inode()?.file_type().is_directory() {
            return Err(Qnx6Error::RootNotDirectory);
        }
        Ok(filesystem)
    }

    /// Active, newest valid superblock snapshot.
    #[must_use]
    pub const fn superblock(&self) -> &Qnx6Superblock {
        &self.superblock
    }

    /// Which superblock copy supplied the active snapshot.
    #[must_use]
    pub const fn active_copy(&self) -> SuperblockCopy {
        self.active_copy
    }

    fn superblock_for(&self, snapshot: SuperblockCopy) -> Result<&Qnx6Superblock> {
        if snapshot == self.active_copy {
            return Ok(&self.superblock);
        }
        self.alternate
            .as_ref()
            .filter(|(copy, _)| *copy == snapshot)
            .map(|(_, superblock)| superblock)
            .ok_or(Qnx6Error::SnapshotUnavailable(snapshot))
    }

    fn recovery_snapshot(&self) -> Option<SuperblockCopy> {
        let (copy, alternate) = self.alternate.as_ref()?;
        (alternate.inode_root() != self.superblock.inode_root()
            || alternate.long_name_root() != self.superblock.long_name_root())
        .then_some(*copy)
    }

    /// Whether the first superblock copy passed magic, geometry, and CRC checks.
    #[must_use]
    pub const fn primary_copy_valid(&self) -> bool {
        self.primary_valid
    }

    /// Whether the trailing superblock copy passed magic, geometry, and CRC checks.
    #[must_use]
    pub const fn secondary_copy_valid(&self) -> bool {
        self.secondary_valid
    }

    /// Byte offset of the expected trailing superblock.
    #[must_use]
    pub const fn secondary_superblock_offset(&self) -> u64 {
        self.secondary_offset
    }

    /// Length reported by the underlying volume reader.
    #[must_use]
    pub const fn source_length(&self) -> u64 {
        self.source_length
    }

    /// Borrow the underlying byte source.
    #[must_use]
    pub const fn reader(&self) -> &R {
        &self.reader
    }

    /// Mutably borrow the underlying byte source.
    pub const fn reader_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume the parser and return its byte source.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Read the root inode.
    ///
    /// # Errors
    ///
    /// Returns an error when the active inode tree is unreadable or shorter
    /// than one inode record.
    pub fn root_inode(&mut self) -> Result<Qnx6Inode> {
        self.inode(QNX6_ROOT_INODE)
    }

    /// Read one inode-table record by its one-based inode number.
    ///
    /// # Errors
    ///
    /// Returns an error for an out-of-range number, inconsistent inode-tree
    /// length, invalid file-tree depth, block pointer, or I/O failure.
    pub fn inode(&mut self, number: u32) -> Result<Qnx6Inode> {
        self.inode_from_snapshot(self.active_copy, number)
    }

    /// Read the inode referenced by a directory entry from the snapshot that
    /// supplied that entry.
    ///
    /// This distinction matters for deleted names recovered from the previous
    /// valid Power-Safe snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the entry's snapshot is unavailable or its inode
    /// table record, tree geometry, block pointers, or source bytes are invalid.
    pub fn directory_entry_inode(&mut self, entry: &Qnx6DirectoryEntry) -> Result<Qnx6Inode> {
        self.inode_from_snapshot(entry.snapshot, entry.inode)
    }

    fn inode_from_snapshot(&mut self, snapshot: SuperblockCopy, number: u32) -> Result<Qnx6Inode> {
        let superblock = self.superblock_for(snapshot)?;
        if number == 0 || number > superblock.num_inodes() {
            return Err(Qnx6Error::InvalidInodeNumber {
                inode: number,
                maximum: superblock.num_inodes(),
            });
        }
        let offset = u64::from(number - 1)
            .checked_mul(
                u64::try_from(QNX6_INODE_SIZE)
                    .map_err(|_| Qnx6Error::Overflow("inode record size"))?,
            )
            .ok_or(Qnx6Error::Overflow("inode-table offset"))?;
        let end = offset
            .checked_add(
                u64::try_from(QNX6_INODE_SIZE)
                    .map_err(|_| Qnx6Error::Overflow("inode record end"))?,
            )
            .ok_or(Qnx6Error::Overflow("inode record end"))?;
        let descriptor = *superblock.inode_root().tree();
        let order = superblock.byte_order();
        if end > descriptor.size() {
            return Err(Qnx6Error::MetadataTooShort {
                tree: "inode",
                offset,
                end,
            });
        }
        let mut bytes = [0_u8; QNX6_INODE_SIZE];
        self.read_tree_exact(&descriptor, offset, &mut bytes)?;
        Qnx6Inode::from_bytes(number, snapshot, &bytes, order)
    }

    /// Read an entire non-directory object's data.
    ///
    /// # Errors
    ///
    /// Returns an error for a directory, an object too large for the process,
    /// allocation failure, invalid pointers, or source I/O failure.
    pub fn read_file(&mut self, inode: &Qnx6Inode) -> Result<Vec<u8>> {
        if inode.file_type().is_directory() {
            return Err(Qnx6Error::NotAFile(inode.number()));
        }
        let length =
            usize::try_from(inode.size()).map_err(|_| Qnx6Error::ObjectTooLarge(inode.size()))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Qnx6Error::AllocationFailed)?;
        bytes.resize(length, 0);
        self.read_file_range(inode, 0, &mut bytes)?;
        Ok(bytes)
    }

    /// Read a bounded byte range from a non-directory object.
    ///
    /// A range at or beyond EOF returns zero. Unallocated pointers within a
    /// sparse object return zero bytes for their covered range.
    ///
    /// # Errors
    ///
    /// Returns an error for a directory, invalid tree geometry or pointers,
    /// arithmetic overflow, or source I/O failure.
    pub fn read_file_range(
        &mut self,
        inode: &Qnx6Inode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if inode.file_type().is_directory() {
            return Err(Qnx6Error::NotAFile(inode.number()));
        }
        self.read_tree_range(inode.tree(), offset, buffer)
    }

    fn read_tree_exact(
        &mut self,
        descriptor: &TreeDescriptor,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<()> {
        let read = self.read_tree_range(descriptor, offset, buffer)?;
        if read != buffer.len() {
            return Err(Qnx6Error::MetadataTooShort {
                tree: "object",
                offset,
                end: offset.saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX)),
            });
        }
        Ok(())
    }

    fn read_tree_range(
        &mut self,
        descriptor: &TreeDescriptor,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        if buffer.is_empty() || offset >= descriptor.size() {
            return Ok(0);
        }
        let available = descriptor.size() - offset;
        let requested = u64::try_from(buffer.len()).unwrap_or(u64::MAX);
        let total = usize::try_from(available.min(requested))
            .map_err(|_| Qnx6Error::ObjectTooLarge(available))?;
        let block_size = u64::from(self.superblock.block_size());
        let mut filled = 0_usize;
        while filled < total {
            let position = offset
                .checked_add(
                    u64::try_from(filled).map_err(|_| Qnx6Error::Overflow("read position"))?,
                )
                .ok_or(Qnx6Error::Overflow("read position"))?;
            let logical_block = position / block_size;
            let within = position % block_size;
            let remaining_in_block = block_size - within;
            let remaining = total - filled;
            let chunk = usize::try_from(remaining_in_block)
                .unwrap_or(usize::MAX)
                .min(remaining);
            if let Some(block) = self.map_tree_block(descriptor, logical_block)? {
                let physical = self
                    .physical_block_offset(block)?
                    .checked_add(within)
                    .ok_or(Qnx6Error::Overflow("physical data offset"))?;
                self.reader.seek(SeekFrom::Start(physical))?;
                self.reader
                    .read_exact(&mut buffer[filled..filled + chunk])?;
            } else {
                buffer[filled..filled + chunk].fill(0);
            }
            filled += chunk;
        }
        Ok(filled)
    }

    fn map_tree_block(
        &mut self,
        descriptor: &TreeDescriptor,
        logical_block: u64,
    ) -> Result<Option<u32>> {
        let pointers_per_block = u64::from(self.superblock.block_size() / 4);
        let levels = descriptor.levels();
        let pointers = descriptor.pointers();
        let mut span = 1_u64;
        for _ in 0..levels {
            span = span
                .checked_mul(pointers_per_block)
                .ok_or(Qnx6Error::Overflow("tree pointer span"))?;
        }
        let direct = logical_block / span;
        let direct_index = usize::try_from(direct).unwrap_or(usize::MAX);
        if direct_index >= pointers.len() {
            return Err(Qnx6Error::TreeCapacityExceeded {
                block: logical_block,
                levels,
            });
        }
        let mut block = pointers[direct_index];
        let mut remainder = logical_block % span;
        let mut current_span = span;
        for depth in 0..levels {
            if block == QNX6_UNUSED_BLOCK {
                return Ok(None);
            }
            self.validate_block(block)?;
            current_span /= pointers_per_block;
            let index = remainder / current_span;
            remainder %= current_span;
            block = self.read_indirect_pointer(usize::from(depth), block, index)?;
        }
        if block == QNX6_UNUSED_BLOCK {
            return Ok(None);
        }
        self.validate_block(block)?;
        Ok(Some(block))
    }

    fn read_indirect_pointer(&mut self, depth: usize, block: u32, index: u64) -> Result<u32> {
        let physical = self.physical_block_offset(block)?;
        let pointer_offset = usize::try_from(
            index
                .checked_mul(4)
                .ok_or(Qnx6Error::Overflow("indirect pointer offset"))?,
        )
        .map_err(|_| Qnx6Error::Overflow("indirect pointer offset"))?;
        let order = self.superblock.byte_order();
        let cached = self
            .pointer_cache
            .get_mut(depth)
            .ok_or(Qnx6Error::Overflow("pointer cache depth"))?;
        let bytes = cached.read_block(&mut self.reader, physical)?;
        Ok(order.read_u32(bytes, pointer_offset))
    }

    fn validate_block(&self, block: u32) -> Result<()> {
        if block >= self.superblock.num_blocks() {
            return Err(Qnx6Error::InvalidBlockPointer {
                block,
                maximum: self.superblock.num_blocks(),
            });
        }
        Ok(())
    }

    fn physical_block_offset(&self, block: u32) -> Result<u64> {
        u64::from(block)
            .checked_mul(u64::from(self.superblock.block_size()))
            .and_then(|offset| offset.checked_add(QNX6_DATA_AREA_OFFSET))
            .ok_or(Qnx6Error::Overflow("physical block offset"))
    }
}

/// Read and fully validate one superblock record.
fn read_superblock<R: Read + Seek>(reader: &mut R, offset: u64) -> Result<Qnx6Superblock> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = [0_u8; QNX6_SUPERBLOCK_SIZE];
    reader.read_exact(&mut bytes)?;
    Qnx6Superblock::from_bytes(&bytes)
}
