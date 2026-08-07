//! Volume bootstrap, tree traversal, path lookup, and logical reads.

use alloc::vec::Vec;

use crate::chunk::{CHUNK_ITEM_KEY, ChunkMapping, merge_chunk, parse_system_chunks};
use crate::item::{
    BtrfsFileType, BtrfsInode, CHECKSUM_TREE_OBJECT_ID, DIR_INDEX_KEY, DIR_ITEM_KEY,
    EXTENT_CHECKSUM_KEY, EXTENT_CHECKSUM_OBJECT_ID, FIRST_FREE_OBJECT_ID, FS_TREE_OBJECT_ID,
    INODE_ITEM_KEY, ROOT_ITEM_KEY, ROOT_TREE_DIR_OBJECT_ID, ROOT_TREE_OBJECT_ID, RawDirectoryEntry,
    RootItem, parse_directory_entries, valid_filesystem_tree_id,
};
use crate::tree::{TreeBlock, TreeItem, TreeRoot};
use crate::{BtrfsError, BtrfsSuperblock, DiskKey, Result};
use fsmnt_parser_core::io::{Read, Seek, SeekFrom};

struct Device<R> {
    reader: R,
    superblock: BtrfsSuperblock,
}

#[derive(Clone, Copy)]
struct TreeRange {
    owner: u64,
    start: DiskKey,
    end: DiskKey,
}

/// Stable identifier for an object in one Btrfs filesystem tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsEntry {
    tree_id: u64,
    object_id: u64,
    file_type: BtrfsFileType,
}

impl BtrfsEntry {
    /// Subvolume or filesystem-tree identifier.
    #[must_use]
    pub const fn tree_id(self) -> u64 {
        self.tree_id
    }

    /// Inode object identifier within the tree.
    #[must_use]
    pub const fn object_id(self) -> u64 {
        self.object_id
    }

    /// Kind recorded by the directory item.
    ///
    /// The canonical kind is available from [`Btrfs::inode`].
    #[must_use]
    pub const fn file_type(self) -> BtrfsFileType {
        self.file_type
    }
}

/// Named child returned by a Btrfs directory scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsDirEntry {
    name: Vec<u8>,
    entry: BtrfsEntry,
    trans_id: u64,
}

impl BtrfsDirEntry {
    /// Byte-exact filename.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Object referenced by this name.
    #[must_use]
    pub const fn entry(&self) -> BtrfsEntry {
        self.entry
    }

    /// Transaction that last updated the directory item.
    #[must_use]
    pub const fn trans_id(&self) -> u64 {
        self.trans_id
    }
}

/// Opened Btrfs volume backed by one or more seekable device readers.
///
/// [`Btrfs::new`] and [`Btrfs::from_devices`] validate all primary
/// superblocks immediately. Tree and chunk metadata is loaded lazily by the
/// first traversal operation, or explicitly with [`Btrfs::initialize`].
pub struct Btrfs<R> {
    primary: Device<R>,
    additional: Vec<Device<R>>,
    chunks: Vec<ChunkMapping>,
    root_tree: Option<TreeRoot>,
    cached_roots: Vec<TreeRoot>,
    default_tree_id: u64,
    initialized: bool,
}

impl<R: Read + Seek> Btrfs<R> {
    /// Open a single-device Btrfs volume and validate its primary superblock.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when the reader cannot reach the primary
    /// superblock or its identifying fields and geometry are invalid.
    pub fn new(reader: R) -> Result<Self> {
        Self::from_devices(alloc::vec![reader])
    }

    /// Open every raw member of one Btrfs filesystem.
    ///
    /// Device order is irrelevant. The member carrying the newest valid
    /// superblock supplies the authoritative roots. All members must share an
    /// FSID, declare the same member count, and have unique device IDs and
    /// UUIDs.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] for missing, duplicate, foreign, unreadable, or
    /// structurally invalid device members.
    pub fn from_devices(readers: Vec<R>) -> Result<Self> {
        let mut devices = Vec::with_capacity(readers.len());
        for mut reader in readers {
            reader.seek(SeekFrom::Start(
                crate::superblock::PRIMARY_SUPERBLOCK_OFFSET,
            ))?;
            let mut data = [0_u8; crate::superblock::SUPERBLOCK_SIZE];
            reader.read_exact(&mut data)?;
            devices.push(Device {
                reader,
                superblock: BtrfsSuperblock::from_primary_bytes(&data)?,
            });
        }

        if devices.is_empty() {
            return Err(BtrfsError::NoDevices);
        }
        let mut primary_index = 0;
        for index in 1..devices.len() {
            if devices[index].superblock.generation()
                > devices[primary_index].superblock.generation()
            {
                primary_index = index;
            }
        }
        let primary = devices.remove(primary_index);
        let additional = devices;
        validate_devices(&primary, &additional)?;

        Ok(Self {
            primary,
            additional,
            chunks: Vec::new(),
            root_tree: None,
            cached_roots: Vec::new(),
            default_tree_id: FS_TREE_OBJECT_ID,
            initialized: false,
        })
    }

    /// Load the chunk tree, root tree, and default subvolume.
    ///
    /// Calling this method more than once is harmless.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] if logical mapping, a tree block, a root item,
    /// or the default root inode is invalid.
    pub fn initialize(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }

        self.chunks = parse_system_chunks(
            self.superblock().system_chunk_array(),
            self.superblock().sector_size(),
            self.superblock().incompat_flags(),
        )?;
        let chunk_root = TreeRoot {
            tree_id: crate::item::CHUNK_TREE_OBJECT_ID,
            logical: self.superblock().chunk_root(),
            level: self.superblock().chunk_root_level(),
            expected_generation: Some(self.superblock().chunk_root_generation()),
        };
        let chunk_items = self.collect_items(
            chunk_root,
            DiskKey::range_start(256, CHUNK_ITEM_KEY),
            DiskKey::range_end(256, CHUNK_ITEM_KEY),
        )?;
        let sector_size = self.superblock().sector_size();
        let incompat_flags = self.superblock().incompat_flags();
        for item in chunk_items {
            let mapping =
                ChunkMapping::parse(item.key.offset, &item.data, sector_size, incompat_flags)?;
            merge_chunk(&mut self.chunks, mapping)?;
        }
        self.validate_chunk_devices()?;

        let root_tree = TreeRoot {
            tree_id: ROOT_TREE_OBJECT_ID,
            logical: self.superblock().root(),
            level: self.superblock().root_level(),
            expected_generation: Some(self.superblock().generation()),
        };
        self.root_tree = Some(root_tree);
        self.cached_roots.clear();
        self.cached_roots.push(root_tree);

        self.default_tree_id = self.find_default_tree_id()?.unwrap_or(FS_TREE_OBJECT_ID);
        let default_root = self.lookup_tree_root(self.default_tree_id)?;
        self.inode_from_root(default_root, FIRST_FREE_OBJECT_ID)?;
        self.initialized = true;
        Ok(())
    }

    /// Validated primary-superblock metadata.
    #[must_use]
    pub const fn superblock(&self) -> &BtrfsSuperblock {
        &self.primary.superblock
    }

    /// Shared access to the primary underlying device reader.
    #[must_use]
    pub const fn reader(&self) -> &R {
        &self.primary.reader
    }

    /// Mutable access to the primary underlying device reader.
    pub const fn reader_mut(&mut self) -> &mut R {
        &mut self.primary.reader
    }

    /// Consume the volume wrapper and return its primary reader.
    #[must_use]
    pub fn into_inner(self) -> R {
        self.primary.reader
    }

    /// Consume the volume wrapper and return every reader, primary first.
    #[must_use]
    pub fn into_readers(self) -> Vec<R> {
        let mut readers = Vec::with_capacity(self.additional.len().saturating_add(1));
        readers.push(self.primary.reader);
        readers.extend(self.additional.into_iter().map(|device| device.reader));
        readers
    }

    /// Root directory of the configured default subvolume.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] if volume initialization or the root inode fails.
    pub fn root(&mut self) -> Result<BtrfsEntry> {
        self.initialize()?;
        let entry = BtrfsEntry {
            tree_id: self.default_tree_id,
            object_id: FIRST_FREE_OBJECT_ID,
            file_type: BtrfsFileType::Directory,
        };
        let inode = self.inode(entry)?;
        if !inode.file_type().is_directory() {
            return Err(BtrfsError::NotADirectory);
        }
        Ok(entry)
    }

    /// Resolve one byte-exact child name within a directory.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotADirectory`] for a non-directory parent,
    /// [`BtrfsError::NotFound`] for an absent name, or a parsing/I/O error.
    pub fn lookup(&mut self, parent: BtrfsEntry, name: &[u8]) -> Result<BtrfsEntry> {
        self.read_dir(parent)?
            .into_iter()
            .find(|candidate| candidate.name == name)
            .map(|candidate| candidate.entry)
            .ok_or(BtrfsError::NotFound)
    }

    /// Resolve a sequence of byte-exact path components from the default root.
    ///
    /// # Errors
    ///
    /// Returns the first lookup, tree, or I/O error encountered.
    pub fn resolve_path<'component>(
        &mut self,
        components: impl IntoIterator<Item = &'component [u8]>,
    ) -> Result<BtrfsEntry> {
        let mut current = self.root()?;
        for component in components {
            current = self.lookup(current, component)?;
        }
        Ok(current)
    }

    /// Read canonical inode metadata.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotFound`] when the inode item is absent, or a
    /// tree/I/O error when it cannot be parsed.
    pub fn inode(&mut self, entry: BtrfsEntry) -> Result<BtrfsInode> {
        self.initialize()?;
        let root = self.lookup_tree_root(entry.tree_id)?;
        self.inode_from_root(root, entry.object_id)
    }

    /// Enumerate a directory in its stable on-disk index order.
    ///
    /// Subvolume directory entries are followed into their own tree and
    /// represented by that tree's root inode.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError::NotADirectory`] for a non-directory or the first
    /// tree, item, or I/O error encountered.
    pub fn read_dir(&mut self, directory: BtrfsEntry) -> Result<Vec<BtrfsDirEntry>> {
        self.initialize()?;
        if !self.inode(directory)?.file_type().is_directory() {
            return Err(BtrfsError::NotADirectory);
        }
        let root = self.lookup_tree_root(directory.tree_id)?;
        let items = self.collect_items(
            root,
            DiskKey::range_start(directory.object_id, DIR_INDEX_KEY),
            DiskKey::range_end(directory.object_id, DIR_INDEX_KEY),
        )?;
        let mut entries = Vec::new();
        for item in items {
            for raw in parse_directory_entries(item.key, &item.data)? {
                entries.push(self.resolve_directory_entry(directory.tree_id, raw)?);
            }
        }
        Ok(entries)
    }

    pub(crate) fn collect_items(
        &mut self,
        root: TreeRoot,
        start: DiskKey,
        end: DiskKey,
    ) -> Result<Vec<TreeItem>> {
        let mut items = Vec::new();
        let range = TreeRange {
            owner: root.tree_id,
            start,
            end,
        };
        self.collect_block(
            root.logical,
            root.level,
            range,
            root.expected_generation,
            None,
            &mut items,
        )?;
        Ok(items)
    }

    pub(crate) fn verify_data_checksums(&mut self, logical: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let sector_size = usize::try_from(self.superblock().sector_size())
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        if !logical.is_multiple_of(u64::from(self.superblock().sector_size()))
            || !data.len().is_multiple_of(sector_size)
        {
            return Err(BtrfsError::InvalidFileExtentRange);
        }
        let checksum_type = self.superblock().checksum_type();
        let checksum_size = checksum_type.size();
        let checksum_root = self.lookup_tree_root(CHECKSUM_TREE_OBJECT_ID)?;
        let last_byte = logical
            .checked_add(u64::try_from(data.len()).map_err(|_| BtrfsError::IntegerOverflow)?)
            .and_then(|end| end.checked_sub(1))
            .ok_or(BtrfsError::IntegerOverflow)?;
        let start_key = DiskKey {
            object_id: EXTENT_CHECKSUM_OBJECT_ID,
            item_type: EXTENT_CHECKSUM_KEY,
            offset: logical,
        };
        let end_key = DiskKey {
            object_id: EXTENT_CHECKSUM_OBJECT_ID,
            item_type: EXTENT_CHECKSUM_KEY,
            offset: last_byte,
        };
        let predecessor = self
            .find_predecessor(checksum_root, start_key)?
            .filter(|item| {
                item.key.object_id == EXTENT_CHECKSUM_OBJECT_ID
                    && item.key.item_type == EXTENT_CHECKSUM_KEY
            })
            .ok_or(BtrfsError::DataChecksumMissing { logical })?;
        let mut checksum_items = self.collect_items(checksum_root, predecessor.key, end_key)?;
        if checksum_items
            .first()
            .is_none_or(|item| item.key != predecessor.key)
        {
            checksum_items.insert(0, predecessor);
        }
        validate_checksum_items(
            &checksum_items,
            self.superblock().sector_size(),
            checksum_size,
        )?;

        for (sector_index, sector) in data.chunks_exact(sector_size).enumerate() {
            let sector_delta = sector_index
                .checked_mul(sector_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let sector_logical = logical
                .checked_add(u64::try_from(sector_delta).map_err(|_| BtrfsError::IntegerOverflow)?)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let checksum_item = checksum_items
                .iter()
                .rev()
                .find(|item| item.key.offset <= sector_logical)
                .ok_or(BtrfsError::DataChecksumMissing {
                    logical: sector_logical,
                })?;
            let item_delta = sector_logical - checksum_item.key.offset;
            if !item_delta.is_multiple_of(u64::from(self.superblock().sector_size())) {
                return Err(BtrfsError::DataChecksumMissing {
                    logical: sector_logical,
                });
            }
            let checksum_index =
                usize::try_from(item_delta / u64::from(self.superblock().sector_size()))
                    .map_err(|_| BtrfsError::IntegerOverflow)?;
            let checksum_offset = checksum_index
                .checked_mul(checksum_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let checksum_end = checksum_offset
                .checked_add(checksum_size)
                .ok_or(BtrfsError::IntegerOverflow)?;
            let expected = checksum_item
                .data
                .get(checksum_offset..checksum_end)
                .ok_or(BtrfsError::DataChecksumMissing {
                    logical: sector_logical,
                })?;
            if !checksum_type.verify(expected, sector) {
                return Err(BtrfsError::InvalidChecksum {
                    structure: "data sector",
                    logical: sector_logical,
                });
            }
        }
        Ok(())
    }

    fn collect_block(
        &mut self,
        logical: u64,
        level: u8,
        range: TreeRange,
        expected_generation: Option<u64>,
        expected_first_key: Option<DiskKey>,
        output: &mut Vec<TreeItem>,
    ) -> Result<()> {
        let block = self.read_tree_block(
            logical,
            level,
            range.owner,
            expected_generation,
            expected_first_key,
        )?;
        match block {
            TreeBlock::Leaf { items, .. } => {
                output.extend(
                    items
                        .into_iter()
                        .filter(|item| item.key >= range.start && item.key <= range.end),
                );
            }
            TreeBlock::Node { pointers, .. } => {
                for (index, pointer) in pointers.iter().enumerate() {
                    let next = pointers.get(index + 1).map(|next_pointer| next_pointer.key);
                    let overlaps = pointer.key <= range.end
                        && next.is_none_or(|next_key| next_key > range.start);
                    if overlaps {
                        self.collect_block(
                            pointer.logical,
                            level - 1,
                            range,
                            Some(pointer.generation),
                            Some(pointer.key),
                            output,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    fn find_predecessor(&mut self, root: TreeRoot, target: DiskKey) -> Result<Option<TreeItem>> {
        self.find_predecessor_block(
            root.tree_id,
            root.logical,
            root.level,
            target,
            root.expected_generation,
            None,
        )
    }

    fn find_predecessor_block(
        &mut self,
        expected_owner: u64,
        logical: u64,
        level: u8,
        target: DiskKey,
        expected_generation: Option<u64>,
        expected_first_key: Option<DiskKey>,
    ) -> Result<Option<TreeItem>> {
        let block = self.read_tree_block(
            logical,
            level,
            expected_owner,
            expected_generation,
            expected_first_key,
        )?;
        match block {
            TreeBlock::Leaf { items, .. } => Ok(items
                .into_iter()
                .take_while(|item| item.key <= target)
                .last()),
            TreeBlock::Node { pointers, .. } => {
                let pointer = pointers.iter().rev().find(|pointer| pointer.key <= target);
                match pointer {
                    Some(pointer) => self.find_predecessor_block(
                        expected_owner,
                        pointer.logical,
                        level - 1,
                        target,
                        Some(pointer.generation),
                        Some(pointer.key),
                    ),
                    None => Ok(None),
                }
            }
        }
    }

    fn read_tree_block(
        &mut self,
        logical: u64,
        level: u8,
        expected_owner: u64,
        expected_generation: Option<u64>,
        expected_first_key: Option<DiskKey>,
    ) -> Result<TreeBlock> {
        let node_size = usize::try_from(self.superblock().node_size())
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        let mut data = alloc::vec![0_u8; node_size];
        let replica_count = self.logical_replica_count(logical)?;
        let mut last_error = None;
        for replica in 0..replica_count {
            self.read_logical_exact_from_replica(logical, &mut data, replica)?;
            match TreeBlock::parse(
                &data,
                logical,
                level,
                self.superblock().tree_uuid(),
                self.superblock().checksum_type(),
                self.superblock().sector_size(),
            ) {
                Ok(block) => {
                    let (generation, owner) = match &block {
                        TreeBlock::Leaf {
                            generation, owner, ..
                        }
                        | TreeBlock::Node {
                            generation, owner, ..
                        } => (*generation, *owner),
                    };
                    match validate_tree_identity(
                        expected_owner,
                        expected_generation,
                        expected_first_key,
                        owner,
                        generation,
                        block.first_key(),
                        logical,
                    ) {
                        Ok(()) => return Ok(block),
                        Err(error) => last_error = Some(error),
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or(BtrfsError::MalformedTreeBlock { logical }))
    }

    pub(crate) fn logical_replica_count(&self, logical: u64) -> Result<usize> {
        let count = self
            .chunks
            .iter()
            .find(|chunk| chunk.contains(logical))
            .ok_or(BtrfsError::LogicalAddressUnmapped { logical })?
            .map(logical, 1)?
            .locations
            .len();
        if count == 0 {
            return Err(BtrfsError::LogicalAddressUnmapped { logical });
        }
        Ok(count)
    }

    pub(crate) fn read_logical_exact_from_replica(
        &mut self,
        mut logical: u64,
        mut output: &mut [u8],
        preferred_replica: usize,
    ) -> Result<()> {
        while !output.is_empty() {
            let segment = self
                .chunks
                .iter()
                .find(|chunk| chunk.contains(logical))
                .ok_or(BtrfsError::LogicalAddressUnmapped { logical })?
                .map(logical, output.len())?;
            if segment.length == 0 {
                return Err(BtrfsError::LogicalAddressUnmapped { logical });
            }
            let target = &mut output[..segment.length];
            let mut last_error = None;
            let mut succeeded = false;
            let location_count = segment.locations.len();
            if location_count == 0 {
                return Err(BtrfsError::LogicalAddressUnmapped { logical });
            }
            for relative_index in 0..location_count {
                let location_index = preferred_replica
                    .checked_add(relative_index)
                    .ok_or(BtrfsError::IntegerOverflow)?
                    % location_count;
                let location = segment.locations[location_index];
                match self.read_physical_exact(location.device_id, location.offset, target) {
                    Ok(()) => {
                        succeeded = true;
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if !succeeded {
                return Err(last_error.unwrap_or(BtrfsError::LogicalAddressUnmapped { logical }));
            }
            let consumed =
                u64::try_from(segment.length).map_err(|_| BtrfsError::IntegerOverflow)?;
            logical = logical
                .checked_add(consumed)
                .ok_or(BtrfsError::IntegerOverflow)?;
            output = &mut output[segment.length..];
        }
        Ok(())
    }

    fn read_physical_exact(
        &mut self,
        device_id: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        let reader = self
            .device_reader_mut(device_id)
            .ok_or(BtrfsError::MissingDevice { device_id })?;
        reader.seek(SeekFrom::Start(offset))?;
        reader.read_exact(output)?;
        Ok(())
    }

    fn device_reader_mut(&mut self, device_id: u64) -> Option<&mut R> {
        if self.primary.superblock.device_id() == device_id {
            return Some(&mut self.primary.reader);
        }
        self.additional
            .iter_mut()
            .find(|device| device.superblock.device_id() == device_id)
            .map(|device| &mut device.reader)
    }

    fn validate_chunk_devices(&self) -> Result<()> {
        for chunk in &self.chunks {
            for stripe in &chunk.stripes {
                let device = self
                    .device(stripe.device_id)
                    .ok_or(BtrfsError::MissingDevice {
                        device_id: stripe.device_id,
                    })?;
                if device.superblock.device_uuid() != &stripe.device_uuid {
                    return Err(BtrfsError::ForeignDevice);
                }
            }
        }
        Ok(())
    }

    fn device(&self, device_id: u64) -> Option<&Device<R>> {
        if self.primary.superblock.device_id() == device_id {
            return Some(&self.primary);
        }
        self.additional
            .iter()
            .find(|device| device.superblock.device_id() == device_id)
    }

    pub(crate) fn lookup_tree_root(&mut self, tree_id: u64) -> Result<TreeRoot> {
        if let Some(root) = self
            .cached_roots
            .iter()
            .find(|root| root.tree_id == tree_id)
        {
            return Ok(*root);
        }
        let root_tree = self.root_tree.ok_or(BtrfsError::TreeRootNotFound {
            tree_id: ROOT_TREE_OBJECT_ID,
        })?;
        let items = self.collect_items(
            root_tree,
            DiskKey::range_start(tree_id, ROOT_ITEM_KEY),
            DiskKey::range_end(tree_id, ROOT_ITEM_KEY),
        )?;
        let mut newest = None;
        let sector_size = self.superblock().sector_size();
        let super_generation = self.superblock().generation();
        for item in items {
            let candidate = RootItem::parse(item.key, &item.data, sector_size, super_generation)?;
            if should_replace_root(newest.as_ref(), &candidate) {
                newest = Some(candidate);
            }
        }
        let root_item = newest.ok_or(BtrfsError::TreeRootNotFound { tree_id })?;
        let root = TreeRoot {
            tree_id,
            logical: root_item.logical,
            level: root_item.level,
            expected_generation: Some(root_item.generation),
        };
        self.cached_roots.push(root);
        Ok(root)
    }

    fn inode_from_root(&mut self, root: TreeRoot, object_id: u64) -> Result<BtrfsInode> {
        let key = DiskKey {
            object_id,
            item_type: INODE_ITEM_KEY,
            offset: 0,
        };
        let item = self
            .collect_items(root, key, key)?
            .into_iter()
            .next()
            .ok_or(BtrfsError::NotFound)?;
        BtrfsInode::parse(item.key, &item.data, self.superblock().generation())
    }

    fn find_default_tree_id(&mut self) -> Result<Option<u64>> {
        let root_tree = self.root_tree.ok_or(BtrfsError::TreeRootNotFound {
            tree_id: ROOT_TREE_OBJECT_ID,
        })?;
        let items = self.collect_items(
            root_tree,
            DiskKey::range_start(ROOT_TREE_DIR_OBJECT_ID, DIR_ITEM_KEY),
            DiskKey::range_end(ROOT_TREE_DIR_OBJECT_ID, DIR_ITEM_KEY),
        )?;
        for item in items {
            for entry in parse_directory_entries(item.key, &item.data)? {
                if entry.name == b"default" && entry.location.item_type == ROOT_ITEM_KEY {
                    return Ok(Some(entry.location.object_id));
                }
            }
        }
        Ok(None)
    }

    fn resolve_directory_entry(
        &mut self,
        parent_tree_id: u64,
        raw: RawDirectoryEntry,
    ) -> Result<BtrfsDirEntry> {
        let entry = match raw.location.item_type {
            INODE_ITEM_KEY => BtrfsEntry {
                tree_id: parent_tree_id,
                object_id: raw.location.object_id,
                file_type: raw.file_type,
            },
            ROOT_ITEM_KEY => {
                self.lookup_tree_root(raw.location.object_id)?;
                BtrfsEntry {
                    tree_id: raw.location.object_id,
                    object_id: FIRST_FREE_OBJECT_ID,
                    file_type: BtrfsFileType::Directory,
                }
            }
            _ => {
                return Err(BtrfsError::MalformedItem {
                    object_id: raw.location.object_id,
                    item_type: raw.location.item_type,
                    offset: raw.location.offset,
                });
            }
        };
        Ok(BtrfsDirEntry {
            name: raw.name,
            entry,
            trans_id: raw.trans_id,
        })
    }
}

fn should_replace_root(current: Option<&RootItem>, candidate: &RootItem) -> bool {
    current.is_none_or(|root| candidate.key_offset > root.key_offset)
}

fn validate_devices<R>(primary: &Device<R>, additional: &[Device<R>]) -> Result<()> {
    let actual = additional.len().saturating_add(1);
    let actual_u64 = u64::try_from(actual).map_err(|_| BtrfsError::IntegerOverflow)?;
    if primary.superblock.num_devices() != actual_u64 {
        return Err(BtrfsError::DeviceCountMismatch {
            expected: primary.superblock.num_devices(),
            actual,
        });
    }
    for device in additional {
        if device.superblock.fsid() != primary.superblock.fsid()
            || device.superblock.num_devices() != primary.superblock.num_devices()
        {
            return Err(BtrfsError::ForeignDevice);
        }
    }
    let mut identities = Vec::with_capacity(actual);
    identities.push((
        primary.superblock.device_id(),
        *primary.superblock.device_uuid(),
    ));
    for device in additional {
        let identity = (
            device.superblock.device_id(),
            *device.superblock.device_uuid(),
        );
        if identities
            .iter()
            .any(|(device_id, uuid)| *device_id == identity.0 || *uuid == identity.1)
        {
            return Err(BtrfsError::DuplicateDevice {
                device_id: identity.0,
            });
        }
        identities.push(identity);
    }
    Ok(())
}

fn validate_tree_identity(
    expected_owner: u64,
    expected_generation: Option<u64>,
    expected_first_key: Option<DiskKey>,
    owner: u64,
    generation: u64,
    first_key: Option<DiskKey>,
    logical: u64,
) -> Result<()> {
    let owner_matches = if expected_first_key.is_none() {
        owner == expected_owner
    } else if valid_filesystem_tree_id(expected_owner) {
        valid_filesystem_tree_id(owner)
    } else {
        owner == expected_owner
    };
    if !owner_matches
        || expected_generation.is_some_and(|expected| expected != generation)
        || expected_first_key.is_some_and(|expected| Some(expected) != first_key)
    {
        return Err(BtrfsError::MalformedTreeBlock { logical });
    }
    Ok(())
}

fn validate_checksum_items(
    items: &[TreeItem],
    sector_size: u32,
    checksum_size: usize,
) -> Result<()> {
    if sector_size == 0 || checksum_size == 0 {
        return Err(BtrfsError::InvalidFileExtentRange);
    }
    let mut previous_end = None;
    for item in items {
        if item.key.object_id != EXTENT_CHECKSUM_OBJECT_ID
            || item.key.item_type != EXTENT_CHECKSUM_KEY
            || !item.key.offset.is_multiple_of(u64::from(sector_size))
            || item.data.is_empty()
            || !item.data.len().is_multiple_of(checksum_size)
        {
            return Err(malformed_item(item.key));
        }
        let checksum_count = item.data.len() / checksum_size;
        let covered_bytes = u64::try_from(checksum_count)
            .map_err(|_| BtrfsError::IntegerOverflow)?
            .checked_mul(u64::from(sector_size))
            .ok_or(BtrfsError::IntegerOverflow)?;
        let item_end = item
            .key
            .offset
            .checked_add(covered_bytes)
            .ok_or_else(|| malformed_item(item.key))?;
        if previous_end.is_some_and(|end| end > item.key.offset) {
            return Err(malformed_item(item.key));
        }
        previous_end = Some(item_end);
    }
    Ok(())
}

const fn malformed_item(key: DiskKey) -> BtrfsError {
    BtrfsError::MalformedItem {
        object_id: key.object_id,
        item_type: key.item_type,
        offset: key.offset,
    }
}

#[cfg(test)]
#[path = "volume/tests.rs"]
mod tests;
