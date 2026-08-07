//! Volume bootstrap, tree traversal, path lookup, and logical reads.

mod checksum;
mod device_discovery;
mod global_roots;
mod log;
mod mapping;
mod raid_stripe;
mod recovery;
mod remap;
mod subvolume;
mod validation;

use alloc::vec::Vec;

use crate::chunk::{CHUNK_ITEM_KEY, ChunkMapping, merge_chunk, parse_system_chunks};
use crate::item::{
    BtrfsFileType, BtrfsInode, DIR_INDEX_KEY, DIR_ITEM_KEY, FIRST_FREE_OBJECT_ID,
    FS_TREE_OBJECT_ID, INODE_ITEM_KEY, ROOT_ITEM_KEY, ROOT_TREE_DIR_OBJECT_ID, ROOT_TREE_OBJECT_ID,
    RawDirectoryEntry, RootItem, parse_directory_entries,
};
use crate::tree::{TreeBlock, TreeItem, TreeRoot};
use crate::{BtrfsDeviceSource, BtrfsError, BtrfsSuperblock, DiskKey, Result};
pub use device_discovery::BtrfsDeviceIdentity;
use fsmnt_parser_core::io::{Read, Seek};
use global_roots::{CachedRoot, GlobalRootState};
use log::LogOverlay;
pub use recovery::BtrfsRecovery;
use recovery::{BootstrapCandidate, bootstrap_candidates};
use validation::{
    should_replace_root, should_select_primary, validate_devices, validate_tree_identity,
};

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
/// [`Btrfs::new`] and [`Btrfs::from_devices`] validate every available
/// superblock mirror immediately and select the newest valid generation. Tree
/// and chunk metadata is loaded lazily by the first traversal operation, or
/// explicitly with [`Btrfs::initialize`].
pub struct Btrfs<R> {
    primary: Device<R>,
    additional: Vec<Device<R>>,
    tree_uuids: Vec<[u8; 16]>,
    chunks: Vec<ChunkMapping>,
    root_tree: Option<TreeRoot>,
    cached_roots: Vec<CachedRoot>,
    raid_stripe_root: Option<TreeRoot>,
    remap_root: Option<TreeRoot>,
    global_roots: GlobalRootState,
    log_overlay: LogOverlay,
    default_tree_id: u64,
    active_generation: u64,
    active_total_bytes: u64,
    recovery: Option<BtrfsRecovery>,
    initialized: bool,
}

impl<R: Read + Seek> Btrfs<R> {
    /// Open a single-device Btrfs volume and select its best superblock mirror.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when no valid superblock mirror is readable.
    pub fn new(reader: R) -> Result<Self> {
        Self::from_devices(alloc::vec![reader])
    }

    /// Open every raw member of one Btrfs filesystem.
    ///
    /// Device order is irrelevant. The member carrying the newest valid
    /// superblock supplies the authoritative roots. Supplied members must share
    /// an FSID and declared member count and have unique device IDs and UUIDs.
    /// Members may be omitted when every chunk needed by the requested read
    /// remains recoverable through its redundancy profile.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] for duplicate, foreign, unreadable, excessive, or
    /// structurally invalid device members. Initialization or a later read
    /// reports chunks that exceed the supplied members' redundancy.
    pub fn from_devices(readers: Vec<R>) -> Result<Self> {
        Self::from_device_sources(readers.into_iter().map(BtrfsDeviceSource::new).collect())
    }

    /// Open Btrfs members with explicit conventional or zoned source geometry.
    ///
    /// Device order is irrelevant. Each zoned member must include the sparse
    /// two-zone reports for every superblock log pair that fits on that
    /// member. Members are otherwise validated identically to
    /// [`Btrfs::from_devices`].
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] for invalid zone geometry, missing or malformed
    /// superblocks, duplicate or foreign members, and inconsistent device
    /// counts.
    pub fn from_device_sources(sources: Vec<BtrfsDeviceSource<R>>) -> Result<Self> {
        let mut devices = Vec::with_capacity(sources.len());
        for source in sources {
            let (mut reader, zoned) = source.into_parts();
            let superblock = if let Some(zoned) = zoned.as_ref() {
                crate::superblock::read_best_zoned_superblock(&mut reader, zoned)?
            } else {
                crate::superblock::read_best_superblock(&mut reader)?
            };
            devices.push(Device { reader, superblock });
        }

        if devices.is_empty() {
            return Err(BtrfsError::NoDevices);
        }
        let mut primary_index = 0;
        for index in 1..devices.len() {
            if should_select_primary(
                &devices[primary_index].superblock,
                &devices[index].superblock,
            ) {
                primary_index = index;
            }
        }
        let primary = devices.remove(primary_index);
        let additional = devices;
        validate_devices(&primary, &additional)?;
        let active_generation = primary.superblock.generation();
        let active_total_bytes = primary.superblock.total_bytes();
        let mut tree_uuids = Vec::with_capacity(additional.len().saturating_add(1));
        tree_uuids.push(*primary.superblock.tree_uuid());
        for device in &additional {
            let uuid = *device.superblock.tree_uuid();
            if !tree_uuids.contains(&uuid) {
                tree_uuids.push(uuid);
            }
        }

        Ok(Self {
            primary,
            additional,
            tree_uuids,
            chunks: Vec::new(),
            root_tree: None,
            cached_roots: Vec::new(),
            raid_stripe_root: None,
            remap_root: None,
            global_roots: GlobalRootState::default(),
            log_overlay: LogOverlay::default(),
            default_tree_id: FS_TREE_OBJECT_ID,
            active_generation,
            active_total_bytes,
            recovery: None,
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

        let candidates = bootstrap_candidates(self.superblock());
        let live = BootstrapCandidate::live(self.superblock());
        let mut first_error = None;
        for candidate in candidates {
            self.prepare_bootstrap(candidate);
            match self.initialize_from(candidate) {
                Ok(()) => {
                    self.initialized = true;
                    return Ok(());
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        self.prepare_bootstrap(live);
        Err(first_error.unwrap_or(BtrfsError::IntegerOverflow))
    }

    fn initialize_from(&mut self, candidate: BootstrapCandidate) -> Result<()> {
        self.load_chunk_mappings(candidate)?;
        self.validate_chunk_devices()?;

        self.root_tree = Some(candidate.root_tree);
        self.cached_roots.clear();
        self.cached_roots
            .push(CachedRoot::new(0, candidate.root_tree));
        self.validate_direct_remap_root()?;
        self.load_raid_stripe_root()?;
        self.log_overlay = if candidate.replay_log {
            self.read_log_overlay()?
        } else {
            LogOverlay::default()
        };
        let global_roots = self.load_global_root_state()?;
        self.global_roots = global_roots;

        self.default_tree_id = self.find_default_tree_id()?.unwrap_or(FS_TREE_OBJECT_ID);
        let default_root = self.lookup_tree_root(self.default_tree_id)?;
        self.inode_from_root(default_root, FIRST_FREE_OBJECT_ID)?;
        Ok(())
    }

    fn load_chunk_mappings(&mut self, candidate: BootstrapCandidate) -> Result<()> {
        self.chunks = parse_system_chunks(
            self.superblock().system_chunk_array(),
            self.superblock().sector_size(),
            self.superblock().incompat_flags(),
        )?;
        let chunk_items = self.collect_items_raw(
            candidate.chunk_tree,
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
        Ok(())
    }

    fn prepare_bootstrap(&mut self, candidate: BootstrapCandidate) {
        self.chunks.clear();
        self.root_tree = None;
        self.cached_roots.clear();
        self.raid_stripe_root = None;
        self.remap_root = match (
            self.superblock().remap_root(),
            self.superblock().remap_root_level(),
            self.superblock().remap_root_generation(),
        ) {
            (Some(logical), Some(level), Some(generation)) => Some(TreeRoot {
                tree_id: remap::REMAP_TREE_OBJECT_ID,
                logical,
                level,
                expected_generation: Some(generation),
            }),
            _ => None,
        };
        self.global_roots = GlobalRootState::default();
        self.log_overlay = LogOverlay::default();
        self.default_tree_id = FS_TREE_OBJECT_ID;
        self.active_generation = candidate.generation;
        self.active_total_bytes = candidate.total_bytes;
        self.recovery = candidate.recovery;
        self.initialized = false;
    }

    /// Validated metadata from the selected authoritative superblock mirror.
    #[must_use]
    pub const fn superblock(&self) -> &BtrfsSuperblock {
        &self.primary.superblock
    }

    /// Transaction generation currently exposed by tree traversal.
    ///
    /// This initially matches the selected superblock and changes to the
    /// historical transaction generation if initialization recovers through a
    /// root-backup record.
    #[must_use]
    pub const fn active_generation(&self) -> u64 {
        self.active_generation
    }

    /// Historical recovery selected during initialization, if any.
    #[must_use]
    pub const fn recovery(&self) -> Option<BtrfsRecovery> {
        self.recovery
    }

    pub(crate) const fn active_total_bytes(&self) -> u64 {
        self.active_total_bytes
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
        self.subvolume_root(self.default_tree_id)
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
        let root = self.root()?;
        self.resolve_path_from(root, components)
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
        let committed = self.collect_items_raw(root, start, end)?;
        self.log_overlay
            .overlay_items(root.tree_id, start, end, committed)
    }

    pub(super) fn collect_items_raw(
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

    pub(crate) fn logged_file_extents(
        &self,
        tree_id: u64,
        object_id: u64,
        request_start: u64,
        request_end: u64,
    ) -> Vec<TreeItem> {
        self.log_overlay
            .logged_extents(tree_id, object_id, request_start, request_end)
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

    pub(crate) fn find_predecessor(
        &mut self,
        root: TreeRoot,
        target: DiskKey,
    ) -> Result<Option<TreeItem>> {
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
        let apply_remap = expected_owner != remap::REMAP_TREE_OBJECT_ID;
        let replica_count = self.logical_replica_count(logical, apply_remap)?;
        let mut last_error = None;
        for replica in 0..replica_count {
            if let Err(error) =
                self.read_logical_exact_from_replica(logical, &mut data, replica, apply_remap)
            {
                last_error = Some(error);
                continue;
            }
            match TreeBlock::parse_with_uuids(
                &data,
                logical,
                level,
                &self.tree_uuids,
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

    fn validate_chunk_devices(&self) -> Result<()> {
        for chunk in &self.chunks {
            if !chunk.is_readable_with(|stripe| {
                self.device(stripe.device_id, &stripe.device_uuid).is_some()
            }) {
                return Err(BtrfsError::InsufficientDevicesForChunk {
                    logical: chunk.logical,
                });
            }
        }
        for device in &self.additional {
            if device.superblock.fsid() != self.primary.superblock.fsid()
                && !self.chunks.iter().any(|chunk| {
                    chunk.stripes.iter().any(|stripe| {
                        stripe.device_id == device.superblock.device_id()
                            && &stripe.device_uuid == device.superblock.device_uuid()
                    })
                })
            {
                return Err(BtrfsError::ForeignDevice);
            }
        }
        Ok(())
    }

    fn device(&self, device_id: u64, device_uuid: &[u8; 16]) -> Option<&Device<R>> {
        if self.primary.superblock.device_id() == device_id
            && self.primary.superblock.device_uuid() == device_uuid
        {
            return Some(&self.primary);
        }
        self.additional.iter().find(|device| {
            device.superblock.device_id() == device_id
                && device.superblock.device_uuid() == device_uuid
        })
    }

    pub(crate) fn lookup_tree_root(&mut self, tree_id: u64) -> Result<TreeRoot> {
        if let Some(root) = self
            .cached_roots
            .iter()
            .find(|cached| cached.root.tree_id == tree_id)
        {
            return Ok(root.root);
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
        let super_generation = self.active_generation;
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
        self.cached_roots
            .push(CachedRoot::new(root_item.key_offset, root));
        Ok(root)
    }

    pub(super) fn lookup_tree_root_exact(
        &mut self,
        tree_id: u64,
        key_offset: u64,
    ) -> Result<TreeRoot> {
        if let Some(cached) = self
            .cached_roots
            .iter()
            .find(|cached| cached.root.tree_id == tree_id && cached.key_offset == key_offset)
        {
            return Ok(cached.root);
        }
        let root_tree = self.root_tree.ok_or(BtrfsError::TreeRootNotFound {
            tree_id: ROOT_TREE_OBJECT_ID,
        })?;
        let key = DiskKey {
            object_id: tree_id,
            item_type: ROOT_ITEM_KEY,
            offset: key_offset,
        };
        let item = self
            .collect_items_raw(root_tree, key, key)?
            .into_iter()
            .next()
            .ok_or(BtrfsError::TreeRootNotFound { tree_id })?;
        let root_item = RootItem::parse(
            item.key,
            &item.data,
            self.superblock().sector_size(),
            self.active_generation,
        )?;
        let root = TreeRoot {
            tree_id,
            logical: root_item.logical,
            level: root_item.level,
            expected_generation: Some(root_item.generation),
        };
        self.cached_roots
            .push(CachedRoot::new(root_item.key_offset, root));
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
        BtrfsInode::parse(item.key, &item.data, self.active_generation)
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

#[cfg(test)]
#[path = "volume/tests.rs"]
mod tests;
