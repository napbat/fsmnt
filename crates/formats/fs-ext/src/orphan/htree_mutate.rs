//! Htree (hash-tree) directory maintenance for fast-commit CREAT/LINK/
//! UNLINK replay.
//!
//! `htree.rs` is the read-side model for the on-disk dx_root/dx_node
//! structure; this module is the write side. It mirrors the kernel
//! `fs/ext4/namei.c` directory-index paths: `dx_probe` (descend the
//! tree recording the path), `ext4_dx_add_entry` (insert into a leaf,
//! splitting it when full), and `do_split` (redistribute a full leaf's
//! entries by hash).
//!
//! `HtreeSurgeon` deliberately is not a `&mut self` `Mutator` method:
//! a leaf split must append a directory-logical block, which means
//! appending an extent through `ExtentSurgeon`. `ExtentSurgeon::new`
//! borrows the `Mutator` mutably, so the htree code must hold the
//! `Mutator` as a field rather than be a method on it — the same
//! borrow structure `ExtentSurgeon` itself uses.

use alloc::vec;
use alloc::vec::Vec;

use crate::error::ExtError;
use crate::ext::Ext;
use crate::hash::dx_hash;
use crate::inode::InodeFlags;
use crate::io::{Read, Seek};
use crate::journal::fast_commit::extents::{ExtentSurgeon, ExtentSurgeryOutcome, RawExtent};
use crate::orphan::mutator::{CurrentDirInode, DirLeafAppendCtx};
use crate::orphan::{DirReplayOutcome, Mutator, MutatorError};

/// Result alias for htree surgery; reuses the mutator error type.
type HtreeResult<T> = core::result::Result<T, MutatorError>;

/// Offset of the on-disk `DxCountLimit` within a dx_root block.
const DX_ROOT_COUNT_LIMIT_OFFSET: usize = 0x20;
/// Offset of the on-disk `DxCountLimit` within an interior dx_node block.
const DX_NODE_COUNT_LIMIT_OFFSET: usize = 0x08;
/// Size of one on-disk `dx_entry` (hash u32 + block u32).
const DX_ENTRY_SIZE: usize = 8;

/// One level of a recorded dx-tree descent path.
#[derive(Clone, Debug)]
struct DxPathNode {
    /// Directory-logical block number of this node (0 == dx_root).
    logical_block: u32,
    /// Physical block backing `logical_block`.
    physical_block: u64,
    /// Full block bytes as read (scratch-aware).
    bytes: Vec<u8>,
    /// Byte offset of this node's `DxCountLimit`.
    count_limit_offset: usize,
    /// Index of the chosen `dx_entry` (0 == leftmost child).
    chosen_entry: usize,
}

impl DxPathNode {
    fn is_root(&self) -> bool {
        self.logical_block == 0
    }

    /// Live `DxCountLimit.count` (at byte +2 of the count_limit struct).
    fn count(&self) -> u16 {
        u16::from_le_bytes([
            self.bytes[self.count_limit_offset + 2],
            self.bytes[self.count_limit_offset + 3],
        ])
    }

    /// Maximum `DxCountLimit.limit` (at byte +0 of the count_limit struct).
    fn limit(&self) -> u16 {
        u16::from_le_bytes([
            self.bytes[self.count_limit_offset],
            self.bytes[self.count_limit_offset + 1],
        ])
    }
}

/// A fully-recorded dx-tree probe: every node visited plus the leaf.
#[derive(Debug)]
struct DxProbe {
    /// dx_root and any interior dx_nodes, root first.
    path: Vec<DxPathNode>,
    /// Directory-logical block number of the target leaf.
    leaf_logical: u32,
    /// Physical block backing the leaf.
    leaf_physical: u64,
    /// Half-MD4/TEA major hash of the lookup name.
    name_hash: u32,
}

/// Htree directory surgeon. Holds the `Ext`, the overlay reader, and the
/// `Mutator` so a leaf split can drive `ExtentSurgeon` for the new block.
pub(crate) struct HtreeSurgeon<'ext, 'op, T> {
    ext: &'ext Ext,
    fs: &'op mut T,
    mutator: &'op mut Mutator<'ext>,
}

impl<'ext, 'op, T: Read + Seek> HtreeSurgeon<'ext, 'op, T> {
    pub(crate) fn new(ext: &'ext Ext, fs: &'op mut T, mutator: &'op mut Mutator<'ext>) -> Self {
        Self { ext, fs, mutator }
    }

    /// Replay a CREAT or LINK against an htree-indexed parent. Mirrors
    /// `ext4_dx_add_entry`: probe to the target leaf, insert in place if
    /// it has room, otherwise split the leaf and insert.
    pub(crate) fn add_entry(
        &mut self,
        parent_inum: u32,
        child_inum: u32,
        name: &[u8],
        file_type: u8,
    ) -> HtreeResult<DirReplayOutcome> {
        let Some(dir) = self.prepare_parent(parent_inum, name)? else {
            return Ok(DirReplayOutcome::SkippedHtree);
        };
        let probe = self.dx_probe(parent_inum, &dir, name)?;

        let ctx = DirLeafAppendCtx {
            parent_inum,
            parent_generation: dir.generation(),
            child_inum,
            name,
            file_type,
        };
        if self
            .mutator
            .dir_leaf_append(self.fs, ctx, probe.leaf_physical)?
        {
            return Ok(DirReplayOutcome::Applied);
        }
        self.split_leaf_and_insert(parent_inum, &dir, &probe, ctx)
    }

    /// Replay an UNLINK against an htree-indexed parent. Mirrors
    /// `ext4_delete_entry` reached through `dx_probe`: locate the leaf,
    /// remove the entry, and prune the leaf's dx_entry if it empties.
    pub(crate) fn remove_entry(
        &mut self,
        parent_inum: u32,
        child_inum: u32,
        name: &[u8],
    ) -> HtreeResult<DirReplayOutcome> {
        let Some(dir) = self.prepare_parent(parent_inum, name)? else {
            return Ok(DirReplayOutcome::SkippedHtree);
        };
        let probe = self.dx_probe(parent_inum, &dir, name)?;

        if !self.mutator.dir_leaf_remove(
            self.fs,
            parent_inum,
            dir.generation(),
            child_inum,
            name,
            probe.leaf_physical,
        )? {
            return Ok(DirReplayOutcome::SkippedTargetMissing);
        }
        self.prune_empty_leaf(parent_inum, &dir, &probe)?;
        Ok(DirReplayOutcome::Applied)
    }

    /// Validate the parent inode. Returns `None` for an htree directory
    /// whose variant this maintainer does not support (casefold, encrypt,
    /// inline-data, or — defensively — a non-indexed parent): the caller
    /// maps `None` to `SkippedHtree`, preserving the pre-#116 conservative
    /// behavior (forward progress + a `HtreeNotMaintained` warning) rather
    /// than aborting replay. `Err` is reserved for a genuinely malformed
    /// record (an empty or over-long name).
    fn prepare_parent(
        &mut self,
        parent_inum: u32,
        name: &[u8],
    ) -> HtreeResult<Option<CurrentDirInode>> {
        if name.is_empty() || name.len() > 255 {
            return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
                inode: parent_inum,
                offset: 0,
            }));
        }
        let dir = self.mutator.current_dir_inode(self.fs, parent_inum)?;
        let flags = dir.flags();
        // Casefolded htree maintenance would need the folded name for
        // hashing and leaf comparison; encrypted and inline-data
        // directories are likewise out of scope. Skip rather than abort.
        if !flags.contains(InodeFlags::INDEX_FL)
            || flags.contains(InodeFlags::CASEFOLD_FL)
            || flags.contains(InodeFlags::ENCRYPT_FL)
            || flags.contains(InodeFlags::INLINE_DATA_FL)
        {
            return Ok(None);
        }
        Ok(Some(dir))
    }

    /// Descend the dx-tree recording every node, terminating at the leaf
    /// block whose hash range contains `name`. Mirrors `dx_probe`.
    fn dx_probe(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        name: &[u8],
    ) -> HtreeResult<DxProbe> {
        let root_bytes = self.read_dir_block(parent_inum, dir, 0)?;
        let header = parse_dx_root(&root_bytes, parent_inum)?;
        let name_hash = self.name_hash(parent_inum, header.hash_version, name)?;

        let mut path: Vec<DxPathNode> = Vec::new();
        let mut node_bytes = root_bytes;
        let mut count_limit_offset = DX_ROOT_COUNT_LIMIT_OFFSET;
        let mut logical_block = 0u32;
        let mut remaining_levels = header.indirect_levels;

        loop {
            let physical = self.resolve(parent_inum, dir, logical_block)?;
            // The dx_root navigates by the major hash; interior dx_node
            // levels navigate by the minor hash — matching the read
            // path (`htree.rs`: `find_target_block` then
            // `navigate_interior`). Using the major hash everywhere
            // would pick the wrong interior child on a multi-level
            // htree and desync the index from lookups.
            let nav_hash = if count_limit_offset == DX_ROOT_COUNT_LIMIT_OFFSET {
                name_hash.major
            } else {
                name_hash.minor
            };
            let (chosen_entry, child_block) =
                choose_child(&node_bytes, count_limit_offset, nav_hash, parent_inum)?;
            path.push(DxPathNode {
                logical_block,
                physical_block: physical,
                bytes: node_bytes,
                count_limit_offset,
                chosen_entry,
            });
            if remaining_levels == 0 {
                let leaf_physical = self.resolve(parent_inum, dir, child_block)?;
                return Ok(DxProbe {
                    path,
                    leaf_logical: child_block,
                    leaf_physical,
                    name_hash: name_hash.major,
                });
            }
            node_bytes = self.read_dir_block(parent_inum, dir, child_block)?;
            count_limit_offset = DX_NODE_COUNT_LIMIT_OFFSET;
            logical_block = child_block;
            remaining_levels -= 1;
        }
    }

    /// Split a full leaf in half by hash and insert the new entry, then
    /// register the new leaf's `dx_entry` in the parent dx node. Mirrors
    /// `do_split` followed by `ext4_dx_add_entry`'s index insertion.
    fn split_leaf_and_insert(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        probe: &DxProbe,
        ctx: DirLeafAppendCtx<'_>,
    ) -> HtreeResult<DirReplayOutcome> {
        let parent = path_deepest(probe);
        if usize::from(parent.count()) >= usize::from(parent.limit()) {
            // The parent dx node has no free dx_entry slot: a leaf split
            // here would need a dx-node split or a dx_root depth grow
            // (kernel `ext4_dx_add_entry`'s rare node-split branch). That
            // is out of scope for issue #116 — directories large enough
            // to fill a 4 KiB dx node hold ~500 leaves. Falling back to
            // `SkippedHtree` preserves forward progress: the caller still
            // applies the child link-count change and emits a single
            // `HtreeNotMaintained` warning, leaving the kernel to rebuild
            // the index lazily.
            return Ok(DirReplayOutcome::SkippedHtree);
        }

        let leaf_bytes = self.read_dir_block(parent_inum, dir, probe.leaf_logical)?;
        let split = self.plan_leaf_split(parent_inum, dir, &leaf_bytes)?;

        // `append_dir_block` returns the new block's logical *and*
        // physical number: the physical is known directly from the
        // allocation, so no resolve against the (now stale) snapshot.
        let (new_logical, new_physical) = self.append_dir_block(parent_inum, dir)?;

        let block_size = self.ext.block_size() as usize;
        let has_filetype = self.ext.has_filetype();
        let mut low_block = vec![0u8; block_size];
        let mut high_block = vec![0u8; block_size];
        write_leaf_entries(
            &mut low_block,
            &split.low_entries,
            has_filetype,
            parent_inum,
        )?;
        write_leaf_entries(
            &mut high_block,
            &split.high_entries,
            has_filetype,
            parent_inum,
        )?;

        let into_high = probe.name_hash >= split.boundary_hash;
        let target = if into_high {
            &mut high_block
        } else {
            &mut low_block
        };
        insert_into_leaf(target, ctx, self.ext.has_filetype(), parent_inum)?;

        let seed = self.ext.checksum_seed();
        finish_dir_block(seed, parent_inum, dir.generation(), &mut low_block);
        finish_dir_block(seed, parent_inum, dir.generation(), &mut high_block);

        self.mutator
            .write_dir_block(self.fs, parent_inum, probe.leaf_physical, &low_block)?;
        self.mutator
            .write_dir_block(self.fs, parent_inum, new_physical, &high_block)?;

        self.insert_dx_entry(parent_inum, dir, probe, split.boundary_hash, new_logical)?;
        Ok(DirReplayOutcome::Applied)
    }

    /// Hash every entry in a full leaf, sort by `(hash, on-disk order)`,
    /// and split near the count midpoint. Mirrors `dx_make_map` plus the
    /// `count/2` split in `do_split`, with one deviation: the split point
    /// is moved off any run of equal hashes so the boundary falls between
    /// two *distinct* hash values. The kernel instead keeps a `continued`
    /// run spanning two leaves and follows it during lookup; this crate's
    /// read path (`find_target_block` + a single `scan_leaf_block`) does
    /// not follow `continued` chains, so a clean hash partition keeps
    /// every name reachable. `boundary_hash` is then the new (high) leaf's
    /// minimum hash and the dx navigation `hash <= boundary` is exact.
    fn plan_leaf_split(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        leaf_bytes: &[u8],
    ) -> HtreeResult<LeafSplit> {
        let header = parse_dx_root(&self.read_dir_block(parent_inum, dir, 0)?, parent_inum)?;
        let mut entries = collect_leaf_entries(leaf_bytes, self.ext.has_filetype(), parent_inum)?;
        for entry in &mut entries {
            entry.hash = self
                .name_hash(parent_inum, header.hash_version, &entry.name)?
                .major;
        }
        entries.sort_by(|a, b| a.hash.cmp(&b.hash).then(a.order.cmp(&b.order)));
        if entries.len() < 2 {
            return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
                inode: parent_inum,
                offset: 0,
            }));
        }

        let split = clean_split_point(&entries).ok_or(MutatorError::Ext(
            ExtError::InvalidDirectoryEntry {
                inode: parent_inum,
                offset: 0,
            },
        ))?;
        let boundary_hash = entries[split].hash;
        let high_entries = entries.split_off(split);
        Ok(LeafSplit {
            low_entries: entries,
            high_entries,
            boundary_hash,
        })
    }

    /// Insert a new `dx_entry { boundary_hash, new_logical }` into the
    /// deepest probed dx node, keeping entries sorted by hash. Mirrors
    /// `dx_insert_block` + `ext4_handle_dirty_dx_node`.
    fn insert_dx_entry(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        probe: &DxProbe,
        boundary_hash: u32,
        new_logical: u32,
    ) -> HtreeResult<()> {
        let parent = path_deepest(probe);
        let mut bytes = parent.bytes.clone();
        let count = parent.count();
        let cl = parent.count_limit_offset;

        // Find the insertion slot: first entry with hash > boundary_hash.
        let mut slot = usize::from(count);
        for i in 1..usize::from(count) {
            let off = cl + i * DX_ENTRY_SIZE;
            let hash = u32::from_le_bytes(bytes[off..off + 4].try_into().expect("len 4"));
            if hash > boundary_hash {
                slot = i;
                break;
            }
        }

        let insert_off = cl + slot * DX_ENTRY_SIZE;
        let tail_src = cl + usize::from(count) * DX_ENTRY_SIZE;
        bytes.copy_within(insert_off..tail_src, insert_off + DX_ENTRY_SIZE);
        bytes[insert_off..insert_off + 4].copy_from_slice(&boundary_hash.to_le_bytes());
        bytes[insert_off + 4..insert_off + 8].copy_from_slice(&new_logical.to_le_bytes());

        let new_count = count + 1;
        bytes[cl + 2..cl + 4].copy_from_slice(&new_count.to_le_bytes());

        self.write_dx_node(parent_inum, dir, parent, &mut bytes, new_count)
    }

    /// Drop the leaf's `dx_entry` from its parent dx node when the leaf
    /// has no real entries left. Required by issue #116 ("prune dx entry
    /// if leaf becomes empty").
    fn prune_empty_leaf(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        probe: &DxProbe,
    ) -> HtreeResult<()> {
        let leaf_bytes = self.read_dir_block(parent_inum, dir, probe.leaf_logical)?;
        if leaf_has_real_entries(&leaf_bytes, self.ext.has_filetype(), parent_inum)? {
            return Ok(());
        }
        let parent = path_deepest(probe);
        // The leftmost child (entry 0) has no removable dx_entry; the
        // kernel leaves an emptied leftmost leaf in place.
        if parent.chosen_entry == 0 {
            return Ok(());
        }
        let count = parent.count();
        let cl = parent.count_limit_offset;
        let mut bytes = parent.bytes.clone();
        let remove_off = cl + parent.chosen_entry * DX_ENTRY_SIZE;
        let tail_src = cl + usize::from(count) * DX_ENTRY_SIZE;
        bytes.copy_within(remove_off + DX_ENTRY_SIZE..tail_src, remove_off);
        let new_count = count - 1;
        bytes[cl + 2..cl + 4].copy_from_slice(&new_count.to_le_bytes());
        bytes[tail_src - DX_ENTRY_SIZE..tail_src].fill(0);
        // Depth-shrink (collapsing a dx node back to a single leaf when
        // `new_count == 1`) is intentionally not performed: the kernel
        // shrinks the index lazily and a trailing emptied leaf block is
        // harmless. The dx_entry prune above is the part issue #116
        // requires.
        self.write_dx_node(parent_inum, dir, parent, &mut bytes, new_count)
    }

    /// Recompute the dx_root/dx_node CRC32C tail and stage the node bytes.
    /// `count` is the post-edit live entry count; `limit` is unchanged by
    /// an entry insert/remove (the dx_tail slot is fixed by `limit`).
    fn write_dx_node(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        node: &DxPathNode,
        bytes: &mut [u8],
        count: u16,
    ) -> HtreeResult<()> {
        let limit = node.limit();
        if let Some(seed) = self.ext.checksum_seed() {
            if node.is_root() {
                crate::checksum::compute_dx_root_csum(
                    seed,
                    parent_inum,
                    dir.generation(),
                    bytes,
                    count,
                    limit,
                );
            } else {
                crate::checksum::compute_dx_node_csum(
                    seed,
                    parent_inum,
                    dir.generation(),
                    bytes,
                    count,
                    limit,
                );
            }
        }
        self.mutator
            .write_dir_block(self.fs, parent_inum, node.physical_block, bytes)
    }

    /// Append one directory-logical block: allocate a metadata block,
    /// register the extent through `ExtentSurgeon`, and grow `i_size`.
    /// Returns `(new_logical_block, new_physical_block)`.
    fn append_dir_block(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
    ) -> HtreeResult<(u32, u64)> {
        let block_size = u64::from(self.ext.block_size());
        let dir_blocks = dir.size().div_ceil(block_size);
        let new_logical = u32::try_from(dir_blocks)
            .map_err(|_| MutatorError::Ext(ExtError::BlockOutOfRange { block: dir_blocks }))?;
        let new_physical = self.mutator.allocate_metadata_block(self.fs, parent_inum)?;

        let extent = RawExtent {
            ee_block: new_logical,
            ee_len: 1,
            ee_pblk: new_physical,
            unwritten: false,
        };
        let outcome = {
            let mut surgeon = ExtentSurgeon::new(self.ext, self.fs, self.mutator);
            surgeon
                .add_range(parent_inum, extent)
                .map_err(MutatorError::Ext)?
        };
        match outcome {
            ExtentSurgeryOutcome::Applied => {}
            _ => {
                return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: new_physical,
                }));
            }
        }

        let new_size = dir.size().checked_add(block_size).ok_or(MutatorError::Ext(
            ExtError::BlockOutOfRange { block: dir_blocks },
        ))?;
        self.mutator
            .patch_inode_scratch(self.fs, parent_inum, |inode| {
                inode[0x04..0x08].copy_from_slice(&(new_size as u32).to_le_bytes());
                inode[0x6C..0x70].copy_from_slice(&((new_size >> 32) as u32).to_le_bytes());
                Ok(())
            })?;
        Ok((new_logical, new_physical))
    }

    /// Compute the htree name hash (major + minor). Casefolded
    /// directories are already filtered out by `prepare_parent`, so the
    /// plaintext name is hashed directly; an unrecognized `hash_version`
    /// byte is corruption.
    fn name_hash(
        &self,
        parent_inum: u32,
        hash_version: u8,
        name: &[u8],
    ) -> HtreeResult<crate::hash::DxHash> {
        dx_hash(name, hash_version, self.ext.hash_seed()).ok_or(MutatorError::Ext(
            ExtError::InvalidDirectoryEntry {
                inode: parent_inum,
                offset: 0x1C,
            },
        ))
    }

    /// Resolve a directory-logical block to a physical block.
    fn resolve(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        logical: u32,
    ) -> HtreeResult<u64> {
        let _ = parent_inum;
        self.mutator.resolve_dir_block(self.fs, dir, logical)
    }

    /// Read a directory-logical block's full bytes (scratch-aware).
    fn read_dir_block(
        &mut self,
        parent_inum: u32,
        dir: &CurrentDirInode,
        logical: u32,
    ) -> HtreeResult<Vec<u8>> {
        let physical = self.resolve(parent_inum, dir, logical)?;
        let (bytes, _) = self.mutator.current_block_bytes(self.fs, physical)?;
        Ok(bytes.into_vec())
    }
}

/// Parsed dx_root header fields needed for maintenance.
struct DxRootHeader {
    hash_version: u8,
    indirect_levels: u8,
}

/// A leaf entry collected for hash-sorted redistribution.
#[derive(Clone, Debug)]
struct LeafEntry {
    inode: u32,
    file_type: u8,
    name: Vec<u8>,
    /// On-disk order index, used as a stable secondary sort key.
    order: u32,
    /// Htree major hash; filled in after collection.
    hash: u32,
}

/// The plan for redistributing a full leaf across two blocks.
struct LeafSplit {
    /// Entries that stay in the original (low-hash) leaf block.
    low_entries: Vec<LeafEntry>,
    /// Entries that move to the newly allocated (high-hash) leaf block.
    high_entries: Vec<LeafEntry>,
    /// dx_entry hash for the new (high) block.
    boundary_hash: u32,
}

/// Choose a split index for a hash-sorted entry list such that the
/// boundary lies between two *distinct* hashes (`entries[i-1].hash !=
/// entries[i].hash`), as close to the count midpoint as possible. Both
/// halves are non-empty. Returns `None` only when every entry shares one
/// hash (no clean partition exists).
fn clean_split_point(entries: &[LeafEntry]) -> Option<usize> {
    let len = entries.len();
    let mid = len / 2;
    for delta in 0..len {
        for candidate in [mid + delta, mid.wrapping_sub(delta)] {
            if candidate >= 1
                && candidate < len
                && entries[candidate - 1].hash != entries[candidate].hash
            {
                return Some(candidate);
            }
        }
    }
    None
}

/// Deepest recorded dx node (the leaf's parent index node).
fn path_deepest(probe: &DxProbe) -> &DxPathNode {
    probe
        .path
        .last()
        .expect("dx_probe always records at least the root")
}

/// Parse the dx_root header at offset 0x1C of block 0.
fn parse_dx_root(block: &[u8], inode: u32) -> HtreeResult<DxRootHeader> {
    if block.len() < DX_ROOT_COUNT_LIMIT_OFFSET + DX_ENTRY_SIZE {
        return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode,
            offset: 0x1C,
        }));
    }
    let info_length = block[0x1D];
    if info_length != 8 {
        return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode,
            offset: 0x1D,
        }));
    }
    Ok(DxRootHeader {
        hash_version: block[0x1C],
        indirect_levels: block[0x1E],
    })
}

/// Pick the child `dx_entry` for `name_hash`: the last entry whose hash
/// is `<= name_hash` (entry 0's hash is treated as zero). Mirrors the
/// read path's `find_target_block`.
fn choose_child(
    block: &[u8],
    count_limit_offset: usize,
    name_hash: u32,
    inode: u32,
) -> HtreeResult<(usize, u32)> {
    if count_limit_offset + DX_ENTRY_SIZE > block.len() {
        return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode,
            offset: count_limit_offset as u64,
        }));
    }
    // `DxCountLimit.count` is the u16 at byte +2 of the count_limit.
    let count = u16::from_le_bytes([block[count_limit_offset + 2], block[count_limit_offset + 3]]);
    if count == 0 {
        return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode,
            offset: (count_limit_offset + 2) as u64,
        }));
    }
    let mut chosen = 0usize;
    for i in 0..usize::from(count) {
        let off = count_limit_offset + i * DX_ENTRY_SIZE;
        if off + DX_ENTRY_SIZE > block.len() {
            return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
                inode,
                offset: off as u64,
            }));
        }
        let hash = u32::from_le_bytes(block[off..off + 4].try_into().expect("len 4"));
        if i == 0 || hash <= name_hash {
            chosen = i;
        } else {
            break;
        }
    }
    let off = count_limit_offset + chosen * DX_ENTRY_SIZE;
    let child = u32::from_le_bytes(block[off + 4..off + 8].try_into().expect("len 4"));
    Ok((chosen, child))
}

/// Collect every real (`inode != 0`) entry from a linear leaf block,
/// preserving on-disk order. Stops at the `dir_entry_tail` sentinel.
fn collect_leaf_entries(
    block: &[u8],
    has_filetype: bool,
    inode: u32,
) -> HtreeResult<Vec<LeafEntry>> {
    let usable_end = leaf_entry_region_end(block);
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut order = 0u32;
    while offset < usable_end {
        if offset + 8 > usable_end {
            return Err(invalid_entry(inode, offset));
        }
        let entry_inode = u32::from_le_bytes(block[offset..offset + 4].try_into().expect("len 4"));
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().expect("len 4"));
        if rec_len < 8 || rec_len % 4 != 0 {
            return Err(invalid_entry(inode, offset));
        }
        let next = offset
            .checked_add(usize::from(rec_len))
            .ok_or(invalid_entry(inode, offset))?;
        if next > usable_end {
            return Err(invalid_entry(inode, offset));
        }
        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().expect("len 4"),
            ))
        };
        if name_len > usize::from(rec_len) - 8 {
            return Err(invalid_entry(inode, offset));
        }
        if entry_inode != 0 {
            let file_type = if has_filetype { block[offset + 7] } else { 0 };
            entries.push(LeafEntry {
                inode: entry_inode,
                file_type,
                name: block[offset + 8..offset + 8 + name_len].to_vec(),
                order,
                hash: 0,
            });
            order += 1;
        }
        offset = next;
    }
    Ok(entries)
}

/// Whether a leaf block has any real (`inode != 0`) entries.
fn leaf_has_real_entries(block: &[u8], has_filetype: bool, inode: u32) -> HtreeResult<bool> {
    Ok(!collect_leaf_entries(block, has_filetype, inode)?.is_empty())
}

/// Write a list of entries densely into a fresh leaf block, leaving the
/// last entry's `rec_len` to span up to the `dir_entry_tail` region.
fn write_leaf_entries(
    block: &mut [u8],
    entries: &[LeafEntry],
    has_filetype: bool,
    inode: u32,
) -> HtreeResult<()> {
    let region_end = block.len() - 12;
    let mut offset = 0usize;
    for (idx, entry) in entries.iter().enumerate() {
        let min_len = aligned_entry_len(entry.name.len()).ok_or(invalid_entry(inode, offset))?;
        let is_last = idx + 1 == entries.len();
        let rec_len = if is_last {
            region_end - offset
        } else {
            min_len
        };
        if offset + rec_len > region_end || rec_len > usize::from(u16::MAX) {
            return Err(invalid_entry(inode, offset));
        }
        write_dir_entry(block, offset, entry, rec_len as u16, has_filetype);
        offset += rec_len;
    }
    if entries.is_empty() {
        // An empty leaf still needs one spanning empty entry.
        let rec_len = region_end as u16;
        block[4..6].copy_from_slice(&rec_len.to_le_bytes());
    }
    Ok(())
}

/// Insert one new entry into a (possibly post-split) leaf block, reusing
/// the trailing entry's slack. Returns an error if no room — the split
/// midpoint guarantees room, so this is a structural invariant.
fn insert_into_leaf(
    block: &mut [u8],
    ctx: DirLeafAppendCtx<'_>,
    has_filetype: bool,
    inode: u32,
) -> HtreeResult<()> {
    let region_end = block.len() - 12;
    let required = aligned_entry_len(ctx.name.len()).ok_or(invalid_entry(inode, 0))?;
    let mut offset = 0usize;
    let mut last: Option<(usize, usize, usize)> = None;
    while offset < region_end {
        let rec_len =
            u16::from_le_bytes(block[offset + 4..offset + 6].try_into().expect("len 4")) as usize;
        if rec_len < 8 {
            return Err(invalid_entry(inode, offset));
        }
        let entry_inode = u32::from_le_bytes(block[offset..offset + 4].try_into().expect("len 4"));
        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().expect("len 4"),
            ))
        };
        let used = if entry_inode == 0 {
            0
        } else {
            aligned_entry_len(name_len).ok_or(invalid_entry(inode, offset))?
        };
        last = Some((offset, used, rec_len));
        offset += rec_len;
    }
    let (last_off, used, rec_len) = last.ok_or(invalid_entry(inode, 0))?;
    let slack = rec_len - used;
    if slack < required {
        return Err(invalid_entry(inode, last_off));
    }
    let new_off = last_off + used;
    block[last_off + 4..last_off + 6].copy_from_slice(&(used as u16).to_le_bytes());
    let entry = LeafEntry {
        inode: ctx.child_inum,
        file_type: ctx.file_type,
        name: ctx.name.to_vec(),
        order: 0,
        hash: 0,
    };
    write_dir_entry(block, new_off, &entry, slack as u16, has_filetype);
    Ok(())
}

/// Write one directory entry's bytes at `offset` with the given `rec_len`.
///
/// When the filesystem has the `filetype` incompat feature, byte 6 is an
/// 8-bit `name_len` and byte 7 the file type. Without it, bytes 6..8 are
/// a single little-endian 16-bit `name_len` — writing a file type into
/// byte 7 there would corrupt the parsed length.
fn write_dir_entry(
    block: &mut [u8],
    offset: usize,
    entry: &LeafEntry,
    rec_len: u16,
    has_filetype: bool,
) {
    let end = offset + usize::from(rec_len);
    block[offset..end].fill(0);
    block[offset..offset + 4].copy_from_slice(&entry.inode.to_le_bytes());
    block[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
    let name_len = entry.name.len();
    if has_filetype {
        block[offset + 6] = name_len as u8;
        block[offset + 7] = entry.file_type;
    } else {
        block[offset + 6..offset + 8].copy_from_slice(&(name_len as u16).to_le_bytes());
    }
    block[offset + 8..offset + 8 + name_len].copy_from_slice(&entry.name);
}

/// Stamp the `dir_entry_tail` sentinel and recompute the dir-leaf CRC32C.
fn finish_dir_block(seed: Option<u32>, inode: u32, generation: u32, block: &mut [u8]) {
    let tail_off = block.len() - 12;
    block[tail_off..tail_off + 4].copy_from_slice(&0u32.to_le_bytes());
    block[tail_off + 4..tail_off + 6].copy_from_slice(&12u16.to_le_bytes());
    block[tail_off + 6] = 0;
    block[tail_off + 7] = 0xDE;
    let Some(seed) = seed else {
        return;
    };
    let mut crc = crate::checksum::ext4_crc32c(seed, &inode.to_le_bytes());
    crc = crate::checksum::ext4_crc32c(crc, &generation.to_le_bytes());
    crc = crate::checksum::ext4_crc32c(crc, &block[..tail_off]);
    block[tail_off + 8..tail_off + 12].copy_from_slice(&crc.to_le_bytes());
}

/// Byte offset where the linear-entry region of a leaf ends (before the
/// `dir_entry_tail` sentinel, when present).
fn leaf_entry_region_end(block: &[u8]) -> usize {
    if block.len() >= 12 {
        let tail_off = block.len() - 12;
        if block[tail_off + 7] == 0xDE
            && u32::from_le_bytes(block[tail_off..tail_off + 4].try_into().expect("len 4")) == 0
        {
            return tail_off;
        }
    }
    block.len()
}

/// 4-byte aligned `rec_len` for a name of `name_len` bytes.
fn aligned_entry_len(name_len: usize) -> Option<usize> {
    8usize
        .checked_add(name_len)
        .and_then(|len| len.checked_add(3))
        .map(|len| len & !3)
}

fn invalid_entry(inode: u32, offset: usize) -> MutatorError {
    MutatorError::Ext(ExtError::InvalidDirectoryEntry {
        inode,
        offset: offset as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum::ChecksumState;
    use fs_common::FsTryIterator;

    /// Inode of the 500-file htree directory `/htree_dir` in ext4.img.
    const HTREE_DIR: u32 = 21;

    /// Build a `(Ext, image_bytes)` pair from the htree fixture.
    fn fixture() -> (Ext, Vec<u8>) {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes.clone());
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        (ext, bytes)
    }

    /// Read the sb-host block for `Mutator::new`.
    fn sb_host_block(ext: &Ext, image: &[u8]) -> alloc::boxed::Box<[u8]> {
        let bs = ext.block_size() as usize;
        let host = if ext.block_size() > 1024 { 0 } else { 1 };
        image[host * bs..host * bs + bs].to_vec().into_boxed_slice()
    }

    /// Apply a finalized `OrphanOverlayDelta` onto a fresh copy of the
    /// image, then re-open it so post-replay lookups see the new state.
    fn apply_delta(
        ext: &Ext,
        image: &[u8],
        delta: &crate::orphan::plan::OrphanOverlayDelta,
    ) -> Vec<u8> {
        let bs = ext.block_size() as usize;
        let mut out = image.to_vec();
        for (&block, content) in &delta.blocks {
            let start = block as usize * bs;
            out[start..start + content.len()].copy_from_slice(content);
        }
        if let Some(sb_host) = &delta.sb_host_override {
            out[0..sb_host.len()].copy_from_slice(sb_host);
        }
        out
    }

    /// Pick a fresh entry name of `len` bytes whose half-MD4 hash routes
    /// to dx_entry index `want_index` of the `/htree_dir` dx_root. A long
    /// `len` is used to force a leaf split; a short `len` to land in a
    /// leaf with room.
    fn name_for_leaf(ext: &Ext, image: &[u8], want_index: usize, len: usize) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
        let i_block = dir.i_block();
        let root_pblk = crate::extent::resolve_extent(
            ext,
            &mut cursor,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            0,
        )
        .expect("resolve dx_root")
        .expect("dx_root extent")
        .physical_block;
        let bs = ext.block_size() as usize;
        let root = &image[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        let header = parse_dx_root(root, HTREE_DIR).expect("parse dx_root");

        for n in 0..1_000_000u32 {
            let mut name = alloc::format!("zfc{n:09}").into_bytes();
            name.resize(len, b'x');
            let hash = dx_hash(&name, header.hash_version, ext.hash_seed())
                .expect("hash")
                .major;
            let (idx, _) =
                choose_child(root, DX_ROOT_COUNT_LIMIT_OFFSET, hash, HTREE_DIR).expect("choose");
            if idx == want_index {
                return name;
            }
        }
        panic!("no probe name routed to dx_entry {want_index}");
    }

    /// Collect `n` distinct long names that all route to dx_entry index
    /// `want_index` of the original dx_root. Inserting them in order
    /// fills the target leaf and forces a split.
    fn names_for_leaf(ext: &Ext, image: &[u8], want_index: usize, n: usize) -> Vec<Vec<u8>> {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
        let i_block = dir.i_block();
        let root_pblk = crate::extent::resolve_extent(
            ext,
            &mut cursor,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            0,
        )
        .expect("resolve dx_root")
        .expect("dx_root extent")
        .physical_block;
        let bs = ext.block_size() as usize;
        let root = &image[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        let header = parse_dx_root(root, HTREE_DIR).expect("parse dx_root");

        let mut out = Vec::new();
        for seq in 0..1_000_000u32 {
            // 250-byte names: only ~3 fit a leaf's free slack, so the
            // fourth forces a split.
            let mut name = alloc::format!("zsplit{seq:09}").into_bytes();
            name.resize(250, b'q');
            let hash = dx_hash(&name, header.hash_version, ext.hash_seed())
                .expect("hash")
                .major;
            let (idx, _) =
                choose_child(root, DX_ROOT_COUNT_LIMIT_OFFSET, hash, HTREE_DIR).expect("choose");
            if idx == want_index {
                out.push(name);
                if out.len() == n {
                    return out;
                }
            }
        }
        panic!("could not collect {n} names for dx_entry {want_index}");
    }

    /// Verify both htree and sequential lookup agree on `name` in
    /// `/htree_dir`, and that every dx node and dir leaf checksum is
    /// valid. `expect` is `Some(inode)` when the name must be present.
    fn assert_consistent(image: &[u8], name: &[u8], expect: Option<u32>) {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let ext = Ext::open_lenient(&mut cursor).expect("re-open image");
        let mut dir = ext.directory_at(HTREE_DIR);
        let htree = dir.lookup(&mut cursor, name);
        match expect {
            Some(inode) => {
                let entry = htree.expect("htree lookup must find the name");
                assert_eq!(entry.inode_number, inode, "htree lookup inode mismatch");
            }
            None => {
                assert!(
                    matches!(htree, Err(crate::error::ExtError::NotFound)),
                    "htree lookup must miss a removed name"
                );
            }
        }
        // Sequential scan must agree with the htree result.
        let seq = sequential_find(&ext, &mut cursor, name);
        assert_eq!(seq, expect, "sequential scan disagrees with htree lookup");
        assert_dx_and_leaf_checksums(&ext, image);
    }

    /// Sequential directory scan: returns the inode for `name`, or `None`.
    fn sequential_find(
        ext: &Ext,
        cursor: &mut std::io::Cursor<Vec<u8>>,
        name: &[u8],
    ) -> Option<u32> {
        let mut dir = ext.directory_at(HTREE_DIR);
        let mut iter = dir.raw_entries(cursor).expect("raw entries");
        while let Some(entry) = iter.try_next(cursor).expect("raw entry") {
            if entry.name_bytes() == name {
                return Some(entry.inode_number());
            }
        }
        None
    }

    /// Walk every directory block of `/htree_dir`: dx_root/dx_node blocks
    /// must pass `verify_dx_*`, leaf blocks must pass `verify_dir_block`.
    fn assert_dx_and_leaf_checksums(ext: &Ext, image: &[u8]) {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let dir = ext.inode(&mut cursor, HTREE_DIR).expect("htree inode");
        let seed = ext.checksum_seed().expect("metadata_csum fixture");
        let generation = dir.generation();
        let bs = ext.block_size() as usize;
        let dir_blocks = dir.size().div_ceil(bs as u64);
        let i_block = dir.i_block();

        let root_pblk =
            crate::extent::resolve_extent(ext, &mut cursor, HTREE_DIR, generation, &i_block, 0)
                .expect("resolve dx_root")
                .expect("dx_root extent")
                .physical_block;
        let root = &image[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        let count = u16::from_le_bytes([root[0x22], root[0x23]]);
        let limit = u16::from_le_bytes([root[0x20], root[0x21]]);
        assert_eq!(
            crate::checksum::verify_dx_root(seed, HTREE_DIR, generation, root, count, limit),
            ChecksumState::Valid,
            "dx_root checksum invalid post-replay"
        );

        for logical in 1..dir_blocks {
            let logical = logical as u32;
            let pblk = crate::extent::resolve_extent(
                ext,
                &mut cursor,
                HTREE_DIR,
                generation,
                &i_block,
                logical,
            )
            .expect("resolve leaf")
            .expect("leaf extent")
            .physical_block;
            let block = &image[pblk as usize * bs..pblk as usize * bs + bs];
            assert_eq!(
                crate::checksum::verify_dir_block(seed, HTREE_DIR, generation, block),
                ChecksumState::Valid,
                "dir leaf {logical} checksum invalid post-replay"
            );
        }
    }

    /// Run `body` against a fresh `HtreeSurgeon`, finalize, and return the
    /// post-replay image bytes.
    fn run_surgery<F>(ext: &Ext, image: &[u8], body: F) -> Vec<u8>
    where
        F: FnOnce(&mut HtreeSurgeon<'_, '_, std::io::Cursor<Vec<u8>>>) -> DirReplayOutcome,
    {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let mut mutator = Mutator::new(ext, &sb_host_block(ext, image));
        let outcome = {
            let mut surgeon = HtreeSurgeon::new(ext, &mut cursor, &mut mutator);
            body(&mut surgeon)
        };
        assert_eq!(outcome, DirReplayOutcome::Applied, "surgery did not apply");
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        apply_delta(ext, image, &delta)
    }

    #[test]
    fn creat_into_leaf_with_room_inserts_without_dx_change() {
        let (ext, image) = fixture();
        // dx_entry index 3 backs the near-empty fourth leaf (8 entries).
        let name = name_for_leaf(&ext, &image, 3, 16);
        let child = 23u32;

        let after = run_surgery(&ext, &image, |s| {
            s.add_entry(HTREE_DIR, child, &name, 1)
                .expect("creat into htree parent")
        });

        assert_consistent(&after, &name, Some(child));
        // dx_root count unchanged: leaf had room, no split.
        let mut cursor = std::io::Cursor::new(after.clone());
        let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
        assert!(reopened.has_dir_index());
    }

    #[test]
    fn link_into_htree_parent_uses_creat_path() {
        let (ext, image) = fixture();
        let name = name_for_leaf(&ext, &image, 3, 16);
        let child = 24u32;
        // LINK and CREAT share the add_entry path; verify a second add.
        let after = run_surgery(&ext, &image, |s| {
            s.add_entry(HTREE_DIR, child, &name, 1)
                .expect("link into htree parent")
        });
        assert_consistent(&after, &name, Some(child));
    }

    /// Byte offset of inode `inum`'s on-disk `i_flags` field in `image`.
    fn inode_flags_offset(ext: &Ext, inum: u32) -> usize {
        let group = ((inum - 1) / ext.inodes_per_group) as usize;
        let index = u64::from((inum - 1) % ext.inodes_per_group);
        let table = ext.group_descs[group].inode_table;
        let bs = u64::from(ext.block_size());
        (table * bs + index * u64::from(ext.inode_size())) as usize + 0x20
    }

    #[test]
    fn add_entry_skips_unsupported_htree_variant_without_aborting() {
        // An htree directory whose variant this maintainer does not
        // support (here: casefold) must yield SkippedHtree so the caller
        // emits a HtreeNotMaintained warning and preserves forward
        // progress — not a hard error that aborts the whole FC replay.
        let (ext, mut image) = fixture();
        let off = inode_flags_offset(&ext, HTREE_DIR);
        let mut flags = u32::from_le_bytes(image[off..off + 4].try_into().unwrap());
        flags |= InodeFlags::CASEFOLD_FL.bits();
        image[off..off + 4].copy_from_slice(&flags.to_le_bytes());

        let mut cursor = std::io::Cursor::new(image.clone());
        let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
        let outcome = {
            let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
            surgeon
                .add_entry(HTREE_DIR, 23, b"casefold-skip", 1)
                .expect("casefolded htree must skip, not error")
        };
        assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
    }

    #[test]
    fn write_dir_entry_encodes_name_len_per_filetype_feature() {
        let entry = LeafEntry {
            inode: 42,
            file_type: 7,
            name: b"report.txt".to_vec(),
            order: 0,
            hash: 0,
        };

        // No `filetype` feature: bytes 6..8 are a single LE u16 name_len;
        // the file type must not bleed into byte 7.
        let mut no_ft = alloc::vec![0u8; 64];
        write_dir_entry(&mut no_ft, 0, &entry, 24, false);
        assert_eq!(
            u16::from_le_bytes([no_ft[6], no_ft[7]]),
            entry.name.len() as u16,
        );
        assert_eq!(
            no_ft[7], 0,
            "file type must not corrupt the name_len high byte"
        );

        // With `filetype`: byte 6 = u8 name_len, byte 7 = file type.
        let mut ft = alloc::vec![0u8; 64];
        write_dir_entry(&mut ft, 0, &entry, 24, true);
        assert_eq!(ft[6], entry.name.len() as u8);
        assert_eq!(ft[7], 7);
    }

    #[test]
    fn creat_forcing_leaf_split_redistributes_and_updates_dx() {
        let (ext, image) = fixture();
        // Four long names into the same leaf: the fourth overflows the
        // leaf's free slack and forces a split.
        let names = names_for_leaf(&ext, &image, 1, 4);
        let child = 25u32;

        let after = run_surgery(&ext, &image, |s| {
            let mut last = DirReplayOutcome::Applied;
            for name in &names {
                last = s
                    .add_entry(HTREE_DIR, child, name, 1)
                    .expect("creat forcing leaf split");
            }
            last
        });

        // Every inserted name is reachable and both lookup paths agree.
        for name in &names {
            assert_consistent(&after, name, Some(child));
        }

        // The directory grew by one logical block and the dx_root gained
        // a dx_entry (count 4 -> 5).
        let mut cursor = std::io::Cursor::new(after.clone());
        let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
        let dir = reopened.inode(&mut cursor, HTREE_DIR).expect("inode");
        assert_eq!(dir.size(), 6 * u64::from(ext.block_size()), "i_size grew");

        let i_block = dir.i_block();
        let root_pblk = crate::extent::resolve_extent(
            &reopened,
            &mut cursor,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            0,
        )
        .expect("resolve")
        .expect("extent")
        .physical_block;
        let bs = ext.block_size() as usize;
        let root = &after[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        let count = u16::from_le_bytes([root[0x22], root[0x23]]);
        assert_eq!(count, 5, "dx_root gained a dx_entry after the split");
    }

    #[test]
    fn split_keeps_every_preexisting_name_reachable() {
        let (ext, image) = fixture();
        let names = names_for_leaf(&ext, &image, 2, 4);
        let child = 26u32;
        let after = run_surgery(&ext, &image, |s| {
            let mut last = DirReplayOutcome::Applied;
            for name in &names {
                last = s
                    .add_entry(HTREE_DIR, child, name, 1)
                    .expect("creat forcing split");
            }
            last
        });
        // The split moved entries into a freshly appended block.
        let mut cursor = std::io::Cursor::new(after.clone());
        let reopened = Ext::open_lenient(&mut cursor).expect("reopen");
        assert_eq!(
            reopened.inode(&mut cursor, HTREE_DIR).unwrap().size(),
            6 * u64::from(ext.block_size()),
            "split must append one directory block"
        );

        // Every original file_NNN.txt (the fixture names file_001.txt
        // through file_500.txt) resolves through the htree and the
        // sequential scan identically, in whichever post-split block.
        let mut found = 0u32;
        for n in 1..=500u32 {
            let fname = alloc::format!("file_{n:03}.txt");
            let seq = sequential_find(&reopened, &mut cursor, fname.as_bytes());
            let mut dir = reopened.directory_at(HTREE_DIR);
            let htree = dir.lookup(&mut cursor, fname.as_bytes());
            match seq {
                Some(inode) => {
                    let entry =
                        htree.unwrap_or_else(|_| panic!("htree must find surviving name {fname}"));
                    assert_eq!(entry.inode_number, inode, "lookup mismatch {fname}");
                    found += 1;
                }
                None => assert!(
                    matches!(htree, Err(crate::error::ExtError::NotFound)),
                    "htree found {fname} that sequential scan did not"
                ),
            }
        }
        assert_eq!(found, 500, "all 500 fixture files must survive the split");
        for name in &names {
            assert_consistent(&after, name, Some(child));
        }
    }

    #[test]
    fn unlink_from_htree_parent_removes_entry() {
        let (ext, image) = fixture();
        // file_002.txt is inode 23 per the fixture (debugfs ls).
        let name = b"file_002.txt";
        let after = run_surgery(&ext, &image, |s| {
            s.remove_entry(HTREE_DIR, 23, name)
                .expect("unlink from htree parent")
        });
        assert_consistent(&after, name, None);
    }

    #[test]
    fn unlink_missing_name_reports_target_missing() {
        let (ext, image) = fixture();
        let mut cursor = std::io::Cursor::new(image.clone());
        let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
        let outcome = {
            let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
            surgeon
                .remove_entry(HTREE_DIR, 999, b"no_such_name.txt")
                .expect("unlink missing")
        };
        assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);
    }

    #[test]
    fn unlink_emptying_leaf_prunes_dx_entry() {
        // The fourth leaf (dx_entry 3) holds only 8 entries; remove all of
        // them so the leaf empties and its dx_entry is pruned.
        let (ext, image) = fixture();
        let mut cursor = std::io::Cursor::new(image.clone());
        let names = leaf_three_entry_names(&ext, &image);
        assert!(!names.is_empty(), "fourth leaf must hold entries");

        let mut mutator = Mutator::new(&ext, &sb_host_block(&ext, &image));
        {
            let mut surgeon = HtreeSurgeon::new(&ext, &mut cursor, &mut mutator);
            for (inode, name) in &names {
                let outcome = surgeon
                    .remove_entry(HTREE_DIR, *inode, name)
                    .expect("unlink leaf entry");
                assert_eq!(outcome, DirReplayOutcome::Applied);
            }
        }
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let after = apply_delta(&ext, &image, &delta);

        // dx_root lost the now-empty leaf's dx_entry (count 4 -> 3).
        let bs = ext.block_size() as usize;
        let mut rc = std::io::Cursor::new(after.clone());
        let reopened = Ext::open_lenient(&mut rc).expect("reopen");
        let dir = reopened.inode(&mut rc, HTREE_DIR).expect("inode");
        let i_block = dir.i_block();
        let root_pblk = crate::extent::resolve_extent(
            &reopened,
            &mut rc,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            0,
        )
        .expect("resolve")
        .expect("extent")
        .physical_block;
        let root = &after[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        let count = u16::from_le_bytes([root[0x22], root[0x23]]);
        assert_eq!(count, 3, "emptied leaf's dx_entry must be pruned");
        assert_dx_and_leaf_checksums(&ext, &after);
    }

    /// Collect `(inode, name)` for every entry in the fourth dx leaf
    /// (dx_entry index 3) of `/htree_dir`.
    fn leaf_three_entry_names(ext: &Ext, image: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut cursor = std::io::Cursor::new(image.to_vec());
        let dir = ext.inode(&mut cursor, HTREE_DIR).expect("inode");
        let i_block = dir.i_block();
        let bs = ext.block_size() as usize;
        let root_pblk = crate::extent::resolve_extent(
            ext,
            &mut cursor,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            0,
        )
        .expect("resolve")
        .expect("extent")
        .physical_block;
        let root = &image[root_pblk as usize * bs..root_pblk as usize * bs + bs];
        // dx_entry index 3 -> child logical block.
        let off = DX_ROOT_COUNT_LIMIT_OFFSET + 3 * DX_ENTRY_SIZE;
        let leaf_logical = u32::from_le_bytes(root[off + 4..off + 8].try_into().unwrap());
        let leaf_pblk = crate::extent::resolve_extent(
            ext,
            &mut cursor,
            HTREE_DIR,
            dir.generation(),
            &i_block,
            leaf_logical,
        )
        .expect("resolve leaf")
        .expect("leaf extent")
        .physical_block;
        let leaf = &image[leaf_pblk as usize * bs..leaf_pblk as usize * bs + bs];
        collect_leaf_entries(leaf, ext.has_filetype(), HTREE_DIR)
            .expect("collect")
            .into_iter()
            .map(|e| (e.inode, e.name))
            .collect()
    }
}
