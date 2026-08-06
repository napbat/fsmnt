//! Htree (hash-tree) directory maintenance for fast-commit CREAT/LINK/
//! UNLINK replay.
//!
//! `htree.rs` is the read-side model for the on-disk `dx_root/dx_node`
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

/// Offset of the on-disk `DxCountLimit` within a `dx_root` block.
const DX_ROOT_COUNT_LIMIT_OFFSET: usize = 0x20;
/// Offset of the on-disk `DxCountLimit` within an interior `dx_node` block.
const DX_NODE_COUNT_LIMIT_OFFSET: usize = 0x08;
/// Size of one on-disk `dx_entry` (hash u32 + block u32).
const DX_ENTRY_SIZE: usize = 8;

/// One level of a recorded dx-tree descent path.
#[derive(Clone, Debug)]
struct DxPathNode {
    /// Directory-logical block number of this node (0 == `dx_root`).
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

    /// Live `DxCountLimit.count` (at byte +2 of the `count_limit` struct).
    fn count(&self) -> u16 {
        u16::from_le_bytes([
            self.bytes[self.count_limit_offset + 2],
            self.bytes[self.count_limit_offset + 3],
        ])
    }

    /// Maximum `DxCountLimit.limit` (at byte +0 of the `count_limit` struct).
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
    /// `dx_root` and any interior `dx_nodes`, root first.
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
    /// remove the entry, and prune the leaf's `dx_entry` if it empties.
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

    /// Recompute the `dx_root/dx_node` CRC32C tail and stage the node bytes.
    /// `count` is the post-edit live entry count; `limit` is unchanged by
    /// an entry insert/remove (the `dx_tail` slot is fixed by `limit`).
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
                let size_bytes = new_size.to_le_bytes();
                inode[0x04..0x08].copy_from_slice(&size_bytes[..4]);
                inode[0x6C..0x70].copy_from_slice(&size_bytes[4..]);
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

/// Parsed `dx_root` header fields needed for maintenance.
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
    /// `dx_entry` hash for the new (high) block.
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

/// Parse the `dx_root` header at offset 0x1C of block 0.
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
        write_dir_entry(
            block,
            offset,
            entry,
            u16::try_from(rec_len).expect("directory record length was bounded above"),
            has_filetype,
        );
        offset += rec_len;
    }
    if entries.is_empty() {
        // An empty leaf still needs one spanning empty entry.
        let rec_len = u16::try_from(region_end).map_err(|_| invalid_entry(inode, 0))?;
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
        let rec_len = usize::from(u16::from_le_bytes(
            block[offset + 4..offset + 6].try_into().expect("len 4"),
        ));
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
    block[last_off + 4..last_off + 6].copy_from_slice(
        &u16::try_from(used)
            .expect("used directory-record bytes cannot exceed its u16 record length")
            .to_le_bytes(),
    );
    let entry = LeafEntry {
        inode: ctx.child_inum,
        file_type: ctx.file_type,
        name: ctx.name.to_vec(),
        order: 0,
        hash: 0,
    };
    write_dir_entry(
        block,
        new_off,
        &entry,
        u16::try_from(slack).expect("directory-record slack cannot exceed its u16 record length"),
        has_filetype,
    );
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
        block[offset + 6] =
            u8::try_from(name_len).expect("ext directory entry names contain at most 255 bytes");
        block[offset + 7] = entry.file_type;
    } else {
        block[offset + 6..offset + 8].copy_from_slice(
            &u16::try_from(name_len)
                .expect("ext directory entry names contain at most 255 bytes")
                .to_le_bytes(),
        );
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
#[path = "htree_mutate_tests/mod.rs"]
mod tests;
