//! Narrow write-side primitives for orphan Level-3 apply. Policy-free:
//! this module has no visibility into `OrphanPlan`, `OrphanStopReason`,
//! or apply-phase decisions. It owns scratch state (per-block patches,
//! per-group tallies, sb-host scratch) and the dangerous accounting
//! (bigalloc-aware allocation freeing, bitmap math, checksum recompute).
//!
//! See `docs/superpowers/specs/2026-04-24-fs-ext-orphan-level3-design.md`
//! §2.5 and §3.
//!
//! Fast-commit link-count note: kernel replay routes link-count updates through
//! ordinary inode mutation/writeback paths. This mutator intentionally uses
//! checked arithmetic instead; underflow/overflow returns
//! `LinkCountChange::{Underflow,Overflow}` for the caller to map to
//! `FastCommitStopReason::LinkCountOverflow` without modifying inode bytes.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;

use crate::error::ExtError;
use crate::ext::Ext;
use crate::io::{Read, Seek};

mod allocation_helpers;
mod allocation_methods;
mod directory_helpers;

use allocation_helpers::{
    allocation_units_per_group, apply_group_tally, apply_sb_tallies, mark_bitmap_bits,
    project_block_range_to_alloc_units, read_desc_u16, read_le_u16, read_le_u32,
    recompute_block_checksums, recompute_group_descriptor_checksums, write_desc_u16,
    write_desc_u32_split,
};
use directory_helpers::{
    aligned_dir_entry_len, apply_dir_append_slot, apply_dir_remove_slot, find_dir_append_slot,
    find_dir_remove_slot, refresh_dir_tail_checksum, resolve_dir_logical_block,
    validate_dir_tail_checksum,
};

/// One contiguous physical run owned by an inode.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AllocationRun {
    pub physical_start: u64,
    pub block_len: u32,
    pub kind: AllocationKind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AllocationKind {
    /// File-data allocation. Participates in bigalloc logical-cluster
    /// overlap detection. `logical_cluster_start` is the file-logical
    /// cluster number of the run's first block.
    Data { logical_cluster_start: u64 },
    /// Inode-owned metadata: extent-tree index/leaf block, indirect
    /// block, xattr block routed through the xattr-block plan, or EA
    /// inode body during cascade-free. No logical-cluster overlap
    /// detection; still uses cluster-granularity bitmap and count
    /// accounting on bigalloc.
    Metadata,
}

#[derive(Debug)]
pub(crate) enum MutatorError {
    Ext(ExtError),
    BigallocClusterOverlap {
        inode: u32,
        cluster: u64,
        first_block: u64,
        second_block: u64,
    },
}

impl From<ExtError> for MutatorError {
    fn from(err: ExtError) -> Self {
        Self::Ext(err)
    }
}

pub(crate) type MutatorResult<T> = core::result::Result<T, MutatorError>;

#[derive(Debug, Clone, Copy)]
enum BlockClass {
    InodeTable {
        /// Carried for debugging; the actual group is re-derived from the inode
        /// number at checksum-recompute time.
        #[expect(dead_code, reason = "carried for debugging; not needed by finalize")]
        group: u32,
    },
    XattrBlock,
    ExtentBlock {
        owner_inode: u32,
        owner_generation: u32,
    },
    OrphanFileBlock {
        file_inode: u32,
        file_generation: u32,
    },
    /// A directory block. `parent_inum` is the inode that owns this directory;
    /// required for dir-tail checksum recompute in finalize.
    #[allow(dead_code, reason = "consumed by fast-commit directory replay")]
    DirectoryBlock {
        block: u64,
        parent_inum: u32,
    },
    BlockBitmap {
        group: u32,
    },
    InodeBitmap {
        group: u32,
    },
    GroupDescriptor {
        /// Descriptor-block index (group / `desc_per_block`). Used by the
        /// finalize pass to compute the first group in the block; replaces
        /// the META_BG-broken `(gdt_block - gdt_start)` reverse arithmetic.
        desc_block_nr: u32,
    },
    /// Classical ext2/3-style indirect pointer block. No per-block checksum
    /// on ext4 with `METADATA_CSUM` (indirect blocks predate that feature),
    /// so finalize does no checksum recompute for this class.
    IndirectBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirReplayOutcome {
    Applied,
    SkippedHtree,
    SkippedTargetMissing,
}

fn validate_directory_replay_request(
    ext: &Ext,
    parent_inum: u32,
    child_inum: u32,
    name: &[u8],
) -> MutatorResult<()> {
    if child_inum == 0 || child_inum > ext.inodes_count {
        return Err(MutatorError::Ext(ExtError::InodeOutOfRange {
            inode: child_inum,
        }));
    }
    if name.is_empty() || name.len() > 255 {
        return Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode: parent_inum,
            offset: 0,
        }));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkCountChange {
    Applied { from: u16, to: u16 },
    Underflow { from: u16, would_be_delta: i32 },
    Overflow { from: u16, would_be_delta: i32 },
}

/// Parameters for a single linear-leaf directory append. Groups the
/// per-entry fields so `dir_leaf_append` stays within the positional-
/// parameter limit.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DirLeafAppendCtx<'a> {
    pub parent_inum: u32,
    pub parent_generation: u32,
    pub child_inum: u32,
    pub name: &'a [u8],
    pub file_type: u8,
}

#[derive(Clone, Copy, Debug)]
struct DirAppendSlot {
    last_entry_offset: usize,
    shrunk_last_rec_len: u16,
    new_entry_offset: usize,
    new_entry_rec_len: u16,
}

#[derive(Clone, Copy, Debug)]
enum DirRemoveSlot {
    MergeIntoPrev {
        prev_offset: usize,
        current_offset: usize,
        current_rec_len: u16,
    },
    ClearCurrentInode {
        current_offset: usize,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CurrentDirInode {
    number: u32,
    mode: u16,
    flags: crate::inode::InodeFlags,
    size: u64,
    generation: u32,
    i_block: [u8; 60],
}

impl CurrentDirInode {
    /// Inode flags as parsed from the on-disk `i_flags` field.
    pub(crate) fn flags(self) -> crate::inode::InodeFlags {
        self.flags
    }

    /// Inode `i_size` in bytes (lo + hi halves combined).
    pub(crate) fn size(self) -> u64 {
        self.size
    }

    /// Inode `i_generation`.
    pub(crate) fn generation(self) -> u32 {
        self.generation
    }

    fn parse(inum: u32, inode_bytes: &[u8]) -> MutatorResult<Self> {
        if inode_bytes.len() < 128 {
            return Err(MutatorError::Ext(ExtError::InvalidInode {
                inode: inum,
                reason: "too short",
            }));
        }

        let mode = read_le_u16(inode_bytes, 0x00);
        let size = u64::from(read_le_u32(inode_bytes, 0x04))
            | (u64::from(read_le_u32(inode_bytes, 0x6C)) << 32);
        let flags = crate::inode::InodeFlags::from_bits_retain(read_le_u32(inode_bytes, 0x20));
        let mut i_block = [0u8; 60];
        i_block.copy_from_slice(&inode_bytes[0x28..0x64]);
        let generation = read_le_u32(inode_bytes, 0x64);

        Ok(Self {
            number: inum,
            mode,
            flags,
            size,
            generation,
            i_block,
        })
    }

    fn is_directory(self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
}

#[derive(Debug)]
struct ScratchBlock {
    class: BlockClass,
    content: Box<[u8]>,
    /// Inode numbers mutated within this block (`InodeTable` only).
    mutated_inodes: alloc::collections::BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, Default)]
struct GroupTally {
    /// Clusters (== blocks on non-bigalloc) freed in this group.
    clusters_freed: u64,
    /// Clusters (== blocks on non-bigalloc) allocated in this group.
    clusters_allocated: u64,
    /// Inodes freed in this group.
    inodes_freed: u32,
    /// Directory-inodes freed in this group (subtracted from `bg_used_dirs_count`).
    dirs_freed: u32,
}

/// Orphan-apply scratch. Single instance per apply run; consumed by
/// `finalize`. Callers pass the post-journal overlay to every method
/// that needs to seed scratch from disk.
#[derive(Debug)]
pub(crate) struct Mutator<'a> {
    ext: &'a Ext,
    blocks: BTreeMap<u64, ScratchBlock>,
    group_tallies: BTreeMap<u32, GroupTally>,
    initialized_block_groups: BTreeSet<u32>,
    sb_host_scratch: Box<[u8]>,
    sb_dirty: bool,
    total_clusters_freed: u64,
    total_inodes_freed: u64,
}

impl<'a> Mutator<'a> {
    /// Create a new mutator seeded with the journal's post-replay
    /// sb-host block content. Callers pass in
    /// `journal.sb_host_block_content()` bytes so the sb scratch starts
    /// from the journal-replayed state (`INCOMPAT_RECOVER` cleared, etc.)
    /// rather than the raw image.
    pub(crate) fn new(ext: &'a Ext, journal_sb_host_block: &[u8]) -> Self {
        Self {
            ext,
            blocks: BTreeMap::new(),
            group_tallies: BTreeMap::new(),
            initialized_block_groups: BTreeSet::new(),
            sb_host_scratch: journal_sb_host_block.to_vec().into_boxed_slice(),
            sb_dirty: false,
            total_clusters_freed: 0,
            total_inodes_freed: 0,
        }
    }

    /// Patch the sb-host scratch buffer in place. No overlay read needed —
    /// the scratch is already seeded from the journal's sb-host block at
    /// construction. Used by `apply.rs` for orphan-linkage clears
    /// (`s_last_orphan`, `ORPHAN_PRESENT` bit) and by `finalize` for free-count
    /// tally updates.
    pub(crate) fn patch_superblock_bytes<F>(&mut self, f: F) -> MutatorResult<()>
    where
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        f(&mut self.sb_host_scratch)?;
        self.sb_dirty = true;
        Ok(())
    }

    /// Seed the scratch for `block_num` from the overlay reader if not
    /// already present. Returns a mutable reference to the now-present
    /// `ScratchBlock`.
    fn seed_block<T: Read + Seek>(
        &mut self,
        overlay: &mut T,
        block_num: u64,
        class: BlockClass,
    ) -> MutatorResult<&mut ScratchBlock> {
        if !self.blocks.contains_key(&block_num) {
            let bs = self.ext.block_size() as usize;
            let mut buf = alloc::vec![0u8; bs];
            let byte_offset = block_num
                .checked_mul(u64::from(self.ext.block_size()))
                .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: block_num,
                }))?;
            overlay
                .seek(crate::io::SeekFrom::Start(byte_offset))
                .map_err(ExtError::Io)?;
            overlay.read_exact(&mut buf).map_err(ExtError::Io)?;
            self.blocks.insert(
                block_num,
                ScratchBlock {
                    class,
                    content: buf.into_boxed_slice(),
                    mutated_inodes: BTreeSet::new(),
                },
            );
        }
        Ok(self.blocks.get_mut(&block_num).expect("just inserted"))
    }

    /// Patch the scratch bytes of inode `inum`. Seeds the containing inode
    /// table block from the overlay on first patch. Records `inum` in the
    /// block's mutated-inodes set so `finalize` can recompute each
    /// mutated inode's checksum.
    pub(crate) fn patch_inode_scratch<T, F>(
        &mut self,
        overlay: &mut T,
        inum: u32,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let (block, offset, size) = self.inode_table_slot(inum)?;
        let class = BlockClass::InodeTable {
            group: self.group_of_inode(inum),
        };
        let scratch = self.seed_block(overlay, block, class)?;
        f(&mut scratch.content[offset..offset + size])?;
        scratch.mutated_inodes.insert(inum);
        Ok(())
    }

    /// Seed the scratch for `block` from the overlay and apply `f` to the
    /// full block content. Records the block as `XattrBlock` class so
    /// `finalize` can recompute the xattr block checksum.
    pub(crate) fn patch_xattr_block<T, F>(
        &mut self,
        overlay: &mut T,
        block: u64,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let scratch = self.seed_block(overlay, block, BlockClass::XattrBlock)?;
        f(&mut scratch.content)
    }

    /// Seed the scratch for `block` from the overlay and apply `f` to the
    /// full directory block content. Records the owning directory inode so
    /// `finalize` can recompute the dir-tail checksum.
    #[allow(dead_code, reason = "consumed by fast-commit directory replay")]
    pub(crate) fn patch_directory_block<T, F>(
        &mut self,
        overlay: &mut T,
        block: u64,
        parent_inum: u32,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let scratch = self.seed_block(
            overlay,
            block,
            BlockClass::DirectoryBlock { block, parent_inum },
        )?;
        f(&mut scratch.content)
    }

    /// Append one entry to a linear directory block by splitting the trailing
    /// entry's `rec_len` slack. Htree directories are intentionally skipped until
    /// fast-commit replay grows indexed-directory surgery.
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub(crate) fn dir_append_entry<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        parent_inum: u32,
        child_inum: u32,
        name: &[u8],
        file_type: u8,
    ) -> MutatorResult<DirReplayOutcome> {
        validate_directory_replay_request(self.ext, parent_inum, child_inum, name)?;

        let parent = self.current_dir_inode(fs, parent_inum)?;
        if !parent.is_directory() {
            return Err(MutatorError::Ext(ExtError::NotADirectory {
                inode: parent_inum,
            }));
        }

        let parent_flags = parent.flags;
        if parent_flags.contains(crate::inode::InodeFlags::INDEX_FL) {
            return Ok(DirReplayOutcome::SkippedHtree);
        }
        if parent_flags.contains(crate::inode::InodeFlags::ENCRYPT_FL) {
            return Err(MutatorError::Ext(ExtError::EncryptedInode {
                inode: parent_inum,
            }));
        }
        if parent_flags.contains(crate::inode::InodeFlags::INLINE_DATA_FL) {
            return Err(MutatorError::Ext(ExtError::InvalidInlineData {
                inode: parent_inum,
            }));
        }

        let required_len = aligned_dir_entry_len(name.len()).ok_or(MutatorError::Ext(
            ExtError::InvalidDirectoryEntry {
                inode: parent_inum,
                offset: 0,
            },
        ))?;
        let block_size = self.ext.block_size() as usize;
        let dir_blocks = parent.size.div_ceil(u64::from(self.ext.block_size()));
        let has_filetype = self.ext.has_filetype();
        let checksum_seed = self.ext.checksum_seed();
        let parent_generation = parent.generation;
        for logical in 0..dir_blocks {
            let logical = u32::try_from(logical)
                .map_err(|_| MutatorError::Ext(ExtError::BlockOutOfRange { block: logical }))?;
            let physical = resolve_dir_logical_block(self.ext, fs, &parent, logical)?;
            let slot = if let Some(scratch) = self.blocks.get(&physical) {
                validate_dir_tail_checksum(
                    checksum_seed,
                    parent_inum,
                    parent_generation,
                    &scratch.content,
                )?;
                find_dir_append_slot(&scratch.content, has_filetype, parent_inum, required_len)?
            } else {
                let mut block = alloc::vec![0u8; block_size];
                let byte_offset = physical
                    .checked_mul(u64::from(self.ext.block_size()))
                    .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                        block: physical,
                    }))?;
                fs.seek(crate::io::SeekFrom::Start(byte_offset))
                    .map_err(ExtError::Io)?;
                fs.read_exact(&mut block).map_err(ExtError::Io)?;
                validate_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, &block)?;
                let slot = find_dir_append_slot(&block, has_filetype, parent_inum, required_len)?;
                if slot.is_some() {
                    self.blocks.insert(
                        physical,
                        ScratchBlock {
                            class: BlockClass::DirectoryBlock {
                                block: physical,
                                parent_inum,
                            },
                            content: block.into_boxed_slice(),
                            mutated_inodes: BTreeSet::new(),
                        },
                    );
                }
                slot
            };

            let Some(slot) = slot else {
                continue;
            };

            self.patch_directory_block(fs, physical, parent_inum, |dir_block| {
                apply_dir_append_slot(
                    dir_block,
                    slot,
                    child_inum,
                    name,
                    file_type,
                    has_filetype,
                    parent_inum,
                )?;
                refresh_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, dir_block);
                Ok(())
            })?;
            return Ok(DirReplayOutcome::Applied);
        }

        Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry {
            inode: parent_inum,
            offset: parent.size,
        }))
    }

    /// Remove one entry from a linear directory block by merging its `rec_len`
    /// into the preceding entry. Htree directories are intentionally skipped
    /// until fast-commit replay grows indexed-directory surgery.
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub(crate) fn dir_remove_entry<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        parent_inum: u32,
        child_inum: u32,
        name: &[u8],
    ) -> MutatorResult<DirReplayOutcome> {
        validate_directory_replay_request(self.ext, parent_inum, child_inum, name)?;

        let parent = self.current_dir_inode(fs, parent_inum)?;
        if !parent.is_directory() {
            return Err(MutatorError::Ext(ExtError::NotADirectory {
                inode: parent_inum,
            }));
        }

        let parent_flags = parent.flags;
        if parent_flags.contains(crate::inode::InodeFlags::INDEX_FL) {
            return Ok(DirReplayOutcome::SkippedHtree);
        }
        if parent_flags.contains(crate::inode::InodeFlags::ENCRYPT_FL) {
            return Err(MutatorError::Ext(ExtError::EncryptedInode {
                inode: parent_inum,
            }));
        }
        if parent_flags.contains(crate::inode::InodeFlags::INLINE_DATA_FL) {
            return Err(MutatorError::Ext(ExtError::InvalidInlineData {
                inode: parent_inum,
            }));
        }

        let block_size = self.ext.block_size() as usize;
        let dir_blocks = parent.size.div_ceil(u64::from(self.ext.block_size()));
        let has_filetype = self.ext.has_filetype();
        let checksum_seed = self.ext.checksum_seed();
        let parent_generation = parent.generation;
        for logical in 0..dir_blocks {
            let logical = u32::try_from(logical)
                .map_err(|_| MutatorError::Ext(ExtError::BlockOutOfRange { block: logical }))?;
            let physical = resolve_dir_logical_block(self.ext, fs, &parent, logical)?;
            let slot = if let Some(scratch) = self.blocks.get(&physical) {
                validate_dir_tail_checksum(
                    checksum_seed,
                    parent_inum,
                    parent_generation,
                    &scratch.content,
                )?;
                find_dir_remove_slot(
                    &scratch.content,
                    has_filetype,
                    parent_inum,
                    child_inum,
                    name,
                )?
            } else {
                let mut block = alloc::vec![0u8; block_size];
                let byte_offset = physical
                    .checked_mul(u64::from(self.ext.block_size()))
                    .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                        block: physical,
                    }))?;
                fs.seek(crate::io::SeekFrom::Start(byte_offset))
                    .map_err(ExtError::Io)?;
                fs.read_exact(&mut block).map_err(ExtError::Io)?;
                validate_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, &block)?;
                find_dir_remove_slot(&block, has_filetype, parent_inum, child_inum, name)?
            };

            let Some(slot) = slot else {
                continue;
            };

            self.patch_directory_block(fs, physical, parent_inum, |dir_block| {
                apply_dir_remove_slot(dir_block, slot, parent_inum)?;
                refresh_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, dir_block);
                Ok(())
            })?;
            return Ok(DirReplayOutcome::Applied);
        }

        Ok(DirReplayOutcome::SkippedTargetMissing)
    }

    /// Adjust only `i_links_count` for `inum`, preserving inode checksum
    /// recompute through the inode-scratch patch path.
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub(crate) fn adjust_inode_links_count<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        inum: u32,
        delta: i32,
    ) -> MutatorResult<LinkCountChange> {
        let current_inode = self.current_inode_bytes(fs, inum)?;
        let current = read_le_u16(&current_inode, 0x1A);
        let next = i64::from(current) + i64::from(delta);
        if next < 0 {
            return Ok(LinkCountChange::Underflow {
                from: current,
                would_be_delta: delta,
            });
        }
        if next > i64::from(u16::MAX) {
            return Ok(LinkCountChange::Overflow {
                from: current,
                would_be_delta: delta,
            });
        }

        let next =
            u16::try_from(next).expect("link-count bounds were checked before converting to u16");
        self.patch_inode_scratch(fs, inum, |inode_bytes| {
            inode_bytes[0x1A..0x1C].copy_from_slice(&next.to_le_bytes());
            Ok(())
        })?;
        Ok(LinkCountChange::Applied {
            from: current,
            to: next,
        })
    }

    /// Seed the scratch for `block` from the overlay and apply `f` to the
    /// full block content. Records owner inode + generation so `finalize`
    /// can recompute the extent-tree block checksum.
    pub(crate) fn patch_extent_block<T, F>(
        &mut self,
        overlay: &mut T,
        block: u64,
        owner_inode: u32,
        owner_generation: u32,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let scratch = self.seed_block(
            overlay,
            block,
            BlockClass::ExtentBlock {
                owner_inode,
                owner_generation,
            },
        )?;
        f(&mut scratch.content)
    }

    /// Seed the scratch for `block` from the overlay and apply `f` to the
    /// full block content. Records file inode + generation so `finalize`
    /// can recompute the orphan-file block checksum.
    pub(crate) fn patch_orphan_file_block<T, F>(
        &mut self,
        overlay: &mut T,
        block: u64,
        file_inode: u32,
        file_generation: u32,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let scratch = self.seed_block(
            overlay,
            block,
            BlockClass::OrphanFileBlock {
                file_inode,
                file_generation,
            },
        )?;
        f(&mut scratch.content)
    }

    /// Patch a classical ext2/3-style indirect block (pure array of u32 block
    /// pointers — no header, no checksum). Seeds from overlay on first call.
    /// Used by orphan Level-3 truncate to zero freed child-pointer slots in
    /// partially-surviving indirect blocks.
    pub(crate) fn patch_indirect_block<T, F>(
        &mut self,
        overlay: &mut T,
        block: u64,
        f: F,
    ) -> MutatorResult<()>
    where
        T: Read + Seek,
        F: FnOnce(&mut [u8]) -> MutatorResult<()>,
    {
        let scratch = self.seed_block(overlay, block, BlockClass::IndirectBlock)?;
        f(&mut scratch.content)
    }
}

#[cfg(test)]
#[path = "../mutator_tests/mod.rs"]
mod tests;
