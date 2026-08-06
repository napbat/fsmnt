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
        /// Descriptor-block index (group / desc_per_block). Used by the
        /// finalize pass to compute the first group in the block; replaces
        /// the META_BG-broken `(gdt_block - gdt_start)` reverse arithmetic.
        desc_block_nr: u32,
    },
    /// Classical ext2/3-style indirect pointer block. No per-block checksum
    /// on ext4 with METADATA_CSUM (indirect blocks predate that feature),
    /// so finalize does no checksum recompute for this class.
    IndirectBlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirReplayOutcome {
    Applied,
    SkippedHtree,
    SkippedTargetMissing,
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
    /// Inode numbers mutated within this block (InodeTable only).
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
    /// Directory-inodes freed in this group (subtracted from bg_used_dirs_count).
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
    /// from the journal-replayed state (INCOMPAT_RECOVER cleared, etc.)
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
    /// (s_last_orphan, ORPHAN_PRESENT bit) and by `finalize` for free-count
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
    /// entry's rec_len slack. Htree directories are intentionally skipped until
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
        if child_inum == 0 || child_inum > self.ext.inodes_count {
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

    /// Remove one entry from a linear directory block by merging its rec_len
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
        if child_inum == 0 || child_inum > self.ext.inodes_count {
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

        let next = next as u16;
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

    /// Locate `(block_num, byte_offset_within_block, inode_size)` for `inum`.
    /// Mirrors `apply::inode_block_and_offset` but also returns inode_size.
    fn inode_table_slot(&self, inum: u32) -> MutatorResult<(u64, usize, usize)> {
        if inum == 0 || inum > self.ext.inodes_count {
            return Err(MutatorError::Ext(ExtError::InodeOutOfRange { inode: inum }));
        }
        let group = self.group_of_inode(inum);
        let index_in_group = u64::from((inum - 1) % self.ext.inodes_per_group);
        let inode_size = u64::from(self.ext.inode_size());
        let byte_in_table = index_in_group * inode_size;
        let block_size = u64::from(self.ext.block_size());
        let table_block = self.ext.group_descs[group as usize].inode_table;
        let block = table_block + byte_in_table / block_size;
        let offset_in_block = (byte_in_table % block_size) as usize;
        Ok((block, offset_in_block, inode_size as usize))
    }

    fn group_of_inode(&self, inum: u32) -> u32 {
        (inum - 1) / self.ext.inodes_per_group
    }

    pub(crate) fn current_inode_bytes<T: Read + Seek>(
        &self,
        fs: &mut T,
        inum: u32,
    ) -> MutatorResult<Box<[u8]>> {
        let (block, offset, size) = self.inode_table_slot(inum)?;
        if let Some(scratch) = self.blocks.get(&block) {
            return Ok(scratch.content[offset..offset + size]
                .to_vec()
                .into_boxed_slice());
        }

        let block_offset = block
            .checked_mul(u64::from(self.ext.block_size()))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block }))?;
        let byte_offset = block_offset
            .checked_add(offset as u64)
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block }))?;
        let mut inode_bytes = alloc::vec![0u8; size].into_boxed_slice();
        fs.seek(crate::io::SeekFrom::Start(byte_offset))
            .map_err(ExtError::Io)?;
        fs.read_exact(&mut inode_bytes).map_err(ExtError::Io)?;
        Ok(inode_bytes)
    }

    /// Drop the inode table scratch containing `inum` if the whole block is
    /// byte-identical to the backing overlay. This is used after compensating
    /// updates that make an inode-table scratch net-neutral.
    pub(crate) fn prune_inode_table_block_if_unchanged<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        inum: u32,
    ) -> MutatorResult<bool> {
        let (block, _, _) = self.inode_table_slot(inum)?;
        let Some(scratch) = self.blocks.get(&block) else {
            return Ok(false);
        };
        if !matches!(scratch.class, BlockClass::InodeTable { .. }) {
            return Ok(false);
        }

        let byte_offset = block
            .checked_mul(u64::from(self.ext.block_size()))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block }))?;
        let mut backing = alloc::vec![0u8; self.ext.block_size() as usize];
        fs.seek(crate::io::SeekFrom::Start(byte_offset))
            .map_err(ExtError::Io)?;
        fs.read_exact(&mut backing).map_err(ExtError::Io)?;

        if scratch.content.as_ref() == backing.as_slice() {
            self.blocks.remove(&block);
            return Ok(true);
        }
        Ok(false)
    }

    /// Return the current full-block bytes for `block`, preferring already
    /// staged scratch over the backing overlay. The boolean is true when the
    /// bytes came from scratch.
    pub(crate) fn current_block_bytes<T: Read + Seek>(
        &self,
        fs: &mut T,
        block: u64,
    ) -> MutatorResult<(Box<[u8]>, bool)> {
        if let Some(scratch) = self.blocks.get(&block) {
            return Ok((scratch.content.to_vec().into_boxed_slice(), true));
        }
        if block >= self.ext.blocks_count {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange { block }));
        }

        let byte_offset = block
            .checked_mul(u64::from(self.ext.block_size()))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block }))?;
        let mut block_bytes = alloc::vec![0u8; self.ext.block_size() as usize].into_boxed_slice();
        fs.seek(crate::io::SeekFrom::Start(byte_offset))
            .map_err(ExtError::Io)?;
        fs.read_exact(&mut block_bytes).map_err(ExtError::Io)?;
        Ok((block_bytes, false))
    }

    pub(crate) fn current_dir_inode<T: Read + Seek>(
        &self,
        fs: &mut T,
        inum: u32,
    ) -> MutatorResult<CurrentDirInode> {
        let inode_bytes = self.current_inode_bytes(fs, inum)?;
        CurrentDirInode::parse(inum, &inode_bytes)
    }

    /// Resolve directory-relative `logical` block to a physical block,
    /// honouring already-staged extent-tree edits. Exposed for htree
    /// directory surgery, which navigates directory-logical blocks.
    pub(crate) fn resolve_dir_block<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        dir: &CurrentDirInode,
        logical: u32,
    ) -> MutatorResult<u64> {
        resolve_dir_logical_block(self.ext, fs, dir, logical)
    }

    /// Append one entry to a linear directory block (`physical`), splitting
    /// the trailing entry's `rec_len` slack. Returns `false` when the block
    /// has no room. Exposed for htree leaf maintenance.
    pub(crate) fn dir_leaf_append<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        ctx: DirLeafAppendCtx<'_>,
        physical: u64,
    ) -> MutatorResult<bool> {
        let has_filetype = self.ext.has_filetype();
        let checksum_seed = self.ext.checksum_seed();
        let required_len = aligned_dir_entry_len(ctx.name.len()).ok_or(MutatorError::Ext(
            ExtError::InvalidDirectoryEntry {
                inode: ctx.parent_inum,
                offset: 0,
            },
        ))?;
        let (block, _) = self.current_block_bytes(fs, physical)?;
        validate_dir_tail_checksum(
            checksum_seed,
            ctx.parent_inum,
            ctx.parent_generation,
            &block,
        )?;
        let Some(slot) = find_dir_append_slot(&block, has_filetype, ctx.parent_inum, required_len)?
        else {
            return Ok(false);
        };
        let parent_inum = ctx.parent_inum;
        let parent_generation = ctx.parent_generation;
        self.patch_directory_block(fs, physical, parent_inum, |dir_block| {
            apply_dir_append_slot(
                dir_block,
                slot,
                ctx.child_inum,
                ctx.name,
                ctx.file_type,
                has_filetype,
                parent_inum,
            )?;
            refresh_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, dir_block);
            Ok(())
        })?;
        Ok(true)
    }

    /// Remove one entry from a linear directory block (`physical`). Returns
    /// `false` when the name+inode pair is not present. Exposed for htree
    /// leaf maintenance.
    pub(crate) fn dir_leaf_remove<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        parent_inum: u32,
        parent_generation: u32,
        child_inum: u32,
        name: &[u8],
        physical: u64,
    ) -> MutatorResult<bool> {
        let has_filetype = self.ext.has_filetype();
        let checksum_seed = self.ext.checksum_seed();
        let (block, _) = self.current_block_bytes(fs, physical)?;
        validate_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, &block)?;
        let Some(slot) = find_dir_remove_slot(&block, has_filetype, parent_inum, child_inum, name)?
        else {
            return Ok(false);
        };
        self.patch_directory_block(fs, physical, parent_inum, |dir_block| {
            apply_dir_remove_slot(dir_block, slot, parent_inum)?;
            refresh_dir_tail_checksum(checksum_seed, parent_inum, parent_generation, dir_block);
            Ok(())
        })?;
        Ok(true)
    }

    /// Replace the full content of directory block `physical` with `bytes`,
    /// recording it as a directory block. The caller must have already set
    /// the dir-tail checksum (htree leaf rewrites do this inline).
    pub(crate) fn write_dir_block<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        parent_inum: u32,
        physical: u64,
        bytes: &[u8],
    ) -> MutatorResult<()> {
        self.patch_directory_block(fs, physical, parent_inum, |dir_block| {
            if dir_block.len() != bytes.len() {
                return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: physical,
                }));
            }
            dir_block.copy_from_slice(bytes);
            Ok(())
        })
    }

    /// Clear the inode-bitmap bit for `inum` on scratch. Tallies the
    /// decrement for the containing group (plus `dirs_freed` when
    /// `was_dir`). Bits already clear are silent no-ops — no tally
    /// increment. Locates the bitmap block via the group descriptor, so
    /// callers do not need to pre-seed.
    pub(crate) fn clear_inode_bitmap_bit<T: Read + Seek>(
        &mut self,
        overlay: &mut T,
        inum: u32,
        was_dir: bool,
    ) -> MutatorResult<()> {
        if inum == 0 || u64::from(inum) > u64::from(self.ext.inodes_count) {
            return Err(MutatorError::Ext(ExtError::InodeOutOfRange { inode: inum }));
        }
        let group = self.group_of_inode(inum);
        let index_in_group = (inum - 1) % self.ext.inodes_per_group;
        let bitmap_block = self
            .ext
            .group_descs
            .get(group as usize)
            .ok_or(MutatorError::Ext(ExtError::InodeOutOfRange { inode: inum }))?
            .inode_bitmap;
        let scratch = self.seed_block(overlay, bitmap_block, BlockClass::InodeBitmap { group })?;

        let byte = (index_in_group / 8) as usize;
        let bit = (index_in_group % 8) as u8;
        let mask = 1u8 << bit;
        if scratch.content[byte] & mask != 0 {
            scratch.content[byte] &= !mask;
            let tally = self.group_tallies.entry(group).or_default();
            tally.inodes_freed = tally.inodes_freed.saturating_add(1);
            if was_dir {
                tally.dirs_freed = tally.dirs_freed.saturating_add(1);
            }
            self.total_inodes_freed = self.total_inodes_freed.saturating_add(1);
        }
        Ok(())
    }

    /// Free the physical allocations described by `runs`. Clears block /
    /// cluster bitmap bits, tallies per-group cluster decrements, updates
    /// `total_clusters_freed`. Idempotent: already-clear bits are silent
    /// no-ops.
    ///
    /// On bigalloc filesystems, additionally verifies that no two `Data`
    /// allocations in `runs` map to the same physical cluster from
    /// different logical cluster slots — returns
    /// `MutatorError::BigallocClusterOverlap` on conflict. `Metadata`
    /// runs skip the overlap check but still participate in cluster
    /// accounting.
    ///
    /// `inode` is used as the inode witness in overlap errors; it has no
    /// semantic effect on successful frees.
    pub(crate) fn free_allocations<T: Read + Seek>(
        &mut self,
        overlay: &mut T,
        inode: u32,
        runs: &[AllocationRun],
    ) -> MutatorResult<()> {
        let blocks_per_cluster = u64::from(self.ext.blocks_per_cluster);
        let first_data_block = u64::from(self.ext.first_data_block);
        let blocks_per_group = u64::from(self.ext.blocks_per_group);

        // Pass 1: detect Data-run logical-cluster overlaps; collect unique clusters.
        let mut cluster_owners: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        let mut clusters_to_free: BTreeMap<u64, u64> = BTreeMap::new();

        for run in runs {
            for off in 0..u64::from(run.block_len) {
                let phys = run
                    .physical_start
                    .checked_add(off)
                    .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                        block: run.physical_start,
                    }))?;
                if phys >= self.ext.blocks_count {
                    return Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: phys }));
                }
                let phys_rel = phys
                    .checked_sub(first_data_block)
                    .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: phys }))?;
                let cluster = phys_rel / blocks_per_cluster;
                match run.kind {
                    AllocationKind::Data {
                        logical_cluster_start,
                    } => {
                        let logical_cluster = logical_cluster_start
                            .checked_add(off / blocks_per_cluster)
                            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: phys }))?;
                        if let Some(&(existing_lc, existing_block)) = cluster_owners.get(&cluster) {
                            if existing_lc != logical_cluster {
                                return Err(MutatorError::BigallocClusterOverlap {
                                    inode,
                                    cluster,
                                    first_block: existing_block,
                                    second_block: phys,
                                });
                            }
                        } else {
                            cluster_owners.insert(cluster, (logical_cluster, phys));
                        }
                    }
                    AllocationKind::Metadata => {}
                }
                clusters_to_free.entry(cluster).or_insert(phys);
            }
        }

        // Pass 2: for each unique cluster, clear the bitmap bit and tally.
        for (cluster, repr_block) in clusters_to_free {
            let repr_rel = repr_block
                .checked_sub(first_data_block)
                .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: repr_block,
                }))?;
            let group = (repr_rel / blocks_per_group) as u32;
            let block_bitmap = self
                .ext
                .group_descs
                .get(group as usize)
                .ok_or(MutatorError::Ext(ExtError::InodeOutOfRange { inode }))?
                .block_bitmap;
            let scratch =
                self.seed_block(overlay, block_bitmap, BlockClass::BlockBitmap { group })?;

            let cluster_in_group = cluster
                .checked_sub(u64::from(group) * blocks_per_group / blocks_per_cluster)
                .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: repr_block,
                }))?;
            let byte = (cluster_in_group / 8) as usize;
            let bit = (cluster_in_group % 8) as u8;
            let mask = 1u8 << bit;
            if scratch.content[byte] & mask != 0 {
                scratch.content[byte] &= !mask;
                let tally = self.group_tallies.entry(group).or_default();
                tally.clusters_freed = tally.clusters_freed.saturating_add(1);
                self.total_clusters_freed = self.total_clusters_freed.saturating_add(1);
            }
        }

        Ok(())
    }

    /// Mark `block_len` filesystem blocks at physical block `pblk` as free in
    /// the block bitmap. Returns the number of allocation units that actually
    /// changed state.
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub(crate) fn mark_block_range_free<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        pblk: u64,
        block_len: u32,
    ) -> MutatorResult<u32> {
        self.mark_block_range_state(fs, pblk, block_len, false)
    }

    /// Mark `block_len` filesystem blocks at physical block `pblk` as allocated
    /// in the block bitmap. Returns the number of allocation units that actually
    /// changed state.
    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    pub(crate) fn mark_block_range_allocated<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        pblk: u64,
        block_len: u32,
    ) -> MutatorResult<u32> {
        self.mark_block_range_state(fs, pblk, block_len, true)
    }

    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    fn mark_block_range_state<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        pblk: u64,
        block_len: u32,
        alloc: bool,
    ) -> MutatorResult<u32> {
        let first_data_block = u64::from(self.ext.first_data_block);
        if pblk < first_data_block {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }));
        }
        if block_len == 0 {
            return Ok(0);
        }
        let end_block = pblk
            .checked_add(u64::from(block_len))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;
        if pblk >= self.ext.blocks_count || end_block > self.ext.blocks_count {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: end_block,
            }));
        }

        let ratio = u64::from(self.ext.blocks_per_cluster).max(1);
        let (mut alloc_unit, total_count) =
            project_block_range_to_alloc_units(pblk, block_len, ratio, first_data_block)?;
        let clusters_per_group = allocation_units_per_group(self.ext, ratio)?;
        let end_alloc_unit = alloc_unit
            .checked_add(total_count)
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;

        let mut changed_total = 0u32;
        while alloc_unit < end_alloc_unit {
            let group = (alloc_unit / clusters_per_group) as u32;
            let group_start = u64::from(group) * clusters_per_group;
            let group_end = group_start.saturating_add(clusters_per_group);
            let run_end = end_alloc_unit.min(group_end);
            let count = run_end - alloc_unit;

            if group as usize >= self.ext.group_descs.len() {
                return Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }));
            }
            self.ensure_block_group_initialized(fs, group)?;

            let block_bitmap = self.ext.group_descs[group as usize].block_bitmap;
            let scratch = self.seed_block(fs, block_bitmap, BlockClass::BlockBitmap { group })?;
            let bit_start = alloc_unit - group_start;
            let changed = mark_bitmap_bits(&mut scratch.content, bit_start, count, alloc)?;

            if changed > 0 {
                let tally = self.group_tallies.entry(group).or_default();
                if alloc {
                    tally.clusters_allocated =
                        tally.clusters_allocated.saturating_add(u64::from(changed));
                } else {
                    tally.clusters_freed = tally.clusters_freed.saturating_add(u64::from(changed));
                }
                changed_total = changed_total.saturating_add(changed);
            }

            alloc_unit = run_end;
        }

        Ok(changed_total)
    }

    #[allow(dead_code, reason = "consumed by fast-commit replay")]
    fn ensure_block_group_initialized<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        group: u32,
    ) -> MutatorResult<()> {
        const EXT4_BG_BLOCK_UNINIT: u16 = 0x0002;

        let Some(gdp) = self.ext.group_descs.get(group as usize) else {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: u64::from(group) * u64::from(self.ext.blocks_per_group),
            }));
        };
        if gdp.flags & EXT4_BG_BLOCK_UNINIT == 0 {
            return Ok(());
        }
        if self.initialized_block_groups.contains(&group) {
            return Ok(());
        }

        let block_bitmap = gdp.block_bitmap;
        let initialized_free = crate::block_group::free_clusters_after_init(self.ext, group, gdp);
        let mut reserved_units = BTreeSet::new();
        crate::block_group::reserve_metadata_allocation_units(
            self.ext,
            group,
            gdp,
            &mut reserved_units,
        );
        let real_units = crate::block_group::allocation_units_in_group(self.ext, group);
        let bitmap_scratch =
            self.seed_block(fs, block_bitmap, BlockClass::BlockBitmap { group })?;
        bitmap_scratch.content.fill(0);
        for unit in reserved_units {
            mark_bitmap_bits(&mut bitmap_scratch.content, unit, 1, true)?;
        }
        let bitmap_bits = (bitmap_scratch.content.len() * 8) as u64;
        if real_units < bitmap_bits {
            mark_bitmap_bits(
                &mut bitmap_scratch.content,
                real_units,
                bitmap_bits - real_units,
                true,
            )?;
        }

        let (gdt_block, offset_in_block, desc_size) = self.group_desc_slot(group)?;
        let desc_block_nr = group / self.ext.gdt_layout.desc_per_block();
        let scratch =
            self.seed_block(fs, gdt_block, BlockClass::GroupDescriptor { desc_block_nr })?;
        let desc_bytes = &mut scratch.content[offset_in_block..offset_in_block + desc_size];
        let flags = read_desc_u16(desc_bytes, 0x12) & !EXT4_BG_BLOCK_UNINIT;
        write_desc_u16(desc_bytes, 0x12, flags);
        write_desc_u32_split(
            desc_bytes,
            0x0C,
            (desc_size >= 64).then_some(0x2C),
            initialized_free,
        );
        self.initialized_block_groups.insert(group);
        Ok(())
    }

    /// Allocate one free metadata block, marking it allocated in the block
    /// bitmap scratch. Scans block groups starting from `near_inum`'s group,
    /// then outward, for locality. On bigalloc the unit is a cluster and the
    /// returned physical block is cluster-aligned. Returns the physical block
    /// number; the caller is expected to immediately overwrite the block's
    /// content via `patch_extent_block` (or similar). The allocation is staged
    /// in scratch only, so it rolls back when the mutator is dropped.
    pub(crate) fn allocate_metadata_block<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        near_inum: u32,
    ) -> MutatorResult<u64> {
        let group_count = self.ext.group_descs.len();
        if group_count == 0 {
            return Err(MutatorError::Ext(ExtError::InvalidSuperblock {
                reason: "no block groups",
            }));
        }
        let start_group = if near_inum == 0 || near_inum > self.ext.inodes_count {
            0
        } else {
            self.group_of_inode(near_inum)
        };
        for offset in 0..group_count {
            let group = ((start_group as usize + offset) % group_count) as u32;
            if let Some(pblk) = self.try_allocate_in_group(fs, group)? {
                return Ok(pblk);
            }
        }
        Err(MutatorError::Ext(ExtError::BlockOutOfRange {
            block: self.ext.blocks_count,
        }))
    }

    /// Scan one block group's bitmap for a free allocation unit. Returns the
    /// physical block of the first free unit and marks it allocated, or `None`
    /// if the group is full.
    fn try_allocate_in_group<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        group: u32,
    ) -> MutatorResult<Option<u64>> {
        let real_units = crate::block_group::allocation_units_in_group(self.ext, group);
        if real_units == 0 {
            return Ok(None);
        }
        self.ensure_block_group_initialized(fs, group)?;
        let block_bitmap = self.ext.group_descs[group as usize].block_bitmap;
        let scratch = self.seed_block(fs, block_bitmap, BlockClass::BlockBitmap { group })?;
        let mut free_unit = None;
        for unit in 0..real_units {
            let byte = (unit / 8) as usize;
            let mask = 1u8 << (unit % 8);
            if scratch
                .content
                .get(byte)
                .is_some_and(|slot| slot & mask == 0)
            {
                free_unit = Some(unit);
                break;
            }
        }
        let Some(unit) = free_unit else {
            return Ok(None);
        };

        let ratio = u64::from(self.ext.blocks_per_cluster).max(1);
        let clusters_per_group = allocation_units_per_group(self.ext, ratio)?;
        let global_unit = u64::from(group)
            .checked_mul(clusters_per_group)
            .and_then(|base| base.checked_add(unit))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: self.ext.blocks_count,
            }))?;
        let pblk = global_unit
            .checked_mul(ratio)
            .and_then(|rel| rel.checked_add(u64::from(self.ext.first_data_block)))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: self.ext.blocks_count,
            }))?;
        if pblk >= self.ext.blocks_count {
            return Ok(None);
        }
        self.mark_block_range_allocated(fs, pblk, 1)?;
        Ok(Some(pblk))
    }

    /// Consume the mutator. Materializes accumulated tallies into group-
    /// descriptor and sb-host scratch, then recomputes every required
    /// checksum. Returns the composed delta; `sb_host_override` is
    /// populated only when `patch_superblock_bytes` was called or when
    /// free-count tallies produced sb changes (`total_clusters_freed > 0`
    /// or `total_inodes_freed > 0`).
    pub(crate) fn finalize<T: Read + Seek>(
        mut self,
        overlay: &mut T,
    ) -> MutatorResult<crate::orphan::plan::OrphanOverlayDelta> {
        // Phase 1: collect all groups that need a GDT scratch entry — either
        // because they have a tally change, or because a bitmap scratch paired
        // with this group exists.
        let mut dirty_groups: BTreeSet<u32> = BTreeSet::new();
        for &group in self.group_tallies.keys() {
            dirty_groups.insert(group);
        }
        for scratch in self.blocks.values() {
            match scratch.class {
                BlockClass::BlockBitmap { group } | BlockClass::InodeBitmap { group } => {
                    dirty_groups.insert(group);
                }
                _ => {}
            }
        }

        // Snapshot tallies to avoid simultaneous borrows through seed_block.
        let tallies_snapshot: alloc::vec::Vec<(u32, GroupTally)> =
            self.group_tallies.iter().map(|(&g, t)| (g, *t)).collect();

        // Materialize GDT scratch for each dirty group and apply tally changes.
        let dirty_copy: alloc::vec::Vec<u32> = dirty_groups.iter().copied().collect();
        for &group in &dirty_copy {
            let (gdt_block, offset_in_block, desc_size) = self.group_desc_slot(group)?;
            let desc_block_nr = group / self.ext.gdt_layout.desc_per_block();
            let class = BlockClass::GroupDescriptor { desc_block_nr };
            self.seed_block(overlay, gdt_block, class)?;
            if let Some(&(_, tally)) = tallies_snapshot.iter().find(|&&(g, _)| g == group) {
                let scratch = self.blocks.get_mut(&gdt_block).expect("just seeded");
                let desc_bytes = &mut scratch.content[offset_in_block..offset_in_block + desc_size];
                apply_group_tally(self.ext, desc_bytes, tally);
            }
        }

        // Phase 2: apply sb totals when any group tally is non-zero.
        if self.total_clusters_freed > 0 || self.total_inodes_freed > 0 {
            apply_sb_tallies(
                self.ext,
                &mut self.sb_host_scratch,
                self.total_clusters_freed,
                self.total_inodes_freed,
            );
            self.sb_dirty = true;
        }

        // Phase 3: per-block checksum recompute.
        recompute_block_checksums(self.ext, &mut self.blocks)?;

        // Phase 4: GDT bitmap-csum updates and per-group bg_checksum recompute.
        recompute_group_descriptor_checksums(self.ext, &mut self.blocks, &dirty_groups)?;

        // Phase 5: superblock checksum.
        if self.sb_dirty && self.ext.has_metadata_csum() {
            // The superblock occupies bytes 1024..2048 of block 0 on filesystems
            // with block_size > 1024, or bytes 0..1024 of block 1 on 1 KiB
            // filesystems. compute_superblock_csum takes exactly 1024 bytes.
            let sb_offset: usize = if self.ext.block_size > 1024 { 1024 } else { 0 };
            let new_sum = {
                let sb_region: &[u8] = &self.sb_host_scratch[sb_offset..sb_offset + 1024];
                let sb_array: &[u8; 1024] = sb_region
                    .try_into()
                    .expect("sb region is exactly 1024 bytes");
                crate::checksum::compute_superblock_csum(sb_array)
            };
            // s_checksum at offset 0x3FC within the 1024-byte superblock.
            let abs = sb_offset + 0x3FC;
            self.sb_host_scratch[abs..abs + 4].copy_from_slice(&new_sum.to_le_bytes());
        }

        // Phase 6: assemble delta.
        let sb_host_override = if self.sb_dirty {
            Some(self.sb_host_scratch)
        } else {
            None
        };
        let blocks = self
            .blocks
            .into_iter()
            .map(|(k, v)| (k, v.content))
            .collect();

        Ok(crate::orphan::plan::OrphanOverlayDelta {
            blocks,
            sb_host_override,
        })
    }

    /// Return `(gdt_block_num, byte_offset_within_block, desc_size_in_bytes)`
    /// for the group descriptor of `group`.
    fn group_desc_slot(&self, group: u32) -> MutatorResult<(u64, usize, usize)> {
        let layout = &self.ext.gdt_layout;
        let desc_size = u64::from(layout.desc_size());
        let block_size = u64::from(layout.block_size());
        let gdt_block = crate::block_group::descriptor_block_for_group(layout, group);
        let byte_offset_in_block = u64::from(group % layout.desc_per_block()) * desc_size;
        let offset = (byte_offset_in_block % block_size) as usize;
        Ok((gdt_block, offset, desc_size as usize))
    }

    /// Test shim: returns the count of `BlockBitmap` scratch entries. Used by
    /// truncate tests to assert that at least one block bitmap was dirtied.
    #[cfg(test)]
    pub(crate) fn block_bitmap_scratch_count(&self) -> usize {
        self.blocks
            .values()
            .filter(|s| matches!(s.class, BlockClass::BlockBitmap { .. }))
            .count()
    }

    /// Test shim: exposes `total_clusters_freed` for cascade-free assertions.
    #[cfg(test)]
    pub(crate) fn total_clusters_freed_for_test(&self) -> u64 {
        self.total_clusters_freed
    }

    /// Test shim: returns the in-memory scratch bytes for `block`, or `None`
    /// if no scratch was created for that physical block during the apply
    /// run. Used by EA-inode bigalloc tests to confirm the expected bitmap
    /// bits were actually cleared.
    #[cfg(test)]
    pub(crate) fn block_scratch_bytes_for_test(&self, block: u64) -> Option<&[u8]> {
        self.blocks.get(&block).map(|s| s.content.as_ref())
    }

    /// Test shim: exposes `inode_table_slot` for verifying the expected block number.
    #[cfg(test)]
    pub(crate) fn inode_table_slot_for_test(
        ext: &Ext,
        inum: u32,
    ) -> MutatorResult<(u64, usize, usize)> {
        if inum == 0 || inum > ext.inodes_count {
            return Err(MutatorError::Ext(ExtError::InodeOutOfRange { inode: inum }));
        }
        let group = (inum - 1) / ext.inodes_per_group;
        let index_in_group = u64::from((inum - 1) % ext.inodes_per_group);
        let inode_size = u64::from(ext.inode_size());
        let byte_in_table = index_in_group * inode_size;
        let block_size = u64::from(ext.block_size());
        let table_block = ext.group_descs[group as usize].inode_table;
        let block = table_block + byte_in_table / block_size;
        let offset_in_block = (byte_in_table % block_size) as usize;
        Ok((block, offset_in_block, inode_size as usize))
    }
}

fn resolve_dir_logical_block<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: &CurrentDirInode,
    logical_block: u32,
) -> MutatorResult<u64> {
    let physical = if inode.flags.contains(crate::inode::InodeFlags::EXTENTS_FL) {
        let extent = crate::extent::resolve_extent(
            ext,
            fs,
            inode.number,
            inode.generation,
            &inode.i_block,
            logical_block,
        )?
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
            block: u64::from(logical_block),
        }))?;
        if extent.uninitialized {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            }));
        }
        let blocks_into =
            logical_block
                .checked_sub(extent.logical_block)
                .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                    block: u64::from(logical_block),
                }))?;
        extent
            .physical_block
            .checked_add(u64::from(blocks_into))
            .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: extent.physical_block,
            }))?
    } else {
        crate::block_map::resolve_block_map(ext, fs, &inode.i_block, logical_block)?.ok_or(
            MutatorError::Ext(ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            }),
        )?
    };

    if physical >= ext.blocks_count {
        return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
            block: physical,
        }));
    }
    Ok(physical)
}

fn find_dir_append_slot(
    block: &[u8],
    has_filetype: bool,
    parent_inum: u32,
    required_len: usize,
) -> MutatorResult<Option<DirAppendSlot>> {
    let usable_end = directory_entry_region_end(block);
    let mut offset = 0usize;
    let mut last_real: Option<(usize, usize, usize, u16)> = None;

    while offset < usable_end {
        if offset + 8 > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
        if rec_len < 8 || rec_len % 4 != 0 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let rec_len_usize = usize::from(rec_len);
        let next_offset = offset
            .checked_add(rec_len_usize)
            .ok_or(invalid_dir_entry(parent_inum, offset))?;
        if next_offset > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().unwrap(),
            ))
        };
        if name_len > rec_len_usize - 8 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        if inode != 0 {
            let min_len =
                aligned_dir_entry_len(name_len).ok_or(invalid_dir_entry(parent_inum, offset))?;
            if min_len > rec_len_usize {
                return Err(invalid_dir_entry(parent_inum, offset));
            }
            last_real = Some((offset, next_offset, min_len, rec_len));
        }

        offset = next_offset;
    }

    let Some((last_offset, last_next, min_len, rec_len)) = last_real else {
        return Ok(None);
    };
    if last_next != usable_end {
        return Ok(None);
    }

    let slack = usize::from(rec_len)
        .checked_sub(min_len)
        .ok_or(invalid_dir_entry(parent_inum, last_offset))?;
    if slack < required_len {
        return Ok(None);
    }

    Ok(Some(DirAppendSlot {
        last_entry_offset: last_offset,
        shrunk_last_rec_len: u16::try_from(min_len)
            .map_err(|_| invalid_dir_entry(parent_inum, last_offset))?,
        new_entry_offset: last_offset + min_len,
        new_entry_rec_len: u16::try_from(slack)
            .map_err(|_| invalid_dir_entry(parent_inum, last_offset))?,
    }))
}

fn apply_dir_append_slot(
    block: &mut [u8],
    slot: DirAppendSlot,
    child_inum: u32,
    name: &[u8],
    file_type: u8,
    has_filetype: bool,
    parent_inum: u32,
) -> MutatorResult<()> {
    let new_entry_end = slot.new_entry_offset + usize::from(slot.new_entry_rec_len);
    let name_end = slot.new_entry_offset + 8 + name.len();
    if slot.last_entry_offset + 8 > block.len()
        || new_entry_end > block.len()
        || name_end > new_entry_end
    {
        return Err(invalid_dir_entry(parent_inum, slot.last_entry_offset));
    }

    block[slot.last_entry_offset + 4..slot.last_entry_offset + 6]
        .copy_from_slice(&slot.shrunk_last_rec_len.to_le_bytes());

    block[slot.new_entry_offset..new_entry_end].fill(0);
    block[slot.new_entry_offset..slot.new_entry_offset + 4]
        .copy_from_slice(&child_inum.to_le_bytes());
    block[slot.new_entry_offset + 4..slot.new_entry_offset + 6]
        .copy_from_slice(&slot.new_entry_rec_len.to_le_bytes());
    if has_filetype {
        block[slot.new_entry_offset + 6] = name.len() as u8;
        block[slot.new_entry_offset + 7] = file_type;
    } else {
        block[slot.new_entry_offset + 6..slot.new_entry_offset + 8]
            .copy_from_slice(&(name.len() as u16).to_le_bytes());
    }
    block[slot.new_entry_offset + 8..name_end].copy_from_slice(name);
    Ok(())
}

fn find_dir_remove_slot(
    block: &[u8],
    has_filetype: bool,
    parent_inum: u32,
    child_inum: u32,
    name: &[u8],
) -> MutatorResult<Option<DirRemoveSlot>> {
    let usable_end = directory_entry_region_end(block);
    let mut offset = 0usize;
    let mut prev: Option<(usize, u16)> = None;

    while offset < usable_end {
        if offset + 8 > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
        if rec_len < 8 || rec_len % 4 != 0 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let rec_len_usize = usize::from(rec_len);
        let next_offset = offset
            .checked_add(rec_len_usize)
            .ok_or(invalid_dir_entry(parent_inum, offset))?;
        if next_offset > usable_end {
            return Err(invalid_dir_entry(parent_inum, offset));
        }

        let name_len = if has_filetype {
            usize::from(block[offset + 6])
        } else {
            usize::from(u16::from_le_bytes(
                block[offset + 6..offset + 8].try_into().unwrap(),
            ))
        };
        if name_len > rec_len_usize - 8 {
            return Err(invalid_dir_entry(parent_inum, offset));
        }
        let name_end = offset + 8 + name_len;
        if inode == child_inum && &block[offset + 8..name_end] == name {
            let Some((prev_offset, _)) = prev else {
                if offset == 0 {
                    return Ok(Some(DirRemoveSlot::ClearCurrentInode {
                        current_offset: offset,
                    }));
                }
                return Err(invalid_dir_entry(parent_inum, offset));
            };
            return Ok(Some(DirRemoveSlot::MergeIntoPrev {
                prev_offset,
                current_offset: offset,
                current_rec_len: rec_len,
            }));
        }

        prev = Some((offset, rec_len));
        offset = next_offset;
    }

    Ok(None)
}

fn apply_dir_remove_slot(
    block: &mut [u8],
    slot: DirRemoveSlot,
    parent_inum: u32,
) -> MutatorResult<()> {
    match slot {
        DirRemoveSlot::MergeIntoPrev {
            prev_offset,
            current_offset,
            current_rec_len,
        } => {
            if prev_offset + 6 > block.len()
                || current_offset + usize::from(current_rec_len) > block.len()
            {
                return Err(invalid_dir_entry(parent_inum, prev_offset));
            }
            let prev_rec_len =
                u16::from_le_bytes(block[prev_offset + 4..prev_offset + 6].try_into().unwrap());
            if prev_rec_len < 8
                || prev_rec_len % 4 != 0
                || prev_offset + usize::from(prev_rec_len) != current_offset
            {
                return Err(invalid_dir_entry(parent_inum, prev_offset));
            }
            let merged_prev_rec_len = prev_rec_len
                .checked_add(current_rec_len)
                .ok_or(invalid_dir_entry(parent_inum, prev_offset))?;
            block[prev_offset + 4..prev_offset + 6]
                .copy_from_slice(&merged_prev_rec_len.to_le_bytes());
        }
        DirRemoveSlot::ClearCurrentInode { current_offset } => {
            if current_offset + 4 > block.len() {
                return Err(invalid_dir_entry(parent_inum, current_offset));
            }
            block[current_offset..current_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        }
    }
    Ok(())
}

fn validate_dir_tail_checksum(
    seed: Option<u32>,
    parent_inum: u32,
    parent_generation: u32,
    block: &[u8],
) -> MutatorResult<()> {
    let Some(seed) = seed else {
        return Ok(());
    };
    let Some(tail_offset) = directory_tail_offset(block) else {
        return Ok(());
    };

    if crate::checksum::verify_dir_block(seed, parent_inum, parent_generation, block)
        == crate::checksum::ChecksumState::Invalid
    {
        return Err(invalid_dir_entry(parent_inum, tail_offset));
    }
    Ok(())
}

fn refresh_dir_tail_checksum(
    seed: Option<u32>,
    parent_inum: u32,
    parent_generation: u32,
    block: &mut [u8],
) {
    let Some(seed) = seed else {
        return;
    };
    let Some(tail_offset) = directory_tail_offset(block) else {
        return;
    };

    let crc = crate::checksum::ext4_crc32c(seed, &parent_inum.to_le_bytes());
    let crc = crate::checksum::ext4_crc32c(crc, &parent_generation.to_le_bytes());
    let crc = crate::checksum::ext4_crc32c(crc, &block[..tail_offset]);
    block[tail_offset + 8..tail_offset + 12].copy_from_slice(&crc.to_le_bytes());
}

fn aligned_dir_entry_len(name_len: usize) -> Option<usize> {
    8usize
        .checked_add(name_len)
        .and_then(|len| len.checked_add(3))
        .map(|len| len & !3)
}

fn directory_entry_region_end(block: &[u8]) -> usize {
    directory_tail_offset(block).unwrap_or(block.len())
}

fn directory_tail_offset(block: &[u8]) -> Option<usize> {
    if block.len() >= 12 {
        let tail_offset = block.len() - 12;
        let tail = &block[tail_offset..];
        let inode = u32::from_le_bytes(tail[0..4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(tail[4..6].try_into().unwrap());
        if inode == 0 && rec_len == 12 && tail[6] == 0 && tail[7] == 0xDE {
            return Some(tail_offset);
        }
    }
    None
}

fn invalid_dir_entry(parent_inum: u32, offset: usize) -> MutatorError {
    MutatorError::Ext(ExtError::InvalidDirectoryEntry {
        inode: parent_inum,
        offset: offset as u64,
    })
}

/// Apply a group tally's freed counts to a raw group descriptor byte slice.
///
/// Modifies the lo and (when 64-bit) hi halves of `bg_free_blocks_count`,
/// `bg_free_inodes_count`, and `bg_used_dirs_count` in place.
///
/// Offsets (per ext4 on-disk layout):
/// - `bg_free_blocks_count_lo` at 0x0C, `_hi` at 0x2C
/// - `bg_free_inodes_count_lo` at 0x0E, `_hi` at 0x2E
/// - `bg_used_dirs_count_lo`   at 0x10, `_hi` at 0x30
fn apply_group_tally(ext: &Ext, desc_bytes: &mut [u8], tally: GroupTally) {
    let is_64 = ext.desc_size >= 64;

    // bg_free_blocks_count: add clusters_freed, subtract clusters_allocated.
    let hi_off = is_64.then_some(0x2C);
    let current = read_desc_u32_split(desc_bytes, 0x0C, hi_off);
    let updated = current
        .saturating_add(tally.clusters_freed as u32)
        .saturating_sub(tally.clusters_allocated as u32);
    write_desc_u32_split(desc_bytes, 0x0C, hi_off, updated);

    // bg_free_inodes_count: add inodes_freed.
    let hi_off = is_64.then_some(0x2E);
    let current = read_desc_u32_split(desc_bytes, 0x0E, hi_off);
    write_desc_u32_split(
        desc_bytes,
        0x0E,
        hi_off,
        current.saturating_add(tally.inodes_freed),
    );

    // bg_used_dirs_count: subtract dirs_freed.
    let hi_off = is_64.then_some(0x30);
    let current = read_desc_u32_split(desc_bytes, 0x10, hi_off);
    write_desc_u32_split(
        desc_bytes,
        0x10,
        hi_off,
        current.saturating_sub(tally.dirs_freed),
    );
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
fn project_block_range_to_alloc_units(
    pblk: u64,
    block_len: u32,
    ratio: u64,
    first_data_block: u64,
) -> MutatorResult<(u64, u64)> {
    if ratio == 0 {
        return Err(MutatorError::Ext(ExtError::InvalidSuperblock {
            reason: "blocks_per_cluster is zero",
        }));
    }
    let rel_start = pblk
        .checked_sub(first_data_block)
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;
    if block_len == 0 {
        return Ok((rel_start / ratio, 0));
    }
    let rel_end = rel_start
        .checked_add(u64::from(block_len))
        .ok_or(MutatorError::Ext(ExtError::BlockOutOfRange { block: pblk }))?;
    let first = rel_start / ratio;
    let last_excl = rel_end.div_ceil(ratio);
    Ok((first, last_excl - first))
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
fn allocation_units_per_group(ext: &Ext, ratio: u64) -> MutatorResult<u64> {
    let clusters_per_group = if ext.clusters_per_group != 0 {
        u64::from(ext.clusters_per_group)
    } else {
        u64::from(ext.blocks_per_group) / ratio
    };
    if clusters_per_group == 0 {
        return Err(MutatorError::Ext(ExtError::InvalidSuperblock {
            reason: "clusters_per_group is zero",
        }));
    }
    Ok(clusters_per_group)
}

#[allow(dead_code, reason = "consumed by fast-commit replay")]
fn mark_bitmap_bits(
    bitmap: &mut [u8],
    bit_start: u64,
    count: u64,
    alloc: bool,
) -> MutatorResult<u32> {
    let mut changed = 0u32;
    for bit_index in bit_start..bit_start.saturating_add(count) {
        let byte = (bit_index / 8) as usize;
        let Some(slot) = bitmap.get_mut(byte) else {
            return Err(MutatorError::Ext(ExtError::BlockOutOfRange {
                block: bit_index,
            }));
        };
        let mask = 1u8 << (bit_index % 8);
        let already_allocated = *slot & mask != 0;
        if alloc {
            if !already_allocated {
                *slot |= mask;
                changed = changed.saturating_add(1);
            }
        } else if already_allocated {
            *slot &= !mask;
            changed = changed.saturating_add(1);
        }
    }
    Ok(changed)
}

fn read_le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn read_le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_desc_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn write_desc_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn read_desc_u32_split(bytes: &[u8], off_lo: usize, off_hi: Option<usize>) -> u32 {
    let lo = read_desc_u16(bytes, off_lo) as u32;
    let hi = off_hi.map(|o| read_desc_u16(bytes, o) as u32).unwrap_or(0);
    (hi << 16) | lo
}

fn write_desc_u32_split(bytes: &mut [u8], off_lo: usize, off_hi: Option<usize>, value: u32) {
    write_desc_u16(bytes, off_lo, value as u16);
    if let Some(o) = off_hi {
        write_desc_u16(bytes, o, (value >> 16) as u16);
    }
}

/// Apply accumulated free-count totals to the raw sb-host block bytes.
///
/// Modifies `s_free_blocks_count_lo` (0x0C) and `_hi` (0x150 if 64-bit),
/// and `s_free_inodes_count` (0x10) within the 1024-byte superblock region.
fn apply_sb_tallies(ext: &Ext, sb_bytes: &mut [u8], clusters_freed: u64, inodes_freed: u64) {
    // The superblock occupies bytes 1024..2048 on >1 KiB-block filesystems,
    // or bytes 0..1024 on 1 KiB-block filesystems. All sb field offsets below
    // are relative to the start of the 1024-byte superblock region.
    let sb_off: usize = if ext.block_size > 1024 { 1024 } else { 0 };

    let current_lo = u32::from_le_bytes(sb_bytes[sb_off + 0x0C..sb_off + 0x10].try_into().unwrap());
    let current_hi = if ext.is_64bit {
        u32::from_le_bytes(sb_bytes[sb_off + 0x150..sb_off + 0x154].try_into().unwrap())
    } else {
        0
    };
    let current_blocks = (u64::from(current_hi) << 32) | u64::from(current_lo);
    let new_blocks = current_blocks.saturating_add(clusters_freed);
    sb_bytes[sb_off + 0x0C..sb_off + 0x10].copy_from_slice(&(new_blocks as u32).to_le_bytes());
    if ext.is_64bit {
        sb_bytes[sb_off + 0x150..sb_off + 0x154]
            .copy_from_slice(&((new_blocks >> 32) as u32).to_le_bytes());
    }

    let current_inodes =
        u32::from_le_bytes(sb_bytes[sb_off + 0x10..sb_off + 0x14].try_into().unwrap());
    let new_inodes = u64::from(current_inodes).saturating_add(inodes_freed) as u32;
    sb_bytes[sb_off + 0x10..sb_off + 0x14].copy_from_slice(&new_inodes.to_le_bytes());
}

/// Recompute per-block checksums for all scratch blocks that carry inline
/// checksum fields (inode table, xattr, extent tree, orphan-file blocks).
///
/// Bitmap and group-descriptor checksums are handled separately in
/// `recompute_group_descriptor_checksums`.
fn recompute_block_checksums(
    ext: &Ext,
    blocks: &mut BTreeMap<u64, ScratchBlock>,
) -> MutatorResult<()> {
    use crate::checksum;
    if !ext.has_metadata_csum() {
        return Ok(());
    }
    let seed = ext.checksum_seed.unwrap_or(0);

    // Collect the block numbers that need processing so we can iterate mutably.
    let block_nums: alloc::vec::Vec<u64> = blocks.keys().copied().collect();

    for block_num in block_nums {
        let scratch = blocks.get_mut(&block_num).expect("just collected from map");
        match scratch.class {
            BlockClass::InodeTable { .. } => {
                let inode_size = usize::from(ext.inode_size);
                let mutated: alloc::vec::Vec<u32> =
                    scratch.mutated_inodes.iter().copied().collect();
                for inum in mutated {
                    let index_in_group = (inum - 1) % ext.inodes_per_group;
                    let byte_offset_in_group = u64::from(index_in_group) * inode_size as u64;
                    let block_size = u64::from(ext.block_size);
                    let slot_offset = (byte_offset_in_group % block_size) as usize;
                    // Zero checksum slots before computing — mirrors verify_inode feeding.
                    let slot_bytes = &mut scratch.content[slot_offset..slot_offset + inode_size];
                    // Read generation at offset 0x64 before zeroing anything.
                    let generation = u32::from_le_bytes(slot_bytes[0x64..0x68].try_into().unwrap());
                    let has_hi = inode_size > 128;
                    // Zero checksum fields before computing so they feed as 0.
                    slot_bytes[0x7C..0x7E].copy_from_slice(&[0u8; 2]);
                    if has_hi {
                        slot_bytes[0x82..0x84].copy_from_slice(&[0u8; 2]);
                    }
                    let (lo, hi) =
                        checksum::compute_inode_csum(seed, inum, generation, slot_bytes, has_hi);
                    slot_bytes[0x7C..0x7E].copy_from_slice(&lo.to_le_bytes());
                    if has_hi {
                        slot_bytes[0x82..0x84].copy_from_slice(&hi.to_le_bytes());
                    }
                }
            }
            BlockClass::XattrBlock => {
                // Zero h_checksum before computing.
                scratch.content[0x10..0x14].copy_from_slice(&[0u8; 4]);
                let csum = checksum::compute_xattr_block_csum(seed, block_num, &scratch.content);
                scratch.content[0x10..0x14].copy_from_slice(&csum.to_le_bytes());
            }
            BlockClass::ExtentBlock {
                owner_inode,
                owner_generation,
            } => {
                let csum = checksum::compute_extent_block_csum(
                    seed,
                    owner_inode,
                    owner_generation,
                    &scratch.content,
                );
                let eh_max = u16::from_le_bytes([scratch.content[4], scratch.content[5]]) as usize;
                let tail_off = 12 + eh_max * 12;
                if tail_off + 4 <= scratch.content.len() {
                    scratch.content[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
                }
            }
            BlockClass::OrphanFileBlock {
                file_inode,
                file_generation,
            } => {
                let csum = checksum::compute_orphan_file_block_csum(
                    seed,
                    file_inode,
                    file_generation,
                    block_num,
                    &scratch.content,
                );
                let tail_off = scratch.content.len() - 4;
                scratch.content[tail_off..tail_off + 4].copy_from_slice(&csum.to_le_bytes());
            }
            BlockClass::DirectoryBlock { block, parent_inum } => {
                debug_assert_eq!(block, block_num);
                let _ = parent_inum;
                // Directory tail checksum recompute is implemented with the
                // directory replay primitives that consume this block class.
            }
            // Bitmap csums: computed in recompute_group_descriptor_checksums.
            BlockClass::BlockBitmap { .. }
            | BlockClass::InodeBitmap { .. }
            | BlockClass::GroupDescriptor { .. } => {}
            BlockClass::IndirectBlock => {
                // Legacy ext2/3 indirect pointer blocks have no per-block checksum
                // on any ext filesystem version.
            }
        }
    }
    Ok(())
}

/// Update GDT-level bitmap-csum fields for each dirty group's bitmap scratches,
/// then recompute `bg_checksum` for every group descriptor scratch block.
fn recompute_group_descriptor_checksums(
    ext: &Ext,
    blocks: &mut BTreeMap<u64, ScratchBlock>,
    dirty_groups: &BTreeSet<u32>,
) -> MutatorResult<()> {
    use crate::checksum;

    let desc_size = usize::from(ext.desc_size);

    // Step A: propagate bitmap checksums into GDT scratch entries.
    if ext.has_metadata_csum() {
        let seed = ext.checksum_seed.unwrap_or(0);
        let dpb = ext.gdt_layout.desc_per_block();

        for &group in dirty_groups {
            // Compute CRC pairs under immutable borrow, then apply under
            // mutable borrow — avoids cloning full bitmap blocks (up to 64 KiB
            // each) that the previous snapshot approach required.
            let pairs: alloc::vec::Vec<(BlockClass, (u16, u16))> = blocks
                .values()
                .filter_map(|s| match s.class {
                    BlockClass::BlockBitmap { group: g } if g == group => {
                        Some((s.class, checksum::compute_bitmap_csum(seed, &s.content)))
                    }
                    BlockClass::InodeBitmap { group: g } if g == group => {
                        Some((s.class, checksum::compute_bitmap_csum(seed, &s.content)))
                    }
                    _ => None,
                })
                .collect();

            if pairs.is_empty() {
                continue;
            }

            let gdt_block = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group);
            let offset_in_block = (group % dpb) as usize * desc_size;

            let Some(gdt_scratch) = blocks.get_mut(&gdt_block) else {
                continue;
            };
            let desc_bytes = &mut gdt_scratch.content[offset_in_block..offset_in_block + desc_size];

            for (kind, (lo, hi)) in &pairs {
                match kind {
                    BlockClass::BlockBitmap { .. } => {
                        // bg_block_bitmap_csum_lo at 0x18..0x1A; _hi at 0x38..0x3A
                        desc_bytes[0x18..0x1A].copy_from_slice(&lo.to_le_bytes());
                        if desc_size >= 64 {
                            desc_bytes[0x38..0x3A].copy_from_slice(&hi.to_le_bytes());
                        }
                    }
                    BlockClass::InodeBitmap { .. } => {
                        // bg_inode_bitmap_csum_lo at 0x1A..0x1C; _hi at 0x3A..0x3C
                        desc_bytes[0x1A..0x1C].copy_from_slice(&lo.to_le_bytes());
                        if desc_size >= 64 {
                            desc_bytes[0x3A..0x3C].copy_from_slice(&hi.to_le_bytes());
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    // Step B: recompute bg_checksum on every dirty GDT scratch block.
    let gdt_blocks: alloc::vec::Vec<(u64, u32)> = blocks
        .iter()
        .filter_map(|(&b, s)| match s.class {
            BlockClass::GroupDescriptor { desc_block_nr } => Some((b, desc_block_nr)),
            _ => None,
        })
        .collect();

    let dpb = ext.gdt_layout.desc_per_block();
    for (gdt_block, desc_block_nr) in gdt_blocks {
        let Some(gdt_scratch) = blocks.get_mut(&gdt_block) else {
            continue;
        };
        let descs_per_block = dpb as usize;
        let first_group = desc_block_nr * dpb;

        for i in 0..descs_per_block {
            let offset = i * desc_size;
            if offset + desc_size > gdt_scratch.content.len() {
                break;
            }
            let group = first_group + i as u32;
            // Only recompute the checksum for groups that are actually dirty.
            if !dirty_groups.contains(&group) {
                continue;
            }
            let desc_bytes = &mut gdt_scratch.content[offset..offset + desc_size];
            // Zero bg_checksum before computing.
            desc_bytes[0x1E..0x20].copy_from_slice(&[0u8; 2]);
            let csum = if ext.has_metadata_csum() {
                let seed = ext.checksum_seed.unwrap_or(0);
                checksum::compute_group_descriptor_csum_crc32c(seed, group, desc_bytes)
            } else if ext.has_gdt_csum() {
                checksum::compute_group_descriptor_csum_crc16(&ext.uuid, group, desc_bytes)
            } else {
                continue;
            };
            desc_bytes[0x1E..0x20].copy_from_slice(&csum.to_le_bytes());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_mutator_starts_with_empty_scratch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mutator = Mutator::new(&ext, &sb_host_block);
        assert!(mutator.blocks.is_empty());
        assert!(mutator.group_tallies.is_empty());
        assert_eq!(mutator.total_clusters_freed, 0);
        assert_eq!(mutator.total_inodes_freed, 0);
        assert_eq!(mutator.sb_host_scratch.len(), ext.block_size() as usize);
    }

    #[test]
    fn patch_superblock_bytes_mutates_sb_host_scratch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let mut sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        sb_host_block[0x1C] = 0xAA;
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        mutator
            .patch_superblock_bytes(|buf| {
                buf[0x1C] = 0xBB;
                Ok(())
            })
            .expect("patch sb");
        assert_eq!(mutator.sb_host_scratch[0x1C], 0xBB);
    }

    #[test]
    fn patch_inode_scratch_seeds_from_overlay_and_records_mutation() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
                inode_bytes[0..2].copy_from_slice(&0u16.to_le_bytes());
                Ok(())
            })
            .expect("patch root inode");

        let (expected_block, _offset, _size) =
            Mutator::inode_table_slot_for_test(&ext, 2).expect("locate inode 2");
        let scratch = mutator
            .blocks
            .get(&expected_block)
            .expect("inode 2 table block present in scratch");
        assert!(matches!(scratch.class, BlockClass::InodeTable { .. }));
        assert!(scratch.mutated_inodes.contains(&2));
    }

    #[test]
    fn patch_inode_scratch_second_patch_sees_first_patch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_inode_scratch(&mut cursor, 2, |bytes| {
                bytes[0x10..0x14].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
                Ok(())
            })
            .expect("first patch");

        let mut observed = 0u32;
        mutator
            .patch_inode_scratch(&mut cursor, 2, |bytes| {
                observed = u32::from_le_bytes(bytes[0x10..0x14].try_into().unwrap());
                Ok(())
            })
            .expect("second patch");

        assert_eq!(observed, 0xDEAD_BEEFu32);
    }

    #[test]
    fn adjust_links_count_applies_increment() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        let inum = 2u32;
        let pre = ext
            .inode(&mut cursor, inum)
            .expect("read inode")
            .links_count();

        let result = mutator
            .adjust_inode_links_count(&mut cursor, inum, 1)
            .expect("adjust link count");

        assert_eq!(
            result,
            LinkCountChange::Applied {
                from: pre,
                to: pre + 1,
            }
        );
        assert_eq!(
            scratch_inode_links_count(&mutator, &ext, inum),
            pre + 1,
            "scratch inode bytes must show the incremented count"
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_links_count(&delta, &ext, inum),
            pre + 1,
            "finalized inode bytes must show the incremented count"
        );
    }

    #[test]
    fn adjust_links_count_returns_underflow_without_modifying_bytes() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        let inum = 11u32;
        mutator
            .patch_inode_scratch(&mut cursor, inum, |bytes| {
                bytes[0x1A..0x1C].copy_from_slice(&0u16.to_le_bytes());
                Ok(())
            })
            .expect("seed zero link count");

        let result = mutator
            .adjust_inode_links_count(&mut cursor, inum, -1)
            .expect("adjust link count");

        assert_eq!(
            result,
            LinkCountChange::Underflow {
                from: 0,
                would_be_delta: -1,
            }
        );
        assert_eq!(
            scratch_inode_links_count(&mutator, &ext, inum),
            0,
            "underflow must leave scratch inode bytes unchanged"
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_links_count(&delta, &ext, inum),
            0,
            "underflow must leave finalized inode bytes unchanged"
        );
    }

    #[test]
    fn adjust_links_count_underflow_without_existing_scratch_does_not_patch_inode() {
        let mut bytes = crate::test_support::load_clean_ext4_image();
        let mut layout_cursor = std::io::Cursor::new(bytes.clone());
        let ext = Ext::open_lenient(&mut layout_cursor).expect("open ext4.img");
        let inum = 11u32;
        set_inode_links_count_in_image(&mut bytes, &ext, inum, 0);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        let (inode_block, _inode_offset, _inode_size) =
            Mutator::inode_table_slot_for_test(&ext, inum).expect("locate inode");
        let original_block_count = mutator.blocks.len();

        let result = mutator
            .adjust_inode_links_count(&mut cursor, inum, -1)
            .expect("adjust link count");

        assert_eq!(
            result,
            LinkCountChange::Underflow {
                from: 0,
                would_be_delta: -1,
            }
        );
        assert_eq!(
            mutator.blocks.len(),
            original_block_count,
            "underflow without prior scratch must not create any scratch blocks"
        );
        assert!(
            !mutator.blocks.contains_key(&inode_block),
            "underflow must not create an inode-table scratch block"
        );
    }

    #[test]
    fn adjust_links_count_returns_overflow_at_u16_max() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        let inum = 12u32;
        mutator
            .patch_inode_scratch(&mut cursor, inum, |bytes| {
                bytes[0x1A..0x1C].copy_from_slice(&u16::MAX.to_le_bytes());
                Ok(())
            })
            .expect("seed max link count");

        let result = mutator
            .adjust_inode_links_count(&mut cursor, inum, 1)
            .expect("adjust link count");

        assert_eq!(
            result,
            LinkCountChange::Overflow {
                from: u16::MAX,
                would_be_delta: 1,
            }
        );
        assert_eq!(
            scratch_inode_links_count(&mutator, &ext, inum),
            u16::MAX,
            "overflow must leave scratch inode bytes unchanged"
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert_eq!(
            finalized_inode_links_count(&delta, &ext, inum),
            u16::MAX,
            "overflow must leave finalized inode bytes unchanged"
        );
    }

    #[test]
    fn adjust_links_count_overflow_without_existing_scratch_does_not_patch_inode() {
        let mut bytes = crate::test_support::load_clean_ext4_image();
        let mut layout_cursor = std::io::Cursor::new(bytes.clone());
        let ext = Ext::open_lenient(&mut layout_cursor).expect("open ext4.img");
        let inum = 12u32;
        set_inode_links_count_in_image(&mut bytes, &ext, inum, u16::MAX);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        let (inode_block, _inode_offset, _inode_size) =
            Mutator::inode_table_slot_for_test(&ext, inum).expect("locate inode");
        let original_block_count = mutator.blocks.len();

        let result = mutator
            .adjust_inode_links_count(&mut cursor, inum, 1)
            .expect("adjust link count");

        assert_eq!(
            result,
            LinkCountChange::Overflow {
                from: u16::MAX,
                would_be_delta: 1,
            }
        );
        assert_eq!(
            mutator.blocks.len(),
            original_block_count,
            "overflow without prior scratch must not create any scratch blocks"
        );
        assert!(
            !mutator.blocks.contains_key(&inode_block),
            "overflow must not create an inode-table scratch block"
        );
    }

    #[test]
    fn patch_xattr_block_records_xattr_block_class() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        // Pick any valid block — the mutator doesn't validate content here,
        // only seeds and records the class.
        let block: u64 = 100;
        mutator
            .patch_xattr_block(&mut cursor, block, |buf| {
                buf[0] ^= 0xFF;
                Ok(())
            })
            .expect("patch xattr block");

        let scratch = mutator.blocks.get(&block).expect("scratch present");
        assert!(matches!(scratch.class, BlockClass::XattrBlock));
    }

    #[test]
    fn patch_directory_block_records_directory_block_class() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");

        // Root dir is at block 8 in the standard layout for ext4.img.
        let dir_block = 8u64;
        let parent_inum = 2u32;
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);
        mutator
            .patch_directory_block(&mut cursor, dir_block, parent_inum, |buf| {
                let _ = buf;
                Ok(())
            })
            .expect("patch dir block");

        let scratch = mutator.blocks.get(&dir_block).expect("scratch present");
        assert!(matches!(
            scratch.class,
            BlockClass::DirectoryBlock {
                block,
                parent_inum: 2,
            } if block == dir_block
        ));
    }

    #[test]
    fn dir_append_entry_appends_to_linear_directory() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let original_dir_data = read_block(&ext, &mut cursor, dir_block);
        let original_tail = dir_tail_bytes(&original_dir_data).map(<[u8]>::to_vec);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_append_entry(&mut cursor, parent_inum, 99, b"newfile", 1)
            .expect("append directory entry");
        assert_eq!(outcome, DirReplayOutcome::Applied);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let dir_data = delta
            .blocks
            .get(&dir_block)
            .expect("directory block patched");
        assert!(
            dir_data.windows(7).any(|window| window == b"newfile"),
            "patched directory block must contain the appended name"
        );
        assert_eq!(
            find_raw_dir_entry(dir_data, b"newfile").map(|entry| (entry.inode, entry.file_type)),
            Some((99, 1))
        );
        if let Some(original_tail) = original_tail {
            let tail = dir_tail_bytes(dir_data).expect("dir-tail still present");
            assert_eq!(
                &tail[..8],
                &original_tail[..8],
                "append must preserve the directory checksum tail sentinel"
            );
            if let Some(seed) = ext.checksum_seed() {
                let parent = ext.inode(&mut cursor, parent_inum).expect("read parent");
                assert_eq!(
                    crate::checksum::verify_dir_block(
                        seed,
                        parent_inum,
                        parent.generation(),
                        dir_data
                    ),
                    crate::checksum::ChecksumState::Valid
                );
            }
        }
    }

    #[test]
    fn dir_append_entry_composes_multiple_appends_before_finalize() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        assert_eq!(
            mutator
                .dir_append_entry(&mut cursor, parent_inum, 99, b"first-new", 1)
                .expect("append first entry"),
            DirReplayOutcome::Applied
        );
        assert_eq!(
            mutator
                .dir_append_entry(&mut cursor, parent_inum, 100, b"second-new", 1)
                .expect("append second entry"),
            DirReplayOutcome::Applied
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let dir_data = delta
            .blocks
            .get(&dir_block)
            .expect("directory block patched");
        assert_eq!(
            find_raw_dir_entry(dir_data, b"first-new").map(|entry| (entry.inode, entry.file_type)),
            Some((99, 1)),
            "second append must not overwrite the first appended entry"
        );
        assert_eq!(
            find_raw_dir_entry(dir_data, b"second-new").map(|entry| (entry.inode, entry.file_type)),
            Some((100, 1))
        );
    }

    #[test]
    fn dir_append_entry_rejects_invalid_dir_tail_checksum() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        assert!(
            ext.has_metadata_csum(),
            "test fixture must use metadata checksums"
        );
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let original_dir_data = read_block(&ext, &mut cursor, dir_block);
        let tail = dir_tail_bytes(&original_dir_data).expect("root dir has dir-tail");
        let tail_offset = original_dir_data.len() - tail.len();
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_directory_block(&mut cursor, dir_block, parent_inum, |block| {
                block[tail_offset + 8] ^= 0xFF;
                Ok(())
            })
            .expect("corrupt dir-tail checksum in scratch");

        match mutator.dir_append_entry(&mut cursor, parent_inum, 99, b"newfile", 1) {
            Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry { inode, offset })) => {
                assert_eq!(inode, parent_inum);
                assert_eq!(offset, tail_offset as u64);
            }
            other => panic!("expected structural directory error, got {other:?}"),
        }
    }

    #[test]
    fn dir_append_entry_returns_skipped_htree_for_indexed_directory() {
        let mut bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes.clone());
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        set_inode_flags_in_image(&mut bytes, &ext, 2, crate::inode::InodeFlags::INDEX_FL);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_append_entry(&mut cursor, 2, 99, b"newfile", 1)
            .expect("skip htree directory");
        assert_eq!(outcome, DirReplayOutcome::SkippedHtree);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.blocks.is_empty(),
            "htree skip must not patch directory blocks"
        );
    }

    #[test]
    fn dir_append_entry_observes_parent_flags_from_inode_scratch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let dir_block =
            dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
                let flags_offset = 0x20;
                let existing = u32::from_le_bytes(
                    inode_bytes[flags_offset..flags_offset + 4]
                        .try_into()
                        .unwrap(),
                );
                inode_bytes[flags_offset..flags_offset + 4].copy_from_slice(
                    &(existing | crate::inode::InodeFlags::INDEX_FL.bits()).to_le_bytes(),
                );
                Ok(())
            })
            .expect("set root INDEX_FL in inode scratch");

        let outcome = mutator
            .dir_append_entry(&mut cursor, 2, 99, b"newfile", 1)
            .expect("skip scratch-indexed directory");
        assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
        assert!(
            !matches!(
                mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
                Some(BlockClass::DirectoryBlock { .. })
            ),
            "htree skip must not patch a directory block"
        );
    }

    #[test]
    fn dir_remove_entry_removes_from_linear_directory() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let original_dir_data = read_block(&ext, &mut cursor, dir_block);
        let original_tail = dir_tail_bytes(&original_dir_data).map(<[u8]>::to_vec);
        let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
            .expect("fixture root has lost+found entry");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_remove_entry(&mut cursor, parent_inum, target.inode, b"lost+found")
            .expect("remove directory entry");
        assert_eq!(outcome, DirReplayOutcome::Applied);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let dir_data = delta
            .blocks
            .get(&dir_block)
            .expect("directory block patched");
        assert_eq!(find_raw_dir_entry(dir_data, b"lost+found"), None);
        if let Some(original_tail) = original_tail {
            let tail = dir_tail_bytes(dir_data).expect("dir-tail still present");
            assert_eq!(
                &tail[..8],
                &original_tail[..8],
                "remove must preserve the directory checksum tail sentinel"
            );
            if let Some(seed) = ext.checksum_seed() {
                let parent = ext.inode(&mut cursor, parent_inum).expect("read parent");
                assert_eq!(
                    crate::checksum::verify_dir_block(
                        seed,
                        parent_inum,
                        parent.generation(),
                        dir_data
                    ),
                    crate::checksum::ChecksumState::Valid
                );
            }
        }
    }

    #[test]
    fn dir_remove_entry_returns_skipped_target_missing_without_patching() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_remove_entry(&mut cursor, 2, 99, b"missing-target")
            .expect("skip missing directory entry");
        assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.blocks.is_empty(),
            "missing target skip must not patch directory blocks"
        );
    }

    #[test]
    fn dir_remove_entry_returns_skipped_when_name_matches_different_inode() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let dir_block =
            dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
        let original_dir_data = read_block(&ext, &mut cursor, dir_block);
        let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
            .expect("fixture root has lost+found entry");
        let wrong_child = 99u32;
        assert_ne!(target.inode, wrong_child);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_remove_entry(&mut cursor, 2, wrong_child, b"lost+found")
            .expect("skip wrong child inode");
        assert_eq!(outcome, DirReplayOutcome::SkippedTargetMissing);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.blocks.is_empty(),
            "wrong-inode name match must not patch directory blocks"
        );
    }

    #[test]
    fn dir_remove_entry_returns_skipped_htree_for_indexed_directory() {
        let mut bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes.clone());
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let dir_block =
            dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
        set_inode_flags_in_image(&mut bytes, &ext, 2, crate::inode::InodeFlags::INDEX_FL);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let outcome = mutator
            .dir_remove_entry(&mut cursor, 2, 11, b"lost+found")
            .expect("skip htree directory");
        assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
        assert!(
            !matches!(
                mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
                Some(BlockClass::DirectoryBlock { .. })
            ),
            "htree skip must not patch a directory block"
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.blocks.is_empty(),
            "htree skip must not patch directory blocks"
        );
    }

    #[test]
    fn dir_remove_entry_observes_parent_flags_from_inode_scratch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let dir_block =
            dir_physical_block(&ext, &mut cursor, 2, 0).expect("resolve root directory block");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_inode_scratch(&mut cursor, 2, |inode_bytes| {
                let flags_offset = 0x20;
                let existing = u32::from_le_bytes(
                    inode_bytes[flags_offset..flags_offset + 4]
                        .try_into()
                        .unwrap(),
                );
                inode_bytes[flags_offset..flags_offset + 4].copy_from_slice(
                    &(existing | crate::inode::InodeFlags::INDEX_FL.bits()).to_le_bytes(),
                );
                Ok(())
            })
            .expect("set root INDEX_FL in inode scratch");

        let outcome = mutator
            .dir_remove_entry(&mut cursor, 2, 11, b"lost+found")
            .expect("skip scratch-indexed directory");
        assert_eq!(outcome, DirReplayOutcome::SkippedHtree);
        assert!(
            !matches!(
                mutator.blocks.get(&dir_block).map(|scratch| scratch.class),
                Some(BlockClass::DirectoryBlock { .. })
            ),
            "htree skip must not patch a directory block"
        );
    }

    #[test]
    fn dir_remove_entry_composes_with_append_before_finalize() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        assert_eq!(
            mutator
                .dir_append_entry(&mut cursor, parent_inum, 99, b"temporary", 1)
                .expect("append entry"),
            DirReplayOutcome::Applied
        );
        assert_eq!(
            mutator
                .dir_remove_entry(&mut cursor, parent_inum, 99, b"temporary")
                .expect("remove appended entry"),
            DirReplayOutcome::Applied
        );

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let dir_data = delta
            .blocks
            .get(&dir_block)
            .expect("directory block patched");
        assert_eq!(find_raw_dir_entry(dir_data, b"temporary"), None);
    }

    #[test]
    fn dir_remove_entry_clears_inode_for_head_entry_in_later_block() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        let parent_inum = 2u32;
        let first_dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let second_dir_block = first_dir_block + 1;
        let block_size = ext.block_size() as usize;
        let parent_generation = ext
            .inode(&mut cursor, parent_inum)
            .expect("read parent")
            .generation();
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_inode_scratch(&mut cursor, parent_inum, |inode_bytes| {
                inode_bytes[0x04..0x08].copy_from_slice(&(ext.block_size() * 2).to_le_bytes());
                inode_bytes[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
                let extent_len_offset = 0x28 + 12 + 4;
                inode_bytes[extent_len_offset..extent_len_offset + 2]
                    .copy_from_slice(&2u16.to_le_bytes());
                Ok(())
            })
            .expect("extend root directory extent in scratch");
        mutator
            .patch_directory_block(&mut cursor, second_dir_block, parent_inum, |block| {
                block.fill(0);
                let tail_offset = block_size - 12;
                write_test_dir_entry(block, 0, 99, tail_offset as u16, b"block-head", 1);
                block[tail_offset + 4..tail_offset + 6].copy_from_slice(&12u16.to_le_bytes());
                block[tail_offset + 7] = 0xDE;
                refresh_dir_tail_checksum(
                    ext.checksum_seed(),
                    parent_inum,
                    parent_generation,
                    block,
                );
                Ok(())
            })
            .expect("seed synthetic second directory block");

        let outcome = mutator
            .dir_remove_entry(&mut cursor, parent_inum, 99, b"block-head")
            .expect("remove head entry from later block");
        assert_eq!(outcome, DirReplayOutcome::Applied);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let dir_data = delta
            .blocks
            .get(&second_dir_block)
            .expect("second directory block patched");
        assert_eq!(
            u32::from_le_bytes(dir_data[0..4].try_into().unwrap()),
            0,
            "head-of-block removal must clear the current entry inode"
        );
        assert_eq!(
            u16::from_le_bytes(dir_data[4..6].try_into().unwrap()),
            (block_size - 12) as u16,
            "clear-current removal must preserve the entry rec_len"
        );
        assert_eq!(find_raw_dir_entry(dir_data, b"block-head"), None);
    }

    #[test]
    fn dir_remove_entry_rejects_invalid_dir_tail_checksum() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::open_lenient(&mut cursor).expect("open ext4.img");
        assert!(
            ext.has_metadata_csum(),
            "test fixture must use metadata checksums"
        );
        let parent_inum = 2u32;
        let dir_block = dir_physical_block(&ext, &mut cursor, parent_inum, 0)
            .expect("resolve root directory block");
        let original_dir_data = read_block(&ext, &mut cursor, dir_block);
        let target = find_raw_dir_entry(&original_dir_data, b"lost+found")
            .expect("fixture root has lost+found entry");
        let tail = dir_tail_bytes(&original_dir_data).expect("root dir has dir-tail");
        let tail_offset = original_dir_data.len() - tail.len();
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .patch_directory_block(&mut cursor, dir_block, parent_inum, |block| {
                block[tail_offset + 8] ^= 0xFF;
                Ok(())
            })
            .expect("corrupt dir-tail checksum in scratch");

        match mutator.dir_remove_entry(&mut cursor, parent_inum, target.inode, b"lost+found") {
            Err(MutatorError::Ext(ExtError::InvalidDirectoryEntry { inode, offset })) => {
                assert_eq!(inode, parent_inum);
                assert_eq!(offset, tail_offset as u64);
            }
            other => panic!("expected structural directory error, got {other:?}"),
        }
    }

    #[test]
    fn patch_extent_block_records_owner_inum_and_generation() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let block: u64 = 200;
        mutator
            .patch_extent_block(&mut cursor, block, 42, 0x1234_5678, |buf| {
                buf[0] ^= 0xFF;
                Ok(())
            })
            .expect("patch extent block");

        let scratch = mutator.blocks.get(&block).expect("scratch present");
        match scratch.class {
            BlockClass::ExtentBlock {
                owner_inode,
                owner_generation,
            } => {
                assert_eq!(owner_inode, 42);
                assert_eq!(owner_generation, 0x1234_5678);
            }
            _ => panic!("wrong class"),
        }
    }

    #[test]
    fn patch_orphan_file_block_records_file_inum_and_generation() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let block: u64 = 300;
        mutator
            .patch_orphan_file_block(&mut cursor, block, 7, 0xCAFE_BABE, |buf| {
                buf[0] ^= 0xFF;
                Ok(())
            })
            .expect("patch orphan-file block");

        let scratch = mutator.blocks.get(&block).expect("scratch present");
        match scratch.class {
            BlockClass::OrphanFileBlock {
                file_inode,
                file_generation,
            } => {
                assert_eq!(file_inode, 7);
                assert_eq!(file_generation, 0xCAFE_BABE);
            }
            _ => panic!("wrong class"),
        }
    }

    #[test]
    fn clear_inode_bitmap_bit_tallies_decrement_and_seeds_bitmap_scratch() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .clear_inode_bitmap_bit(&mut cursor, 2, false)
            .expect("clear root inode bitmap bit");

        let group = 0u32;
        let bitmap_block = ext.group_descs[group as usize].inode_bitmap;
        assert!(mutator.blocks.contains_key(&bitmap_block));
        let tally = mutator.group_tallies.get(&group).expect("group 0 tally");
        assert_eq!(tally.inodes_freed, 1);
        assert_eq!(tally.dirs_freed, 0);
        assert_eq!(mutator.total_inodes_freed, 1);
    }

    #[test]
    fn clear_inode_bitmap_bit_tallies_dir_when_was_dir_true() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        mutator
            .clear_inode_bitmap_bit(&mut cursor, 2, true)
            .expect("clear root dir inode bitmap bit");

        let tally = mutator.group_tallies.get(&0).expect("group 0 tally");
        assert_eq!(tally.dirs_freed, 1);
    }

    #[test]
    fn clear_inode_bitmap_bit_is_idempotent_when_bit_already_clear() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        // The largest inode number on a clean fs is almost certainly free;
        // its bitmap bit is zero.
        let high = ext.inodes_count;
        mutator
            .clear_inode_bitmap_bit(&mut cursor, high, false)
            .expect("no-op when bit already clear");

        // Either no tally was created, or the existing tally shows zero decrements.
        let group = (high - 1) / ext.inodes_per_group;
        let inodes_freed = mutator
            .group_tallies
            .get(&group)
            .map(|t| t.inodes_freed)
            .unwrap_or(0);
        assert_eq!(inodes_freed, 0);
        assert_eq!(mutator.total_inodes_freed, 0);
    }

    #[test]
    fn free_allocations_non_bigalloc_clears_bits_and_tallies() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let first_data_block = first_data_block_of_root(&ext, &mut cursor)
            .expect("root inode has at least one data block");

        let runs = [AllocationRun {
            physical_start: first_data_block,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        }];
        mutator
            .free_allocations(&mut cursor, 2, &runs)
            .expect("free 1 block");

        assert_eq!(mutator.total_clusters_freed, 1);
        let group = ((first_data_block - u64::from(ext.first_data_block))
            / u64::from(ext.blocks_per_group)) as u32;
        let tally = mutator.group_tallies.get(&group).expect("group tally");
        assert_eq!(tally.clusters_freed, 1);
    }

    #[test]
    fn free_allocations_non_bigalloc_dedupes_and_is_idempotent() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let first_data_block = first_data_block_of_root(&ext, &mut cursor)
            .expect("root inode has at least one data block");

        let runs = [AllocationRun {
            physical_start: first_data_block,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        }];
        mutator
            .free_allocations(&mut cursor, 2, &runs)
            .expect("first call");
        mutator
            .free_allocations(&mut cursor, 2, &runs)
            .expect("second call is idempotent");

        // Second call must not double-count.
        assert_eq!(mutator.total_clusters_freed, 1);
    }

    #[test]
    fn free_allocations_bigalloc_detects_logical_cluster_overlap() {
        // Synthetic Ext with blocks_per_cluster = 4 → blocks 0..4 share cluster 0.
        let ext = Ext::dummy_for_test_bigalloc(4);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(ext, &sb_host_block);

        let mut dummy_overlay = std::io::Cursor::new(alloc::vec![0u8; 1 << 20]);

        // Two Data runs: physical block 0 from logical cluster 0,
        // physical block 1 from logical cluster 100. Both blocks live in
        // physical cluster 0 (since blocks_per_cluster=4 and first_data_block=0).
        let runs = [
            AllocationRun {
                physical_start: 0,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: 0,
                },
            },
            AllocationRun {
                physical_start: 1,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: 100,
                },
            },
        ];

        match mutator.free_allocations(&mut dummy_overlay, 42, &runs) {
            Err(MutatorError::BigallocClusterOverlap {
                inode,
                cluster,
                first_block,
                second_block,
            }) => {
                assert_eq!(inode, 42);
                assert_eq!(cluster, 0);
                assert_eq!(first_block, 0);
                assert_eq!(second_block, 1);
            }
            other => panic!("expected BigallocClusterOverlap, got {other:?}"),
        }
    }

    #[test]
    fn free_allocations_bigalloc_same_logical_cluster_no_overlap() {
        // Two Data blocks in the same physical cluster, both from the same
        // logical cluster (legitimate bigalloc layout — should NOT trigger overlap).
        // No bitmap clear happens because group_descs is empty in the synthetic Ext;
        // the method bails on the GroupDescriptor lookup. We only want to verify
        // pass 1 didn't trip BigallocClusterOverlap.
        let ext = Ext::dummy_for_test_bigalloc(4);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(ext, &sb_host_block);

        let mut dummy_overlay = std::io::Cursor::new(alloc::vec![0u8; 1 << 20]);

        let runs = [
            AllocationRun {
                physical_start: 0,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: 0,
                },
            },
            AllocationRun {
                physical_start: 1,
                block_len: 1,
                kind: AllocationKind::Data {
                    logical_cluster_start: 0,
                },
            },
        ];

        // The error MUST NOT be BigallocClusterOverlap.
        let result = mutator.free_allocations(&mut dummy_overlay, 42, &runs);
        match result {
            Err(MutatorError::BigallocClusterOverlap { .. }) => {
                panic!("same-cluster same-logical-cluster runs must NOT overlap");
            }
            Err(MutatorError::Ext(_)) => { /* expected: pass 2 fails on empty group_descs */ }
            Ok(()) => { /* also acceptable if pass 2 short-circuits cleanly */ }
        }
    }

    /// Walk the root inode's extent tree (logical block 0) and return the physical
    /// block number of its first data block. The root directory inode (inum 2) always
    /// has at least one allocated data block on a non-empty fixture.
    ///
    /// Uses `crate::extent::resolve_extent` — the same walker used in `ExtFile` —
    /// rather than hand-rolling iteration. Logical block 0 is sufficient because
    /// the tests only need ONE confirmed-allocated physical block.
    fn first_data_block_of_root<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        overlay: &mut T,
    ) -> Option<u64> {
        use crate::inode::InodeFlags;

        let root = ext.inode(overlay, 2).ok()?;
        // Root must use extents (EXTENTS_FL); inline data is not applicable.
        if !root.flags().contains(InodeFlags::EXTENTS_FL) {
            return None;
        }
        let resolved =
            crate::extent::resolve_extent(ext, overlay, 2, root.generation(), &root.i_block(), 0)
                .ok()??;
        Some(resolved.physical_block)
    }

    #[test]
    fn finalize_produces_delta_with_sb_host_override_when_sb_was_patched() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");

        // Seed sb_host_scratch from the actual on-disk sb-host block (block 0 for 4 KiB fs).
        let sb_host_block_num: u64 = if ext.block_size() > 1024 { 0 } else { 1 };
        let mut sb_bytes = alloc::vec![0u8; ext.block_size() as usize];
        cursor
            .seek(crate::io::SeekFrom::Start(
                sb_host_block_num * u64::from(ext.block_size()),
            ))
            .expect("seek sb host");
        cursor.read_exact(&mut sb_bytes).expect("read sb host");

        let mut mutator = Mutator::new(&ext, &sb_bytes);
        mutator
            .patch_superblock_bytes(|buf| {
                // Flip a harmless byte — triggers "sb was patched".
                buf[0x68] ^= 0xFF; // s_hash_seed[0] low byte
                Ok(())
            })
            .expect("patch sb");

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(delta.sb_host_override.is_some());
    }

    #[test]
    fn finalize_preserves_sb_host_override_absent_when_no_sb_patches() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_bytes = alloc::vec![0u8; ext.block_size() as usize];
        let mutator = Mutator::new(&ext, &sb_bytes);
        let delta = mutator.finalize(&mut cursor).expect("finalize");
        // No patches were made → override is None.
        assert!(delta.sb_host_override.is_none());
    }

    // physical_start = u64::MAX with block_len = 2 forces physical_start + off (off=1)
    // to overflow u64, exercising the checked_add guard in Pass 1.
    #[test]
    fn free_allocations_rejects_overflow_physical_start_plus_len() {
        let ext = Ext::dummy_for_test_bigalloc(1);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(ext, &sb_host_block);
        let mut dummy = std::io::Cursor::new(alloc::vec![0u8; 1 << 20]);
        let runs = [AllocationRun {
            physical_start: u64::MAX,
            block_len: 2,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        }];
        match mutator.free_allocations(&mut dummy, 42, &runs) {
            Err(MutatorError::Ext(ExtError::BlockOutOfRange { .. })) => {}
            other => panic!("expected BlockOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn free_allocations_rejects_physical_block_at_blocks_count() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let runs = [AllocationRun {
            physical_start: ext.blocks_count,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        }];

        match mutator.free_allocations(&mut cursor, 42, &runs) {
            Err(MutatorError::Ext(ExtError::BlockOutOfRange { block })) => {
                assert_eq!(block, ext.blocks_count);
            }
            other => panic!("expected BlockOutOfRange at blocks_count, got {other:?}"),
        }
    }

    #[test]
    fn mark_block_range_projection_formula_handles_unaligned_starts() {
        let cases = [
            (0, 4, 0, 4, 0, 1),
            (0, 4, 0, 8, 0, 2),
            (0, 4, 2, 4, 0, 2),
            (0, 4, 4, 4, 1, 1),
            (0, 4, 3, 1, 0, 1),
            (0, 8, 6, 4, 0, 2),
            (0, 1, 100, 50, 100, 50),
            (1, 1, 8192, 1, 8191, 1),
        ];

        for (first_data_block, ratio, pblk, block_len, expected_first, expected_count) in cases {
            let (first, count) =
                project_block_range_to_alloc_units(pblk, block_len, ratio, first_data_block)
                    .expect("project");
            assert_eq!(
                first, expected_first,
                "first mismatch on {pblk}+{block_len}/{ratio} first_data_block={first_data_block}"
            );
            assert_eq!(
                count, expected_count,
                "count mismatch on {pblk}+{block_len}/{ratio} first_data_block={first_data_block}"
            );
        }

        assert!(matches!(
            project_block_range_to_alloc_units(0, 0, 1, 1),
            Err(MutatorError::Ext(ExtError::BlockOutOfRange { block: 0 }))
        ));
    }

    #[test]
    fn mark_block_range_free_bigalloc_aligned_one_cluster_changes_one_unit() {
        let ext = synthetic_bigalloc_ext(1, 0, 16, false);
        let mut bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_free(&mut cursor, 0, 4)
            .expect("mark cluster free");
        assert_eq!(changed, 1);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let bitmap = finalized_bitmap(&delta, &ext, 0);
        assert!(!decode_block_bitmap_bit(bitmap, 0));
        let gdt = finalized_gdt_block(&delta, &ext, 0);
        assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 11);
    }

    #[test]
    fn mark_block_range_free_bigalloc_mid_cluster_start_changes_two_units() {
        let ext = synthetic_bigalloc_ext(1, 0, 16, false);
        let mut bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 1, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_free(&mut cursor, 2, 4)
            .expect("mark unaligned range free");
        assert_eq!(changed, 2);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let bitmap = finalized_bitmap(&delta, &ext, 0);
        assert!(!decode_block_bitmap_bit(bitmap, 0));
        assert!(!decode_block_bitmap_bit(bitmap, 1));
        let gdt = finalized_gdt_block(&delta, &ext, 0);
        assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 12);
    }

    #[test]
    fn mark_block_range_allocated_inside_already_allocated_cluster_changes_zero() {
        let ext = synthetic_bigalloc_ext(1, 0, 16, false);
        let mut bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 1, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_allocated(&mut cursor, 5, 1)
            .expect("mark already allocated subrange");
        assert_eq!(changed, 0);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let bitmap = finalized_bitmap(&delta, &ext, 0);
        assert!(decode_block_bitmap_bit(bitmap, 1));
        let gdt = finalized_gdt_block(&delta, &ext, 0);
        assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 10);
    }

    #[test]
    fn mark_block_range_bigalloc_count_direction_matches_alloc_vs_free() {
        let ext = synthetic_bigalloc_ext(1, 0, 16, false);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];

        let mut free_bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut free_bytes, &ext, 0, 0, true);
        let mut free_cursor = std::io::Cursor::new(free_bytes);
        let mut free_mutator = Mutator::new(&ext, &sb_host_block);
        assert_eq!(
            free_mutator
                .mark_block_range_free(&mut free_cursor, 0, 4)
                .expect("mark free"),
            1
        );
        let free_delta = free_mutator.finalize(&mut free_cursor).expect("finalize");
        assert_eq!(
            decode_bg_free_blocks_count(finalized_gdt_block(&free_delta, &ext, 0), &ext, 0),
            11
        );

        let alloc_bytes = synthetic_overlay(&ext);
        let mut alloc_cursor = std::io::Cursor::new(alloc_bytes);
        let mut alloc_mutator = Mutator::new(&ext, &sb_host_block);
        assert_eq!(
            alloc_mutator
                .mark_block_range_allocated(&mut alloc_cursor, 0, 4)
                .expect("mark allocated"),
            1
        );
        let alloc_delta = alloc_mutator.finalize(&mut alloc_cursor).expect("finalize");
        assert_eq!(
            decode_bg_free_blocks_count(finalized_gdt_block(&alloc_delta, &ext, 0), &ext, 0),
            9
        );
    }

    #[test]
    fn mark_block_range_splits_bigalloc_range_across_group_boundary() {
        let ext = synthetic_bigalloc_ext(2, 1, 16, false);
        let mut bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 3, true);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 1, 0, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_free(&mut cursor, 13, 8)
            .expect("mark boundary-spanning range free");
        assert_eq!(changed, 2);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(!decode_block_bitmap_bit(
            finalized_bitmap(&delta, &ext, 0),
            3
        ));
        assert!(!decode_block_bitmap_bit(
            finalized_bitmap(&delta, &ext, 1),
            0
        ));
        let gdt = finalized_gdt_block(&delta, &ext, 0);
        assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 0), 11);
        assert_eq!(decode_bg_free_blocks_count(gdt, &ext, 1), 11);
    }

    #[test]
    fn mark_block_range_finalize_recomputes_bitmap_and_group_descriptor_checksums() {
        let ext = synthetic_bigalloc_ext(1, 0, 16, true);
        let seed = ext.checksum_seed.expect("metadata checksum seed");
        let mut bytes = synthetic_overlay(&ext);
        set_synthetic_bitmap_bit(&mut bytes, &ext, 0, 0, true);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_free(&mut cursor, 0, 4)
            .expect("mark cluster free");
        assert_eq!(changed, 1);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let bitmap = finalized_bitmap(&delta, &ext, 0);
        let desc = finalized_group_desc(&delta, &ext, 0);
        let block_bitmap_csum_lo = read_desc_u16(desc, 0x18);
        let block_bitmap_csum_hi = read_desc_u16(desc, 0x38);

        assert_eq!(
            crate::checksum::verify_bitmap_csum(
                seed,
                bitmap,
                block_bitmap_csum_lo,
                Some(block_bitmap_csum_hi),
            ),
            crate::checksum::ChecksumState::Valid
        );
        assert_eq!(
            crate::checksum::verify_group_descriptor(seed, 0, desc),
            crate::checksum::ChecksumState::Valid
        );
    }

    #[test]
    fn mark_block_range_free_clears_bitmap_bits_and_increments_gdp_count() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

        let first_data_block = first_data_block_of_root(&ext, &mut cursor)
            .expect("root inode has at least one data block");
        let group = (first_data_block / u64::from(ext.blocks_per_group)) as u32;
        let pre_count = ext.group_descs[group as usize].free_blocks_count;
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_free(&mut cursor, first_data_block, 1)
            .expect("mark free");
        assert_eq!(changed, 1);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(
            delta.sb_host_override.is_none(),
            "fast-commit bitmap primitive must not alter superblock tallies"
        );

        let gdt_block = u64::from(ext.first_data_block)
            + 1
            + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
        let gdt_bytes = delta.blocks.get(&gdt_block).expect("gdt dirtied");
        let updated_gdp_free = decode_bg_free_blocks_count(gdt_bytes, &ext, group);
        assert_eq!(updated_gdp_free, pre_count + 1);

        let bitmap_block = ext.group_descs[group as usize].block_bitmap;
        let bitmap_bytes = delta.blocks.get(&bitmap_block).expect("bitmap dirtied");
        let bit_in_group = first_data_block - u64::from(group) * u64::from(ext.blocks_per_group);
        assert!(
            !decode_block_bitmap_bit(bitmap_bytes, bit_in_group),
            "bitmap bit for root data block must be cleared"
        );
    }

    #[test]
    fn mark_block_range_allocated_already_allocated_unit_changes_zero() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

        let first_data_block = first_data_block_of_root(&ext, &mut cursor)
            .expect("root inode has at least one data block");
        let group = (first_data_block / u64::from(ext.blocks_per_group)) as u32;
        let pre_count = ext.group_descs[group as usize].free_blocks_count;
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_allocated(&mut cursor, first_data_block, 1)
            .expect("mark allocated");
        assert_eq!(changed, 0);

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        assert!(delta.sb_host_override.is_none());
        let gdt_block = u64::from(ext.first_data_block)
            + 1
            + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
        let gdt_bytes = delta.blocks.get(&gdt_block).expect("gdt dirtied");
        let updated_gdp_free = decode_bg_free_blocks_count(gdt_bytes, &ext, group);
        assert_eq!(updated_gdp_free, pre_count);
    }

    #[test]
    fn mark_block_range_allocated_initializes_stale_uninit_block_bitmap() {
        const BLOCK_UNINIT: u16 = 0x0002;

        let ext = Ext {
            inodes_count: 64,
            blocks_count: 128,
            block_size: 1024,
            group_count: 1,
            inodes_per_group: 4,
            inode_size: 128,
            first_data_block: 1,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                1,
                1024,
                64,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 64,
            cluster_size: 4096,
            blocks_per_cluster: 4,
            clusters_per_group: 16,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat: crate::feature_flags::RoCompatFeatures::empty(),
            compat: crate::feature_flags::CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![crate::block_group::GroupDescriptor {
                inode_table: 8,
                block_bitmap: 5,
                inode_bitmap: 6,
                free_blocks_count: 0,
                free_inodes_count: 0,
                flags: BLOCK_UNINIT,
                checksum: crate::checksum::ChecksumState::Unknown,
            }],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        };
        let mut bytes = alloc::vec![0u8; 128 * 1024];
        bytes[2 * 1024 + 0x12..2 * 1024 + 0x14].copy_from_slice(&BLOCK_UNINIT.to_le_bytes());
        bytes[5 * 1024..6 * 1024].fill(0xFF);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let changed = mutator
            .mark_block_range_allocated(&mut cursor, 9, 1)
            .expect("mark allocated in initialized uninit group");
        assert_eq!(
            changed, 1,
            "stale all-ones bitmap must be ignored for BLOCK_UNINIT"
        );

        let bitmap = &mutator
            .blocks
            .get(&5)
            .expect("block bitmap scratch")
            .content;
        assert!(decode_block_bitmap_bit(bitmap, 0), "super/GDT cluster");
        assert!(
            decode_block_bitmap_bit(bitmap, 1),
            "bitmap/inode-table cluster"
        );
        assert!(
            decode_block_bitmap_bit(bitmap, 2),
            "requested allocated data cluster"
        );
        assert!(
            !decode_block_bitmap_bit(bitmap, 3),
            "unrequested data cluster"
        );
        assert!(decode_block_bitmap_bit(bitmap, 16), "end-of-group padding");
    }

    #[test]
    fn mark_block_range_allocated_initializes_uninit_group_once_per_mutator() {
        const BLOCK_UNINIT: u16 = 0x0002;

        let ext = Ext {
            inodes_count: 64,
            blocks_count: 128,
            block_size: 1024,
            group_count: 1,
            inodes_per_group: 4,
            inode_size: 128,
            first_data_block: 1,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                1,
                1024,
                64,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 64,
            cluster_size: 4096,
            blocks_per_cluster: 4,
            clusters_per_group: 16,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat: crate::feature_flags::RoCompatFeatures::empty(),
            compat: crate::feature_flags::CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![crate::block_group::GroupDescriptor {
                inode_table: 8,
                block_bitmap: 5,
                inode_bitmap: 6,
                free_blocks_count: 0,
                free_inodes_count: 0,
                flags: BLOCK_UNINIT,
                checksum: crate::checksum::ChecksumState::Unknown,
            }],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        };
        let mut bytes = alloc::vec![0u8; 128 * 1024];
        bytes[2 * 1024 + 0x12..2 * 1024 + 0x14].copy_from_slice(&BLOCK_UNINIT.to_le_bytes());
        bytes[5 * 1024..6 * 1024].fill(0xFF);
        let mut cursor = std::io::Cursor::new(bytes);
        let sb_host_block = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let first_changed = mutator
            .mark_block_range_allocated(&mut cursor, 9, 1)
            .expect("mark first allocated unit");
        let second_changed = mutator
            .mark_block_range_allocated(&mut cursor, 13, 1)
            .expect("mark second allocated unit");
        assert_eq!(first_changed + second_changed, 2);

        let bitmap = &mutator
            .blocks
            .get(&5)
            .expect("block bitmap scratch")
            .content;
        assert!(decode_block_bitmap_bit(bitmap, 2), "first allocation bit");
        assert!(decode_block_bitmap_bit(bitmap, 3), "second allocation bit");

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let gdt_bytes = delta.blocks.get(&2).expect("gdt dirtied");
        assert_eq!(
            decode_bg_free_blocks_count(gdt_bytes, &ext, 0),
            12,
            "initialized free count 14 minus two allocated units"
        );
    }

    #[test]
    fn free_allocations_finalize_updates_superblock_free_count() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = Ext::new(&mut cursor).expect("open ext4.img");
        assert!(!ext.has_bigalloc(), "test assumes non-bigalloc fixture");

        let first_data_block = first_data_block_of_root(&ext, &mut cursor)
            .expect("root inode has at least one data block");
        let sb_host_block = read_sb_block(&ext, &mut cursor);
        let pre_sb_free = decode_sb_free_blocks_count(&sb_host_block, &ext);
        let mut mutator = Mutator::new(&ext, &sb_host_block);

        let runs = [AllocationRun {
            physical_start: first_data_block,
            block_len: 1,
            kind: AllocationKind::Data {
                logical_cluster_start: 0,
            },
        }];
        mutator
            .free_allocations(&mut cursor, 2, &runs)
            .expect("free allocation");

        let delta = mutator.finalize(&mut cursor).expect("finalize");
        let sb_override = delta
            .sb_host_override
            .expect("orphan free_allocations updates sb tallies");
        assert_eq!(
            decode_sb_free_blocks_count(&sb_override, &ext),
            pre_sb_free + 1
        );
    }

    fn read_sb_block<T: crate::io::Read + crate::io::Seek>(ext: &Ext, fs: &mut T) -> Box<[u8]> {
        let sb_host_block_num: u64 = if ext.block_size() > 1024 { 0 } else { 1 };
        let mut sb_bytes = alloc::vec![0u8; ext.block_size() as usize].into_boxed_slice();
        fs.seek(crate::io::SeekFrom::Start(
            sb_host_block_num * u64::from(ext.block_size()),
        ))
        .expect("seek sb host");
        fs.read_exact(&mut sb_bytes).expect("read sb host");
        sb_bytes
    }

    fn dir_physical_block<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        fs: &mut T,
        inum: u32,
        logical_block: u32,
    ) -> crate::error::Result<u64> {
        let inode = ext.inode(fs, inum)?;
        let i_block = inode.i_block();
        if inode.flags().contains(crate::inode::InodeFlags::EXTENTS_FL) {
            let extent = crate::extent::resolve_extent(
                ext,
                fs,
                inum,
                inode.generation(),
                &i_block,
                logical_block,
            )?
            .ok_or(crate::error::ExtError::BlockOutOfRange {
                block: u64::from(logical_block),
            })?;
            Ok(extent.physical_block + u64::from(logical_block - extent.logical_block))
        } else {
            crate::block_map::resolve_block_map(ext, fs, &i_block, logical_block)?.ok_or(
                crate::error::ExtError::BlockOutOfRange {
                    block: u64::from(logical_block),
                },
            )
        }
    }

    fn read_block<T: crate::io::Read + crate::io::Seek>(
        ext: &Ext,
        fs: &mut T,
        block: u64,
    ) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; ext.block_size() as usize];
        fs.seek(crate::io::SeekFrom::Start(
            block * u64::from(ext.block_size()),
        ))
        .expect("seek block");
        fs.read_exact(&mut buf).expect("read block");
        buf
    }

    fn scratch_inode_links_count(mutator: &Mutator<'_>, ext: &Ext, inum: u32) -> u16 {
        let (inode_block, inode_offset, inode_size) =
            Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
        let scratch = mutator
            .blocks
            .get(&inode_block)
            .expect("inode table block present in scratch");
        read_le_u16(
            &scratch.content[inode_offset..inode_offset + inode_size],
            0x1A,
        )
    }

    fn finalized_inode_links_count(
        delta: &crate::orphan::plan::OrphanOverlayDelta,
        ext: &Ext,
        inum: u32,
    ) -> u16 {
        let (inode_block, inode_offset, inode_size) =
            Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
        let block = delta
            .blocks
            .get(&inode_block)
            .expect("inode table block finalized");
        read_le_u16(&block[inode_offset..inode_offset + inode_size], 0x1A)
    }

    fn set_inode_links_count_in_image(image: &mut [u8], ext: &Ext, inum: u32, links_count: u16) {
        let (inode_block, inode_offset, _inode_size) =
            Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
        let links_offset = inode_block as usize * ext.block_size() as usize + inode_offset + 0x1A;
        image[links_offset..links_offset + 2].copy_from_slice(&links_count.to_le_bytes());
    }

    fn dir_tail_bytes(block: &[u8]) -> Option<&[u8]> {
        if block.len() < 12 {
            return None;
        }
        let tail = &block[block.len() - 12..];
        let inode = u32::from_le_bytes(tail[0..4].try_into().unwrap());
        let rec_len = u16::from_le_bytes(tail[4..6].try_into().unwrap());
        (inode == 0 && rec_len == 12 && tail[6] == 0 && tail[7] == 0xDE).then_some(tail)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct RawDirEntryForTest {
        inode: u32,
        file_type: u8,
    }

    fn find_raw_dir_entry(block: &[u8], name: &[u8]) -> Option<RawDirEntryForTest> {
        let usable_end = dir_tail_bytes(block)
            .map(|tail| block.len() - tail.len())
            .unwrap_or(block.len());
        let mut offset = 0usize;
        while offset + 8 <= usable_end {
            let inode = u32::from_le_bytes(block[offset..offset + 4].try_into().unwrap());
            let rec_len = u16::from_le_bytes(block[offset + 4..offset + 6].try_into().unwrap());
            if rec_len < 8 || rec_len % 4 != 0 {
                return None;
            }
            let name_len = usize::from(block[offset + 6]);
            let file_type = block[offset + 7];
            let next = offset + usize::from(rec_len);
            if next > usable_end || offset + 8 + name_len > next {
                return None;
            }
            if inode != 0 && &block[offset + 8..offset + 8 + name_len] == name {
                return Some(RawDirEntryForTest { inode, file_type });
            }
            offset = next;
        }
        None
    }

    fn write_test_dir_entry(
        block: &mut [u8],
        offset: usize,
        inode: u32,
        rec_len: u16,
        name: &[u8],
        file_type: u8,
    ) {
        block[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        block[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
        block[offset + 6] = name.len() as u8;
        block[offset + 7] = file_type;
        block[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
    }

    fn set_inode_flags_in_image(
        image: &mut [u8],
        ext: &Ext,
        inum: u32,
        flags: crate::inode::InodeFlags,
    ) {
        let (inode_block, inode_offset, _inode_size) =
            Mutator::inode_table_slot_for_test(ext, inum).expect("locate inode");
        let flags_offset = inode_block as usize * ext.block_size() as usize + inode_offset + 0x20;
        let existing =
            u32::from_le_bytes(image[flags_offset..flags_offset + 4].try_into().unwrap());
        image[flags_offset..flags_offset + 4]
            .copy_from_slice(&(existing | flags.bits()).to_le_bytes());
    }

    fn synthetic_bigalloc_ext(
        group_count: u32,
        first_data_block: u32,
        blocks_per_group: u32,
        metadata_csum: bool,
    ) -> Ext {
        let desc_size = if metadata_csum { 64 } else { 32 };
        let mut ro_compat = crate::feature_flags::RoCompatFeatures::BIGALLOC;
        if metadata_csum {
            ro_compat |= crate::feature_flags::RoCompatFeatures::METADATA_CSUM;
        }
        let group_descs = (0..group_count)
            .map(|group| crate::block_group::GroupDescriptor {
                block_bitmap: 20 + u64::from(group) * 3,
                inode_bitmap: 21 + u64::from(group) * 3,
                inode_table: 22 + u64::from(group) * 3,
                free_blocks_count: 10,
                free_inodes_count: 0,
                flags: 0,
                checksum: crate::checksum::ChecksumState::Unknown,
            })
            .collect();

        Ext {
            inodes_count: 64,
            blocks_count: u64::from(first_data_block)
                .saturating_add(u64::from(group_count) * u64::from(blocks_per_group))
                .max(128),
            block_size: 1024,
            group_count,
            inodes_per_group: 4,
            inode_size: 128,
            first_data_block,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                first_data_block,
                1024,
                blocks_per_group,
                desc_size,
                0,
                false,
                false,
                false,
                [0, 0],
                group_count,
                0,
            )
            .expect("test layout"),
            blocks_per_group,
            cluster_size: 4096,
            blocks_per_cluster: 4,
            clusters_per_group: blocks_per_group / 4,
            backup_bgs: [0, 0],
            desc_size,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat,
            compat: crate::feature_flags::CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: metadata_csum,
            uuid: [0xA5u8; 16],
            hash_seed: [0u32; 4],
            group_descs,
            checksum_seed: metadata_csum.then_some(0x1234_5678),
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        }
    }

    fn synthetic_overlay(ext: &Ext) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0u8; ext.blocks_count as usize * ext.block_size() as usize];
        for group in 0..ext.group_count {
            let desc_offset = gdt_desc_byte_offset(ext, group);
            let desc = &mut bytes[desc_offset..desc_offset + usize::from(ext.desc_size)];
            let gdp = &ext.group_descs[group as usize];
            desc[0x00..0x04].copy_from_slice(&(gdp.block_bitmap as u32).to_le_bytes());
            desc[0x04..0x08].copy_from_slice(&(gdp.inode_bitmap as u32).to_le_bytes());
            desc[0x08..0x0C].copy_from_slice(&(gdp.inode_table as u32).to_le_bytes());
            desc[0x0C..0x0E].copy_from_slice(&(gdp.free_blocks_count as u16).to_le_bytes());
            desc[0x0E..0x10].copy_from_slice(&(gdp.free_inodes_count as u16).to_le_bytes());
            desc[0x12..0x14].copy_from_slice(&gdp.flags.to_le_bytes());
            if ext.desc_size >= 64 {
                desc[0x2C..0x2E]
                    .copy_from_slice(&((gdp.free_blocks_count >> 16) as u16).to_le_bytes());
                desc[0x2E..0x30]
                    .copy_from_slice(&((gdp.free_inodes_count >> 16) as u16).to_le_bytes());
            }
        }
        bytes
    }

    fn set_synthetic_bitmap_bit(
        bytes: &mut [u8],
        ext: &Ext,
        group: u32,
        bit: u64,
        allocated: bool,
    ) {
        let block = ext.group_descs[group as usize].block_bitmap;
        let byte_offset = block as usize * ext.block_size() as usize + (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        if allocated {
            bytes[byte_offset] |= mask;
        } else {
            bytes[byte_offset] &= !mask;
        }
    }

    fn finalized_gdt_block<'a>(
        delta: &'a crate::orphan::plan::OrphanOverlayDelta,
        ext: &Ext,
        group: u32,
    ) -> &'a [u8] {
        let gdt_block = u64::from(ext.first_data_block)
            + 1
            + (u64::from(group) * u64::from(ext.desc_size)) / u64::from(ext.block_size);
        delta.blocks.get(&gdt_block).expect("gdt dirtied")
    }

    fn finalized_group_desc<'a>(
        delta: &'a crate::orphan::plan::OrphanOverlayDelta,
        ext: &Ext,
        group: u32,
    ) -> &'a [u8] {
        let gdt = finalized_gdt_block(delta, ext, group);
        let offset =
            (u64::from(group) * u64::from(ext.desc_size) % u64::from(ext.block_size)) as usize;
        &gdt[offset..offset + usize::from(ext.desc_size)]
    }

    fn finalized_bitmap<'a>(
        delta: &'a crate::orphan::plan::OrphanOverlayDelta,
        ext: &Ext,
        group: u32,
    ) -> &'a [u8] {
        let bitmap_block = ext.group_descs[group as usize].block_bitmap;
        delta.blocks.get(&bitmap_block).expect("bitmap dirtied")
    }

    fn gdt_desc_byte_offset(ext: &Ext, group: u32) -> usize {
        ((u64::from(ext.first_data_block) + 1) * u64::from(ext.block_size)
            + u64::from(group) * u64::from(ext.desc_size)) as usize
    }

    fn decode_bg_free_blocks_count(gdt_block_bytes: &[u8], ext: &Ext, group: u32) -> u32 {
        let byte_offset = (u64::from(group) * u64::from(ext.desc_size)) % u64::from(ext.block_size);
        let desc =
            &gdt_block_bytes[byte_offset as usize..byte_offset as usize + ext.desc_size as usize];
        let lo = u16::from_le_bytes(desc[0x0C..0x0E].try_into().unwrap()) as u32;
        let hi = if ext.desc_size >= 64 {
            u16::from_le_bytes(desc[0x2C..0x2E].try_into().unwrap()) as u32
        } else {
            0
        };
        (hi << 16) | lo
    }

    fn decode_sb_free_blocks_count(sb_host_bytes: &[u8], ext: &Ext) -> u64 {
        let sb_offset = if ext.block_size() > 1024 { 1024 } else { 0 };
        let lo = u32::from_le_bytes(
            sb_host_bytes[sb_offset + 0x0C..sb_offset + 0x10]
                .try_into()
                .unwrap(),
        );
        let hi = if ext.is_64bit {
            u32::from_le_bytes(
                sb_host_bytes[sb_offset + 0x150..sb_offset + 0x154]
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };
        (u64::from(hi) << 32) | u64::from(lo)
    }

    fn decode_block_bitmap_bit(bitmap_bytes: &[u8], bit: u64) -> bool {
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        bitmap_bytes[byte] & mask != 0
    }

    #[test]
    fn block_class_group_descriptor_carries_desc_block_nr() {
        // Constructing the variant requires the new field.
        let class = BlockClass::GroupDescriptor { desc_block_nr: 7 };
        if let BlockClass::GroupDescriptor { desc_block_nr } = class {
            assert_eq!(desc_block_nr, 7);
        } else {
            panic!("variant mismatch");
        }
    }

    #[test]
    fn group_desc_slot_classical_unchanged() {
        let bytes = crate::test_support::load_clean_ext4_image();
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = crate::Ext::new(&mut cursor).expect("open ext4.img");
        let sb_host = alloc::vec![0u8; ext.block_size() as usize];
        let mutator = Mutator::new(&ext, &sb_host);

        // Classical layout: gdt_block = first_data_block + 1 + group / desc_per_block.
        let (gdt_block, _, _) = mutator.group_desc_slot(0).expect("group 0 slot");
        let expected = u64::from(ext.first_data_block) + 1;
        assert_eq!(gdt_block, expected);
    }

    #[test]
    fn descriptor_recompute_uses_block_class_metadata_not_arithmetic() {
        if !crate::test_support::fixture_available("ext4-meta-bg.img") {
            eprintln!("skipping: ext4-meta-bg.img fixture not generated");
            return;
        }
        let mut cursor = crate::test_support::load_image("ext4-meta-bg.img");
        let ext = crate::Ext::new(&mut cursor).expect("open ext4-meta-bg.img");
        let dpb = ext.gdt_layout.desc_per_block();
        let group = dpb; // first group of metagroup 1 — in the META_BG range.
        if group >= ext.group_count() {
            eprintln!("skipping: fixture too small");
            return;
        }

        let sb_host = alloc::vec![0u8; ext.block_size() as usize];
        let mut mutator = Mutator::new(&ext, &sb_host);

        // Mark a block in `group` free to dirty that group's GDT descriptor.
        let group_first =
            u64::from(ext.first_data_block) + u64::from(group) * u64::from(ext.blocks_per_group);
        mutator
            .mark_block_range_free(&mut cursor, group_first + 100, 1)
            .expect("mark free");

        let delta = mutator.finalize(&mut cursor).expect("finalize");

        // The META_BG GDT block for `group` must appear in the overlay.
        let expected_gdt_block =
            crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group);
        let bytes = delta
            .blocks
            .get(&expected_gdt_block)
            .expect("META_BG GDT block must be patched");

        // The recomputed CRC for `group` must validate.
        let csum_seed = ext
            .checksum_seed()
            .expect("metadata_csum must be on for this fixture");
        let desc_idx = (group % dpb) as usize;
        let desc_size = usize::from(ext.desc_size);
        let off = desc_idx * desc_size;
        let state = crate::checksum::verify_group_descriptor(
            csum_seed,
            group,
            &bytes[off..off + desc_size],
        );
        assert!(
            matches!(state, crate::checksum::ChecksumState::Valid),
            "recomputed CRC must validate, got {state:?}"
        );
    }

    #[test]
    fn group_desc_slot_meta_bg_pure_uses_descriptor_block_for_group() {
        if !crate::test_support::fixture_available("ext4-meta-bg.img") {
            eprintln!("skipping: ext4-meta-bg.img fixture not generated");
            return;
        }
        let mut cursor = crate::test_support::load_image("ext4-meta-bg.img");
        let ext = crate::Ext::new(&mut cursor).expect("open ext4-meta-bg.img");
        assert!(ext.is_meta_bg());

        let sb_host = alloc::vec![0u8; ext.block_size() as usize];
        let mutator = Mutator::new(&ext, &sb_host);

        // Pick a group in the META_BG range (any group in metagroup >= 1).
        let dpb = ext.gdt_layout.desc_per_block();
        let group_in_meta_bg = dpb; // first group of metagroup 1.
        if group_in_meta_bg >= ext.group_count() {
            eprintln!("skipping: fixture too small for META_BG range");
            return;
        }
        let (gdt_block, _, _) = mutator.group_desc_slot(group_in_meta_bg).expect("slot");

        // Expected via the new helper; must NOT match classical formula.
        let expected =
            crate::block_group::descriptor_block_for_group(&ext.gdt_layout, group_in_meta_bg);
        let classical =
            u64::from(ext.first_data_block) + 1 + u64::from(group_in_meta_bg) / u64::from(dpb);
        assert_eq!(gdt_block, expected);
        assert_ne!(
            gdt_block, classical,
            "META_BG block must not equal classical formula"
        );
    }

    #[test]
    fn group_desc_slot_meta_bg_mixed() {
        if !crate::test_support::fixture_available("ext4-meta-bg.img") {
            eprintln!("skipping: ext4-meta-bg.img fixture not generated");
            return;
        }
        let mut bytes = crate::test_support::load_image("ext4-meta-bg.img").into_inner();

        // Patch s_first_meta_bg = 1 to enable mixed mode: groups in metagroup 0
        // use the classical GDT layout, groups >= dpb use the META_BG layout.
        let s_first_meta_bg_offset = 1024 + 0x104;
        bytes[s_first_meta_bg_offset..s_first_meta_bg_offset + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        let sb: &[u8; 1024] = (&bytes[1024..2048]).try_into().unwrap();
        let new_csum = crate::checksum::compute_superblock_csum(sb);
        bytes[1024 + 0x3FC..1024 + 0x400].copy_from_slice(&new_csum.to_le_bytes());

        let mut cursor = std::io::Cursor::new(bytes);
        let ext = crate::Ext::new(&mut cursor).expect("open mixed-mode patch");
        assert!(ext.is_meta_bg());
        assert_eq!(ext.gdt_layout.first_meta_bg(), 1);

        let sb_host = alloc::vec![0u8; ext.block_size() as usize];
        let mutator = Mutator::new(&ext, &sb_host);

        // Group 0 is in the classical prefix (desc_block_nr 0 < first_meta_bg=1).
        let (gdt_block_classical, _, _) = mutator.group_desc_slot(0).expect("slot 0");
        let expected_classical = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, 0);
        assert_eq!(gdt_block_classical, expected_classical);

        // Group dpb is the first group in metagroup 1 (META_BG range).
        let dpb = ext.gdt_layout.desc_per_block();
        if dpb >= ext.group_count() {
            eprintln!("skipping mixed-mode META_BG branch: fixture too small");
            return;
        }
        let (gdt_block_meta_bg, _, _) = mutator.group_desc_slot(dpb).expect("slot dpb");
        let expected_meta_bg = crate::block_group::descriptor_block_for_group(&ext.gdt_layout, dpb);
        assert_eq!(gdt_block_meta_bg, expected_meta_bg);

        // Mixed-mode produces different GDT block addresses for the two groups.
        assert_ne!(
            gdt_block_classical, gdt_block_meta_bg,
            "mixed-mode classical and META_BG groups must resolve to different GDT blocks"
        );
    }
}
