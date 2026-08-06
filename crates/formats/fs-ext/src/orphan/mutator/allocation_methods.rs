use super::{
    AllocationKind, AllocationRun, BTreeMap, BTreeSet, BlockClass, Box, CurrentDirInode,
    DirLeafAppendCtx, ExtError, GroupTally, Mutator, MutatorError, MutatorResult, Read, Seek,
    aligned_dir_entry_len, allocation_units_per_group, apply_dir_append_slot,
    apply_dir_remove_slot, apply_group_tally, apply_sb_tallies, find_dir_append_slot,
    find_dir_remove_slot, mark_bitmap_bits, project_block_range_to_alloc_units, read_desc_u16,
    recompute_block_checksums, recompute_group_descriptor_checksums, refresh_dir_tail_checksum,
    resolve_dir_logical_block, validate_dir_tail_checksum, write_desc_u16, write_desc_u32_split,
};

#[cfg(test)]
use super::Ext;

impl Mutator<'_> {
    /// Locate `(block_num, byte_offset_within_block, inode_size)` for `inum`.
    /// Mirrors `apply::inode_block_and_offset` but also returns `inode_size`.
    pub(super) fn inode_table_slot(&self, inum: u32) -> MutatorResult<(u64, usize, usize)> {
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
        let offset_in_block = usize::try_from(byte_in_table % block_size)
            .expect("the test fixture value fits in usize");
        Ok((
            block,
            offset_in_block,
            usize::try_from(inode_size).expect("the test fixture value fits in usize"),
        ))
    }

    pub(super) fn group_of_inode(&self, inum: u32) -> u32 {
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
            let group = u32::try_from(repr_rel / blocks_per_group)
                .expect("the test fixture value fits in u32");
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
            let group = u32::try_from(alloc_unit / clusters_per_group)
                .expect("the test fixture value fits in u32");
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
            let group = u32::try_from((start_group as usize + offset) % group_count)
                .expect("the test fixture value fits in u32");
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
    pub(super) fn group_desc_slot(&self, group: u32) -> MutatorResult<(u64, usize, usize)> {
        let layout = &self.ext.gdt_layout;
        let desc_size = u64::from(layout.desc_size());
        let block_size = u64::from(layout.block_size());
        let gdt_block = crate::block_group::descriptor_block_for_group(layout, group);
        let byte_offset_in_block = u64::from(group % layout.desc_per_block()) * desc_size;
        let offset = usize::try_from(byte_offset_in_block % block_size).map_err(|_| {
            MutatorError::Ext(ExtError::InvalidGroupDescriptor {
                group,
                reason: "descriptor offset exceeds addressable memory",
            })
        })?;
        Ok((
            gdt_block,
            offset,
            usize::try_from(desc_size).map_err(|_| {
                MutatorError::Ext(ExtError::InvalidGroupDescriptor {
                    group,
                    reason: "descriptor size exceeds addressable memory",
                })
            })?,
        ))
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
        let offset_in_block = usize::try_from(byte_in_table % block_size)
            .expect("the test fixture value fits in usize");
        Ok((
            block,
            offset_in_block,
            usize::try_from(inode_size).expect("the test fixture value fits in usize"),
        ))
    }
}
