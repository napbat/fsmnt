//! `OrphanReplay`: composes a consumed `JournalReplay` with orphan-specific
//! overlay patches and exposes the merged view via `OverlaySource`.

use alloc::vec::Vec;

use crate::error::{ExtError, Result};
use crate::inode::InodeFlags;
use crate::io::{Read, Seek};
use crate::journal::{JournalReplay, OverlaySource};
use crate::orphan::apply::{ClassifiedApply, classify_apply};
use crate::orphan::ea_inode::apply_ea_inode_plan;
use crate::orphan::mutator::{AllocationKind, AllocationRun, Mutator, MutatorError, MutatorResult};
use crate::orphan::parse::{detect_duplicates, scan_orphan_file, walk_legacy_chain};
use crate::orphan::plan::{
    OrphanDisposition, OrphanOverlayDelta, OrphanPlan, OrphanPosition, OrphanStop,
};
use crate::orphan::shared_xattr::apply_shared_xattr_plan;
use crate::orphan::truncate::complete_truncate;

/// Final orphan-recovery artifact. Owns the consumed journal artifact,
/// the forensic plan, and the orphan-specific delta.
#[derive(Debug)]
pub struct OrphanReplay {
    pub(crate) journal: JournalReplay,
    pub(crate) plan: OrphanPlan,
    pub(crate) overlay: OrphanOverlayDelta,
}

impl OrphanReplay {
    /// Forensic record of the consumed journal replay.
    #[must_use]
    pub fn journal_plan(&self) -> &crate::journal::ReplayPlan {
        self.journal.plan()
    }

    /// Orphan-stage forensic record.
    #[must_use]
    pub fn orphan_plan(&self) -> &OrphanPlan {
        &self.plan
    }

    /// Drop the overlay and return both plans.
    #[must_use]
    pub fn into_plans(self) -> (crate::journal::ReplayPlan, OrphanPlan) {
        (self.journal.into_plan(), self.plan)
    }

    /// Returns `true` when the orphan overlay delta is empty — no block patches
    /// and no superblock override were produced.
    ///
    /// A stop path must leave the delta empty (the atomic-contract invariant).
    /// Integration tests call this to assert that invariant without accessing the
    /// private `OrphanOverlayDelta` type directly.
    #[must_use]
    pub fn delta_is_empty(&self) -> bool {
        self.overlay.is_empty()
    }

    /// Build an orphan replay artifact by consuming a `JournalReplay`.
    ///
    /// # Errors
    ///
    /// Returns an I/O or ext metadata error if orphan discovery cannot be
    /// completed safely. Recoverable forensic stops are stored in
    /// [`OrphanPlan::stop`] and still return an artifact.
    pub fn build<T: Read + Seek>(
        journal: JournalReplay,
        ext: &crate::ext::Ext,
        fs: &mut T,
    ) -> Result<Self> {
        let mut plan = OrphanPlan::default();
        let commit_secs = latest_commit_seconds(&journal);
        parse_orphan_sources(ext, fs, &journal, &mut plan)?;
        if plan.stop.is_some() {
            return Ok(stopped_replay(journal, plan));
        }

        let classified = {
            let mut reader = crate::OverlayReader::new(fs, &journal);
            classify_apply(ext, &mut reader, &mut plan)?
        };
        if plan.stop.is_some() {
            return Ok(stopped_replay(journal, plan));
        }

        let sb_host_bytes = crate::journal::OverlaySource::sb_host_block_content(&journal);
        let mut mutator = Mutator::new(ext, sb_host_bytes);
        apply_orphan_mutations(
            ext,
            fs,
            &journal,
            &mut mutator,
            &mut plan,
            &classified,
            commit_secs,
        )?;
        if plan.stop.is_some() {
            return Ok(stopped_replay(journal, plan));
        }

        patch_orphan_linkage_in_sb(ext, &mut mutator)?;
        let delta = mutator.finalize(fs).map_err(|e| match e {
            MutatorError::Ext(ext_err) => ext_err,
            MutatorError::BigallocClusterOverlap { .. } => {
                ExtError::InvalidExtentHeader { inode: 0 }
            }
        })?;

        Ok(Self {
            journal,
            plan,
            overlay: delta,
        })
    }
}

fn stopped_replay(journal: JournalReplay, plan: OrphanPlan) -> OrphanReplay {
    OrphanReplay {
        journal,
        plan,
        overlay: OrphanOverlayDelta::default(),
    }
}

fn latest_commit_seconds(journal: &JournalReplay) -> Option<u32> {
    journal
        .plan()
        .committed
        .last()
        .and_then(|transaction| transaction.commit_time)
        .and_then(|time| u32::try_from(time.secs & u64::from(u32::MAX)).ok())
}

fn parse_orphan_sources<T: Read + Seek>(
    ext: &crate::ext::Ext,
    fs: &mut T,
    journal: &JournalReplay,
    plan: &mut OrphanPlan,
) -> Result<()> {
    let mut reader = crate::OverlayReader::new(fs, journal);
    let head = read_s_last_orphan(&mut reader)?;
    walk_legacy_chain(ext, &mut reader, head, plan)?;
    if plan.stop.is_none() {
        scan_orphan_file(ext, &mut reader, plan)?;
    }
    detect_duplicates(plan);
    Ok(())
}

fn handle_mutator_result(plan: &mut OrphanPlan, result: MutatorResult<()>) -> Result<bool> {
    match result {
        Ok(()) => Ok(false),
        Err(MutatorError::Ext(error)) => Err(error),
        Err(MutatorError::BigallocClusterOverlap {
            inode,
            cluster,
            first_block,
            second_block,
        }) => {
            plan.stop = Some(OrphanStop {
                position: OrphanPosition::Apply,
                reason: crate::orphan::plan::OrphanStopReason::BigallocClusterOverlap {
                    inode,
                    cluster,
                    first_block,
                    second_block,
                },
            });
            Ok(true)
        }
    }
}

fn free_unlinked_hosts<T: Read + Seek>(
    ext: &crate::ext::Ext,
    reader: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &mut OrphanPlan,
    classified: &ClassifiedApply,
    commit_secs: Option<u32>,
) -> Result<bool> {
    for &inode_number in &classified.unique_unlinked {
        let inode = ext.inode(reader, inode_number)?;
        let was_directory = inode.is_directory();
        let runs = collect_unlinked_host_runs(ext, reader, &inode, inode_number)?;
        if handle_mutator_result(plan, mutator.free_allocations(reader, inode_number, &runs))? {
            return Ok(true);
        }
        if handle_mutator_result(
            plan,
            mutator.clear_inode_bitmap_bit(reader, inode_number, was_directory),
        )? {
            return Ok(true);
        }
        let deletion_time = commit_secs.unwrap_or(0);
        if handle_mutator_result(
            plan,
            mutator.patch_inode_scratch(reader, inode_number, |inode_bytes| {
                inode_bytes.fill(0);
                inode_bytes[0x14..0x18].copy_from_slice(&deletion_time.to_le_bytes());
                Ok(())
            }),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn apply_reference_plans<T: Read + Seek>(
    ext: &crate::ext::Ext,
    reader: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &mut OrphanPlan,
    classified: &ClassifiedApply,
) -> Result<bool> {
    if handle_mutator_result(
        plan,
        apply_ea_inode_plan(ext, reader, mutator, &classified.ea_plan),
    )? {
        return Ok(true);
    }
    handle_mutator_result(
        plan,
        apply_shared_xattr_plan(
            ext,
            reader,
            mutator,
            &classified.xattr_plan,
            &classified.xattr_refs,
        ),
    )
}

fn truncate_deferred_inodes<T: Read + Seek>(
    ext: &crate::ext::Ext,
    reader: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &mut OrphanPlan,
    classified: &ClassifiedApply,
) -> Result<bool> {
    for &inode_number in &classified.unique_truncate {
        let target_size = ext.inode(reader, inode_number)?.size();
        if handle_mutator_result(
            plan,
            complete_truncate(ext, reader, mutator, inode_number, target_size),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn clear_source_linkage<T: Read + Seek>(
    ext: &crate::ext::Ext,
    reader: &mut T,
    mutator: &mut Mutator<'_>,
    plan: &mut OrphanPlan,
) -> Result<bool> {
    let legacy_truncates: Vec<u32> = plan
        .legacy
        .iter()
        .filter(|entry| matches!(entry.disposition, OrphanDisposition::TruncateDeferred))
        .map(|entry| entry.inode)
        .collect();
    for inode_number in legacy_truncates {
        if handle_mutator_result(
            plan,
            mutator.patch_inode_scratch(reader, inode_number, |inode_bytes| {
                inode_bytes[0x14..0x18].copy_from_slice(&0u32.to_le_bytes());
                Ok(())
            }),
        )? {
            return Ok(true);
        }
    }
    if !ext.has_orphan_file() || !ext.has_orphan_present() {
        return Ok(false);
    }

    let entries: Vec<(u32, u32)> = plan
        .orphan_file
        .iter()
        .map(|entry| (entry.file_block_index, entry.slot_index))
        .collect();
    let orphan_inode_number = ext.orphan_file_inum();
    let orphan_inode = ext.inode(reader, orphan_inode_number)?;
    let orphan_generation = orphan_inode.generation();
    let orphan_file = orphan_inode.open_file()?;
    for (file_block_index, slot_index) in entries {
        let fs_block = orphan_file.logical_to_physical_block(reader, file_block_index)?;
        let slot_offset = usize::try_from(slot_index)
            .ok()
            .and_then(|slot| slot.checked_mul(4))
            .ok_or(ExtError::InvalidOrphanFile {
                reason: "slot offset exceeds addressable memory",
            })?;
        if handle_mutator_result(
            plan,
            mutator.patch_orphan_file_block(
                reader,
                fs_block,
                orphan_inode_number,
                orphan_generation,
                |buffer| {
                    buffer[slot_offset..slot_offset + 4].fill(0);
                    Ok(())
                },
            ),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn apply_orphan_mutations<T: Read + Seek>(
    ext: &crate::ext::Ext,
    fs: &mut T,
    journal: &JournalReplay,
    mutator: &mut Mutator<'_>,
    plan: &mut OrphanPlan,
    classified: &ClassifiedApply,
    commit_secs: Option<u32>,
) -> Result<()> {
    let mut reader = crate::OverlayReader::new(fs, journal);
    if free_unlinked_hosts(ext, &mut reader, mutator, plan, classified, commit_secs)?
        || apply_reference_plans(ext, &mut reader, mutator, plan, classified)?
        || truncate_deferred_inodes(ext, &mut reader, mutator, plan, classified)?
    {
        return Ok(());
    }
    clear_source_linkage(ext, &mut reader, mutator, plan)?;
    Ok(())
}

impl OverlaySource for OrphanReplay {
    fn block_size(&self) -> u32 {
        OverlaySource::block_size(&self.journal)
    }

    fn sb_host_block(&self) -> u64 {
        OverlaySource::sb_host_block(&self.journal)
    }

    fn sb_host_block_content(&self) -> &[u8] {
        match &self.overlay.sb_host_override {
            Some(content) => content,
            None => OverlaySource::sb_host_block_content(&self.journal),
        }
    }

    fn overlay_block(&self, fs_block: u64) -> Option<&[u8]> {
        self.overlay
            .blocks
            .get(&fs_block)
            .map(core::convert::AsRef::as_ref)
            .or_else(|| OverlaySource::overlay_block(&self.journal, fs_block))
    }
}

/// Collect `AllocationRun`s for an Unlinked host's owned data/metadata blocks.
///
/// Walks the inode's extent tree via `collect_tagged_extent_blocks_into` and
/// emits leaf extents as `Data` runs (preserving the `ee_block`-derived
/// logical cluster) and extent-tree index blocks as `Metadata` runs. The
/// host's xattr block is intentionally excluded here — it is handled by
/// `apply_shared_xattr_plan` in step 3.
fn collect_unlinked_host_runs<T: Read + Seek>(
    ext: &crate::ext::Ext,
    overlay: &mut T,
    inode: &crate::inode::ExtInode<'_>,
    inum: u32,
) -> Result<Vec<AllocationRun>> {
    if !inode.flags().contains(InodeFlags::EXTENTS_FL) {
        // EA inodes and inline-data inodes use i_block as raw data storage, not
        // as a block-pointer map.  Their bytes are not filesystem block numbers;
        // walking them as an indirect-block map would misinterpret arbitrary data
        // bytes as pointers and could raise spurious InvalidIndirectBlock errors.
        // Return empty: the bitmap accounting for these special formats is handled
        // elsewhere (EA inodes → apply_ea_inode_plan; inline data → no data blocks).
        if flags_indicate_raw_iblock_storage(inode.flags()) {
            return Ok(Vec::new());
        }
        let i_block = inode.i_block();
        let result = crate::orphan::truncate::walk_indirect_map(
            ext, overlay, inum, &i_block, 0, // cutoff = 0 frees every allocated block
        )?;
        // result.new_i_block and surviving_* are unused — the caller zeroes the
        // inode entirely via the inode-table scratch, so there is nothing to
        // patch back.
        return Ok(result.freed_runs);
    }

    let mut tagged: Vec<crate::extent::ExtentAllocation> = Vec::new();
    let i_block = inode.i_block();
    let generation = inode.generation();
    crate::extent::collect_tagged_extent_blocks_into(
        ext,
        overlay,
        inum,
        generation,
        &i_block,
        &mut tagged,
    )?;

    let blocks_per_cluster = u64::from(ext.blocks_per_cluster());
    let runs = tagged
        .into_iter()
        .map(|e| match e {
            crate::extent::ExtentAllocation::Data {
                physical_start,
                block_len,
                logical_block_start,
            } => AllocationRun {
                physical_start,
                block_len,
                kind: AllocationKind::Data {
                    logical_cluster_start: u64::from(logical_block_start) / blocks_per_cluster,
                },
            },
            crate::extent::ExtentAllocation::IndexBlock(block) => AllocationRun {
                physical_start: block,
                block_len: 1,
                kind: AllocationKind::Metadata,
            },
        })
        .collect();
    Ok(runs)
}

/// Whether `i_flags` indicates the inode stores raw bytes in `i_block`
/// (rather than the usual block-pointer map / extent tree). Currently
/// `EA_INODE_FL` and `INLINE_DATA_FL` both opt into raw `i_block`
/// storage; misinterpreting their bytes as block numbers would raise
/// spurious `InvalidIndirectBlock` errors during orphan recovery.
///
/// Extracted so `#[cfg_attr(test, mutants::skip)]` applies only to the
/// flag-combination expression: `EA_INODE_FL (0x00200000)` and
/// `INLINE_DATA_FL (0x10000000)` occupy disjoint bit positions, so
/// `EA_INODE_FL | INLINE_DATA_FL` and `EA_INODE_FL ^ INLINE_DATA_FL`
/// produce identical bit sets — the `| -> ^` mutant is equivalent. See
/// `crates/fs-ext/docs/mutation-testing.md`.
#[cfg_attr(test, mutants::skip)]
fn flags_indicate_raw_iblock_storage(flags: InodeFlags) -> bool {
    flags.intersects(InodeFlags::EA_INODE_FL | InodeFlags::INLINE_DATA_FL)
}

/// Clear the `RO_COMPAT_ORPHAN_PRESENT` bit and zero `s_last_orphan` in the
/// mutator's sb-host scratch. The `s_checksum` is recomputed by `finalize`.
fn patch_orphan_linkage_in_sb(ext: &crate::ext::Ext, mutator: &mut Mutator) -> Result<()> {
    const RO_COMPAT_ORPHAN_PRESENT_BIT: u32 = 0x0001_0000;
    const S_FEATURE_RO_COMPAT_OFFSET: usize = 0x64;
    const S_LAST_ORPHAN_OFFSET: usize = 0xE8;

    // Superblock starts at byte 1024 within the host block for block_size > 1024,
    // or at byte 0 for 1 KiB block_size (where the sb is in block 1, offset 0).
    let sb_off: usize = if ext.block_size() > 1024 { 1024 } else { 0 };

    mutator
        .patch_superblock_bytes(|host| {
            let ro_off = sb_off + S_FEATURE_RO_COMPAT_OFFSET;
            let mut ro_compat =
                u32::from_le_bytes(host[ro_off..ro_off + 4].try_into().expect("4 bytes"));
            ro_compat &= !RO_COMPAT_ORPHAN_PRESENT_BIT;
            host[ro_off..ro_off + 4].copy_from_slice(&ro_compat.to_le_bytes());

            let lo_off = sb_off + S_LAST_ORPHAN_OFFSET;
            host[lo_off..lo_off + 4].fill(0);
            Ok(())
        })
        .map_err(|e| match e {
            MutatorError::Ext(ext_err) => ext_err,
            MutatorError::BigallocClusterOverlap { .. } => unreachable!(),
        })
}

/// Read the post-journal superblock's `s_last_orphan` through the overlay.
fn read_s_last_orphan<T: Read + Seek>(overlay: &mut T) -> Result<u32> {
    const S_LAST_ORPHAN_OFFSET: u64 = 0xE8;
    let mut buf = [0u8; 4];
    overlay.seek(crate::io::SeekFrom::Start(
        crate::superblock::SUPERBLOCK_OFFSET + S_LAST_ORPHAN_OFFSET,
    ))?;
    overlay.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

#[cfg(test)]
#[path = "replay_tests/mod.rs"]
mod tests;
