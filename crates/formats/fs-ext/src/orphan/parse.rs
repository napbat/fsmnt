//! Parse phase: legacy chain walker and orphan-file scanner.

use alloc::collections::BTreeSet;

use crate::checksum::{ChecksumState, ORPHAN_FILE_MAGIC, verify_orphan_file_block};
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::inode::{ExtInode, InodeFlags};
use crate::io::{FsReadSeek, Read, Seek, SeekFrom};
use crate::orphan::plan::{
    LegacyOrphanEntry, OrphanDisposition, OrphanFileEntry, OrphanPlan, OrphanPosition,
    OrphanSourceKind, OrphanStop, OrphanStopReason, OrphanWarning, OrphanWarningKind,
};

/// Walk the legacy `s_last_orphan` chain via the post-journal overlay and
/// append each visited entry to `plan.legacy`. On cycle / out-of-range inode,
/// sets `plan.stop` and returns.
pub(crate) fn walk_legacy_chain<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    head: u32,
    plan: &mut OrphanPlan,
) -> Result<()> {
    let mut cur = head;
    let mut visited: BTreeSet<u32> = BTreeSet::new();

    while cur != 0 {
        if !visited.insert(cur) {
            plan.stop = Some(OrphanStop {
                position: OrphanPosition::LegacyInode { inode: cur },
                reason: OrphanStopReason::LegacyChainCycle { at_inode: cur },
            });
            return Ok(());
        }
        match ext.inode(overlay, cur) {
            Ok(inode) => {
                let raw_dtime = inode.raw_i_dtime();
                plan.legacy.push(LegacyOrphanEntry {
                    inode: cur,
                    next_legacy: raw_dtime,
                    mode: inode.mode(),
                    links_count: inode.links_count(),
                    size: inode.size(),
                    disposition: if inode.links_count() == 0 {
                        OrphanDisposition::Unlinked
                    } else {
                        OrphanDisposition::TruncateDeferred
                    },
                });
                cur = raw_dtime;
            }
            Err(ExtError::InodeOutOfRange { inode }) => {
                let position = if plan.legacy.is_empty() {
                    OrphanPosition::LegacyHead
                } else {
                    OrphanPosition::LegacyInode { inode: cur }
                };
                plan.stop = Some(OrphanStop {
                    position,
                    reason: OrphanStopReason::LegacyChainInodeOutOfRange { inode },
                });
                return Ok(());
            }
            Err(other) => return Err(other),
        }
    }
    Ok(())
}

/// Validated orphan-file inode handle plus its block count. Constructed once
/// per scan in [`validate_orphan_file_inode`].
pub(crate) struct ValidatedOrphanFile<'e> {
    pub(crate) inode: ExtInode<'e>,
    pub(crate) inum: u32,
    pub(crate) generation: u32,
    pub(crate) block_count: u32,
}

/// Load the orphan-file inode via the post-journal overlay and validate that
/// it is shaped the way the kernel produces. Returns:
///
/// - `Err(OrphanFileInodeZero)` when `inum == 0`.
/// - `Err(InvalidOrphanFile { reason })` for non-regular, inline-data,
///   zero-sized, or non-block-aligned sizes.
/// - Other I/O / parse errors propagate unchanged.
pub(crate) fn validate_orphan_file_inode<'e, T: Read + Seek>(
    ext: &'e Ext,
    overlay: &mut T,
    inum: u32,
) -> Result<ValidatedOrphanFile<'e>> {
    if inum == 0 {
        return Err(ExtError::OrphanFileInodeZero);
    }
    let inode = ext.inode(overlay, inum)?;

    if !inode.is_regular_file() {
        return Err(ExtError::InvalidOrphanFile {
            reason: "inode is not a regular file",
        });
    }
    if inode.flags().contains(InodeFlags::INLINE_DATA_FL) {
        return Err(ExtError::InvalidOrphanFile {
            reason: "inode has INLINE_DATA_FL",
        });
    }
    let size = inode.size();
    if size == 0 {
        return Err(ExtError::InvalidOrphanFile {
            reason: "inode size is zero",
        });
    }
    let block_size = u64::from(ext.block_size());
    if size % block_size != 0 {
        return Err(ExtError::InvalidOrphanFile {
            reason: "inode size is not a whole number of blocks",
        });
    }
    let block_count = (size / block_size) as u32;
    let generation = inode.generation();
    Ok(ValidatedOrphanFile {
        inode,
        inum,
        generation,
        block_count,
    })
}

/// Scan the orphan file when both `COMPAT_ORPHAN_FILE` and
/// `RO_COMPAT_ORPHAN_PRESENT` are set. No-op otherwise.
///
/// Soft conditions (bad tail magic, bad CRC, out-of-range inode) populate
/// `plan.stop` and return `Ok(())`. Genuine I/O or parse failures propagate.
pub(crate) fn scan_orphan_file<T: Read + Seek>(
    ext: &Ext,
    overlay: &mut T,
    plan: &mut OrphanPlan,
) -> Result<()> {
    if !ext.has_orphan_file() || !ext.has_orphan_present() {
        return Ok(());
    }
    let validated = validate_orphan_file_inode(ext, overlay, ext.orphan_file_inum())?;
    let block_size = ext.block_size();
    let slots_per_block = (block_size - 8) / 4;

    let mut file = validated.inode.open_file()?;

    for block_idx in 0..validated.block_count {
        let mut buf = alloc::vec![0u8; block_size as usize];
        let offset = u64::from(block_idx) * u64::from(block_size);
        file.seek(overlay, SeekFrom::Start(offset))?;
        file.read_exact(overlay, &mut buf)?;

        // Resolve physical block number for checksum verification.
        let phys_block = file.logical_to_physical_block(overlay, block_idx)?;

        let tail_off = buf.len() - 8;
        let magic =
            u32::from_le_bytes(buf[tail_off..tail_off + 4].try_into().expect("fixed slice"));
        if magic != ORPHAN_FILE_MAGIC {
            plan.stop = Some(OrphanStop {
                position: OrphanPosition::OrphanFileBlock {
                    file_block_index: block_idx,
                    slot_index: None,
                },
                reason: OrphanStopReason::OrphanFileTailMagicInvalid,
            });
            return Ok(());
        }

        if let Some(seed) = ext.checksum_seed() {
            match verify_orphan_file_block(
                seed,
                validated.inum,
                validated.generation,
                phys_block,
                &buf,
            ) {
                ChecksumState::Valid | ChecksumState::Unknown => {}
                ChecksumState::Invalid => {
                    plan.stop = Some(OrphanStop {
                        position: OrphanPosition::OrphanFileBlock {
                            file_block_index: block_idx,
                            slot_index: None,
                        },
                        reason: OrphanStopReason::OrphanFileChecksumInvalid,
                    });
                    return Ok(());
                }
            }
        }

        for slot in 0..slots_per_block {
            let off = (slot as usize) * 4;
            let raw = u32::from_le_bytes(buf[off..off + 4].try_into().expect("fixed slice"));
            if raw == 0 {
                continue;
            }
            match ext.inode(overlay, raw) {
                Ok(inode) => {
                    plan.orphan_file.push(OrphanFileEntry {
                        inode: raw,
                        file_block_index: block_idx,
                        slot_index: slot,
                        mode: inode.mode(),
                        links_count: inode.links_count(),
                        size: inode.size(),
                        disposition: if inode.links_count() == 0 {
                            OrphanDisposition::Unlinked
                        } else {
                            OrphanDisposition::TruncateDeferred
                        },
                    });
                }
                Err(ExtError::InodeOutOfRange { inode }) => {
                    plan.stop = Some(OrphanStop {
                        position: OrphanPosition::OrphanFileBlock {
                            file_block_index: block_idx,
                            slot_index: Some(slot),
                        },
                        reason: OrphanStopReason::OrphanFileInodeOutOfRange { inode },
                    });
                    return Ok(());
                }
                Err(other) => return Err(other),
            }
        }
    }
    Ok(())
}

/// Populate `plan.warnings` with one `DuplicateInode` entry per inode
/// appearing in both source lists. Preserves entry membership in both
/// `plan.legacy` and `plan.orphan_file`.
pub(crate) fn detect_duplicates(plan: &mut OrphanPlan) {
    let legacy_set: BTreeSet<u32> = plan.legacy.iter().map(|e| e.inode).collect();
    for entry in &plan.orphan_file {
        if legacy_set.contains(&entry.inode) {
            plan.warnings.push(OrphanWarning {
                kind: OrphanWarningKind::DuplicateInode {
                    inode: entry.inode,
                    first_source: OrphanSourceKind::Legacy,
                    second_source: OrphanSourceKind::OrphanFile,
                },
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_chain_with_zero_head_is_a_no_op() {
        let mut fs = std::io::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        let mut plan = OrphanPlan::default();
        walk_legacy_chain(&ext, &mut fs, 0, &mut plan).expect("no-op walk");
        assert!(plan.legacy.is_empty());
        assert!(plan.stop.is_none());
    }

    #[test]
    fn orphan_file_scan_skipped_when_flags_clear() {
        let mut fs = std::io::Cursor::new(crate::test_support::load_clean_ext4_image());
        let ext = crate::Ext::open_lenient(&mut fs).expect("lenient");
        // ext4.img has COMPAT_ORPHAN_FILE but NOT RO_COMPAT_ORPHAN_PRESENT
        // (the latter is only set when the kernel has pending orphan entries),
        // so scan_orphan_file returns early.
        let mut plan = OrphanPlan::default();
        scan_orphan_file(&ext, &mut fs, &mut plan).expect("no-op");
        assert!(plan.orphan_file.is_empty());
        assert!(plan.stop.is_none());
    }

    #[test]
    fn duplicate_detection_emits_warning_for_cross_source_match() {
        let mut plan = OrphanPlan::default();
        plan.legacy.push(LegacyOrphanEntry {
            inode: 100,
            next_legacy: 0,
            mode: 0x81A4,
            links_count: 0,
            size: 0,
            disposition: OrphanDisposition::Unlinked,
        });
        plan.orphan_file.push(OrphanFileEntry {
            inode: 100,
            file_block_index: 0,
            slot_index: 3,
            mode: 0x81A4,
            links_count: 0,
            size: 0,
            disposition: OrphanDisposition::Unlinked,
        });
        detect_duplicates(&mut plan);

        assert_eq!(plan.warnings.len(), 1);
        let crate::orphan::plan::OrphanWarningKind::DuplicateInode {
            inode,
            first_source,
            second_source,
        } = plan.warnings[0].kind;
        assert_eq!(inode, 100);
        assert!(matches!(
            first_source,
            crate::orphan::plan::OrphanSourceKind::Legacy
        ));
        assert!(matches!(
            second_source,
            crate::orphan::plan::OrphanSourceKind::OrphanFile
        ));
    }

    #[test]
    fn validate_orphan_file_inode_block_count_divides_size_by_block_size() {
        // The dirty-orphan fixture has both COMPAT_ORPHAN_FILE and
        // RO_COMPAT_ORPHAN_PRESENT set with a populated orphan-file inode,
        // so the validator reaches the `(size / block_size) as u32`
        // computation — kills the `/ -> %` survivor at line 118.
        if !crate::test_support::fixture_available("ext4-dirty-orphan.img") {
            eprintln!("skipping: ext4-dirty-orphan.img not generated");
            return;
        }
        let mut fs = crate::test_support::load_image("ext4-dirty-orphan.img");
        let ext = crate::Ext::open_lenient(&mut fs).expect("open dirty-orphan image");
        assert!(
            ext.has_orphan_file() && ext.has_orphan_present(),
            "dirty-orphan fixture must have both orphan-file flags set"
        );

        let inum = ext.orphan_file_inum();
        assert!(
            inum != 0,
            "dirty-orphan fixture must point s_orphan_file_inum at a real inode"
        );

        let validated =
            validate_orphan_file_inode(&ext, &mut fs, inum).expect("orphan-file inode validates");

        let block_size = u64::from(ext.block_size());
        let expected_blocks = (validated.inode.size() / block_size) as u32;
        assert!(
            expected_blocks > 0,
            "orphan-file inode must span at least one block (kills / -> % via {} % {} = 0)",
            validated.inode.size(),
            block_size,
        );
        assert_eq!(
            validated.block_count, expected_blocks,
            "block_count must be size / block_size; modulo would yield 0"
        );
    }

    #[test]
    fn duplicate_detection_no_warning_when_disjoint() {
        let mut plan = OrphanPlan::default();
        plan.legacy.push(LegacyOrphanEntry {
            inode: 100,
            next_legacy: 0,
            mode: 0x81A4,
            links_count: 0,
            size: 0,
            disposition: OrphanDisposition::Unlinked,
        });
        plan.orphan_file.push(OrphanFileEntry {
            inode: 200,
            file_block_index: 0,
            slot_index: 0,
            mode: 0x81A4,
            links_count: 0,
            size: 0,
            disposition: OrphanDisposition::Unlinked,
        });
        detect_duplicates(&mut plan);
        assert!(plan.warnings.is_empty());
    }
}
