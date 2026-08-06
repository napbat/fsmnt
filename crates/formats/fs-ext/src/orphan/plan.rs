//! Data model for orphan recovery. Full surface defined in Task 13.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Block-level delta contributed by orphan apply on top of a journal overlay.
///
/// `blocks` holds full-block replacement content for every orphan-mutated
/// filesystem block except the superblock host. `sb_host_override` holds the
/// merged sb-host block image when apply produced superblock changes; `None`
/// when apply did not touch the superblock (e.g. on a stop).
#[derive(Debug, Default)]
pub(crate) struct OrphanOverlayDelta {
    pub(crate) blocks: BTreeMap<u64, Box<[u8]>>,
    pub(crate) sb_host_override: Option<Box<[u8]>>,
}

impl OrphanOverlayDelta {
    /// Returns `true` when the delta contains no block patches and no
    /// superblock override — i.e. apply produced no mutations.
    ///
    /// Used by tests to assert the atomic-contract invariant: a stop path
    /// must leave the delta empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.blocks.is_empty() && self.sb_host_override.is_none()
    }
}

#[cfg(test)]
mod overlay_delta_tests {
    use super::{BTreeMap, OrphanOverlayDelta};

    #[test]
    fn is_empty_requires_no_blocks_and_no_sb_override() {
        let empty = OrphanOverlayDelta::default();
        assert!(empty.is_empty());

        // A single block patch makes the delta non-empty. This kills
        // both the `is_empty -> true` mutant and the `&& -> ||` mutant
        // (with blocks non-empty and the override `None`, `||` would
        // wrongly report empty).
        let mut blocks = BTreeMap::new();
        blocks.insert(0u64, alloc::vec![0u8; 4].into_boxed_slice());
        let with_block = OrphanOverlayDelta {
            blocks,
            sb_host_override: None,
        };
        assert!(!with_block.is_empty());

        // An sb-host override alone is also a non-empty delta.
        let with_sb = OrphanOverlayDelta {
            blocks: BTreeMap::new(),
            sb_host_override: Some(alloc::vec![0u8; 4].into_boxed_slice()),
        };
        assert!(!with_sb.is_empty());
    }
}

/// Forensic record produced by orphan recovery.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct OrphanPlan {
    pub legacy: Vec<LegacyOrphanEntry>,
    pub orphan_file: Vec<OrphanFileEntry>,
    pub warnings: Vec<OrphanWarning>,
    pub stop: Option<OrphanStop>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LegacyOrphanEntry {
    pub inode: u32,
    pub next_legacy: u32,
    pub mode: u16,
    pub links_count: u16,
    pub size: u64,
    pub disposition: OrphanDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanFileEntry {
    pub inode: u32,
    pub file_block_index: u32,
    pub slot_index: u32,
    pub mode: u16,
    pub links_count: u16,
    pub size: u64,
    pub disposition: OrphanDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanDisposition {
    /// `i_links_count == 0` at parse time. Apply performs full unlink
    /// bookkeeping once per unique inode.
    Unlinked,
    /// `i_links_count > 0` at parse time. Apply clears only the orphan-list
    /// linkage for each source entry.
    TruncateDeferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanWarning {
    pub kind: OrphanWarningKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanWarningKind {
    /// Same inode number appears in both orphan sources.
    DuplicateInode {
        inode: u32,
        first_source: OrphanSourceKind,
        second_source: OrphanSourceKind,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanSourceKind {
    Legacy,
    OrphanFile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanStop {
    pub position: OrphanPosition,
    pub reason: OrphanStopReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanPosition {
    LegacyHead,
    LegacyInode {
        inode: u32,
    },
    OrphanFileBlock {
        file_block_index: u32,
        slot_index: Option<u32>,
    },
    Apply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanStopReason {
    LegacyChainCycle {
        at_inode: u32,
    },
    LegacyChainInodeOutOfRange {
        inode: u32,
    },
    OrphanFileInodeOutOfRange {
        inode: u32,
    },
    OrphanFileTailMagicInvalid,
    OrphanFileChecksumInvalid,
    /// Two owned physical blocks of one inode mapped to the same
    /// allocation cluster from different logical cluster slots. Only
    /// reachable on `RO_COMPAT_BIGALLOC` filesystems.
    BigallocClusterOverlap {
        inode: u32,
        cluster: u64,
        first_block: u64,
        second_block: u64,
    },
    /// An EA inode referenced by an Unlinked host does not have
    /// `EA_INODE_FL` set.
    EaInodeMissingFlag {
        host_inode: u32,
        ea_inode: u32,
    },
    /// An EA inode referenced by an Unlinked host had an effective
    /// refcount of zero at the time of the decrement — whether on-disk
    /// zero or the sum of unlinked references already exceeds the
    /// pre-apply refcount.
    EaInodeRefcountZero {
        host_inode: u32,
        ea_inode: u32,
    },
    /// An EA inode's `i_size` does not match the host's xattr entry
    /// `e_value_size`. Expected / actual both widened to u64.
    EaInodeSizeMismatch {
        host_inode: u32,
        ea_inode: u32,
        expected: u64,
        actual: u64,
    },
    /// `METADATA_CSUM` is set and the EA inode's stored value hash in
    /// `i_atime` does not match `ea_inode_hash(seed, value_bytes)`.
    EaInodeChecksumInvalid {
        host_inode: u32,
        ea_inode: u32,
    },
    /// An EA inode carries its own non-empty xattrs (i-body or any
    /// `i_file_acl != 0`). The specific `EaInodeSharedXattrBlock`
    /// variant handles the shared-external-block case; this variant
    /// covers all other non-empty-xattr cases on EA inodes.
    EaInodeNestedReference {
        host_inode: u32,
        ea_inode: u32,
    },
    /// An EA inode has `i_file_acl != 0` pointing at an external xattr
    /// block with `h_refcount > 1`. More specific than the generic
    /// `EaInodeNestedReference`.
    EaInodeSharedXattrBlock {
        host_inode: u32,
        ea_inode: u32,
        xattr_block: u64,
        refcount: u32,
    },
    /// An xattr block referenced by one or more Unlinked hosts has
    /// `h_refcount == 0` — either on-disk zero or `count > h_refcount`
    /// at apply time.
    SharedXattrBlockRefcountZero {
        inode: u32,
        xattr_block: u64,
    },
    /// An xattr block referenced by an Unlinked host has `h_refcount >
    /// EXT4_XATTR_REFCOUNT_MAX` (0x4000_0000).
    SharedXattrBlockRefcountOverflow {
        inode: u32,
        xattr_block: u64,
        refcount: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_plan_default_is_empty() {
        let plan = OrphanPlan::default();
        assert!(plan.legacy.is_empty());
        assert!(plan.orphan_file.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(plan.stop.is_none());
    }

    #[test]
    fn stop_reason_is_non_exhaustive_covered() {
        let reasons = [
            // Level-2 retained (5).
            OrphanStopReason::LegacyChainCycle { at_inode: 10 },
            OrphanStopReason::LegacyChainInodeOutOfRange { inode: 10 },
            OrphanStopReason::OrphanFileInodeOutOfRange { inode: 10 },
            OrphanStopReason::OrphanFileTailMagicInvalid,
            OrphanStopReason::OrphanFileChecksumInvalid,
            // Level-3 additions (9).
            OrphanStopReason::BigallocClusterOverlap {
                inode: 10,
                cluster: 42,
                first_block: 168,
                second_block: 169,
            },
            OrphanStopReason::EaInodeMissingFlag {
                host_inode: 10,
                ea_inode: 20,
            },
            OrphanStopReason::EaInodeRefcountZero {
                host_inode: 10,
                ea_inode: 20,
            },
            OrphanStopReason::EaInodeSizeMismatch {
                host_inode: 10,
                ea_inode: 20,
                expected: 4096,
                actual: 2048,
            },
            OrphanStopReason::EaInodeChecksumInvalid {
                host_inode: 10,
                ea_inode: 20,
            },
            OrphanStopReason::EaInodeNestedReference {
                host_inode: 10,
                ea_inode: 20,
            },
            OrphanStopReason::EaInodeSharedXattrBlock {
                host_inode: 10,
                ea_inode: 20,
                xattr_block: 500,
                refcount: 2,
            },
            OrphanStopReason::SharedXattrBlockRefcountZero {
                inode: 10,
                xattr_block: 500,
            },
            OrphanStopReason::SharedXattrBlockRefcountOverflow {
                inode: 10,
                xattr_block: 500,
                refcount: 0xFFFF_FFFF,
            },
        ];
        assert_eq!(reasons.len(), 14);
    }

    #[test]
    fn duplicate_warning_records_both_sources() {
        let w = OrphanWarning {
            kind: OrphanWarningKind::DuplicateInode {
                inode: 42,
                first_source: OrphanSourceKind::Legacy,
                second_source: OrphanSourceKind::OrphanFile,
            },
        };
        let OrphanWarningKind::DuplicateInode {
            inode,
            first_source,
            second_source,
        } = w.kind;
        assert_eq!(inode, 42);
        assert!(matches!(first_source, OrphanSourceKind::Legacy));
        assert!(matches!(second_source, OrphanSourceKind::OrphanFile));
    }
}
