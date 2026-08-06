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
    /// Entries discovered by walking the legacy `s_last_orphan` inode chain.
    pub legacy: Vec<LegacyOrphanEntry>,
    /// Entries decoded from the indexed orphan file.
    pub orphan_file: Vec<OrphanFileEntry>,
    /// Recoverable inconsistencies observed while combining both sources.
    pub warnings: Vec<OrphanWarning>,
    /// Fatal condition that prevented recovery from completing.
    pub stop: Option<OrphanStop>,
}

/// Snapshot of one inode discovered in the legacy orphan chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LegacyOrphanEntry {
    /// Orphaned inode number.
    pub inode: u32,
    /// Next inode number stored in the legacy chain link.
    pub next_legacy: u32,
    /// Raw inode mode at parse time.
    pub mode: u16,
    /// Link count at parse time.
    pub links_count: u16,
    /// File size at parse time.
    pub size: u64,
    /// Recovery action implied by the inode's link count.
    pub disposition: OrphanDisposition,
}

/// Snapshot of one slot decoded from the ext4 orphan file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanFileEntry {
    /// Orphaned inode number stored in the slot.
    pub inode: u32,
    /// Logical orphan-file block containing the slot.
    pub file_block_index: u32,
    /// Entry index within the orphan-file block.
    pub slot_index: u32,
    /// Raw inode mode at parse time.
    pub mode: u16,
    /// Link count at parse time.
    pub links_count: u16,
    /// File size at parse time.
    pub size: u64,
    /// Recovery action implied by the inode's link count.
    pub disposition: OrphanDisposition,
}

/// Recovery action selected for an orphan entry.
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

/// Recoverable inconsistency observed during orphan discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanWarning {
    /// Category and affected objects for the warning.
    pub kind: OrphanWarningKind,
}

/// Kinds of recoverable orphan-discovery inconsistency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanWarningKind {
    /// Same inode number appears in both orphan sources.
    DuplicateInode {
        /// Inode that appeared more than once.
        inode: u32,
        /// Source in which the inode was first observed.
        first_source: OrphanSourceKind,
        /// Source containing the duplicate entry.
        second_source: OrphanSourceKind,
    },
}

/// On-disk mechanism from which an orphan entry was discovered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanSourceKind {
    /// Legacy linked list rooted at `s_last_orphan`.
    Legacy,
    /// Indexed orphan file enabled by `COMPAT_ORPHAN_FILE`.
    OrphanFile,
}

/// Location and reason at which orphan recovery stopped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OrphanStop {
    /// Discovery or apply location associated with the failure.
    pub position: OrphanPosition,
    /// Condition that made recovery unsafe.
    pub reason: OrphanStopReason,
}

/// Logical location within orphan discovery or application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanPosition {
    /// Superblock head of the legacy orphan chain.
    LegacyHead,
    /// A specific inode while walking the legacy chain.
    LegacyInode {
        /// Inode being decoded.
        inode: u32,
    },
    /// A block and optional slot in the orphan file.
    OrphanFileBlock {
        /// Logical orphan-file block index.
        file_block_index: u32,
        /// Slot index when failure occurred after selecting a slot.
        slot_index: Option<u32>,
    },
    /// Atomic overlay-application phase.
    Apply,
}

/// Fatal conditions that stop orphan discovery or application.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum OrphanStopReason {
    /// The legacy orphan chain revisited an inode.
    LegacyChainCycle {
        /// Inode at which the cycle was detected.
        at_inode: u32,
    },
    /// The legacy chain points outside the filesystem's inode range.
    LegacyChainInodeOutOfRange {
        /// Invalid inode number stored in the chain.
        inode: u32,
    },
    /// An orphan-file slot names an inode outside the valid range.
    OrphanFileInodeOutOfRange {
        /// Invalid inode number stored in the slot.
        inode: u32,
    },
    /// An orphan-file block does not end with the required tail magic.
    OrphanFileTailMagicInvalid,
    /// An orphan-file block failed metadata-checksum validation.
    OrphanFileChecksumInvalid,
    /// Two owned physical blocks of one inode mapped to the same
    /// allocation cluster from different logical cluster slots. Only
    /// reachable on `RO_COMPAT_BIGALLOC` filesystems.
    BigallocClusterOverlap {
        /// Inode containing the overlapping mappings.
        inode: u32,
        /// Allocation cluster claimed more than once.
        cluster: u64,
        /// First physical block mapped into the cluster.
        first_block: u64,
        /// Conflicting physical block mapped into the same cluster.
        second_block: u64,
    },
    /// An EA inode referenced by an Unlinked host does not have
    /// `EA_INODE_FL` set.
    EaInodeMissingFlag {
        /// Orphaned inode containing the xattr reference.
        host_inode: u32,
        /// Referenced external-value inode.
        ea_inode: u32,
    },
    /// An EA inode referenced by an Unlinked host had an effective
    /// refcount of zero at the time of the decrement — whether on-disk
    /// zero or the sum of unlinked references already exceeds the
    /// pre-apply refcount.
    EaInodeRefcountZero {
        /// Orphaned inode whose reference would be removed.
        host_inode: u32,
        /// Referenced EA inode with no remaining count.
        ea_inode: u32,
    },
    /// An EA inode's `i_size` does not match the host's xattr entry
    /// `e_value_size`. Expected / actual both widened to u64.
    EaInodeSizeMismatch {
        /// Orphaned inode containing the xattr entry.
        host_inode: u32,
        /// EA inode supplying the external xattr value.
        ea_inode: u32,
        /// Value size recorded in the host's xattr entry.
        expected: u64,
        /// Size stored in the EA inode.
        actual: u64,
    },
    /// `METADATA_CSUM` is set and the EA inode's stored value hash in
    /// `i_atime` does not match `ea_inode_hash(seed, value_bytes)`.
    EaInodeChecksumInvalid {
        /// Orphaned inode containing the xattr reference.
        host_inode: u32,
        /// EA inode whose stored value hash is invalid.
        ea_inode: u32,
    },
    /// An EA inode carries its own non-empty xattrs (i-body or any
    /// `i_file_acl != 0`). The specific `EaInodeSharedXattrBlock`
    /// variant handles the shared-external-block case; this variant
    /// covers all other non-empty-xattr cases on EA inodes.
    EaInodeNestedReference {
        /// Orphaned inode containing the original reference.
        host_inode: u32,
        /// EA inode that itself carries xattrs.
        ea_inode: u32,
    },
    /// An EA inode has `i_file_acl != 0` pointing at an external xattr
    /// block with `h_refcount > 1`. More specific than the generic
    /// `EaInodeNestedReference`.
    EaInodeSharedXattrBlock {
        /// Orphaned inode containing the original reference.
        host_inode: u32,
        /// EA inode that points at the shared block.
        ea_inode: u32,
        /// Shared external xattr block number.
        xattr_block: u64,
        /// On-disk reference count of that block.
        refcount: u32,
    },
    /// An xattr block referenced by one or more Unlinked hosts has
    /// `h_refcount == 0` — either on-disk zero or `count > h_refcount`
    /// at apply time.
    SharedXattrBlockRefcountZero {
        /// Orphaned inode referencing the block.
        inode: u32,
        /// External xattr block with an exhausted reference count.
        xattr_block: u64,
    },
    /// An xattr block referenced by an Unlinked host has `h_refcount >
    /// EXT4_XATTR_REFCOUNT_MAX` (`0x4000_0000`).
    SharedXattrBlockRefcountOverflow {
        /// Orphaned inode referencing the block.
        inode: u32,
        /// External xattr block with an invalid reference count.
        xattr_block: u64,
        /// On-disk reference count exceeding the ext4 maximum.
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
