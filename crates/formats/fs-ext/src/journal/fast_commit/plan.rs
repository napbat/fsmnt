//! Fast-commit replay plan, stop, and warning types.
//!
//! These types are part of the crate's public API per spec section 11.1. They
//! mirror the orphan-replay precedent at `crates/fs-ext/src/orphan/plan.rs`.

use alloc::vec::Vec;

#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FastCommitPlan {
    /// Transactions whose TAIL validated and were applied.
    pub transactions_replayed: u32,
    /// Distinct inodes touched (size of internal modified_inodes set).
    pub inodes_modified: u32,
    /// Last good TID. None when no transaction's TAIL closed.
    pub last_committed_tid: Option<u32>,
    pub tag_counts: FastCommitTagCounts,
    /// Allocation units mutated by pass-B frees and pass-C allocations.
    /// Units are filesystem blocks under non-bigalloc, clusters under
    /// bigalloc -- matches EXT4_C2B/EXT4_NUM_B2C semantics.
    pub allocation_units_marked_free: u64,
    pub allocation_units_marked_allocated: u64,
    /// Why replay halted before fc_last_inclusive. None on clean end.
    pub stop: Option<FastCommitStop>,
    /// Per-record skip-and-continue events. Capped at 256; overflow
    /// indicated by warnings_truncated.
    pub warnings: Vec<FastCommitWarning>,
    pub warnings_truncated: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct FastCommitTagCounts {
    pub head: u32,
    pub pad: u32,
    pub inode: u32,
    pub creat: u32,
    pub link: u32,
    pub unlink: u32,
    pub add_range: u32,
    pub del_range: u32,
    pub tail: u32,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct FastCommitStop {
    pub position: FastCommitPosition,
    pub last_committed_tid: Option<u32>,
    pub reason: FastCommitStopReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FastCommitStopReason {
    UnsupportedHeadFeatures {
        features: u32,
    },
    HeadTidMismatch {
        expected: u32,
        seen: u32,
    },
    TailChecksumInvalid {
        tid_seen: u32,
        tid_expected: u32,
        crc_seen: u32,
        crc_computed: u32,
    },
    MalformedRecord {
        tag: u16,
        fc_len: u16,
        reason: &'static str,
    },
    UnsupportedTag {
        tag: u16,
    },
    RegionExhaustedMidTransaction,
    /// ADD_RANGE or DEL_RANGE could not be applied in-place because the
    /// inode's extent tree would need a new metadata allocation, or has an
    /// unsupported shape for in-place surgery. Containing transaction is
    /// rolled back; FC replay halts.
    ExtentReplayRequiresMetadataAllocation {
        inum: u32,
    },
    /// CREAT/LINK/UNLINK link-count adjustment under/overflowed under
    /// checked arithmetic. Containing transaction is rolled back; FC
    /// replay halts.
    LinkCountOverflow {
        inum: u32,
        current: u16,
        delta: i32,
    },
    /// Pass-B: extent surgery failed for a concrete reason (csum
    /// invalid on existing extent block, malformed extent header,
    /// sibling-block out of range, bigalloc cluster misalignment).
    /// Containing transaction is rolled back; FC replay halts because
    /// later transactions may depend on the partially-applied tree
    /// state this surgery would have produced.
    ExtentReplayFailed {
        inum: u32,
        reason: ExtentReplayReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastCommitPosition {
    /// Journal-relative block index in fc_first..=fc_last_inclusive.
    pub fc_block: u32,
    /// Byte offset of the failing record within that block.
    pub block_offset: u32,
    /// Absolute filesystem byte offset for cross-tool correlation.
    pub fs_byte_offset: u64,
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FastCommitWarning {
    /// Position of the first occurrence.
    pub position: FastCommitPosition,
    /// TID of the transaction that contained the (first) skipped record.
    pub current_tid: Option<u32>,
    pub kind: FastCommitWarningKind,
    /// 1 for unique events; >1 when aggregation merged identical kinds
    /// targeting the same narrow-scope key (e.g., same parent_inum for
    /// DirectoryReplayFailed, same inum for FinalizerExtentWalkFailed).
    pub occurrences: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FastCommitWarningKind {
    /// fc_ino == 0 || fc_ino > sb.s_inodes_count.
    InodeOutOfRange { inum: u32 },
    /// Resolved physical mapping out of sb.s_blocks_count range.
    PhysicalBlockOutOfRange { inum: u32, pblk: u64, len: u32 },
    /// DEL_RANGE logical (lblk + len) overflowed inode logical capacity.
    LogicalRangeInvalid { inum: u32, lblk: u32, len: u32 },
    /// Directory mutation skipped -- typically conservative-htree skip,
    /// or parent corruption.
    DirectoryReplayFailed {
        parent_inum: u32,
        reason: DirectoryReplayReason,
    },
    /// Pass-C extent walk failed for this inode; allocations not
    /// reconciled. Other inodes' allocations are unaffected.
    FinalizerExtentWalkFailed { inum: u32 },
    /// UNLINK target name not present in parent's directory entries.
    UnlinkTargetMissing { parent_inum: u32, child_inum: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryReplayReason {
    /// Parent uses htree; full htree maintenance is out of scope.
    /// Emitted by mutator via DirReplayOutcome::SkippedHtree.
    HtreeNotMaintained,
    /// Parent inode is not present or its inum is out of range.
    /// Caller-emitted via precheck -- mutator is not invoked.
    ParentInodeMissing,
    /// Parent inode exists but is not a directory.
    /// Caller-emitted via precheck -- mutator is not invoked.
    ParentNotADirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExtentReplayReason {
    ExtentBlockChecksumInvalid,
    ExtentHeaderMalformed,
    SiblingBlockOutOfRange,
    BigallocPblkNotClusterAligned,
    BigallocPartialClusterDelRange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_default_is_empty() {
        let plan = FastCommitPlan::default();
        assert_eq!(plan.transactions_replayed, 0);
        assert_eq!(plan.inodes_modified, 0);
        assert!(plan.last_committed_tid.is_none());
        assert_eq!(plan.allocation_units_marked_free, 0);
        assert_eq!(plan.allocation_units_marked_allocated, 0);
        assert!(plan.stop.is_none());
        assert!(plan.warnings.is_empty());
        assert!(!plan.warnings_truncated);
    }

    #[test]
    fn tag_counts_default_is_zero() {
        let tc = FastCommitTagCounts::default();
        assert_eq!(tc.head, 0);
        assert_eq!(tc.tail, 0);
        assert_eq!(tc.add_range, 0);
    }

    #[test]
    fn stop_reasons_are_clone_copy_compatible() {
        let r = FastCommitStopReason::UnsupportedTag { tag: 0x99 };
        let r2 = r;
        assert_eq!(r, r2);
    }

    #[test]
    #[allow(unreachable_patterns, reason = "non_exhaustive catch-all required")]
    fn stop_reason_match_compiles_with_non_exhaustive_arm() {
        let reason = FastCommitStopReason::UnsupportedTag { tag: 0 };
        let _ = match reason {
            FastCommitStopReason::UnsupportedHeadFeatures { .. } => 0,
            FastCommitStopReason::HeadTidMismatch { .. } => 1,
            FastCommitStopReason::TailChecksumInvalid { .. } => 2,
            FastCommitStopReason::MalformedRecord { .. } => 3,
            FastCommitStopReason::UnsupportedTag { .. } => 4,
            FastCommitStopReason::RegionExhaustedMidTransaction => 5,
            FastCommitStopReason::ExtentReplayRequiresMetadataAllocation { .. } => 6,
            FastCommitStopReason::LinkCountOverflow { .. } => 7,
            FastCommitStopReason::ExtentReplayFailed { .. } => 8,
            _ => 9,
        };
    }
}
