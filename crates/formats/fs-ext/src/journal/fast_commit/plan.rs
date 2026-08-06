//! Fast-commit replay plan, stop, and warning types.
//!
//! These types are part of the crate's public API per spec section 11.1. They
//! mirror the orphan-replay precedent at `crates/fs-ext/src/orphan/plan.rs`.

use alloc::vec::Vec;

/// Forensic summary of a fast-commit replay attempt.
///
/// The plan records committed transactions, allocation effects, recoverable
/// warnings, and the first condition that stopped replay.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct FastCommitPlan {
    /// Transactions whose TAIL validated and were applied.
    pub transactions_replayed: u32,
    /// Distinct inodes touched (size of internal `modified_inodes` set).
    pub inodes_modified: u32,
    /// Last good TID. None when no transaction's TAIL closed.
    pub last_committed_tid: Option<u32>,
    /// Number of records encountered for each fast-commit tag.
    pub tag_counts: FastCommitTagCounts,
    /// Allocation units mutated by pass-B frees and pass-C allocations.
    /// Units are filesystem blocks under non-bigalloc, clusters under
    /// bigalloc -- matches `EXT4_C2B/EXT4_NUM_B2C` semantics.
    pub allocation_units_marked_free: u64,
    /// Allocation units marked allocated while finalizing replay.
    pub allocation_units_marked_allocated: u64,
    /// Why replay halted before `fc_last_inclusive`. None on clean end.
    pub stop: Option<FastCommitStop>,
    /// Per-record skip-and-continue events. Capped at 256; overflow
    /// indicated by `warnings_truncated`.
    pub warnings: Vec<FastCommitWarning>,
    /// Whether additional warnings were omitted after reaching the cap.
    pub warnings_truncated: bool,
}

/// Counts of each on-disk fast-commit record type encountered during replay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct FastCommitTagCounts {
    /// `HEAD` records encountered.
    pub head: u32,
    /// `PAD` records encountered.
    pub pad: u32,
    /// `INODE` records encountered.
    pub inode: u32,
    /// `CREAT` records encountered.
    pub creat: u32,
    /// `LINK` records encountered.
    pub link: u32,
    /// `UNLINK` records encountered.
    pub unlink: u32,
    /// `ADD_RANGE` records encountered.
    pub add_range: u32,
    /// `DEL_RANGE` records encountered.
    pub del_range: u32,
    /// `TAIL` records encountered.
    pub tail: u32,
}

/// Location and reason at which fast-commit replay stopped.
#[derive(Debug)]
#[non_exhaustive]
pub struct FastCommitStop {
    /// Journal position of the record that caused replay to stop.
    pub position: FastCommitPosition,
    /// Most recent transaction ID closed by a valid tail, if any.
    pub last_committed_tid: Option<u32>,
    /// Condition that made further replay unsafe.
    pub reason: FastCommitStopReason,
}

/// Fatal conditions that prevent safe continuation of fast-commit replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FastCommitStopReason {
    /// A `HEAD` record enables unsupported feature bits.
    UnsupportedHeadFeatures {
        /// Unsupported feature mask recorded in the head.
        features: u32,
    },
    /// A `HEAD` transaction ID differs from the expected next transaction.
    HeadTidMismatch {
        /// Transaction ID expected from journal sequencing.
        expected: u32,
        /// Transaction ID stored in the head record.
        seen: u32,
    },
    /// A `TAIL` record has an unexpected transaction ID or checksum.
    TailChecksumInvalid {
        /// Transaction ID stored in the tail.
        tid_seen: u32,
        /// Transaction ID expected for the open transaction.
        tid_expected: u32,
        /// Checksum stored in the tail.
        crc_seen: u32,
        /// Checksum computed over the transaction.
        crc_computed: u32,
    },
    /// A recognized record has an invalid encoded length or payload.
    MalformedRecord {
        /// Raw record tag.
        tag: u16,
        /// Encoded record length.
        fc_len: u16,
        /// Description of the structural violation.
        reason: &'static str,
    },
    /// The transaction contains a tag this implementation cannot replay.
    UnsupportedTag {
        /// Unsupported raw record tag.
        tag: u16,
    },
    /// The fast-commit region ended before the current transaction's tail.
    RegionExhaustedMidTransaction,
    /// `ADD_RANGE` or `DEL_RANGE` could not be applied in-place because the
    /// inode's extent tree would need a new metadata allocation, or has an
    /// unsupported shape for in-place surgery. Containing transaction is
    /// rolled back; FC replay halts.
    ExtentReplayRequiresMetadataAllocation {
        /// Inode whose extent tree requires structural growth.
        inum: u32,
    },
    /// CREAT/LINK/UNLINK link-count adjustment under/overflowed under
    /// checked arithmetic. Containing transaction is rolled back; FC
    /// replay halts.
    LinkCountOverflow {
        /// Inode whose link count could not be adjusted.
        inum: u32,
        /// Link count before applying the record.
        current: u16,
        /// Signed link-count adjustment requested by the transaction.
        delta: i32,
    },
    /// Pass-B: extent surgery failed for a concrete reason (csum
    /// invalid on existing extent block, malformed extent header,
    /// sibling-block out of range, bigalloc cluster misalignment).
    /// Containing transaction is rolled back; FC replay halts because
    /// later transactions may depend on the partially-applied tree
    /// state this surgery would have produced.
    ExtentReplayFailed {
        /// Inode whose extent edit failed.
        inum: u32,
        /// Concrete extent-tree failure.
        reason: ExtentReplayReason,
    },
}

/// Physical location of a fast-commit record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FastCommitPosition {
    /// Journal-relative block index in `fc_first..=fc_last_inclusive`.
    pub fc_block: u32,
    /// Byte offset of the failing record within that block.
    pub block_offset: u32,
    /// Absolute filesystem byte offset for cross-tool correlation.
    pub fs_byte_offset: u64,
}

/// Recoverable fast-commit replay issue that caused one operation to be skipped.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FastCommitWarning {
    /// Position of the first occurrence.
    pub position: FastCommitPosition,
    /// TID of the transaction that contained the (first) skipped record.
    pub current_tid: Option<u32>,
    /// Category and affected object for the warning.
    pub kind: FastCommitWarningKind,
    /// 1 for unique events; >1 when aggregation merged identical kinds
    /// targeting the same narrow-scope key (e.g., same `parent_inum` for
    /// `DirectoryReplayFailed`, same inum for `FinalizerExtentWalkFailed`).
    pub occurrences: u32,
}

/// Recoverable conditions reported while replay continues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FastCommitWarningKind {
    /// `fc_ino` == 0 || `fc_ino` > `sb.s_inodes_count`.
    InodeOutOfRange {
        /// Invalid inode number carried by the record.
        inum: u32,
    },
    /// Resolved physical mapping out of `sb.s_blocks_count` range.
    PhysicalBlockOutOfRange {
        /// Inode whose mapping was rejected.
        inum: u32,
        /// First physical block of the invalid mapping.
        pblk: u64,
        /// Mapping length in filesystem blocks.
        len: u32,
    },
    /// `DEL_RANGE` logical (lblk + len) overflowed inode logical capacity.
    LogicalRangeInvalid {
        /// Inode targeted by the range record.
        inum: u32,
        /// First logical block requested.
        lblk: u32,
        /// Requested logical length in blocks.
        len: u32,
    },
    /// Directory mutation skipped -- typically conservative-htree skip,
    /// or parent corruption.
    DirectoryReplayFailed {
        /// Parent directory targeted by the skipped mutation.
        parent_inum: u32,
        /// Reason the directory could not be updated safely.
        reason: DirectoryReplayReason,
    },
    /// Pass-C extent walk failed for this inode; allocations not
    /// reconciled. Other inodes' allocations are unaffected.
    FinalizerExtentWalkFailed {
        /// Inode whose final extent walk failed.
        inum: u32,
    },
    /// UNLINK target name not present in parent's directory entries.
    UnlinkTargetMissing {
        /// Parent directory searched for the target name.
        parent_inum: u32,
        /// Child inode named by the unlink record.
        child_inum: u32,
    },
}

/// Reasons a fast-commit directory mutation can be skipped.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum DirectoryReplayReason {
    /// Parent uses htree; full htree maintenance is out of scope.
    /// Emitted by mutator via `DirReplayOutcome::SkippedHtree`.
    HtreeNotMaintained,
    /// Parent inode is not present or its inum is out of range.
    /// Caller-emitted via precheck -- mutator is not invoked.
    ParentInodeMissing,
    /// Parent inode exists but is not a directory.
    /// Caller-emitted via precheck -- mutator is not invoked.
    ParentNotADirectory,
}

/// Reasons an in-place fast-commit extent edit can fail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ExtentReplayReason {
    /// An existing extent block failed metadata-checksum validation.
    ExtentBlockChecksumInvalid,
    /// An extent node contains an invalid header or record layout.
    ExtentHeaderMalformed,
    /// An extent index references a physical block outside the filesystem.
    SiblingBlockOutOfRange,
    /// A physical extent does not begin on a bigalloc cluster boundary.
    BigallocPblkNotClusterAligned,
    /// A delete range would free only part of a bigalloc cluster.
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
