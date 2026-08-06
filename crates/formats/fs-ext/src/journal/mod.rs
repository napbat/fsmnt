//! jbd2 journal recovery for ext3/ext4 filesystems.
//!
//! See `docs/superpowers/specs/2026-04-22-fs-ext-journal-recovery-design.md`
//! for the design.

mod checksum;
pub(crate) mod fast_commit;
mod features;
mod overlay;
mod replay;
pub(crate) mod source;
mod superblock;
mod tags;

pub use fast_commit::{
    DirectoryReplayReason, ExtentReplayReason, FastCommitPlan, FastCommitPosition, FastCommitStop,
    FastCommitStopReason, FastCommitTagCounts, FastCommitWarning, FastCommitWarningKind,
};
pub use features::JournalInvariantKind;
pub use overlay::OverlayReader;
pub(crate) use overlay::OverlaySource;
#[cfg(test)]
pub(crate) use replay::BlockOverlay;
pub use replay::{
    CommittedTx, JbdCommitTime, JournalPosition, JournalReplay, ReplayPlan, ReplayStop,
    RevocationSummary, StopReason,
};
