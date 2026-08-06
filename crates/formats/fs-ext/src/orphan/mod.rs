//! Orphan-inode recovery: walks the legacy `s_last_orphan` chain and the
//! modern orphan file, applies Level-2 unlink bookkeeping on top of a
//! `JournalReplay`, and produces a composable overlay artifact.
//!
//! See `docs/superpowers/specs/2026-04-22-fs-ext-orphan-handling-design.md`.

mod apply;
mod ea_inode;
mod htree_mutate;
mod mutator;
mod parse;
mod plan;
mod replay;
mod shared_xattr;
mod truncate;

pub(crate) use htree_mutate::HtreeSurgeon;
pub(crate) use mutator::{DirReplayOutcome, LinkCountChange, Mutator, MutatorError};
pub(crate) use plan::OrphanOverlayDelta;

pub use replay::OrphanReplay;

pub use plan::{
    LegacyOrphanEntry, OrphanDisposition, OrphanFileEntry, OrphanPlan, OrphanPosition,
    OrphanSourceKind, OrphanStop, OrphanStopReason, OrphanWarning, OrphanWarningKind,
};
