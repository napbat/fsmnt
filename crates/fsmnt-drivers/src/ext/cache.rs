//! Bounded path-derived state for the ext adapter.

use fs_ext::{ExtFileKind, ExtPositionedFile};
use fsmnt_core::FsMetadata;

use super::EXT4_ROOT_INO;

/// What a path names inside the mounted volume.
#[derive(Clone, Copy)]
pub(super) enum Target {
    /// The mount root, which salvage mode treats specially.
    Root,
    /// An inode reached through the directory tree, or directly by number
    /// under the salvage directory.
    Inode(u32),
    /// The synthetic salvage directory itself. It has no inode: its entries
    /// are produced by sweeping the inode tables.
    SalvageRoot,
}

impl Target {
    /// The inode backing this target, or `None` for the synthetic salvage
    /// directory.
    pub(super) const fn inode(self) -> Option<u32> {
        match self {
            Self::Root => Some(EXT4_ROOT_INO),
            Self::Inode(inum) => Some(inum),
            Self::SalvageRoot => None,
        }
    }
}

/// Reusable state derived from the active ext path's inode.
pub(super) struct CachedExtTarget {
    pub(super) target: Target,
    pub(super) kind: Option<ExtFileKind>,
    pub(super) metadata: Option<FsMetadata>,
    pub(super) file: Option<ExtPositionedFile>,
}

impl CachedExtTarget {
    /// Starts a cache entry before any inode-derived state has been read.
    pub(super) const fn new(target: Target) -> Self {
        Self {
            target,
            kind: None,
            metadata: None,
            file: None,
        }
    }
}
