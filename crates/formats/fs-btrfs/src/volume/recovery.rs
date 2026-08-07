//! Bootstrap candidates derived from live and historical superblock roots.

use alloc::vec::Vec;

use crate::item::{CHUNK_TREE_OBJECT_ID, ROOT_TREE_OBJECT_ID};
use crate::tree::TreeRoot;
use crate::{BtrfsRootBackup, BtrfsSuperblock};

/// Details of a historical root set selected during initialization recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BtrfsRecovery {
    backup_slot: usize,
    generation: u64,
    used_backup_chunk_tree: bool,
}

impl BtrfsRecovery {
    /// Superblock root-backup array slot that supplied the recovered root.
    #[must_use]
    pub const fn backup_slot(self) -> usize {
        self.backup_slot
    }

    /// Historical transaction generation exposed by the recovered volume.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Whether recovery also required the historical chunk-tree pointer.
    ///
    /// A false value means the historical root tree remained readable through
    /// the current chunk tree, matching Linux's normal `usebackuproot`
    /// behavior.
    #[must_use]
    pub const fn used_backup_chunk_tree(self) -> bool {
        self.used_backup_chunk_tree
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BootstrapCandidate {
    pub(super) root_tree: TreeRoot,
    pub(super) chunk_tree: TreeRoot,
    pub(super) generation: u64,
    pub(super) total_bytes: u64,
    pub(super) replay_log: bool,
    pub(super) recovery: Option<BtrfsRecovery>,
}

impl BootstrapCandidate {
    pub(super) fn live(superblock: &BtrfsSuperblock) -> Self {
        Self {
            root_tree: TreeRoot {
                tree_id: ROOT_TREE_OBJECT_ID,
                logical: superblock.root(),
                level: superblock.root_level(),
                expected_generation: Some(superblock.generation()),
            },
            chunk_tree: live_chunk_tree(superblock),
            generation: superblock.generation(),
            total_bytes: superblock.total_bytes(),
            replay_log: true,
            recovery: None,
        }
    }
}

pub(super) fn bootstrap_candidates(superblock: &BtrfsSuperblock) -> Vec<BootstrapCandidate> {
    let live = BootstrapCandidate::live(superblock);
    let mut candidates = alloc::vec![live];
    let mut backups = superblock.root_backups().to_vec();
    backups.sort_unstable_by(|left, right| {
        right
            .root_tree()
            .generation()
            .cmp(&left.root_tree().generation())
            .then_with(|| left.slot().cmp(&right.slot()))
    });

    for backup in backups {
        append_backup_candidates(&mut candidates, live.chunk_tree, backup);
    }
    candidates
}

fn append_backup_candidates(
    candidates: &mut Vec<BootstrapCandidate>,
    live_chunk_tree: TreeRoot,
    backup: BtrfsRootBackup,
) {
    let root = backup.root_tree();
    let root_tree = TreeRoot {
        tree_id: ROOT_TREE_OBJECT_ID,
        logical: root.logical(),
        level: root.level(),
        expected_generation: Some(root.generation()),
    };
    let recovery = BtrfsRecovery {
        backup_slot: backup.slot(),
        generation: root.generation(),
        used_backup_chunk_tree: false,
    };
    append_unique(
        candidates,
        BootstrapCandidate {
            root_tree,
            chunk_tree: live_chunk_tree,
            generation: root.generation(),
            total_bytes: backup.total_bytes(),
            replay_log: false,
            recovery: Some(recovery),
        },
    );

    let chunk = backup.chunk_tree();
    let backup_chunk_tree = TreeRoot {
        tree_id: CHUNK_TREE_OBJECT_ID,
        logical: chunk.logical(),
        level: chunk.level(),
        expected_generation: Some(chunk.generation()),
    };
    if backup_chunk_tree != live_chunk_tree {
        append_unique(
            candidates,
            BootstrapCandidate {
                root_tree,
                chunk_tree: backup_chunk_tree,
                generation: root.generation(),
                total_bytes: backup.total_bytes(),
                replay_log: false,
                recovery: Some(BtrfsRecovery {
                    used_backup_chunk_tree: true,
                    ..recovery
                }),
            },
        );
    }
}

fn append_unique(candidates: &mut Vec<BootstrapCandidate>, candidate: BootstrapCandidate) {
    if !candidates.iter().any(|existing| {
        existing.root_tree == candidate.root_tree && existing.chunk_tree == candidate.chunk_tree
    }) {
        candidates.push(candidate);
    }
}

fn live_chunk_tree(superblock: &BtrfsSuperblock) -> TreeRoot {
    TreeRoot {
        tree_id: CHUNK_TREE_OBJECT_ID,
        logical: superblock.chunk_root(),
        level: superblock.chunk_root_level(),
        expected_generation: Some(superblock.chunk_root_generation()),
    }
}
