//! Recovering ext files when the directory tree is unusable.
//!
//! An ext filesystem stores *names* in directory blocks and *content*
//! through inodes, and the two need not live near each other. Android
//! system images are the extreme case: mkfs places directories at the very
//! end of the volume, so an image truncated at 90 % still holds almost all
//! file data while the tree that names it is gone. The same shape appears
//! whenever directory blocks are damaged and inode tables are not.
//!
//! Salvage mode answers that by ignoring names entirely: it sweeps the
//! inode tables of every readable block group and exposes each in-use
//! inode under a synthetic directory as `inode-<N>`. Reads then go through
//! the ordinary inode path, so extents, block maps, inline data and holes
//! all behave exactly as they do for a named file. Directories found this
//! way are exposed too — entering one recovers the names of everything
//! below it.

use std::path::PathBuf;

use fs_ext::io::{Read, Seek};
use fs_ext::{Ext, ExtInode};
use fsmnt_core::{FsEntry, FsEntryFlags, FsMetadata};

use super::{Reader, ts_to_utc};

/// Name of the synthetic top-level directory holding the sweep results.
///
/// The leading dot plus the `fsmnt-` prefix keeps it out of the way of
/// real entries: no distribution ships a root directory by this name, and
/// a collision would only hide fsmnt's own view, never a real file.
pub(super) const SALVAGE_DIR: &str = ".fsmnt-salvage";

/// Prefix of a salvaged entry's name; the rest is its inode number.
const INODE_PREFIX: &str = "inode-";

/// Lowest inode number a sweep will consider when the superblock does not
/// say otherwise (`s_first_ino` on a revision-0 filesystem).
///
/// Everything below it is filesystem bookkeeping — root, the journal, the
/// resize inode, quota files — which the tree already exposes properly and
/// which would only add noise here.
const DEFAULT_FIRST_INODE: u32 = 11;

/// One in-use inode found by the sweep.
pub(super) struct SalvagedInode {
    /// Inode number, which is also the entry name via [`inode_name`].
    pub(super) inum: u32,
    /// Metadata read from the inode itself.
    pub(super) metadata: FsMetadata,
}

/// The entry name a salvaged inode is exposed under.
pub(super) fn inode_name(inum: u32) -> String {
    format!("{INODE_PREFIX}{inum}")
}

/// The inode number a salvage entry name refers to, or `None` when `name`
/// is not one of ours.
pub(super) fn name_inode(name: &str) -> Option<u32> {
    name.strip_prefix(INODE_PREFIX)?.parse().ok()
}

/// Metadata for the synthetic salvage directory itself.
pub(super) fn directory_metadata() -> FsMetadata {
    FsMetadata {
        is_dir: true,
        ..FsMetadata::default()
    }
}

/// The [`FsEntry`] that advertises the salvage directory inside a listing
/// of `parent`.
pub(super) fn directory_entry(parent: &str) -> FsEntry {
    FsEntry {
        path: PathBuf::from(parent).join(SALVAGE_DIR),
        name: SALVAGE_DIR.to_string(),
        flags: FsEntryFlags::empty(),
        file_id: None,
        metadata: directory_metadata(),
    }
}

/// Whether an inode holds content worth recovering.
///
/// Only regular files and directories qualify: a device node or socket has
/// no bytes to recover, and a symlink without its name is meaningless.
/// `links_count > 0` with `dtime == 0` is the pair the kernel keeps for a
/// live inode — a deleted one has its deletion time stamped, and an inode
/// that was never allocated reads as all zeros and fails both tests.
fn is_in_use(inode: &ExtInode<'_>) -> bool {
    (inode.is_regular_file() || inode.is_directory())
        && inode.links_count() > 0
        && inode.dtime().seconds == 0
}

/// The first inode number of the block group after the one holding `inum`.
fn next_group_start(inum: u32, inodes_per_group: u32) -> Option<u32> {
    let group = inum.checked_sub(1)? / inodes_per_group;
    group
        .checked_add(1)?
        .checked_mul(inodes_per_group)?
        .checked_add(1)
}

/// Sweep every readable inode table and collect the in-use inodes.
///
/// A block group whose inode table cannot be read — the usual end state of
/// a truncated image — contributes nothing and the sweep moves straight to
/// the next group rather than retrying each of its thousands of slots. No
/// diagnostics are emitted: on a damaged volume that is the expected case,
/// not an anomaly, and the caller sees the shortfall as missing entries.
pub(super) fn sweep<R: Read + Seek>(ext: &Ext, reader: &mut Reader<'_, R>) -> Vec<SalvagedInode> {
    let inodes_per_group = ext.inodes_per_group().max(1);
    let total = ext.inode_count();
    let mut inum = ext.first_inode().max(DEFAULT_FIRST_INODE);
    let mut found = Vec::new();

    while inum <= total {
        let Ok(inode) = ext.inode(reader, inum) else {
            // The group's inode table is unreadable — the usual end state
            // of a truncated image. Skip straight past its remaining
            // thousands of slots instead of failing on each in turn.
            let Some(next) = next_group_start(inum, inodes_per_group) else {
                break;
            };
            inum = next;
            continue;
        };
        if is_in_use(&inode) {
            let is_dir = inode.is_directory();
            found.push(SalvagedInode {
                inum,
                metadata: FsMetadata {
                    size: if is_dir { 0 } else { inode.size() },
                    is_dir,
                    created: inode.crtime().and_then(ts_to_utc),
                    modified: ts_to_utc(inode.mtime()),
                    accessed: ts_to_utc(inode.atime()),
                    readonly: false,
                    hidden: false,
                    system: false,
                },
            });
        }
        let Some(next) = inum.checked_add(1) else {
            break;
        };
        inum = next;
    }
    found
}

/// Turn sweep results into a directory listing rooted at `path`.
pub(super) fn listing(found: &[SalvagedInode], path: &str) -> Vec<FsEntry> {
    let parent = PathBuf::from(path);
    found
        .iter()
        .map(|salvaged| {
            let name = inode_name(salvaged.inum);
            FsEntry {
                path: parent.join(&name),
                name,
                flags: FsEntryFlags::empty(),
                file_id: Some(u64::from(salvaged.inum)),
                metadata: salvaged.metadata.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_round_trip() {
        assert_eq!(inode_name(12), "inode-12");
        assert_eq!(name_inode("inode-12"), Some(12));
        assert_eq!(name_inode("inode-0"), Some(0));
    }

    #[test]
    fn foreign_names_are_not_salvage_entries() {
        assert_eq!(name_inode("hello.txt"), None);
        assert_eq!(name_inode("inode-"), None);
        assert_eq!(name_inode("inode-x"), None);
        assert_eq!(name_inode("inode--1"), None);
    }

    #[test]
    fn a_failed_group_is_skipped_whole() {
        // 8192 inodes per group: inode 1 is in group 0, 8193 in group 1.
        assert_eq!(next_group_start(1, 8192), Some(8193));
        assert_eq!(next_group_start(8192, 8192), Some(8193));
        assert_eq!(next_group_start(8193, 8192), Some(16385));
    }

    #[test]
    fn a_sweep_near_the_inode_ceiling_terminates() {
        assert_eq!(next_group_start(u32::MAX, 1), None);
    }
}
