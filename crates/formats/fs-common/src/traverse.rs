//! Directory traversal traits and a generic recursive walker.
//!
//! Provides [`FsDirEntry`] and [`FsDirectory`] for filesystem-agnostic
//! directory enumeration, plus [`walk_dir`] for recursive traversal with
//! cycle detection.

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
use std::collections::BTreeSet;

use crate::error::FsError;
use crate::io::{Read, Seek};
use crate::iter::{FsTryIterator, FsTryIteratorType};

/// Whether a directory entry is a file, directory, or something else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Regular file.
    File,
    /// Directory (container for other entries).
    Directory,
    /// Symbolic link.
    Symlink,
    /// FIFO / named pipe.
    Fifo,
    /// Character device node.
    CharDevice,
    /// Block device node.
    BlockDevice,
    /// Unix-domain socket node.
    Socket,
    /// Anything the filesystem-specific layer chose not to classify
    /// (NTFS reparse points the layer doesn't categorize, FAT volume
    /// labels, unknown ext4 file-type bytes, etc).
    Other,
}

/// Opaque filesystem-specific identifier for cycle detection and
/// hardlink/clone deduplication.
///
/// Semantics vary by filesystem:
/// - NTFS: MFT record number
/// - FAT: starting cluster
/// - ext*: inode number
/// - APFS: object identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FsId(pub u64);

/// A single entry in a directory listing.
///
/// Intentionally minimal: no metadata, timestamps, or size. Those belong
/// in per-crate types or in a future fs-unified metadata model.
///
/// # Naming convention
///
/// Implementors should use `*TraversalEntry` (or `*DirEnt`) for
/// types that implement this trait, reserving plain `*Entry` for
/// raw on-disk record types. This prevents collisions with
/// existing low-level types (e.g. `NtfsDirectoryEntry` in slack
/// recovery, `FatDirEntry` in fs-fat).
pub trait FsDirEntry<R: Read + Seek> {
    /// The error type.
    type Error: FsError;

    /// The directory handle type returned by [`open_dir`](Self::open_dir).
    /// Intentionally unconstrained here; the recursive constraint is
    /// applied at walker use-sites.
    type Dir;

    /// Whether this entry is a file, directory, or other.
    fn kind(&self) -> EntryKind;

    /// Raw on-disk name bytes. Encoding is filesystem-specific:
    /// - NTFS: UTF-16LE
    /// - FAT: CP437 (SFN) or UTF-16LE (LFN)
    /// - ext*: arbitrary bytes (typically UTF-8)
    fn name_bytes(&self) -> &[u8];

    /// Stable identifier for cycle detection and hardlink dedup.
    /// Returns `None` if the filesystem doesn't support stable IDs.
    fn id(&self) -> Option<FsId>;

    /// Open this entry as a directory for recursive traversal.
    /// Returns `Ok(None)` if this entry is not a directory.
    fn open_dir(&self, r: &mut R) -> Result<Option<Self::Dir>, Self::Error>;
}

/// A directory handle that can enumerate its entries.
///
/// # Implementation guidance
///
/// Prefer streaming iterators that read entries on demand
/// over pre-collecting into a `Vec`. Pre-collection trades
/// streaming semantics and memory for simpler lifetime
/// management — acceptable as a crate-specific workaround
/// (see `fs-ntfs::traverse`) but not the target pattern.
///
/// Traversal entries (`Item` of `EntryIter`) should ideally
/// be cheap handles (IDs, offsets, record references) rather
/// than types that heap-allocate per entry.
pub trait FsDirectory<R: Read + Seek> {
    /// The error type.
    type Error: FsError;

    /// The iterator over directory entries.
    type EntryIter: FsTryIterator<R, Error = Self::Error>;

    /// Returns an iterator over this directory's entries.
    fn entries(&mut self, r: &mut R) -> Result<Self::EntryIter, Self::Error>;

    /// Stable identifier for this directory, used to seed
    /// [`walk_dir`]'s cycle-detection set before descent.
    ///
    /// Returns `None` by default. Implementations should override
    /// this when the directory's own ID is known (e.g. FAT root
    /// cluster, NTFS MFT record number) so that child entries
    /// pointing back to this directory are detected as cycles.
    fn id(&self) -> Option<FsId> {
        None
    }
}

/// Maximum recursion depth for [`walk_dir`]. Prevents stack overflow
/// when [`FsDirEntry::id`] returns `None` in cyclic directory graphs.
/// Set to 4096 to avoid truncating legitimate deep trees in forensic
/// collection (~800 KB stack at worst, well within default limits).
const MAX_WALK_DEPTH: usize = 4096;

/// Recursively walks a directory tree, calling `on_entry` for each entry.
///
/// Uses [`BTreeSet<FsId>`] for cycle detection (avoids `hashbrown`
/// dependency). The recursive `Dir = D` constraint is expressed here,
/// not in the trait definitions.
///
/// # Cycle detection
///
/// Cycle breaking relies on [`FsDirEntry::id`] returning `Some(id)`.
/// Implementations that return `None` bypass id-based detection; a
/// hard depth limit of [`MAX_WALK_DEPTH`] (4096) prevents stack
/// overflow in that case.
///
/// # Supertrait split avoids `'static` forcing
///
/// The GAT `Item<'a>` is defined in [`FsTryIteratorType`] (the
/// supertrait) without a `where Self: 'a` bound. This prevents
/// the `for<'a>` HRTB bounds below from forcing
/// `D::EntryIter: 'static` (rust-lang/rust#87479), allowing
/// iterators with non-`'static` lifetime parameters.
///
/// [`FsTryIteratorType`]: crate::iter::FsTryIteratorType
pub fn walk_dir<R, D, F>(
    r: &mut R,
    dir: &mut D,
    seen: &mut BTreeSet<FsId>,
    on_entry: &mut F,
) -> Result<(), D::Error>
where
    R: Read + Seek,
    D: FsDirectory<R>,
    for<'a> <D::EntryIter as FsTryIteratorType>::Item<'a>: FsDirEntry<R, Error = D::Error, Dir = D>,
    F: for<'a> FnMut(<D::EntryIter as FsTryIteratorType>::Item<'a>),
{
    // Seed the seen set with the root directory's own ID so that
    // child entries pointing back to root (e.g. FAT "." entries)
    // are detected as cycles immediately.
    if let Some(id) = dir.id() {
        seen.insert(id);
    }
    walk_dir_inner(r, dir, seen, on_entry, 0)
}

fn walk_dir_inner<R, D, F>(
    r: &mut R,
    dir: &mut D,
    seen: &mut BTreeSet<FsId>,
    on_entry: &mut F,
    depth: usize,
) -> Result<(), D::Error>
where
    R: Read + Seek,
    D: FsDirectory<R>,
    for<'a> <D::EntryIter as FsTryIteratorType>::Item<'a>: FsDirEntry<R, Error = D::Error, Dir = D>,
    F: for<'a> FnMut(<D::EntryIter as FsTryIteratorType>::Item<'a>),
{
    if depth >= MAX_WALK_DEPTH {
        return Ok(());
    }
    let mut it = dir.entries(r)?;
    while let Some(entry) = it.try_next(r)? {
        let kind = entry.kind();
        let id = entry.id();

        // Cycle-check before open_dir to avoid wasted work on
        // duplicates.
        let mut should_recurse = kind == EntryKind::Directory;
        if should_recurse
            && let Some(id) = id
            && !seen.insert(id)
        {
            should_recurse = false;
        }

        // Open child dir while entry is still alive (before the
        // by-value callback consumes it). If open_dir returns Err,
        // the error propagates and on_entry is NOT called for this
        // entry — correct for a forensic walker (fail fast on I/O).
        let child_dir = if should_recurse {
            entry.open_dir(r)?
        } else {
            None
        };

        on_entry(entry);

        if let Some(mut child) = child_dir {
            walk_dir_inner(r, &mut child, seen, on_entry, depth + 1)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, IoError};
    use std::io::Cursor;
    use std::vec::Vec;

    #[derive(Debug)]
    struct MockError;

    impl From<IoError> for MockError {
        fn from(_: IoError) -> Self {
            Self
        }
    }

    impl FsError for MockError {
        fn io_kind(&self) -> Option<ErrorKind> {
            None
        }

        fn byte_offset(&self) -> Option<u64> {
            None
        }
    }

    #[derive(Clone)]
    struct MockChild {
        name: Vec<u8>,
        kind: EntryKind,
        id: Option<u64>,
        subdir_children: Vec<MockChild>,
    }

    struct MockDir {
        children: Vec<MockChild>,
        id: Option<u64>,
    }

    struct MockDirIter {
        children: Vec<MockChild>,
        pos: usize,
    }

    impl crate::iter::FsTryIteratorType for MockDirIter {
        type Error = MockError;
        type Item<'a> = MockChild;
    }

    impl FsTryIterator<Cursor<Vec<u8>>> for MockDirIter {
        fn try_next(&mut self, _r: &mut Cursor<Vec<u8>>) -> Result<Option<MockChild>, MockError> {
            if self.pos < self.children.len() {
                let child = self.children[self.pos].clone();
                self.pos += 1;
                Ok(Some(child))
            } else {
                Ok(None)
            }
        }
    }

    impl FsDirEntry<Cursor<Vec<u8>>> for MockChild {
        type Error = MockError;
        type Dir = MockDir;

        fn kind(&self) -> EntryKind {
            self.kind
        }

        fn name_bytes(&self) -> &[u8] {
            &self.name
        }

        fn id(&self) -> Option<FsId> {
            self.id.map(FsId)
        }

        fn open_dir(&self, _r: &mut Cursor<Vec<u8>>) -> Result<Option<MockDir>, MockError> {
            if self.kind == EntryKind::Directory {
                Ok(Some(MockDir {
                    children: self.subdir_children.clone(),
                    id: self.id,
                }))
            } else {
                Ok(None)
            }
        }
    }

    impl FsDirectory<Cursor<Vec<u8>>> for MockDir {
        type Error = MockError;
        type EntryIter = MockDirIter;

        fn entries(&mut self, _r: &mut Cursor<Vec<u8>>) -> Result<MockDirIter, MockError> {
            Ok(MockDirIter {
                children: self.children.clone(),
                pos: 0,
            })
        }

        fn id(&self) -> Option<FsId> {
            self.id.map(FsId)
        }
    }

    #[test]
    fn walk_visits_all_entries() {
        let mut root = MockDir {
            children: vec![
                MockChild {
                    name: b"file1.txt".to_vec(),
                    kind: EntryKind::File,
                    id: Some(1),
                    subdir_children: Vec::new(),
                },
                MockChild {
                    name: b"file2.txt".to_vec(),
                    kind: EntryKind::File,
                    id: Some(2),
                    subdir_children: Vec::new(),
                },
            ],
            id: None,
        };

        let mut reader = Cursor::new(Vec::new());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        walk_dir(&mut reader, &mut root, &mut seen, &mut |entry| {
            visited.push(entry.name_bytes().to_vec());
        })
        .expect("walk_dir should not fail");

        assert_eq!(visited.len(), 2);
        assert_eq!(visited[0], b"file1.txt");
        assert_eq!(visited[1], b"file2.txt");
    }

    #[test]
    fn walk_nested_directories() {
        let mut root = MockDir {
            children: vec![
                MockChild {
                    name: b"file_a".to_vec(),
                    kind: EntryKind::File,
                    id: Some(1),
                    subdir_children: Vec::new(),
                },
                MockChild {
                    name: b"subdir".to_vec(),
                    kind: EntryKind::Directory,
                    id: Some(2),
                    subdir_children: vec![MockChild {
                        name: b"nested_file".to_vec(),
                        kind: EntryKind::File,
                        id: Some(3),
                        subdir_children: Vec::new(),
                    }],
                },
            ],
            id: None,
        };

        let mut reader = Cursor::new(Vec::new());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        walk_dir(&mut reader, &mut root, &mut seen, &mut |entry| {
            visited.push(entry.name_bytes().to_vec());
        })
        .expect("walk_dir should not fail");

        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], b"file_a");
        assert_eq!(visited[1], b"subdir");
        assert_eq!(visited[2], b"nested_file");
    }

    #[test]
    fn walk_detects_cycles() {
        // Two directories that reference each other via the same FsId.
        // dir_a (id=10) contains dir_b (id=11).
        // dir_b (id=11) contains a "link" back to dir_a (id=10).
        // walk_dir should visit dir_a, dir_b, and the link entry,
        // but NOT recurse into the link because id=10 was already seen.
        let mut root = MockDir {
            children: vec![MockChild {
                name: b"dir_a".to_vec(),
                kind: EntryKind::Directory,
                id: Some(10),
                subdir_children: vec![MockChild {
                    name: b"dir_b".to_vec(),
                    kind: EntryKind::Directory,
                    id: Some(11),
                    subdir_children: vec![MockChild {
                        name: b"link_to_a".to_vec(),
                        kind: EntryKind::Directory,
                        id: Some(10),
                        subdir_children: vec![MockChild {
                            name: b"should_not_reach".to_vec(),
                            kind: EntryKind::File,
                            id: Some(99),
                            subdir_children: Vec::new(),
                        }],
                    }],
                }],
            }],
            id: None,
        };

        let mut reader = Cursor::new(Vec::new());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        walk_dir(&mut reader, &mut root, &mut seen, &mut |entry| {
            visited.push(entry.name_bytes().to_vec());
        })
        .expect("walk_dir should not fail");

        // dir_a, dir_b, and link_to_a are visited (on_entry is
        // called before the cycle check skips recursion).
        // "should_not_reach" must NOT appear.
        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], b"dir_a");
        assert_eq!(visited[1], b"dir_b");
        assert_eq!(visited[2], b"link_to_a");
        assert!(
            !visited.iter().any(|n| n == b"should_not_reach"),
            "cycle detection failed: walked into already-seen directory"
        );
    }

    #[test]
    fn walk_respects_depth_limit_when_id_is_none() {
        // Use walk_dir_inner directly with a small depth limit
        // to verify the depth guard truncates traversal.
        // Build a 5-level deep chain (all id=None) and walk
        // with max_depth starting at 3. Levels 4+ should be
        // skipped.
        fn make_chain(depth: usize) -> MockChild {
            if depth == 0 {
                return MockChild {
                    name: b"leaf".to_vec(),
                    kind: EntryKind::File,
                    id: None,
                    subdir_children: Vec::new(),
                };
            }
            let mut name = b"dir_".to_vec();
            name.push(b'0' + depth as u8);
            MockChild {
                name,
                kind: EntryKind::Directory,
                id: None,
                subdir_children: vec![make_chain(depth - 1)],
            }
        }

        let mut root = MockDir {
            children: vec![make_chain(5)],
            id: None,
        };

        let mut reader = Cursor::new(Vec::new());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        // Start at depth 0, limit effectively at 3
        walk_dir_inner(
            &mut reader,
            &mut root,
            &mut seen,
            &mut |entry: MockChild| {
                visited.push(entry.name_bytes().to_vec());
            },
            MAX_WALK_DEPTH - 3,
        )
        .expect("walk_dir_inner should not fail");

        // With 3 levels allowed: dir_5 (depth 0), dir_4 (depth 1),
        // dir_3 (depth 2) — then depth 3 hits the limit, so
        // dir_2 and below are NOT visited.
        assert_eq!(visited.len(), 3);
        assert_eq!(visited[0], b"dir_5");
        assert_eq!(visited[1], b"dir_4");
        assert_eq!(visited[2], b"dir_3");
    }

    #[test]
    fn walk_seeds_root_id_in_seen_set() {
        // Root directory has id=100. A child entry points back
        // to root (id=100). Without root seeding, this would
        // recurse once into root before detecting the cycle.
        // With seeding, the back-edge is detected immediately.
        let mut root = MockDir {
            children: vec![
                MockChild {
                    name: b"file.txt".to_vec(),
                    kind: EntryKind::File,
                    id: Some(1),
                    subdir_children: Vec::new(),
                },
                MockChild {
                    name: b"dot".to_vec(),
                    kind: EntryKind::Directory,
                    id: Some(100), // same as root
                    subdir_children: vec![MockChild {
                        name: b"should_not_reach".to_vec(),
                        kind: EntryKind::File,
                        id: Some(2),
                        subdir_children: Vec::new(),
                    }],
                },
            ],
            id: Some(100),
        };

        let mut reader = Cursor::new(Vec::new());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        walk_dir(&mut reader, &mut root, &mut seen, &mut |entry| {
            visited.push(entry.name_bytes().to_vec());
        })
        .expect("walk_dir should not fail");

        // file.txt and dot are visited, but dot's children are
        // NOT because id=100 was already seeded as root.
        assert_eq!(visited.len(), 2);
        assert_eq!(visited[0], b"file.txt");
        assert_eq!(visited[1], b"dot");
        assert!(
            !visited.iter().any(|n| n == b"should_not_reach"),
            "root-id seeding failed: walked into back-edge to root"
        );
    }
}
