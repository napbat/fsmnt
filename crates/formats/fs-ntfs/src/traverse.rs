//! NTFS-specific [`FsDirectory`] / [`FsDirEntry`] implementation.
//!
//! # Design notes
//!
//! ## Streaming via [`NtfsOwnedIndexEntries`]
//!
//! [`NtfsDirectoryIter`] wraps an [`NtfsOwnedIndexEntries`] that
//! *owns* the [`NtfsIndex`]. Each call to [`FsTryIterator::try_next`]
//! advances the B-tree walk one step and returns a lending
//! [`NtfsTraversalEntry`] whose name bytes borrow directly from the
//! iterator's owned index data — zero heap allocations per entry.
//!
//! ## Supertrait split avoids `'static` forcing
//!
//! The GAT `Item<'a>` is defined in [`FsTryIteratorType`] (the
//! supertrait) without `where Self: 'a`. This prevents the
//! `for<'a>` HRTB in [`walk_dir`] from forcing `'n: 'static`
//! (rust-lang/rust#87479), so tests can use stack-local [`Ntfs`]
//! instances without `Box::leak`.
//!
//! [`NtfsIndex`]: crate::NtfsIndex
//! [`NtfsFile`]: crate::NtfsFile
//! [`NtfsIndexEntry`]: crate::NtfsIndexEntry
//! [`NtfsOwnedIndexEntries`]: crate::NtfsOwnedIndexEntries
//! [`FsTryIterator::try_next`]: fs_common::iter::FsTryIterator::try_next
//! [`FsTryIteratorType`]: fs_common::iter::FsTryIteratorType
//! [`walk_dir`]: fs_common::traverse::walk_dir
//! [`Ntfs`]: crate::Ntfs

use fs_common::iter::{FsTryIterator, FsTryIteratorType};
use fs_common::traverse::{EntryKind, FsDirEntry, FsDirectory, FsId};

use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::index::NtfsOwnedIndexEntries;
use crate::indexes::NtfsFileNameIndex;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;

/// An NTFS directory handle that implements [`FsDirectory`].
///
/// Stores an [`Ntfs`] reference and MFT record number. The
/// directory is re-opened from disk each time [`entries`] is
/// called, avoiding self-referential lifetime issues with
/// [`NtfsIndex`] (see [module-level docs](self) for details).
///
/// [`entries`]: FsDirectory::entries
/// [`NtfsIndex`]: crate::NtfsIndex
pub struct NtfsDirectory<'n> {
    ntfs: &'n Ntfs,
    file_record_number: u64,
}

impl<'n> NtfsDirectory<'n> {
    /// Creates a directory handle from an [`Ntfs`] reference and
    /// MFT record number.
    #[must_use]
    pub fn new(ntfs: &'n Ntfs, file_record_number: u64) -> Self {
        Self {
            ntfs,
            file_record_number,
        }
    }

    /// Creates a directory handle from an [`NtfsFile`].
    ///
    /// The [`Ntfs`] reference is derived from the file itself,
    /// ensuring the directory handle is always bound to the
    /// correct volume.
    ///
    /// Returns `Err(NtfsError::NotADirectory)` if the file is
    /// not a directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory index is malformed or cannot be read.
    pub fn from_file<R: Read + Seek>(file: &NtfsFile<'n>, r: &mut R) -> Result<Self> {
        if !file.is_directory() {
            return Err(NtfsError::NotADirectory {
                position: file.position(),
            });
        }
        // Verify we can open the directory index (validates the
        // file is a well-formed directory).
        let _ = file.directory_index(r)?;
        Ok(Self::new(file.ntfs(), file.file_record_number()))
    }

    /// Returns the MFT file record number of this directory.
    #[must_use]
    pub fn file_record_number(&self) -> u64 {
        self.file_record_number
    }
}

impl<'n, R: Read + Seek> FsDirectory<R> for NtfsDirectory<'n> {
    type Error = NtfsError;
    type EntryIter = NtfsDirectoryIter<'n>;

    /// Opens the directory index and returns a streaming iterator
    /// over its entries.  The [`NtfsIndex`] is moved into the
    /// returned [`NtfsDirectoryIter`] via [`NtfsIndex::into_entries`],
    /// so entries are read on demand rather than pre-collected.
    ///
    /// [`NtfsIndex`]: crate::NtfsIndex
    /// [`NtfsIndex::into_entries`]: crate::NtfsIndex::into_entries
    fn entries(&mut self, r: &mut R) -> Result<NtfsDirectoryIter<'n>> {
        let file = self.ntfs.file(r, self.file_record_number)?;
        let index = file.directory_index(r)?;

        Ok(NtfsDirectoryIter {
            ntfs: self.ntfs,
            inner: index.into_entries(),
        })
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(self.file_record_number))
    }
}

/// Streaming iterator over NTFS directory entries.
///
/// Wraps an [`NtfsOwnedIndexEntries`] that owns the [`NtfsIndex`].
/// Each call to [`FsTryIterator::try_next`] walks the B-tree one
/// step and returns a lending [`NtfsTraversalEntry`] whose name
/// bytes borrow from the iterator's owned index data.
///
/// [`NtfsIndex`]: crate::NtfsIndex
/// [`NtfsOwnedIndexEntries`]: crate::NtfsOwnedIndexEntries
/// [`NtfsIndexEntry`]: crate::NtfsIndexEntry
/// [`FsTryIterator::try_next`]: fs_common::iter::FsTryIterator::try_next
pub struct NtfsDirectoryIter<'n> {
    ntfs: &'n Ntfs,
    inner: NtfsOwnedIndexEntries<'n, NtfsFileNameIndex>,
}

impl<'n> FsTryIteratorType for NtfsDirectoryIter<'n> {
    type Error = NtfsError;
    type Item<'a> = NtfsTraversalEntry<'n, 'a>;
}

impl<'n, R: Read + Seek> FsTryIterator<R> for NtfsDirectoryIter<'n> {
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsTraversalEntry<'n, '_>>> {
        // Keyless sentinel entries are filtered by btree_walk_next,
        // so every entry yielded here has a valid key.
        let Some(entry) = self.inner.try_next(r)? else {
            return Ok(None);
        };

        let file_ref = entry.file_reference();
        let key_ref = entry
            .key_ref()
            .expect("btree_walk_next filters keyless entries")?;
        Ok(Some(NtfsTraversalEntry {
            ntfs: self.ntfs,
            name: key_ref.name_bytes(),
            is_directory: key_ref.is_directory(),
            file_record_number: file_ref.file_record_number(),
        }))
    }
}

/// NTFS directory entry for the traversal framework.
///
/// # Naming convention
///
/// Named `NtfsTraversalEntry` (not `NtfsDirectoryEntry`) to avoid
/// collision with [`NtfsDirectoryEntry`](crate::NtfsDirectoryEntry)
/// from slack recovery. Convention for future crates: reserve
/// `*Entry` for raw on-disk record types; use `*TraversalEntry`
/// for [`FsDirEntry`] adapters.
///
/// # Cost profile
///
/// | Field | Size | Allocation |
/// |-------|------|------------|
/// | `ntfs` | 8 B | pointer copy — free |
/// | `name` | 16 B | borrowed slice — **zero heap alloc** |
/// | `is_directory` | 1 B | copied from index key |
/// | `file_record_number` | 8 B | copied from file reference |
///
/// The `name` field borrows directly from the index entry data
/// owned by the iterator, avoiding per-entry heap allocation.
pub struct NtfsTraversalEntry<'n, 'a> {
    ntfs: &'n Ntfs,
    /// UTF-16LE name bytes, borrowed from the iterator's index data.
    name: &'a [u8],
    is_directory: bool,
    file_record_number: u64,
}

impl NtfsTraversalEntry<'_, '_> {
    /// Returns the MFT file record number of this entry.
    #[must_use]
    pub fn file_record_number(&self) -> u64 {
        self.file_record_number
    }
}

impl<'n, R: Read + Seek> FsDirEntry<R> for NtfsTraversalEntry<'n, '_> {
    type Error = NtfsError;
    type Dir = NtfsDirectory<'n>;

    fn kind(&self) -> EntryKind {
        if self.is_directory {
            EntryKind::Directory
        } else {
            EntryKind::File
        }
    }

    fn name_bytes(&self) -> &[u8] {
        self.name
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(self.file_record_number))
    }

    fn open_dir(&self, _r: &mut R) -> Result<Option<Self::Dir>> {
        if !self.is_directory {
            return Ok(None);
        }
        Ok(Some(NtfsDirectory::new(self.ntfs, self.file_record_number)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;
    use alloc::vec::Vec;
    use fs_common::traverse::walk_dir;

    /// Verify that the trait bounds required by `walk_dir` are
    /// satisfied for our types. Compile-time check only.
    #[allow(dead_code)]
    fn assert_fs_directory_bound<'n, R: Read + Seek>()
    where
        NtfsDirectory<'n>: FsDirectory<R>,
    {
    }

    /// Verify `NtfsTraversalEntry` satisfies `FsDirEntry` with
    /// the correct `Dir` associated type.
    #[allow(dead_code)]
    fn assert_fs_dir_entry_bound<'n, 'a, R: Read + Seek>()
    where
        NtfsTraversalEntry<'n, 'a>: FsDirEntry<R, Dir = NtfsDirectory<'n>>,
    {
    }

    use crate::file::synthetic;

    /// Concrete reader type for resolving the generic `FsDirEntry`/`FsDirectory`
    /// trait methods in tests.
    type TestReader = fsmnt_testkit::Cursor<Vec<u8>>;

    #[test]
    fn test_directory_accessors() {
        // Build a bare Ntfs from a synthetic boot sector (no record needed).
        let record = synthetic::file_record(0x0001, 1, 1, &[]);
        let (ntfs, _cursor) = synthetic::load(&record, 0);

        // file_record_number returns the stored value (distinct from 0/1).
        let dir = NtfsDirectory::new(&ntfs, 42);
        assert_eq!(dir.file_record_number(), 42);
        assert_eq!(FsDirectory::<TestReader>::id(&dir), Some(FsId(42)));
    }

    #[test]
    fn test_from_file_accepts_well_formed_directory() {
        // A well-formed directory (record 1) with a valid $I30 INDEX_ROOT must
        // be accepted by from_file. Guards the `!file.is_directory()` check:
        // deleting `!` would make this directory wrongly return NotADirectory.
        let dir = synthetic::directory_record(7, false, "child.txt");
        let image = synthetic::mft_image(&[dir]);
        let mut cursor = fsmnt_testkit::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();

        let dir_file = ntfs.file(&mut cursor, 1).unwrap();
        assert!(dir_file.is_directory());

        let handle = NtfsDirectory::from_file(&dir_file, &mut cursor)
            .expect("a well-formed directory must be accepted");
        assert_eq!(handle.file_record_number(), 1);
    }

    #[test]
    fn test_directory_iter_yields_entry() {
        // Walk a directory whose $I30 index has one FILE_NAME entry. The
        // iterator must yield that entry (guards try_next returning Ok(None)).
        let dir = synthetic::directory_record(7, false, "child.txt");
        let image = synthetic::mft_image(&[dir]);
        let mut cursor = fsmnt_testkit::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();

        let mut handle = NtfsDirectory::new(&ntfs, 1);
        let mut iter = FsDirectory::<TestReader>::entries(&mut handle, &mut cursor).unwrap();

        let entry = iter
            .try_next(&mut cursor)
            .unwrap()
            .expect("expected one directory entry");
        assert_eq!(entry.file_record_number(), 7);
        assert_eq!(
            FsDirEntry::<TestReader>::name_bytes(&entry),
            "child.txt"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>()
        );

        // No further entries.
        assert!(iter.try_next(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn test_from_file_rejects_non_directory() {
        // A non-directory file must produce NotADirectory (guards `!is_directory`).
        let attrs = [crate::file::synthetic::ResidentAttr {
            ty: crate::attribute::NtfsAttributeType::Data,
            instance: 0,
            name: "",
            value: alloc::vec![0u8; 4],
        }];
        let record = synthetic::file_record(0x0001, 1, 1, &attrs);
        let (ntfs, mut cursor) = synthetic::load(&record, 30);
        let file = synthetic::open_file(&ntfs, &mut cursor, 30);

        let result = NtfsDirectory::from_file(&file, &mut cursor);
        assert!(matches!(result, Err(NtfsError::NotADirectory { .. })));
    }

    #[test]
    fn test_traversal_entry_accessors() {
        // Build a traversal entry directly (fields are private to this module).
        let record = synthetic::file_record(0x0001, 1, 1, &[]);
        let (ntfs, _cursor) = synthetic::load(&record, 0);

        let name = b"hello".as_slice();
        let dir_entry = NtfsTraversalEntry {
            ntfs: &ntfs,
            name,
            is_directory: true,
            file_record_number: 77,
        };
        assert_eq!(dir_entry.file_record_number(), 77);
        assert_eq!(FsDirEntry::<TestReader>::id(&dir_entry), Some(FsId(77)));
        assert_eq!(FsDirEntry::<TestReader>::name_bytes(&dir_entry), b"hello");
        assert_eq!(
            FsDirEntry::<TestReader>::kind(&dir_entry),
            EntryKind::Directory
        );

        let file_entry = NtfsTraversalEntry {
            ntfs: &ntfs,
            name: b"file".as_slice(),
            is_directory: false,
            file_record_number: 88,
        };
        assert_eq!(file_entry.file_record_number(), 88);
        assert_eq!(FsDirEntry::<TestReader>::kind(&file_entry), EntryKind::File);
    }

    #[test]
    fn test_open_dir_directory_vs_file() {
        // open_dir returns Some for a directory entry, None for a file entry.
        let record = synthetic::file_record(0x0001, 1, 1, &[]);
        let (ntfs, mut cursor) = synthetic::load(&record, 0);

        let dir_entry = NtfsTraversalEntry {
            ntfs: &ntfs,
            name: b"sub".as_slice(),
            is_directory: true,
            file_record_number: 50,
        };
        let opened = dir_entry.open_dir(&mut cursor).unwrap();
        assert!(opened.is_some());
        assert_eq!(opened.unwrap().file_record_number(), 50);

        let file_entry = NtfsTraversalEntry {
            ntfs: &ntfs,
            name: b"f".as_slice(),
            is_directory: false,
            file_record_number: 51,
        };
        assert!(file_entry.open_dir(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn walk_ntfs_directory_tree() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        let mut dir = NtfsDirectory::new(&ntfs, root_dir.file_record_number());
        let mut seen = BTreeSet::new();
        let mut visited = Vec::new();

        walk_dir(
            &mut testfs1,
            &mut dir,
            &mut seen,
            &mut |entry: NtfsTraversalEntry<'_, '_>| {
                visited.push(entry.name.to_vec());
            },
        )
        .expect("walk_dir should not fail");

        // The test filesystem has several files and directories.
        // Verify we visited a reasonable number of entries.
        assert!(
            visited.len() > 5,
            "Expected at least 5 entries, got {}",
            visited.len()
        );
    }
}
