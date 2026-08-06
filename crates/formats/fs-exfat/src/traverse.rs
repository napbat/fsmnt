//! Shared trait adapters for generic directory traversal.
//!
//! Provides [`ExFatDirectory`], [`ExFatDirectoryIter`], and
//! [`ExFatTraversalEntry`] — thin wrappers around existing fs-exfat
//! types that implement the [`FsDirectory`], [`FsTryIterator`], and
//! [`FsDirEntry`] traits from fs-common.

use fs_common::iter::{FsTryIterator, FsTryIteratorType};
use fs_common::traverse::{EntryKind, FsDirEntry, FsDirectory, FsId};

use crate::entry_set::{ExFatDirItem, ExFatEntrySet};
use crate::error::{ExFatError, Result};
use crate::exfat::ExFat;
use crate::io::{Read, Seek};

// ================================================================
// ExFatDirectory
// ================================================================

/// An exFAT directory handle implementing [`FsDirectory`].
///
/// Wraps an [`ExFat`] reference and a cluster number to enumerate
/// directory entries via the shared trait interface.
pub struct ExFatDirectory<'e> {
    exfat: &'e ExFat,
    cluster: u32,
}

impl<'e> ExFatDirectory<'e> {
    /// Creates a directory handle for the given cluster.
    #[must_use]
    pub fn new(exfat: &'e ExFat, cluster: u32) -> Self {
        Self { exfat, cluster }
    }

    /// Creates a directory handle for the root directory.
    #[must_use]
    pub fn root(exfat: &'e ExFat) -> Self {
        Self::new(exfat, exfat.root_directory_cluster())
    }
}

impl<'e, R: Read + Seek> FsDirectory<R> for ExFatDirectory<'e> {
    type Error = ExFatError;
    type EntryIter = ExFatDirectoryIter<'e>;

    fn entries(&mut self, _r: &mut R) -> core::result::Result<ExFatDirectoryIter<'e>, ExFatError> {
        Ok(ExFatDirectoryIter::new(self.exfat, self.cluster))
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(u64::from(self.cluster)))
    }
}

// ================================================================
// ExFatDirectoryIter
// ================================================================

/// Iterator adapter wrapping [`ExFatDirEntries`] for the
/// [`FsDirectory`] trait.
///
/// Yields [`ExFatTraversalEntry`] items, skipping volume labels
/// (which are metadata, not file/directory children).
pub struct ExFatDirectoryIter<'e> {
    inner: crate::dir_iter::ExFatDirEntries<'e>,
    exfat: &'e ExFat,
}

impl<'e> ExFatDirectoryIter<'e> {
    /// Creates a new traversal iterator for the given directory.
    pub(crate) fn new(exfat: &'e ExFat, start_cluster: u32) -> Self {
        Self {
            inner: exfat.dir_entries(start_cluster),
            exfat,
        }
    }
}

impl<'e> FsTryIteratorType for ExFatDirectoryIter<'e> {
    type Error = ExFatError;
    type Item<'a> = ExFatTraversalEntry<'e>;
}

impl<'e, R: Read + Seek> FsTryIterator<R> for ExFatDirectoryIter<'e> {
    fn try_next<'a>(
        &'a mut self,
        r: &mut R,
    ) -> core::result::Result<Option<ExFatTraversalEntry<'e>>, ExFatError> {
        loop {
            match self.inner.next(r) {
                Some(Ok(ExFatDirItem::FileEntry(entry_set))) => {
                    return Ok(Some(ExFatTraversalEntry {
                        entry_set,
                        exfat: self.exfat,
                    }));
                }
                Some(Ok(
                    ExFatDirItem::VolumeLabel(_)
                    | ExFatDirItem::BenignEntry { .. }
                    | ExFatDirItem::DeletedEntry { .. },
                )) => {}
                Some(Err(e)) => return Err(e),
                None => return Ok(None),
            }
        }
    }
}

// ================================================================
// ExFatTraversalEntry
// ================================================================

/// An exFAT directory entry paired with an [`ExFat`] reference,
/// implementing [`FsDirEntry`].
pub struct ExFatTraversalEntry<'e> {
    entry_set: ExFatEntrySet,
    exfat: &'e ExFat,
}

impl ExFatTraversalEntry<'_> {
    /// Returns a reference to the underlying [`ExFatEntrySet`].
    #[must_use]
    pub fn inner(&self) -> &ExFatEntrySet {
        &self.entry_set
    }
}

impl<'e, R: Read + Seek> FsDirEntry<R> for ExFatTraversalEntry<'e> {
    type Error = ExFatError;
    type Dir = ExFatDirectory<'e>;

    fn kind(&self) -> EntryKind {
        if self.entry_set.is_directory() {
            EntryKind::Directory
        } else {
            EntryKind::File
        }
    }

    fn name_bytes(&self) -> &[u8] {
        self.entry_set.name_utf16le()
    }

    fn id(&self) -> Option<FsId> {
        let cluster = self.entry_set.first_cluster();
        if cluster == 0 {
            None
        } else {
            Some(FsId(u64::from(cluster)))
        }
    }

    fn open_dir(&self, _r: &mut R) -> Result<Option<Self::Dir>> {
        if !self.entry_set.is_directory() {
            return Ok(None);
        }
        Ok(Some(ExFatDirectory::new(
            self.exfat,
            self.entry_set.first_cluster(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::io::Cursor;

    #[test]
    fn directory_iter_implements_fstryiterator() {
        fn assert_impl<R: Read + Seek, T: FsTryIterator<R>>() {}
        assert_impl::<Cursor<Vec<u8>>, ExFatDirectoryIter<'_>>();
    }

    #[test]
    fn traversal_entry_implements_fsdirentry() {
        fn assert_dir_entry<R: Read + Seek, T: FsDirEntry<R>>() {}
        assert_dir_entry::<Cursor<Vec<u8>>, ExFatTraversalEntry<'_>>();
    }

    #[test]
    fn directory_implements_fsdirectory() {
        fn assert_dir<R: Read + Seek, T: FsDirectory<R>>() {}
        assert_dir::<Cursor<Vec<u8>>, ExFatDirectory<'_>>();
    }

    /// `ExFatDirectory::id` is provided only through the
    /// `FsDirectory` trait. Inherent-method tests cannot reach it,
    /// leaving the `→ None` mutation alive. A trait-bounded helper
    /// dispatches through the trait impl.
    #[test]
    fn fsdirectory_id_returns_cluster_via_trait() {
        fn id<R: Read + Seek, D: FsDirectory<R>>(d: &D) -> Option<FsId> {
            d.id()
        }
        let image = make_image();
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let root = ExFatDirectory::root(&exfat);
        assert_eq!(id::<Cursor<Vec<u8>>, _>(&root), Some(FsId(2)));
        let other = ExFatDirectory::new(&exfat, 7);
        assert_eq!(id::<Cursor<Vec<u8>>, _>(&other), Some(FsId(7)));
    }

    /// Helper: builds a single-entry root directory with one file
    /// named `name` pointing to `cluster`. Returns the image so
    /// callers can construct a cursor.
    fn build_image_with_file_entry(name: &str, cluster: u32) -> Vec<u8> {
        use crate::dir_entry::*;
        use crate::entry_set::compute_set_checksum;
        use crate::upcase::compute_name_hash;

        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let utf16: Vec<u16> = name.encode_utf16().collect();
        let hash = compute_name_hash(&utf16);
        let mut raw = vec![0u8; 3 * DIR_ENTRY_SIZE];
        raw[0] = ENTRY_TYPE_FILE;
        raw[1] = 2;
        raw[4] = 0x20; // ARCHIVE
        raw[32] = ENTRY_TYPE_STREAM;
        raw[33] = 0x01;
        raw[35] = u8::try_from(utf16.len()).expect("test name fits the exFAT length field");
        raw[36..38].copy_from_slice(&hash.to_le_bytes());
        raw[52..56].copy_from_slice(&cluster.to_le_bytes());
        raw[56..64].copy_from_slice(&0u64.to_le_bytes());
        raw[40..48].copy_from_slice(&0u64.to_le_bytes());
        raw[64] = ENTRY_TYPE_NAME;
        for (i, &ch) in utf16.iter().enumerate() {
            let [lo, hi] = ch.to_le_bytes();
            raw[66 + i * 2] = lo;
            raw[66 + i * 2 + 1] = hi;
        }
        let cs = compute_set_checksum(&raw);
        raw[2..4].copy_from_slice(&cs.to_le_bytes());

        let root_off = cluster_heap_offset(2);
        image[root_off..root_off + raw.len()].copy_from_slice(&raw);
        image
    }

    /// `ExFatTraversalEntry::name_bytes` (a `FsDirEntry` trait
    /// method) returns the stored UTF-16LE name bytes. Asserting
    /// the exact bytes catches every `Vec::leak(...)` constant
    /// replacement on that method.
    #[test]
    fn fsdirentry_name_bytes_returns_utf16le_name() {
        fn name<R: Read + Seek, E: FsDirEntry<R>>(e: &E) -> &[u8] {
            e.name_bytes()
        }

        let image = build_image_with_file_entry("AB", 5);
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut root = ExFatDirectory::root(&exfat);
        let mut iter =
            <ExFatDirectory<'_> as FsDirectory<Cursor<Vec<u8>>>>::entries(&mut root, &mut cursor)
                .unwrap();
        let entry = iter
            .try_next(&mut cursor)
            .expect("no error")
            .expect("at least one entry");
        // "AB" in UTF-16LE = 0x41 0x00 0x42 0x00.
        assert_eq!(
            name::<Cursor<Vec<u8>>, _>(&entry),
            &[0x41, 0x00, 0x42, 0x00]
        );
    }

    /// `ExFatTraversalEntry::id` returns `Some(FsId(cluster))` for
    /// non-zero clusters and `None` for cluster 0. Both branches
    /// must be exercised to kill `→ None` and the `== → !=`
    /// mutation on the cluster-zero guard.
    #[test]
    fn fsdirentry_id_distinguishes_zero_and_nonzero_cluster() {
        fn id<R: Read + Seek, E: FsDirEntry<R>>(e: &E) -> Option<FsId> {
            e.id()
        }

        // cluster = 5 → Some(FsId(5))
        let image = build_image_with_file_entry("A", 5);
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut root = ExFatDirectory::root(&exfat);
        let mut iter =
            <ExFatDirectory<'_> as FsDirectory<Cursor<Vec<u8>>>>::entries(&mut root, &mut cursor)
                .unwrap();
        let entry = iter
            .try_next(&mut cursor)
            .expect("ok")
            .expect("at least one entry");
        assert_eq!(id::<Cursor<Vec<u8>>, _>(&entry), Some(FsId(5)));
        drop(iter);
        drop(entry);
        drop(cursor);

        // cluster = 0 → None
        let image_zero = build_image_with_file_entry("B", 0);
        let mut cursor_zero = Cursor::new(image_zero);
        let exfat_zero = ExFat::new(&mut cursor_zero).unwrap();
        let mut root_zero = ExFatDirectory::root(&exfat_zero);
        let mut iter_zero = <ExFatDirectory<'_> as FsDirectory<Cursor<Vec<u8>>>>::entries(
            &mut root_zero,
            &mut cursor_zero,
        )
        .unwrap();
        let entry_zero = iter_zero
            .try_next(&mut cursor_zero)
            .expect("ok")
            .expect("at least one entry");
        assert_eq!(id::<Cursor<Vec<u8>>, _>(&entry_zero), None);
    }

    #[test]
    fn walk_dir_two_level() {
        use crate::dir_entry::*;
        use crate::entry_set::compute_set_checksum;
        use crate::upcase::compute_name_hash;
        use fs_common::traverse::{EntryKind, walk_dir};

        let mut image = make_image();

        // FAT: clusters 2, 5, 6, 8 -> EOC
        for c in [2u32, 5, 6, 8] {
            set_fat_entry(&mut image, c, 0xFFFF_FFFF);
        }

        // Helper: write a file/dir entry set
        let write_entry =
            |image: &mut Vec<u8>, off: usize, name: &str, cluster: u32, is_dir: bool| {
                let utf16: Vec<u16> = name.encode_utf16().collect();
                let hash = compute_name_hash(&utf16);
                let mut raw = vec![0u8; 3 * DIR_ENTRY_SIZE];
                raw[0] = ENTRY_TYPE_FILE;
                raw[1] = 2;
                raw[4] = if is_dir { 0x10 } else { 0x20 };
                raw[32] = ENTRY_TYPE_STREAM;
                raw[33] = 0x01;
                raw[35] = u8::try_from(utf16.len()).expect("test name fits the exFAT length field");
                raw[36..38].copy_from_slice(&hash.to_le_bytes());
                raw[52..56].copy_from_slice(&cluster.to_le_bytes());
                raw[56..64].copy_from_slice(&512u64.to_le_bytes());
                raw[40..48].copy_from_slice(&512u64.to_le_bytes());
                raw[64] = ENTRY_TYPE_NAME;
                for (i, &ch) in utf16.iter().enumerate() {
                    let [lo, hi] = ch.to_le_bytes();
                    raw[66 + i * 2] = lo;
                    raw[66 + i * 2 + 1] = hi;
                }
                let cs = compute_set_checksum(&raw);
                raw[2..4].copy_from_slice(&cs.to_le_bytes());
                image[off..off + raw.len()].copy_from_slice(&raw);
            };

        // Root dir (cluster 2): DOCS/ + PHOTO.JPG
        let root_off = cluster_heap_offset(2);
        write_entry(&mut image, root_off, "DOCS", 5, true);
        write_entry(
            &mut image,
            root_off + 3 * DIR_ENTRY_SIZE,
            "PHOTO.JPG",
            6,
            false,
        );

        // DOCS dir (cluster 5): README.TXT
        let docs_off = cluster_heap_offset(5);
        write_entry(&mut image, docs_off, "README.TXT", 8, false);

        // Parse and walk
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut root = ExFatDirectory::root(&exfat);
        let mut seen = alloc::collections::BTreeSet::new();
        let mut names: Vec<(String, EntryKind)> = Vec::new();

        walk_dir(
            &mut cursor,
            &mut root,
            &mut seen,
            &mut |entry: ExFatTraversalEntry<'_>| {
                let name = entry.inner().name_string();
                let kind = if entry.inner().is_directory() {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };
                names.push((name, kind));
            },
        )
        .unwrap();

        assert_eq!(names.len(), 3);
        assert!(
            names
                .iter()
                .any(|(n, k)| n == "DOCS" && *k == EntryKind::Directory)
        );
        assert!(
            names
                .iter()
                .any(|(n, k)| n == "PHOTO.JPG" && *k == EntryKind::File)
        );
        assert!(
            names
                .iter()
                .any(|(n, k)| n == "README.TXT" && *k == EntryKind::File)
        );
    }
}
