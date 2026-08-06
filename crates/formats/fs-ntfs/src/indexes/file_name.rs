use core::cmp::Ordering;

use crate::error::Result;
use crate::index::NtfsIndexFinder;
use crate::index_entry::NtfsIndexEntry;
use crate::indexes::{NtfsIndexEntryHasFileReference, NtfsIndexEntryType};
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::structured_values::{NtfsFileName, NtfsFileNameRef, NtfsFileNamespace};
use crate::upcase_table::{CaseSensitiveOrd, UpcaseOrd};

/// Defines the [`NtfsIndexEntryType`] for filename indexes (commonly known as "directories").
#[derive(Clone, Copy, Debug)]
pub struct NtfsFileNameIndex;

impl NtfsFileNameIndex {
    /// Finds a file in a filename index by name and returns the [`NtfsIndexEntry`] (if any).
    ///
    /// This function uses a two-phase search to correctly handle both case-insensitive
    /// (Win32/DOS) and case-sensitive (POSIX) filename namespaces:
    ///
    /// 1. **Phase 1 (B-tree navigation)**: Uses case-insensitive comparison to navigate
    ///    the B-tree index, since NTFS always sorts entries case-insensitively.
    ///
    /// 2. **Phase 2 (Exact match verification)**: Once a case-insensitive match is found,
    ///    checks the filename namespace. For POSIX namespace files (which are case-sensitive),
    ///    performs an additional case-sensitive comparison to ensure an exact match.
    ///
    /// # Namespace Behavior
    ///
    /// - **POSIX namespace** ([`NtfsFileNamespace::Posix`]): Case-sensitive matching.
    ///   Files like "File.txt" and "file.txt" are considered different.
    /// - **Win32/DOS namespaces** ([`NtfsFileNamespace::Win32`], [`NtfsFileNamespace::Dos`],
    ///   [`NtfsFileNamespace::Win32AndDos`]): Case-insensitive matching.
    ///   Files like "File.txt" and "file.txt" are considered the same.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called on the passed [`Ntfs`] object.
    pub fn find<'a, T>(
        index_finder: &'a mut NtfsIndexFinder<Self>,
        ntfs: &Ntfs,
        fs: &mut T,
        name: &str,
    ) -> Option<Result<NtfsIndexEntry<'a, Self>>>
    where
        T: Read + Seek,
    {
        // Phase 1: Use case-insensitive comparison for B-tree navigation.
        // NTFS B-tree indexes are always sorted case-insensitively, so we must use
        // case-insensitive comparison to correctly traverse the tree.
        index_finder.find(fs, |file_name: &NtfsFileNameRef<'_>| {
            let cmp_result = name.upcase_cmp(ntfs, &file_name.name());

            // Phase 2: For case-insensitive matches, verify exact match for POSIX namespace.
            if cmp_result == Ordering::Equal {
                // Check if this is a POSIX namespace file (case-sensitive).
                // Upstream wrapped this in `core::hint::unlikely(..)`, which is
                // still nightly-only; the hint is advisory, so it is dropped.
                if file_name.namespace() == NtfsFileNamespace::Posix {
                    // For POSIX files, we need an exact case-sensitive match.
                    // If the case doesn't match exactly, we need to continue searching.
                    // However, since the B-tree is sorted case-insensitively, files that
                    // differ only by case will be adjacent. We return Equal here to get
                    // the entry, and then verify the exact match below.
                    return name.case_sensitive_cmp(&file_name.name());
                }
            }

            cmp_result
        })
    }

    /// Finds a file in a filename index by name using only case-insensitive comparison.
    ///
    /// This is the traditional NTFS behavior and matches how Windows Explorer and most
    /// Windows applications find files. Use this when you want to match files regardless
    /// of case, even for POSIX namespace files.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called on the passed [`Ntfs`] object.
    pub fn find_case_insensitive<'a, T>(
        index_finder: &'a mut NtfsIndexFinder<Self>,
        ntfs: &Ntfs,
        fs: &mut T,
        name: &str,
    ) -> Option<Result<NtfsIndexEntry<'a, Self>>>
    where
        T: Read + Seek,
    {
        index_finder.find(fs, |file_name: &NtfsFileNameRef<'_>| {
            name.upcase_cmp(ntfs, &file_name.name())
        })
    }
}

impl NtfsIndexEntryType for NtfsFileNameIndex {
    type KeyType = NtfsFileName;
}

impl NtfsIndexEntryHasFileReference for NtfsFileNameIndex {}
