use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::attribute::NtfsAttributeType;
use crate::error::Result;
use crate::file::NtfsFileFlags;
use crate::io::{Read, Seek};
use crate::mft::NtfsMftEntries;
use crate::ntfs::Ntfs;
use crate::structured_values::{NtfsFileName, NtfsFileNamespace};
use fs_common::iter::FsTryIterator;

/// A child record in the parent map, representing one MFT entry that names
/// a particular directory as its parent (via a `$FILE_NAME` attribute).
#[derive(Clone, Debug)]
pub struct NtfsChildEntry {
    record_number: u64,
    sequence_number: u16,
    parent_sequence: u16,
    is_directory: bool,
    namespace: NtfsFileNamespace,
}

impl NtfsChildEntry {
    /// The child's MFT record number.
    #[must_use]
    pub fn record_number(&self) -> u64 {
        self.record_number
    }

    /// The child's sequence number (from its MFT record header).
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// The parent's sequence number as recorded in the child's `$FILE_NAME`
    /// attribute (`parent_directory_reference`).
    #[must_use]
    pub fn parent_sequence(&self) -> u16 {
        self.parent_sequence
    }

    /// Whether this child is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// The file name namespace (Win32, Dos, Posix, or `Win32AndDos`).
    #[must_use]
    pub fn namespace(&self) -> NtfsFileNamespace {
        self.namespace
    }
}

/// A map from parent MFT record numbers to their child entries, built by
/// scanning every in-use MFT record's `$FILE_NAME` attributes.
///
/// Use [`NtfsParentMap::orphans_for`] to find children that claim a directory
/// as their parent but do not appear in that directory's index.
#[derive(Clone, Debug)]
pub struct NtfsParentMap {
    map: BTreeMap<u64, Vec<NtfsChildEntry>>,
}

impl NtfsParentMap {
    /// Scans the entire MFT and builds the parent-to-children map.
    ///
    /// For each in-use MFT entry, every `$FILE_NAME` attribute is inspected
    /// and the entry is recorded under its parent's record number. Corrupt or
    /// unreadable records are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if the MFT iterator cannot be initialized.
    pub fn build<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        let mut iter = NtfsMftEntries::new(ntfs, fs)?;
        let mut map: BTreeMap<u64, Vec<NtfsChildEntry>> = BTreeMap::new();

        while let Some(result) = iter.next(ntfs, fs) {
            let Ok(file) = result else {
                continue;
            };
            if !file.flags().contains(NtfsFileFlags::IN_USE) {
                continue;
            }

            let is_directory = file.flags().contains(NtfsFileFlags::IS_DIRECTORY);
            let record_number = file.file_record_number();
            let sequence_number = file.sequence_number();

            let mut attrs = file.attributes();
            loop {
                let item = match attrs.try_next(fs) {
                    Ok(Some(a)) => a,
                    Ok(None) => break,
                    Err(_) => continue,
                };
                let Ok(attr) = item.to_attribute() else {
                    continue;
                };
                if attr.ty().unwrap_or(NtfsAttributeType::End) != NtfsAttributeType::FileName {
                    continue;
                }
                let Ok(fname) = attr.structured_value::<_, NtfsFileName>(fs) else {
                    continue;
                };

                let parent_ref = fname.parent_directory_reference();
                let entry = NtfsChildEntry {
                    record_number,
                    sequence_number,
                    parent_sequence: parent_ref.sequence_number(),
                    is_directory,
                    namespace: fname.namespace(),
                };
                map.entry(parent_ref.file_record_number())
                    .or_default()
                    .push(entry);
            }
        }

        Ok(Self { map })
    }

    /// Returns all children whose `$FILE_NAME` attributes name `parent_record_number`
    /// as their parent directory.
    pub fn children(&self, parent_record_number: u64) -> &[NtfsChildEntry] {
        self.map
            .get(&parent_record_number)
            .map_or(&[], Vec::as_slice)
    }

    /// Returns children that claim `dir_record_number` as their parent (with a
    /// matching `dir_sequence`) but whose record numbers are absent from
    /// `indexed_records`.
    ///
    /// These are potential orphan files — allocated entries that the directory
    /// index no longer references.
    #[must_use]
    pub fn orphans_for(
        &self,
        dir_record_number: u64,
        dir_sequence: u16,
        indexed_records: &BTreeSet<u64>,
    ) -> Vec<&NtfsChildEntry> {
        self.children(dir_record_number)
            .iter()
            .filter(|child| {
                child.parent_sequence == dir_sequence
                    && !indexed_records.contains(&child.record_number)
            })
            .collect()
    }

    /// Returns the total number of child entries across all parents.
    pub fn len(&self) -> usize {
        self.map.values().map(Vec::len).sum()
    }

    /// Returns `true` if the map contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_common::iter::FsTryIterator;

    /// Builds a child entry with explicit field values for accessor tests.
    fn child(
        record_number: u64,
        sequence_number: u16,
        parent_sequence: u16,
        is_directory: bool,
    ) -> NtfsChildEntry {
        NtfsChildEntry {
            record_number,
            sequence_number,
            parent_sequence,
            is_directory,
            namespace: NtfsFileNamespace::Win32,
        }
    }

    /// Builds a parent map directly from (`parent_record`, children) pairs,
    /// bypassing the MFT scan in `build`.
    fn map_from(entries: Vec<(u64, Vec<NtfsChildEntry>)>) -> NtfsParentMap {
        NtfsParentMap {
            map: entries.into_iter().collect(),
        }
    }

    #[test]
    fn test_child_entry_accessors() {
        // Distinct, non-0/1 values so return-value replacements are caught.
        let c = child(42, 7, 3, true);
        assert_eq!(c.record_number(), 42);
        assert_eq!(c.sequence_number(), 7);
        assert_eq!(c.parent_sequence(), 3);
        assert!(c.is_directory());
        assert_eq!(c.namespace(), NtfsFileNamespace::Win32);

        let f = child(99, 2, 5, false);
        assert_eq!(f.record_number(), 99);
        assert_eq!(f.sequence_number(), 2);
        assert_eq!(f.parent_sequence(), 5);
        assert!(!f.is_directory());
    }

    #[test]
    fn test_children_present_and_absent() {
        // Parent 5 has two children; parent 9 has one; parent 100 has none.
        let pmap = map_from(vec![
            (5, vec![child(10, 1, 1, false), child(11, 1, 1, true)]),
            (9, vec![child(20, 1, 1, false)]),
        ]);

        let kids = pmap.children(5);
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].record_number(), 10);
        assert_eq!(kids[1].record_number(), 11);

        assert_eq!(pmap.children(9).len(), 1);
        // An absent parent returns an empty slice (not a leaked vec).
        assert!(pmap.children(100).is_empty());
    }

    #[test]
    fn test_len_and_is_empty() {
        // Empty map.
        let empty = map_from(vec![]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        // 2 + 1 = 3 children total across two parents — distinct from 0/1.
        let pmap = map_from(vec![
            (5, vec![child(10, 1, 1, false), child(11, 1, 1, true)]),
            (9, vec![child(20, 1, 1, false)]),
        ]);
        assert!(!pmap.is_empty());
        assert_eq!(pmap.len(), 3);
    }

    #[test]
    fn test_build_scans_in_use_filename_records() {
        use crate::attribute::NtfsAttributeType;
        use crate::file::synthetic;

        // Record 1: in-use, FILE_NAME naming parent record 5, Win32.
        let fname1 = synthetic::file_name_value(5, 1, 1, false, "child1");
        let r1 = synthetic::file_record(
            0x0001, // IN_USE
            1,
            1,
            &[synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 0,
                name: "",
                value: fname1,
            }],
        );
        // Record 2: NOT in-use (flags 0); its FILE_NAME must be ignored.
        let fname2 = synthetic::file_name_value(5, 1, 1, false, "ghost");
        let r2 = synthetic::file_record(
            0x0000, // not in use
            1,
            1,
            &[synthetic::ResidentAttr {
                ty: NtfsAttributeType::FileName,
                instance: 0,
                name: "",
                value: fname2,
            }],
        );

        let image = synthetic::mft_image(&[r1, r2]);
        let mut cursor = std::io::Cursor::new(image);
        let ntfs = Ntfs::new(&mut cursor).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut cursor).unwrap();

        // Record 1 (in-use) is recorded under parent 5; record 2 (free) is not.
        let children = pmap.children(5);
        assert_eq!(
            children.len(),
            1,
            "only the in-use record should be recorded"
        );
        assert_eq!(children[0].record_number(), 1);
        assert_eq!(children[0].parent_sequence(), 1);
        assert!(!pmap.is_empty());
    }

    #[test]
    fn test_orphans_for_filters_sequence_and_indexed() {
        // Parent dir record 5, sequence 4. Three children claim it:
        //  - rec 10: matching parent_sequence, NOT indexed -> orphan
        //  - rec 11: matching parent_sequence, indexed     -> not orphan
        //  - rec 12: WRONG parent_sequence (5), NOT indexed -> not orphan
        let pmap = map_from(vec![(
            5,
            vec![
                child(10, 1, 4, false),
                child(11, 1, 4, false),
                child(12, 1, 5, false),
            ],
        )]);

        let mut indexed: BTreeSet<u64> = BTreeSet::new();
        indexed.insert(11);

        let orphans = pmap.orphans_for(5, 4, &indexed);
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].record_number(), 10);

        // A different sequence (3) matches none of the children.
        assert!(pmap.orphans_for(5, 3, &indexed).is_empty());

        // If rec 10 is also indexed, no orphans remain (distinguishes `&&`
        // from `||` and the `==`/`!=` and `!` mutations on the filter).
        let mut all_indexed = indexed.clone();
        all_indexed.insert(10);
        assert!(pmap.orphans_for(5, 4, &all_indexed).is_empty());
    }

    #[test]
    fn test_parent_map_build() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();
        assert!(!pmap.is_empty());

        // Root directory (record 5) should have children.
        let root_children = pmap.children(5);
        assert!(!root_children.is_empty());
    }

    #[test]
    fn test_parent_map_children() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();
        let root_children = pmap.children(5);

        // Root should have multiple children (system files + user dirs).
        assert!(root_children.len() > 1);

        // All children should claim record 5 as parent (verified by the map structure).
        // Verify we can find at least one directory child.
        let has_dir = root_children
            .iter()
            .any(super::NtfsChildEntry::is_directory);
        assert!(
            has_dir,
            "root directory should have at least one subdirectory child"
        );
    }

    #[test]
    fn test_parent_map_orphans_for() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();

        // Enumerate the root directory index to collect indexed record numbers.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_seq = root_dir.sequence_number();
        let index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut iter = index.entries();

        let mut indexed: BTreeSet<u64> = BTreeSet::new();
        while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
            let fname = entry.key().unwrap().unwrap();
            indexed.insert(fname.parent_directory_reference().file_record_number());
            // The indexed record is the entry's file reference, not the parent.
            let file_ref = entry.file_reference();
            indexed.insert(file_ref.file_record_number());
        }

        let orphans = pmap.orphans_for(5, root_seq, &indexed);
        // On a well-formed test filesystem, no indexed entries should appear as orphans.
        for orphan in &orphans {
            assert!(
                !indexed.contains(&orphan.record_number()),
                "record {} is indexed but reported as orphan",
                orphan.record_number()
            );
        }
    }

    #[test]
    fn test_parent_map_len() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();
        assert!(!pmap.is_empty());
        assert!(!pmap.is_empty());

        // len() should equal the sum of all children vectors.
        let manual_count: usize = pmap.map.values().map(Vec::len).sum();
        assert_eq!(pmap.len(), manual_count);
    }

    #[test]
    fn test_parent_map_empty_parent() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pmap = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();

        // A nonexistent parent record should return an empty slice.
        let children = pmap.children(0xFFFF_FFFF);
        assert!(children.is_empty());
    }

    #[test]
    fn test_convenience_method() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let pmap = ntfs.build_parent_map(&mut testfs1).unwrap();
        assert!(!pmap.is_empty());

        // Should produce the same data as direct build.
        let pmap2 = NtfsParentMap::build(&ntfs, &mut testfs1).unwrap();
        assert_eq!(pmap.len(), pmap2.len());
    }
}
