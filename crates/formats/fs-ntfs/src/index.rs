use core::cmp::Ordering;
use core::marker::PhantomData;

use alloc::vec;
use alloc::vec::Vec;

use fs_common::iter::{FsTryIterator, FsTryIteratorType};

use crate::attribute::{NtfsAttributeItem, NtfsAttributeType};
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::index_entry::{
    IndexEntryRange, IndexNodeEntryRanges, NtfsDirEntry, NtfsIndexEntry, NtfsIndexEntryFlags,
};
use crate::index_record::NtfsIndexRecord;
use crate::indexes::{NtfsIndexEntryKey, NtfsIndexEntryType};
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsIndexRoot;
use crate::types::NtfsPosition;

/// Maximum allowed B-tree depth for index traversal.
///
/// Real NTFS B-trees rarely exceed 3-4 levels even for directories with
/// hundreds of thousands of entries. This generous cap prevents stack overflow
/// and unbounded memory growth from crafted recursive B-tree structures.
const MAX_INDEX_DEPTH: usize = 20;

/// Owned data extracted from the `$INDEX_ALLOCATION` attribute at
/// construction time so that `NtfsIndex` does not borrow from
/// `NtfsFile`.
#[derive(Clone, Debug)]
struct IndexAllocationInfo {
    data_run_map: DataRunMap,
    data_position: NtfsPosition,
    total_size: u64,
}

/// Helper structure to iterate over all entries of an index or find a specific one.
///
/// The `E` type parameter of [`NtfsIndexEntryType`] specifies the type of the index entries.
/// The most common one is [`NtfsFileNameIndex`] for file name indexes, commonly known as "directories".
/// Check out [`NtfsFile::directory_index`] to return an [`NtfsIndex`] object for a directory without
/// any hassles.
///
/// [`NtfsFile::directory_index`]: crate::NtfsFile::directory_index
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
#[derive(Clone, Debug)]
pub struct NtfsIndex<'n, E>
where
    E: NtfsIndexEntryType,
{
    ntfs: &'n Ntfs,
    index_record_size: u32,
    index_root_entry_ranges: IndexNodeEntryRanges<E>,
    index_root_position: NtfsPosition,
    index_allocation: Option<IndexAllocationInfo>,
    entry_type: PhantomData<E>,
}

impl<'n, E> NtfsIndex<'n, E>
where
    E: NtfsIndexEntryType,
{
    /// Creates a new [`NtfsIndex`] object from a previously looked up [`NtfsIndexRoot`] attribute
    /// (contained in an [`NtfsAttributeItem`]) and, in case of a large index, a matching
    /// `$INDEX_ALLOCATION` attribute (also contained in an [`NtfsAttributeItem`]).
    ///
    /// The allocation attribute's data runs are extracted into an owned
    /// [`DataRunMap`] at construction time so that the index does not
    /// borrow from the [`NtfsFile`].
    ///
    /// If you just want to look up files in a directory, check out [`NtfsFile::directory_index`],
    /// which looks up the correct [`NtfsIndexRoot`] and `$INDEX_ALLOCATION` attributes for you.
    ///
    /// [`DataRunMap`]: crate::data_run_map::DataRunMap
    /// [`NtfsFile`]: crate::NtfsFile
    /// [`NtfsFile::directory_index`]: crate::NtfsFile::directory_index
    pub fn new<R: Read + Seek>(
        ntfs: &'n Ntfs,
        index_root_item: NtfsAttributeItem<'n, '_>,
        index_allocation_item: Option<NtfsAttributeItem<'n, '_>>,
        fs: &mut R,
    ) -> Result<Self> {
        let index_root_attribute = index_root_item.to_attribute()?;
        index_root_attribute.ensure_ty(NtfsAttributeType::IndexRoot)?;
        let index_root = index_root_attribute.resident_structured_value::<NtfsIndexRoot>()?;

        let index_allocation = if let Some(item) = &index_allocation_item {
            let attribute = item.to_attribute()?;
            attribute.ensure_ty(NtfsAttributeType::IndexAllocation)?;

            let value = attribute.value(fs)?;
            let data_position = value.data_position();
            let total_size = value.len();
            let data_run_map = value.data_run_map(fs)?;

            Some(IndexAllocationInfo {
                data_run_map,
                data_position,
                total_size,
            })
        } else if index_root.is_large_index() {
            return Err(NtfsError::MissingIndexAllocation {
                position: index_root.position(),
            });
        } else {
            None
        };

        let index_record_size = index_root.index_record_size();
        let index_root_entry_ranges = index_root.entry_ranges();
        let index_root_position = index_root.position();

        Ok(Self {
            ntfs,
            index_record_size,
            index_root_entry_ranges,
            index_root_position,
            index_allocation,
            entry_type: PhantomData,
        })
    }

    /// Returns an [`NtfsIndexEntries`] iterator to perform an in-order traversal of this index.
    ///
    /// The returned iterator borrows from this index via `'i`.
    /// For an owning variant, see [`into_entries`](Self::into_entries).
    pub fn entries<'i>(&'i self) -> NtfsIndexEntries<'n, 'i, E> {
        NtfsIndexEntries::new(self)
    }

    /// Consumes this index and returns an [`NtfsOwnedIndexEntries`]
    /// iterator that owns the index data.
    ///
    /// Unlike [`entries`](Self::entries) (which borrows the index), this
    /// method moves the index into the iterator, eliminating the `'i`
    /// lifetime.  This is useful when the iterator must outlive the
    /// scope that created the index (e.g. streaming directory traversal).
    pub fn into_entries(self) -> NtfsOwnedIndexEntries<'n, E> {
        NtfsOwnedIndexEntries::new(self)
    }

    /// Returns an [`NtfsDirEntries`] iterator that prepends synthetic `.` and `..`
    /// entries before the real index entries.
    ///
    /// NTFS does not store `.`/`..` on disk; this method synthesizes them from the
    /// provided file references.
    ///
    /// # Arguments
    ///
    /// * `dir_ref` - File reference for this directory (used as the `.` entry).
    /// * `parent_ref` - File reference for the parent directory (used as the `..` entry).
    ///   For the root directory, this should point to itself.
    pub fn entries_with_dots<'i>(
        &'i self,
        dir_ref: NtfsFileReference,
        parent_ref: NtfsFileReference,
    ) -> NtfsDirEntries<'n, 'i, E> {
        NtfsDirEntries::new(self, dir_ref, parent_ref)
    }

    /// Returns an [`NtfsIndexFinder`] structure to efficiently find an entry in this index.
    pub fn finder<'i>(&'i self) -> NtfsIndexFinder<'n, 'i, E> {
        NtfsIndexFinder::new(self)
    }

    /// Reads the subnode index record at the given VCN from the index
    /// allocation, using the owned [`DataRunMap`].
    fn read_subnode<T: Read + Seek>(
        &self,
        fs: &mut T,
        vcn: crate::types::Vcn,
    ) -> Result<NtfsIndexRecord> {
        let alloc = self
            .index_allocation
            .as_ref()
            .ok_or(NtfsError::MissingIndexAllocation {
                position: self.index_root_position,
            })?;

        let vcn_byte_offset = vcn.offset(self.ntfs)?;
        if vcn_byte_offset < 0 || vcn_byte_offset as u64 >= alloc.total_size {
            return Err(NtfsError::VcnOutOfBoundsInIndexAllocation {
                position: alloc.data_position,
                vcn,
            });
        }

        let mut buf = vec![0u8; self.index_record_size as usize];
        let position = alloc
            .data_run_map
            .read_at(fs, vcn_byte_offset as u64, &mut buf)?;

        let record = NtfsIndexRecord::from_raw_data(buf, position)?;

        if record.vcn() != vcn {
            return Err(NtfsError::VcnMismatchInIndexAllocation {
                position: alloc.data_position,
                expected: vcn,
                actual: record.vcn(),
            });
        }

        Ok(record)
    }
}

/// Shared B-tree in-order walk used by both [`NtfsIndexEntries`] (borrowing)
/// and [`NtfsOwnedIndexEntries`] (owning).
///
/// Returns the next entry from the in-order traversal.  The returned
/// [`NtfsIndexEntry`] borrows from data owned by `inner_iterators`.
fn btree_walk_next<'a, 'n, E, T>(
    index: &NtfsIndex<'n, E>,
    inner_iterators: &'a mut Vec<IndexNodeEntryRanges<E>>,
    following_entries: &mut Vec<Option<IndexEntryRange<E>>>,
    fs: &mut T,
) -> Option<Result<NtfsIndexEntry<'a, E>>>
where
    E: NtfsIndexEntryType,
    T: Read + Seek,
{
    // NTFS B-tree indexes are composed out of nodes, with multiple entries per node.
    // Each entry may have a reference to a subnode.
    // If that is the case, the subnode entries comes before the parent entry lexicographically.
    //
    // An example for an unbalanced, but otherwise valid and sorted tree:
    //
    //                                   -------------
    // INDEX ROOT NODE:                  | 4 | 5 | 6 |
    //                                   -------------
    //                                     |
    //                                 ---------
    // INDEX ALLOCATION SUBNODE:       | 1 | 3 |
    //                                 ---------
    //                                       |
    //                                     -----
    // INDEX ALLOCATION SUBNODE:           | 2 |
    //                                     -----
    //
    let entry_range = loop {
        // Get the iterator from the current node level, if any.
        let iter = inner_iterators.last_mut()?;

        // Get the next `IndexEntryRange` from it.
        if let Some(entry_range) = iter.next() {
            let entry_range = iter_try!(entry_range);

            // Convert that `IndexEntryRange` to a (lifetime-bound) `NtfsIndexEntry`.
            let entry = iter_try!(entry_range.to_entry(iter.data()));
            let is_last_entry = entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY);
            // Entries with key_length == 0 on non-last positions are
            // corruption; skip them so lending iterators that borrow
            // from the yielded entry don't need a sentinel-skip loop
            // (which would conflict with the borrow checker).
            let has_key = entry.key_length() > 0;

            // Does this entry have a subnode that needs to be iterated first?
            if let Some(subnode_vcn) = entry.subnode_vcn() {
                let subnode_vcn = iter_try!(subnode_vcn);

                let subnode = iter_try!(index.read_subnode(fs, subnode_vcn));
                let subnode_iter = subnode.into_entry_ranges();

                let following_entry = if !is_last_entry && has_key {
                    // This entry comes after the subnode lexicographically, so save it.
                    // We'll pick it up again after the subnode iterator has been fully iterated.
                    Some(entry_range)
                } else {
                    None
                };

                // Save this subnode's iterator and any following entry.
                // We'll pick up the iterator through `inner_iterators.last_mut()` in the next loop iteration.
                if inner_iterators.len() >= MAX_INDEX_DEPTH {
                    return Some(Err(NtfsError::IndexBTreeTooDeep {
                        position: index.index_root_position,
                        max_depth: MAX_INDEX_DEPTH,
                    }));
                }
                inner_iterators.push(subnode_iter);
                following_entries.push(following_entry);
            } else if !is_last_entry && has_key {
                // There is no subnode, this is not the empty "last entry",
                // and the entry has a valid key — yield it.
                break entry_range;
            }
        } else {
            // The iterator for this subnode level has been fully iterated.
            // Drop it.
            inner_iterators.pop();

            // The entry, whose subnode we just fully iterated, may have been saved in `following_entries`.
            // This depends on its `is_last_entry` flag:
            //   * If it was not the last entry, it contains an entry that comes next lexicographically,
            //     and has therefore been saved in `following_entries`.
            //   * If it was the last entry, it contains no further information.
            //     `None` has been saved in `following_entries`, so that `following_entries.len()` always
            //     matches `inner_iterators.len() - 1`.
            //
            // If we just finished iterating the root-level node, `following_entries` is empty and we are done.
            // Otherwise, we can be sure that `inner_iterators.last()` is the matching iterator for converting
            // `IndexEntryRange` to a (lifetime-bound) `NtfsIndexEntry`.
            if let Some(entry_range) = following_entries.pop()? {
                break entry_range;
            }
        }
    };

    let iter = inner_iterators.last().unwrap();
    let entry = iter_try!(entry_range.to_entry(iter.data()));

    Some(Ok(entry))
}

/// Iterator over
///   all index entries of an index,
///   sorted ascending by the index key,
///   returning an [`NtfsIndexEntry`] for each entry.
///
/// This iterator is returned from the [`NtfsIndex::entries`] function.
/// It borrows from the [`NtfsIndex`] via `'i`.  For an owning variant
/// that moves the index into the iterator, see [`NtfsOwnedIndexEntries`].
#[derive(Clone, Debug)]
pub struct NtfsIndexEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    index: &'i NtfsIndex<'n, E>,
    inner_iterators: Vec<IndexNodeEntryRanges<E>>,
    following_entries: Vec<Option<IndexEntryRange<E>>>,
}

impl<'n, 'i, E> NtfsIndexEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    fn new(index: &'i NtfsIndex<'n, E>) -> Self {
        let inner_iterators = vec![index.index_root_entry_ranges.clone()];
        let following_entries = Vec::new();

        Self {
            index,
            inner_iterators,
            following_entries,
        }
    }

    /// See [`Iterator::next`].
    pub fn next<'a, T>(&'a mut self, fs: &mut T) -> Option<Result<NtfsIndexEntry<'a, E>>>
    where
        T: Read + Seek,
    {
        btree_walk_next(
            self.index,
            &mut self.inner_iterators,
            &mut self.following_entries,
            fs,
        )
    }
}

/// Owning iterator over all index entries of an index, sorted ascending
/// by the index key.
///
/// Unlike [`NtfsIndexEntries`] (which borrows the [`NtfsIndex`] via `'i`),
/// this iterator *moves* the index into itself, eliminating the `'i`
/// lifetime.  This makes it possible to store the iterator alongside the
/// data it reads from — a pattern that is required by the traverse module
/// to stream directory entries without pre-collection.
///
/// Created by [`NtfsIndex::into_entries`].
#[derive(Clone, Debug)]
pub struct NtfsOwnedIndexEntries<'n, E>
where
    E: NtfsIndexEntryType,
{
    index: NtfsIndex<'n, E>,
    inner_iterators: Vec<IndexNodeEntryRanges<E>>,
    following_entries: Vec<Option<IndexEntryRange<E>>>,
}

impl<'n, E> NtfsOwnedIndexEntries<'n, E>
where
    E: NtfsIndexEntryType,
{
    fn new(index: NtfsIndex<'n, E>) -> Self {
        let inner_iterators = vec![index.index_root_entry_ranges.clone()];
        let following_entries = Vec::new();

        Self {
            index,
            inner_iterators,
            following_entries,
        }
    }

    /// See [`Iterator::next`].
    pub fn next<'a, T>(&'a mut self, fs: &mut T) -> Option<Result<NtfsIndexEntry<'a, E>>>
    where
        T: Read + Seek,
    {
        btree_walk_next(
            &self.index,
            &mut self.inner_iterators,
            &mut self.following_entries,
            fs,
        )
    }
}

/// Internal state for [`NtfsDirEntries`].
#[derive(Clone, Debug)]
enum DotState {
    Dot,
    DotDot,
    Entries,
}

/// Iterator over directory entries that prepends synthetic `.` and `..` entries
/// before the real index entries.
///
/// Created by [`NtfsIndex::entries_with_dots`].
#[derive(Clone, Debug)]
pub struct NtfsDirEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    state: DotState,
    dir_ref: NtfsFileReference,
    parent_ref: NtfsFileReference,
    inner: NtfsIndexEntries<'n, 'i, E>,
}

impl<'n, 'i, E> NtfsDirEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    fn new(
        index: &'i NtfsIndex<'n, E>,
        dir_ref: NtfsFileReference,
        parent_ref: NtfsFileReference,
    ) -> Self {
        Self {
            state: DotState::Dot,
            dir_ref,
            parent_ref,
            inner: NtfsIndexEntries::new(index),
        }
    }

    /// See [`Iterator::next`].
    pub fn next<'a, T>(&'a mut self, fs: &mut T) -> Option<Result<NtfsDirEntry<'a, E>>>
    where
        T: Read + Seek,
    {
        match self.state {
            DotState::Dot => {
                self.state = DotState::DotDot;
                Some(Ok(NtfsDirEntry::CurrentDirectory(self.dir_ref)))
            }
            DotState::DotDot => {
                self.state = DotState::Entries;
                Some(Ok(NtfsDirEntry::ParentDirectory(self.parent_ref)))
            }
            DotState::Entries => match self.inner.try_next(fs) {
                Ok(Some(entry)) => Some(Ok(NtfsDirEntry::IndexEntry(entry))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            },
        }
    }
}

impl<'n, 'i, E> FsTryIteratorType for NtfsIndexEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    type Error = NtfsError;
    type Item<'a> = NtfsIndexEntry<'a, E>;
}

impl<'n, 'i, E, R> FsTryIterator<R> for NtfsIndexEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
    R: Read + Seek,
{
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsIndexEntry<'_, E>>> {
        self.next(r).transpose()
    }
}

impl<'n, E> FsTryIteratorType for NtfsOwnedIndexEntries<'n, E>
where
    E: NtfsIndexEntryType,
{
    type Error = NtfsError;
    type Item<'a> = NtfsIndexEntry<'a, E>;
}

impl<'n, E, R> FsTryIterator<R> for NtfsOwnedIndexEntries<'n, E>
where
    E: NtfsIndexEntryType,
    R: Read + Seek,
{
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsIndexEntry<'_, E>>> {
        self.next(r).transpose()
    }
}

impl<'n, 'i, E> FsTryIteratorType for NtfsDirEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    type Error = NtfsError;
    type Item<'a> = NtfsDirEntry<'a, E>;
}

impl<'n, 'i, E, R> FsTryIterator<R> for NtfsDirEntries<'n, 'i, E>
where
    E: NtfsIndexEntryType,
    R: Read + Seek,
{
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsDirEntry<'_, E>>> {
        self.next(r).transpose()
    }
}

/// Helper structure to efficiently find an entry in an index, created by [`NtfsIndex::finder`].
///
/// This helper is required, because the returned entry borrows from the iterator it was created from.
/// The idea is that you copy the field(s) you need from the returned entry and then drop the entry and the finder.
pub struct NtfsIndexFinder<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    index: &'i NtfsIndex<'n, E>,
    inner_iterator: IndexNodeEntryRanges<E>,
}

impl<'n, 'i, E> NtfsIndexFinder<'n, 'i, E>
where
    E: NtfsIndexEntryType,
{
    fn new(index: &'i NtfsIndex<'n, E>) -> Self {
        // This is superfluous and done again in `find`, but doesn't justify using an `Option` here.
        let inner_iterator = index.index_root_entry_ranges.clone();

        Self {
            index,
            inner_iterator,
        }
    }

    /// Finds an entry in this index using the given comparison function and returns an [`NtfsIndexEntry`]
    /// (if there is one).
    ///
    /// The closure receives a borrowed [`Ref`](NtfsIndexEntryKey::Ref)
    /// view of each key, avoiding per-comparison heap allocation for
    /// variable-length keys like [`NtfsFileName`].
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    pub fn find<'a, T, F>(&'a mut self, fs: &mut T, cmp: F) -> Option<Result<NtfsIndexEntry<'a, E>>>
    where
        T: Read + Seek,
        F: for<'k> Fn(&<E::KeyType as NtfsIndexEntryKey>::Ref<'k>) -> Ordering,
    {
        // Always (re)start by iterating through the Index Root entry ranges.
        self.inner_iterator = self.index.index_root_entry_ranges.clone();
        let mut depth: usize = 0;

        loop {
            // Get the next entry.
            //
            // A textbook B-tree search algorithm would get the middle entry and perform binary search.
            // But we can't do that here, as we are dealing with variable-length entries.
            let entry_range = iter_try!(self.inner_iterator.next()?);
            let entry = iter_try!(entry_range.to_entry(self.inner_iterator.data()));

            // Check if this entry has a key.
            if let Some(key_ref) = entry.key_ref() {
                // The entry has a key, so compare it using the given function.
                let key_ref = iter_try!(key_ref);

                match cmp(&key_ref) {
                    Ordering::Equal => {
                        // We found what we were looking for!
                        // Recreate `entry` from the last `self.inner_iterator` to please the borrow checker.
                        let entry = iter_try!(entry_range.to_entry(self.inner_iterator.data()));
                        return Some(Ok(entry));
                    }
                    Ordering::Less => {
                        // What we are looking for comes BEFORE this entry.
                        // Hence, it must be in a subnode of this entry and we continue below.
                    }
                    Ordering::Greater => {
                        // What we are looking for comes AFTER this entry.
                        // Keep searching on the same subnode level.
                        continue;
                    }
                }
            }

            // Either this entry has no key (= is the last one on this subnode level) or
            // it comes lexicographically AFTER what we're looking for.
            // In both cases, we have to continue iterating in the subnode of this entry (if there is any).
            let subnode_vcn = iter_try!(entry.subnode_vcn()?);

            depth += 1;
            if depth >= MAX_INDEX_DEPTH {
                return Some(Err(NtfsError::IndexBTreeTooDeep {
                    position: self.index.index_root_position,
                    max_depth: MAX_INDEX_DEPTH,
                }));
            }

            let subnode = iter_try!(self.index.read_subnode(fs, subnode_vcn));
            self.inner_iterator = subnode.into_entry_ranges();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use fs_common::iter::FsTryIterator;

    #[test]
    fn test_index_find() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "many_subdirs" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
                .unwrap()
                .unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Prove that we can find all 512 indexed subdirectories.
        let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
        let mut subdir_finder = subdir_index.finder();

        for i in 1..=512 {
            let dir_name = format!("{i}");
            let entry = NtfsFileNameIndex::find(&mut subdir_finder, &ntfs, &mut testfs1, &dir_name)
                .unwrap()
                .unwrap();
            let entry_name = entry.key().unwrap().unwrap();
            assert_eq!(entry_name.name(), dir_name.as_str());
        }
    }

    #[test]
    fn test_index_iter() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "many_subdirs" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
                .unwrap()
                .unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Prove that we can iterate through all 512 indexed subdirectories in order.
        // Keep in mind that subdirectories are ordered like "1", "10", "100", "101", ...
        // We can create the same order by adding them to a vector and sorting that vector.
        let mut dir_names = Vec::with_capacity(512);
        for i in 1..=512 {
            dir_names.push(format!("{i}"));
        }

        dir_names.sort_unstable();

        let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
        let mut subdir_iter = subdir_index.entries();

        for dir_name in dir_names {
            let entry = subdir_iter.try_next(&mut testfs1).unwrap().unwrap();
            let entry_name = entry.key().unwrap().unwrap();
            assert_eq!(entry_name.name(), dir_name.as_str());
        }

        assert!(subdir_iter.try_next(&mut testfs1).unwrap().is_none());
    }

    #[test]
    fn test_unicode_filename() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "edge-cases" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
                .unwrap()
                .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Find the unicode filename.
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "unicode-名前-имя-🎉.txt",
        )
        .unwrap()
        .unwrap();
        let entry_name = entry.key().unwrap().unwrap();
        assert_eq!(entry_name.name(), "unicode-名前-имя-🎉.txt");
    }

    #[test]
    fn test_long_filename() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "edge-cases" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
                .unwrap()
                .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Find the long filename (200 'a' characters + .txt).
        let long_name = "a".repeat(200) + ".txt";
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut edge_cases_finder, &ntfs, &mut testfs1, &long_name)
                .unwrap()
                .unwrap();
        let entry_name = entry.key().unwrap().unwrap();
        // Verify the name matches (200 'a's + ".txt")
        assert_eq!(entry_name.name(), long_name.as_str());
    }

    #[test]
    fn test_empty_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "edge-cases" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
                .unwrap()
                .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Find the empty directory.
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "empty-directory",
        )
        .unwrap()
        .unwrap();
        let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Verify it's a directory and is empty.
        assert!(empty_dir.is_directory());
        let empty_dir_index = empty_dir.directory_index(&mut testfs1).unwrap();
        let mut empty_dir_iter = empty_dir_index.entries();
        assert!(empty_dir_iter.try_next(&mut testfs1).unwrap().is_none());
    }

    #[test]
    fn test_deep_nesting() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Navigate through edge-cases/level1/level2/.../level10/deep-file.txt
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
        let mut current_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Navigate through 10 levels of nesting.
        for level in 1..=10 {
            let dir_name = format!("level{}", level);
            let dir_index = current_dir.directory_index(&mut testfs1).unwrap();
            let mut dir_finder = dir_index.finder();
            let entry = NtfsFileNameIndex::find(&mut dir_finder, &ntfs, &mut testfs1, &dir_name)
                .unwrap()
                .unwrap();
            current_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();
        }

        // Find the deep file at level 10.
        let dir_index = current_dir.directory_index(&mut testfs1).unwrap();
        let mut dir_finder = dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut dir_finder, &ntfs, &mut testfs1, "deep-file.txt")
            .unwrap()
            .unwrap();
        let entry_name = entry.key().unwrap().unwrap();
        assert_eq!(entry_name.name(), "deep-file.txt");
    }

    #[test]
    fn test_entries_with_dots_root_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        let dir_ref = NtfsFileReference::from_parts(
            root_dir.file_record_number(),
            root_dir.sequence_number(),
        );
        // Root directory's parent is itself.
        let parent_ref = root_dir.parent_reference(&mut testfs1).unwrap();

        let index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut iter = index.entries_with_dots(dir_ref, parent_ref);

        // First entry should be "." pointing to the root directory.
        let entry = iter.try_next(&mut testfs1).unwrap().unwrap();
        match entry {
            NtfsDirEntry::CurrentDirectory(r) => {
                assert_eq!(
                    r.file_record_number(),
                    KnownNtfsFileRecordNumber::RootDirectory as u64
                );
            }
            _ => panic!("expected CurrentDirectory"),
        }

        // Second entry should be ".." also pointing to root (for root dir).
        let entry = iter.try_next(&mut testfs1).unwrap().unwrap();
        match entry {
            NtfsDirEntry::ParentDirectory(r) => {
                assert_eq!(
                    r.file_record_number(),
                    KnownNtfsFileRecordNumber::RootDirectory as u64
                );
            }
            _ => panic!("expected ParentDirectory"),
        }

        // Remaining entries should be real index entries.
        let mut real_count = 0;
        while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
            assert!(matches!(entry, NtfsDirEntry::IndexEntry(_)));
            real_count += 1;
        }
        assert!(real_count > 0, "root directory should have children");
    }

    #[test]
    fn test_entries_with_dots_subdirectory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "edge-cases" subdirectory.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
        let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let dir_ref =
            NtfsFileReference::from_parts(subdir.file_record_number(), subdir.sequence_number());
        let parent_ref = subdir.parent_reference(&mut testfs1).unwrap();

        let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
        let mut iter = subdir_index.entries_with_dots(dir_ref, parent_ref);

        // "." should point to the subdirectory itself.
        let dot = iter.try_next(&mut testfs1).unwrap().unwrap();
        assert_eq!(
            dot.file_reference().file_record_number(),
            subdir.file_record_number()
        );

        // ".." should point to root (MFT 5).
        let dotdot = iter.try_next(&mut testfs1).unwrap().unwrap();
        assert_eq!(
            dotdot.file_reference().file_record_number(),
            KnownNtfsFileRecordNumber::RootDirectory as u64
        );

        // Count real entries match entries() count.
        let mut dots_real_count = 0;
        while let Some(_entry) = iter.try_next(&mut testfs1).unwrap() {
            dots_real_count += 1;
        }

        let mut plain_iter = subdir_index.entries();
        let mut plain_count = 0;
        while let Some(_entry) = plain_iter.try_next(&mut testfs1).unwrap() {
            plain_count += 1;
        }

        assert_eq!(dots_real_count, plain_count);
    }

    #[test]
    fn test_entries_with_dots_empty_directory() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to edge-cases/empty-directory.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
            .unwrap()
            .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "empty-directory")
            .unwrap()
            .unwrap();
        let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let dir_ref = NtfsFileReference::from_parts(
            empty_dir.file_record_number(),
            empty_dir.sequence_number(),
        );
        let parent_ref = empty_dir.parent_reference(&mut testfs1).unwrap();

        let empty_index = empty_dir.directory_index(&mut testfs1).unwrap();
        let mut iter = empty_index.entries_with_dots(dir_ref, parent_ref);

        // Should still get "." and ".." even for an empty directory.
        let dot = iter.try_next(&mut testfs1).unwrap().unwrap();
        assert!(matches!(dot, NtfsDirEntry::CurrentDirectory(_)));

        let dotdot = iter.try_next(&mut testfs1).unwrap().unwrap();
        assert!(matches!(dotdot, NtfsDirEntry::ParentDirectory(_)));

        // No more entries.
        assert!(iter.try_next(&mut testfs1).unwrap().is_none());
    }
}
