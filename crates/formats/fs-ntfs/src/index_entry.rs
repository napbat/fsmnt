use core::iter::FusedIterator;
use core::marker::PhantomData;
use core::ops::Range;
use core::{fmt, mem};

use alloc::vec::Vec;
use bitflags::bitflags;
use memoffset::offset_of;

use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::file_reference::NtfsFileReference;
use crate::indexes::{
    NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryHasFileReference, NtfsIndexEntryKey,
    NtfsIndexEntryType,
};
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;
use crate::types::Vcn;

/// Size of all [`IndexEntryHeader`] fields plus some reserved bytes.
const INDEX_ENTRY_HEADER_SIZE: usize = 16;

#[repr(C, packed)]
struct IndexEntryHeader {
    // The following three fields are used for the u64 file reference if the entry type
    // has no data, but a file reference instead.
    // This is indicated by the entry type implementing `NtfsIndexEntryHasFileReference`.
    // Currently, only `NtfsFileNameIndex` has such a file reference.
    data_offset: u16,
    data_length: u16,
    padding: u32,

    index_entry_length: u16,
    key_length: u16,
    flags: u8,
}

bitflags! {
    /// Flags returned by [`NtfsIndexEntry::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsIndexEntryFlags: u8 {
        /// This Index Entry points to a sub-node.
        const HAS_SUBNODE = 0x01;
        /// This is the last Index Entry in the list.
        const LAST_ENTRY = 0x02;
    }
}

impl fmt::Display for NtfsIndexEntryFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsIndexEntryFlags {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u8 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexEntryRange<E>
where
    E: NtfsIndexEntryType,
{
    range: Range<usize>,
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<E> IndexEntryRange<E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(range: Range<usize>, position: NtfsPosition) -> Self {
        let entry_type = PhantomData;
        Self {
            range,
            position,
            entry_type,
        }
    }

    pub(crate) fn to_entry<'s>(&self, slice: &'s [u8]) -> Result<NtfsIndexEntry<'s, E>> {
        NtfsIndexEntry::new(&slice[self.range.clone()], self.position)
    }
}

/// A single entry of an NTFS index.
///
/// NTFS uses B-tree indexes to quickly look up files, Object IDs, Reparse Points, Security Descriptors, etc.
/// They are described via [`NtfsIndexRoot`] and [`NtfsIndexAllocation`] attributes, which can be comfortably
/// accessed via [`NtfsIndex`].
///
/// The `E` type parameter of [`NtfsIndexEntryType`] specifies the type of the Index Entry.
/// The most common one is [`NtfsFileNameIndex`] for file name indexes, commonly known as "directories".
/// Check out [`NtfsFile::directory_index`] to return an [`NtfsIndex`] object for a directory without
/// any hassles.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_entry.html>
///
/// [`NtfsFileNameIndex`]: crate::indexes::NtfsFileNameIndex
/// [`NtfsIndex`]: crate::NtfsIndex
/// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
#[derive(Clone, Debug)]
pub struct NtfsIndexEntry<'s, E>
where
    E: NtfsIndexEntryType,
{
    slice: &'s [u8],
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<'s, E> NtfsIndexEntry<'s, E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(slice: &'s [u8], position: NtfsPosition) -> Result<Self> {
        let entry_type = PhantomData;

        let mut entry = Self {
            slice,
            position,
            entry_type,
        };
        entry.validate_size()?;
        entry.slice = &entry.slice[..entry.index_entry_length() as usize];

        Ok(entry)
    }

    /// Returns the data of this Index Entry, if any and if supported by this Index Entry type.
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::file_reference`].
    /// An Index Entry can either have data or a file reference.
    pub fn data(&self) -> Option<Result<E::DataType>>
    where
        E: NtfsIndexEntryHasData,
    {
        if self.data_offset() == 0 || self.data_length() == 0 {
            return None;
        }

        let start = self.data_offset() as usize;
        let end = start + self.data_length() as usize;
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let data = iter_try!(E::DataType::data_from_slice(slice, position));
        Some(Ok(data))
    }

    fn data_offset(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_offset);
        u16::from_le_bytes(*self.slice[start..].first_chunk().unwrap())
    }

    /// Returns the length of the data of this Index Entry (if supported by this Index Entry type).
    pub fn data_length(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_length);
        u16::from_le_bytes(*self.slice[start..].first_chunk().unwrap())
    }

    /// Returns an [`NtfsFileReference`] for the file referenced by this Index Entry
    /// (if supported by this Index Entry type).
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::data`].
    /// An Index Entry can either have data or a file reference.
    pub fn file_reference(&self) -> NtfsFileReference
    where
        E: NtfsIndexEntryHasFileReference,
    {
        // The "file_reference_data" is at the same position as the `data_offset`, `data_length`, and `padding` fields.
        // There can either be extra data or a file reference!
        NtfsFileReference::new(self.slice[..mem::size_of::<u64>()].try_into().unwrap())
    }

    /// Returns flags set for this attribute as specified by [`NtfsIndexEntryFlags`].
    pub fn flags(&self) -> NtfsIndexEntryFlags {
        let flags = self.slice[offset_of!(IndexEntryHeader, flags)];
        NtfsIndexEntryFlags::from_bits_truncate(flags)
    }

    /// Returns the total length of this Index Entry, in bytes.
    ///
    /// The next Index Entry is exactly at [`NtfsIndexEntry::position`] + [`NtfsIndexEntry::index_entry_length`]
    /// on the filesystem, unless this is the last entry ([`NtfsIndexEntry::flags`] contains
    /// [`NtfsIndexEntryFlags::LAST_ENTRY`]).
    pub fn index_entry_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, index_entry_length);
        u16::from_le_bytes(*self.slice[start..].first_chunk().unwrap())
    }

    /// Returns the raw key bytes of this Index Entry, or `None` if
    /// this is the last entry (which has no key).
    ///
    /// This is a lower-level alternative to [`key`](Self::key) that
    /// returns the unparsed key slice instead of constructing a typed
    /// key object. Useful when only a subset of key fields is needed
    /// (e.g. extracting name bytes from a FILE_NAME key without
    /// creating an [`NtfsFileName`]).
    ///
    /// The returned slice borrows from the same buffer as the entry
    /// itself (`'s`), so it can be stored without copying.
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    pub fn key_data(&self) -> Option<Result<&'s [u8]>> {
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }
        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + self.key_length() as usize;
        let slice = self.slice.get(start..end);
        Some(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16,
        }))
    }

    /// Returns the structured value of the key of this Index Entry,
    /// or `None` if this Index Entry has no key.
    ///
    /// The last Index Entry never has a key.
    pub fn key(&self) -> Option<Result<E::KeyType>> {
        // The key/stream is only set when the last entry flag is not set.
        // https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_entry.html
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }

        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + self.key_length() as usize;
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let key = iter_try!(E::KeyType::key_from_slice(slice, position));
        Some(Ok(key))
    }

    /// Returns a borrowed view of the key of this Index Entry,
    /// or `None` if this Index Entry has no key.
    ///
    /// Like [`key`](Self::key) but returns the lightweight
    /// [`Ref`](NtfsIndexEntryKey::Ref) GAT instead of the full
    /// owned key type. Used by the finder to avoid per-comparison
    /// heap allocation for variable-length keys like `NtfsFileName`.
    pub fn key_ref(&self) -> Option<Result<<E::KeyType as NtfsIndexEntryKey>::Ref<'s>>> {
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }

        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + self.key_length() as usize;
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let key = iter_try!(E::KeyType::key_ref_from_slice(slice, position));
        Some(Ok(key))
    }

    /// Returns the length of the key of this Index Entry.
    pub fn key_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, key_length);
        u16::from_le_bytes(*self.slice[start..].first_chunk().unwrap())
    }

    /// Returns the absolute position of this NTFS Index Entry within the filesystem, in bytes.
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    /// Returns the Virtual Cluster Number (VCN) of the subnode of this Index Entry,
    /// or `None` if this Index Entry has no subnode.
    pub fn subnode_vcn(&self) -> Option<Result<Vcn>> {
        if !self.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE) {
            return None;
        }

        // Get the subnode VCN from the very end of the Index Entry, but at least after the header.
        let start = usize::max(
            self.index_entry_length() as usize - mem::size_of::<Vcn>(),
            INDEX_ENTRY_HEADER_SIZE,
        );
        let end = start + mem::size_of::<Vcn>();

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len() as u16
        }));

        let vcn = Vcn::from(i64::from_le_bytes(*slice.first_chunk().unwrap()));
        Some(Ok(vcn))
    }

    /// Returns an [`NtfsFile`] for the file referenced by this Index Entry.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        E: NtfsIndexEntryHasFileReference,
        T: Read + Seek,
    {
        self.file_reference().to_file(ntfs, fs)
    }

    fn validate_size(&self) -> Result<()> {
        if self.slice.len() < INDEX_ENTRY_HEADER_SIZE {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: INDEX_ENTRY_HEADER_SIZE as u16,
                actual: self.slice.len() as u16,
            });
        }

        let index_entry_length = self.index_entry_length();

        // The index entry must at least be large enough to contain the full
        // header; otherwise subsequent header field accesses (including
        // another call to `index_entry_length`) would read past the end of
        // the slice and panic. Treat such entries as structurally invalid.
        if index_entry_length < INDEX_ENTRY_HEADER_SIZE as u16 {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: INDEX_ENTRY_HEADER_SIZE as u16,
                actual: index_entry_length,
            });
        }

        if index_entry_length as usize > self.slice.len() {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: index_entry_length,
                actual: self.slice.len() as u16,
            });
        }

        Ok(())
    }
}

/// A directory entry: either a synthetic `.`/`..` or a real index entry.
///
/// NTFS does not store `.` or `..` entries on disk; they are synthesized by the
/// OS driver. This enum wraps both synthetic and real entries for a unified
/// directory iteration API.
///
/// Created by [`NtfsDirEntries`], which is returned from
/// [`NtfsIndex::entries_with_dots`].
///
/// [`NtfsDirEntries`]: crate::NtfsDirEntries
/// [`NtfsIndex::entries_with_dots`]: crate::NtfsIndex::entries_with_dots
#[derive(Clone, Debug)]
pub enum NtfsDirEntry<'s, E: NtfsIndexEntryType> {
    /// The `.` entry (current directory).
    CurrentDirectory(NtfsFileReference),
    /// The `..` entry (parent directory).
    ParentDirectory(NtfsFileReference),
    /// A real index entry from the B-tree.
    IndexEntry(NtfsIndexEntry<'s, E>),
}

impl<'s, E: NtfsIndexEntryType> NtfsDirEntry<'s, E> {
    /// Returns the file reference for any variant.
    pub fn file_reference(&self) -> NtfsFileReference
    where
        E: NtfsIndexEntryHasFileReference,
    {
        match self {
            Self::CurrentDirectory(r) => *r,
            Self::ParentDirectory(r) => *r,
            Self::IndexEntry(e) => e.file_reference(),
        }
    }

    /// Returns the index entry key, or `None` for `.`/`..` entries.
    ///
    /// The `.` and `..` entries are synthesized (not stored on disk) and have
    /// no associated index key. For real index entries, this delegates to
    /// [`NtfsIndexEntry::key`].
    pub fn key(&self) -> Option<Result<E::KeyType>> {
        match self {
            Self::CurrentDirectory(_) | Self::ParentDirectory(_) => None,
            Self::IndexEntry(e) => e.key(),
        }
    }

    /// Returns a borrowed key view, or `None` for `.`/`..` entries.
    ///
    /// Like [`key`](Self::key) but delegates to
    /// [`NtfsIndexEntry::key_ref`].
    pub fn key_ref(&self) -> Option<Result<<E::KeyType as NtfsIndexEntryKey>::Ref<'s>>> {
        match self {
            Self::CurrentDirectory(_) | Self::ParentDirectory(_) => None,
            Self::IndexEntry(e) => e.key_ref(),
        }
    }

    /// Returns `true` for the `.` (current directory) entry.
    pub fn is_current_directory(&self) -> bool {
        matches!(self, Self::CurrentDirectory(_))
    }

    /// Returns `true` for the `..` (parent directory) entry.
    pub fn is_parent_directory(&self) -> bool {
        matches!(self, Self::ParentDirectory(_))
    }

    /// Returns `true` for a real index entry (not `.` or `..`).
    pub fn is_index_entry(&self) -> bool {
        matches!(self, Self::IndexEntry(_))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    data: Vec<u8>,
    range: Range<usize>,
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<E> IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(data: Vec<u8>, range: Range<usize>, position: NtfsPosition) -> Self {
        debug_assert!(range.end <= data.len());
        let entry_type = PhantomData;

        Self {
            data,
            range,
            position,
            entry_type,
        }
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

impl<E> Iterator for IndexNodeEntryRanges<E>
where
    E: NtfsIndexEntryType,
{
    type Item = Result<IndexEntryRange<E>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.is_empty() {
            return None;
        }

        // Get the current entry.
        let start = self.range.start;
        let position = self.position;
        let entry = iter_try!(NtfsIndexEntry::<E>::new(&self.data[start..], position));
        let end = start + entry.index_entry_length() as usize;

        if entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            // This is the last entry.
            // Ensure that we don't read any other entries by advancing `self.range.start` to the end.
            self.range.start = self.data.len();
        } else {
            // This is not the last entry.
            // Advance our iterator to the next entry.
            self.range.start = end;
            self.position += entry.index_entry_length();
        }

        Some(Ok(IndexEntryRange::new(start..end, position)))
    }
}

impl<E> FusedIterator for IndexNodeEntryRanges<E> where E: NtfsIndexEntryType {}

/// Iterator over
///   all index entries of a single index node,
///   sorted ascending by the index key,
///   returning an [`NtfsIndexEntry`] for each entry.
///
/// An index node can be an [`NtfsIndexRoot`] attribute or an [`NtfsIndexRecord`]
/// (which comes from an [`NtfsIndexAllocation`] attribute).
///
/// As such, this iterator is returned from the [`NtfsIndexRoot::entries`] and
/// [`NtfsIndexRecord::entries`] functions.
///
/// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
/// [`NtfsIndexRecord`]: crate::NtfsIndexRecord
/// [`NtfsIndexRecord::entries`]: crate::NtfsIndexRecord::entries
/// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
/// [`NtfsIndexRoot::entries`]: crate::structured_values::NtfsIndexRoot::entries
#[derive(Clone, Debug)]
pub struct NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    slice: &'s [u8],
    position: NtfsPosition,
    entry_type: PhantomData<E>,
}

impl<'s, E> NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    pub(crate) fn new(slice: &'s [u8], position: NtfsPosition) -> Self {
        let entry_type = PhantomData;
        Self {
            slice,
            position,
            entry_type,
        }
    }
}

impl<'s, E> Iterator for NtfsIndexNodeEntries<'s, E>
where
    E: NtfsIndexEntryType,
{
    type Item = Result<NtfsIndexEntry<'s, E>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }

        // Get the current entry.
        let entry = iter_try!(NtfsIndexEntry::new(self.slice, self.position));

        if entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            // This is the last entry.
            // Ensure that we don't read any other entries by emptying the slice.
            self.slice = &[];
        } else {
            // This is not the last entry.
            // Advance our iterator to the next entry.
            let bytes_to_advance = entry.index_entry_length() as usize;
            self.slice = &self.slice[bytes_to_advance..];
            self.position += bytes_to_advance;
        }

        Some(Ok(entry))
    }
}

impl<'s, E> FusedIterator for NtfsIndexNodeEntries<'s, E> where E: NtfsIndexEntryType {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute::NtfsAttributeType;
    use crate::indexes::NtfsFileNameIndex;
    use crate::indexes::NtfsReparsePointIndex;
    use crate::indexes::NtfsSecurityIdIndex;
    use crate::ntfs::Ntfs;
    use crate::structured_values::NtfsIndexRoot;
    use fs_common::iter::FsTryIterator;

    #[test]
    fn test_index_node_entry_flags() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Access the root directory's $INDEX_ROOT directly to see raw index entries
        // including the LAST_ENTRY sentinel.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let mut attrs = root_dir.attributes_raw();

        // Find $INDEX_ROOT attribute.
        let index_root_attr = loop {
            let attr = attrs.next().unwrap().unwrap();
            if attr.ty().unwrap() == NtfsAttributeType::IndexRoot {
                break attr;
            }
        };

        let index_root = index_root_attr
            .resident_structured_value::<NtfsIndexRoot>()
            .unwrap();

        let entries = index_root.entries::<NtfsFileNameIndex>().unwrap();
        let mut found_last = false;
        let mut entry_count = 0;

        for entry in entries {
            let entry = entry.unwrap();
            let flags = entry.flags();
            entry_count += 1;

            if flags.contains(NtfsIndexEntryFlags::LAST_ENTRY) {
                found_last = true;
                // Last entry should not have a key.
                assert!(entry.key().is_none());
            } else {
                // Non-last entries should have a key.
                assert!(entry.key().is_some());
                // key_length should be nonzero.
                assert!(entry.key_length() > 0);
            }

            // Every entry should have a valid length.
            assert!(entry.index_entry_length() >= 16);
        }

        assert!(found_last, "should have encountered the LAST_ENTRY flag");
        assert!(
            entry_count >= 1,
            "index root should have at least one entry"
        );
    }

    #[test]
    fn test_index_entry_file_reference() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();

        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "file-with-12345")
            .unwrap()
            .unwrap();

        // The file reference should resolve to a valid file.
        let file_ref = entry.file_reference();
        let file = file_ref.to_file(&ntfs, &mut testfs1).unwrap();
        assert!(!file.is_directory());
    }

    #[test]
    fn test_index_entry_position_is_nonzero() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut entries = root_dir_index.entries();

        // Check that entries have nonzero positions.
        if let Some(entry) = entries.try_next(&mut testfs1).unwrap() {
            // The position should point somewhere in the filesystem.
            assert!(entry.position().value().is_some());
        }
    }

    #[test]
    fn test_index_entry_subnode_vcn_in_large_dir() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();

        // Navigate to "many_subdirs" which has a large B-tree index.
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut finder = root_dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
            .unwrap()
            .unwrap();
        let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();
        assert!(many_subdirs.is_directory());

        // Access index root directly to see HAS_SUBNODE entries.
        let mut attrs = many_subdirs.attributes_raw();
        let index_root_attr = loop {
            let attr = attrs.next().unwrap().unwrap();
            if attr.ty().unwrap() == NtfsAttributeType::IndexRoot {
                break attr;
            }
        };
        let index_root = index_root_attr
            .resident_structured_value::<NtfsIndexRoot>()
            .unwrap();

        // A large index should have entries with HAS_SUBNODE.
        assert!(index_root.is_large_index());

        let entries = index_root.entries::<NtfsFileNameIndex>().unwrap();
        let mut found_subnode = false;

        for entry in entries {
            let entry = entry.unwrap();
            if entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE) {
                let vcn = entry.subnode_vcn().unwrap().unwrap();
                assert!(vcn.value() >= 0);
                found_subnode = true;
            }
        }

        assert!(
            found_subnode,
            "expected HAS_SUBNODE entries in many_subdirs"
        );
    }

    /// Builds a synthetic 28-byte `$R` index entry buffer with hardcoded
    /// little-endian bytes, suitable for `NtfsIndexEntry::new()`.
    ///
    /// Layout (INDEX_ENTRY_HEADER_SIZE = 16, key = 12):
    ///   [0..8]   header file reference (for HasFileReference)
    ///   [8..10]  index_entry_length (u16 LE)
    ///   [10..12] key_length (u16 LE)
    ///   [12]     flags (u8)
    ///   [13..16] reserved
    ///   [16..20] reparse_tag (u32 LE)
    ///   [20..28] key file_reference (u64 LE packed)
    fn build_synthetic_r_entry(
        header_file_ref: [u8; 8],
        reparse_tag: [u8; 4],
        key_file_ref: [u8; 8],
        flags: u8,
    ) -> [u8; 28] {
        let mut buf = [0u8; 28];
        buf[0..8].copy_from_slice(&header_file_ref);
        buf[8..10].copy_from_slice(&28u16.to_le_bytes());
        buf[10..12].copy_from_slice(&12u16.to_le_bytes());
        buf[12] = flags;
        buf[16..20].copy_from_slice(&reparse_tag);
        buf[20..28].copy_from_slice(&key_file_ref);
        buf
    }

    #[test]
    fn synthetic_r_entry_key_round_trip() {
        // header file ref: record=100, seq=7
        // tag = 0xA000_001D (IO_REPARSE_TAG_LX_SYMLINK)
        // key file ref: record=5678, seq=2
        let header_ref: [u8; 8] = [0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00];
        let tag: [u8; 4] = [0x1D, 0x00, 0x00, 0xA0];
        let key_ref: [u8; 8] = [0x2E, 0x16, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00];
        let buf = build_synthetic_r_entry(header_ref, tag, key_ref, 0);

        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x1000))
            .expect("should parse synthetic $R entry");

        // Header file reference (from HasFileReference trait)
        let hdr_ref = entry.file_reference();
        assert_eq!(hdr_ref.file_record_number(), 100);
        assert_eq!(hdr_ref.sequence_number(), 7);

        // Key
        let key = entry
            .key()
            .expect("non-last entry should have a key")
            .expect("key parsing should succeed");
        assert_eq!(key.reparse_tag(), 0xA000_001D);
        assert_eq!(key.file_reference().file_record_number(), 5678);
        assert_eq!(key.file_reference().sequence_number(), 2);

        // Structural fields
        assert_eq!(entry.index_entry_length(), 28);
        assert_eq!(entry.key_length(), 12);
        assert!(!entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY));
        assert!(!entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE));
    }

    #[test]
    fn synthetic_r_entry_last_entry_has_no_key() {
        let buf = build_synthetic_r_entry(
            [0; 8],
            [0x0C, 0x00, 0x00, 0xA0],
            [0; 8],
            NtfsIndexEntryFlags::LAST_ENTRY.bits(),
        );

        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
            .expect("should parse last-entry sentinel");

        assert!(entry.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY));
        assert!(entry.key().is_none(), "last entry should not return a key");
    }

    #[test]
    fn synthetic_r_entry_header_and_key_refs_differ() {
        // Verify that the header file reference and key file reference
        // are parsed from independent byte ranges.
        let header_ref: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x00];
        let key_ref: [u8; 8] = [0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00];
        let buf = build_synthetic_r_entry(header_ref, [0x12, 0x00, 0x00, 0x80], key_ref, 0);

        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x2000))
            .expect("should parse entry with differing refs");

        // Header ref: record=1, seq=10
        assert_eq!(entry.file_reference().file_record_number(), 1);
        assert_eq!(entry.file_reference().sequence_number(), 10);

        // Key ref: record=255, seq=20
        let key = entry.key().unwrap().unwrap();
        assert_eq!(key.reparse_tag(), 0x8000_0012);
        assert_eq!(key.file_reference().file_record_number(), 255);
        assert_eq!(key.file_reference().sequence_number(), 20);
    }

    #[test]
    fn synthetic_r_entry_rejects_truncated_buffer() {
        let buf = [0u8; 15]; // Less than INDEX_ENTRY_HEADER_SIZE (16)
        let result = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x500));
        assert!(
            result.is_err(),
            "buffer shorter than header should be rejected"
        );
    }

    /// Builds a synthetic `$SII` index entry (an entry type that *has data*).
    ///
    /// Layout (header 16 + key 4 + data 20 = 40 bytes):
    ///   [0..2]   data_offset  (u16 LE) = 20
    ///   [2..4]   data_length  (u16 LE) = 20
    ///   [4..8]   padding
    ///   [8..10]  index_entry_length (u16 LE) = 40
    ///   [10..12] key_length (u16 LE) = 4
    ///   [12]     flags
    ///   [13..16] reserved
    ///   [16..20] $SII key: security_id (u32 LE)
    ///   [20..40] $SII data: hash, security_id, sds_offset, sds_size
    fn build_sii_entry(security_id: u32, flags: u8) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..2].copy_from_slice(&20u16.to_le_bytes()); // data_offset
        buf[2..4].copy_from_slice(&20u16.to_le_bytes()); // data_length
        buf[8..10].copy_from_slice(&40u16.to_le_bytes()); // index_entry_length
        buf[10..12].copy_from_slice(&4u16.to_le_bytes()); // key_length
        buf[12] = flags;
        buf[16..20].copy_from_slice(&security_id.to_le_bytes()); // key
        // $SII data body (20 bytes): hash, security_id, sds_offset, sds_size.
        buf[20..24].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // hash
        buf[24..28].copy_from_slice(&security_id.to_le_bytes()); // security_id
        buf[28..36].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes()); // sds_offset
        buf[36..40].copy_from_slice(&0x4444u32.to_le_bytes()); // sds_size
        buf
    }

    #[test]
    fn sii_entry_data_offset_and_length() {
        let buf = build_sii_entry(0x1234_5678, 0);
        let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&buf, NtfsPosition::new(0x800))
            .expect("should parse synthetic $SII entry");

        // data_offset and data_length return the genuine header values
        // (distinct from the 0/1 replacements).
        assert_eq!(entry.data_offset(), 20);
        assert_eq!(entry.data_length(), 20);
        assert_eq!(entry.key_length(), 4);
        assert_eq!(entry.index_entry_length(), 40);

        // The key parses to the expected security ID.
        let key = entry.key().unwrap().unwrap();
        assert_eq!(key.security_id(), 0x1234_5678);
    }

    #[test]
    fn sii_entry_data_round_trip() {
        let buf = build_sii_entry(0x00AB_CDEF, 0);
        let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&buf, NtfsPosition::new(0x800))
            .expect("should parse synthetic $SII entry");

        // data() slices [data_offset .. data_offset + data_length] and parses
        // the $SII data body. A wrong offset/length or a None replacement
        // changes the parsed fields.
        let data = entry.data().expect("entry has data").expect("data parses");
        assert_eq!(data.hash(), 0xDEAD_BEEF);
        assert_eq!(data.security_id(), 0x00AB_CDEF);
        assert_eq!(data.sds_offset(), 0x0102_0304_0506_0708);
        assert_eq!(data.sds_size(), 0x4444);
    }

    #[test]
    fn sii_entry_data_none_when_offset_or_length_zero() {
        // data_offset == 0 -> None (anchors the `== 0` / `||` checks at 146).
        let mut zero_offset = build_sii_entry(1, 0);
        zero_offset[0..2].copy_from_slice(&0u16.to_le_bytes());
        let entry = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&zero_offset, NtfsPosition::none())
            .expect("parses with zero data_offset");
        assert!(entry.data().is_none());

        // data_length == 0 -> None.
        let mut zero_length = build_sii_entry(1, 0);
        zero_length[2..4].copy_from_slice(&0u16.to_le_bytes());
        let entry2 = NtfsIndexEntry::<NtfsSecurityIdIndex>::new(&zero_length, NtfsPosition::none())
            .expect("parses with zero data_length");
        assert!(entry2.data().is_none());
    }

    #[test]
    fn r_entry_key_data_round_trip() {
        // key_data() returns the raw key slice [16 .. 16 + key_length].
        let header_ref: [u8; 8] = [0x01, 0, 0, 0, 0, 0, 0, 0];
        let tag: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let key_ref: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let buf = build_synthetic_r_entry(header_ref, tag, key_ref, 0);

        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x1000))
            .expect("should parse synthetic $R entry");

        let key_data = entry
            .key_data()
            .expect("non-last entry has key data")
            .expect("key data slice is in range");
        // 12-byte key: the reparse tag bytes followed by the key file ref.
        assert_eq!(key_data.len(), 12);
        assert_eq!(&key_data[0..4], &tag);
        assert_eq!(&key_data[4..12], &key_ref);

        // key_ref() builds the borrowed key view from the same bytes.
        let kref = entry.key_ref().unwrap().unwrap();
        assert_eq!(kref.reparse_tag(), 0xDDCC_BBAA);
    }

    #[test]
    fn r_entry_key_data_none_for_last_entry() {
        // The LAST_ENTRY flag means no key, so key_data and key_ref are None.
        let buf = build_synthetic_r_entry(
            [0; 8],
            [0x0C, 0x00, 0x00, 0xA0],
            [0; 8],
            NtfsIndexEntryFlags::LAST_ENTRY.bits(),
        );
        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
            .expect("parses last-entry sentinel");
        assert!(entry.key_data().is_none());
        assert!(entry.key_ref().is_none());
    }

    /// Builds an `$R` entry carrying a subnode VCN at its very end.
    ///
    /// HAS_SUBNODE is set and the 8-byte VCN occupies the last 8 bytes of the
    /// entry, i.e. [index_entry_length - 8 .. index_entry_length].
    fn build_r_entry_with_subnode(vcn: i64) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[8..10].copy_from_slice(&36u16.to_le_bytes()); // index_entry_length
        buf[10..12].copy_from_slice(&12u16.to_le_bytes()); // key_length
        buf[12] = NtfsIndexEntryFlags::HAS_SUBNODE.bits();
        // key occupies [16..28]; the subnode VCN sits in the final 8 bytes.
        buf[28..36].copy_from_slice(&vcn.to_le_bytes());
        buf
    }

    #[test]
    fn r_entry_subnode_vcn_round_trip() {
        let buf = build_r_entry_with_subnode(0x0011_2233_4455_6677);
        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::new(0x2000))
            .expect("parses entry with subnode");
        assert!(entry.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE));
        let vcn = entry.subnode_vcn().expect("has subnode").expect("vcn ok");
        assert_eq!(vcn.value(), 0x0011_2233_4455_6677);
    }

    #[test]
    fn r_entry_subnode_vcn_none_without_flag() {
        // Without HAS_SUBNODE, subnode_vcn returns None (anchors `!` at 306).
        let buf = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
            .expect("parses entry without subnode");
        assert!(entry.subnode_vcn().is_none());
    }

    #[test]
    fn validate_size_rejects_tiny_and_oversize() {
        // index_entry_length smaller than the header (anchors `<` at 352).
        let mut too_small = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
        too_small[8..10].copy_from_slice(&8u16.to_le_bytes());
        assert!(
            NtfsIndexEntry::<NtfsReparsePointIndex>::new(&too_small, NtfsPosition::none()).is_err()
        );

        // index_entry_length larger than the slice (anchors `>` at 360).
        let mut too_big = build_synthetic_r_entry([0; 8], [0; 4], [0; 8], 0);
        too_big[8..10].copy_from_slice(&64u16.to_le_bytes());
        assert!(
            NtfsIndexEntry::<NtfsReparsePointIndex>::new(&too_big, NtfsPosition::none()).is_err()
        );

        // Exactly INDEX_ENTRY_HEADER_SIZE (16) for both lengths is valid.
        let mut exact = [0u8; 16];
        exact[8..10].copy_from_slice(&16u16.to_le_bytes());
        assert!(NtfsIndexEntry::<NtfsReparsePointIndex>::new(&exact, NtfsPosition::none()).is_ok());
    }

    #[test]
    fn dir_entry_real_index_delegates_key() {
        // An IndexEntry dir entry delegates key/key_ref and reports
        // is_index_entry; the dot variants report their own predicates.
        let header_ref: [u8; 8] = [0x05, 0, 0, 0, 0, 0, 0, 0];
        let buf = build_synthetic_r_entry(
            header_ref,
            [0x12, 0, 0, 0x80],
            [0x07, 0, 0, 0, 0, 0, 0, 0],
            0,
        );
        let entry = NtfsIndexEntry::<NtfsReparsePointIndex>::new(&buf, NtfsPosition::none())
            .expect("parses entry");

        let dir_entry = NtfsDirEntry::IndexEntry(entry);
        assert!(dir_entry.is_index_entry());
        assert!(!dir_entry.is_current_directory());
        assert!(!dir_entry.is_parent_directory());
        let key = dir_entry.key().expect("real entry has a key").unwrap();
        assert_eq!(key.reparse_tag(), 0x8000_0012);
        assert!(dir_entry.key_ref().is_some());

        let cur: NtfsDirEntry<NtfsReparsePointIndex> =
            NtfsDirEntry::CurrentDirectory(NtfsFileReference::new([0; 8]));
        assert!(cur.is_current_directory());
        assert!(!cur.is_parent_directory());
        assert!(!cur.is_index_entry());
        assert!(cur.key().is_none());
        assert!(cur.key_ref().is_none());

        let parent: NtfsDirEntry<NtfsReparsePointIndex> =
            NtfsDirEntry::ParentDirectory(NtfsFileReference::new([0; 8]));
        assert!(parent.is_parent_directory());
        assert!(!parent.is_current_directory());
    }

    #[test]
    fn index_node_entry_ranges_iterates_two_entries() {
        // Two non-last $R entries followed by a LAST_ENTRY sentinel. The
        // ranges iterator must advance by index_entry_length each time
        // (anchors `+` at 492) and stop at the sentinel.
        let e0 =
            build_synthetic_r_entry([0x01, 0, 0, 0, 0, 0, 0, 0], [0x10, 0, 0, 0xA0], [0; 8], 0);
        let e1 =
            build_synthetic_r_entry([0x02, 0, 0, 0, 0, 0, 0, 0], [0x20, 0, 0, 0xA0], [0; 8], 0);
        let last = build_synthetic_r_entry(
            [0; 8],
            [0; 4],
            [0; 8],
            NtfsIndexEntryFlags::LAST_ENTRY.bits(),
        );
        let mut data = Vec::new();
        data.extend_from_slice(&e0);
        data.extend_from_slice(&e1);
        data.extend_from_slice(&last);
        let total = data.len();

        let ranges = IndexNodeEntryRanges::<NtfsReparsePointIndex>::new(
            data.clone(),
            0..total,
            NtfsPosition::new(0x4000),
        );
        let collected: Vec<_> = ranges.collect::<Result<_>>().unwrap();
        // e0, e1, and the sentinel are all yielded (3 ranges).
        assert_eq!(collected.len(), 3);
        assert_eq!(
            collected[0]
                .clone()
                .to_entry(&data)
                .unwrap()
                .index_entry_length(),
            28
        );
        // The second range starts exactly one entry length in.
        let second = collected[1].clone().to_entry(&data).unwrap();
        assert_eq!(second.file_reference().file_record_number(), 2);
    }

    #[test]
    fn index_node_entries_iterates_until_last() {
        // The slice-based iterator yields each entry and stops at LAST_ENTRY.
        let e0 =
            build_synthetic_r_entry([0x09, 0, 0, 0, 0, 0, 0, 0], [0x10, 0, 0, 0xA0], [0; 8], 0);
        let last = build_synthetic_r_entry(
            [0; 8],
            [0; 4],
            [0; 8],
            NtfsIndexEntryFlags::LAST_ENTRY.bits(),
        );
        let mut data = Vec::new();
        data.extend_from_slice(&e0);
        data.extend_from_slice(&last);

        let entries =
            NtfsIndexNodeEntries::<NtfsReparsePointIndex>::new(&data, NtfsPosition::new(0x6000));
        let collected: Vec<_> = entries.collect::<Result<_>>().unwrap();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0].file_reference().file_record_number(), 9);
        assert!(
            collected[1]
                .flags()
                .contains(NtfsIndexEntryFlags::LAST_ENTRY)
        );
    }

    #[test]
    fn index_entry_flags_display_renders_bits() {
        // The flags Display delegates to the bitflags formatter; a non-empty
        // set must not render as the Default (empty) string.
        let flags = NtfsIndexEntryFlags::HAS_SUBNODE | NtfsIndexEntryFlags::LAST_ENTRY;
        let rendered = format!("{flags}");
        assert_ne!(rendered, "");
        assert!(rendered.contains("HAS_SUBNODE"), "got {rendered:?}");
        assert!(rendered.contains("LAST_ENTRY"), "got {rendered:?}");
    }
}
