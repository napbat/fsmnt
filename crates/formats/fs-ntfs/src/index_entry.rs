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

fn validated_entry_bytes<const N: usize>(data: &[u8], start: usize) -> [u8; N] {
    data.get(start..)
        .and_then(|bytes| bytes.first_chunk())
        .copied()
        .expect("index-entry construction validates every fixed-width field")
}

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
        entry.slice = &entry.slice[..usize::from(entry.index_entry_length())];

        Ok(entry)
    }

    /// Returns the data of this Index Entry, if any and if supported by this Index Entry type.
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::file_reference`].
    /// An Index Entry can either have data or a file reference.
    #[must_use]
    pub fn data(&self) -> Option<Result<E::DataType>>
    where
        E: NtfsIndexEntryHasData,
    {
        if self.data_offset() == 0 || self.data_length() == 0 {
            return None;
        }

        let start = usize::from(self.data_offset());
        let end = start + usize::from(self.data_length());
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len()
        }));

        let data = iter_try!(E::DataType::data_from_slice(slice, position));
        Some(Ok(data))
    }

    fn data_offset(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_offset);
        u16::from_le_bytes(validated_entry_bytes(self.slice, start))
    }

    /// Returns the length of the data of this Index Entry (if supported by this Index Entry type).
    #[must_use]
    pub fn data_length(&self) -> u16
    where
        E: NtfsIndexEntryHasData,
    {
        let start = offset_of!(IndexEntryHeader, data_length);
        u16::from_le_bytes(validated_entry_bytes(self.slice, start))
    }

    /// Returns an [`NtfsFileReference`] for the file referenced by this Index Entry
    /// (if supported by this Index Entry type).
    ///
    /// This function is mutually exclusive with [`NtfsIndexEntry::data`].
    /// An Index Entry can either have data or a file reference.
    #[must_use]
    pub fn file_reference(&self) -> NtfsFileReference
    where
        E: NtfsIndexEntryHasFileReference,
    {
        // The "file_reference_data" is at the same position as the `data_offset`, `data_length`, and `padding` fields.
        // There can either be extra data or a file reference!
        NtfsFileReference::new(validated_entry_bytes(self.slice, 0))
    }

    /// Returns flags set for this attribute as specified by [`NtfsIndexEntryFlags`].
    #[must_use]
    pub fn flags(&self) -> NtfsIndexEntryFlags {
        let flags = validated_entry_bytes::<1>(self.slice, offset_of!(IndexEntryHeader, flags))[0];
        NtfsIndexEntryFlags::from_bits_truncate(flags)
    }

    /// Returns the total length of this Index Entry, in bytes.
    ///
    /// The next Index Entry is exactly at [`NtfsIndexEntry::position`] + [`NtfsIndexEntry::index_entry_length`]
    /// on the filesystem, unless this is the last entry ([`NtfsIndexEntry::flags`] contains
    /// [`NtfsIndexEntryFlags::LAST_ENTRY`]).
    #[must_use]
    pub fn index_entry_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, index_entry_length);
        u16::from_le_bytes(validated_entry_bytes(self.slice, start))
    }

    /// Returns the raw key bytes of this Index Entry, or `None` if
    /// this is the last entry (which has no key).
    ///
    /// This is a lower-level alternative to [`key`](Self::key) that
    /// returns the unparsed key slice instead of constructing a typed
    /// key object. Useful when only a subset of key fields is needed
    /// (e.g. extracting name bytes from a `FILE_NAME` key without
    /// creating an [`NtfsFileName`]).
    ///
    /// The returned slice borrows from the same buffer as the entry
    /// itself (`'s`), so it can be stored without copying.
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    #[must_use]
    pub fn key_data(&self) -> Option<Result<&'s [u8]>> {
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }
        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + usize::from(self.key_length());
        let slice = self.slice.get(start..end);
        Some(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len(),
        }))
    }

    /// Returns the structured value of the key of this Index Entry,
    /// or `None` if this Index Entry has no key.
    ///
    /// The last Index Entry never has a key.
    #[must_use]
    pub fn key(&self) -> Option<Result<E::KeyType>> {
        // The key/stream is only set when the last entry flag is not set.
        // https://flatcap.github.io/linux-ntfs/ntfs/concepts/index_entry.html
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }

        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + usize::from(self.key_length());
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len()
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
    #[must_use]
    pub fn key_ref(&self) -> Option<Result<<E::KeyType as NtfsIndexEntryKey>::Ref<'s>>> {
        if self.key_length() == 0 || self.flags().contains(NtfsIndexEntryFlags::LAST_ENTRY) {
            return None;
        }

        let start = INDEX_ENTRY_HEADER_SIZE;
        let end = start + usize::from(self.key_length());
        let position = self.position + start;

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len()
        }));

        let key = iter_try!(E::KeyType::key_ref_from_slice(slice, position));
        Some(Ok(key))
    }

    /// Returns the length of the key of this Index Entry.
    #[must_use]
    pub fn key_length(&self) -> u16 {
        let start = offset_of!(IndexEntryHeader, key_length);
        u16::from_le_bytes(validated_entry_bytes(self.slice, start))
    }

    /// Returns the absolute position of this NTFS Index Entry within the filesystem, in bytes.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    /// Returns the Virtual Cluster Number (VCN) of the subnode of this Index Entry,
    /// or `None` if this Index Entry has no subnode.
    #[must_use]
    pub fn subnode_vcn(&self) -> Option<Result<Vcn>> {
        if !self.flags().contains(NtfsIndexEntryFlags::HAS_SUBNODE) {
            return None;
        }

        // Get the subnode VCN from the very end of the Index Entry, but at least after the header.
        let start = usize::max(
            usize::from(self.index_entry_length()) - mem::size_of::<Vcn>(),
            INDEX_ENTRY_HEADER_SIZE,
        );
        let end = start + mem::size_of::<Vcn>();

        let slice = self.slice.get(start..end);
        let slice = iter_try!(slice.ok_or(NtfsError::InvalidIndexEntryDataRange {
            position: self.position,
            range: start..end,
            size: self.slice.len()
        }));

        let vcn = Vcn::from(i64::from_le_bytes(validated_entry_bytes(slice, 0)));
        Some(Ok(vcn))
    }

    /// Returns an [`NtfsFile`] for the file referenced by this Index Entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the index metadata is malformed or its allocation data cannot be read.
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
                expected: INDEX_ENTRY_HEADER_SIZE,
                actual: self.slice.len(),
            });
        }

        let index_entry_length = self.index_entry_length();

        // The index entry must at least be large enough to contain the full
        // header; otherwise subsequent header field accesses (including
        // another call to `index_entry_length`) would read past the end of
        // the slice and panic. Treat such entries as structurally invalid.
        if usize::from(index_entry_length) < INDEX_ENTRY_HEADER_SIZE {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: INDEX_ENTRY_HEADER_SIZE,
                actual: usize::from(index_entry_length),
            });
        }

        if usize::from(index_entry_length) > self.slice.len() {
            return Err(NtfsError::InvalidIndexEntrySize {
                position: self.position,
                expected: usize::from(index_entry_length),
                actual: self.slice.len(),
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
    #[must_use]
    pub fn file_reference(&self) -> NtfsFileReference
    where
        E: NtfsIndexEntryHasFileReference,
    {
        match self {
            Self::CurrentDirectory(r) | Self::ParentDirectory(r) => *r,
            Self::IndexEntry(e) => e.file_reference(),
        }
    }

    /// Returns the index entry key, or `None` for `.`/`..` entries.
    ///
    /// The `.` and `..` entries are synthesized (not stored on disk) and have
    /// no associated index key. For real index entries, this delegates to
    /// [`NtfsIndexEntry::key`].
    #[must_use]
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
    #[must_use]
    pub fn key_ref(&self) -> Option<Result<<E::KeyType as NtfsIndexEntryKey>::Ref<'s>>> {
        match self {
            Self::CurrentDirectory(_) | Self::ParentDirectory(_) => None,
            Self::IndexEntry(e) => e.key_ref(),
        }
    }

    /// Returns `true` for the `.` (current directory) entry.
    #[must_use]
    pub fn is_current_directory(&self) -> bool {
        matches!(self, Self::CurrentDirectory(_))
    }

    /// Returns `true` for the `..` (parent directory) entry.
    #[must_use]
    pub fn is_parent_directory(&self) -> bool {
        matches!(self, Self::ParentDirectory(_))
    }

    /// Returns `true` for a real index entry (not `.` or `..`).
    #[must_use]
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
        let end = start + usize::from(entry.index_entry_length());

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
            let bytes_to_advance = usize::from(entry.index_entry_length());
            self.slice = &self.slice[bytes_to_advance..];
            self.position += bytes_to_advance;
        }

        Some(Ok(entry))
    }
}

impl<E> FusedIterator for NtfsIndexNodeEntries<'_, E> where E: NtfsIndexEntryType {}

#[cfg(test)]
#[path = "index_entry_tests/mod.rs"]
mod tests;
