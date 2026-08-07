use core::mem;

use arrayvec::ArrayVec;
use nt_string::u16strle::U16StrLe;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

use crate::attribute::{NtfsAttribute, NtfsAttributeType};
use crate::attribute_value::{NtfsAttributeValue, NtfsNonResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::file_reference::NtfsFileReference;
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::structured_values::NtfsStructuredValue;
use crate::types::{NtfsPosition, Vcn};
use fsmnt_parser_core::io::FsReadSeek;

/// Size of all [`AttributeListEntryHeader`] fields.
const ATTRIBUTE_LIST_ENTRY_HEADER_SIZE: usize = 26;

/// [`AttributeListEntryHeader::name_length`] is an `u8` length field specifying the number of UTF-16 code points.
/// Hence, the name occupies up to 510 bytes.
const NAME_MAX_SIZE: usize = 255 * mem::size_of::<u16>();

#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct AttributeListEntryHeader {
    /// Type of the attribute, known types are in [`NtfsAttributeType`].
    ty: U32<LittleEndian>,
    /// Length of this attribute list entry, in bytes.
    list_entry_length: U16<LittleEndian>,
    /// Length of the name, in UTF-16 code points (every code point is 2 bytes).
    name_length: u8,
    /// Offset to the beginning of the name, in bytes from the beginning of this header.
    name_offset: u8,
    /// Lower boundary of Virtual Cluster Numbers (VCNs) referenced by this attribute.
    /// This becomes relevant when file data is split over multiple attributes.
    /// Otherwise, it's zero.
    lowest_vcn: Vcn,
    /// Reference to the File Record where this attribute is stored.
    base_file_reference: NtfsFileReference,
    /// Identifier of this attribute that is unique within the [`NtfsFile`].
    instance: U16<LittleEndian>,
}

/// Structure of an $`ATTRIBUTE_LIST` attribute.
///
/// When a File Record lacks space to incorporate further attributes, NTFS creates an additional File Record,
/// moves all or some of the existing attributes there, and references them via a resident $`ATTRIBUTE_LIST` attribute
/// in the original File Record.
/// When you add even more attributes, NTFS may turn the resident $`ATTRIBUTE_LIST` into a non-resident one to
/// make up the required space.
///
/// An $`ATTRIBUTE_LIST` attribute can hence be resident or non-resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/attribute_list.html>
///
/// Spec reference: MS-FSCC Section 2.3.2 (`ATTRIBUTE_LIST_ENTRY`) via NTFS attribute types.
#[derive(Clone, Debug)]
pub enum NtfsAttributeList<'n, 'f> {
    /// A resident $`ATTRIBUTE_LIST` attribute.
    Resident(&'f [u8], NtfsPosition),
    /// A non-resident $`ATTRIBUTE_LIST` attribute.
    NonResident(NtfsNonResidentAttributeValue<'n, 'f>),
}

impl<'n, 'f> NtfsAttributeList<'n, 'f> {
    /// Returns an iterator over all entries of this $`ATTRIBUTE_LIST` attribute (cf. [`NtfsAttributeListEntry`]).
    #[must_use]
    pub fn entries(&self) -> NtfsAttributeListEntries<'n, 'f> {
        NtfsAttributeListEntries::new(self.clone())
    }

    /// Returns the absolute position of this $`ATTRIBUTE_LIST` attribute value within the filesystem, in bytes.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        match self {
            Self::Resident(_slice, position) => *position,
            Self::NonResident(value) => value.data_position(),
        }
    }
}

impl<'n, 'f> NtfsStructuredValue<'n, 'f> for NtfsAttributeList<'n, 'f> {
    const TY: NtfsAttributeType = NtfsAttributeType::AttributeList;

    fn from_attribute_value<T>(_fs: &mut T, value: NtfsAttributeValue<'n, 'f>) -> Result<Self>
    where
        T: Read + Seek,
    {
        match value {
            NtfsAttributeValue::Resident(value) => {
                let slice = value.data();
                let position = value.data_position();
                Ok(Self::Resident(slice, position))
            }
            NtfsAttributeValue::NonResident(value) => Ok(Self::NonResident(value)),
            NtfsAttributeValue::AttributeListNonResident(value) => {
                // Attribute Lists are never nested.
                // Hence, we must not create this attribute from an attribute that is already part of Attribute List.
                let position = value.data_position();
                Err(NtfsError::UnexpectedAttributeListAttribute { position })
            }
            #[cfg(feature = "compression")]
            NtfsAttributeValue::CompressedNonResident(_) => {
                // Attribute Lists should not be compressed.
                Err(NtfsError::CompressedAttributeNotSupported)
            }
        }
    }
}

/// Iterator over
///   all entries of an [`NtfsAttributeList`] attribute,
///   returning an [`NtfsAttributeListEntry`] for each entry.
///
/// This iterator is returned from the [`NtfsAttributeList::entries`] function.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListEntries<'n, 'f> {
    attribute_list: NtfsAttributeList<'n, 'f>,
}

impl<'n, 'f> NtfsAttributeListEntries<'n, 'f> {
    fn new(attribute_list: NtfsAttributeList<'n, 'f>) -> Self {
        Self { attribute_list }
    }

    /// See [`Iterator::next`].
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        match &mut self.attribute_list {
            NtfsAttributeList::Resident(slice, position) => Self::next_resident(slice, position),
            NtfsAttributeList::NonResident(value) => Self::next_non_resident(fs, value),
        }
    }

    fn next_non_resident<T>(
        fs: &mut T,
        value: &mut NtfsNonResidentAttributeValue<'n, 'f>,
    ) -> Option<Result<NtfsAttributeListEntry>>
    where
        T: Read + Seek,
    {
        if value.stream_position() >= value.len() {
            return None;
        }

        // Get the current entry.
        let mut value_attached = value.clone().attach(fs);
        let position = value.data_position();
        let entry = iter_try!(NtfsAttributeListEntry::new(&mut value_attached, position));

        // Advance our iterator to the next entry.
        iter_try!(value.seek(fs, SeekFrom::Current(i64::from(entry.list_entry_length()))));

        Some(Ok(entry))
    }

    fn next_resident(
        slice: &mut &'f [u8],
        position: &mut NtfsPosition,
    ) -> Option<Result<NtfsAttributeListEntry>> {
        if slice.len() < ATTRIBUTE_LIST_ENTRY_HEADER_SIZE {
            return None;
        }

        // Get the current entry.
        let mut cursor = ReadOnlyCursor::new(slice);
        let entry = iter_try!(NtfsAttributeListEntry::new(&mut cursor, *position));

        // Advance our iterator to the next entry.
        // Guard against zero list_entry_length which would cause an infinite loop.
        let bytes_to_advance =
            usize::from(entry.list_entry_length()).max(ATTRIBUTE_LIST_ENTRY_HEADER_SIZE);
        *slice = slice.get(bytes_to_advance..)?;
        *position += bytes_to_advance;
        Some(Ok(entry))
    }
}

impl fsmnt_parser_core::iter::FsTryIteratorType for NtfsAttributeListEntries<'_, '_> {
    type Error = NtfsError;
    type Item<'a> = NtfsAttributeListEntry;
}

impl<R: Read + Seek> fsmnt_parser_core::iter::FsTryIterator<R>
    for NtfsAttributeListEntries<'_, '_>
{
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsAttributeListEntry>> {
        self.next(r).transpose()
    }
}

/// A single entry of an [`NtfsAttributeList`] attribute.
#[derive(Clone, Debug)]
pub struct NtfsAttributeListEntry {
    header: AttributeListEntryHeader,
    name: ArrayVec<u8, NAME_MAX_SIZE>,
    position: NtfsPosition,
}

impl NtfsAttributeListEntry {
    fn new<T>(r: &mut T, position: NtfsPosition) -> Result<Self>
    where
        T: Read,
    {
        let header = read_pod::<T, AttributeListEntryHeader, ATTRIBUTE_LIST_ENTRY_HEADER_SIZE>(r)?;

        let mut entry = Self {
            header,
            name: ArrayVec::from([0u8; NAME_MAX_SIZE]),
            position,
        };
        entry.validate_entry_and_name_length()?;
        entry.read_name(r)?;

        Ok(entry)
    }

    /// Returns a reference to the File Record where the attribute is stored.
    #[must_use]
    pub fn base_file_reference(&self) -> NtfsFileReference {
        self.header.base_file_reference
    }

    /// Returns the instance number of this attribute list entry.
    ///
    /// An instance number is unique within a single NTFS File Record.
    ///
    /// Multiple entries of the same type and instance number form a connected attribute,
    /// meaning an attribute whose value is stretched over multiple attributes.
    #[must_use]
    pub fn instance(&self) -> u16 {
        self.header.instance.get()
    }

    /// Returns the length of this attribute list entry, in bytes.
    #[must_use]
    pub fn list_entry_length(&self) -> u16 {
        self.header.list_entry_length.get()
    }

    /// Returns the offset of this attribute's value data as a Virtual Cluster Number (VCN).
    ///
    /// This is zero for all unconnected attributes and for the first attribute of a connected attribute.
    /// For subsequent attributes of a connected attribute, this value is nonzero.
    ///
    /// The `lowest_vcn` + data length of one attribute equal the `lowest_vcn` of its following connected attribute.
    #[must_use]
    pub fn lowest_vcn(&self) -> Vcn {
        self.header.lowest_vcn
    }

    /// Gets the attribute name and returns it wrapped in a [`U16StrLe`].
    #[must_use]
    pub fn name(&self) -> U16StrLe<'_> {
        U16StrLe(&self.name)
    }

    /// Returns the file name length, in bytes.
    ///
    /// A file name has a maximum length of 255 UTF-16 code points (510 bytes).
    #[must_use]
    pub fn name_length(&self) -> usize {
        usize::from(self.header.name_length) * mem::size_of::<u16>()
    }

    /// Returns the absolute position of this attribute list entry within the filesystem, in bytes.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    fn read_name<T>(&mut self, r: &mut T) -> Result<()>
    where
        T: Read,
    {
        let len = self.name_length();
        crate::helpers::read_name_into(r, &mut self.name, len)
    }

    /// Returns an [`NtfsAttribute`] for the attribute described by this list entry.
    ///
    /// Use [`NtfsAttributeListEntry::to_file`] first to get the required File Record.
    ///
    /// # Panics
    ///
    /// Panics if a wrong File Record has been passed.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry has an unsupported attribute type or the
    /// matching resident attribute cannot be found in `file`.
    pub fn to_attribute<'n, 'f>(&self, file: &'f NtfsFile<'n>) -> Result<NtfsAttribute<'n, 'f>> {
        let file_record_number = self.base_file_reference().file_record_number();
        assert_eq!(
            file.file_record_number(),
            file_record_number,
            "The given NtfsFile's record number does not match the expected record number. \
            Always use NtfsAttributeListEntry::to_file to retrieve the correct NtfsFile."
        );

        let instance = self.instance();
        let ty = self.ty()?;

        file.find_resident_attribute(ty, None, Some(instance))
    }

    /// Reads the entire File Record referenced by this attribute and returns it.
    ///
    /// # Errors
    ///
    /// Returns an error if the referenced file record cannot be read or fails
    /// NTFS record validation.
    pub fn to_file<'n, T>(&self, ntfs: &'n Ntfs, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        let file_record_number = self.base_file_reference().file_record_number();
        ntfs.file(fs, file_record_number)
    }

    /// Returns the type of this NTFS Attribute, or [`NtfsError::UnsupportedAttributeType`]
    /// if it's an unknown type.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::UnsupportedAttributeType`] when the on-disk type
    /// identifier is not recognized.
    pub fn ty(&self) -> Result<NtfsAttributeType> {
        NtfsAttributeType::n(self.header.ty.get()).ok_or(NtfsError::UnsupportedAttributeType {
            position: self.position(),
            actual: self.header.ty.get(),
        })
    }

    fn validate_entry_and_name_length(&self) -> Result<()> {
        let total_size = ATTRIBUTE_LIST_ENTRY_HEADER_SIZE + self.name_length();

        if total_size > usize::from(self.list_entry_length()) {
            return Err(NtfsError::InvalidStructuredValueSize {
                position: self.position(),
                ty: NtfsAttributeType::AttributeList,
                expected: u64::from(self.list_entry_length()),
                actual: u64::try_from(total_size).unwrap_or(u64::MAX),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_parser_core::iter::FsTryIterator;
    use fsmnt_testkit::Cursor;

    /// Build a minimal valid resident attribute list containing one entry.
    /// The entry describes a $`STANDARD_INFORMATION` (type 0x10) attribute with no name.
    fn make_attribute_list_entry() -> Vec<u8> {
        let mut data = Vec::new();

        // AttributeListEntryHeader (26 bytes):
        // ty: u32 = 0x10 (StandardInformation)
        data.extend_from_slice(&0x10u32.to_le_bytes());
        // list_entry_length: u16 = 26 (header only, no name)
        data.extend_from_slice(&26u16.to_le_bytes());
        // name_length: u8 = 0 (no name)
        data.push(0);
        // name_offset: u8 = 26 (would be after header, but name_length=0)
        data.push(26);
        // lowest_vcn: i64 = 0
        data.extend_from_slice(&0i64.to_le_bytes());
        // base_file_reference: u64 = 5 (root directory, for testing)
        data.extend_from_slice(&5u64.to_le_bytes());
        // instance: u16 = 0
        data.extend_from_slice(&0u16.to_le_bytes());

        assert_eq!(data.len(), ATTRIBUTE_LIST_ENTRY_HEADER_SIZE);
        data
    }

    #[test]
    fn test_attribute_list_resident_parse_entry() {
        let entry_data = make_attribute_list_entry();
        let position = NtfsPosition::new(100);

        let attr_list = NtfsAttributeList::Resident(&entry_data, position);
        assert_eq!(attr_list.position(), position);

        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());

        let entry = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(entry.ty().unwrap(), NtfsAttributeType::StandardInformation);
        assert_eq!(entry.instance(), 0);
        assert_eq!(entry.lowest_vcn().value(), 0);
        assert_eq!(entry.name_length(), 0);
        assert_eq!(entry.list_entry_length(), 26);
        assert_eq!(entry.base_file_reference().file_record_number(), 5);

        // No more entries.
        assert!(entries.try_next(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn test_attribute_list_resident_multiple_entries() {
        // Build two entries back-to-back.
        let mut data = make_attribute_list_entry();
        // Second entry: type = 0x30 (FileName)
        let mut entry2 = Vec::new();
        entry2.extend_from_slice(&0x30u32.to_le_bytes()); // ty: FileName
        entry2.extend_from_slice(&26u16.to_le_bytes()); // list_entry_length
        entry2.push(0); // name_length
        entry2.push(26); // name_offset
        entry2.extend_from_slice(&0i64.to_le_bytes()); // lowest_vcn
        entry2.extend_from_slice(&5u64.to_le_bytes()); // base_file_reference
        entry2.extend_from_slice(&1u16.to_le_bytes()); // instance
        data.extend_from_slice(&entry2);

        let attr_list = NtfsAttributeList::Resident(&data, NtfsPosition::new(200));
        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());

        let e1 = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(e1.ty().unwrap(), NtfsAttributeType::StandardInformation);
        assert_eq!(e1.instance(), 0);

        let e2 = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(e2.ty().unwrap(), NtfsAttributeType::FileName);
        assert_eq!(e2.instance(), 1);

        assert!(entries.try_next(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn test_attribute_list_resident_with_named_entry() {
        // Build an entry with a 4-char name (e.g., "$SDS").
        let mut data = Vec::new();
        let name_bytes = 4 * 2; // 4 UTF-16 code points = 8 bytes
        let entry_length = ATTRIBUTE_LIST_ENTRY_HEADER_SIZE + name_bytes;

        // ty: Data (0x80)
        data.extend_from_slice(&0x80u32.to_le_bytes());
        // list_entry_length
        data.extend_from_slice(
            &u16::try_from(entry_length)
                .expect("test value fits u16")
                .to_le_bytes(),
        );
        // name_length: 4 chars
        data.push(4);
        // name_offset: 26 (right after header)
        data.push(26);
        // lowest_vcn: 0
        data.extend_from_slice(&0i64.to_le_bytes());
        // base_file_reference: 9 ($Secure)
        data.extend_from_slice(&9u64.to_le_bytes());
        // instance: 3
        data.extend_from_slice(&3u16.to_le_bytes());
        // name: "$SDS" in UTF-16LE
        data.extend_from_slice(&[b'$', 0, b'S', 0, b'D', 0, b'S', 0]);

        let attr_list = NtfsAttributeList::Resident(&data, NtfsPosition::new(300));
        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());

        let entry = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(entry.ty().unwrap(), NtfsAttributeType::Data);
        assert_eq!(entry.instance(), 3);
        assert_eq!(entry.name_length(), 8); // 8 bytes
        assert_eq!(entry.name(), "$SDS");
    }

    #[test]
    fn test_attribute_list_position() {
        let data = make_attribute_list_entry();
        let pos = NtfsPosition::new(42);
        let attr_list = NtfsAttributeList::Resident(&data, pos);
        assert_eq!(attr_list.position(), pos);
    }

    #[test]
    fn test_validate_rejects_name_longer_than_entry() {
        // name_length = 4 chars (8 bytes) -> total_size = 26 + 8 = 34,
        // but list_entry_length is only 30. validate_entry_and_name_length
        // must reject this (total_size > list_entry_length).
        let mut data = Vec::new();
        data.extend_from_slice(&0x80u32.to_le_bytes()); // ty: Data
        data.extend_from_slice(&30u16.to_le_bytes()); // list_entry_length = 30
        data.push(4); // name_length = 4 chars (8 bytes)
        data.push(26); // name_offset
        data.extend_from_slice(&0i64.to_le_bytes()); // lowest_vcn
        data.extend_from_slice(&9u64.to_le_bytes()); // base_file_reference
        data.extend_from_slice(&3u16.to_le_bytes()); // instance
        data.extend_from_slice(&[b'$', 0, b'S', 0, b'D', 0, b'S', 0]); // name

        let attr_list = NtfsAttributeList::Resident(&data, NtfsPosition::new(300));
        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());

        let result = entries.try_next(&mut cursor);
        let err = result.expect_err("entry with oversized name must be rejected");
        assert!(
            matches!(err, NtfsError::InvalidStructuredValueSize { .. }),
            "expected InvalidStructuredValueSize, got {err:?}"
        );
    }

    #[test]
    fn test_validate_accepts_exact_fit() {
        // total_size (26 + 8 = 34) == list_entry_length (34): the `>` guard
        // is false, so the entry is accepted. Pairs with the rejection test
        // to pin the `>` boundary and the `+` in total_size.
        let mut data = Vec::new();
        data.extend_from_slice(&0x80u32.to_le_bytes());
        data.extend_from_slice(&34u16.to_le_bytes()); // list_entry_length = 34
        data.push(4); // name_length = 4 chars
        data.push(26);
        data.extend_from_slice(&0i64.to_le_bytes());
        data.extend_from_slice(&9u64.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&[b'$', 0, b'S', 0, b'D', 0, b'S', 0]);

        let attr_list = NtfsAttributeList::Resident(&data, NtfsPosition::new(300));
        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let entry = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(entry.name_length(), 8);
        assert_eq!(entry.name(), "$SDS");
    }

    #[test]
    fn test_max_length_name_fits_buffer() {
        // A 255-char name occupies 510 bytes (= NAME_MAX_SIZE). This must
        // parse without overflowing the name ArrayVec, which catches a
        // mutated NAME_MAX_SIZE (e.g. 255+2 or 255/2 instead of 255*2).
        let name_chars = 255usize;
        let name_bytes = name_chars * 2; // 510
        let entry_length = ATTRIBUTE_LIST_ENTRY_HEADER_SIZE + name_bytes; // 536

        let mut data = Vec::new();
        data.extend_from_slice(&0x80u32.to_le_bytes()); // ty: Data
        data.extend_from_slice(
            &u16::try_from(entry_length)
                .expect("test value fits u16")
                .to_le_bytes(),
        );
        data.push(u8::try_from(name_chars).expect("test value fits u8")); // name_length = 255
        data.push(26); // name_offset
        data.extend_from_slice(&0i64.to_le_bytes()); // lowest_vcn
        data.extend_from_slice(&9u64.to_le_bytes()); // base_file_reference
        data.extend_from_slice(&7u16.to_le_bytes()); // instance
        // Name: 255 copies of 'a' in UTF-16LE.
        for _ in 0..name_chars {
            data.extend_from_slice(&[b'a', 0]);
        }
        assert_eq!(data.len(), entry_length);

        let attr_list = NtfsAttributeList::Resident(&data, NtfsPosition::new(300));
        let mut entries = attr_list.entries();
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let entry = entries.try_next(&mut cursor).unwrap().unwrap();
        assert_eq!(entry.name_length(), 510);
        assert_eq!(entry.name().to_string_lossy().chars().count(), 255);
    }
}
