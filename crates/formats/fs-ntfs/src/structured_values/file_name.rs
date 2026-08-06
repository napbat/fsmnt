use core::mem;

use arrayvec::ArrayVec;
use nt_string::u16strle::U16StrLe;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, U64, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::NtfsAttributeValue;
use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::indexes::NtfsIndexEntryKey;
use crate::io::{Read, Seek};
use crate::structured_values::{NtfsFileAttributeFlags, NtfsStructuredValue};
use crate::time::NtfsTime;
use crate::types::NtfsPosition;

/// Size of all [`FileNameHeader`] fields.
const FILE_NAME_HEADER_SIZE: usize = 66;
const FILE_NAME_HEADER_SIZE_U64: u64 = 66;

/// The smallest `FileName` attribute has a name containing just a single character.
const FILE_NAME_MIN_SIZE: usize = FILE_NAME_HEADER_SIZE + mem::size_of::<u16>();
const FILE_NAME_MIN_SIZE_U64: u64 = 68;

/// The "name" stored in the `FileName` attribute has an `u8` length field specifying the number of UTF-16 code points.
/// Hence, the name occupies up to 510 bytes.
const NAME_MAX_SIZE: usize = 255 * mem::size_of::<u16>();

#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct FileNameHeader {
    parent_directory_reference: NtfsFileReference,
    creation_time: NtfsTime,
    modification_time: NtfsTime,
    mft_record_modification_time: NtfsTime,
    access_time: NtfsTime,
    allocated_size: U64<LittleEndian>,
    data_size: U64<LittleEndian>,
    file_attributes: U32<LittleEndian>,
    reparse_point_tag: U32<LittleEndian>,
    name_length: u8,
    namespace: u8,
}

/// Character set constraint of the filename, returned by [`NtfsFileName::namespace`].
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/filename_namespace.html>
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NtfsFileNamespace {
    /// A POSIX-compatible filename, which is case-sensitive and supports all Unicode
    /// characters except for the forward slash (/) and the NUL character.
    Posix = 0,
    /// A long filename for Windows, which is case-insensitive and supports all Unicode
    /// characters except for " * < > ? \ | / : (and doesn't end with a dot or a space).
    Win32 = 1,
    /// An MS-DOS 8+3 filename (8 uppercase characters with a 3-letter uppercase extension)
    /// that consists entirely of printable ASCII characters (except for " * < > ? \ | / : ; . , + = [ ]).
    Dos = 2,
    /// A Windows filename that also fulfills all requirements of an MS-DOS 8+3 filename (minus the
    /// uppercase requirement), and therefore only got a single $`FILE_NAME` record with this name.
    Win32AndDos = 3,
}

impl NtfsFileNamespace {
    /// Converts an on-disk namespace byte into a known filename namespace.
    ///
    /// Returns `None` for reserved namespace values.
    #[must_use]
    pub fn n(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Posix),
            1 => Some(Self::Win32),
            2 => Some(Self::Dos),
            3 => Some(Self::Win32AndDos),
            _ => None,
        }
    }

    #[cfg(test)]
    const fn on_disk_value(self) -> u8 {
        match self {
            Self::Posix => 0,
            Self::Win32 => 1,
            Self::Dos => 2,
            Self::Win32AndDos => 3,
        }
    }

    /// Returns `true` if this is a "long" name namespace ([`Win32`] or [`Posix`]).
    ///
    /// These are the primary display names for a file. A file with a long name typically
    /// also has a separate [`Dos`] entry for backward compatibility.
    ///
    /// [`Win32`]: NtfsFileNamespace::Win32
    /// [`Posix`]: NtfsFileNamespace::Posix
    /// [`Dos`]: NtfsFileNamespace::Dos
    #[must_use]
    pub fn is_long(&self) -> bool {
        matches!(self, Self::Win32 | Self::Posix)
    }

    /// Returns `true` if this name satisfies DOS 8.3 constraints ([`Dos`] or [`Win32AndDos`]).
    ///
    /// [`Dos`]: NtfsFileNamespace::Dos
    /// [`Win32AndDos`]: NtfsFileNamespace::Win32AndDos
    #[must_use]
    pub fn is_dos_compatible(&self) -> bool {
        matches!(self, Self::Dos | Self::Win32AndDos)
    }

    /// Returns `true` if this is a combined [`Win32AndDos`] entry where the name satisfies
    /// both Win32 and DOS constraints, so only a single `$FILE_NAME` attribute is stored.
    ///
    /// [`Win32AndDos`]: NtfsFileNamespace::Win32AndDos
    #[must_use]
    pub fn is_combined(&self) -> bool {
        matches!(self, Self::Win32AndDos)
    }
}

fn validated_namespace(value: u8) -> NtfsFileNamespace {
    match value {
        0 => NtfsFileNamespace::Posix,
        1 => NtfsFileNamespace::Win32,
        2 => NtfsFileNamespace::Dos,
        3 => NtfsFileNamespace::Win32AndDos,
        _ => unreachable!("file-name constructors validate the namespace byte"),
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsFileNamespace {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variants = [
            NtfsFileNamespace::Posix,
            NtfsFileNamespace::Win32,
            NtfsFileNamespace::Dos,
            NtfsFileNamespace::Win32AndDos,
        ];
        let index: usize = u.arbitrary()?;
        Ok(variants[index % variants.len()])
    }
}

/// Structure of a $`FILE_NAME` attribute.
///
/// NTFS creates a $`FILE_NAME` attribute for every hard link.
/// Its valuable information is the actual file name and whether this file represents a directory.
/// Apart from that, it duplicates several fields of $`STANDARD_INFORMATION`, but these are only updated when the file name changes.
/// You usually want to use the corresponding fields from [`NtfsStandardInformation`] instead.
///
/// A $`FILE_NAME` attribute can be resident or non-resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/file_name.html>
///
/// Spec reference: MS-FSCC Section 2.4.7 (`FileBasicInformation`) for timestamps; Section 2.1.5 (Pathname) for name formats.
///
/// [`NtfsStandardInformation`]: crate::structured_values::NtfsStandardInformation
#[derive(Clone, Debug)]
pub struct NtfsFileName {
    header: FileNameHeader,
    name: ArrayVec<u8, NAME_MAX_SIZE>,
}

impl NtfsFileName {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length < FILE_NAME_MIN_SIZE_U64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::FileName,
                expected: FILE_NAME_MIN_SIZE_U64,
                actual: value_length,
            });
        }

        let header = read_pod::<T, FileNameHeader, FILE_NAME_HEADER_SIZE>(r)?;

        let mut file_name = Self {
            header,
            name: ArrayVec::from([0u8; NAME_MAX_SIZE]),
        };
        file_name.validate_name_length(value_length, position)?;
        file_name.validate_namespace(position)?;
        file_name.read_name(r)?;

        Ok(file_name)
    }

    /// Returns the last access time stored in this $`FILE_NAME` record.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// Check [`NtfsStandardInformation::access_time`] for a last access time that is always up to date.
    ///
    /// [`NtfsStandardInformation::access_time`]: crate::structured_values::NtfsStandardInformation::access_time
    #[must_use]
    pub fn access_time(&self) -> NtfsTime {
        self.header.access_time
    }

    /// Returns the allocated size of the file data, in bytes.
    /// "Data" refers to the unnamed $DATA attribute only.
    /// Other $DATA attributes are not considered.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// If you need an always up-to-date allocated size, use [`NtfsFile::data`] to get the unnamed $DATA attribute,
    /// fetch the corresponding [`NtfsAttribute`], and use [`NtfsAttribute::value`] to fetch the corresponding
    /// [`NtfsAttributeValue`].
    /// For non-resident attribute values, you now need to walk through each Data Run and sum up the return values of
    /// [`NtfsDataRun::allocated_size`].
    /// For resident attribute values, the length equals the allocated size.
    ///
    /// [`NtfsAttribute`]: crate::NtfsAttribute
    /// [`NtfsAttribute::value`]: crate::NtfsAttribute::value
    /// [`NtfsDataRun::allocated_size`]: crate::attribute_value::NtfsDataRun::allocated_size
    /// [`NtfsFile::data`]: crate::NtfsFile::data
    #[must_use]
    pub fn allocated_size(&self) -> u64 {
        self.header.allocated_size.get()
    }

    /// Returns the creation time stored in this $`FILE_NAME` record.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// Check [`NtfsStandardInformation::creation_time`] for a creation time that is always up to date.
    ///
    /// [`NtfsStandardInformation::creation_time`]: crate::structured_values::NtfsStandardInformation::creation_time
    #[must_use]
    pub fn creation_time(&self) -> NtfsTime {
        self.header.creation_time
    }

    /// Returns the size actually used by the file data, in bytes.
    ///
    /// "Data" refers to the unnamed $DATA attribute only.
    /// Other $DATA attributes are not considered.
    ///
    /// This is less or equal than [`NtfsFileName::allocated_size`].
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// If you need an always up-to-date size, use [`NtfsFile::data`] to get the unnamed $DATA attribute,
    /// fetch the corresponding [`NtfsAttribute`], and use [`NtfsAttribute::value`] to fetch the corresponding
    /// [`NtfsAttributeValue`].
    /// Then query [`NtfsAttributeValue::len`].
    ///
    /// [`NtfsAttribute`]: crate::attribute::NtfsAttribute
    /// [`NtfsAttribute::value`]: crate::attribute::NtfsAttribute::value
    /// [`NtfsFile::data`]: crate::file::NtfsFile::data
    #[must_use]
    pub fn data_size(&self) -> u64 {
        self.header.data_size.get()
    }

    /// Returns flags that a user can set for a file (Read-Only, Hidden, System, Archive, etc.).
    /// Commonly called "File Attributes" in Windows Explorer.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// Check [`NtfsStandardInformation::file_attributes`] for file attributes that are always up to date.
    ///
    /// [`NtfsStandardInformation::file_attributes`]: crate::structured_values::NtfsStandardInformation::file_attributes
    #[must_use]
    pub fn file_attributes(&self) -> NtfsFileAttributeFlags {
        NtfsFileAttributeFlags::from_bits_truncate(self.header.file_attributes.get())
    }

    /// Returns whether this file is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_attributes()
            .contains(NtfsFileAttributeFlags::IS_DIRECTORY)
    }

    /// Returns the MFT record modification time stored in this $`FILE_NAME` record.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// Check [`NtfsStandardInformation::mft_record_modification_time`] for an MFT record modification time that is always up to date.
    ///
    /// [`NtfsStandardInformation::mft_record_modification_time`]: crate::structured_values::NtfsStandardInformation::mft_record_modification_time
    #[must_use]
    pub fn mft_record_modification_time(&self) -> NtfsTime {
        self.header.mft_record_modification_time
    }

    /// Returns the modification time stored in this $`FILE_NAME` record.
    ///
    /// **Note that NTFS only updates it when the file name is changed!**
    /// Check [`NtfsStandardInformation::modification_time`] for a modification time that is always up to date.
    ///
    /// [`NtfsStandardInformation::modification_time`]: crate::structured_values::NtfsStandardInformation::modification_time
    #[must_use]
    pub fn modification_time(&self) -> NtfsTime {
        self.header.modification_time
    }

    /// Gets the file name and returns it wrapped in a [`U16StrLe`].
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

    /// Returns the [`NtfsFileNamespace`] of this file name.
    #[must_use]
    pub fn namespace(&self) -> NtfsFileNamespace {
        validated_namespace(self.header.namespace)
    }

    /// Returns an [`NtfsFileReference`] for the directory where this file is located.
    #[must_use]
    pub fn parent_directory_reference(&self) -> NtfsFileReference {
        self.header.parent_directory_reference
    }

    /// Returns the reparse point tag if this file is a reparse point.
    ///
    /// Returns 0 if this file is not a reparse point.
    /// Check [`NtfsFileAttributeFlags::REPARSE_POINT`] in [`file_attributes`](Self::file_attributes)
    /// to determine if this file is a reparse point.
    #[must_use]
    pub fn reparse_point_tag(&self) -> u32 {
        self.header.reparse_point_tag.get()
    }

    fn read_name<T>(&mut self, r: &mut T) -> Result<()>
    where
        T: Read,
    {
        let len = self.name_length();
        crate::helpers::read_name_into(r, &mut self.name, len)
    }

    fn validate_name_length(&self, data_size: u64, position: NtfsPosition) -> Result<()> {
        let total_size =
            u64::try_from(FILE_NAME_HEADER_SIZE + self.name_length()).unwrap_or(u64::MAX);

        if total_size > data_size {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::FileName,
                expected: data_size,
                actual: total_size,
            });
        }

        Ok(())
    }

    fn validate_namespace(&self, position: NtfsPosition) -> Result<()> {
        if NtfsFileNamespace::n(self.header.namespace).is_none() {
            return Err(NtfsError::UnsupportedFileNamespace {
                position,
                actual: self.header.namespace,
            });
        }

        Ok(())
    }
}

impl_structured_value_via_new!(NtfsFileName, NtfsAttributeType::FileName);

#[cfg(test)]
impl NtfsFileName {
    /// Test-only constructor that reads from a byte slice.
    pub(crate) fn from_bytes_for_test(data: &[u8]) -> Self {
        let position = NtfsPosition::none();
        let mut cursor = ReadOnlyCursor::new(data);
        Self::new(
            &mut cursor,
            position,
            u64::try_from(data.len()).expect("test file-name data length fits u64"),
        )
        .expect("test FN construction failed")
    }
}

/// Zero-copy borrowed view of a `$FILE_NAME` attribute key.
///
/// Unlike [`NtfsFileName`] (which copies the 66-byte header and up to
/// 510 name bytes), this type borrows directly from the index entry
/// slice. It exposes the subset of accessors needed by the B-tree
/// finder and traversal code.
///
/// Both types exist because they serve different lifetime needs:
///
/// - **`NtfsFileNameRef<'a>`** — hot-path reads where the value is
///   used within the lifetime of the index entry slice (finder
///   comparisons, traversal name extraction).
/// - **[`NtfsFileName`]** — storage beyond the entry lifetime
///   ([`NtfsFileNamePair`](crate::NtfsFileNamePair), slack recovery
///   results, returned from [`NtfsFile::name`](crate::NtfsFile::name)).
#[derive(Debug)]
pub struct NtfsFileNameRef<'a> {
    header: &'a FileNameHeader,
    name: &'a [u8],
}

impl<'a> NtfsFileNameRef<'a> {
    /// Constructs a borrowed file name view from a raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the fixed header or name is truncated, or if the
    /// namespace byte is unsupported.
    pub fn from_slice(slice: &'a [u8], position: NtfsPosition) -> Result<Self> {
        let slice_length = u64::try_from(slice.len()).unwrap_or(u64::MAX);
        if slice.len() < FILE_NAME_MIN_SIZE {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::FileName,
                expected: FILE_NAME_MIN_SIZE_U64,
                actual: slice_length,
            });
        }

        let (header, remainder) = FileNameHeader::ref_from_prefix(slice).map_err(|_| {
            NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::FileName,
                expected: FILE_NAME_HEADER_SIZE_U64,
                actual: slice_length,
            }
        })?;

        // Validate namespace (must be 0-3).
        if NtfsFileNamespace::n(header.namespace).is_none() {
            return Err(NtfsError::UnsupportedFileNamespace {
                position,
                actual: header.namespace,
            });
        }

        let name_len = usize::from(header.name_length) * mem::size_of::<u16>();
        if name_len < mem::size_of::<u16>() || name_len > remainder.len() {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::FileName,
                expected: u64::try_from(FILE_NAME_HEADER_SIZE + name_len).unwrap_or(u64::MAX),
                actual: slice_length,
            });
        }

        let name = &remainder[..name_len];
        Ok(Self { header, name })
    }

    /// Gets the file name and returns it wrapped in a [`U16StrLe`].
    #[must_use]
    pub fn name(&self) -> U16StrLe<'a> {
        U16StrLe(self.name)
    }

    /// Returns the file name length, in bytes.
    #[must_use]
    pub fn name_length(&self) -> usize {
        usize::from(self.header.name_length) * mem::size_of::<u16>()
    }

    /// Returns the [`NtfsFileNamespace`] of this file name.
    #[must_use]
    pub fn namespace(&self) -> NtfsFileNamespace {
        validated_namespace(self.header.namespace)
    }

    /// Returns whether this file is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_attributes()
            .contains(NtfsFileAttributeFlags::IS_DIRECTORY)
    }

    /// Returns flags that a user can set for a file.
    #[must_use]
    pub fn file_attributes(&self) -> NtfsFileAttributeFlags {
        NtfsFileAttributeFlags::from_bits_truncate(self.header.file_attributes.get())
    }

    /// Returns an [`NtfsFileReference`] for the parent directory.
    #[must_use]
    pub fn parent_directory_reference(&self) -> NtfsFileReference {
        self.header.parent_directory_reference
    }

    /// Returns the raw UTF-16LE name bytes.
    #[must_use]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }
}

// `NtfsFileName` is special in the regard that the Index Entry key has the same structure as the structured value.
impl NtfsIndexEntryKey for NtfsFileName {
    type Ref<'a> = NtfsFileNameRef<'a>;

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let value_length = u64::try_from(slice.len()).unwrap_or(u64::MAX);

        let mut cursor = ReadOnlyCursor::new(slice);
        Self::new(&mut cursor, position, value_length)
    }

    fn key_ref_from_slice(slice: &[u8], position: NtfsPosition) -> Result<NtfsFileNameRef<'_>> {
        NtfsFileNameRef::from_slice(slice, position)
    }
}

#[cfg(feature = "arbitrary")]
mod arbitrary_impl;

#[cfg(test)]
mod fixture_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_is_long() {
        assert!(NtfsFileNamespace::Posix.is_long());
        assert!(NtfsFileNamespace::Win32.is_long());
        assert!(!NtfsFileNamespace::Dos.is_long());
        assert!(!NtfsFileNamespace::Win32AndDos.is_long());
    }

    #[test]
    fn test_namespace_is_dos_compatible() {
        assert!(!NtfsFileNamespace::Posix.is_dos_compatible());
        assert!(!NtfsFileNamespace::Win32.is_dos_compatible());
        assert!(NtfsFileNamespace::Dos.is_dos_compatible());
        assert!(NtfsFileNamespace::Win32AndDos.is_dos_compatible());
    }

    #[test]
    fn test_namespace_is_combined() {
        assert!(!NtfsFileNamespace::Posix.is_combined());
        assert!(!NtfsFileNamespace::Win32.is_combined());
        assert!(!NtfsFileNamespace::Dos.is_combined());
        assert!(NtfsFileNamespace::Win32AndDos.is_combined());
    }

    #[test]
    fn file_name_ref_from_raw_bytes() {
        // Build a minimal $FILE_NAME structure:
        //   FileNameHeader (66 bytes) + UTF-16LE name "AB" (4 bytes)
        let mut buf = [0u8; FILE_NAME_MIN_SIZE + 4];

        // parent_directory_reference (8 bytes) — MFT record 5, seq 1
        buf[0..6].copy_from_slice(&5u64.to_le_bytes()[..6]);
        buf[6..8].copy_from_slice(&1u16.to_le_bytes());

        // Skip timestamps (8*4 = 32 bytes at offset 8..40) and
        // allocated_size/data_size (16 bytes at 40..56) — all zeros.

        // file_attributes at offset 56 — IS_DIRECTORY
        buf[56..60].copy_from_slice(&0x1000_0000u32.to_le_bytes());

        // reparse_point_tag at offset 60 — 0
        // name_length at offset 64
        buf[64] = 2; // 2 UTF-16 code units
        // namespace at offset 65
        buf[65] = NtfsFileNamespace::Win32.on_disk_value();

        // UTF-16LE name "AB" at offset 66
        buf[66] = b'A';
        buf[67] = 0;
        buf[68] = b'B';
        buf[69] = 0;

        let r =
            NtfsFileNameRef::from_slice(&buf, NtfsPosition::none()).expect("valid $FILE_NAME ref");
        assert_eq!(r.name(), "AB");
        assert_eq!(r.namespace(), NtfsFileNamespace::Win32);
        assert!(r.is_directory());
        assert_eq!(r.name_length(), 4); // 2 code units * 2 bytes
        assert_eq!(r.parent_directory_reference().file_record_number(), 5,);
    }

    #[test]
    fn file_name_ref_rejects_truncated() {
        let buf = [0u8; FILE_NAME_MIN_SIZE - 1];
        let result = NtfsFileNameRef::from_slice(&buf, NtfsPosition::new(0x100));
        assert!(result.is_err());
    }

    #[test]
    fn file_name_ref_rejects_bad_namespace() {
        let mut buf = [0u8; FILE_NAME_MIN_SIZE + 2];
        buf[64] = 1; // name_length = 1
        buf[65] = 4; // invalid namespace
        buf[66] = b'X';
        buf[67] = 0;

        let result = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none());
        assert!(result.is_err());
    }

    /// Builds a `$FILE_NAME` attribute byte buffer for synthetic tests.
    ///
    /// Layout (MS-FSCC 2.4.7-style $`FILE_NAME)`:
    /// - 0..8   `parent_directory_reference`
    /// - 8..40  four 8-byte NTFS timestamps (left zero)
    /// - 40..48 `allocated_size`
    /// - 48..56 `data_size`
    /// - 56..60 `file_attributes`
    /// - 60..64 `reparse_point_tag`
    /// - 64     `name_length` (UTF-16 code units)
    /// - 65     namespace
    /// - 66..   UTF-16LE name
    fn build_file_name(
        parent: u64,
        allocated_size: u64,
        data_size: u64,
        file_attributes: u32,
        reparse_tag: u32,
        namespace: u8,
        name: &str,
    ) -> Vec<u8> {
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let mut buf = vec![0u8; FILE_NAME_HEADER_SIZE];
        buf[0..8].copy_from_slice(&parent.to_le_bytes());
        buf[40..48].copy_from_slice(&allocated_size.to_le_bytes());
        buf[48..56].copy_from_slice(&data_size.to_le_bytes());
        buf[56..60].copy_from_slice(&file_attributes.to_le_bytes());
        buf[60..64].copy_from_slice(&reparse_tag.to_le_bytes());
        buf[64] = u8::try_from(name_units.len()).expect("test value fits u8");
        buf[65] = namespace;
        for unit in &name_units {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_file_name_accessors_from_synthetic_bytes() {
        // Distinct, non-default field values so accessor mutants flip.
        let buf = build_file_name(
            0x0102_0304_0506, // parent (6 bytes meaningful)
            0x1111_2222_3333_4444,
            0x0AAA_BBBB_CCCC_DDDD,
            0x1000_0000, // IS_DIRECTORY
            0xDEAD_BEEF, // reparse_point_tag
            NtfsFileNamespace::Win32.on_disk_value(),
            "hi",
        );
        let fname = NtfsFileName::from_bytes_for_test(&buf);

        assert_eq!(fname.allocated_size(), 0x1111_2222_3333_4444);
        assert_eq!(fname.data_size(), 0x0AAA_BBBB_CCCC_DDDD);
        assert!(fname.is_directory());
        // name_length = 2 code units * 2 bytes = 4.
        assert_eq!(fname.name_length(), 4);
        assert_eq!(fname.reparse_point_tag(), 0xDEAD_BEEF);
        assert_eq!(fname.namespace(), NtfsFileNamespace::Win32);
        assert_eq!(fname.name(), "hi");
        assert_eq!(
            fname.parent_directory_reference().file_record_number(),
            0x0102_0304_0506
        );
    }

    #[test]
    fn test_file_name_not_directory() {
        // file_attributes without IS_DIRECTORY: is_directory must be false.
        let buf = build_file_name(5, 0, 0, 0x0000_0020, 0, 0, "x");
        let fname = NtfsFileName::from_bytes_for_test(&buf);
        assert!(!fname.is_directory());
    }

    #[test]
    fn test_file_name_length_three_units() {
        // 3 code units * 2 = 6 bytes. Distinguishes name_length from 0/1 and
        // pins the `* size_of::<u16>()` multiply (vs / which would give 1).
        let buf = build_file_name(
            5,
            0,
            0,
            0,
            0,
            NtfsFileNamespace::Posix.on_disk_value(),
            "abc",
        );
        let fname = NtfsFileName::from_bytes_for_test(&buf);
        assert_eq!(fname.name_length(), 6);
        assert_eq!(fname.name(), "abc");
    }

    #[test]
    fn test_file_name_validate_length_rejects_when_total_exceeds_declared() {
        // The buffer physically holds the full 4-code-unit name (header + 8
        // bytes), but the DECLARED value_length is too small to contain it.
        // validate_name_length compares total_size (66 + 8 = 74) against the
        // declared data_size; passing value_length = 70 makes total_size > 70
        // -> Err. Crucially, the buffer itself is large enough that read_name
        // would SUCCEED if validation were skipped, so a
        // `validate_name_length -> Ok(())` mutant would let parsing succeed.
        // This kills both the `-> Ok(())` mutant and the `> -> <` boundary.
        let buf = build_file_name(
            5,
            0,
            0,
            0,
            0,
            NtfsFileNamespace::Win32.on_disk_value(),
            "ABCD",
        );
        assert_eq!(buf.len(), FILE_NAME_HEADER_SIZE + 8);
        let position = NtfsPosition::none();
        let mut cursor = ReadOnlyCursor::new(&buf);
        // Declare a value_length smaller than the real total size.
        let result = NtfsFileName::new(&mut cursor, position, 70);
        assert!(matches!(
            result,
            Err(NtfsError::InvalidStructuredValueSize { .. })
        ));
    }

    #[test]
    fn test_file_name_validate_length_accepts_when_total_below_declared() {
        // total_size (66 + 2 = 68) is strictly LESS than the declared
        // value_length (100). The original `>` is false -> accepted. A `> -> <`
        // mutant would see `68 < 100` true -> reject, so a successful parse
        // here kills `> -> <`. The buffer holds the 1-code-unit name.
        let buf = build_file_name(5, 0, 0, 0, 0, NtfsFileNamespace::Win32.on_disk_value(), "Z");
        let position = NtfsPosition::none();
        let mut cursor = ReadOnlyCursor::new(&buf);
        let fname = NtfsFileName::new(&mut cursor, position, 100).unwrap();
        assert_eq!(fname.name(), "Z");
        assert_eq!(fname.name_length(), 2);
    }

    #[test]
    fn test_file_name_validate_length_accepts_exact_fit() {
        // The minimal valid case: header + exactly the declared name bytes,
        // total_size == data_size. Boundary for `total_size > data_size`.
        let buf = build_file_name(5, 0, 0, 0, 0, NtfsFileNamespace::Win32.on_disk_value(), "Z");
        // value_length is exactly header + 2 bytes for one code unit.
        assert_eq!(buf.len(), FILE_NAME_HEADER_SIZE + 2);
        let fname = NtfsFileName::from_bytes_for_test(&buf);
        assert_eq!(fname.name(), "Z");
        assert_eq!(fname.name_length(), 2);
    }

    #[test]
    fn test_file_name_rejects_bad_namespace() {
        // namespace byte = 5 is outside 0..=3; validate_namespace must fail.
        let mut buf = build_file_name(5, 0, 0, 0, 0, 1, "q");
        buf[65] = 5;
        let position = NtfsPosition::none();
        let mut cursor = ReadOnlyCursor::new(&buf);
        let result = NtfsFileName::new(
            &mut cursor,
            position,
            u64::try_from(buf.len()).expect("test buffer length fits u64"),
        );
        assert!(matches!(
            result,
            Err(NtfsError::UnsupportedFileNamespace { actual: 5, .. })
        ));
    }

    #[test]
    fn test_file_name_long_name_near_max() {
        // A 200-code-unit name (400 bytes) exercises NAME_MAX_SIZE capacity
        // (510 bytes). A mutated NAME_MAX_SIZE of 127 (`* -> /`) would make
        // the backing ArrayVec too small and panic; the genuine constant
        // (255 * 2 = 510) accommodates it.
        let name: String = std::iter::repeat_n('a', 200).collect();
        let buf = build_file_name(
            5,
            0,
            0,
            0,
            0,
            NtfsFileNamespace::Posix.on_disk_value(),
            &name,
        );
        let fname = NtfsFileName::from_bytes_for_test(&buf);
        assert_eq!(fname.name_length(), 400);
        assert_eq!(fname.name().to_string_lossy().len(), 200);
    }

    #[test]
    fn test_file_name_ref_directory_flag_false() {
        // NtfsFileNameRef::is_directory must reflect the absence of the flag.
        let buf = build_file_name(
            5,
            0,
            0,
            0x0000_0020,
            0,
            NtfsFileNamespace::Win32.on_disk_value(),
            "AB",
        );
        let r = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none()).unwrap();
        assert!(!r.is_directory());
    }

    #[test]
    fn test_file_name_ref_name_bytes_and_length() {
        // name_bytes returns the genuine UTF-16LE slice (not empty / [0] / [1]).
        // Use a 3-code-unit name so name_length is 3 * 2 = 6, distinct from
        // 3 + 2 = 5 and 3 / 2 = 1 — pinning the `* size_of::<u16>()` multiply.
        let buf = build_file_name(
            5,
            0,
            0,
            0,
            0,
            NtfsFileNamespace::Win32.on_disk_value(),
            "ABC",
        );
        let r = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none()).unwrap();
        assert_eq!(r.name_bytes(), &[b'A', 0, b'B', 0, b'C', 0]);
        assert_eq!(r.name_length(), 6);
    }

    #[test]
    fn test_file_name_ref_rejects_zero_name_length() {
        // name_length = 0 -> name_len (0) < size_of::<u16>() (2), rejected.
        // Pins the `name_len < mem::size_of::<u16>()` lower-bound check.
        let mut buf = build_file_name(5, 0, 0, 0, 0, NtfsFileNamespace::Win32.on_disk_value(), "A");
        buf[64] = 0; // zero code units
        let result = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_file_name_ref_rejects_name_past_remainder() {
        // name_length claims more bytes than the remainder holds -> rejected.
        // Pins `name_len > remainder.len()`. The error's `expected` field is
        // FILE_NAME_HEADER_SIZE + name_len = 66 + 200 = 266; asserting it
        // exactly kills the `+ -> *` mutation (which would compute 66 * 200).
        let mut buf = build_file_name(
            5,
            0,
            0,
            0,
            0,
            NtfsFileNamespace::Win32.on_disk_value(),
            "AB",
        );
        buf[64] = 100; // 100 code units = 200 bytes, far past the 4-byte name
        let result = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none());
        match result {
            Err(NtfsError::InvalidStructuredValueSize { expected, .. }) => {
                assert_eq!(
                    expected,
                    u64::try_from(FILE_NAME_HEADER_SIZE + 200)
                        .expect("test expected size fits u64")
                );
            }
            other => panic!("expected InvalidStructuredValueSize, got {other:?}"),
        }
    }

    #[test]
    fn test_file_name_ref_exact_min_size_accepted() {
        // slice.len() == FILE_NAME_MIN_SIZE must be accepted (boundary for
        // `slice.len() < FILE_NAME_MIN_SIZE`).
        let buf = build_file_name(5, 0, 0, 0, 0, NtfsFileNamespace::Win32.on_disk_value(), "A");
        assert_eq!(buf.len(), FILE_NAME_MIN_SIZE);
        let r = NtfsFileNameRef::from_slice(&buf, NtfsPosition::none()).unwrap();
        assert_eq!(r.name(), "A");
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_namespace_arbitrary_index_modulo() {
        use arbitrary::{Arbitrary, Unstructured};

        // `arbitrary` reads a usize (8 bytes LE on 64-bit) then indexes
        // `variants[index % 4]`. Choosing index values 0..7 and asserting the
        // exact variant pins `index % variants.len()` (vs / or +, which would
        // panic with out-of-bounds or pick the wrong variant).
        let expected = [
            NtfsFileNamespace::Posix,       // 0 % 4
            NtfsFileNamespace::Win32,       // 1 % 4
            NtfsFileNamespace::Dos,         // 2 % 4
            NtfsFileNamespace::Win32AndDos, // 3 % 4
            NtfsFileNamespace::Posix,       // 4 % 4
            NtfsFileNamespace::Win32,       // 5 % 4
            NtfsFileNamespace::Dos,         // 6 % 4
            NtfsFileNamespace::Win32AndDos, // 7 % 4
        ];
        for (index, want) in expected.iter().enumerate() {
            let bytes = index.to_le_bytes();
            let mut u = Unstructured::new(&bytes);
            let got = NtfsFileNamespace::arbitrary(&mut u).unwrap();
            assert_eq!(got, *want, "index {index} produced wrong namespace");
        }
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_file_name_arbitrary_clamps_name_length() {
        use arbitrary::{Arbitrary, Unstructured};

        // Construct a header whose name_length byte is 5, with namespace 9
        // (clamped to 9 % 4 = 1 = Win32). The generated name_len is
        // name_chars * size_of::<u16>() = 5 * 2 = 10 bytes; supply enough
        // trailing bytes. This pins the `%= 4`, `clamp`, and `* size_of`
        // arithmetic in the NtfsFileName arbitrary impl.
        let mut bytes = vec![0u8; FILE_NAME_HEADER_SIZE];
        bytes[64] = 5; // name_length code units
        bytes[65] = 9; // namespace -> 9 % 4 = 1
        bytes.extend_from_slice(&[0xAB; 32]); // ample bytes for the name body
        let mut u = Unstructured::new(&bytes);
        let fname = NtfsFileName::arbitrary(&mut u).unwrap();
        assert_eq!(fname.namespace(), NtfsFileNamespace::Win32);
        // 5 code units -> name_length() == 10 bytes.
        assert_eq!(fname.name_length(), 10);
        // The actual name body holds name_chars * size_of::<u16>() = 10 bytes.
        // The U16StrLe tuple field exposes the raw byte slice; its length is
        // the generated `name_len`. A `* -> +` mutation would push 7 bytes and
        // `* -> /` would push 2, so asserting 10 kills both at line 466.
        assert_eq!(fname.name().0.len(), 10);
    }
}
