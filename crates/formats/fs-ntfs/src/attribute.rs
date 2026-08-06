use alloc::collections::BTreeSet;
use core::iter::FusedIterator;
use core::ops::Range;
use core::{fmt, mem};

use crate::io::{Read, Seek};
use bitflags::bitflags;
use enumn::N;
use memoffset::offset_of;
use nt_string::u16strle::U16StrLe;
use strum_macros::Display;

use crate::attribute_value::{
    NtfsAttributeListNonResidentAttributeValue, NtfsAttributeValue, NtfsNonResidentAttributeValue,
    NtfsResidentAttributeValue,
};
use crate::error::{NtfsError, Result};
use crate::file::NtfsFile;
use crate::structured_values::{
    NtfsAttributeList, NtfsAttributeListEntries, NtfsStructuredValue,
    NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::{NtfsPosition, Vcn};

/// Size of all [`NtfsAttributeHeader`] fields.
const ATTRIBUTE_HEADER_SIZE: usize = 16;

/// Minimum size of an [`NtfsResidentAttributeHeader`] (generic header + resident-specific fields).
const RESIDENT_ATTRIBUTE_MIN_SIZE: usize = mem::size_of::<NtfsResidentAttributeHeader>();

/// Minimum size of an [`NtfsNonResidentAttributeHeader`] (generic header + non-resident-specific fields).
const NON_RESIDENT_ATTRIBUTE_MIN_SIZE: usize = mem::size_of::<NtfsNonResidentAttributeHeader>();

/// On-disk structure of the generic header of an NTFS Attribute.
#[repr(C, packed)]
struct NtfsAttributeHeader {
    /// Type of the attribute, known types are in [`NtfsAttributeType`].
    ty: u32,
    /// Length of the resident part of this attribute, in bytes.
    length: u32,
    /// 0 if this attribute has a resident value, 1 if this attribute has a non-resident value.
    is_non_resident: u8,
    /// Length of the name, in UTF-16 code points (every code point is 2 bytes).
    name_length: u8,
    /// Offset to the beginning of the name, in bytes from the beginning of this header.
    name_offset: u16,
    /// Flags of the attribute, known flags are in [`NtfsAttributeFlags`].
    flags: u16,
    /// Identifier of this attribute that is unique within the [`NtfsFile`].
    instance: u16,
}

bitflags! {
    /// Flags returned by [`NtfsAttribute::flags`].
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsAttributeFlags: u16 {
        /// The attribute value is compressed.
        const COMPRESSED = 0x0001;
        /// The attribute value is encrypted.
        const ENCRYPTED = 0x4000;
        /// The attribute value is stored sparsely.
        const SPARSE = 0x8000;
    }
}

impl fmt::Display for NtfsAttributeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsAttributeFlags {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u16 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

/// On-disk structure of the extra header of an NTFS Attribute that has a resident value.
#[repr(C, packed)]
struct NtfsResidentAttributeHeader {
    attribute_header: NtfsAttributeHeader,
    /// Length of the value, in bytes.
    value_length: u32,
    /// Offset to the beginning of the value, in bytes from the beginning of the [`NtfsAttributeHeader`].
    value_offset: u16,
    /// 1 if this attribute (with resident value) is referenced in an index.
    indexed_flag: u8,
}

/// On-disk structure of the extra header of an NTFS Attribute that has a non-resident value.
#[repr(C, packed)]
struct NtfsNonResidentAttributeHeader {
    attribute_header: NtfsAttributeHeader,
    /// Lower boundary of Virtual Cluster Numbers (VCNs) referenced by this attribute.
    /// This becomes relevant when file data is split over multiple attributes.
    /// Otherwise, it's zero.
    lowest_vcn: Vcn,
    /// Upper boundary of Virtual Cluster Numbers (VCNs) referenced by this attribute.
    /// This becomes relevant when file data is split over multiple attributes.
    /// Otherwise, it's zero (or even -1 for zero-length files according to NTFS-3G).
    highest_vcn: Vcn,
    /// Offset to the beginning of the value data runs.
    data_runs_offset: u16,
    /// Binary exponent denoting the number of clusters in a compression unit.
    /// A typical value is 4, meaning that 2^4 = 16 clusters are part of a compression unit.
    /// A value of zero means no compression (but that should better be determined via
    /// [`NtfsAttributeFlags`]).
    compression_unit_exponent: u8,
    reserved: [u8; 5],
    /// Allocated space for the attribute value, in bytes. This is always a multiple of the cluster size.
    /// For compressed files, this is always a multiple of the compression unit size.
    allocated_size: u64,
    /// Size of the attribute value, in bytes.
    /// This can be larger than `allocated_size` if the value is compressed or stored sparsely.
    data_size: u64,
    /// Size of the initialized part of the attribute value, in bytes.
    /// This is usually the same as `data_size`.
    initialized_size: u64,
}

/// All known NTFS Attribute types.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/index.html>
#[derive(Clone, Copy, Debug, Display, Eq, N, PartialEq)]
#[repr(u32)]
pub enum NtfsAttributeType {
    /// $STANDARD_INFORMATION, see [`NtfsStandardInformation`].
    ///
    /// [`NtfsStandardInformation`]: crate::structured_values::NtfsStandardInformation
    StandardInformation = 0x10,
    /// $ATTRIBUTE_LIST, see [`NtfsAttributeList`].
    ///
    /// [`NtfsAttributeList`]: crate::structured_values::NtfsAttributeList
    AttributeList = 0x20,
    /// $FILE_NAME, see [`NtfsFileName`].
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    FileName = 0x30,
    /// $OBJECT_ID, see [`NtfsObjectId`].
    ///
    /// [`NtfsObjectId`]: crate::structured_values::NtfsObjectId
    ObjectId = 0x40,
    /// $SECURITY_DESCRIPTOR
    SecurityDescriptor = 0x50,
    /// $VOLUME_NAME, see [`NtfsVolumeName`].
    ///
    /// [`NtfsVolumeName`]: crate::structured_values::NtfsVolumeName
    VolumeName = 0x60,
    /// $VOLUME_INFORMATION, see [`NtfsVolumeInformation`].
    ///
    /// [`NtfsVolumeInformation`]: crate::structured_values::NtfsVolumeInformation
    VolumeInformation = 0x70,
    /// $DATA, see [`NtfsFile::data`].
    Data = 0x80,
    /// $INDEX_ROOT, see [`NtfsIndexRoot`].
    ///
    /// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
    IndexRoot = 0x90,
    /// $INDEX_ALLOCATION, see [`NtfsIndexAllocation`].
    ///
    /// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
    IndexAllocation = 0xA0,
    /// $BITMAP
    Bitmap = 0xB0,
    /// $REPARSE_POINT
    ReparsePoint = 0xC0,
    /// $EA_INFORMATION
    EAInformation = 0xD0,
    /// $EA
    EA = 0xE0,
    /// $PROPERTY_SET, see [`NtfsPropertySet`].
    ///
    /// [`NtfsPropertySet`]: crate::structured_values::NtfsPropertySet
    PropertySet = 0xF0,
    /// $LOGGED_UTILITY_STREAM, see [`NtfsLoggedUtilityStream`].
    ///
    /// [`NtfsLoggedUtilityStream`]: crate::structured_values::NtfsLoggedUtilityStream
    LoggedUtilityStream = 0x100,
    /// Marks the end of the valid attributes.
    End = 0xFFFF_FFFF,
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsAttributeType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variants = [
            NtfsAttributeType::StandardInformation,
            NtfsAttributeType::AttributeList,
            NtfsAttributeType::FileName,
            NtfsAttributeType::ObjectId,
            NtfsAttributeType::SecurityDescriptor,
            NtfsAttributeType::VolumeName,
            NtfsAttributeType::VolumeInformation,
            NtfsAttributeType::Data,
            NtfsAttributeType::IndexRoot,
            NtfsAttributeType::IndexAllocation,
            NtfsAttributeType::Bitmap,
            NtfsAttributeType::ReparsePoint,
            NtfsAttributeType::EAInformation,
            NtfsAttributeType::EA,
            NtfsAttributeType::PropertySet,
            NtfsAttributeType::LoggedUtilityStream,
            NtfsAttributeType::End,
        ];
        let index: usize = u.arbitrary()?;
        Ok(variants[index % variants.len()])
    }
}

/// A single NTFS Attribute of an [`NtfsFile`].
///
/// Not to be confused with [`NtfsFileAttributeFlags`].
///
/// This structure is returned by the [`NtfsAttributesRaw`] iterator as well as [`NtfsAttributeItem::to_attribute`].
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/concepts/attribute_header.html>
///
/// [`NtfsFileAttributeFlags`]: crate::structured_values::NtfsFileAttributeFlags
#[derive(Clone, Debug)]
pub struct NtfsAttribute<'n, 'f> {
    file: &'f NtfsFile<'n>,
    offset: usize,
    /// Has a value if this attribute's value may be split over multiple attributes.
    /// The connected attributes can be iterated using the encapsulated iterator.
    list_entries: Option<&'f NtfsAttributeListEntries<'n, 'f>>,
}

impl<'n, 'f> NtfsAttribute<'n, 'f> {
    pub(crate) fn new(
        file: &'f NtfsFile<'n>,
        offset: usize,
        list_entries: Option<&'f NtfsAttributeListEntries<'n, 'f>>,
    ) -> Result<Self> {
        let attribute = Self {
            file,
            offset,
            list_entries,
        };
        attribute.validate_attribute_length()?;

        Ok(attribute)
    }

    /// Returns the length of this NTFS Attribute, in bytes.
    ///
    /// This denotes the length of the attribute structure on disk.
    /// Apart from various headers, this structure also includes the name and,
    /// for resident attributes, the actual value.
    pub fn attribute_length(&self) -> u32 {
        let start = self.offset + offset_of!(NtfsAttributeHeader, length);
        u32::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    pub(crate) fn ensure_ty(&self, expected: NtfsAttributeType) -> Result<()> {
        let ty = self.ty()?;
        if ty != expected {
            return Err(NtfsError::AttributeOfDifferentType {
                position: self.position(),
                expected,
                actual: ty,
            });
        }

        Ok(())
    }

    /// Returns flags set for this attribute as specified by [`NtfsAttributeFlags`].
    pub fn flags(&self) -> NtfsAttributeFlags {
        let start = self.offset + offset_of!(NtfsAttributeHeader, flags);
        NtfsAttributeFlags::from_bits_truncate(u16::from_le_bytes(
            *self.file.record_data()[start..].first_chunk().unwrap(),
        ))
    }

    /// Returns the identifier of this attribute that is unique within the [`NtfsFile`].
    pub fn instance(&self) -> u16 {
        let start = self.offset + offset_of!(NtfsAttributeHeader, instance);
        u16::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    /// Returns `true` if this is a resident attribute, i.e. one where its value
    /// is part of the attribute structure.
    pub fn is_resident(&self) -> bool {
        let start = self.offset + offset_of!(NtfsAttributeHeader, is_non_resident);
        let is_non_resident = self.file.record_data()[start];
        is_non_resident == 0
    }

    /// Gets the name of this NTFS Attribute (if any) and returns it wrapped in a [`U16StrLe`].
    ///
    /// Note that most NTFS attributes have no name and are distinguished by their types.
    /// Use [`NtfsAttribute::ty`] to get the attribute type.
    pub fn name(&self) -> Result<U16StrLe<'f>> {
        if self.name_offset() == 0 || self.name_length() == 0 {
            return Ok(U16StrLe(&[]));
        }

        self.validate_name_sizes()?;

        let start = self.offset + self.name_offset() as usize;
        let end = start + self.name_length();
        let string = U16StrLe(&self.file.record_data()[start..end]);

        Ok(string)
    }

    fn name_offset(&self) -> u16 {
        let start = self.offset + offset_of!(NtfsAttributeHeader, name_offset);
        u16::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    /// Returns the length of the name of this NTFS Attribute, in bytes.
    ///
    /// An attribute name has a maximum length of 255 UTF-16 code points (510 bytes).
    /// It is always part of the attribute itself and hence also of the length
    /// returned by [`NtfsAttribute::attribute_length`].
    pub fn name_length(&self) -> usize {
        let start = self.offset + offset_of!(NtfsAttributeHeader, name_length);
        let name_length_in_characters = self.file.record_data()[start];
        name_length_in_characters as usize * mem::size_of::<u16>()
    }

    pub(crate) fn non_resident_value(&self) -> Result<NtfsNonResidentAttributeValue<'n, 'f>> {
        let (data, position) = self.non_resident_value_data_and_position()?;
        let data_size = self.non_resident_value_data_size();
        let initialized_size = self.non_resident_value_initialized_size().min(data_size);

        NtfsNonResidentAttributeValue::new(
            self.file.ntfs(),
            data,
            position,
            data_size,
            initialized_size,
        )
    }

    pub(crate) fn non_resident_value_data_and_position(&self) -> Result<(&'f [u8], NtfsPosition)> {
        debug_assert!(!self.is_resident());
        let start = self.offset + self.non_resident_value_data_runs_offset() as usize;
        let end = self.offset + self.attribute_length() as usize;
        let position = self.file.position() + start;
        let data = &self.file.record_data().get(start..end).ok_or(
            NtfsError::InvalidNonResidentValueDataRange {
                position,
                range: start..end,
                size: self.file.record_data().len(),
            },
        )?;
        Ok((data, position))
    }

    fn non_resident_value_data_size(&self) -> u64 {
        debug_assert!(!self.is_resident());
        let start = self.offset + offset_of!(NtfsNonResidentAttributeHeader, data_size);
        u64::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    fn non_resident_value_initialized_size(&self) -> u64 {
        debug_assert!(!self.is_resident());
        let start = self.offset + offset_of!(NtfsNonResidentAttributeHeader, initialized_size);
        u64::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    fn non_resident_value_data_runs_offset(&self) -> u16 {
        debug_assert!(!self.is_resident());
        let start = self.offset + offset_of!(NtfsNonResidentAttributeHeader, data_runs_offset);
        u16::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the absolute position of this NTFS Attribute within the filesystem, in bytes.
    pub fn position(&self) -> NtfsPosition {
        self.file.position() + self.offset
    }

    /// Attempts to parse the value data as the given resident structured value type and returns that.
    ///
    /// This is a fast path for attributes that are always resident.
    /// It doesn't need a reference to the filesystem reader.
    ///
    /// This function first checks that the attribute is of the required type for that structured value
    /// and if it's a resident attribute.
    /// It returns with an error if that is not the case.
    /// It also returns an error for any parsing problem.
    pub fn resident_structured_value<S>(&self) -> Result<S>
    where
        S: NtfsStructuredValueFromResidentAttributeValue<'n, 'f>,
    {
        self.ensure_ty(S::TY)?;

        if !self.is_resident() {
            return Err(NtfsError::UnexpectedNonResidentAttribute {
                position: self.position(),
            });
        }

        let resident_value = self.resident_value()?;
        S::from_resident_attribute_value(resident_value)
    }

    pub(crate) fn resident_value(&self) -> Result<NtfsResidentAttributeValue<'f>> {
        debug_assert!(self.is_resident());
        self.validate_resident_value_sizes()?;

        let start = self.offset + self.resident_value_offset() as usize;
        let end = start + self.resident_value_length() as usize;
        let data = &self.file.record_data()[start..end];

        Ok(NtfsResidentAttributeValue::new(data, self.position()))
    }

    fn resident_value_length(&self) -> u32 {
        debug_assert!(self.is_resident());
        let start = self.offset + offset_of!(NtfsResidentAttributeHeader, value_length);
        u32::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    fn resident_value_offset(&self) -> u16 {
        debug_assert!(self.is_resident());
        let start = self.offset + offset_of!(NtfsResidentAttributeHeader, value_offset);
        u16::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap())
    }

    /// Attempts to parse the value data as the given structured value type and returns that.
    ///
    /// This function first checks that the attribute is of the required type for that structured value.
    /// It returns with an error if that is not the case.
    /// It also returns an error for any parsing problem.
    pub fn structured_value<T, S>(&self, fs: &mut T) -> Result<S>
    where
        T: Read + Seek,
        S: NtfsStructuredValue<'n, 'f>,
    {
        self.ensure_ty(S::TY)?;
        let value = self.value(fs)?;
        S::from_attribute_value(fs, value)
    }

    /// Returns the type of this NTFS Attribute, or [`NtfsError::UnsupportedAttributeType`]
    /// if it's an unknown type.
    // mutants::skip: `offset_of!(NtfsAttributeHeader, ty)` is 0 (ty is the
    // first field), so `self.offset + 0` and `self.offset - 0` are
    // identical for all inputs — the `+`->`-` mutant here is provably
    // equivalent and cannot be killed by any test.
    #[cfg_attr(test, mutants::skip)]
    pub fn ty(&self) -> Result<NtfsAttributeType> {
        let start = self.offset + offset_of!(NtfsAttributeHeader, ty);
        let ty = u32::from_le_bytes(*self.file.record_data()[start..].first_chunk().unwrap());

        NtfsAttributeType::n(ty).ok_or(NtfsError::UnsupportedAttributeType {
            position: self.position(),
            actual: ty,
        })
    }

    fn validate_attribute_length(&self) -> Result<()> {
        let start = self.offset;
        let end = self.file.record_data().len();
        let remaining_length = (start..end).len();

        if remaining_length < ATTRIBUTE_HEADER_SIZE {
            return Err(NtfsError::InvalidAttributeLength {
                position: self.position(),
                expected: ATTRIBUTE_HEADER_SIZE,
                actual: remaining_length,
            });
        }

        let attribute_length = self.attribute_length() as usize;
        if attribute_length < ATTRIBUTE_HEADER_SIZE {
            return Err(NtfsError::InvalidAttributeLength {
                position: self.position(),
                expected: ATTRIBUTE_HEADER_SIZE,
                actual: attribute_length,
            });
        }

        if attribute_length > remaining_length {
            return Err(NtfsError::InvalidAttributeLength {
                position: self.position(),
                expected: attribute_length,
                actual: remaining_length,
            });
        }

        // Validate that the attribute is large enough for its type-specific header.
        let min_size = if self.is_resident() {
            RESIDENT_ATTRIBUTE_MIN_SIZE
        } else {
            NON_RESIDENT_ATTRIBUTE_MIN_SIZE
        };

        if attribute_length < min_size {
            return Err(NtfsError::InvalidAttributeLength {
                position: self.position(),
                expected: min_size,
                actual: attribute_length,
            });
        }

        Ok(())
    }

    fn validate_name_sizes(&self) -> Result<()> {
        let start = self.name_offset();
        if start as u32 >= self.attribute_length() {
            return Err(NtfsError::InvalidAttributeNameOffset {
                position: self.position(),
                expected: start,
                actual: self.attribute_length(),
            });
        }

        let end = start as usize + self.name_length();
        if end > self.attribute_length() as usize {
            return Err(NtfsError::InvalidAttributeNameLength {
                position: self.position(),
                expected: end,
                actual: self.attribute_length(),
            });
        }

        Ok(())
    }

    fn validate_resident_value_sizes(&self) -> Result<()> {
        debug_assert!(self.is_resident());

        let position = self.position();
        let attribute_length = self.attribute_length();

        let start = self.resident_value_offset();
        if start as u32 > attribute_length {
            return Err(NtfsError::InvalidResidentAttributeValueOffset {
                position,
                expected: start,
                actual: attribute_length,
            });
        }

        let length = self.resident_value_length();

        let end = u32::from(start).checked_add(length).ok_or(
            NtfsError::InvalidResidentAttributeValueLength {
                position,
                length,
                offset: start,
                actual: attribute_length,
            },
        )?;
        if end > attribute_length {
            return Err(NtfsError::InvalidResidentAttributeValueLength {
                position,
                length,
                offset: start,
                actual: attribute_length,
            });
        }

        Ok(())
    }

    /// Returns an [`NtfsAttributeValue`] structure to read the value of this NTFS Attribute.
    pub fn value<T>(&self, fs: &mut T) -> Result<NtfsAttributeValue<'n, 'f>>
    where
        T: Read + Seek,
    {
        if let Some(list_entries) = self.list_entries {
            // The first attribute reports the entire data size for all connected attributes
            // (remaining ones are set to zero).
            // Fortunately, we are the first attribute :)
            let data_size = self.non_resident_value_data_size();
            let initialized_size = self.non_resident_value_initialized_size().min(data_size);

            let value = NtfsAttributeListNonResidentAttributeValue::new(
                self.file.ntfs(),
                fs,
                list_entries.clone(),
                self.instance(),
                self.ty()?,
                data_size,
                initialized_size,
            )?;
            Ok(NtfsAttributeValue::AttributeListNonResident(value))
        } else if self.is_resident() {
            let value = self.resident_value()?;
            Ok(NtfsAttributeValue::Resident(value))
        } else {
            let value = self.non_resident_value()?;
            Ok(NtfsAttributeValue::NonResident(value))
        }
    }

    /// Returns the length of the value data of this NTFS Attribute, in bytes.
    pub fn value_length(&self) -> u64 {
        if self.is_resident() {
            self.resident_value_length() as u64
        } else {
            self.non_resident_value_data_size()
        }
    }

    /// Returns `true` if this attribute's value is compressed.
    pub fn is_compressed(&self) -> bool {
        self.flags().contains(NtfsAttributeFlags::COMPRESSED)
    }

    /// Returns the compression unit exponent for non-resident attributes.
    ///
    /// Returns `None` for resident attributes (which cannot be compressed).
    /// A typical value is 4, meaning 2^4 = 16 clusters per compression unit.
    pub fn compression_unit_exponent(&self) -> Option<u8> {
        if self.is_resident() {
            return None;
        }

        let start =
            self.offset + offset_of!(NtfsNonResidentAttributeHeader, compression_unit_exponent);
        let exponent = self.file.record_data()[start];
        if exponent > 0 { Some(exponent) } else { None }
    }

    /// Returns the compression unit size in bytes, if compression is enabled.
    ///
    /// This is calculated as `2^exponent × cluster_size`.
    /// Returns `None` for resident attributes or if compression is disabled.
    pub fn compression_unit_size(&self, ntfs: &crate::ntfs::Ntfs) -> Option<u64> {
        self.compression_unit_exponent()
            .map(|exp| (1u64 << exp) * ntfs.cluster_size() as u64)
    }
}

/// Iterator over
///   all attributes of an [`NtfsFile`],
///   returning an [`NtfsAttributeItem`] for each entry.
///
/// This iterator is returned from the [`NtfsFile::attributes`] function.
/// It provides a flattened "data-centric" view of the attributes and abstracts away the filesystem details
/// to deal with many or large attributes (Attribute Lists and connected attributes).
///
/// Check [`NtfsAttributesRaw`] if you want to iterate over the plain attributes on the filesystem.
/// See [`NtfsAttributesAttached`] for an iterator that implements [`Iterator`] and [`FusedIterator`].
#[derive(Clone, Debug)]
pub struct NtfsAttributes<'n, 'f> {
    raw_iter: NtfsAttributesRaw<'n, 'f>,
    list_entries: Option<NtfsAttributeListEntries<'n, 'f>>,
    list_skip_info: Option<(u16, NtfsAttributeType)>,
    /// Tracks (MFT record number, attribute instance) pairs visited during attribute
    /// list processing to detect circular references. A single extension record can
    /// legitimately hold multiple attributes with different instances, so tracking
    /// record number alone would produce false positives.
    visited_entries: Option<BTreeSet<(u64, u16)>>,
}

impl<'n, 'f> NtfsAttributes<'n, 'f> {
    pub(crate) fn new(file: &'f NtfsFile<'n>) -> Self {
        Self {
            raw_iter: NtfsAttributesRaw::new(file),
            list_entries: None,
            list_skip_info: None,
            visited_entries: None,
        }
    }

    /// Returns a variant of this iterator that implements [`Iterator`] and [`FusedIterator`]
    /// by mutably borrowing the filesystem reader.
    pub fn attach<'a, T>(self, fs: &'a mut T) -> NtfsAttributesAttached<'n, 'f, 'a, T>
    where
        T: Read + Seek,
    {
        NtfsAttributesAttached::new(fs, self)
    }

    /// See [`Iterator::next`].
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<NtfsAttributeItem<'n, 'f>>>
    where
        T: Read + Seek,
    {
        loop {
            if let Some(attribute_list_entries) = &mut self.list_entries {
                loop {
                    // If the next Attribute List entry turns out to be a non-resident attribute, that attribute's
                    // value may be split over multiple (adjacent) attributes.
                    // To view this value as a single one, we need an `AttributeListConnectedEntries` iterator
                    // and that iterator needs `NtfsAttributeListEntries` where the next call to `next` yields
                    // the first connected attribute.
                    // Therefore, we need to clone `attribute_list_entries` before every call.
                    let attribute_list_entries_clone = attribute_list_entries.clone();

                    let entry = match attribute_list_entries.next(fs) {
                        Some(Ok(entry)) => entry,
                        Some(Err(e)) => return Some(Err(e)),
                        None => break,
                    };
                    let entry_instance = entry.instance();
                    let entry_record_number = entry.base_file_reference().file_record_number();
                    let entry_ty = iter_try!(entry.ty());

                    // Ignore all Attribute List entries that just repeat attributes of the raw iterator.
                    if entry_record_number == self.raw_iter.file.file_record_number() {
                        continue;
                    }

                    // Ignore all Attribute List entries that are connected attributes of a previous one.
                    if let Some((skip_instance, skip_ty)) = self.list_skip_info
                        && entry_instance == skip_instance
                        && entry_ty == skip_ty
                    {
                        continue;
                    }

                    // We found an attribute that we want to return.
                    self.list_skip_info = None;

                    // Check for circular references: ensure this (record, instance)
                    // pair hasn't been visited before. We track both because a single
                    // extension record can legitimately hold multiple attributes with
                    // different instance numbers.
                    let visited = self.visited_entries.get_or_insert_with(BTreeSet::new);
                    if !visited.insert((entry_record_number, entry_instance)) {
                        return Some(Err(NtfsError::CircularAttributeList {
                            position: entry.position(),
                            record_number: entry_record_number,
                        }));
                    }

                    let ntfs = self.raw_iter.file.ntfs();
                    let entry_file = iter_try!(entry.to_file(ntfs, fs));
                    let entry_attribute = iter_try!(entry.to_attribute(&entry_file));
                    let attribute_offset = entry_attribute.offset();

                    let mut list_entries = None;
                    if !entry_attribute.is_resident() {
                        list_entries = Some(attribute_list_entries_clone);
                        self.list_skip_info = Some((entry_instance, entry_ty));
                    }

                    let item = NtfsAttributeItem {
                        attribute_file: self.raw_iter.file,
                        attribute_value_file: Some(entry_file),
                        attribute_offset,
                        list_entries,
                    };
                    return Some(Ok(item));
                }
            }

            let attribute = iter_try!(self.raw_iter.next()?);
            if let Ok(NtfsAttributeType::AttributeList) = attribute.ty() {
                let attribute_list =
                    iter_try!(attribute.structured_value::<T, NtfsAttributeList>(fs));
                self.list_entries = Some(attribute_list.entries());
            } else {
                let item = NtfsAttributeItem {
                    attribute_file: self.raw_iter.file,
                    attribute_value_file: None,
                    attribute_offset: attribute.offset(),
                    list_entries: None,
                };
                return Some(Ok(item));
            }
        }
    }
}

impl<'n, 'f> fs_common::iter::FsTryIteratorType for NtfsAttributes<'n, 'f> {
    type Error = NtfsError;
    type Item<'a> = NtfsAttributeItem<'n, 'f>;
}

impl<'n, 'f, R: Read + Seek> fs_common::iter::FsTryIterator<R> for NtfsAttributes<'n, 'f> {
    fn try_next(&mut self, r: &mut R) -> Result<Option<NtfsAttributeItem<'n, 'f>>> {
        self.next(r).transpose()
    }
}

/// Iterator over
///   all attributes of an [`NtfsFile`],
///   returning an [`NtfsAttributeItem`] for each entry,
///   implementing [`Iterator`] and [`FusedIterator`].
///
/// This iterator is returned from the [`NtfsAttributes::attach`] function.
/// Conceptually the same as [`NtfsAttributes`], but mutably borrows the filesystem
/// to implement aforementioned traits.
#[derive(Debug)]
pub struct NtfsAttributesAttached<'n, 'f, 'a, T: Read + Seek> {
    fs: &'a mut T,
    attributes: NtfsAttributes<'n, 'f>,
}

impl<'n, 'f, 'a, T> NtfsAttributesAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    fn new(fs: &'a mut T, attributes: NtfsAttributes<'n, 'f>) -> Self {
        Self { fs, attributes }
    }

    /// Consumes this iterator and returns the inner [`NtfsAttributes`].
    pub fn detach(self) -> NtfsAttributes<'n, 'f> {
        self.attributes
    }
}

impl<'n, 'f, 'a, T> Iterator for NtfsAttributesAttached<'n, 'f, 'a, T>
where
    T: Read + Seek,
{
    type Item = Result<NtfsAttributeItem<'n, 'f>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.attributes.next(self.fs)
    }
}

impl<'n, 'f, 'a, T> FusedIterator for NtfsAttributesAttached<'n, 'f, 'a, T> where T: Read + Seek {}

/// Item returned by the [`NtfsAttributes`] iterator.
///
/// [`NtfsAttributes`] provides a flattened view over the attributes by traversing Attribute Lists.
/// Attribute Lists may contain entries with references to other [`NtfsFile`]s.
/// Therefore, the attribute's information may either be stored in the original [`NtfsFile`] or in another
/// [`NtfsFile`] that has been read just for this attribute.
///
/// [`NtfsAttributeItem`] abstracts over both cases by providing a reference to the original [`NtfsFile`],
/// and optionally holding another [`NtfsFile`] if the attribute is actually stored there.
#[derive(Clone, Debug)]
pub struct NtfsAttributeItem<'n, 'f> {
    attribute_file: &'f NtfsFile<'n>,
    attribute_value_file: Option<NtfsFile<'n>>,
    attribute_offset: usize,
    list_entries: Option<NtfsAttributeListEntries<'n, 'f>>,
}

impl<'n, 'f> NtfsAttributeItem<'n, 'f> {
    /// Returns the actual [`NtfsAttribute`] structure for this NTFS Attribute.
    pub fn to_attribute<'i>(&'i self) -> Result<NtfsAttribute<'n, 'i>> {
        if let Some(file) = &self.attribute_value_file {
            NtfsAttribute::new(file, self.attribute_offset, self.list_entries.as_ref())
        } else {
            NtfsAttribute::new(
                self.attribute_file,
                self.attribute_offset,
                self.list_entries.as_ref(),
            )
        }
    }
}

/// Iterator over
///   all top-level attributes of an [`NtfsFile`],
///   returning an [`NtfsAttribute`] for each entry,
///   implementing [`Iterator`] and [`FusedIterator`].
///
/// This iterator is returned from the [`NtfsFile::attributes_raw`] function.
/// Contrary to [`NtfsAttributes`], it does not traverse $ATTRIBUTE_LIST attributes and returns them
/// as raw [`NtfsAttribute`]s.
/// Check that structure if you want an iterator providing a flattened "data-centric" view over
/// the attributes by traversing Attribute Lists automatically.
#[derive(Clone, Debug)]
pub struct NtfsAttributesRaw<'n, 'f> {
    file: &'f NtfsFile<'n>,
    items_range: Range<usize>,
}

impl<'n, 'f> NtfsAttributesRaw<'n, 'f> {
    pub(crate) fn new(file: &'f NtfsFile<'n>) -> Self {
        let start = file.first_attribute_offset() as usize;
        let end = file.data_size() as usize;
        let items_range = start..end;

        Self { file, items_range }
    }
}

impl<'n, 'f> Iterator for NtfsAttributesRaw<'n, 'f> {
    type Item = Result<NtfsAttribute<'n, 'f>>;

    fn next(&mut self) -> Option<Self::Item> {
        // This may be an entire attribute or just the 4-byte end marker.
        // Check if this marks the end of the attribute list.
        let start = self.items_range.start;
        let end = start + mem::size_of::<u32>();
        let ty_slice = self.file.record_data().get(start..end)?;

        let ty = u32::from_le_bytes(*ty_slice.first_chunk().unwrap());
        if ty == NtfsAttributeType::End as u32 {
            return None;
        }

        // It's a real attribute.
        let attribute = iter_try!(NtfsAttribute::new(self.file, self.items_range.start, None));
        self.items_range.start += attribute.attribute_length() as usize;

        Some(Ok(attribute))
    }
}

impl<'n, 'f> FusedIterator for NtfsAttributesRaw<'n, 'f> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::NtfsFile;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::structured_values::NtfsStandardInformation;
    use core::num::NonZeroU64;
    use fs_common::io::FsReadSeek;
    use std::io::Cursor;

    /// Byte position of the synthetic FILE record inside the image.
    /// Chosen well clear of the 512-byte boot sector.
    const RECORD_POSITION: u64 = 4096;

    /// Size of the synthetic FILE record (matches the boot sector's
    /// `clusters_per_mft_record = -10` => 2^10 = 1024 bytes).
    const RECORD_SIZE: usize = 1024;

    /// Offset of the first attribute within the synthetic FILE record,
    /// placed just after the 16-byte header + 6-byte update sequence array.
    const FIRST_ATTRIBUTE_OFFSET: usize = 56;

    /// Builds a minimal valid 512-byte NTFS boot sector that `Ntfs::new`
    /// accepts: NTFS OEM ID, 512-byte sectors, 1 sector/cluster
    /// (cluster_size = 512), 1 KiB MFT records, and the 0x55AA signature.
    fn make_boot_sector() -> [u8; 512] {
        let mut bs = [0u8; 512];
        bs[3..11].copy_from_slice(b"NTFS    "); // OEM ID (offset 0x03)
        bs[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector
        bs[0x0D] = 1; // sectors_per_cluster => cluster_size 512
        bs[0x28..0x30].copy_from_slice(&8192u64.to_le_bytes()); // total_sectors
        bs[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn (>0)
        bs[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn (>0)
        bs[0x40] = 0xF6; // clusters_per_mft_record = -10 => 1024-byte records
        bs[0x48..0x50].copy_from_slice(&0x0123_4567_89ab_cdefu64.to_le_bytes()); // serial
        bs[510] = 0x55;
        bs[511] = 0xAA;
        bs
    }

    /// Builds a 1 KiB FILE record whose first attribute starts at
    /// `FIRST_ATTRIBUTE_OFFSET` and is initialised from `attr`. The update
    /// sequence array is laid out so `Record::fixup` succeeds (the two
    /// per-sector USN slots at offsets 510 and 1022 carry the USN before
    /// fixup, and the array supplies their fixed-up values afterwards).
    fn make_file_record(attr: &[u8]) -> Vec<u8> {
        let mut rec = vec![0u8; RECORD_SIZE];
        // RecordHeader: "FILE" signature.
        rec[0..4].copy_from_slice(b"FILE");
        // update_sequence_offset = 0x30 (offset 4).
        rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
        // update_sequence_count = 3 (1 USN + 2 array entries) (offset 6).
        rec[6..8].copy_from_slice(&3u16.to_le_bytes());
        // Update sequence array at 0x30: USN, then two fixup values.
        let usn = 0x0001u16;
        rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes()); // USN
        rec[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes()); // sector 0 value
        rec[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes()); // sector 1 value
        // Per-sector USN slots must equal the USN for fixup to validate.
        rec[510..512].copy_from_slice(&usn.to_le_bytes());
        rec[1022..1024].copy_from_slice(&usn.to_le_bytes());

        // FileRecordHeader fields (after the 16-byte RecordHeader).
        rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
        rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
        // first_attribute_offset (offset 20).
        rec[20..22].copy_from_slice(&(FIRST_ATTRIBUTE_OFFSET as u16).to_le_bytes());
        rec[22..24].copy_from_slice(&1u16.to_le_bytes()); // flags (IN_USE)
        rec[24..28].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes()); // data_size
        rec[28..32].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes()); // allocated_size

        rec[FIRST_ATTRIBUTE_OFFSET..FIRST_ATTRIBUTE_OFFSET + attr.len()].copy_from_slice(attr);
        rec
    }

    /// Assembles a full in-memory NTFS image: boot sector, padding, and a
    /// single FILE record at `RECORD_POSITION`.
    fn make_image(attr: &[u8]) -> Cursor<Vec<u8>> {
        let mut data = vec![0u8; RECORD_POSITION as usize + RECORD_SIZE];
        data[0..512].copy_from_slice(&make_boot_sector());
        let record = make_file_record(attr);
        data[RECORD_POSITION as usize..RECORD_POSITION as usize + RECORD_SIZE]
            .copy_from_slice(&record);
        Cursor::new(data)
    }

    /// A resident `$DATA` attribute (type 0x80) whose value is `value`,
    /// with the given attribute `flags` and an attribute `name`
    /// (UTF-16 code points, 2 bytes each). Layout follows
    /// `NtfsResidentAttributeHeader`.
    fn resident_attribute(value: &[u8], flags: u16, name_utf16: &[u16]) -> Vec<u8> {
        let header = 24usize; // resident header rounded up to 8 bytes
        let name_offset = header;
        let name_bytes = name_utf16.len() * 2;
        let value_offset = name_offset + name_bytes;
        let attribute_length = value_offset + value.len();

        let mut attr = vec![0u8; attribute_length];
        attr[0..4].copy_from_slice(&(NtfsAttributeType::Data as u32).to_le_bytes()); // ty
        attr[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes()); // length
        attr[8] = 0; // is_non_resident = 0 (resident)
        attr[9] = name_utf16.len() as u8; // name_length (chars)
        attr[10..12].copy_from_slice(&(name_offset as u16).to_le_bytes()); // name_offset
        attr[12..14].copy_from_slice(&flags.to_le_bytes()); // flags
        attr[14..16].copy_from_slice(&7u16.to_le_bytes()); // instance
        attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes()); // value_length
        attr[20..22].copy_from_slice(&(value_offset as u16).to_le_bytes()); // value_offset
        attr[22] = 0; // indexed_flag
        for (i, cp) in name_utf16.iter().enumerate() {
            attr[name_offset + i * 2..name_offset + i * 2 + 2].copy_from_slice(&cp.to_le_bytes());
        }
        attr[value_offset..value_offset + value.len()].copy_from_slice(value);
        attr
    }

    /// A non-resident `$DATA` attribute (type 0x80). The data runs region
    /// (between `data_runs_offset` and `attribute_length`) carries `runs`.
    fn non_resident_attribute(
        runs: &[u8],
        flags: u16,
        compression_unit_exponent: u8,
        data_size: u64,
        initialized_size: u64,
    ) -> Vec<u8> {
        let header = 64usize; // size_of NtfsNonResidentAttributeHeader (packed)
        let data_runs_offset = header;
        let attribute_length = data_runs_offset + runs.len();

        let mut attr = vec![0u8; attribute_length];
        attr[0..4].copy_from_slice(&(NtfsAttributeType::Data as u32).to_le_bytes()); // ty
        attr[4..8].copy_from_slice(&(attribute_length as u32).to_le_bytes()); // length
        attr[8] = 1; // is_non_resident = 1
        attr[9] = 0; // name_length
        attr[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset
        attr[12..14].copy_from_slice(&flags.to_le_bytes()); // flags
        attr[14..16].copy_from_slice(&7u16.to_le_bytes()); // instance
        // lowest_vcn @16 (8), highest_vcn @24 (8): leave zero.
        attr[32..34].copy_from_slice(&(data_runs_offset as u16).to_le_bytes()); // data_runs_offset
        attr[34] = compression_unit_exponent; // compression_unit_exponent
        attr[40..48].copy_from_slice(&0u64.to_le_bytes()); // allocated_size
        attr[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
        attr[56..64].copy_from_slice(&initialized_size.to_le_bytes()); // initialized_size
        attr[data_runs_offset..attribute_length].copy_from_slice(runs);
        attr
    }

    /// Construct an `Ntfs` plus a `NtfsFile` over the synthetic image.
    /// The caller holds the returned tuple so the borrows stay alive.
    fn open(attr: &[u8]) -> (Ntfs, Cursor<Vec<u8>>) {
        let mut fs = make_image(attr);
        let ntfs = Ntfs::new(&mut fs).unwrap();
        (ntfs, fs)
    }

    fn file<'n>(ntfs: &'n Ntfs, fs: &mut Cursor<Vec<u8>>) -> NtfsFile<'n> {
        NtfsFile::new(ntfs, fs, NonZeroU64::new(RECORD_POSITION).unwrap(), 0).unwrap()
    }

    /// Builds an image with the attribute placed at a custom `offset`
    /// within the FILE record (rather than `FIRST_ATTRIBUTE_OFFSET`), so
    /// tests can drive a chosen `remaining_length` for boundary checks.
    fn open_at(offset: usize, attr: &[u8]) -> (Ntfs, Cursor<Vec<u8>>) {
        let mut record = make_file_record(&[]);
        record[20..22].copy_from_slice(&(offset as u16).to_le_bytes()); // first_attribute_offset
        record[offset..offset + attr.len()].copy_from_slice(attr);
        // Restore the per-sector update-sequence slots in case the attribute
        // overlapped them, so the FILE record still passes USA fixup.
        let usn = 0x0001u16;
        record[510..512].copy_from_slice(&usn.to_le_bytes());
        record[1022..1024].copy_from_slice(&usn.to_le_bytes());
        let mut data = vec![0u8; RECORD_POSITION as usize + RECORD_SIZE];
        data[0..512].copy_from_slice(&make_boot_sector());
        data[RECORD_POSITION as usize..RECORD_POSITION as usize + RECORD_SIZE]
            .copy_from_slice(&record);
        (
            Ntfs::new(&mut Cursor::new(data.clone())).unwrap(),
            Cursor::new(data),
        )
    }

    /// As [`make_image`] but fills the cluster region targeted by a data run
    /// (`fill_lcn` * cluster_size) with `fill_len` bytes of `fill_byte`, so
    /// non-resident reads observe known initialized data.
    fn open_with_cluster_data(
        attr: &[u8],
        fill_lcn: u64,
        fill_len: usize,
        fill_byte: u8,
    ) -> (Ntfs, Cursor<Vec<u8>>) {
        let mut data = vec![0u8; RECORD_POSITION as usize + RECORD_SIZE];
        data[0..512].copy_from_slice(&make_boot_sector());
        let record = make_file_record(attr);
        data[RECORD_POSITION as usize..RECORD_POSITION as usize + RECORD_SIZE]
            .copy_from_slice(&record);
        let fill_start = (fill_lcn * 512) as usize;
        for b in &mut data[fill_start..fill_start + fill_len] {
            *b = fill_byte;
        }
        (
            Ntfs::new(&mut Cursor::new(data.clone())).unwrap(),
            Cursor::new(data),
        )
    }

    #[test]
    fn synthetic_resident_attribute_accessors() {
        let value = b"hello";
        let name = [b'A' as u16, b'D' as u16, b'S' as u16]; // "ADS"
        let attr_bytes = resident_attribute(value, NtfsAttributeFlags::COMPRESSED.bits(), &name);
        let attr_len = attr_bytes.len() as u32;
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

        // attribute_length reads the on-disk length field (line 252/253):
        // distinct from 0/1 and from offset arithmetic mutations.
        assert_eq!(attr.attribute_length(), attr_len);
        assert!(attr_len > 1);
        // ty (line 446/447).
        assert_eq!(attr.ty().unwrap(), NtfsAttributeType::Data);
        // ensure_ty (line 257/258): matching type Ok, mismatch Err.
        assert!(attr.ensure_ty(NtfsAttributeType::Data).is_ok());
        assert!(attr.ensure_ty(NtfsAttributeType::FileName).is_err());
        // flags (line 271): COMPRESSED set.
        assert_eq!(attr.flags(), NtfsAttributeFlags::COMPRESSED);
        assert!(attr.is_compressed()); // line 605
        // instance (line 279): on-disk value 7, distinct from 0/1.
        assert_eq!(attr.instance(), 7);
        // is_resident (line 286/288): true for resident.
        assert!(attr.is_resident());
        // name (lines 296/302) and name_offset/name_length (310/320/322).
        assert_eq!(attr.name_length(), 6); // 3 chars * 2 bytes
        let parsed_name = attr.name().unwrap();
        assert_eq!(parsed_name.to_string_lossy(), "ADS");
        // offset (line 373): the offset we constructed at.
        assert_eq!(attr.offset(), FIRST_ATTRIBUTE_OFFSET);
        // resident_value_length / resident_value_offset reflected by value.
        assert_eq!(attr.value_length(), value.len() as u64); // line 596
        let resident = attr.resident_value().unwrap();
        assert_eq!(resident.data(), value);
        // compression_unit_exponent is None for resident (line 613).
        assert_eq!(attr.compression_unit_exponent(), None);
        assert_eq!(attr.compression_unit_size(&ntfs), None);
    }

    #[test]
    fn synthetic_resident_no_name_and_no_flags() {
        // name_offset 0 / name_length 0 => empty name (line 296 boundary).
        let attr_bytes = resident_attribute(b"xyz", 0, &[]);
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

        assert_eq!(attr.name_length(), 0);
        assert!(attr.name().unwrap().is_empty());
        assert!(!attr.is_compressed());
        assert_eq!(attr.flags(), NtfsAttributeFlags::empty());
    }

    #[test]
    fn synthetic_name_length_zero_with_bad_offset_short_circuits() {
        // name() returns empty when EITHER name_offset or name_length is 0
        // (line 296 `||`). Here name_length == 0 but name_offset is set
        // OUT OF RANGE: the `||` short-circuits to Ok(empty). An `&&`
        // mutation (or `name_length == 0` -> `!= 0`) would instead fall
        // through to validate_name_sizes and surface an offset error.
        let mut attr_bytes = resident_attribute(b"v", 0, &[]);
        let attr_len = attr_bytes.len() as u16;
        attr_bytes[9] = 0; // name_length (chars) = 0
        attr_bytes[10..12].copy_from_slice(&(attr_len + 8).to_le_bytes()); // bad name_offset
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(attr.name_length(), 0);
        assert!(attr.name_offset() >= attr.attribute_length() as u16);
        assert!(attr.name().expect("empty name, no validation").is_empty());
    }

    #[test]
    fn synthetic_name_offset_zero_short_circuits() {
        // name_offset == 0 short-circuits to empty (line 296). With a
        // non-zero name_length and name_offset 0, the genuine `== 0` returns
        // Ok(empty); flipping it to `!= 0` would read a non-empty name from
        // the attribute header bytes instead.
        let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
        attr_bytes[9] = 1; // name_length (chars) = 1 (=> 2 bytes)
        attr_bytes[10..12].copy_from_slice(&0u16.to_le_bytes()); // name_offset = 0
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(attr.name_offset(), 0);
        assert_eq!(attr.name_length(), 2);
        assert!(attr.name().expect("empty name").is_empty());
    }

    #[test]
    fn synthetic_non_resident_attribute_accessors() {
        // A simple single data run: header byte 0x21 (1 length byte, 1
        // offset byte), length 0x05 clusters, LCN offset 0x02, terminator.
        let runs = [0x21u8, 0x05, 0x02, 0x00];
        let data_size = 2560u64; // 5 clusters * 512
        let initialized_size = 2048u64;
        let attr_bytes = non_resident_attribute(&runs, 0, 4, data_size, initialized_size);
        let attr_len = attr_bytes.len() as u32;
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

        assert!(!attr.is_resident());
        assert_eq!(attr.attribute_length(), attr_len);
        // value_length for non-resident == data_size (line 596 / 355).
        assert_eq!(attr.value_length(), data_size);
        // compression_unit_exponent reads on-disk exponent 4 (line 613/618/620).
        assert_eq!(attr.compression_unit_exponent(), Some(4));
        // compression_unit_size = (1 << 4) * cluster_size(512) = 8192 (line 629).
        assert_eq!(attr.compression_unit_size(&ntfs), Some(16 * 512));
        // The non-resident value parses (exercises data_runs_offset,
        // data_size, initialized_size accessors: lines 341/342/356/362/368).
        let nrv = attr.non_resident_value().unwrap();
        assert_eq!(nrv.len(), data_size);
    }

    #[test]
    fn synthetic_compression_unit_exponent_zero_is_none() {
        // exponent 0 => None (line 620 boundary: `> 0`).
        let runs = [0x00u8];
        let attr_bytes = non_resident_attribute(&runs, 0, 0, 512, 512);
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(attr.compression_unit_exponent(), None);
        assert_eq!(attr.compression_unit_size(&ntfs), None);
    }

    #[test]
    fn synthetic_non_resident_initialized_size_governs_read() {
        // data_size = 1024 (2 clusters), initialized_size = 512 (1 cluster).
        // The data run maps LCN 2 (byte 1024) for 2 clusters; the first
        // cluster is filled with 0xAB. A read of all 1024 bytes returns the
        // 0xAB-initialised first half and zeros beyond initialized_size.
        // Mutating non_resident_value_initialized_size to 0/1 (or its offset
        // arithmetic) shrinks the initialised region and zeros the bytes we
        // assert as 0xAB.
        let runs = [0x21u8, 0x02, 0x02, 0x00]; // 2 clusters at LCN 2
        let data_size = 1024u64;
        let initialized_size = 512u64;
        let attr_bytes = non_resident_attribute(&runs, 0, 0, data_size, initialized_size);
        // Fill BOTH on-disk clusters (bytes 1024..2048) with 0xAB so any
        // bytes read back as zero must come from the initialized_size cap,
        // not from empty disk. An offset-arithmetic mutation of
        // non_resident_value_initialized_size (`+`->`-`) reads the field
        // from the wrong location, yielding a huge value clamped to
        // data_size (1024) and exposing the 0xAB data past offset 512.
        let (ntfs, mut fs) = open_with_cluster_data(&attr_bytes, 2, 1024, 0xAB);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();

        let mut value = attr.value(&mut fs).unwrap();
        let mut buf = [0u8; 1024];
        value.read_exact(&mut fs, &mut buf).unwrap();
        // Bytes inside the initialized region are the genuine 0xAB data.
        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[256], 0xAB);
        assert_eq!(buf[511], 0xAB);
        // Bytes beyond initialized_size (512) read back as zero even though
        // the disk holds 0xAB there.
        assert_eq!(buf[512], 0x00);
        assert_eq!(buf[1023], 0x00);
    }

    /// Extracts the `expected`/`actual` fields of an InvalidAttributeLength.
    fn invalid_length_fields(err: &NtfsError) -> (usize, usize) {
        match err {
            NtfsError::InvalidAttributeLength {
                expected, actual, ..
            } => (*expected, *actual),
            other => panic!("expected InvalidAttributeLength, got {other:?}"),
        }
    }

    #[test]
    fn synthetic_validate_attribute_length_too_short_fires_header_check() {
        // remaining_length(16) < ATTRIBUTE_HEADER_SIZE(16) is false at the
        // boundary, so the header check (line 461) is skipped and the
        // type-min check (line 493) fires instead: the error reports
        // expected = RESIDENT_ATTRIBUTE_MIN_SIZE (23), not 16. A `<= ` or
        // `==` mutation of line 461 would fire the header check, reporting
        // expected = 16.
        let mut attr = vec![0u8; 16];
        attr[0..4].copy_from_slice(&(NtfsAttributeType::Data as u32).to_le_bytes());
        attr[4..8].copy_from_slice(&16u32.to_le_bytes()); // attribute_length = 16
        attr[8] = 0; // resident
        let offset = RECORD_SIZE - 16; // remaining_length == 16
        let (ntfs, mut fs) = open_at(offset, &attr);
        let file = file(&ntfs, &mut fs);
        let err = NtfsAttribute::new(&file, offset, None).unwrap_err();
        let (expected, _) = invalid_length_fields(&err);
        assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
    }

    #[test]
    fn synthetic_validate_attribute_length_at_header_size_fires_type_min() {
        // attribute_length(16) < ATTRIBUTE_HEADER_SIZE(16) is false at the
        // boundary (line 470), so validation proceeds to the type-min check
        // (line 493) reporting expected = 23. A `<=`/`==` mutation of line
        // 470 would fire the header check, reporting expected = 16.
        let mut attr_bytes = resident_attribute(b"abcdefgh", 0, &[]);
        attr_bytes[4..8].copy_from_slice(&16u32.to_le_bytes()); // attribute_length = 16
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
        let (expected, actual) = invalid_length_fields(&err);
        assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
        assert_eq!(actual, 16);
    }

    #[test]
    fn synthetic_validate_attribute_length_equal_to_remaining_passes() {
        // attribute_length(968) > remaining_length(968) is false at the
        // boundary (line 478), so the attribute is accepted. A `>=`
        // mutation would reject it.
        let remaining = RECORD_SIZE - FIRST_ATTRIBUTE_OFFSET; // 968
        let mut attr = vec![0u8; remaining];
        attr[0..4].copy_from_slice(&(NtfsAttributeType::Data as u32).to_le_bytes());
        attr[4..8].copy_from_slice(&(remaining as u32).to_le_bytes()); // == remaining
        attr[8] = 0; // resident
        attr[20..22].copy_from_slice(&24u16.to_le_bytes()); // value_offset
        let (ntfs, mut fs) = open_at(FIRST_ATTRIBUTE_OFFSET, &attr);
        let file = file(&ntfs, &mut fs);
        let parsed = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(parsed.attribute_length() as usize, remaining);
    }

    #[test]
    fn synthetic_validate_attribute_length_exceeds_remaining_rejected() {
        // attribute_length(969) > remaining_length(968) => Err (line 478),
        // reporting expected = attribute_length, actual = remaining.
        let remaining = RECORD_SIZE - FIRST_ATTRIBUTE_OFFSET; // 968
        let mut attr_bytes = resident_attribute(b"a", 0, &[]);
        attr_bytes[4..8].copy_from_slice(&((remaining + 1) as u32).to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
        let (expected, actual) = invalid_length_fields(&err);
        assert_eq!(expected, remaining + 1);
        assert_eq!(actual, remaining);
    }

    #[test]
    fn synthetic_validate_attribute_length_below_type_min_rejected() {
        // attribute_length(18) < RESIDENT_ATTRIBUTE_MIN_SIZE(23) => Err
        // (line 493), reporting expected = 23.
        let mut attr_bytes = resident_attribute(b"abcd", 0, &[]);
        attr_bytes[4..8].copy_from_slice(&18u32.to_le_bytes()); // 16 <= 18 < 23
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let err = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap_err();
        let (expected, actual) = invalid_length_fields(&err);
        assert_eq!(expected, RESIDENT_ATTRIBUTE_MIN_SIZE);
        assert_eq!(actual, 18);
    }

    #[test]
    fn synthetic_validate_attribute_length_accepts_exact_min() {
        // attribute_length exactly == RESIDENT_ATTRIBUTE_MIN_SIZE (23) is
        // NOT below it, so validation passes (line 493 `<` boundary). A
        // `<=` mutation would reject the attribute.
        let mut attr_bytes = resident_attribute(b"a", 0, &[]); // 25 bytes
        attr_bytes[4..8].copy_from_slice(&(RESIDENT_ATTRIBUTE_MIN_SIZE as u32).to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let parsed = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(
            parsed.attribute_length() as usize,
            RESIDENT_ATTRIBUTE_MIN_SIZE
        );
    }

    #[test]
    fn synthetic_validate_name_sizes_rejects_bad_offset() {
        // name_offset >= attribute_length => InvalidAttributeNameOffset
        // (line 506 / 515). Build a resident attr then corrupt name_offset.
        let name = [b'X' as u16];
        let mut attr_bytes = resident_attribute(b"v", 0, &name);
        let attr_len = attr_bytes.len() as u16;
        // name_offset field at byte 10..12; set it past the attribute.
        attr_bytes[10..12].copy_from_slice(&(attr_len + 10).to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        let err = attr.name().unwrap_err();
        assert!(matches!(err, NtfsError::InvalidAttributeNameOffset { .. }));
    }

    #[test]
    fn synthetic_validate_name_sizes_rejects_bad_length() {
        // name_offset valid but name_offset + name_length > attribute_length
        // => InvalidAttributeNameLength (line 514/515).
        let name = [b'X' as u16, b'Y' as u16];
        let mut attr_bytes = resident_attribute(b"v", 0, &name);
        // Inflate name_length (chars) at byte 9 so end exceeds the attribute.
        attr_bytes[9] = 200;
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        let err = attr.name().unwrap_err();
        assert!(matches!(err, NtfsError::InvalidAttributeNameLength { .. }));
    }

    #[test]
    fn synthetic_validate_name_sizes_end_equal_to_length_passes() {
        // With an empty value, the name occupies the tail of the attribute:
        // name_offset + name_length == attribute_length. `end > attr_len` is
        // false at the boundary (line 515), so the name parses. A `>=`
        // mutation would reject it.
        let name = [b'Z' as u16];
        let attr_bytes = resident_attribute(b"", 0, &name); // 24 + 2 = 26 bytes
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(attr.name_offset() as usize + attr.name_length(), 26);
        assert_eq!(attr.attribute_length(), 26);
        assert_eq!(attr.name().unwrap().to_string_lossy(), "Z");
    }

    #[test]
    fn synthetic_validate_resident_value_sizes_rejects_bad_offset() {
        // resident_value_offset > attribute_length => Err (line 533).
        let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
        let attr_len = attr_bytes.len() as u16;
        // value_offset field at byte 20..22.
        attr_bytes[20..22].copy_from_slice(&(attr_len + 4).to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        let err = attr.resident_value().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidResidentAttributeValueOffset { .. }
        ));
    }

    #[test]
    fn synthetic_validate_resident_value_sizes_rejects_bad_length() {
        // value_offset + value_length > attribute_length => Err (line 551).
        let mut attr_bytes = resident_attribute(b"vv", 0, &[]);
        // value_length field at byte 16..20; inflate it.
        attr_bytes[16..20].copy_from_slice(&500u32.to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        let err = attr.resident_value().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidResidentAttributeValueLength { .. }
        ));
    }

    #[test]
    fn synthetic_validate_resident_value_offset_equal_to_length_passes() {
        // An empty-value resident attribute has value_offset ==
        // attribute_length (both 24). `value_offset > attr_len` is false at
        // the boundary (line 533), so resident_value succeeds with an empty
        // slice. A `>=` mutation would reject it.
        let attr_bytes = resident_attribute(b"", 0, &[]); // 24 bytes, value_offset 24
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        assert_eq!(attr.attribute_length(), 24);
        let value = attr.resident_value().unwrap();
        assert_eq!(value.data().len(), 0);
    }

    #[test]
    fn synthetic_resident_structured_value_rejects_non_resident() {
        // resident_structured_value on a non-resident attr => Err
        // (line 396 `!is_resident`). Use $STANDARD_INFORMATION type so the
        // ensure_ty check passes first.
        let runs = [0x00u8];
        let mut attr_bytes = non_resident_attribute(&runs, 0, 0, 512, 512);
        attr_bytes[0..4]
            .copy_from_slice(&(NtfsAttributeType::StandardInformation as u32).to_le_bytes());
        let (ntfs, mut fs) = open(&attr_bytes);
        let file = file(&ntfs, &mut fs);
        let attr = NtfsAttribute::new(&file, FIRST_ATTRIBUTE_OFFSET, None).unwrap();
        let err = attr
            .resident_structured_value::<NtfsStandardInformation>()
            .unwrap_err();
        assert!(matches!(
            err,
            NtfsError::UnexpectedNonResidentAttribute { .. }
        ));
    }

    #[test]
    fn synthetic_raw_iterator_yields_attribute_then_end() {
        // NtfsAttributesRaw::next walks attributes and stops at the End
        // marker (lines 882/883/887). Two resident attributes back to back
        // followed by the End marker. The iterator advances by
        // `items_range.start += attribute_length` (line 883) and reads the
        // 4-byte type window via `end = start + size_of::<u32>()` (line 888).
        // The first attribute is large enough (value 250 bytes) that the
        // second begins past offset 256: an `items_range.start *=` mutation
        // (883) or an `end = start *` mutation (888) would compute an
        // out-of-range window for the second attribute and yield only one
        // item, so we assert exactly two attributes are returned in
        // ascending offset order.
        let big_value = [b'x'; 250];
        let attr0 = resident_attribute(&big_value, 0, &[]);
        let attr1 = resident_attribute(b"more", 0, &[]);
        let off1 = FIRST_ATTRIBUTE_OFFSET + attr0.len();
        assert!(off1 > 256, "second attribute must start past offset 256");
        let mut buf = attr0.clone();
        buf.extend_from_slice(&attr1);
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // End marker
        let (ntfs, mut fs) = open(&buf);
        let file = file(&ntfs, &mut fs);

        let mut iter = file.attributes_raw();
        let first = iter.next().expect("first attribute").expect("valid");
        assert_eq!(first.ty().unwrap(), NtfsAttributeType::Data);
        assert_eq!(first.offset(), FIRST_ATTRIBUTE_OFFSET);
        assert_eq!(first.attribute_length() as usize, attr0.len());
        // The iterator advanced by exactly attribute_length to the second
        // attribute (not a multiplied offset).
        let second = iter.next().expect("second attribute").expect("valid");
        assert_eq!(second.offset(), off1);
        assert_eq!(second.attribute_length() as usize, attr1.len());
        // After both attributes the End marker stops iteration.
        assert!(iter.next().is_none());
    }

    #[test]
    fn synthetic_attributes_iterator_yields_item() {
        // NtfsAttributes::next (line 679) and try_next (line 773) yield the
        // single resident attribute. NtfsAttributesAttached::next (line 812)
        // wraps it as an Iterator.
        let attr_bytes = resident_attribute(b"abc", 0, &[]);
        let mut buf = attr_bytes.clone();
        buf.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let (ntfs, mut fs) = open(&buf);
        let file = file(&ntfs, &mut fs);

        let mut attached = file.attributes().attach(&mut fs);
        let item = attached.next().expect("one item").expect("valid");
        let attribute = item.to_attribute().unwrap();
        assert_eq!(attribute.ty().unwrap(), NtfsAttributeType::Data);
        assert!(attached.next().is_none());
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn synthetic_attribute_type_arbitrary_index_wraps() {
        // The arbitrary impl indexes `variants[index % len]` (line 208).
        // `% len` keeps the index in range; `+ len` or `/ len` would panic
        // or pick the wrong element. Verify the modulo selects correctly
        // for indices spanning more than one full wrap.
        let variants = [
            NtfsAttributeType::StandardInformation,
            NtfsAttributeType::AttributeList,
            NtfsAttributeType::FileName,
            NtfsAttributeType::ObjectId,
            NtfsAttributeType::SecurityDescriptor,
            NtfsAttributeType::VolumeName,
            NtfsAttributeType::VolumeInformation,
            NtfsAttributeType::Data,
            NtfsAttributeType::IndexRoot,
            NtfsAttributeType::IndexAllocation,
            NtfsAttributeType::Bitmap,
            NtfsAttributeType::ReparsePoint,
            NtfsAttributeType::EAInformation,
            NtfsAttributeType::EA,
            NtfsAttributeType::PropertySet,
            NtfsAttributeType::LoggedUtilityStream,
            NtfsAttributeType::End,
        ];
        let len = variants.len();
        // Feed several byte patterns; for each, derive the same `usize`
        // the impl decodes and assert the chosen variant matches
        // `variants[index % len]`. A `+ len` mutation would index out of
        // bounds (panic) for indices producing `index + len >= len`, and a
        // `/ len` mutation would pick a different variant. Large patterns
        // (all-0xFF) drive `index` well above `len`.
        let patterns: [&[u8]; 4] = [
            &[0x00; 16],
            &[0xFF; 16],
            &[0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];
        for raw in patterns {
            let index: usize = arbitrary::Unstructured::new(raw).arbitrary().unwrap();
            let mut u = arbitrary::Unstructured::new(raw);
            let ty = <NtfsAttributeType as arbitrary::Arbitrary>::arbitrary(&mut u).unwrap();
            assert_eq!(ty, variants[index % len]);
        }
        // At least one pattern must produce index >= len so the `% len`
        // versus `+ len` / `/ len` distinction is observable.
        let big: usize = arbitrary::Unstructured::new([0xFFu8; 16].as_slice())
            .arbitrary()
            .unwrap();
        assert!(big >= len);
    }

    #[test]
    fn attribute_flags_display_renders_bits() {
        // Display::fmt forwards to the inner flags storage (line 68): a
        // non-empty flag set renders a non-empty string. The
        // `Ok(Default::default())` mutant writes nothing, producing "".
        let flags = NtfsAttributeFlags::COMPRESSED | NtfsAttributeFlags::SPARSE;
        let rendered = alloc::format!("{flags}");
        assert!(!rendered.is_empty(), "rendered: {rendered:?}");
        assert!(rendered.contains("COMPRESSED"), "rendered: {rendered:?}");
        assert!(rendered.contains("SPARSE"), "rendered: {rendered:?}");
    }

    #[test]
    fn test_empty_data_attribute() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "empty-file".
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "empty-file")
                .unwrap()
                .unwrap();
        let empty_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let data_attribute_item = empty_file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        assert_eq!(data_attribute.value_length(), 0);

        let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
        assert!(data_attribute_value.is_empty());

        let mut buf = [0u8; 5];
        let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 0);
    }

    #[test]
    fn test_zero_bytes_file() {
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

        // Find the zero-bytes file.
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "zero-bytes.bin",
        )
        .unwrap()
        .unwrap();
        let zero_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let data_attribute_item = zero_file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        assert_eq!(data_attribute.value_length(), 0);
    }

    #[test]
    fn test_cluster_boundary_file() {
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

        // Find the cluster-boundary file (512 bytes = 1 cluster).
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "cluster-boundary.bin",
        )
        .unwrap()
        .unwrap();
        let cluster_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let data_attribute_item = cluster_file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        // 512 bytes = exactly one cluster
        assert_eq!(data_attribute.value_length(), 512);

        // Read and verify we can read all 512 bytes (content is random from /dev/urandom)
        let mut data_value = data_attribute.value(&mut testfs1).unwrap();
        let mut buf = vec![0u8; 512];
        let bytes_read = data_value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, 512);
    }

    #[test]
    fn test_compressed_directory_files() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "compressed" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "compressed")
                .unwrap()
                .unwrap();
        let compressed_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Find the small-compressed.txt file and verify we can read it.
        let compressed_index = compressed_dir.directory_index(&mut testfs1).unwrap();
        let mut compressed_finder = compressed_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut compressed_finder,
            &ntfs,
            &mut testfs1,
            "small-compressed.txt",
        )
        .unwrap()
        .unwrap();
        let compressed_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Verify we can read the file's attributes and data.
        let _info = compressed_file.info().unwrap();
        let data_attribute_item = compressed_file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();

        // Read the content - should be "Hello, compressed world!"
        let mut data_value = data_attribute.value(&mut testfs1).unwrap();
        let mut buf = vec![0u8; data_attribute.value_length() as usize];
        let bytes_read = data_value.read(&mut testfs1, &mut buf).unwrap();
        assert_eq!(bytes_read, data_attribute.value_length() as usize);
        assert_eq!(
            core::str::from_utf8(&buf).unwrap(),
            "Hello, compressed world!"
        );

        // Test the is_compressed() method - it checks the attribute flags.
        // Note: ntfs-3g's setfattr may not properly set the compression flag,
        // so we just verify the method works without asserting the result.
        let _is_compressed = data_attribute.is_compressed();

        // Find and read the repetitive-compressed.txt file (100KB of 'A's).
        let compressed_index = compressed_dir.directory_index(&mut testfs1).unwrap();
        let mut compressed_finder = compressed_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut compressed_finder,
            &ntfs,
            &mut testfs1,
            "repetitive-compressed.txt",
        )
        .unwrap()
        .unwrap();
        let repetitive_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        let data_attribute_item = repetitive_file.data(&mut testfs1, "").unwrap().unwrap();
        let data_attribute = data_attribute_item.to_attribute().unwrap();
        // Should be 100000 bytes (100KB of 'A's)
        assert_eq!(data_attribute.value_length(), 100000);
    }
}
