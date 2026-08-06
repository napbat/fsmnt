use alloc::vec::Vec;

use bitflags::bitflags;
use core::fmt;
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use fs_common::io::FsReadSeek;

/// Size of a single `$AttrDef` entry on disk, in bytes.
const ATTR_DEF_ENTRY_SIZE: usize = 160;

/// Byte offset of the `attr_type` field within an entry.
const OFF_ATTR_TYPE: usize = 128;

/// Byte offset of the `flags` field within an entry.
const OFF_FLAGS: usize = 140;

/// Byte offset of the `min_size` field within an entry.
const OFF_MIN_SIZE: usize = 144;

/// Byte offset of the `max_size` field within an entry.
const OFF_MAX_SIZE: usize = 152;

fn validated_entry_bytes<const N: usize>(data: &[u8], start: usize) -> [u8; N] {
    data.get(start..)
        .and_then(|bytes| bytes.first_chunk())
        .copied()
        .expect("attribute-definition iteration yields complete fixed-size entries")
}

bitflags! {
    /// Flags from an `$AttrDef` entry indicating attribute behaviour constraints.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsAttrDefFlags: u32 {
        /// The attribute can be used as an index key.
        const INDEXABLE = 0x02;
        /// The attribute must always be resident.
        const ALWAYS_RESIDENT = 0x40;
        /// The attribute is allowed to be non-resident.
        const CAN_BE_NON_RESIDENT = 0x80;
    }
}

impl fmt::Display for NtfsAttrDefFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A single parsed entry from the `$AttrDef` metafile.
///
/// Each entry describes an attribute type: its human-readable name, type code,
/// flags, and size constraints. The entry borrows from the raw data owned by
/// [`NtfsAttrDef`].
#[derive(Clone, Debug)]
pub struct NtfsAttrDefEntry<'d> {
    data: &'d [u8],
}

impl<'d> NtfsAttrDefEntry<'d> {
    /// Returns the attribute name as a UTF-16LE string reference.
    ///
    /// The name occupies the first 128 bytes (64 UTF-16 code points max)
    /// and is null-terminated.
    #[must_use]
    pub fn name(&self) -> U16StrLe<'d> {
        let name_bytes = &self.data[..self.name_length()];
        U16StrLe(name_bytes)
    }

    /// Returns the length of the attribute name in bytes (excluding null terminator).
    #[must_use]
    pub fn name_length(&self) -> usize {
        // Scan for first null UTF-16 code point (two zero bytes at an even offset).
        let label = &self.data[..128];
        let mut len = 0;
        while len + 1 < label.len() {
            if label[len] == 0 && label[len + 1] == 0 {
                break;
            }
            len += 2;
        }
        len
    }

    /// Returns the attribute type, or `None` if the type code is not recognized.
    #[must_use]
    pub fn attribute_type(&self) -> Option<NtfsAttributeType> {
        NtfsAttributeType::n(self.attribute_type_code())
    }

    /// Returns the raw attribute type code.
    #[must_use]
    pub fn attribute_type_code(&self) -> u32 {
        u32::from_le_bytes(validated_entry_bytes(self.data, OFF_ATTR_TYPE))
    }

    /// Returns the flags for this attribute definition entry.
    #[must_use]
    pub fn flags(&self) -> NtfsAttrDefFlags {
        let bits = u32::from_le_bytes(validated_entry_bytes(self.data, OFF_FLAGS));
        NtfsAttrDefFlags::from_bits_truncate(bits)
    }

    /// Returns the minimum allowed size for this attribute's value, in bytes.
    #[must_use]
    pub fn min_size(&self) -> u64 {
        u64::from_le_bytes(validated_entry_bytes(self.data, OFF_MIN_SIZE))
    }

    /// Returns the maximum allowed size for this attribute's value, in bytes.
    ///
    /// A value of `u64::MAX` (0xFFFFFFFFFFFFFFFF) typically means "no limit".
    #[must_use]
    pub fn max_size(&self) -> u64 {
        u64::from_le_bytes(validated_entry_bytes(self.data, OFF_MAX_SIZE))
    }
}

/// Parsed contents of the `$AttrDef` metafile (MFT entry 4).
///
/// `$AttrDef` contains metadata about each attribute type: human-readable name,
/// type code, size constraints, and flags. TSK loads this to display attribute
/// names and validate sizes.
///
/// Created via [`Ntfs::attr_def`] or [`NtfsAttrDef::load`].
#[derive(Clone, Debug)]
pub struct NtfsAttrDef {
    data: Vec<u8>,
}

impl NtfsAttrDef {
    /// Creates an [`NtfsAttrDef`] directly from raw bytes.
    ///
    /// This is useful for testing and fuzzing, bypassing the MFT/attribute
    /// parsing layer.
    #[must_use]
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Loads the `$AttrDef` metafile from the filesystem.
    ///
    /// Opens MFT record 4 and reads its `$DATA` attribute into memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested NTFS metafile is missing, malformed, or cannot be read.
    pub fn load<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        let attrdef_file = ntfs.file(fs, KnownNtfsFileRecordNumber::AttrDef.as_u64())?;
        let data_attribute =
            attrdef_file.find_resident_attribute(NtfsAttributeType::Data, None, None)?;
        let mut data_value = data_attribute.value(fs)?;

        let value_length = data_value.len();
        let len =
            usize::try_from(value_length).map_err(|_| NtfsError::InvalidStructuredValueSize {
                position: data_value.data_position(),
                ty: NtfsAttributeType::AttributeList,
                expected: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                actual: value_length,
            })?;
        let mut data = alloc::vec![0u8; len];
        data_value.read_exact(fs, &mut data)?;

        Ok(Self { data })
    }

    /// Returns an iterator over all entries in the `$AttrDef` table.
    ///
    /// Iteration stops when an entry with `attr_type == 0` is encountered
    /// or when the data is exhausted.
    #[must_use]
    pub fn entries(&self) -> NtfsAttrDefEntries<'_> {
        NtfsAttrDefEntries {
            data: &self.data,
            offset: 0,
        }
    }

    /// Finds an entry by its [`NtfsAttributeType`].
    #[must_use]
    pub fn find_by_type(&self, ty: NtfsAttributeType) -> Option<NtfsAttrDefEntry<'_>> {
        self.find_by_type_code(ty.as_u32())
    }

    /// Finds an entry by its raw attribute type code.
    ///
    /// This is useful for looking up attribute types that are not in the
    /// [`NtfsAttributeType`] enum.
    #[must_use]
    pub fn find_by_type_code(&self, code: u32) -> Option<NtfsAttrDefEntry<'_>> {
        self.entries().find(|e| e.attribute_type_code() == code)
    }
}

/// Iterator over [`NtfsAttrDefEntry`] values in an [`NtfsAttrDef`] table.
///
/// Stops when an entry with `attr_type == 0` is encountered or when the data
/// is exhausted.
#[derive(Clone, Debug)]
pub struct NtfsAttrDefEntries<'d> {
    data: &'d [u8],
    offset: usize,
}

impl<'d> Iterator for NtfsAttrDefEntries<'d> {
    type Item = NtfsAttrDefEntry<'d>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + ATTR_DEF_ENTRY_SIZE > self.data.len() {
            return None;
        }

        let entry_data = &self.data[self.offset..self.offset + ATTR_DEF_ENTRY_SIZE];

        // Check terminator: attr_type == 0 means end of list.
        let attr_type = u32::from_le_bytes(entry_data[OFF_ATTR_TYPE..][..4].try_into().unwrap());
        if attr_type == 0 {
            return None;
        }

        self.offset += ATTR_DEF_ENTRY_SIZE;
        Some(NtfsAttrDefEntry { data: entry_data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};

    /// Builds a single 160-byte `$AttrDef` entry from its component fields.
    ///
    /// The name occupies the first 128 bytes as UTF-16LE (null-terminated);
    /// `attr_type` at offset 128, `flags` at 140, `min_size` at 144, and
    /// `max_size` at 152, matching the on-disk layout constants.
    fn make_entry(
        name: &str,
        attr_type: u32,
        flags: u32,
        min_size: u64,
        max_size: u64,
    ) -> [u8; 160] {
        let mut buf = [0u8; 160];
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        buf[..name_utf16.len()].copy_from_slice(&name_utf16);
        buf[OFF_ATTR_TYPE..][..4].copy_from_slice(&attr_type.to_le_bytes());
        buf[OFF_FLAGS..][..4].copy_from_slice(&flags.to_le_bytes());
        buf[OFF_MIN_SIZE..][..8].copy_from_slice(&min_size.to_le_bytes());
        buf[OFF_MAX_SIZE..][..8].copy_from_slice(&max_size.to_le_bytes());
        buf
    }

    #[test]
    fn test_synthetic_entry_accessors() {
        // $STANDARD_INFORMATION: type 0x10, indexable + always-resident,
        // min 48, max 72 — values chosen distinct from 0/1 and from each other.
        let entry_bytes = make_entry("$STANDARD_INFORMATION", 0x10, 0x42, 48, 72);
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().expect("one entry");

        assert_eq!(entry.attribute_type_code(), 0x10);
        assert_eq!(
            entry.attribute_type(),
            Some(NtfsAttributeType::StandardInformation)
        );
        assert_eq!(entry.min_size(), 48);
        assert_eq!(entry.max_size(), 72);
        assert_eq!(entry.name_length(), "$STANDARD_INFORMATION".len() * 2);
        assert_eq!(entry.name().to_string().unwrap(), "$STANDARD_INFORMATION");

        let flags = entry.flags();
        assert!(flags.contains(NtfsAttrDefFlags::INDEXABLE));
        assert!(flags.contains(NtfsAttrDefFlags::ALWAYS_RESIDENT));
        assert!(!flags.contains(NtfsAttrDefFlags::CAN_BE_NON_RESIDENT));
    }

    #[test]
    fn test_synthetic_name_length_full_label() {
        // A 64-code-point name fills the entire 128-byte label with no
        // null terminator, so name_length must return exactly 128.
        let name: String = "A".repeat(64);
        let entry_bytes = make_entry(&name, 0x80, 0, 0, 0);
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().unwrap();
        assert_eq!(entry.name_length(), 128);
    }

    #[test]
    fn test_synthetic_name_length_high_byte_first() {
        // First UTF-16 code unit is 0x4100: bytes [0x00, 0x41]. Here
        // label[len] == 0 but label[len + 1] != 0, so the `&&` terminator
        // must inspect the *second* byte (label[len + 1]). This distinguishes
        // `label[len + 1]` from `label[len]` (the `+ with *` mutant) and from
        // `label[len - 1]` (the `+ with -` mutant, which underflows at len=0).
        let mut entry_bytes = [0u8; 160];
        // code unit 0 = 0x4100, code unit 1 = 0x0042 ('B'), then null.
        entry_bytes[0] = 0x00;
        entry_bytes[1] = 0x41;
        entry_bytes[2] = 0x42;
        entry_bytes[3] = 0x00;
        // bytes 4..6 stay zero -> terminator.
        entry_bytes[OFF_ATTR_TYPE..][..4].copy_from_slice(&0x80u32.to_le_bytes());
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().unwrap();
        // Two code units precede the null pair -> 4 bytes.
        assert_eq!(entry.name_length(), 4);
    }

    #[test]
    fn test_synthetic_name_length_short() {
        // "$DATA" is 5 code points (10 bytes) followed by a null pair, so
        // name_length stops at 10 (the loop's `+= 2` and `&&` terminator).
        let entry_bytes = make_entry("$DATA", 0x80, 0, 0, 0);
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().unwrap();
        assert_eq!(entry.name_length(), 10);
        assert_eq!(entry.attribute_type_code(), 0x80);
    }

    #[test]
    fn test_synthetic_unknown_type_code() {
        // 0xDEAD is not in NtfsAttributeType, so attribute_type() is None
        // while attribute_type_code() returns the raw value.
        let entry_bytes = make_entry("$WEIRD", 0xDEAD, 0, 0, 0);
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().unwrap();
        assert_eq!(entry.attribute_type_code(), 0xDEAD);
        assert!(entry.attribute_type().is_none());
    }

    #[test]
    fn test_synthetic_find_by_type() {
        // Two entries: $STANDARD_INFORMATION (0x10) then $FILE_NAME (0x30).
        let mut data = Vec::new();
        data.extend_from_slice(&make_entry("$STANDARD_INFORMATION", 0x10, 0x40, 48, 72));
        data.extend_from_slice(&make_entry("$FILE_NAME", 0x30, 0x42, 68, 578));
        let attr_def = NtfsAttrDef::from_bytes(data);

        let si = attr_def
            .find_by_type(NtfsAttributeType::StandardInformation)
            .unwrap();
        assert_eq!(si.attribute_type_code(), 0x10);
        assert_eq!(si.min_size(), 48);

        let fname = attr_def.find_by_type_code(0x30).unwrap();
        assert_eq!(fname.attribute_type(), Some(NtfsAttributeType::FileName));
        assert_eq!(fname.max_size(), 578);
        assert_eq!(fname.name().to_string().unwrap(), "$FILE_NAME");

        // A type code present in neither entry is not found.
        assert!(attr_def.find_by_type_code(0x99).is_none());
        assert!(attr_def.find_by_type(NtfsAttributeType::Data).is_none());
    }

    #[test]
    fn test_synthetic_iterator_terminator_and_count() {
        // Three real entries followed by a zero-type terminator entry.
        // The iterator must stop at the terminator and yield exactly 3.
        let mut data = Vec::new();
        data.extend_from_slice(&make_entry("$A", 0x10, 0, 0, 0));
        data.extend_from_slice(&make_entry("$B", 0x30, 0, 0, 0));
        data.extend_from_slice(&make_entry("$C", 0x80, 0, 0, 0));
        data.extend_from_slice(&make_entry("$END", 0x00, 0, 0, 0)); // terminator
        let attr_def = NtfsAttrDef::from_bytes(data);

        let entries: Vec<_> = attr_def.entries().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].attribute_type_code(), 0x10);
        assert_eq!(entries[1].attribute_type_code(), 0x30);
        assert_eq!(entries[2].attribute_type_code(), 0x80);
    }

    #[test]
    fn test_synthetic_iterator_truncated_data_stops() {
        // 159 bytes is one byte short of a full entry; the iterator's
        // bounds check must yield nothing rather than read out of range.
        let attr_def = NtfsAttrDef::from_bytes(vec![0x11u8; 159]);
        assert_eq!(attr_def.entries().count(), 0);

        // Exactly 160 bytes with a real type yields exactly one entry.
        let attr_def = NtfsAttrDef::from_bytes(make_entry("$X", 0x10, 0, 0, 0).to_vec());
        assert_eq!(attr_def.entries().count(), 1);
    }

    #[test]
    fn test_synthetic_flags_display() {
        // The Display impl must render the underlying numeric bits, not the
        // empty/default string.
        let entry_bytes = make_entry("$X", 0x10, 0x42, 0, 0);
        let attr_def = NtfsAttrDef::from_bytes(entry_bytes.to_vec());
        let entry = attr_def.entries().next().unwrap();
        let rendered = entry.flags().to_string();
        // The Display impl renders the active flag names; the
        // Ok(Default::default()) mutant would produce an empty string.
        assert_eq!(rendered, "INDEXABLE | ALWAYS_RESIDENT");
        assert!(!rendered.is_empty());
    }

    #[test]
    fn test_attr_def_load() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = NtfsAttrDef::load(&ntfs, &mut testfs1).unwrap();
        let entries: Vec<_> = attr_def.entries().collect();
        assert!(!entries.is_empty(), "expected at least one $AttrDef entry");
    }

    #[test]
    fn test_attr_def_standard_information_entry() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = NtfsAttrDef::load(&ntfs, &mut testfs1).unwrap();

        let entry = attr_def
            .find_by_type(NtfsAttributeType::StandardInformation)
            .expect("$STANDARD_INFORMATION should be in $AttrDef");

        assert_eq!(entry.attribute_type_code(), 0x10);
        assert!(entry.attribute_type().is_some());

        let name = entry.name().to_string().unwrap();
        assert_eq!(name, "$STANDARD_INFORMATION");
    }

    #[test]
    fn test_attr_def_find_by_type_code() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = NtfsAttrDef::load(&ntfs, &mut testfs1).unwrap();

        // $DATA is type 0x80.
        let entry = attr_def
            .find_by_type_code(0x80)
            .expect("$DATA should be in $AttrDef");
        assert_eq!(entry.attribute_type(), Some(NtfsAttributeType::Data));

        let name = entry.name().to_string().unwrap();
        assert_eq!(name, "$DATA");
    }

    #[test]
    fn test_attr_def_missing_type() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = NtfsAttrDef::load(&ntfs, &mut testfs1).unwrap();

        // Type 0xDEAD should not exist.
        assert!(attr_def.find_by_type_code(0xDEAD).is_none());
    }

    #[test]
    fn test_attr_def_flags() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = NtfsAttrDef::load(&ntfs, &mut testfs1).unwrap();

        // $FILE_NAME (0x30) should be indexable and always resident.
        let entry = attr_def
            .find_by_type(NtfsAttributeType::FileName)
            .expect("$FILE_NAME should be in $AttrDef");

        let flags = entry.flags();
        assert!(
            flags.contains(NtfsAttrDefFlags::INDEXABLE),
            "$FILE_NAME should be indexable"
        );
        assert!(
            flags.contains(NtfsAttrDefFlags::ALWAYS_RESIDENT),
            "$FILE_NAME should be always-resident"
        );
    }

    #[test]
    fn test_attr_def_via_ntfs_convenience() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let attr_def = ntfs.attr_def(&mut testfs1).unwrap();
        let entries: Vec<_> = attr_def.entries().collect();
        assert!(!entries.is_empty());
    }
}
