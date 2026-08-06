//! On-disk directory entry structures for exFAT.
//!
//! Every exFAT directory entry is exactly 32 bytes. Entries are
//! classified by their `EntryType` byte into primary vs. secondary,
//! critical vs. benign, and in-use vs. deleted.
//!
//! This module provides:
//! - [`EntryTypeInfo`] for parsing the `EntryType` byte into its
//!   component fields.
//! - Zero-copy on-disk structs for each known entry type.
//! - [`ExFatFileAttributes`] bitflags matching the exFAT spec.
//! - Entry type constants for dispatch.

use bitflags::bitflags;
use zerocopy::byteorder::LittleEndian;
use zerocopy::{FromBytes, Immutable, KnownLayout, U16, U32, U64, Unaligned};

// ============================================================
// Entry type constants
// ============================================================

/// End-of-directory marker (not in use, type code 0).
pub const ENTRY_TYPE_END: u8 = 0x00;

/// Allocation bitmap entry (critical primary).
pub const ENTRY_TYPE_BITMAP: u8 = 0x81;

/// Up-case table entry (critical primary).
pub const ENTRY_TYPE_UPCASE: u8 = 0x82;

/// Volume label entry (critical primary).
pub const ENTRY_TYPE_VOLUME_LABEL: u8 = 0x83;

/// File directory entry (critical primary).
pub const ENTRY_TYPE_FILE: u8 = 0x85;

/// Stream extension entry (critical secondary).
pub const ENTRY_TYPE_STREAM: u8 = 0xC0;

/// File name entry (critical secondary).
pub const ENTRY_TYPE_NAME: u8 = 0xC1;

/// Volume GUID directory entry (benign primary).
pub const ENTRY_TYPE_VOLUME_GUID: u8 = 0xA0;

/// `TexFAT` Padding entry (benign primary).
pub const ENTRY_TYPE_TEXFAT_PADDING: u8 = 0xA1;

/// Vendor Extension entry (benign secondary).
pub const ENTRY_TYPE_VENDOR_EXT: u8 = 0xE0;

/// Vendor Allocation entry (benign secondary).
pub const ENTRY_TYPE_VENDOR_ALLOC: u8 = 0xE1;

/// Size of every directory entry in bytes.
pub const DIR_ENTRY_SIZE: usize = 32;

// ============================================================
// EntryTypeInfo
// ============================================================

/// Parsed representation of the one-byte `EntryType` field.
///
/// The exFAT specification encodes four pieces of information in
/// a single byte:
///
/// | Bits | Field            | Meaning                       |
/// |------|------------------|-------------------------------|
/// | 7    | InUse            | 1 = active, 0 = deleted/free  |
/// | 6    | TypeCategory     | 0 = primary, 1 = secondary    |
/// | 5    | TypeImportance   | 0 = critical, 1 = benign      |
/// | 4:0  | TypeCode         | Entry-specific identifier      |
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EntryTypeInfo {
    /// Whether the entry is currently in use.
    pub in_use: bool,
    /// Entry category: `false` = primary, `true` = secondary.
    pub type_category: bool,
    /// Entry importance: `false` = critical, `true` = benign.
    pub type_importance: bool,
    /// 5-bit entry-specific type code (bits 4:0).
    pub type_code: u8,
}

impl EntryTypeInfo {
    /// Parses the `EntryType` byte into its four component fields.
    #[inline]
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        Self {
            in_use: byte & 0x80 != 0,
            type_category: byte & 0x40 != 0,
            type_importance: byte & 0x20 != 0,
            type_code: byte & 0x1F,
        }
    }

    /// Returns `true` if the entry is benign (can be safely ignored
    /// by implementations that do not recognize the type code).
    #[inline]
    #[must_use]
    pub const fn is_benign(&self) -> bool {
        self.type_importance
    }

    /// Returns `true` if the entry is a primary entry.
    #[inline]
    #[must_use]
    pub const fn is_primary(&self) -> bool {
        !self.type_category
    }
}

// ============================================================
// ExFatFileAttributes
// ============================================================

bitflags! {
    /// File attribute flags from the File Directory Entry.
    ///
    /// These correspond to the standard FAT file attributes
    /// preserved in exFAT.
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    pub struct ExFatFileAttributes: u16 {
        /// The file is read-only.
        const READ_ONLY = 0x0001;
        /// The file is hidden.
        const HIDDEN    = 0x0002;
        /// The file is a system file.
        const SYSTEM    = 0x0004;
        /// The entry is a directory.
        const DIRECTORY = 0x0010;
        /// The file has been modified since last backup.
        const ARCHIVE   = 0x0020;
    }
}

// ============================================================
// On-disk entry structures (32 bytes each, zerocopy)
// ============================================================

/// File Directory Entry (`EntryType` 0x85).
///
/// The primary entry for a file or directory. Contains timestamps,
/// file attributes, and the count of secondary entries that follow.
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct FileDirectoryEntry {
    /// Entry type byte (0x85 for in-use file entry).
    pub entry_type: u8,
    /// Number of secondary entries that follow this primary entry.
    pub secondary_count: u8,
    /// Checksum of the entire entry set.
    pub set_checksum: U16<LittleEndian>,
    /// File attribute flags.
    pub file_attributes: U16<LittleEndian>,
    /// Reserved (must be zero).
    pub reserved1: U16<LittleEndian>,
    /// Creation time (DOS packed time).
    pub create_time: U16<LittleEndian>,
    /// Creation date (DOS packed date).
    pub create_date: U16<LittleEndian>,
    /// Last modification time (DOS packed time).
    pub modify_time: U16<LittleEndian>,
    /// Last modification date (DOS packed date).
    pub modify_date: U16<LittleEndian>,
    /// Last access time (DOS packed time).
    pub access_time: U16<LittleEndian>,
    /// Last access date (DOS packed date).
    pub access_date: U16<LittleEndian>,
    /// Creation time 10ms increment (0-199).
    pub create_time_cs: u8,
    /// Last modification time 10ms increment (0-199).
    pub modify_time_cs: u8,
    /// Creation time UTC offset.
    pub create_tz: u8,
    /// Last modification time UTC offset.
    pub modify_tz: u8,
    /// Last access time UTC offset.
    pub access_tz: u8,
    /// Reserved (must be zero).
    pub reserved2: [u8; 7],
}

/// Stream Extension Entry (`EntryType` 0xC0).
///
/// The first secondary entry of a file entry set. Contains the
/// file's data stream location (first cluster and length) and the
/// file name hash and length.
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct StreamExtensionEntry {
    /// Entry type byte (0xC0 for in-use stream extension).
    pub entry_type: u8,
    /// General secondary flags (bit 0 = `AllocationPossible`,
    /// bit 1 = `NoFatChain`).
    pub general_flags: u8,
    /// Reserved.
    pub reserved1: u8,
    /// Length of the file name in Unicode characters (1-255).
    pub name_length: u8,
    /// Hash of the up-cased file name.
    pub name_hash: U16<LittleEndian>,
    /// Reserved.
    pub reserved2: U16<LittleEndian>,
    /// Valid data length (bytes actually written).
    pub valid_data_length: U64<LittleEndian>,
    /// Reserved.
    pub reserved3: U32<LittleEndian>,
    /// First cluster of the data stream.
    pub first_cluster: U32<LittleEndian>,
    /// Allocated data length in bytes.
    pub data_length: U64<LittleEndian>,
}

/// File Name Entry (`EntryType` 0xC1).
///
/// Contains up to 15 UTF-16LE characters of the file name. Multiple
/// file name entries are chained together for longer names.
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct FileNameEntry {
    /// Entry type byte (0xC1 for in-use file name).
    pub entry_type: u8,
    /// General secondary flags.
    pub general_flags: u8,
    /// Up to 15 UTF-16LE code units (30 bytes).
    pub file_name: [u8; 30],
}

/// Volume Label Entry (`EntryType` 0x83).
///
/// Contains the volume label as a UTF-16LE string of up to 11
/// characters.
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct VolumeLabelEntry {
    /// Entry type byte (0x83 for in-use volume label).
    pub entry_type: u8,
    /// Number of characters in the volume label (0-11).
    pub character_count: u8,
    /// Volume label in UTF-16LE (up to 11 characters, 22 bytes).
    pub volume_label: [u8; 22],
    /// Reserved (must be zero).
    pub reserved: [u8; 8],
}

/// Allocation Bitmap Directory Entry (`EntryType` 0x81).
///
/// Located in the root directory. Contains the first cluster and
/// length of the allocation bitmap data. The `bitmap_flags` field
/// bit 0 identifies this as the first (0) or second (1) bitmap.
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct BitmapDirectoryEntry {
    /// Entry type byte (0x81 for in-use allocation bitmap).
    pub entry_type: u8,
    /// Bit 0: `BitmapIdentifier` (0 = first, 1 = second bitmap).
    pub bitmap_flags: u8,
    /// Reserved bytes.
    pub reserved: [u8; 18],
    /// First cluster of the bitmap data.
    pub first_cluster: U32<LittleEndian>,
    /// Length of the bitmap data in bytes.
    pub data_length: U64<LittleEndian>,
}

/// Up-case Table Directory Entry (`EntryType` 0x82).
///
/// Located in the root directory. Contains the first cluster,
/// length, and checksum of the up-case table data (which may be
/// compressed on disk).
#[repr(C, packed)]
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct UpcaseTableDirectoryEntry {
    /// Entry type byte (0x82 for in-use up-case table).
    pub entry_type: u8,
    /// Reserved bytes.
    pub reserved1: [u8; 3],
    /// Checksum of the raw (compressed) table data on disk.
    pub table_checksum: U32<LittleEndian>,
    /// Reserved bytes.
    pub reserved2: [u8; 12],
    /// First cluster of the up-case table data.
    pub first_cluster: U32<LittleEndian>,
    /// Length of the up-case table data in bytes (on-disk, compressed).
    pub data_length: U64<LittleEndian>,
}

// Compile-time size assertions for on-disk structs.
const _: () = assert!(core::mem::size_of::<FileDirectoryEntry>() == 32);
const _: () = assert!(core::mem::size_of::<StreamExtensionEntry>() == 32);
const _: () = assert!(core::mem::size_of::<FileNameEntry>() == 32);
const _: () = assert!(core::mem::size_of::<VolumeLabelEntry>() == 32);
const _: () = assert!(core::mem::size_of::<BitmapDirectoryEntry>() == 32);
const _: () = assert!(core::mem::size_of::<UpcaseTableDirectoryEntry>() == 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_type_info_file_entry() {
        // 0x85 = 1_0_0_00101
        //   in_use=true, category=false (primary),
        //   importance=false (critical), type_code=5
        let info = EntryTypeInfo::from_byte(0x85);
        assert!(info.in_use);
        assert!(!info.type_category);
        assert!(!info.type_importance);
        assert_eq!(info.type_code, 5);
        assert!(info.is_primary());
        assert!(!info.is_benign());
    }

    #[test]
    fn entry_type_info_benign_secondary() {
        // 0xE0 = 1_1_1_00000
        //   in_use=true, category=true (secondary),
        //   importance=true (benign), type_code=0
        let info = EntryTypeInfo::from_byte(0xE0);
        assert!(info.in_use);
        assert!(info.type_category);
        assert!(info.type_importance);
        assert_eq!(info.type_code, 0);
        assert!(!info.is_primary());
        assert!(info.is_benign());
    }

    #[test]
    fn entry_type_info_end_of_dir() {
        // 0x00 = 0_0_0_00000 (not in use)
        let info = EntryTypeInfo::from_byte(0x00);
        assert!(!info.in_use);
    }

    #[test]
    fn file_attributes_directory() {
        let attrs = ExFatFileAttributes::from_bits_truncate(0x0010);
        assert!(attrs.contains(ExFatFileAttributes::DIRECTORY));
        assert!(!attrs.contains(ExFatFileAttributes::READ_ONLY));
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(
            core::mem::size_of::<FileDirectoryEntry>(),
            32,
            "FileDirectoryEntry must be 32 bytes"
        );
        assert_eq!(
            core::mem::size_of::<StreamExtensionEntry>(),
            32,
            "StreamExtensionEntry must be 32 bytes"
        );
        assert_eq!(
            core::mem::size_of::<FileNameEntry>(),
            32,
            "FileNameEntry must be 32 bytes"
        );
        assert_eq!(
            core::mem::size_of::<VolumeLabelEntry>(),
            32,
            "VolumeLabelEntry must be 32 bytes"
        );
        assert_eq!(
            core::mem::size_of::<BitmapDirectoryEntry>(),
            32,
            "BitmapDirectoryEntry must be 32 bytes"
        );
        assert_eq!(
            core::mem::size_of::<UpcaseTableDirectoryEntry>(),
            32,
            "UpcaseTableDirectoryEntry must be 32 bytes"
        );
    }
}
