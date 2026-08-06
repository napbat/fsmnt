use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use bitflags::bitflags;
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::file_reference::NtfsFileReference;
use crate::indexes::NtfsFileNameIndex;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::time::NtfsTime;
use crate::types::NtfsPosition;
use fs_common::io::FsReadSeek;
use fs_common::iter::FsTryIterator;

// ---------------------------------------------------------------------------
// Common header constants (USN_RECORD_COMMON_HEADER, shared by V2 and V3)
// ---------------------------------------------------------------------------

const OFF_RECORD_LENGTH: usize = 0x00;
const OFF_MAJOR_VERSION: usize = 0x04;
const OFF_MINOR_VERSION: usize = 0x06;

/// Smallest valid record across all supported versions (V2 or V3).
/// Used for the iterator's initial size sanity check before reading
/// the version field.
const USN_RECORD_MIN_COMMON_HEADER: usize = 8;
/// `u64` form used when advancing through malformed journal data.
const USN_RECORD_MIN_COMMON_HEADER_U64: u64 = 8;

// ---------------------------------------------------------------------------
// V2 record layout constants
// ---------------------------------------------------------------------------

/// Minimum V2 record size: 60-byte header + 2 bytes (1-char UTF-16 name).
const USN_RECORD_V2_MIN_SIZE: usize = 62;

/// Header size before the variable-length file name.
const USN_RECORD_V2_HEADER_SIZE: usize = 60;

// V2-specific field offsets (after the 8-byte common header).
const OFF_V2_FILE_REFERENCE: usize = 0x08;
const OFF_V2_PARENT_REFERENCE: usize = 0x10;
const OFF_V2_USN: usize = 0x18;
const OFF_V2_TIMESTAMP: usize = 0x20;
const OFF_V2_REASON: usize = 0x28;
const OFF_V2_SOURCE_INFO: usize = 0x2C;
const OFF_V2_SECURITY_ID: usize = 0x30;
const OFF_V2_FILE_ATTRIBUTES: usize = 0x34;
const OFF_V2_FILE_NAME_LENGTH: usize = 0x38;
const OFF_V2_FILE_NAME_OFFSET: usize = 0x3A;

// ---------------------------------------------------------------------------
// V3 record layout constants
// ---------------------------------------------------------------------------

/// Minimum V3 record size: 76-byte header + 2 bytes (1-char UTF-16 name).
const USN_RECORD_V3_MIN_SIZE: usize = 78;

/// Header size before the variable-length file name (V3).
const USN_RECORD_V3_HEADER_SIZE: usize = 76;

// V3-specific field offsets. Both reference fields expand from 8 to
// 16 bytes compared to V2, shifting everything downstream by +16.
const OFF_V3_FILE_REFERENCE: usize = 0x08;
const OFF_V3_PARENT_REFERENCE: usize = 0x18;
const OFF_V3_USN: usize = 0x28;
const OFF_V3_TIMESTAMP: usize = 0x30;
const OFF_V3_REASON: usize = 0x38;
const OFF_V3_SOURCE_INFO: usize = 0x3C;
const OFF_V3_SECURITY_ID: usize = 0x40;
const OFF_V3_FILE_ATTRIBUTES: usize = 0x44;
const OFF_V3_FILE_NAME_LENGTH: usize = 0x48;
const OFF_V3_FILE_NAME_OFFSET: usize = 0x4A;

// ---------------------------------------------------------------------------
// $Max stream layout constants
// ---------------------------------------------------------------------------

/// Minimum size of the on-disk $Max stream (4 fields: `MaximumSize`, `AllocationDelta`,
/// `UsnJournalID`, `LowestValidUsn`). The Windows API struct `USN_JOURNAL_DATA_V0` is 56
/// bytes and includes 3 additional runtime-computed fields (`FirstUsn`, `NextUsn`, `MaxUsn`)
/// that are NOT stored on disk.
const USN_MAX_MIN_SIZE: usize = 32;

/// Copies a fixed-width field from a record already validated by its constructor.
fn validated_usn_bytes<const N: usize>(data: &[u8], offset: usize) -> [u8; N] {
    data.get(offset..)
        .and_then(|tail| tail.first_chunk())
        .copied()
        .expect("USN record construction validates every fixed-width field")
}

/// Borrows a variable-width field already validated by a record constructor.
fn validated_usn_slice(data: &[u8], offset: usize, length: usize) -> &[u8] {
    data.get(offset..)
        .and_then(|tail| tail.get(..length))
        .expect("USN record construction validates the file-name range")
}

// ---------------------------------------------------------------------------
// Bitflags
// ---------------------------------------------------------------------------

bitflags! {
    /// Reason flags indicating what changed in a USN Journal record.
    ///
    /// Multiple flags can be set simultaneously. The `CLOSE` flag indicates
    /// the final record in a batch of changes to a file.
    ///
    /// Spec reference: MS-FSCC Section 2.3.42 (USN_RECORD_V2) and 2.3.43 (USN_RECORD_V3) for reason field layout.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct UsnReason: u32 {
        /// Existing bytes in the unnamed data stream were overwritten.
        const DATA_OVERWRITE        = 0x0000_0001;
        /// The unnamed data stream was extended.
        const DATA_EXTEND           = 0x0000_0002;
        /// The unnamed data stream was truncated.
        const DATA_TRUNCATION       = 0x0000_0004;
        /// Existing bytes in a named stream were overwritten.
        const NAMED_DATA_OVERWRITE  = 0x0000_0010;
        /// A named stream was extended.
        const NAMED_DATA_EXTEND     = 0x0000_0020;
        /// A named stream was truncated.
        const NAMED_DATA_TRUNCATION = 0x0000_0040;
        /// A file or directory was created.
        const FILE_CREATE           = 0x0000_0100;
        /// A file or directory was deleted.
        const FILE_DELETE           = 0x0000_0200;
        /// Extended-attribute data changed.
        const EA_CHANGE             = 0x0000_0400;
        /// The security descriptor changed.
        const SECURITY_CHANGE       = 0x0000_0800;
        /// Records the old name during a rename operation.
        const RENAME_OLD_NAME       = 0x0000_1000;
        /// Records the new name during a rename operation.
        const RENAME_NEW_NAME       = 0x0000_2000;
        /// The file's content-indexing state changed.
        const INDEXABLE_CHANGE      = 0x0000_4000;
        /// Basic file metadata changed.
        const BASIC_INFO_CHANGE     = 0x0000_8000;
        /// A hard link was added or removed.
        const HARD_LINK_CHANGE      = 0x0001_0000;
        /// The compression state changed.
        const COMPRESSION_CHANGE    = 0x0002_0000;
        /// The encryption state changed.
        const ENCRYPTION_CHANGE     = 0x0004_0000;
        /// The object identifier changed.
        const OBJECT_ID_CHANGE      = 0x0008_0000;
        /// Reparse-point data changed.
        const REPARSE_POINT_CHANGE  = 0x0010_0000;
        /// A named stream was added, removed, or renamed.
        const STREAM_CHANGE         = 0x0020_0000;
        /// Transactional NTFS (TxF) operation.
        ///
        /// Not in MS-FSCC v60.0; present in Windows SDK USN_REASON_TRANSACTED_CHANGE.
        const TRANSACTED_CHANGE     = 0x0040_0000;
        /// Integrity-stream state or metadata changed.
        const INTEGRITY_CHANGE      = 0x0080_0000;
        /// This is the final journal record for the current handle close.
        const CLOSE                 = 0x8000_0000;
    }
}

impl fmt::Display for UsnReason {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

bitflags! {
    /// Source information flags in a USN Journal record.
    ///
    /// Spec reference: MS-FSCC Section 2.3.42 (USN_RECORD_V2) and 2.3.43 (USN_RECORD_V3) for source info field layout.
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct UsnSourceInfo: u32 {
        /// The change was made by operating-system data management.
        const DATA_MANAGEMENT               = 0x01;
        /// The change affected auxiliary data rather than user data.
        const AUXILIARY_DATA                = 0x02;
        /// The change was made by a replication service.
        const REPLICATION_MANAGEMENT        = 0x04;
        /// Client-initiated replication management.
        ///
        /// Not in MS-FSCC v60.0; documented in the Windows SDK USN_SOURCE_CLIENT_REPLICATION_MANAGEMENT.
        const CLIENT_REPLICATION_MANAGEMENT = 0x08;
    }
}

impl fmt::Display for UsnSourceInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

// ---------------------------------------------------------------------------
// UsnJournalMetadata ($Max stream)
// ---------------------------------------------------------------------------

/// Metadata from the `$Max` stream of `$UsnJrnl`.
///
/// The on-disk `$Max` stream is 32 bytes and contains 4 fields: `maximum_size`,
/// `allocation_delta`, `journal_id`, and `lowest_valid_usn`. The Windows API struct
/// `USN_JOURNAL_DATA_V0` (returned by `FSCTL_QUERY_USN_JOURNAL`) adds 3 runtime fields
/// (`FirstUsn`, `NextUsn`, `MaxUsn`) that are not stored on disk.
#[derive(Clone, Debug)]
pub struct UsnJournalMetadata {
    /// Target journal size in bytes.
    pub maximum_size: u64,
    /// Allocation granularity in bytes.
    pub allocation_delta: u64,
    /// Unique journal instance identifier.
    pub journal_id: u64,
    /// Oldest still-valid record offset.
    pub lowest_valid_usn: u64,
}

impl UsnJournalMetadata {
    fn from_bytes(data: &[u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < USN_MAX_MIN_SIZE {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "$Max stream too small",
            });
        }

        Ok(Self {
            maximum_size: u64::from_le_bytes(validated_usn_bytes(data, 0)),
            allocation_delta: u64::from_le_bytes(validated_usn_bytes(data, 8)),
            journal_id: u64::from_le_bytes(validated_usn_bytes(data, 16)),
            lowest_valid_usn: u64::from_le_bytes(validated_usn_bytes(data, 24)),
        })
    }
}

// ---------------------------------------------------------------------------
// Shared convenience methods for V2 and V3 records
// ---------------------------------------------------------------------------

/// Generates convenience query methods that delegate to `reason()`.
macro_rules! usn_record_convenience_methods {
    () => {
        /// Returns `true` if this record indicates a file creation.
        pub fn is_create(&self) -> bool {
            self.reason().contains(UsnReason::FILE_CREATE)
        }

        /// Returns `true` if this record indicates a file deletion.
        pub fn is_delete(&self) -> bool {
            self.reason().contains(UsnReason::FILE_DELETE)
        }

        /// Returns `true` if this record indicates a rename operation.
        pub fn is_rename(&self) -> bool {
            self.reason()
                .intersects(UsnReason::RENAME_OLD_NAME | UsnReason::RENAME_NEW_NAME)
        }

        /// Returns `true` if this is the final (CLOSE) record for an
        /// operation.
        pub fn is_close(&self) -> bool {
            self.reason().contains(UsnReason::CLOSE)
        }
    };
}

// ---------------------------------------------------------------------------
// UsnRecord (V2)
// ---------------------------------------------------------------------------

/// A parsed V2 USN Journal record.
///
/// The record borrows from a caller-provided buffer. Use [`NtfsUsnJournal::records`]
/// to iterate over records.
///
/// Spec reference: MS-FSCC Section 2.3.42 (`USN_RECORD_V2`); Section 2.3.41 (`USN_RECORD_COMMON_HEADER`).
#[derive(Clone, Debug)]
pub struct UsnRecord<'s> {
    data: &'s [u8],
    position: NtfsPosition,
}

impl<'s> UsnRecord<'s> {
    /// Creates a [`UsnRecord`] directly from a byte slice.
    ///
    /// This is useful for testing and fuzzing, bypassing the journal
    /// iteration layer.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is shorter than a V2 header or its
    /// file-name range lies outside the declared or available record bytes.
    pub fn from_bytes(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        Self::new(data, position)
    }

    fn new(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < USN_RECORD_V2_MIN_SIZE {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "record too small for V2 header",
            });
        }

        let record = Self { data, position };

        let file_name_offset = usize::from(record.file_name_offset());
        let file_name_length = usize::from(record.file_name_length());
        let record_length =
            usize::try_from(record.record_length()).map_err(|_| NtfsError::InvalidUsnRecord {
                position,
                reason: "record length cannot be represented on this target",
            })?;
        let file_name_end =
            file_name_offset
                .checked_add(file_name_length)
                .ok_or(NtfsError::InvalidUsnRecord {
                    position,
                    reason: "file name range overflows the target address space",
                })?;

        if file_name_offset < USN_RECORD_V2_HEADER_SIZE {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name offset precedes header end",
            });
        }

        if file_name_end > record_length {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name extends beyond record",
            });
        }

        // Also validate against the actual data length, since record_length
        // is read from the (untrusted) data itself and may exceed data.len().
        if file_name_end > data.len() {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name extends beyond available data",
            });
        }

        Ok(record)
    }

    /// Total record length including padding (8-byte aligned).
    #[must_use]
    pub fn record_length(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_RECORD_LENGTH))
    }

    /// Major version of the record format (2 for V2).
    #[must_use]
    pub fn major_version(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_MAJOR_VERSION))
    }

    /// Minor version of the record format (typically 0).
    #[must_use]
    pub fn minor_version(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_MINOR_VERSION))
    }

    /// File reference (48-bit MFT record number + 16-bit sequence number).
    #[must_use]
    pub fn file_reference(&self) -> NtfsFileReference {
        NtfsFileReference::new(validated_usn_bytes(self.data, OFF_V2_FILE_REFERENCE))
    }

    /// Parent directory file reference.
    #[must_use]
    pub fn parent_reference(&self) -> NtfsFileReference {
        NtfsFileReference::new(validated_usn_bytes(self.data, OFF_V2_PARENT_REFERENCE))
    }

    /// The USN (byte offset within `$J`) of this record.
    #[must_use]
    pub fn usn(&self) -> u64 {
        u64::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_USN))
    }

    /// Raw FILETIME timestamp (100-nanosecond intervals since 1601-01-01).
    #[must_use]
    pub fn timestamp(&self) -> NtfsTime {
        NtfsTime::from(u64::from_le_bytes(validated_usn_bytes(
            self.data,
            OFF_V2_TIMESTAMP,
        )))
    }

    /// Reason flags indicating what changed.
    #[must_use]
    pub fn reason(&self) -> UsnReason {
        let bits = u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_REASON));
        UsnReason::from_bits_truncate(bits)
    }

    /// Source information flags.
    #[must_use]
    pub fn source_info(&self) -> UsnSourceInfo {
        let bits = u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_SOURCE_INFO));
        UsnSourceInfo::from_bits_truncate(bits)
    }

    /// Security ID at the time of the operation.
    #[must_use]
    pub fn security_id(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_SECURITY_ID))
    }

    /// File attributes at the time of the operation.
    #[must_use]
    pub fn file_attributes(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_FILE_ATTRIBUTES))
    }

    /// File name length in bytes.
    #[must_use]
    pub fn file_name_length(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_FILE_NAME_LENGTH))
    }

    /// File name offset from the start of the record.
    #[must_use]
    pub fn file_name_offset(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_V2_FILE_NAME_OFFSET))
    }

    /// Returns the file name as a UTF-16LE string reference.
    #[must_use]
    pub fn file_name(&self) -> U16StrLe<'s> {
        let offset = usize::from(self.file_name_offset());
        let length = usize::from(self.file_name_length());
        U16StrLe(validated_usn_slice(self.data, offset, length))
    }

    /// Returns the absolute position of this record within the filesystem.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    usn_record_convenience_methods!();
}

// ---------------------------------------------------------------------------
// UsnRecordV3
// ---------------------------------------------------------------------------

/// A parsed V3 USN Journal record.
///
/// V3 records use 128-bit (16-byte) file references instead of V2's
/// 64-bit (8-byte) references. All other fields have the same semantics
/// at shifted offsets (+16 bytes past the file reference fields).
///
/// The record borrows from a caller-provided buffer.
///
/// Spec reference: MS-FSCC Section 2.3.43 (`USN_RECORD_V3`); Section 2.3.41 (`USN_RECORD_COMMON_HEADER`).
#[derive(Clone, Debug)]
pub struct UsnRecordV3<'s> {
    data: &'s [u8],
    position: NtfsPosition,
}

impl<'s> UsnRecordV3<'s> {
    /// Creates a [`UsnRecordV3`] directly from a byte slice.
    ///
    /// Useful for testing and fuzzing, bypassing journal iteration.
    ///
    /// # Errors
    ///
    /// Returns an error when the record is shorter than a V3 header or its
    /// file-name range lies outside the declared or available record bytes.
    pub fn from_bytes(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        Self::new(data, position)
    }

    fn new(data: &'s [u8], position: NtfsPosition) -> Result<Self> {
        if data.len() < USN_RECORD_V3_MIN_SIZE {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "record too small for V3 header",
            });
        }

        let record = Self { data, position };

        let file_name_offset = usize::from(record.file_name_offset());
        let file_name_length = usize::from(record.file_name_length());
        let record_length =
            usize::try_from(record.record_length()).map_err(|_| NtfsError::InvalidUsnRecord {
                position,
                reason: "record length cannot be represented on this target",
            })?;
        let file_name_end =
            file_name_offset
                .checked_add(file_name_length)
                .ok_or(NtfsError::InvalidUsnRecord {
                    position,
                    reason: "file name range overflows the target address space",
                })?;

        if file_name_offset < USN_RECORD_V3_HEADER_SIZE {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name offset precedes V3 header end",
            });
        }

        if file_name_end > record_length {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name extends beyond record",
            });
        }

        if file_name_end > data.len() {
            return Err(NtfsError::InvalidUsnRecord {
                position,
                reason: "file name extends beyond available data",
            });
        }

        Ok(record)
    }

    /// Total record length including padding (8-byte aligned).
    #[must_use]
    pub fn record_length(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_RECORD_LENGTH))
    }

    /// Major version of the record format (3 for V3).
    #[must_use]
    pub fn major_version(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_MAJOR_VERSION))
    }

    /// Minor version of the record format (typically 0).
    #[must_use]
    pub fn minor_version(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_MINOR_VERSION))
    }

    /// 128-bit file reference number.
    ///
    /// Unlike V2's 64-bit reference (split into 48-bit MFT record
    /// number + 16-bit sequence number), V3 uses the full 128-bit
    /// file ID defined in MS-FSCC section 2.1.10.
    #[must_use]
    pub fn file_reference(&self) -> [u8; 16] {
        validated_usn_bytes(self.data, OFF_V3_FILE_REFERENCE)
    }

    /// 128-bit parent directory file reference number.
    #[must_use]
    pub fn parent_reference(&self) -> [u8; 16] {
        validated_usn_bytes(self.data, OFF_V3_PARENT_REFERENCE)
    }

    /// The USN (byte offset within `$J`) of this record.
    #[must_use]
    pub fn usn(&self) -> u64 {
        u64::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_USN))
    }

    /// Raw FILETIME timestamp (100-ns intervals since 1601-01-01).
    #[must_use]
    pub fn timestamp(&self) -> NtfsTime {
        NtfsTime::from(u64::from_le_bytes(validated_usn_bytes(
            self.data,
            OFF_V3_TIMESTAMP,
        )))
    }

    /// Reason flags indicating what changed.
    #[must_use]
    pub fn reason(&self) -> UsnReason {
        let bits = u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_REASON));
        UsnReason::from_bits_truncate(bits)
    }

    /// Source information flags.
    #[must_use]
    pub fn source_info(&self) -> UsnSourceInfo {
        let bits = u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_SOURCE_INFO));
        UsnSourceInfo::from_bits_truncate(bits)
    }

    /// Security ID at the time of the operation.
    #[must_use]
    pub fn security_id(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_SECURITY_ID))
    }

    /// File attributes at the time of the operation.
    #[must_use]
    pub fn file_attributes(&self) -> u32 {
        u32::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_FILE_ATTRIBUTES))
    }

    /// File name length in bytes.
    #[must_use]
    pub fn file_name_length(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_FILE_NAME_LENGTH))
    }

    /// File name offset from the start of the record.
    #[must_use]
    pub fn file_name_offset(&self) -> u16 {
        u16::from_le_bytes(validated_usn_bytes(self.data, OFF_V3_FILE_NAME_OFFSET))
    }

    /// Returns the file name as a UTF-16LE string reference.
    #[must_use]
    pub fn file_name(&self) -> U16StrLe<'s> {
        let offset = usize::from(self.file_name_offset());
        let length = usize::from(self.file_name_length());
        U16StrLe(validated_usn_slice(self.data, offset, length))
    }

    /// Returns the absolute position of this record.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    usn_record_convenience_methods!();
}

// ---------------------------------------------------------------------------
// UsnRecordVersion (V2/V3 dispatch enum)
// ---------------------------------------------------------------------------

/// A USN Journal record of any supported version.
///
/// Returned by [`NtfsUsnRecords::next_versioned`] when iterating
/// over a journal that may contain both V2 and V3 records.
#[derive(Clone, Debug)]
pub enum UsnRecordVersion<'s> {
    /// A V2 record with 64-bit file references.
    V2(UsnRecord<'s>),
    /// A V3 record with 128-bit file references.
    V3(UsnRecordV3<'s>),
}

// ---------------------------------------------------------------------------
// NtfsUsnJournal
// ---------------------------------------------------------------------------

/// Reader for the NTFS USN Journal (`$Extend\$UsnJrnl`).
///
/// The USN Journal records timestamped entries for every file operation.
/// It is one of the most forensically valuable NTFS artifacts.
///
/// Created via [`NtfsUsnJournal::open`].
#[derive(Clone, Debug)]
pub struct NtfsUsnJournal {
    /// Metadata from the `$Max` stream.
    metadata: UsnJournalMetadata,
    /// Physical layout of the `$J` stream on disk.
    map: DataRunMap,
    /// Total logical size of the `$J` stream.
    j_size: u64,
}

impl NtfsUsnJournal {
    /// Opens the USN Journal.
    ///
    /// Locates `$Extend\$UsnJrnl`, reads the `$Max` metadata stream, and
    /// extracts the `$J` data run layout.
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] has not been called.
    ///
    /// # Errors
    ///
    /// Returns an error if `$Extend`, `$UsnJrnl`, `$Max`, or `$J` cannot be
    /// found, read, or parsed.
    pub fn open<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        // 1. Open $Extend directory (MFT 11).
        let extend_dir = ntfs.file(fs, KnownNtfsFileRecordNumber::Extend.as_u64())?;
        let extend_index = extend_dir.directory_index(fs)?;

        // 2. Find $UsnJrnl in the $Extend directory index.
        let mut finder = extend_index.finder();
        let entry = NtfsFileNameIndex::find(&mut finder, ntfs, fs, "$UsnJrnl").ok_or(
            NtfsError::AttributeNotFound {
                position: extend_dir.position(),
                ty: NtfsAttributeType::Data,
            },
        )??;
        let usnjrnl_file = entry.to_file(ntfs, fs)?;

        // 3. Read $Max stream → parse metadata.
        let metadata = Self::read_max_metadata(&usnjrnl_file, fs)?;

        // 4. Extract $J data runs.
        let j_item = find_named_data_attribute(&usnjrnl_file, fs, "$J")?;
        let j_attribute = j_item.to_attribute()?;
        let non_resident_value = j_attribute.non_resident_value()?;
        let j_size = non_resident_value.len();
        let map = DataRunMap::from_data_runs(non_resident_value.data_runs())?;

        Ok(Self {
            metadata,
            map,
            j_size,
        })
    }

    /// Returns the journal metadata from the `$Max` stream.
    #[must_use]
    pub fn metadata(&self) -> &UsnJournalMetadata {
        &self.metadata
    }

    /// Returns the total logical size of the `$J` stream in bytes.
    #[must_use]
    pub fn j_size(&self) -> u64 {
        self.j_size
    }

    /// Returns an iterator over all USN records starting from `lowest_valid_usn`.
    #[must_use]
    pub fn records(&self) -> NtfsUsnRecords<'_> {
        NtfsUsnRecords::new(self, self.metadata.lowest_valid_usn)
    }

    /// Returns an iterator starting at a specific USN offset.
    #[must_use]
    pub fn records_from(&self, start_usn: u64) -> NtfsUsnRecords<'_> {
        NtfsUsnRecords::new(self, start_usn)
    }

    /// Reads and parses the `$Max` named data stream.
    fn read_max_metadata<T: Read + Seek>(
        usnjrnl_file: &crate::file::NtfsFile<'_>,
        fs: &mut T,
    ) -> Result<UsnJournalMetadata> {
        let max_item = find_named_data_attribute(usnjrnl_file, fs, "$Max")?;
        let max_attribute = max_item.to_attribute()?;
        let mut max_value = max_attribute.value(fs)?;

        let max_len = usize::try_from(max_value.len())
            .unwrap_or(USN_MAX_MIN_SIZE)
            .min(USN_MAX_MIN_SIZE);
        let mut buf = vec![0u8; max_len];
        max_value.read_exact(fs, &mut buf)?;

        let position = max_value.data_position();
        UsnJournalMetadata::from_bytes(&buf, position)
    }
}

/// Finds a named `$DATA` attribute on a file.
fn find_named_data_attribute<'n, 'f, T>(
    file: &'f crate::file::NtfsFile<'n>,
    fs: &mut T,
    name: &str,
) -> Result<crate::attribute::NtfsAttributeItem<'n, 'f>>
where
    T: Read + Seek,
{
    let mut iter = file.attributes();

    while let Some(item) = iter.try_next(fs)? {
        let attribute = item.to_attribute()?;

        if attribute.ty()? != NtfsAttributeType::Data {
            continue;
        }

        if attribute.name()? != name {
            continue;
        }

        return Ok(item);
    }

    Err(NtfsError::AttributeNotFound {
        position: file.position(),
        ty: NtfsAttributeType::Data,
    })
}

// ---------------------------------------------------------------------------
// NtfsUsnRecords (iterator)
// ---------------------------------------------------------------------------

/// Iterator over USN Journal records.
///
/// Automatically skips sparse holes in the `$J` stream. Yields
/// [`UsnRecord`] references borrowing from a caller-provided buffer.
///
/// Created by [`NtfsUsnJournal::records`] or [`NtfsUsnJournal::records_from`].
pub struct NtfsUsnRecords<'j> {
    journal: &'j NtfsUsnJournal,
    /// Current virtual byte offset within `$J`.
    offset: u64,
}

impl NtfsUsnRecords<'_> {
    /// Returns the current virtual byte offset within the `$J` stream.
    ///
    /// This is useful for resuming iteration or reporting progress.
    #[must_use]
    pub fn current_offset(&self) -> u64 {
        self.offset
    }
}

impl<'j> NtfsUsnRecords<'j> {
    fn new(journal: &'j NtfsUsnJournal, start_offset: u64) -> Self {
        Self {
            journal,
            offset: start_offset,
        }
    }

    /// Returns the next V2 USN record, skipping V3 and unknown versions.
    ///
    /// The `buf` parameter is a reusable buffer for reading record data.
    /// The returned [`UsnRecord`] borrows from it.
    ///
    /// To iterate over both V2 and V3 records, use
    /// [`next_versioned`](Self::next_versioned).
    pub fn next<'b, T: Read + Seek>(
        &mut self,
        fs: &mut T,
        buf: &'b mut Vec<u8>,
    ) -> Option<Result<UsnRecord<'b>>> {
        loop {
            let major = iter_try!(self.read_next_record(fs, buf));
            let major = major?;
            let record_length = u64::from(u32::from_le_bytes(validated_usn_bytes(
                buf,
                OFF_RECORD_LENGTH,
            )));
            let position = NtfsPosition::new(self.offset.saturating_sub(record_length));
            if major == 2 {
                return Some(UsnRecord::new(buf, position));
            }
            // Skip V3 and unknown versions.
        }
    }

    /// Returns the next USN record of any supported version.
    ///
    /// The `buf` parameter is a reusable buffer for reading record
    /// data. The returned [`UsnRecordVersion`] borrows from it.
    pub fn next_versioned<'b, T: Read + Seek>(
        &mut self,
        fs: &mut T,
        buf: &'b mut Vec<u8>,
    ) -> Option<Result<UsnRecordVersion<'b>>> {
        loop {
            let major = iter_try!(self.read_next_record(fs, buf));
            let major = major?;
            let record_length = u64::from(u32::from_le_bytes(validated_usn_bytes(
                buf,
                OFF_RECORD_LENGTH,
            )));
            let position = NtfsPosition::new(self.offset.saturating_sub(record_length));
            match major {
                2 => {
                    return Some(UsnRecord::new(buf, position).map(UsnRecordVersion::V2));
                }
                3 => {
                    return Some(UsnRecordV3::new(buf, position).map(UsnRecordVersion::V3));
                }
                _ => {}
            }
        }
    }

    /// Reads the next raw record into `buf`, advancing `self.offset`.
    ///
    /// Returns the major version number on success, or `None` if the
    /// journal is exhausted. Skips sparse holes and zero-length
    /// records automatically.
    fn read_next_record<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        buf: &mut Vec<u8>,
    ) -> Result<Option<u16>> {
        loop {
            if self.offset >= self.journal.j_size {
                return Ok(None);
            }

            let Some((pos, remaining)) = self.journal.map.resolve_position(self.offset) else {
                return Ok(None);
            };

            // Sparse region — skip to next non-sparse segment.
            if pos.value().is_none() {
                match self.journal.map.next_non_sparse_offset(self.offset) {
                    Some(next) if next > self.offset => {
                        self.offset = next;
                        continue;
                    }
                    _ => return Ok(None),
                }
            }

            let Some(disk_pos) = pos.value().map(core::num::NonZero::get) else {
                return Ok(None);
            };

            if remaining < 4 {
                return Ok(None);
            }

            let mut len_buf = [0u8; 4];
            fs.seek(SeekFrom::Start(disk_pos))?;
            fs.read_exact(&mut len_buf)?;

            let record_length_u32 = u32::from_le_bytes(len_buf);
            let record_length_u64 = u64::from(record_length_u32);
            let record_length =
                usize::try_from(record_length_u32).map_err(|_| NtfsError::InvalidUsnRecord {
                    position: pos,
                    reason: "record length cannot be represented on this target",
                })?;

            // Zero length = sparse hole boundary or end of data.
            if record_length == 0 {
                let seg_end = self.journal.map.segment_end(self.offset);
                match self.journal.map.next_non_sparse_offset(seg_end) {
                    Some(next) if next > self.offset => {
                        self.offset = next;
                        continue;
                    }
                    _ => return Ok(None),
                }
            }

            // Need at least the 8-byte common header
            // (RecordLength + MajorVersion + MinorVersion) to
            // determine the version before doing version-specific
            // size validation.
            if record_length < USN_RECORD_MIN_COMMON_HEADER || record_length_u64 > remaining {
                let seg_end = self.journal.map.segment_end(self.offset);
                if seg_end > self.offset {
                    self.offset = seg_end;
                } else {
                    self.offset += USN_RECORD_MIN_COMMON_HEADER_U64;
                }
                continue;
            }

            // Read full record into buf.
            buf.resize(record_length, 0);
            buf[..4].copy_from_slice(&len_buf);
            fs.read_exact(&mut buf[4..])?;

            let major = u16::from_le_bytes(validated_usn_bytes(buf, OFF_MAJOR_VERSION));

            self.offset += record_length_u64;

            return Ok(Some(major));
        }
    }
}

#[cfg(test)]
#[path = "usn_journal_tests/mod.rs"]
mod tests;
