use alloc::boxed::Box;
use core::ops::Range;

use fs_common::error::{self as fse, FsError};
use thiserror::Error;

use crate::attribute::NtfsAttributeType;
use crate::io;
use crate::types::NtfsPosition;
use crate::types::{Lcn, Vcn};

/// Central result type of ntfs.
pub type Result<T, E = NtfsError> = core::result::Result<T, E>;

/// Central error type of ntfs.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NtfsError {
    #[error(
        "The NTFS file at byte position {position:#x} has no attribute of type {ty:?}, but it was expected"
    )]
    AttributeNotFound {
        position: NtfsPosition,
        ty: NtfsAttributeType,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should have type {expected:?}, but it actually has type {actual:?}"
    )]
    AttributeOfDifferentType {
        position: NtfsPosition,
        expected: NtfsAttributeType,
        actual: NtfsAttributeType,
    },
    #[error(
        "The given buffer should have at least {expected} bytes, but it only has {actual} bytes"
    )]
    BufferTooSmall { expected: usize, actual: usize },
    #[error(
        "The NTFS Record at byte position {position:#x} is too small: expected at least {expected} bytes for the header, but only has {actual} bytes"
    )]
    RecordTooSmall {
        position: NtfsPosition,
        expected: usize,
        actual: usize,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} has a length of {expected} bytes, but only {actual} bytes are left in the record"
    )]
    InvalidAttributeLength {
        position: NtfsPosition,
        expected: usize,
        actual: usize,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} indicates a name length up to offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    InvalidAttributeNameLength {
        position: NtfsPosition,
        expected: usize,
        actual: u32,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} indicates that its name starts at offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    InvalidAttributeNameOffset {
        position: NtfsPosition,
        expected: u16,
        actual: u32,
    },
    #[error(
        "The NTFS Data Run header at byte position {position:#x} indicates a maximum byte count of {expected}, but {actual} is the limit"
    )]
    InvalidByteCountInDataRunHeader {
        position: NtfsPosition,
        expected: u8,
        actual: u8,
    },
    #[error(
        "The cluster count {cluster_count} read from the NTFS Data Run header at byte position {position:#x} is invalid"
    )]
    InvalidClusterCountInDataRunHeader {
        position: NtfsPosition,
        cluster_count: u64,
    },
    #[error(
        "The NTFS File Record at byte position {position:#x} indicates an allocated size of {expected} bytes, but the record only has a size of {actual} bytes"
    )]
    InvalidFileAllocatedSize {
        position: NtfsPosition,
        expected: u32,
        actual: u32,
    },
    #[error("The requested NTFS File Record Number {file_record_number} is invalid")]
    InvalidFileRecordNumber { file_record_number: u64 },
    #[error(
        "The NTFS File Record at byte position {position:#x} should have signature {expected:?}, but it has signature {actual:?}"
    )]
    InvalidFileSignature {
        position: NtfsPosition,
        expected: &'static [u8],
        actual: [u8; 4],
    },
    #[error(
        "The NTFS File Record at byte position {position:#x} indicates a used size of {expected} bytes, but only {actual} bytes are allocated"
    )]
    InvalidFileUsedSize {
        position: NtfsPosition,
        expected: u32,
        actual: u32,
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} indicates an allocated size of {expected} bytes, but the record only has a size of {actual} bytes"
    )]
    InvalidIndexAllocatedSize {
        position: NtfsPosition,
        expected: u32,
        actual: u32,
    },
    #[error(
        "The NTFS Index Entry at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    InvalidIndexEntryDataRange {
        position: NtfsPosition,
        range: Range<usize>,
        size: u16,
    },
    #[error(
        "The NTFS Index Entry at byte position {position:#x} reports a size of {expected} bytes, but it only has {actual} bytes"
    )]
    InvalidIndexEntrySize {
        position: NtfsPosition,
        expected: u16,
        actual: u16,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} indicates that its entries start at offset {expected}, but the index root only has a size of {actual} bytes"
    )]
    InvalidIndexRootEntriesOffset {
        position: NtfsPosition,
        expected: usize,
        actual: usize,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} indicates a used size up to offset {expected}, but the index root only has a size of {actual} bytes"
    )]
    InvalidIndexRootUsedSize {
        position: NtfsPosition,
        expected: usize,
        actual: usize,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} has an invalid entries range: entries start at offset {start}, but the index data ends at offset {end}"
    )]
    InvalidIndexRootEntriesRange {
        position: NtfsPosition,
        start: usize,
        end: usize,
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} should have signature {expected:?}, but it has signature {actual:?}"
    )]
    InvalidIndexSignature {
        position: NtfsPosition,
        expected: &'static [u8],
        actual: [u8; 4],
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} indicates a used size of {expected} bytes, but only {actual} bytes are allocated"
    )]
    InvalidIndexUsedSize {
        position: NtfsPosition,
        expected: u32,
        actual: u32,
    },
    #[error("The MFT LCN in the BIOS Parameter Block of the NTFS filesystem is invalid.")]
    InvalidMftLcn,
    #[error("The MFT Mirror LCN in the BIOS Parameter Block of the NTFS filesystem is invalid.")]
    InvalidMftMirrLcn,
    #[error(
        "The NTFS Non Resident Value Data at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    InvalidNonResidentValueDataRange {
        position: NtfsPosition,
        range: Range<usize>,
        size: usize,
    },
    #[error(
        "The resident NTFS Attribute at byte position {position:#x} indicates a value length of {length} starting at offset {offset}, but the attribute only has a size of {actual} bytes"
    )]
    InvalidResidentAttributeValueLength {
        position: NtfsPosition,
        length: u32,
        offset: u16,
        actual: u32,
    },
    #[error(
        "The resident NTFS Attribute at byte position {position:#x} indicates that its value starts at offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    InvalidResidentAttributeValueOffset {
        position: NtfsPosition,
        expected: u16,
        actual: u32,
    },
    #[error(
        "A record size field in the BIOS Parameter Block denotes {size_info}, which is invalid considering the cluster size of {cluster_size} bytes"
    )]
    InvalidRecordSizeInfo { size_info: i8, cluster_size: u32 },
    #[error(
        "The sectors per cluster field in the BIOS Parameter Block denotes {sectors_per_cluster:#04x}, which is invalid"
    )]
    InvalidSectorsPerCluster { sectors_per_cluster: u8 },
    #[error(
        "The NTFS structured value at byte position {position:#x} of type {ty:?} has {actual} bytes where {expected} bytes were expected"
    )]
    InvalidStructuredValueSize {
        position: NtfsPosition,
        ty: NtfsAttributeType,
        expected: u64,
        actual: u64,
    },
    #[error("The given time cannot be represented as the target type")]
    InvalidTime,
    #[error(
        "The 2-byte signature field at byte position {position:#x} should contain {expected:?}, but it contains {actual:?}"
    )]
    InvalidTwoByteSignature {
        position: NtfsPosition,
        expected: &'static [u8],
        actual: [u8; 2],
    },
    #[error(
        "The OEM ID at byte position {position:#x} should be {expected:?}, but it is {actual:?}"
    )]
    InvalidOemId {
        position: NtfsPosition,
        expected: &'static [u8; 8],
        actual: [u8; 8],
    },
    #[error(
        "The volume at byte position {position:#x} is BitLocker-encrypted (OEM ID: {oem_id:?}). Decrypt the volume before parsing as NTFS."
    )]
    BitLockerEncrypted {
        position: NtfsPosition,
        oem_id: [u8; 8],
    },
    #[error("The Upcase Table should have a size of {expected} bytes, but it has {actual} bytes")]
    InvalidUpcaseTableSize { expected: u64, actual: u64 },
    #[error(
        "The NTFS Update Sequence Count of the record at byte position {position:#x} has the invalid value {update_sequence_count}"
    )]
    InvalidUpdateSequenceCount {
        position: NtfsPosition,
        update_sequence_count: u16,
    },
    #[error(
        "The NTFS Update Sequence Number of the record at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    InvalidUpdateSequenceNumberRange {
        position: NtfsPosition,
        range: Range<usize>,
        size: usize,
    },
    #[error(
        "The VCN {vcn} read from the NTFS Data Run header at byte position {position:#x} cannot be added to the LCN {previous_lcn} calculated from previous data runs"
    )]
    InvalidVcnInDataRunHeader {
        position: NtfsPosition,
        vcn: Vcn,
        previous_lcn: Lcn,
    },
    #[error("I/O error: {0:?}")]
    Io(io::Error),
    #[error(
        "The Logical Cluster Number (LCN) {lcn} is too big to be multiplied by the cluster size"
    )]
    LcnTooBig { lcn: Lcn },
    #[error(
        "The index root at byte position {position:#x} is a large index, but no matching index allocation attribute was provided"
    )]
    MissingIndexAllocation { position: NtfsPosition },
    #[error("The NTFS file at byte position {position:#x} is not a directory")]
    NotADirectory { position: NtfsPosition },
    #[error(
        "The total sector count {total_sectors} is too big to be multiplied by the sector size"
    )]
    TotalSectorsTooBig { total_sectors: u64 },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should not belong to an Attribute List, but it does"
    )]
    UnexpectedAttributeListAttribute { position: NtfsPosition },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should be resident, but it is non-resident"
    )]
    UnexpectedNonResidentAttribute { position: NtfsPosition },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should be non-resident, but it is resident"
    )]
    UnexpectedResidentAttribute { position: NtfsPosition },
    #[error(
        "The type of the NTFS Attribute at byte position {position:#x} is {actual:#010x}, which is not supported"
    )]
    UnsupportedAttributeType { position: NtfsPosition, actual: u32 },
    #[error("The cluster size is {actual} bytes, but it needs to be between {min} and {max}")]
    UnsupportedClusterSize { min: u32, max: u32, actual: u32 },
    #[error(
        "The namespace of the NTFS file name starting at byte position {position:#x} is {actual}, which is not supported"
    )]
    UnsupportedFileNamespace { position: NtfsPosition, actual: u8 },
    #[error("The sector size is {actual} bytes, but it needs to be between {min} and {max}")]
    UnsupportedSectorSize { min: u16, max: u16, actual: u16 },
    #[error(
        "The Update Sequence Array (USA) of the record at byte position {position:#x} has entries for {array_count} blocks of 512 bytes, but the record is only {record_size} bytes long"
    )]
    UpdateSequenceArrayExceedsRecordSize {
        position: NtfsPosition,
        array_count: u16,
        record_size: usize,
    },
    #[error(
        "Sector corruption: The 2 bytes at byte position {position:#x} should match the Update Sequence Number (USN) {expected:?}, but they are {actual:?}"
    )]
    UpdateSequenceNumberMismatch {
        position: NtfsPosition,
        expected: [u8; 2],
        actual: [u8; 2],
    },
    #[error(
        "The index allocation at byte position {position:#x} references a Virtual Cluster Number (VCN) {expected}, but a record with VCN {actual} is found at that offset"
    )]
    VcnMismatchInIndexAllocation {
        position: NtfsPosition,
        expected: Vcn,
        actual: Vcn,
    },
    #[error(
        "The index allocation at byte position {position:#x} references a Virtual Cluster Number (VCN) {vcn}, but this VCN exceeds the boundaries of the filesystem"
    )]
    VcnOutOfBoundsInIndexAllocation { position: NtfsPosition, vcn: Vcn },
    #[error(
        "The Virtual Cluster Number (VCN) {vcn} is too big to be multiplied by the cluster size"
    )]
    VcnTooBig { vcn: Vcn },
    #[error("Cluster {cluster} is out of range (filesystem has {total} clusters)")]
    ClusterOutOfRange { cluster: u64, total: u64 },
    #[error("Invalid USN record at byte position {position:#x}: {reason}")]
    InvalidUsnRecord {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Decompression failed: {message}")]
    DecompressionError { message: alloc::string::String },
    #[error("Invalid WOF compressed data: {reason}")]
    InvalidWofData { reason: &'static str },
    #[error("Invalid SID at byte position {position:#x}: {reason}")]
    InvalidSid {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid security descriptor at byte position {position:#x}: {reason}")]
    InvalidSecurityDescriptor {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid ACL at byte position {position:#x}: {reason}")]
    InvalidAcl {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid quota entry at byte position {position:#x}: {reason}")]
    InvalidQuotaEntry {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid $O index entry at byte position {position:#x}: {reason}")]
    InvalidObjectIdIndexEntry {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid reparse point index entry at byte position {position:#x}: {reason}")]
    InvalidReparsePointIndexEntry {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid ACE at byte position {position:#x}: {reason}")]
    InvalidAce {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid $SDS entry at byte position {position:#x}: {reason}")]
    InvalidSdsEntry {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error(
        "Circular attribute list reference at {position:#x}: MFT record {record_number} was already visited"
    )]
    CircularAttributeList {
        position: NtfsPosition,
        record_number: u64,
    },
    #[error("Feature not enabled: {feature}. Enable it in Cargo.toml.")]
    UnsupportedFeature { feature: &'static str },
    #[error("Attribute is compressed but compression support is not enabled")]
    CompressedAttributeNotSupported,
    #[error(
        "The NTFS B-tree index at byte position {position:#x} exceeds the maximum depth of {max_depth} levels"
    )]
    IndexBTreeTooDeep {
        position: NtfsPosition,
        max_depth: usize,
    },
    #[error("Invalid reparse point data at byte position {position:#x}: {reason}")]
    InvalidReparsePointData {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error(
        "Reparse tag mismatch at byte position {position:#x}: expected {expected:#010x}, actual {actual:#010x}"
    )]
    ReparseTagMismatch {
        position: NtfsPosition,
        expected: u32,
        actual: u32,
    },
    #[error(
        "Reparse data at byte position {position:#x} is too large: {size} bytes exceeds maximum of {max_size} bytes"
    )]
    ReparseDataTooLarge {
        position: NtfsPosition,
        size: usize,
        max_size: usize,
    },
    #[error("Invalid $LogFile record at byte position {position:#x}: {reason}")]
    InvalidLogFileRecord {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Unsupported LFS version {major}.{minor} at byte position {position:#x}")]
    UnsupportedLfsVersion {
        position: NtfsPosition,
        major: u16,
        minor: u16,
    },
    #[error("Invalid EFS metadata at byte position {position:#x}: {reason}")]
    InvalidEfsMetadata {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Invalid TxF $TXF_DATA at byte position {position:#x}: {reason}")]
    InvalidTxfData {
        position: NtfsPosition,
        reason: &'static str,
    },
    #[error("Failed to parse MFT record {record_number}: {source}")]
    MftRecordParseFailed {
        record_number: u64,
        #[source]
        source: Box<NtfsError>,
    },
}

impl From<io::Error> for NtfsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// In no_std mode, io::Error = IoError, so From<io::Error> already covers this.
// In std mode, we need an explicit conversion via From<IoError> for std::io::Error.
#[cfg(feature = "std")]
impl From<fse::IoError> for NtfsError {
    fn from(e: fse::IoError) -> Self {
        Self::Io(e.into())
    }
}

impl FsError for NtfsError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(e) = self else {
            return None;
        };
        Some(fse::ErrorKind::from(e.kind()))
    }

    fn byte_offset(&self) -> Option<u64> {
        match self {
            Self::AttributeNotFound { position, .. }
            | Self::AttributeOfDifferentType { position, .. }
            | Self::RecordTooSmall { position, .. }
            | Self::InvalidAttributeLength { position, .. }
            | Self::InvalidAttributeNameLength { position, .. }
            | Self::InvalidAttributeNameOffset { position, .. }
            | Self::InvalidByteCountInDataRunHeader { position, .. }
            | Self::InvalidClusterCountInDataRunHeader { position, .. }
            | Self::InvalidFileAllocatedSize { position, .. }
            | Self::InvalidFileSignature { position, .. }
            | Self::InvalidFileUsedSize { position, .. }
            | Self::InvalidIndexAllocatedSize { position, .. }
            | Self::InvalidIndexEntryDataRange { position, .. }
            | Self::InvalidIndexEntrySize { position, .. }
            | Self::InvalidIndexRootEntriesOffset { position, .. }
            | Self::InvalidIndexRootUsedSize { position, .. }
            | Self::InvalidIndexRootEntriesRange { position, .. }
            | Self::InvalidIndexSignature { position, .. }
            | Self::InvalidIndexUsedSize { position, .. }
            | Self::InvalidNonResidentValueDataRange { position, .. }
            | Self::InvalidResidentAttributeValueLength { position, .. }
            | Self::InvalidResidentAttributeValueOffset { position, .. }
            | Self::InvalidStructuredValueSize { position, .. }
            | Self::InvalidTwoByteSignature { position, .. }
            | Self::InvalidOemId { position, .. }
            | Self::BitLockerEncrypted { position, .. }
            | Self::InvalidUpdateSequenceCount { position, .. }
            | Self::InvalidUpdateSequenceNumberRange { position, .. }
            | Self::InvalidVcnInDataRunHeader { position, .. }
            | Self::MissingIndexAllocation { position }
            | Self::NotADirectory { position }
            | Self::UnexpectedAttributeListAttribute { position }
            | Self::UnexpectedNonResidentAttribute { position }
            | Self::UnexpectedResidentAttribute { position }
            | Self::UnsupportedAttributeType { position, .. }
            | Self::UnsupportedFileNamespace { position, .. }
            | Self::UpdateSequenceArrayExceedsRecordSize { position, .. }
            | Self::UpdateSequenceNumberMismatch { position, .. }
            | Self::VcnMismatchInIndexAllocation { position, .. }
            | Self::VcnOutOfBoundsInIndexAllocation { position, .. }
            | Self::InvalidUsnRecord { position, .. }
            | Self::InvalidSid { position, .. }
            | Self::InvalidSecurityDescriptor { position, .. }
            | Self::InvalidAcl { position, .. }
            | Self::InvalidQuotaEntry { position, .. }
            | Self::InvalidObjectIdIndexEntry { position, .. }
            | Self::InvalidReparsePointIndexEntry { position, .. }
            | Self::InvalidAce { position, .. }
            | Self::InvalidSdsEntry { position, .. }
            | Self::CircularAttributeList { position, .. }
            | Self::IndexBTreeTooDeep { position, .. }
            | Self::InvalidReparsePointData { position, .. }
            | Self::ReparseTagMismatch { position, .. }
            | Self::ReparseDataTooLarge { position, .. }
            | Self::InvalidLogFileRecord { position, .. }
            | Self::InvalidEfsMetadata { position, .. }
            | Self::InvalidTxfData { position, .. }
            | Self::UnsupportedLfsVersion { position, .. } => position.value().map(|v| v.get()),
            Self::BufferTooSmall { .. }
            | Self::InvalidFileRecordNumber { .. }
            | Self::InvalidMftLcn
            | Self::InvalidMftMirrLcn
            | Self::InvalidRecordSizeInfo { .. }
            | Self::InvalidSectorsPerCluster { .. }
            | Self::InvalidTime
            | Self::InvalidUpcaseTableSize { .. }
            | Self::Io(..)
            | Self::LcnTooBig { .. }
            | Self::TotalSectorsTooBig { .. }
            | Self::UnsupportedClusterSize { .. }
            | Self::UnsupportedSectorSize { .. }
            | Self::ClusterOutOfRange { .. }
            | Self::DecompressionError { .. }
            | Self::InvalidWofData { .. }
            | Self::UnsupportedFeature { .. }
            | Self::CompressedAttributeNotSupported
            | Self::MftRecordParseFailed { .. }
            | Self::VcnTooBig { .. } => None,
        }
    }
}

// To stay compatible with standardized interfaces (e.g. io::Read, io::Seek),
// we sometimes need to convert from NtfsError to io::Error.
impl From<NtfsError> for io::Error {
    fn from(error: NtfsError) -> Self {
        match error {
            NtfsError::Io(e) => e,
            #[cfg(feature = "std")]
            other => std::io::Error::other(other),
            #[cfg(not(feature = "std"))]
            _ => io::ErrorKind::Other.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mft_record_parse_failed_display_includes_record_and_cause() {
        let inner = NtfsError::InvalidFileSignature {
            position: NtfsPosition::none(),
            expected: b"FILE",
            actual: [0x00, 0x00, 0x00, 0x00],
        };
        let outer = NtfsError::MftRecordParseFailed {
            record_number: 42,
            source: Box::new(inner),
        };
        let msg = outer.to_string();
        assert!(
            msg.contains("42"),
            "Display should include record number: {msg}",
        );
        assert!(
            msg.contains("signature"),
            "Display should include inner cause: {msg}",
        );
    }

    #[test]
    fn test_mft_record_parse_failed_source_chain() {
        use std::error::Error;

        let inner = NtfsError::InvalidFileSignature {
            position: NtfsPosition::none(),
            expected: b"FILE",
            actual: [0xDE, 0xAD, 0xBE, 0xEF],
        };
        let outer = NtfsError::MftRecordParseFailed {
            record_number: 99,
            source: Box::new(inner),
        };
        let source = outer.source().expect("should have source");
        let source_msg = source.to_string();
        assert!(
            source_msg.contains("signature"),
            "source should be the inner error: {source_msg}",
        );
    }

    #[test]
    fn test_mft_record_parse_failed_pattern_match() {
        let inner = NtfsError::UpdateSequenceNumberMismatch {
            position: NtfsPosition::none(),
            expected: [0x01, 0x00],
            actual: [0xFF, 0xFF],
        };
        let error = NtfsError::MftRecordParseFailed {
            record_number: 1234,
            source: Box::new(inner),
        };
        match &error {
            NtfsError::MftRecordParseFailed {
                record_number,
                source,
            } => {
                assert_eq!(*record_number, 1234);
                assert!(matches!(
                    **source,
                    NtfsError::UpdateSequenceNumberMismatch { .. }
                ),);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn fs_error_io_kind_maps_correctly() {
        let err = NtfsError::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "test"));
        assert_eq!(FsError::io_kind(&err), Some(fse::ErrorKind::UnexpectedEof),);
    }

    #[test]
    fn fs_error_non_io_has_no_io_kind() {
        let err = NtfsError::InvalidTime;
        assert_eq!(FsError::io_kind(&err), None);
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        // The `NtfsError::Io(e) => e` arm must return the wrapped error
        // unchanged, preserving its original kind. Deleting the arm would
        // re-wrap it via `io::Error::other`, downgrading the kind to `Other`.
        let original = NtfsError::Io(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
        let converted: io::Error = original.into();
        assert_eq!(converted.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        // A non-Io error has no inherent io kind, so the conversion wraps it.
        let converted: io::Error = NtfsError::InvalidTime.into();
        assert_ne!(converted.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn fs_error_byte_offset_from_position() {
        let err = NtfsError::InvalidFileSignature {
            position: NtfsPosition::new(0x1000),
            expected: b"FILE",
            actual: [0; 4],
        };
        assert_eq!(FsError::byte_offset(&err), Some(0x1000));
    }

    #[test]
    fn fs_error_byte_offset_none_position() {
        let err = NtfsError::InvalidFileSignature {
            position: NtfsPosition::none(),
            expected: b"FILE",
            actual: [0; 4],
        };
        // NtfsPosition::none() wraps None, so byte_offset is None
        assert_eq!(FsError::byte_offset(&err), None);
    }

    #[test]
    fn fs_error_byte_offset_no_position_variant() {
        let err = NtfsError::InvalidTime;
        assert_eq!(FsError::byte_offset(&err), None);
    }

    #[test]
    fn from_fs_common_io_error() {
        let io_err = fse::IoError::new(fse::ErrorKind::Interrupted);
        let ntfs_err: NtfsError = io_err.into();
        match ntfs_err {
            NtfsError::Io(e) => {
                assert_eq!(e.kind(), io::ErrorKind::Interrupted);
            }
            _ => panic!("Expected NtfsError::Io"),
        }
    }

    #[test]
    fn test_bitlocker_encrypted_display() {
        let err = NtfsError::BitLockerEncrypted {
            position: NtfsPosition::new(0x03),
            oem_id: *b"-FVE-FS-",
        };
        let msg = err.to_string();
        assert!(msg.contains("BitLocker"), "should mention BitLocker: {msg}");
        assert!(msg.contains("0x3"), "should include position: {msg}");
        assert!(msg.contains("Decrypt"), "should suggest decryption: {msg}");
    }

    #[test]
    fn test_bitlocker_encrypted_byte_offset() {
        let err = NtfsError::BitLockerEncrypted {
            position: NtfsPosition::new(0x03),
            oem_id: *b"-FVE-FS-",
        };
        assert_eq!(FsError::byte_offset(&err), Some(3));
    }
}
