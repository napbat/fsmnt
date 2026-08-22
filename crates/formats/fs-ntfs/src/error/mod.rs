use alloc::boxed::Box;
use core::ops::Range;

use fsmnt_parser_core::error::{self as fse, ParserError};
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
    #[doc = "Reports that the requested attribute could not be located."]
    AttributeNotFound {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "NTFS attribute type involved in the failure."]
        ty: NtfsAttributeType,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should have type {expected:?}, but it actually has type {actual:?}"
    )]
    #[doc = "Reports the attribute of different type condition encountered while reading NTFS data."]
    AttributeOfDifferentType {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: NtfsAttributeType,
        #[doc = "Value or size observed in the input."]
        actual: NtfsAttributeType,
    },
    #[error(
        "The given buffer should have at least {expected} bytes, but it only has {actual} bytes"
    )]
    #[doc = "Reports that the buffer does not contain the bytes required by the NTFS format."]
    BufferTooSmall {
        #[doc = "Diagnostic `BufferTooSmall` value retained from the affected on-disk structure."]
        expected: usize,
        #[doc = "Diagnostic `BufferTooSmall` value retained from the affected on-disk structure."]
        actual: usize,
    },
    #[error(
        "The NTFS Record at byte position {position:#x} is too small: expected at least {expected} bytes for the header, but only has {actual} bytes"
    )]
    #[doc = "Reports that the record does not contain the bytes required by the NTFS format."]
    RecordTooSmall {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} has a length of {expected} bytes, but only {actual} bytes are left in the record"
    )]
    #[doc = "Reports malformed or inconsistent attribute length metadata."]
    InvalidAttributeLength {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} indicates a name length up to offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent attribute name length metadata."]
    InvalidAttributeNameLength {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} indicates that its name starts at offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent attribute name offset metadata."]
    InvalidAttributeNameOffset {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u16,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "The NTFS Data Run header at byte position {position:#x} indicates a maximum byte count of {expected}, but {actual} is the limit"
    )]
    #[doc = "Reports malformed or inconsistent byte count in data run header metadata."]
    InvalidByteCountInDataRunHeader {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u8,
        #[doc = "Value or size observed in the input."]
        actual: u8,
    },
    #[error(
        "The cluster count {cluster_count} read from the NTFS Data Run header at byte position {position:#x} is invalid"
    )]
    #[doc = "Reports malformed or inconsistent cluster count in data run header metadata."]
    InvalidClusterCountInDataRunHeader {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Cluster count decoded from the data-run header."]
        cluster_count: u64,
    },
    #[error(
        "The NTFS File Record at byte position {position:#x} indicates an allocated size of {expected} bytes, but the record only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent file allocated size metadata."]
    InvalidFileAllocatedSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error("The requested NTFS File Record Number {file_record_number} is invalid")]
    #[doc = "Reports malformed or inconsistent file record number metadata."]
    InvalidFileRecordNumber {
        #[doc = "Diagnostic `InvalidFileRecordNumber` value retained from the affected on-disk structure."]
        file_record_number: u64,
    },
    #[error(
        "The NTFS File Record at byte position {position:#x} should have signature {expected:?}, but it has signature {actual:?}"
    )]
    #[doc = "Reports malformed or inconsistent file signature metadata."]
    InvalidFileSignature {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: &'static [u8],
        #[doc = "Value or size observed in the input."]
        actual: [u8; 4],
    },
    #[error(
        "The NTFS File Record at byte position {position:#x} indicates a used size of {expected} bytes, but only {actual} bytes are allocated"
    )]
    #[doc = "Reports malformed or inconsistent file used size metadata."]
    InvalidFileUsedSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u32,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} indicates an allocated size of {expected} bytes, but the record only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent index allocated size metadata."]
    InvalidIndexAllocatedSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u64,
        #[doc = "Value or size observed in the input."]
        actual: u64,
    },
    #[error(
        "The NTFS Index Entry at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    #[doc = "Reports malformed or inconsistent index entry data range metadata."]
    InvalidIndexEntryDataRange {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Byte range referenced by the malformed structure."]
        range: Range<usize>,
        #[doc = "Encoded or computed size involved in the failure."]
        size: usize,
    },
    #[error(
        "The NTFS Index Entry at byte position {position:#x} reports a size of {expected} bytes, but it only has {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent index entry size metadata."]
    InvalidIndexEntrySize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} indicates that its entries start at offset {expected}, but the index root only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent index root entries offset metadata."]
    InvalidIndexRootEntriesOffset {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} indicates a used size up to offset {expected}, but the index root only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent index root used size metadata."]
    InvalidIndexRootUsedSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: usize,
        #[doc = "Value or size observed in the input."]
        actual: usize,
    },
    #[error(
        "The NTFS index root at byte position {position:#x} has an invalid entries range: entries start at offset {start}, but the index data ends at offset {end}"
    )]
    #[doc = "Reports malformed or inconsistent index root entries range metadata."]
    InvalidIndexRootEntriesRange {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Starting byte offset of the invalid range."]
        start: usize,
        #[doc = "Ending byte offset of the invalid range."]
        end: usize,
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} should have signature {expected:?}, but it has signature {actual:?}"
    )]
    #[doc = "Reports malformed or inconsistent index signature metadata."]
    InvalidIndexSignature {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: &'static [u8],
        #[doc = "Value or size observed in the input."]
        actual: [u8; 4],
    },
    #[error(
        "The NTFS Index Record at byte position {position:#x} indicates a used size of {expected} bytes, but only {actual} bytes are allocated"
    )]
    #[doc = "Reports malformed or inconsistent index used size metadata."]
    InvalidIndexUsedSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u64,
        #[doc = "Value or size observed in the input."]
        actual: u64,
    },
    #[error("The MFT LCN in the BIOS Parameter Block of the NTFS filesystem is invalid.")]
    #[doc = "Reports malformed or inconsistent mft lcn metadata."]
    InvalidMftLcn,
    #[error("The MFT Mirror LCN in the BIOS Parameter Block of the NTFS filesystem is invalid.")]
    #[doc = "Reports malformed or inconsistent mft mirr lcn metadata."]
    InvalidMftMirrLcn,
    #[error(
        "The NTFS Non Resident Value Data at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    #[doc = "Reports malformed or inconsistent non resident value data range metadata."]
    InvalidNonResidentValueDataRange {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Byte range referenced by the malformed structure."]
        range: Range<usize>,
        #[doc = "Encoded or computed size involved in the failure."]
        size: usize,
    },
    #[error(
        "The resident NTFS Attribute at byte position {position:#x} indicates a value length of {length} starting at offset {offset}, but the attribute only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent resident attribute value length metadata."]
    InvalidResidentAttributeValueLength {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Encoded length that failed validation."]
        length: u32,
        #[doc = "Encoded byte offset that failed validation."]
        offset: u16,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "The resident NTFS Attribute at byte position {position:#x} indicates that its value starts at offset {expected}, but the attribute only has a size of {actual} bytes"
    )]
    #[doc = "Reports malformed or inconsistent resident attribute value offset metadata."]
    InvalidResidentAttributeValueOffset {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u16,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "A record size field in the BIOS Parameter Block denotes {size_info}, which is invalid considering the cluster size of {cluster_size} bytes"
    )]
    #[doc = "Reports malformed or inconsistent record size info metadata."]
    InvalidRecordSizeInfo {
        #[doc = "Diagnostic `InvalidRecordSizeInfo` value retained from the affected on-disk structure."]
        size_info: i8,
        #[doc = "Diagnostic `InvalidRecordSizeInfo` value retained from the affected on-disk structure."]
        cluster_size: u32,
    },
    #[error(
        "The sectors per cluster field in the BIOS Parameter Block denotes {sectors_per_cluster:#04x}, which is invalid"
    )]
    #[doc = "Reports malformed or inconsistent sectors per cluster metadata."]
    InvalidSectorsPerCluster {
        #[doc = "Diagnostic `InvalidSectorsPerCluster` value retained from the affected on-disk structure."]
        sectors_per_cluster: u8,
    },
    #[error(
        "The NTFS structured value at byte position {position:#x} of type {ty:?} has {actual} bytes where {expected} bytes were expected"
    )]
    #[doc = "Reports malformed or inconsistent structured value size metadata."]
    InvalidStructuredValueSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "NTFS attribute type involved in the failure."]
        ty: NtfsAttributeType,
        #[doc = "Value or size required by the NTFS format."]
        expected: u64,
        #[doc = "Value or size observed in the input."]
        actual: u64,
    },
    #[error("The given time cannot be represented as the target type")]
    #[doc = "Reports malformed or inconsistent time metadata."]
    InvalidTime,
    #[error(
        "The 2-byte signature field at byte position {position:#x} should contain {expected:?}, but it contains {actual:?}"
    )]
    #[doc = "Reports malformed or inconsistent two byte signature metadata."]
    InvalidTwoByteSignature {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: &'static [u8],
        #[doc = "Value or size observed in the input."]
        actual: [u8; 2],
    },
    #[error(
        "The OEM ID at byte position {position:#x} should be {expected:?}, but it is {actual:?}"
    )]
    #[doc = "Reports malformed or inconsistent oem id metadata."]
    InvalidOemId {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: &'static [u8; 8],
        #[doc = "Value or size observed in the input."]
        actual: [u8; 8],
    },
    #[error(
        "The volume at byte position {position:#x} is BitLocker-encrypted (OEM ID: {oem_id:?}). Decrypt the volume before parsing as NTFS."
    )]
    #[doc = "Reports the bit locker encrypted condition encountered while reading NTFS data."]
    BitLockerEncrypted {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic oem id value retained from the affected on-disk structure."]
        oem_id: [u8; 8],
    },
    #[error("The Upcase Table should have a size of {expected} bytes, but it has {actual} bytes")]
    #[doc = "Reports malformed or inconsistent upcase table size metadata."]
    InvalidUpcaseTableSize {
        #[doc = "Diagnostic `InvalidUpcaseTableSize` value retained from the affected on-disk structure."]
        expected: u64,
        #[doc = "Diagnostic `InvalidUpcaseTableSize` value retained from the affected on-disk structure."]
        actual: u64,
    },
    #[error(
        "The NTFS Update Sequence Count of the record at byte position {position:#x} has the invalid value {update_sequence_count}"
    )]
    #[doc = "Reports malformed or inconsistent update sequence count metadata."]
    InvalidUpdateSequenceCount {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic update sequence count value retained from the affected on-disk structure."]
        update_sequence_count: u16,
    },
    #[error(
        "The NTFS Update Sequence Number of the record at byte position {position:#x} references a data field in the range {range:?}, but the entry only has a size of {size} bytes"
    )]
    #[doc = "Reports malformed or inconsistent update sequence number range metadata."]
    InvalidUpdateSequenceNumberRange {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Byte range referenced by the malformed structure."]
        range: Range<usize>,
        #[doc = "Encoded or computed size involved in the failure."]
        size: usize,
    },
    #[error(
        "The VCN {vcn} read from the NTFS Data Run header at byte position {position:#x} cannot be added to the LCN {previous_lcn} calculated from previous data runs"
    )]
    #[doc = "Reports malformed or inconsistent vcn in data run header metadata."]
    InvalidVcnInDataRunHeader {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic vcn value retained from the affected on-disk structure."]
        vcn: Vcn,
        #[doc = "Diagnostic previous lcn value retained from the affected on-disk structure."]
        previous_lcn: Lcn,
    },
    #[error("I/O error: {0:?}")]
    #[doc = "Reports the io condition encountered while reading NTFS data."]
    Io(io::Error),
    #[error(
        "The Logical Cluster Number (LCN) {lcn} is too big to be multiplied by the cluster size"
    )]
    #[doc = "Reports the lcn too big condition encountered while reading NTFS data."]
    LcnTooBig {
        #[doc = "Diagnostic `LcnTooBig` value retained from the affected on-disk structure."]
        lcn: Lcn,
    },
    #[error(
        "The index root at byte position {position:#x} is a large index, but no matching index allocation attribute was provided"
    )]
    #[doc = "Reports the missing index allocation condition encountered while reading NTFS data."]
    MissingIndexAllocation {
        #[doc = "Diagnostic `MissingIndexAllocation` value retained from the affected on-disk structure."]
        position: NtfsPosition,
    },
    #[error("The NTFS file at byte position {position:#x} is not a directory")]
    #[doc = "Reports the not a directory condition encountered while reading NTFS data."]
    NotADirectory {
        #[doc = "Diagnostic `NotADirectory` value retained from the affected on-disk structure."]
        position: NtfsPosition,
    },
    #[error(
        "The total sector count {total_sectors} is too big to be multiplied by the sector size"
    )]
    #[doc = "Reports the total sectors too big condition encountered while reading NTFS data."]
    TotalSectorsTooBig {
        #[doc = "Diagnostic `TotalSectorsTooBig` value retained from the affected on-disk structure."]
        total_sectors: u64,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should not belong to an Attribute List, but it does"
    )]
    #[doc = "Reports the unexpected attribute list attribute condition encountered while reading NTFS data."]
    UnexpectedAttributeListAttribute {
        #[doc = "Diagnostic `UnexpectedAttributeListAttribute` value retained from the affected on-disk structure."]
        position: NtfsPosition,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should be resident, but it is non-resident"
    )]
    #[doc = "Reports the unexpected non resident attribute condition encountered while reading NTFS data."]
    UnexpectedNonResidentAttribute {
        #[doc = "Diagnostic `UnexpectedNonResidentAttribute` value retained from the affected on-disk structure."]
        position: NtfsPosition,
    },
    #[error(
        "The NTFS Attribute at byte position {position:#x} should be non-resident, but it is resident"
    )]
    #[doc = "Reports the unexpected resident attribute condition encountered while reading NTFS data."]
    UnexpectedResidentAttribute {
        #[doc = "Diagnostic `UnexpectedResidentAttribute` value retained from the affected on-disk structure."]
        position: NtfsPosition,
    },
    #[error(
        "The type of the NTFS Attribute at byte position {position:#x} is {actual:#010x}, which is not supported"
    )]
    #[doc = "Reports an unsupported attribute type value or feature."]
    UnsupportedAttributeType {
        #[doc = "Diagnostic `UnsupportedAttributeType` value retained from the affected on-disk structure."]
        position: NtfsPosition,
        #[doc = "Diagnostic `UnsupportedAttributeType` value retained from the affected on-disk structure."]
        actual: u32,
    },
    #[error("The cluster size is {actual} bytes, but it needs to be between {min} and {max}")]
    #[doc = "Reports an unsupported cluster size value or feature."]
    UnsupportedClusterSize {
        #[doc = "Diagnostic `UnsupportedClusterSize` value retained from the affected on-disk structure."]
        min: u32,
        #[doc = "Diagnostic `UnsupportedClusterSize` value retained from the affected on-disk structure."]
        max: u32,
        #[doc = "Diagnostic `UnsupportedClusterSize` value retained from the affected on-disk structure."]
        actual: u32,
    },
    #[error(
        "The namespace of the NTFS file name starting at byte position {position:#x} is {actual}, which is not supported"
    )]
    #[doc = "Reports an unsupported file namespace value or feature."]
    UnsupportedFileNamespace {
        #[doc = "Diagnostic `UnsupportedFileNamespace` value retained from the affected on-disk structure."]
        position: NtfsPosition,
        #[doc = "Diagnostic `UnsupportedFileNamespace` value retained from the affected on-disk structure."]
        actual: u8,
    },
    #[error("The sector size is {actual} bytes, but it needs to be between {min} and {max}")]
    #[doc = "Reports an unsupported sector size value or feature."]
    UnsupportedSectorSize {
        #[doc = "Diagnostic `UnsupportedSectorSize` value retained from the affected on-disk structure."]
        min: u16,
        #[doc = "Diagnostic `UnsupportedSectorSize` value retained from the affected on-disk structure."]
        max: u16,
        #[doc = "Diagnostic `UnsupportedSectorSize` value retained from the affected on-disk structure."]
        actual: u16,
    },
    #[error(
        "The Update Sequence Array (USA) of the record at byte position {position:#x} has entries for {array_count} blocks of 512 bytes, but the record is only {record_size} bytes long"
    )]
    #[doc = "Reports the update sequence array exceeds record size condition encountered while reading NTFS data."]
    UpdateSequenceArrayExceedsRecordSize {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic array count value retained from the affected on-disk structure."]
        array_count: u16,
        #[doc = "Diagnostic record size value retained from the affected on-disk structure."]
        record_size: usize,
    },
    #[error(
        "Sector corruption: The 2 bytes at byte position {position:#x} should match the Update Sequence Number (USN) {expected:?}, but they are {actual:?}"
    )]
    #[doc = "Reports the update sequence number mismatch condition encountered while reading NTFS data."]
    UpdateSequenceNumberMismatch {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: [u8; 2],
        #[doc = "Value or size observed in the input."]
        actual: [u8; 2],
    },
    #[error(
        "The index allocation at byte position {position:#x} references a Virtual Cluster Number (VCN) {expected}, but a record with VCN {actual} is found at that offset"
    )]
    #[doc = "Reports the vcn mismatch in index allocation condition encountered while reading NTFS data."]
    VcnMismatchInIndexAllocation {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: Vcn,
        #[doc = "Value or size observed in the input."]
        actual: Vcn,
    },
    #[error(
        "The index allocation at byte position {position:#x} references a Virtual Cluster Number (VCN) {vcn}, but this VCN exceeds the boundaries of the filesystem"
    )]
    #[doc = "Reports the vcn out of bounds in index allocation condition encountered while reading NTFS data."]
    VcnOutOfBoundsInIndexAllocation {
        #[doc = "Diagnostic `VcnOutOfBoundsInIndexAllocation` value retained from the affected on-disk structure."]
        position: NtfsPosition,
        #[doc = "Diagnostic `VcnOutOfBoundsInIndexAllocation` value retained from the affected on-disk structure."]
        vcn: Vcn,
    },
    #[error(
        "The Virtual Cluster Number (VCN) {vcn} is too big to be multiplied by the cluster size"
    )]
    #[doc = "Reports the vcn too big condition encountered while reading NTFS data."]
    VcnTooBig {
        #[doc = "Diagnostic `VcnTooBig` value retained from the affected on-disk structure."]
        vcn: Vcn,
    },
    #[error("Cluster {cluster} is out of range (filesystem has {total} clusters)")]
    #[doc = "Reports the cluster out of range condition encountered while reading NTFS data."]
    ClusterOutOfRange {
        #[doc = "Diagnostic `ClusterOutOfRange` value retained from the affected on-disk structure."]
        cluster: u64,
        #[doc = "Diagnostic `ClusterOutOfRange` value retained from the affected on-disk structure."]
        total: u64,
    },
    #[error("Invalid USN record at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent usn record metadata."]
    InvalidUsnRecord {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Decompression failed: {message}")]
    #[doc = "Reports the decompression error condition encountered while reading NTFS data."]
    DecompressionError {
        #[doc = "Diagnostic `DecompressionError` value retained from the affected on-disk structure."]
        message: alloc::string::String,
    },
    #[error("Invalid WOF compressed data: {reason}")]
    #[doc = "Reports malformed or inconsistent wof data metadata."]
    InvalidWofData {
        #[doc = "Diagnostic `InvalidWofData` value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid SID at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent sid metadata."]
    InvalidSid {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid security descriptor at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent security descriptor metadata."]
    InvalidSecurityDescriptor {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid ACL at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent acl metadata."]
    InvalidAcl {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid quota entry at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent quota entry metadata."]
    InvalidQuotaEntry {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid $O index entry at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent object id index entry metadata."]
    InvalidObjectIdIndexEntry {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid reparse point index entry at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent reparse point index entry metadata."]
    InvalidReparsePointIndexEntry {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid ACE at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent ace metadata."]
    InvalidAce {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid $SDS entry at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent sds entry metadata."]
    InvalidSdsEntry {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error(
        "Circular attribute list reference at {position:#x}: MFT record {record_number} was already visited"
    )]
    #[doc = "Reports the circular attribute list condition encountered while reading NTFS data."]
    CircularAttributeList {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic record number value retained from the affected on-disk structure."]
        record_number: u64,
    },
    #[error("Feature not enabled: {feature}. Enable it in Cargo.toml.")]
    #[doc = "Reports an unsupported feature value or feature."]
    UnsupportedFeature {
        #[doc = "Diagnostic `UnsupportedFeature` value retained from the affected on-disk structure."]
        feature: &'static str,
    },
    #[error("Attribute is compressed but compression support is not enabled")]
    #[doc = "Reports the compressed attribute not supported condition encountered while reading NTFS data."]
    CompressedAttributeNotSupported,
    #[error(
        "The NTFS B-tree index at byte position {position:#x} exceeds the maximum depth of {max_depth} levels"
    )]
    #[doc = "Reports the index b tree too deep condition encountered while reading NTFS data."]
    IndexBTreeTooDeep {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic max depth value retained from the affected on-disk structure."]
        max_depth: usize,
    },
    #[error("Invalid reparse point data at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent reparse point data metadata."]
    InvalidReparsePointData {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error(
        "Reparse tag mismatch at byte position {position:#x}: expected {expected:#010x}, actual {actual:#010x}"
    )]
    #[doc = "Reports the reparse tag mismatch condition encountered while reading NTFS data."]
    ReparseTagMismatch {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Value or size required by the NTFS format."]
        expected: u32,
        #[doc = "Value or size observed in the input."]
        actual: u32,
    },
    #[error(
        "Reparse data at byte position {position:#x} is too large: {size} bytes exceeds maximum of {max_size} bytes"
    )]
    #[doc = "Reports the reparse data too large condition encountered while reading NTFS data."]
    ReparseDataTooLarge {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Encoded or computed size involved in the failure."]
        size: usize,
        #[doc = "Diagnostic max size value retained from the affected on-disk structure."]
        max_size: usize,
    },
    #[error("Invalid $LogFile record at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent log file record metadata."]
    InvalidLogFileRecord {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Unsupported LFS version {major}.{minor} at byte position {position:#x}")]
    #[doc = "Reports an unsupported lfs version value or feature."]
    UnsupportedLfsVersion {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic major value retained from the affected on-disk structure."]
        major: u16,
        #[doc = "Diagnostic minor value retained from the affected on-disk structure."]
        minor: u16,
    },
    #[error("Invalid EFS metadata at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent efs metadata metadata."]
    InvalidEfsMetadata {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Invalid TxF $TXF_DATA at byte position {position:#x}: {reason}")]
    #[doc = "Reports malformed or inconsistent txf data metadata."]
    InvalidTxfData {
        #[doc = "Byte position associated with the malformed NTFS data."]
        position: NtfsPosition,
        #[doc = "Diagnostic reason value retained from the affected on-disk structure."]
        reason: &'static str,
    },
    #[error("Failed to parse MFT record {record_number}: {source}")]
    #[doc = "Reports the mft record parse failed condition encountered while reading NTFS data."]
    MftRecordParseFailed {
        #[doc = "Diagnostic record number value retained from the affected on-disk structure."]
        record_number: u64,
        #[source]
        #[doc = "Underlying error that caused this failure."]
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

impl ParserError for NtfsError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(e) = self else {
            return None;
        };
        #[cfg(feature = "std")]
        {
            Some(fse::ErrorKind::from(e.kind()))
        }
        #[cfg(not(feature = "std"))]
        {
            Some(e.kind())
        }
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
            | Self::UnsupportedLfsVersion { position, .. } => {
                position.value().map(core::num::NonZero::get)
            }
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
mod tests;
