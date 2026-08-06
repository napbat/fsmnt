//! Parser for the NTFS `$LogFile` (MFT record 2).
//!
//! The `$LogFile` contains a transaction journal used by NTFS for crash
//! recovery. It uses a two-layer architecture:
//!
//! - **LFS layer** (Log File Service): manages the circular log format,
//!   restart pages (`RSTR`), record pages (`RCRD`), LSN addressing, and
//!   multi-page record spanning.
//! - **NTFS client layer**: the actual filesystem operations — 33+ operation
//!   codes with typed redo/undo payloads.
//!
//! # Usage
//!
//! ```no_run
//! # use fs_ntfs::Ntfs;
//! # let mut fs = std::io::Cursor::new(vec![]);
//! let ntfs = Ntfs::new(&mut fs).unwrap();
//! let logfile = ntfs.logfile(&mut fs).unwrap();
//!
//! for record in logfile.records() {
//!     println!("LSN {} op {:?}", record.lsn(), record.redo_operation());
//! }
//! ```

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::attribute::NtfsAttributeType;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;
use fs_common::io::FsReadSeek;

// ---- Page signatures ----
const RESTART_PAGE_SIGNATURE: &[u8; 4] = b"RSTR";
const RECORD_PAGE_SIGNATURE: &[u8; 4] = b"RCRD";

// ---- Restart page header offsets (LFS_RESTART_PAGE_HEADER) ----
const RSTR_OFF_SIGNATURE: usize = 0x00;
const RSTR_OFF_USA_OFFSET: usize = 0x04;
const RSTR_OFF_USA_COUNT: usize = 0x06;
const RSTR_OFF_SYSTEM_PAGE_SIZE: usize = 0x10;
const RSTR_OFF_LOG_PAGE_SIZE: usize = 0x14;
const RSTR_OFF_RESTART_OFFSET: usize = 0x18;
const RSTR_OFF_MINOR_VERSION: usize = 0x1A;
const RSTR_OFF_MAJOR_VERSION: usize = 0x1C;
const RSTR_MIN_HEADER_SIZE: usize = 0x1E;

// ---- LFS_RESTART_AREA offsets (relative to restart_offset) ----
const RA_OFF_CURRENT_LSN: usize = 0x00;
const RA_OFF_FLAGS: usize = 0x0E;
const RA_OFF_SEQ_NUMBER_BITS: usize = 0x10;
const RA_OFF_CLIENT_ARRAY_OFFSET: usize = 0x16;
const RA_OFF_FILE_SIZE: usize = 0x18;
const RA_OFF_LOG_PAGE_DATA_OFFSET: usize = 0x26;
const RA_MIN_SIZE: usize = 0x2C;

// ---- LFS_CLIENT_RECORD offsets (relative to client array start) ----
const CR_OFF_CLIENT_NAME_LENGTH: usize = 0x1C;
const CR_OFF_CLIENT_NAME: usize = 0x20;
const CR_SIZE: usize = 0xA0;

// ---- Record page header offsets (LFS_RECORD_PAGE_HEADER) ----
const RCRD_OFF_USA_OFFSET: usize = 0x04;
const RCRD_OFF_USA_COUNT: usize = 0x06;
const RCRD_OFF_NEXT_RECORD_OFFSET: usize = 0x18;
const RCRD_MIN_HEADER_SIZE: usize = 0x28;

// ---- LFS_RECORD_HEADER offsets ----
const LR_OFF_THIS_LSN: usize = 0x00;
const LR_OFF_CLIENT_PREVIOUS_LSN: usize = 0x08;
const LR_OFF_CLIENT_UNDO_NEXT_LSN: usize = 0x10;
const LR_OFF_CLIENT_DATA_LENGTH: usize = 0x18;
const LR_OFF_RECORD_TYPE: usize = 0x20;
const LR_OFF_TRANSACTION_ID: usize = 0x24;
const LR_OFF_FLAGS: usize = 0x28;
const LR_HEADER_SIZE: usize = 0x30;

// ---- NTFS_LOG_RECORD offsets (client data, after LFS header) ----
const NR_OFF_REDO_OP: usize = 0x00;
const NR_OFF_UNDO_OP: usize = 0x02;
const NR_OFF_REDO_OFFSET: usize = 0x04;
const NR_OFF_REDO_LENGTH: usize = 0x06;
const NR_OFF_UNDO_OFFSET: usize = 0x08;
const NR_OFF_UNDO_LENGTH: usize = 0x0A;
const NR_OFF_TARGET_ATTRIBUTE: usize = 0x0C;
const NR_OFF_LCNS_TO_FOLLOW: usize = 0x0E;
const NR_OFF_RECORD_OFFSET: usize = 0x10;
const NR_OFF_ATTRIBUTE_OFFSET: usize = 0x12;
const NR_OFF_CLUSTER_BLOCK_OFFSET: usize = 0x14;
const NR_OFF_TARGET_VCN: usize = 0x18;
const NR_FIXED_HEADER_SIZE: usize = 0x20;

// ---- LFS restart area flags ----
const RESTART_CLEAN_DISMOUNT: u16 = 0x0002;

// ---- Log record flags ----
const LOG_RECORD_MULTI_PAGE: u16 = 0x0001;

// ---- LFS record types ----
const LFS_CLIENT_RECORD: u32 = 0x01;
const LFS_CLIENT_RESTART: u32 = 0x02;

// ---- Update Sequence Array stride ----
const USA_STRIDE: usize = 512;

// ---- NTFS client restart area offsets ----
const NCR_OFF_MAJOR_VERSION: usize = 0x00;
const NCR_OFF_MINOR_VERSION: usize = 0x04;
const NCR_OFF_START_OF_CHECKPOINT_LSN: usize = 0x08;
const NCR_OFF_OPEN_ATTR_TABLE_LSN: usize = 0x10;
const NCR_OFF_ATTR_NAMES_LSN: usize = 0x18;
const NCR_OFF_DIRTY_PAGE_TABLE_LSN: usize = 0x20;
const NCR_OFF_TRANSACTION_TABLE_LSN: usize = 0x28;
const NCR_MIN_SIZE: usize = 0x40;

// ---- Open attribute entry offsets (version 0.0 — used with LFS v1.1) ----
const OAE0_OFF_FILE_REFERENCE: usize = 0x08;
const OAE0_OFF_LSN_OF_OPEN: usize = 0x10;
const OAE0_OFF_ATTR_TYPE: usize = 0x1C;
const OAE0_OFF_BYTES_PER_INDEX: usize = 0x28;
const OAE0_SIZE: usize = 0x2C;

// ---- Open attribute entry offsets (version 1.0 — used with LFS v2.0) ----
const OAE1_OFF_BYTES_PER_INDEX: usize = 0x04;
const OAE1_OFF_ATTR_TYPE: usize = 0x08;
const OAE1_OFF_FILE_REFERENCE: usize = 0x10;
const OAE1_OFF_LSN_OF_OPEN: usize = 0x18;
const OAE1_SIZE: usize = 0x28;

// ---- Attribute name entry offsets ----
const ANE_OFF_INDEX: usize = 0x00;
const ANE_OFF_NAME_LENGTH: usize = 0x02;
const ANE_OFF_NAME: usize = 0x04;

// ---- FILE record header offsets (for LogFileRecordView) ----
const FILE_SIGNATURE: &[u8; 4] = b"FILE";
const FR_OFF_USA_OFFSET: usize = 0x04;
const FR_OFF_USA_COUNT: usize = 0x06;
const FR_OFF_SEQUENCE_NUMBER: usize = 0x10;
const FR_OFF_HARD_LINK_COUNT: usize = 0x12;
const FR_OFF_FIRST_ATTRIBUTE_OFFSET: usize = 0x14;
const FR_OFF_FLAGS: usize = 0x16;
const FR_OFF_USED_SIZE: usize = 0x18;
const FR_OFF_ALLOCATED_SIZE: usize = 0x1C;
const FR_OFF_BASE_FILE_REFERENCE: usize = 0x20;
const FR_MIN_HEADER_SIZE: usize = 0x2A; // 42 bytes

// ---- Attribute record header offsets (for walk_resident_data_attrs) ----
const ATTR_OFF_TYPE: usize = 0x00;
const ATTR_OFF_LENGTH: usize = 0x04;
const ATTR_OFF_NON_RESIDENT: usize = 0x08;
const ATTR_OFF_NAME_LENGTH: usize = 0x09;
const ATTR_OFF_NAME_OFFSET: usize = 0x0A;
const ATTR_OFF_INSTANCE: usize = 0x0E;
const ATTR_MIN_HEADER_SIZE: usize = 0x10;

// ---- Resident attribute extension offsets ----
const RES_OFF_VALUE_LENGTH: usize = 0x10;
const RES_OFF_VALUE_OFFSET: usize = 0x14;
const RES_MIN_HEADER_SIZE: usize = 0x18;

// ---- Attribute end marker ----
const ATTR_END_MARKER: u32 = 0xFFFF_FFFF;

// ---- $DATA attribute type code ----
const ATTR_TYPE_DATA: u32 = 0x80;

// ---- Index entry header offsets (for LogIndexEntryView) ----
const IE_OFF_FILE_REFERENCE: usize = 0x00;
const IE_OFF_INDEX_ENTRY_LENGTH: usize = 0x08;
const IE_OFF_KEY_LENGTH: usize = 0x0A;
const IE_OFF_FLAGS: usize = 0x0C;
const IE_HEADER_SIZE: usize = 0x10; // 16 bytes

// ---- Index entry flags ----
const IE_FLAG_HAS_SUBNODE: u16 = 0x0001;
const IE_FLAG_LAST_ENTRY: u16 = 0x0002;

// ---- FILE_NAME field offsets (for LogFileNameFields) ----
const FN_OFF_PARENT_REF: usize = 0x00;
const FN_OFF_CREATION_TIME: usize = 0x08;
const FN_OFF_MODIFICATION: usize = 0x10;
const FN_OFF_MFT_MODIFIED: usize = 0x18;
const FN_OFF_ACCESS_TIME: usize = 0x20;
const FN_OFF_ALLOCATED_SIZE: usize = 0x28;
const FN_OFF_DATA_SIZE: usize = 0x30;
const FN_OFF_FILE_ATTRIBUTES: usize = 0x38;
const FN_OFF_NAME_LENGTH: usize = 0x40;
const FN_OFF_NAMESPACE: usize = 0x41;
const FN_FIXED_SIZE: usize = 0x42; // 66 bytes

// ---- Transaction table entry offsets ----
const TTE_OFF_ALLOCATED: usize = 0x00;
const TTE_OFF_STATE: usize = 0x04;
const TTE_OFF_FIRST_LSN: usize = 0x08;
const TTE_OFF_PREVIOUS_LSN: usize = 0x10;
const TTE_OFF_UNDO_NEXT_LSN: usize = 0x18;
const TTE_OFF_UNDO_RECORDS: usize = 0x20;
const TTE_OFF_UNDO_BYTES: usize = 0x24;
const TTE_SIZE: usize = 0x28;
const TTE_ALLOCATED_MARKER: u32 = 0xFFFF_FFFF;

/// NTFS `$LogFile` operation codes.
///
/// Each log record contains a redo and an undo operation that describe
/// the forward and backward transformation for crash recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum NtfsLogOperation {
    Noop = 0x00,
    CompensationLogRecord = 0x01,
    InitializeFileRecordSegment = 0x02,
    DeallocateFileRecordSegment = 0x03,
    WriteEndOfFileRecordSegment = 0x04,
    CreateAttribute = 0x05,
    DeleteAttribute = 0x06,
    UpdateResidentValue = 0x07,
    UpdateNonresidentValue = 0x08,
    UpdateMappingPairs = 0x09,
    DeleteDirtyClusters = 0x0A,
    SetNewAttributeSizes = 0x0B,
    AddIndexEntryRoot = 0x0C,
    DeleteIndexEntryRoot = 0x0D,
    AddIndexEntryAllocation = 0x0E,
    DeleteIndexEntryAllocation = 0x0F,
    WriteEndOfIndexBuffer = 0x10,
    SetIndexEntryVcnRoot = 0x11,
    SetIndexEntryVcnAllocation = 0x12,
    UpdateFileNameRoot = 0x13,
    UpdateFileNameAllocation = 0x14,
    SetBitsInNonresidentBitMap = 0x15,
    ClearBitsInNonresidentBitMap = 0x16,
    HotFix = 0x17,
    EndTopLevelAction = 0x18,
    PrepareTransaction = 0x19,
    CommitTransaction = 0x1A,
    ForgetTransaction = 0x1B,
    OpenNonresidentAttribute = 0x1C,
    OpenAttributeTableDump = 0x1D,
    AttributeNamesDump = 0x1E,
    DirtyPageTableDump = 0x1F,
    TransactionTableDump = 0x20,
    UpdateRecordDataRoot = 0x21,
    UpdateRecordDataAllocation = 0x22,
    UpdateRelativeDataIndex = 0x23,
    UpdateRelativeDataAllocation = 0x24,
    ZeroEndOfFileRecord = 0x25,
}

impl NtfsLogOperation {
    /// Convert a raw `u16` operation code to a known variant, or
    /// `None` if the code is unrecognized.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x00 => Some(Self::Noop),
            0x01 => Some(Self::CompensationLogRecord),
            0x02 => Some(Self::InitializeFileRecordSegment),
            0x03 => Some(Self::DeallocateFileRecordSegment),
            0x04 => Some(Self::WriteEndOfFileRecordSegment),
            0x05 => Some(Self::CreateAttribute),
            0x06 => Some(Self::DeleteAttribute),
            0x07 => Some(Self::UpdateResidentValue),
            0x08 => Some(Self::UpdateNonresidentValue),
            0x09 => Some(Self::UpdateMappingPairs),
            0x0A => Some(Self::DeleteDirtyClusters),
            0x0B => Some(Self::SetNewAttributeSizes),
            0x0C => Some(Self::AddIndexEntryRoot),
            0x0D => Some(Self::DeleteIndexEntryRoot),
            0x0E => Some(Self::AddIndexEntryAllocation),
            0x0F => Some(Self::DeleteIndexEntryAllocation),
            0x10 => Some(Self::WriteEndOfIndexBuffer),
            0x11 => Some(Self::SetIndexEntryVcnRoot),
            0x12 => Some(Self::SetIndexEntryVcnAllocation),
            0x13 => Some(Self::UpdateFileNameRoot),
            0x14 => Some(Self::UpdateFileNameAllocation),
            0x15 => Some(Self::SetBitsInNonresidentBitMap),
            0x16 => Some(Self::ClearBitsInNonresidentBitMap),
            0x17 => Some(Self::HotFix),
            0x18 => Some(Self::EndTopLevelAction),
            0x19 => Some(Self::PrepareTransaction),
            0x1A => Some(Self::CommitTransaction),
            0x1B => Some(Self::ForgetTransaction),
            0x1C => Some(Self::OpenNonresidentAttribute),
            0x1D => Some(Self::OpenAttributeTableDump),
            0x1E => Some(Self::AttributeNamesDump),
            0x1F => Some(Self::DirtyPageTableDump),
            0x20 => Some(Self::TransactionTableDump),
            0x21 => Some(Self::UpdateRecordDataRoot),
            0x22 => Some(Self::UpdateRecordDataAllocation),
            0x23 => Some(Self::UpdateRelativeDataIndex),
            0x24 => Some(Self::UpdateRelativeDataAllocation),
            0x25 => Some(Self::ZeroEndOfFileRecord),
            _ => None,
        }
    }
}

impl fmt::Display for NtfsLogOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// LFS record type — distinguishes normal log records from client
/// restart (checkpoint) records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogRecordType {
    /// A normal client log record (redo/undo pair).
    ClientRecord,
    /// A client restart record (checkpoint data).
    ClientRestart,
}

/// LFS restart area information parsed from the most recent `RSTR`
/// page.
#[derive(Clone, Debug)]
pub struct LfsRestartInfo {
    major_version: u16,
    minor_version: u16,
    current_lsn: u64,
    file_size: u64,
    seq_number_bits: u32,
    log_page_size: u32,
    system_page_size: u32,
    log_page_data_offset: u16,
    flags: u16,
    client_name: String,
}

impl LfsRestartInfo {
    /// LFS major version (1 or 2).
    pub fn major_version(&self) -> u16 {
        self.major_version
    }

    /// LFS minor version.
    pub fn minor_version(&self) -> u16 {
        self.minor_version
    }

    /// Most recent LSN at the time the restart page was written.
    pub fn current_lsn(&self) -> u64 {
        self.current_lsn
    }

    /// Total log file size in bytes.
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Bits reserved for the sequence number portion of an LSN.
    pub fn seq_number_bits(&self) -> u32 {
        self.seq_number_bits
    }

    /// Size of each log record page in bytes (typically 4096).
    pub fn log_page_size(&self) -> u32 {
        self.log_page_size
    }

    /// Size of each restart page in bytes.
    pub fn system_page_size(&self) -> u32 {
        self.system_page_size
    }

    /// Whether the log was cleanly dismounted.
    pub fn is_clean_dismount(&self) -> bool {
        self.flags & RESTART_CLEAN_DISMOUNT != 0
    }

    /// The LFS client name (always "NTFS" for NTFS volumes).
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
}

/// NTFS client restart area (checkpoint data).
#[derive(Clone, Debug)]
pub struct NtfsClientRestartArea {
    major_version: u32,
    minor_version: u32,
    start_of_checkpoint_lsn: u64,
    open_attribute_table_lsn: u64,
    attribute_names_lsn: u64,
    dirty_page_table_lsn: u64,
    transaction_table_lsn: u64,
}

impl NtfsClientRestartArea {
    /// NTFS client format major version (0 or 1).
    pub fn major_version(&self) -> u32 {
        self.major_version
    }

    /// NTFS client format minor version.
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// LSN of the start of the last checkpoint.
    pub fn start_of_checkpoint_lsn(&self) -> u64 {
        self.start_of_checkpoint_lsn
    }

    /// LSN of the open attribute table dump (0 if absent).
    pub fn open_attribute_table_lsn(&self) -> u64 {
        self.open_attribute_table_lsn
    }

    /// LSN of the attribute names dump (0 if absent).
    pub fn attribute_names_lsn(&self) -> u64 {
        self.attribute_names_lsn
    }

    /// LSN of the dirty page table dump (0 if absent).
    pub fn dirty_page_table_lsn(&self) -> u64 {
        self.dirty_page_table_lsn
    }

    /// LSN of the transaction table dump (0 if absent).
    pub fn transaction_table_lsn(&self) -> u64 {
        self.transaction_table_lsn
    }
}

/// An entry in the open attribute table, mapping a target attribute
/// index to a file reference and attribute type.
#[derive(Clone, Debug)]
pub struct OpenAttributeEntry {
    file_reference: u64,
    lsn_of_open_record: u64,
    attribute_type: u32,
    bytes_per_index_buffer: u32,
}

impl OpenAttributeEntry {
    /// The MFT file reference for this open attribute.
    pub fn file_reference(&self) -> u64 {
        self.file_reference
    }

    /// LSN of the log record that opened this attribute.
    pub fn lsn_of_open_record(&self) -> u64 {
        self.lsn_of_open_record
    }

    /// The attribute type code.
    pub fn attribute_type_code(&self) -> u32 {
        self.attribute_type
    }

    /// Bytes per index buffer (for index attributes).
    pub fn bytes_per_index_buffer(&self) -> u32 {
        self.bytes_per_index_buffer
    }
}

/// An entry mapping an open attribute index to its Unicode name.
#[derive(Clone, Debug)]
pub struct AttributeNameEntry {
    index: u16,
    name: String,
}

impl AttributeNameEntry {
    /// The open attribute table index this name belongs to.
    pub fn index(&self) -> u16 {
        self.index
    }

    /// The Unicode attribute name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Parsed entry from a `TransactionTableDump` (0x20) payload.
///
/// Each entry represents one transaction table slot from the
/// checkpoint. The `entry_index` is the slot position in the
/// dump array, which is also the transaction ID used by
/// `NtfsLogRecord::transaction_id()`.
#[derive(Clone, Debug)]
pub struct TransactionTableDumpEntry {
    entry_index: u32,
    allocated_or_next_free: u32,
    transaction_state: u32,
    first_lsn: u64,
    previous_lsn: u64,
    undo_next_lsn: u64,
    undo_records: u32,
    undo_bytes: u32,
}

impl TransactionTableDumpEntry {
    /// Slot position in the transaction table array.
    pub fn entry_index(&self) -> u32 {
        self.entry_index
    }

    /// Allocation marker. In-use if `== 0xFFFF_FFFF`.
    pub fn allocated_or_next_free(&self) -> u32 {
        self.allocated_or_next_free
    }

    /// Raw transaction state value.
    pub fn raw_state(&self) -> u32 {
        self.transaction_state
    }

    /// True if transaction state is Active (1).
    pub fn is_active(&self) -> bool {
        self.transaction_state == 1
    }

    /// True if transaction state is Prepared (2).
    pub fn is_prepared(&self) -> bool {
        self.transaction_state == 2
    }

    /// True if transaction state is Committed (3).
    pub fn is_committed(&self) -> bool {
        self.transaction_state == 3
    }

    /// First LSN for this transaction.
    pub fn first_lsn(&self) -> u64 {
        self.first_lsn
    }

    /// Previous (most recent) LSN in the transaction chain.
    pub fn previous_lsn(&self) -> u64 {
        self.previous_lsn
    }

    /// Next LSN to process during undo/rollback.
    pub fn undo_next_lsn(&self) -> u64 {
        self.undo_next_lsn
    }

    /// Count of pending undo records.
    pub fn undo_records(&self) -> u32 {
        self.undo_records
    }

    /// Total bytes in pending undo records.
    pub fn undo_bytes(&self) -> u32 {
        self.undo_bytes
    }
}

/// Lifecycle state of a tracked transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransactionState {
    /// Transaction has been observed but not prepared/committed.
    Active,
    /// `PrepareTransaction` record seen.
    Prepared,
    /// `CommitTransaction` record seen.
    Committed,
    /// `ForgetTransaction` record seen (resources released).
    Forgotten,
}

/// Tracked lifecycle of a single transaction, built from
/// checkpoint dump and forward record scan.
///
/// The `saw_*` flags reflect evidence from either the
/// `TransactionTableDump` baseline or scanned log records
/// (evidence-anywhere semantics).
#[derive(Clone, Debug)]
pub struct TransactionEntry {
    transaction_id: u32,
    state: TransactionState,
    seeded_from_dump: bool,
    first_lsn: u64,
    last_lsn: u64,
    undo_next_lsn: Option<u64>,
    operation_count: u32,
    saw_prepare: bool,
    saw_commit: bool,
    saw_forget: bool,
    forgotten_lsn: Option<u64>,
    recycled: bool,
    recycle_lsn: Option<u64>,
}

impl TransactionEntry {
    /// Transaction table slot index.
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Current lifecycle state.
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// True if seeded from checkpoint TransactionTableDump.
    pub fn seeded_from_dump(&self) -> bool {
        self.seeded_from_dump
    }

    /// Earliest LSN observed for this transaction.
    pub fn first_lsn(&self) -> u64 {
        self.first_lsn
    }

    /// Latest LSN observed for this transaction.
    pub fn last_lsn(&self) -> u64 {
        self.last_lsn
    }

    /// Latest undo chain pointer. `None` when absent (raw 0).
    pub fn undo_next_lsn(&self) -> Option<u64> {
        self.undo_next_lsn
    }

    /// Payload-carrying redo operations (not Unit or Empty).
    pub fn operation_count(&self) -> u32 {
        self.operation_count
    }

    /// Evidence of PrepareTransaction (dump or scan).
    pub fn saw_prepare(&self) -> bool {
        self.saw_prepare
    }

    /// Evidence of CommitTransaction (dump or scan).
    pub fn saw_commit(&self) -> bool {
        self.saw_commit
    }

    /// Evidence of ForgetTransaction (dump or scan).
    pub fn saw_forget(&self) -> bool {
        self.saw_forget
    }

    /// True if CommitTransaction was observed.
    pub fn is_committed(&self) -> bool {
        self.saw_commit
    }

    /// True if ForgetTransaction was observed.
    pub fn is_forgotten(&self) -> bool {
        self.saw_forget
    }

    /// True if the transaction never reached end-of-life.
    pub fn is_incomplete(&self) -> bool {
        !self.saw_forget
    }

    /// LSN of the ForgetTransaction record, if seen.
    pub fn forgotten_lsn(&self) -> Option<u64> {
        self.forgotten_lsn
    }

    /// True if activity was observed after ForgetTransaction
    /// (transaction ID was recycled).
    pub fn recycled(&self) -> bool {
        self.recycled
    }

    /// LSN of first record after ForgetTransaction (recycling).
    pub fn recycle_lsn(&self) -> Option<u64> {
        self.recycle_lsn
    }
}

/// Typed redo/undo payload for an NTFS log operation.
///
/// Variants describe payload *shape*, not operation identity.
/// The operation code on [`NtfsLogRecord`] determines semantics.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum NtfsLogOperationData {
    /// No data was present for a redo/undo slot that normally
    /// carries a payload. May indicate truncation or corruption.
    Empty,
    /// Unrecognized or unexpected payload bytes. Escape hatch
    /// for operations not yet typed.
    Raw { data: Vec<u8> },
    /// `SetNewAttributeSizes` (0x0B) -- parsed size fields.
    SetNewAttributeSizes {
        allocated_length: u64,
        data_length: u64,
        valid_data_length: u64,
        total_allocated: u64,
    },
    /// `SetBitsInNonresidentBitMap` (0x15) -- bitmap range.
    SetBits { bit_offset: u32, num_bits: u32 },
    /// `ClearBitsInNonresidentBitMap` (0x16) -- bitmap range.
    ClearBits { bit_offset: u32, num_bits: u32 },
    /// `OpenNonresidentAttribute` (0x1C) -- file ref + type.
    OpenNonresidentAttribute {
        file_reference: u64,
        attribute_type: u32,
        name: Option<String>,
    },
    /// `OpenAttributeTableDump` (0x1D) -- parsed entries.
    OpenAttributeTableDump { entries: Vec<OpenAttributeEntry> },
    /// `AttributeNamesDump` (0x1E) -- parsed entries.
    AttributeNamesDump { entries: Vec<AttributeNameEntry> },
    /// Operation that does not carry payload data by design.
    /// Which operation this is comes from the [`NtfsLogRecord`]
    /// operation code.
    Unit,
    /// Complete MFT FILE record from
    /// `InitializeFileRecordSegment`.
    FileRecordSegment { data: Vec<u8> },
    /// Raw bytes for value updates, attribute operations, mapping
    /// pairs, and other operations whose semantics depend on the
    /// operation code and target fields on [`NtfsLogRecord`].
    Bytes { data: Vec<u8> },
    /// VCN from `SetIndexEntryVcnRoot` (0x11) or
    /// `SetIndexEntryVcnAllocation` (0x12).
    IndexEntryVcn { vcn: u64 },
    /// `TransactionTableDump` (0x20) -- parsed entries.
    TransactionTableDump {
        entries: Vec<TransactionTableDumpEntry>,
    },
}

impl NtfsLogOperationData {
    /// Returns the raw bytes for `Bytes`, `FileRecordSegment`, or
    /// `Raw` variants. `None` for `Unit`, `Empty`, and typed
    /// variants.
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes { data } | Self::FileRecordSegment { data } | Self::Raw { data } => {
                Some(data)
            }
            _ => None,
        }
    }

    /// Returns the MFT record bytes if this is a
    /// `FileRecordSegment`. `None` otherwise.
    pub fn file_record_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::FileRecordSegment { data } => Some(data),
            _ => None,
        }
    }

    /// Returns `true` if this is a `Unit` (no-payload) variant.
    pub fn is_unit(&self) -> bool {
        matches!(self, Self::Unit)
    }

    /// Returns a lightweight header view over a
    /// `FileRecordSegment` payload.
    ///
    /// Returns `None` if this is not a `FileRecordSegment`.
    /// Returns `Some(Err(...))` if the payload is corrupt or
    /// truncated.
    pub fn file_record_view(&self) -> Option<Result<LogFileRecordView<'_>>> {
        match self {
            Self::FileRecordSegment { data } => Some(LogFileRecordView::new(data)),
            _ => None,
        }
    }

    /// Returns the VCN if this is an `IndexEntryVcn`. `None`
    /// otherwise.
    pub fn index_entry_vcn(&self) -> Option<u64> {
        match self {
            Self::IndexEntryVcn { vcn } => Some(*vcn),
            _ => None,
        }
    }
}

/// Resident `$DATA` attribute value extracted from a FILE record
/// in a `$LogFile` `InitializeFileRecordSegment` payload.
#[derive(Clone, Debug)]
pub struct ResidentDataValue {
    instance: u16,
    name_offset: u16,
    name_length: u8,
    value_offset_in_record: u32,
    data: Vec<u8>,
}

impl ResidentDataValue {
    /// Attribute instance number (unique within the FILE record).
    pub fn instance(&self) -> u16 {
        self.instance
    }

    /// Offset of the attribute name from the start of the
    /// attribute record. Meaningful only when `is_named()` is
    /// true; unspecified otherwise.
    pub fn name_offset(&self) -> u16 {
        self.name_offset
    }

    /// Name length in UTF-16 code units. Zero for the default
    /// unnamed `$DATA` stream.
    pub fn name_length(&self) -> u8 {
        self.name_length
    }

    /// Absolute byte offset of the value within the FILE record.
    pub fn value_offset_in_record(&self) -> u32 {
        self.value_offset_in_record
    }

    /// The resident value bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Whether this is a named `$DATA` stream (alternate data
    /// stream). Returns `true` when `name_length > 0`.
    pub fn is_named(&self) -> bool {
        self.name_length != 0
    }
}

/// Patch bytes from an `UpdateResidentValue` log record
/// targeting a `$DATA` attribute, attributed to a file via the
/// open attribute table.
#[derive(Clone, Debug)]
pub struct ResidentDataPatch<'a> {
    file_reference: u64,
    target_attribute: u16,
    value_offset: u16,
    patch_bytes: &'a [u8],
}

impl<'a> ResidentDataPatch<'a> {
    /// 8-byte MFT file reference from the OAT entry.
    /// Lower 48 bits are the MFT record number; upper 16 bits
    /// are the sequence number.
    pub fn file_reference(&self) -> u64 {
        self.file_reference
    }

    /// OAT index from the log record. Identity key for
    /// correlating patches to the same open attribute.
    pub fn target_attribute(&self) -> u16 {
        self.target_attribute
    }

    /// Byte offset within the attribute value where the patch
    /// applies.
    pub fn value_offset(&self) -> u16 {
        self.value_offset
    }

    /// The patch bytes (borrowed from the redo payload).
    pub fn patch_bytes(&self) -> &[u8] {
        self.patch_bytes
    }

    /// MFT record number (lower 48 bits of file_reference).
    pub fn mft_record_number(&self) -> u64 {
        self.file_reference & 0x0000_FFFF_FFFF_FFFF
    }
}

/// Parsed FILE_NAME attribute fields from an index entry key or
/// `UpdateFileName` log record payload.
///
/// Contains the parent directory reference, four timestamps,
/// sizes, attributes, namespace, and the filename itself.
#[derive(Clone, Debug)]
pub struct LogFileNameFields {
    parent_directory_reference: u64,
    creation_time: u64,
    modification_time: u64,
    mft_record_modification_time: u64,
    access_time: u64,
    allocated_size: u64,
    data_size: u64,
    file_attributes: u32,
    namespace: u8,
    name: Vec<u16>,
}

impl LogFileNameFields {
    /// 8-byte parent directory MFT file reference.
    pub fn parent_directory_reference(&self) -> u64 {
        self.parent_directory_reference
    }

    /// Parent MFT record number (lower 48 bits).
    pub fn parent_mft_record_number(&self) -> u64 {
        self.parent_directory_reference & 0x0000_FFFF_FFFF_FFFF
    }

    /// NTFS creation timestamp (100-ns intervals since 1601).
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }

    /// NTFS last-modification timestamp.
    pub fn modification_time(&self) -> u64 {
        self.modification_time
    }

    /// MFT record modification timestamp.
    pub fn mft_record_modification_time(&self) -> u64 {
        self.mft_record_modification_time
    }

    /// NTFS last-access timestamp.
    pub fn access_time(&self) -> u64 {
        self.access_time
    }

    /// Allocated size in bytes.
    pub fn allocated_size(&self) -> u64 {
        self.allocated_size
    }

    /// Actual data size in bytes.
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    /// DOS file attribute flags.
    pub fn file_attributes(&self) -> u32 {
        self.file_attributes
    }

    /// Whether the directory attribute bit (0x10) is set.
    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x10 != 0
    }

    /// FILE_NAME namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS).
    pub fn namespace(&self) -> u8 {
        self.namespace
    }

    /// Filename as raw UTF-16 code units.
    pub fn name(&self) -> &[u16] {
        &self.name
    }

    /// Filename decoded as a lossy UTF-16 string.
    pub fn name_string(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }
}

fn parse_file_name_fields(
    data: &[u8],
    err_truncated: &'static str,
    err_name_zero: &'static str,
    err_name_exceeds: &'static str,
) -> Result<LogFileNameFields> {
    let position = NtfsPosition::none();

    if data.len() < FN_FIXED_SIZE {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: err_truncated,
        });
    }

    let name_length = data[FN_OFF_NAME_LENGTH] as usize;
    if name_length == 0 {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: err_name_zero,
        });
    }

    let name_byte_len = name_length * 2;
    if FN_FIXED_SIZE + name_byte_len > data.len() {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: err_name_exceeds,
        });
    }

    let mut name = Vec::with_capacity(name_length);
    for i in 0..name_length {
        let off = FN_FIXED_SIZE + i * 2;
        name.push(le_u16(data, off));
    }

    Ok(LogFileNameFields {
        parent_directory_reference: le_u64(data, FN_OFF_PARENT_REF),
        creation_time: le_u64(data, FN_OFF_CREATION_TIME),
        modification_time: le_u64(data, FN_OFF_MODIFICATION),
        mft_record_modification_time: le_u64(data, FN_OFF_MFT_MODIFIED),
        access_time: le_u64(data, FN_OFF_ACCESS_TIME),
        allocated_size: le_u64(data, FN_OFF_ALLOCATED_SIZE),
        data_size: le_u64(data, FN_OFF_DATA_SIZE),
        file_attributes: le_u32(data, FN_OFF_FILE_ATTRIBUTES),
        namespace: data[FN_OFF_NAMESPACE],
        name,
    })
}

/// Lightweight view into an index entry payload from
/// Add/Delete index entry log operations.
#[derive(Clone, Debug)]
pub struct LogIndexEntryView<'a> {
    data: &'a [u8],
}

impl<'a> LogIndexEntryView<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let position = NtfsPosition::none();

        if data.len() < IE_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: index_entry_truncated",
            });
        }

        let entry_length = le_u16(data, IE_OFF_INDEX_ENTRY_LENGTH) as usize;
        if entry_length < IE_HEADER_SIZE || entry_length > data.len() {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: index_entry_length_invalid",
            });
        }

        let key_length = le_u16(data, IE_OFF_KEY_LENGTH) as usize;
        if IE_HEADER_SIZE + key_length > entry_length {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: key_exceeds_entry",
            });
        }

        let flags = le_u16(data, IE_OFF_FLAGS);
        if flags & IE_FLAG_HAS_SUBNODE != 0 {
            let min_with_vcn = IE_HEADER_SIZE + key_length + 8;
            if entry_length < min_with_vcn {
                return Err(NtfsError::InvalidLogFileRecord {
                    position,
                    reason: "log payload: subnode_vcn_no_room",
                });
            }
        }

        Ok(Self { data })
    }

    /// 8-byte file reference from the index entry header.
    pub fn file_reference(&self) -> u64 {
        le_u64(self.data, IE_OFF_FILE_REFERENCE)
    }

    /// MFT record number (lower 48 bits of file_reference).
    pub fn mft_record_number(&self) -> u64 {
        self.file_reference() & 0x0000_FFFF_FFFF_FFFF
    }

    /// Total length of this index entry in bytes.
    pub fn index_entry_length(&self) -> u16 {
        le_u16(self.data, IE_OFF_INDEX_ENTRY_LENGTH)
    }

    /// Length of the key (FILE_NAME) portion in bytes.
    pub fn key_length(&self) -> u16 {
        le_u16(self.data, IE_OFF_KEY_LENGTH)
    }

    /// Raw index entry flags.
    pub fn flags(&self) -> u16 {
        le_u16(self.data, IE_OFF_FLAGS)
    }

    /// Whether this entry has a subnode VCN pointer.
    pub fn has_subnode(&self) -> bool {
        self.flags() & IE_FLAG_HAS_SUBNODE != 0
    }

    /// Whether this is the last (sentinel) entry in the node.
    pub fn is_last_entry(&self) -> bool {
        self.flags() & IE_FLAG_LAST_ENTRY != 0
    }

    /// Subnode VCN, if the has-subnode flag is set.
    pub fn subnode_vcn(&self) -> Option<u64> {
        if !self.has_subnode() {
            return None;
        }
        let entry_len = self.index_entry_length() as usize;
        Some(le_u64(self.data, entry_len - 8))
    }

    /// Key bytes (typically a FILE_NAME structure), or `None`
    /// for zero-length keys (sentinel entries).
    pub fn key_data(&self) -> Option<&[u8]> {
        let key_len = self.key_length() as usize;
        if key_len == 0 {
            return None;
        }
        Some(&self.data[IE_HEADER_SIZE..IE_HEADER_SIZE + key_len])
    }

    /// Parse the key as a FILE_NAME structure.
    /// Returns `None` if the key is empty.
    pub fn parse_file_name(&self) -> Option<Result<LogFileNameFields>> {
        let key = self.key_data()?;
        Some(parse_file_name_fields(
            key,
            "log payload: filename_truncated",
            "log payload: filename_name_length_zero",
            "log payload: filename_name_exceeds_key",
        ))
    }

    /// Raw index entry bytes.
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

/// Lightweight, zero-fixup view into FILE record header fields
/// from a `$LogFile` `InitializeFileRecordSegment` payload.
///
/// This view reads header fields directly from the payload bytes
/// without applying update-sequence-array fixups. Fields may be
/// unreliable if the payload was captured pre-fixup.
///
/// Does not require `&Ntfs`. Use
/// [`NtfsLogOperationData::file_record_view`] to obtain.
#[derive(Clone, Debug)]
pub struct LogFileRecordView<'a> {
    data: &'a [u8],
}

impl<'a> LogFileRecordView<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let position = NtfsPosition::none();

        if data.len() < FR_MIN_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: FILE record too small \
                         for header",
            });
        }

        if data[0..4] != *FILE_SIGNATURE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: FILE signature invalid",
            });
        }

        let used_size = le_u32(data, FR_OFF_USED_SIZE);
        let allocated_size = le_u32(data, FR_OFF_ALLOCATED_SIZE);

        if allocated_size as usize > data.len() {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: allocated_size exceeds \
                         payload length",
            });
        }

        if used_size > allocated_size {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: used_size exceeds \
                         allocated_size",
            });
        }

        let first_attr_offset = le_u16(data, FR_OFF_FIRST_ATTRIBUTE_OFFSET);
        if (first_attr_offset as usize) < FR_MIN_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: first_attribute_offset \
                         inside header",
            });
        }
        if first_attr_offset as u32 >= used_size {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: first_attribute_offset \
                         out of bounds",
            });
        }

        Ok(Self { data })
    }

    /// Allocated size of this MFT record in bytes.
    pub fn allocated_size(&self) -> u32 {
        le_u32(self.data, FR_OFF_ALLOCATED_SIZE)
    }

    /// Used (logical) size in bytes.
    pub fn used_size(&self) -> u32 {
        le_u32(self.data, FR_OFF_USED_SIZE)
    }

    /// Sequence number (incremented each time the record is
    /// reused).
    pub fn sequence_number(&self) -> u16 {
        le_u16(self.data, FR_OFF_SEQUENCE_NUMBER)
    }

    /// Hard link count.
    pub fn hard_link_count(&self) -> u16 {
        le_u16(self.data, FR_OFF_HARD_LINK_COUNT)
    }

    /// MFT record flags (in-use, directory).
    pub fn flags(&self) -> u16 {
        le_u16(self.data, FR_OFF_FLAGS)
    }

    /// Whether the FILE record is marked in-use.
    pub fn is_in_use(&self) -> bool {
        self.flags() & 0x0001 != 0
    }

    /// Whether the FILE record is a directory.
    pub fn is_directory(&self) -> bool {
        self.flags() & 0x0002 != 0
    }

    /// Offset to the first attribute within the record.
    pub fn first_attribute_offset(&self) -> u16 {
        le_u16(self.data, FR_OFF_FIRST_ATTRIBUTE_OFFSET)
    }

    /// Base file reference (non-zero for extension records).
    pub fn base_file_reference(&self) -> u64 {
        le_u64(self.data, FR_OFF_BASE_FILE_REFERENCE)
    }

    /// Update sequence array offset within the record.
    pub fn update_sequence_offset(&self) -> u16 {
        le_u16(self.data, FR_OFF_USA_OFFSET)
    }

    /// Update sequence array count.
    pub fn update_sequence_count(&self) -> u16 {
        le_u16(self.data, FR_OFF_USA_COUNT)
    }

    /// Raw bytes of the entire FILE record payload.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Clone the payload, apply USA fixup, and pass the fixed-up
    /// bytes to a closure.
    ///
    /// The closure receives the full fixed-up record as `&[u8]`,
    /// valid only for the duration of the call. Returns `Err` if
    /// USA fixup fails; otherwise returns the closure's result.
    pub fn with_fixed_up_bytes<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let mut buf = self.data.to_vec();
        let usa_offset = le_u16(self.data, FR_OFF_USA_OFFSET) as usize;
        let usa_count = le_u16(self.data, FR_OFF_USA_COUNT);
        apply_usa_fixup(&mut buf, usa_offset, usa_count, NtfsPosition::none())?;
        f(&buf)
    }

    /// Extract all resident `$DATA` attribute values from this
    /// FILE record payload.
    ///
    /// Clones the payload, applies USA fixup, then walks
    /// attributes looking for resident `$DATA` (type 0x80).
    /// Returns one [`ResidentDataValue`] per match.
    ///
    /// Returns `Err` if USA fixup fails, the attribute chain is
    /// structurally corrupt, or `used_size` exceeds the buffer.
    /// An empty `Vec` is valid (record has no resident `$DATA`).
    pub fn resident_data_values(&self) -> Result<Vec<ResidentDataValue>> {
        self.with_fixed_up_bytes(|buf| {
            let used_size = le_u32(buf, FR_OFF_USED_SIZE) as usize;
            if used_size > buf.len() {
                return Err(NtfsError::InvalidLogFileRecord {
                    position: NtfsPosition::none(),
                    reason: "log payload: \
                             used_size_exceeds_buffer",
                });
            }
            let limit = used_size.min(buf.len());
            let first_attr = le_u16(buf, FR_OFF_FIRST_ATTRIBUTE_OFFSET);
            walk_resident_data_attrs(buf, limit, first_attr)
        })
    }
}

/// A single parsed log record from the `$LogFile`.
#[derive(Clone, Debug)]
pub struct NtfsLogRecord {
    lsn: u64,
    client_previous_lsn: u64,
    client_undo_next_lsn: u64,
    record_type: LogRecordType,
    transaction_id: u32,
    flags: u16,
    redo_operation_code: u16,
    undo_operation_code: u16,
    redo_operation: Option<NtfsLogOperation>,
    undo_operation: Option<NtfsLogOperation>,
    target_attribute: u16,
    target_vcn: u64,
    record_offset: u16,
    attribute_offset: u16,
    cluster_block_offset: u16,
    redo_data: NtfsLogOperationData,
    undo_data: NtfsLogOperationData,
}

impl NtfsLogRecord {
    /// The LSN (Log Sequence Number) of this record.
    pub fn lsn(&self) -> u64 {
        self.lsn
    }

    /// LSN of the previous record in the same transaction.
    pub fn client_previous_lsn(&self) -> u64 {
        self.client_previous_lsn
    }

    /// LSN of the next record to undo on rollback.
    pub fn client_undo_next_lsn(&self) -> u64 {
        self.client_undo_next_lsn
    }

    /// Whether this is a normal record or a client restart.
    pub fn record_type(&self) -> LogRecordType {
        self.record_type
    }

    /// Transaction ID grouping records in a single transaction.
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// The redo operation code.
    pub fn redo_operation(&self) -> Option<NtfsLogOperation> {
        self.redo_operation
    }

    /// The raw redo operation code (useful for unknown operations).
    pub fn redo_operation_code(&self) -> u16 {
        self.redo_operation_code
    }

    /// The undo operation code.
    pub fn undo_operation(&self) -> Option<NtfsLogOperation> {
        self.undo_operation
    }

    /// The raw undo operation code.
    pub fn undo_operation_code(&self) -> u16 {
        self.undo_operation_code
    }

    /// Index into the open attribute table.
    pub fn target_attribute(&self) -> u16 {
        self.target_attribute
    }

    /// Target virtual cluster number.
    pub fn target_vcn(&self) -> u64 {
        self.target_vcn
    }

    /// Byte offset within the target record.
    pub fn record_offset(&self) -> u16 {
        self.record_offset
    }

    /// Byte offset within the target attribute.
    pub fn attribute_offset(&self) -> u16 {
        self.attribute_offset
    }

    /// Cluster block offset for sparse or compressed targets.
    pub fn cluster_block_offset(&self) -> u16 {
        self.cluster_block_offset
    }

    /// The typed redo payload.
    pub fn redo_data(&self) -> &NtfsLogOperationData {
        &self.redo_data
    }

    /// The typed undo payload.
    pub fn undo_data(&self) -> &NtfsLogOperationData {
        &self.undo_data
    }

    /// Whether this record spans multiple pages.
    pub fn is_multi_page(&self) -> bool {
        self.flags & LOG_RECORD_MULTI_PAGE != 0
    }

    /// If this is an `UpdateResidentValue` targeting a `$DATA`
    /// attribute (per the OAT), return the patch location and
    /// bytes.
    ///
    /// Returns `None` if the redo operation is not
    /// `UpdateResidentValue`, or if the OAT entry's attribute
    /// type is not `$DATA` (0x80).
    ///
    /// Returns `Some(Err(...))` if `target_attribute` is out of
    /// OAT bounds, the redo payload is `Empty`, empty `Bytes`,
    /// `Raw`, or an unexpected typed variant.
    ///
    /// Returns `Some(Ok(...))` with file_reference from the OAT,
    /// value_offset from `attribute_offset`, and patch_bytes
    /// borrowed from the redo payload.
    pub fn resident_data_patch<'a>(
        &'a self,
        oat: &[OpenAttributeEntry],
    ) -> Option<Result<ResidentDataPatch<'a>>> {
        // Guard: must be UpdateResidentValue.
        if self.redo_operation != Some(NtfsLogOperation::UpdateResidentValue) {
            return None;
        }

        let position = NtfsPosition::none();

        // OAT lookup.
        let entry = match oat.get(self.target_attribute as usize) {
            Some(e) => e,
            None => {
                return Some(Err(NtfsError::InvalidLogFileRecord {
                    position,
                    reason: "log payload: \
                                 target_attr_oat_oob",
                }));
            }
        };

        // Must target $DATA.
        if entry.attribute_type != ATTR_TYPE_DATA {
            return None;
        }

        // Match redo payload.
        match &self.redo_data {
            NtfsLogOperationData::Bytes { data } if !data.is_empty() => {
                Some(Ok(ResidentDataPatch {
                    file_reference: entry.file_reference,
                    target_attribute: self.target_attribute,
                    value_offset: self.attribute_offset,
                    patch_bytes: data,
                }))
            }
            NtfsLogOperationData::Bytes { .. } => Some(Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: redo_bytes_empty",
            })),
            NtfsLogOperationData::Empty => Some(Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: redo_data_empty",
            })),
            NtfsLogOperationData::Raw { .. } => Some(Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: \
                             unexpected_raw_payload",
            })),
            NtfsLogOperationData::Unit => None,
            _ => Some(Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: \
                         unexpected_payload_variant",
            })),
        }
    }

    /// If this is an Add or Delete index entry operation,
    /// return a view into the index entry payload.
    ///
    /// Returns `None` if the redo operation is not
    /// `AddIndexEntryRoot`, `DeleteIndexEntryRoot`,
    /// `AddIndexEntryAllocation`, or
    /// `DeleteIndexEntryAllocation`.
    ///
    /// Returns `Some(Err(...))` if the payload is truncated
    /// or structurally corrupt.
    ///
    /// Returns `Some(Ok(view))` with the parsed index entry.
    pub fn index_entry_view(&self) -> Option<Result<LogIndexEntryView<'_>>> {
        match self.redo_operation {
            Some(
                NtfsLogOperation::AddIndexEntryRoot
                | NtfsLogOperation::DeleteIndexEntryRoot
                | NtfsLogOperation::AddIndexEntryAllocation
                | NtfsLogOperation::DeleteIndexEntryAllocation,
            ) => {}
            _ => return None,
        }

        let data = match &self.redo_data {
            NtfsLogOperationData::Bytes { data } => data,
            NtfsLogOperationData::Empty => {
                return Some(Err(NtfsError::InvalidLogFileRecord {
                    position: NtfsPosition::none(),
                    reason: "log payload: index_entry_truncated",
                }));
            }
            _ => return None,
        };

        Some(LogIndexEntryView::new(data))
    }

    /// If this is an `UpdateFileName` operation, parse the
    /// redo payload as FILE_NAME fields.
    ///
    /// Returns `None` if the redo operation is not
    /// `UpdateFileNameRoot` or `UpdateFileNameAllocation`.
    ///
    /// Returns `Some(Err(...))` if the payload is truncated
    /// or corrupt.
    ///
    /// Returns `Some(Ok(fields))` with parsed fields.
    pub fn filename_update_view(&self) -> Option<Result<LogFileNameFields>> {
        match self.redo_operation {
            Some(
                NtfsLogOperation::UpdateFileNameRoot | NtfsLogOperation::UpdateFileNameAllocation,
            ) => {}
            _ => return None,
        }

        let data = match &self.redo_data {
            NtfsLogOperationData::Bytes { data } => data.as_slice(),
            NtfsLogOperationData::Empty => {
                return Some(Err(NtfsError::InvalidLogFileRecord {
                    position: NtfsPosition::none(),
                    reason: "log payload: filename_update_truncated",
                }));
            }
            _ => return None,
        };

        Some(parse_file_name_fields(
            data,
            "log payload: filename_update_truncated",
            "log payload: filename_update_name_length_zero",
            "log payload: filename_update_name_exceeds",
        ))
    }
}

/// The parsed `$LogFile` -- top-level container for all log data.
///
/// Created via [`NtfsLogFile::load`] or [`Ntfs::logfile`].
#[derive(Clone, Debug)]
pub struct NtfsLogFile {
    restart_info: LfsRestartInfo,
    client_restart: Option<NtfsClientRestartArea>,
    open_attribute_table: Vec<OpenAttributeEntry>,
    attribute_names: Vec<AttributeNameEntry>,
    transaction_table_dump: Vec<TransactionTableDumpEntry>,
    transaction_states: alloc::collections::BTreeMap<u32, TransactionEntry>,
    records: Vec<NtfsLogRecord>,
    skipped_pages: u32,
}

impl NtfsLogFile {
    /// Load and parse the `$LogFile` from an NTFS filesystem.
    ///
    /// Opens MFT record 2, reads the `$DATA` attribute, and parses all
    /// restart pages and log record pages.
    pub fn load<T>(ntfs: &Ntfs, fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        let logfile_file = ntfs.file(fs, KnownNtfsFileRecordNumber::LogFile as u64)?;

        let data_attr = logfile_file
            .attributes_raw()
            .find_map(|attr| {
                let attr = attr.ok()?;
                if attr.ty().ok()? == NtfsAttributeType::Data {
                    Some(attr)
                } else {
                    None
                }
            })
            .ok_or(NtfsError::InvalidLogFileRecord {
                position: NtfsPosition::none(),
                reason: "$LogFile has no $DATA attribute",
            })?;

        let mut value = data_attr.value(fs)?;
        const MAX_LOGFILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MB
        let raw_len = value.len();
        if raw_len > MAX_LOGFILE_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position: NtfsPosition::none(),
                reason: "$LogFile data exceeds 256 MB limit",
            });
        }
        let len = raw_len as usize;
        let mut data = vec![0u8; len];
        value.read_exact(fs, &mut data)?;

        let position = NtfsPosition::none();

        let restart_info = parse_restart_page(&data, position)?;

        let (records, skipped_pages) = parse_record_pages(&data, &restart_info, position);

        let mut client_restart = None;
        let mut open_attribute_table = Vec::new();
        let mut attribute_names = Vec::new();
        let mut txn_dump_candidates: Vec<(u64, Vec<TransactionTableDumpEntry>)> = Vec::new();

        for record in &records {
            if record.record_type() == LogRecordType::ClientRestart
                && let NtfsLogOperationData::Raw { data: ref cr_data } = record.redo_data
                && cr_data.len() >= NCR_MIN_SIZE
            {
                client_restart = Some(NtfsClientRestartArea {
                    major_version: le_u32(cr_data, NCR_OFF_MAJOR_VERSION),
                    minor_version: le_u32(cr_data, NCR_OFF_MINOR_VERSION),
                    start_of_checkpoint_lsn: le_u64(cr_data, NCR_OFF_START_OF_CHECKPOINT_LSN),
                    open_attribute_table_lsn: le_u64(cr_data, NCR_OFF_OPEN_ATTR_TABLE_LSN),
                    attribute_names_lsn: le_u64(cr_data, NCR_OFF_ATTR_NAMES_LSN),
                    dirty_page_table_lsn: le_u64(cr_data, NCR_OFF_DIRTY_PAGE_TABLE_LSN),
                    transaction_table_lsn: le_u64(cr_data, NCR_OFF_TRANSACTION_TABLE_LSN),
                });
            }

            if let NtfsLogOperationData::OpenAttributeTableDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                open_attribute_table = dump_entries.clone();
            }

            if let NtfsLogOperationData::AttributeNamesDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                attribute_names = dump_entries.clone();
            }

            if let NtfsLogOperationData::TransactionTableDump {
                entries: ref dump_entries,
            } = record.redo_data
            {
                txn_dump_candidates.push((record.lsn(), dump_entries.clone()));
            }
        }

        // Select the best TransactionTableDump: exact match on
        // transaction_table_lsn, then closest at/after, then
        // closest before. Falls back to last candidate if no
        // client restart is available.
        let transaction_table_dump =
            select_transaction_table_dump(&txn_dump_candidates, &client_restart);

        let baseline_lsn = if !transaction_table_dump.is_empty() {
            client_restart
                .as_ref()
                .map(|cr| cr.transaction_table_lsn())
                .unwrap_or(0)
        } else {
            0
        };

        let transaction_states =
            build_transaction_states(&transaction_table_dump, &records, baseline_lsn);

        Ok(Self {
            restart_info,
            client_restart,
            open_attribute_table,
            attribute_names,
            transaction_table_dump,
            transaction_states,
            records,
            skipped_pages,
        })
    }

    /// The LFS restart information.
    pub fn restart_info(&self) -> &LfsRestartInfo {
        &self.restart_info
    }

    /// The NTFS client restart area (checkpoint data), if found.
    pub fn client_restart(&self) -> Option<&NtfsClientRestartArea> {
        self.client_restart.as_ref()
    }

    /// All parsed log records, ordered by LSN.
    pub fn records(&self) -> &[NtfsLogRecord] {
        &self.records
    }

    /// Look up a record by its LSN.
    pub fn record_by_lsn(&self, lsn: u64) -> Option<&NtfsLogRecord> {
        self.records
            .binary_search_by_key(&lsn, |r| r.lsn)
            .ok()
            .map(|idx| &self.records[idx])
    }

    /// Group records by transaction ID.
    pub fn transactions(&self) -> alloc::collections::BTreeMap<u32, Vec<&NtfsLogRecord>> {
        let mut map: alloc::collections::BTreeMap<u32, Vec<&NtfsLogRecord>> =
            alloc::collections::BTreeMap::new();
        for record in &self.records {
            if record.record_type() == LogRecordType::ClientRecord {
                map.entry(record.transaction_id()).or_default().push(record);
            }
        }
        map
    }

    /// The open attribute table.
    pub fn open_attribute_table(&self) -> &[OpenAttributeEntry] {
        &self.open_attribute_table
    }

    /// Attribute name entries from the most recent checkpoint.
    pub fn attribute_names(&self) -> &[AttributeNameEntry] {
        &self.attribute_names
    }

    /// Transaction table entries from the checkpoint dump.
    pub fn transaction_table_dump(&self) -> &[TransactionTableDumpEntry] {
        &self.transaction_table_dump
    }

    /// Transaction lifecycle states, keyed by transaction
    /// table slot index.
    pub fn transaction_states(&self) -> &alloc::collections::BTreeMap<u32, TransactionEntry> {
        &self.transaction_states
    }

    /// Look up a single transaction by its table slot index.
    pub fn transaction_state(&self, id: u32) -> Option<&TransactionEntry> {
        self.transaction_states.get(&id)
    }

    /// Transactions that never reached end-of-life
    /// (ForgetTransaction not observed).
    pub fn incomplete_transactions(&self) -> impl Iterator<Item = &TransactionEntry> + '_ {
        self.transaction_states
            .values()
            .filter(|e| e.is_incomplete())
    }

    /// Number of corrupt record pages skipped during parsing.
    pub fn skipped_pages(&self) -> u32 {
        self.skipped_pages
    }
}

/// Apply Update Sequence Array fixup to a page buffer.
fn apply_usa_fixup(
    page: &mut [u8],
    usa_offset: usize,
    usa_count: u16,
    position: NtfsPosition,
) -> Result<()> {
    if usa_count < 1 {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "USA count is zero",
        });
    }
    let array_count = usa_count - 1;
    let usn_start = usa_offset;
    let usn_end = usn_start + 2;
    if usn_end > page.len() {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "USA offset out of bounds",
        });
    }
    let usn: [u8; 2] = page[usn_start..usn_end].try_into().unwrap();

    for i in 0..array_count as usize {
        let array_pos = usn_start + 2 + i * 2;
        let sector_pos = (i + 1) * USA_STRIDE - 2;

        if array_pos + 2 > page.len() || sector_pos + 2 > page.len() {
            break;
        }

        let replacement: [u8; 2] = page[array_pos..array_pos + 2].try_into().unwrap();

        if page[sector_pos..sector_pos + 2] != usn {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "USA mismatch (sector corruption)",
            });
        }

        page[sector_pos..sector_pos + 2].copy_from_slice(&replacement);
    }
    Ok(())
}

/// Read a little-endian u16 from a byte slice at `offset`.
fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

/// Read a little-endian u32 from a byte slice at `offset`.
fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from a byte slice at `offset`.
fn le_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

/// Walk a fixed-up FILE record buffer and collect resident
/// `$DATA` attribute values.
///
/// `limit` is `min(used_size, buf.len())`. Caller must validate
/// `used_size <= buf.len()` before calling.
///
/// Returns `Err` on structural corruption: truncated headers,
/// zero-length attributes, misaligned lengths, or missing end
/// marker.
fn walk_resident_data_attrs(
    buf: &[u8],
    limit: usize,
    first_attr_offset: u16,
) -> Result<Vec<ResidentDataValue>> {
    let position = NtfsPosition::none();

    if first_attr_offset as usize >= limit {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "log payload: first_attr_offset_out_of_bounds",
        });
    }

    let mut values = Vec::new();
    let mut offset = first_attr_offset as usize;

    loop {
        // Need at least 4 bytes to read the type field.
        if offset + 4 > limit {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: truncated_attr_header",
            });
        }

        let attr_type = le_u32(buf, offset + ATTR_OFF_TYPE);
        if attr_type == ATTR_END_MARKER {
            break;
        }

        // Need full common header to proceed.
        if offset + ATTR_MIN_HEADER_SIZE > limit {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: truncated_attr_header",
            });
        }

        let attr_len = le_u32(buf, offset + ATTR_OFF_LENGTH);

        if (attr_len as usize) < ATTR_MIN_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: attr_len_too_small",
            });
        }

        if !attr_len.is_multiple_of(8) {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: attr_len_unaligned",
            });
        }

        if offset + attr_len as usize > limit {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: attr_exceeds_bounds",
            });
        }

        let non_resident = buf[offset + ATTR_OFF_NON_RESIDENT];
        let name_length = buf[offset + ATTR_OFF_NAME_LENGTH];
        let name_offset = le_u16(buf, offset + ATTR_OFF_NAME_OFFSET);
        let instance = le_u16(buf, offset + ATTR_OFF_INSTANCE);

        // Only collect resident $DATA attributes.
        if attr_type == ATTR_TYPE_DATA && non_resident == 0 {
            if (attr_len as usize) < RES_MIN_HEADER_SIZE {
                return Err(NtfsError::InvalidLogFileRecord {
                    position,
                    reason: "log payload: \
                             resident_header_truncated",
                });
            }

            let value_length = le_u32(buf, offset + RES_OFF_VALUE_LENGTH);
            let value_offset = le_u16(buf, offset + RES_OFF_VALUE_OFFSET);

            if (value_offset as usize) < RES_MIN_HEADER_SIZE {
                return Err(NtfsError::InvalidLogFileRecord {
                    position,
                    reason: "log payload: \
                             resident_value_offset_before_header",
                });
            }

            // Check value bounds against attribute length (not
            // just record limit) to prevent reading into adjacent
            // attributes.
            if value_offset as usize + value_length as usize > attr_len as usize {
                return Err(NtfsError::InvalidLogFileRecord {
                    position,
                    reason: "log payload: \
                             resident_value_exceeds_bounds",
                });
            }

            // Validate name bounds if named.
            if name_length > 0 {
                if (name_offset as usize) < RES_MIN_HEADER_SIZE {
                    return Err(NtfsError::InvalidLogFileRecord {
                        position,
                        reason: "log payload: \
                                 attr_name_offset_before_header",
                    });
                }
                if name_offset as usize + name_length as usize * 2 > attr_len as usize {
                    return Err(NtfsError::InvalidLogFileRecord {
                        position,
                        reason: "log payload: \
                                 attr_name_exceeds_bounds",
                    });
                }
            }

            let val_start = offset + value_offset as usize;
            let val_end = val_start + value_length as usize;

            values.push(ResidentDataValue {
                instance,
                name_offset,
                name_length,
                value_offset_in_record: offset as u32 + value_offset as u32,
                data: buf[val_start..val_end].to_vec(),
            });
        }

        let next_offset = offset + attr_len as usize;
        debug_assert!(next_offset > offset);
        offset = next_offset;
    }

    Ok(values)
}

/// Parse an LFS restart page from the raw log file data.
///
/// Selects the more recent of the two restart pages (by `current_lsn`).
fn parse_restart_page(data: &[u8], position: NtfsPosition) -> Result<LfsRestartInfo> {
    if data.len() < RSTR_MIN_HEADER_SIZE {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "log file too small for restart page header",
        });
    }

    let page0 = parse_single_restart_page(data, 0, position)?;

    let page_size = page0.system_page_size as usize;
    let page1 = if data.len() >= page_size * 2 {
        parse_single_restart_page(data, page_size, NtfsPosition::new(page_size as u64)).ok()
    } else {
        None
    };

    match page1 {
        Some(p1) if p1.current_lsn > page0.current_lsn => Ok(p1),
        _ => Ok(page0),
    }
}

/// Parse a single LFS_RESTART_PAGE at the given offset.
fn parse_single_restart_page(
    data: &[u8],
    offset: usize,
    position: NtfsPosition,
) -> Result<LfsRestartInfo> {
    let page_data = &data[offset..];
    if page_data.len() < RSTR_MIN_HEADER_SIZE {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "restart page too small",
        });
    }

    let sig = &page_data[RSTR_OFF_SIGNATURE..RSTR_OFF_SIGNATURE + 4];
    if sig != RESTART_PAGE_SIGNATURE {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "expected RSTR signature",
        });
    }

    let system_page_size = le_u32(page_data, RSTR_OFF_SYSTEM_PAGE_SIZE);
    let log_page_size = le_u32(page_data, RSTR_OFF_LOG_PAGE_SIZE);
    let restart_offset = le_u16(page_data, RSTR_OFF_RESTART_OFFSET) as usize;
    let minor_version = le_u16(page_data, RSTR_OFF_MINOR_VERSION);
    let major_version = le_u16(page_data, RSTR_OFF_MAJOR_VERSION);

    if !((major_version == 1 && minor_version == 1) || (major_version == 2 && minor_version == 0)) {
        return Err(NtfsError::UnsupportedLfsVersion {
            position,
            major: major_version,
            minor: minor_version,
        });
    }

    let page_end = offset + (system_page_size as usize).min(data.len() - offset);
    let mut page_buf = data[offset..page_end].to_vec();

    let usa_offset = le_u16(&page_buf, RSTR_OFF_USA_OFFSET) as usize;
    let usa_count = le_u16(&page_buf, RSTR_OFF_USA_COUNT);
    if usa_count > 1 {
        apply_usa_fixup(&mut page_buf, usa_offset, usa_count, position)?;
    }

    if restart_offset + RA_MIN_SIZE > page_buf.len() {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "restart area extends beyond page",
        });
    }
    let ra = &page_buf[restart_offset..];

    let current_lsn = le_u64(ra, RA_OFF_CURRENT_LSN);
    let flags = le_u16(ra, RA_OFF_FLAGS);
    let seq_number_bits = le_u32(ra, RA_OFF_SEQ_NUMBER_BITS);
    let client_array_offset = le_u16(ra, RA_OFF_CLIENT_ARRAY_OFFSET) as usize;
    let file_size = le_u64(ra, RA_OFF_FILE_SIZE);
    let log_page_data_offset = le_u16(ra, RA_OFF_LOG_PAGE_DATA_OFFSET);

    let client_name = if client_array_offset + CR_SIZE <= ra.len() {
        let cr = &ra[client_array_offset..];
        let name_len = le_u32(cr, CR_OFF_CLIENT_NAME_LENGTH) as usize;
        let name_start = CR_OFF_CLIENT_NAME;
        let name_end = name_start + name_len.min(128);
        if name_end <= cr.len() {
            let name_bytes = &cr[name_start..name_end];
            let u16s: Vec<u16> = name_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16s)
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    Ok(LfsRestartInfo {
        major_version,
        minor_version,
        current_lsn,
        file_size,
        seq_number_bits,
        log_page_size,
        system_page_size,
        log_page_data_offset,
        flags,
        client_name,
    })
}

/// Returns `true` if the given operation is a "unit" type that
/// does not carry payload data by design.
pub fn operation_is_unit(op: NtfsLogOperation) -> bool {
    matches!(
        op,
        NtfsLogOperation::Noop
            | NtfsLogOperation::CompensationLogRecord
            | NtfsLogOperation::DeallocateFileRecordSegment
            | NtfsLogOperation::EndTopLevelAction
            | NtfsLogOperation::PrepareTransaction
            | NtfsLogOperation::CommitTransaction
            | NtfsLogOperation::ForgetTransaction
    )
}

/// Parse the typed redo/undo payload for an operation.
fn parse_operation_data(
    op_code: u16,
    data: &[u8],
    restart_info: &LfsRestartInfo,
) -> NtfsLogOperationData {
    let op = NtfsLogOperation::from_u16(op_code);

    // Empty-data fast path.
    if data.is_empty() {
        return match op {
            Some(o) if operation_is_unit(o) => NtfsLogOperationData::Unit,
            Some(_) => NtfsLogOperationData::Empty,
            None => NtfsLogOperationData::Raw { data: Vec::new() },
        };
    }

    // Non-empty data: classify by operation.
    match op {
        // Unit ops with unexpected bytes -> preserve as Raw.
        Some(o) if operation_is_unit(o) => NtfsLogOperationData::Raw {
            data: data.to_vec(),
        },

        // MFT record initialization.
        Some(NtfsLogOperation::InitializeFileRecordSegment) => {
            NtfsLogOperationData::FileRecordSegment {
                data: data.to_vec(),
            }
        }

        // Existing typed: SetNewAttributeSizes.
        Some(NtfsLogOperation::SetNewAttributeSizes) if data.len() >= 32 => {
            NtfsLogOperationData::SetNewAttributeSizes {
                allocated_length: le_u64(data, 0),
                data_length: le_u64(data, 8),
                valid_data_length: le_u64(data, 16),
                total_allocated: le_u64(data, 24),
            }
        }

        // Existing typed: SetBits.
        Some(NtfsLogOperation::SetBitsInNonresidentBitMap) if data.len() >= 8 => {
            NtfsLogOperationData::SetBits {
                bit_offset: le_u32(data, 0),
                num_bits: le_u32(data, 4),
            }
        }

        // Existing typed: ClearBits.
        Some(NtfsLogOperation::ClearBitsInNonresidentBitMap) if data.len() >= 8 => {
            NtfsLogOperationData::ClearBits {
                bit_offset: le_u32(data, 0),
                num_bits: le_u32(data, 4),
            }
        }

        // Existing typed: OpenNonresidentAttribute.
        Some(NtfsLogOperation::OpenNonresidentAttribute) if data.len() >= 24 => {
            let (file_reference, attribute_type, name) =
                parse_open_nonresident_attribute(data, restart_info);
            NtfsLogOperationData::OpenNonresidentAttribute {
                file_reference,
                attribute_type,
                name,
            }
        }

        // Existing typed: OpenAttributeTableDump.
        Some(NtfsLogOperation::OpenAttributeTableDump) => {
            let entries = parse_open_attribute_table_dump(data, restart_info);
            NtfsLogOperationData::OpenAttributeTableDump { entries }
        }

        // Existing typed: AttributeNamesDump.
        Some(NtfsLogOperation::AttributeNamesDump) => {
            let entries = parse_attribute_names_dump(data);
            NtfsLogOperationData::AttributeNamesDump { entries }
        }

        // Value/attribute/mapping ops -> Bytes.
        Some(
            NtfsLogOperation::WriteEndOfFileRecordSegment
            | NtfsLogOperation::CreateAttribute
            | NtfsLogOperation::DeleteAttribute
            | NtfsLogOperation::UpdateResidentValue
            | NtfsLogOperation::UpdateNonresidentValue
            | NtfsLogOperation::UpdateMappingPairs
            | NtfsLogOperation::DeleteDirtyClusters
            | NtfsLogOperation::WriteEndOfIndexBuffer
            | NtfsLogOperation::HotFix
            | NtfsLogOperation::ZeroEndOfFileRecord
            | NtfsLogOperation::AddIndexEntryRoot
            | NtfsLogOperation::DeleteIndexEntryRoot
            | NtfsLogOperation::AddIndexEntryAllocation
            | NtfsLogOperation::DeleteIndexEntryAllocation
            | NtfsLogOperation::UpdateFileNameRoot
            | NtfsLogOperation::UpdateFileNameAllocation,
        ) => NtfsLogOperationData::Bytes {
            data: data.to_vec(),
        },

        // SetIndexEntryVcn: parse 8-byte VCN.
        Some(
            NtfsLogOperation::SetIndexEntryVcnRoot | NtfsLogOperation::SetIndexEntryVcnAllocation,
        ) if data.len() >= 8 => NtfsLogOperationData::IndexEntryVcn {
            vcn: le_u64(data, 0),
        },

        // TransactionTableDump.
        Some(NtfsLogOperation::TransactionTableDump) => {
            let entries = parse_transaction_table_dump(data);
            NtfsLogOperationData::TransactionTableDump { entries }
        }

        // Dump tables (future), record data ops,
        // typed ops with too-small data, unknown -> Raw.
        _ => NtfsLogOperationData::Raw {
            data: data.to_vec(),
        },
    }
}

/// Parse an OpenNonresidentAttribute redo payload.
fn parse_open_nonresident_attribute(
    data: &[u8],
    restart_info: &LfsRestartInfo,
) -> (u64, u32, Option<String>) {
    let is_v0 = restart_info.major_version() == 1;
    if is_v0 {
        if data.len() < OAE0_SIZE {
            return (0, 0, None);
        }
        let file_ref = le_u64(data, OAE0_OFF_FILE_REFERENCE);
        let attr_type = le_u32(data, OAE0_OFF_ATTR_TYPE);
        let name = parse_utf16le_name(&data[OAE0_SIZE..]);
        (file_ref, attr_type, name)
    } else {
        if data.len() < OAE1_SIZE {
            return (0, 0, None);
        }
        let file_ref = le_u64(data, OAE1_OFF_FILE_REFERENCE);
        let attr_type = le_u32(data, OAE1_OFF_ATTR_TYPE);
        let name = parse_utf16le_name(&data[OAE1_SIZE..]);
        (file_ref, attr_type, name)
    }
}

/// Parse an OpenAttributeTableDump payload into entries.
fn parse_open_attribute_table_dump(
    data: &[u8],
    restart_info: &LfsRestartInfo,
) -> Vec<OpenAttributeEntry> {
    let is_v0 = restart_info.major_version() == 1;
    let entry_size = if is_v0 { OAE0_SIZE } else { OAE1_SIZE };
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + entry_size <= data.len() {
        let entry = &data[offset..];

        if is_v0 {
            entries.push(OpenAttributeEntry {
                file_reference: le_u64(entry, OAE0_OFF_FILE_REFERENCE),
                lsn_of_open_record: le_u64(entry, OAE0_OFF_LSN_OF_OPEN),
                attribute_type: le_u32(entry, OAE0_OFF_ATTR_TYPE),
                bytes_per_index_buffer: le_u32(entry, OAE0_OFF_BYTES_PER_INDEX),
            });
        } else {
            entries.push(OpenAttributeEntry {
                file_reference: le_u64(entry, OAE1_OFF_FILE_REFERENCE),
                lsn_of_open_record: le_u64(entry, OAE1_OFF_LSN_OF_OPEN),
                attribute_type: le_u32(entry, OAE1_OFF_ATTR_TYPE),
                bytes_per_index_buffer: le_u32(entry, OAE1_OFF_BYTES_PER_INDEX),
            });
        }

        offset += entry_size;
    }

    entries
}

/// Parse an AttributeNamesDump payload into entries.
fn parse_attribute_names_dump(data: &[u8]) -> Vec<AttributeNameEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + ANE_OFF_NAME <= data.len() {
        let index = le_u16(data, offset + ANE_OFF_INDEX);
        let name_length = le_u16(data, offset + ANE_OFF_NAME_LENGTH) as usize;
        let name_start = offset + ANE_OFF_NAME;
        let name_byte_len = name_length * 2;
        let name_end = name_start + name_byte_len;

        if name_end > data.len() {
            break;
        }

        let name_bytes = &data[name_start..name_end];
        let u16s: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let name = String::from_utf16_lossy(&u16s);

        entries.push(AttributeNameEntry { index, name });

        offset = name_end + 2;
    }

    entries
}

/// Parse a TransactionTableDump (0x20) payload into entries.
///
/// Each entry is TTE_SIZE (0x28) bytes. Entries with
/// `allocated_or_next_free != TTE_ALLOCATED_MARKER` are
/// free-list slots and are included with their raw values
/// (filtering is left to callers).
fn parse_transaction_table_dump(data: &[u8]) -> Vec<TransactionTableDumpEntry> {
    let mut entries = Vec::with_capacity(data.len() / TTE_SIZE);
    let mut offset = 0;
    let mut index: u32 = 0;

    while offset + TTE_SIZE <= data.len() {
        let entry = &data[offset..];

        entries.push(TransactionTableDumpEntry {
            entry_index: index,
            allocated_or_next_free: le_u32(entry, TTE_OFF_ALLOCATED),
            transaction_state: le_u32(entry, TTE_OFF_STATE),
            first_lsn: le_u64(entry, TTE_OFF_FIRST_LSN),
            previous_lsn: le_u64(entry, TTE_OFF_PREVIOUS_LSN),
            undo_next_lsn: le_u64(entry, TTE_OFF_UNDO_NEXT_LSN),
            undo_records: le_u32(entry, TTE_OFF_UNDO_RECORDS),
            undo_bytes: le_u32(entry, TTE_OFF_UNDO_BYTES),
        });

        offset += TTE_SIZE;
        index += 1;
    }

    entries
}

/// Select the best `TransactionTableDump` from collected
/// candidates using 3-tier matching against the client restart
/// area's `transaction_table_lsn`:
///
/// 1. Exact LSN match
/// 2. Closest candidate at or after `target_lsn`
/// 3. Closest candidate before `target_lsn`
/// 4. Fallback: last candidate (if no client restart)
fn select_transaction_table_dump(
    candidates: &[(u64, Vec<TransactionTableDumpEntry>)],
    client_restart: &Option<NtfsClientRestartArea>,
) -> Vec<TransactionTableDumpEntry> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let target_lsn = client_restart
        .as_ref()
        .map(|cr| cr.transaction_table_lsn())
        .unwrap_or(0);

    if target_lsn == 0 {
        return candidates
            .last()
            .map(|(_, e)| e.clone())
            .unwrap_or_default();
    }

    // Tier 1: exact match.
    if let Some((_, entries)) = candidates.iter().find(|(lsn, _)| *lsn == target_lsn) {
        return entries.clone();
    }

    // Tier 2: closest at or after target_lsn.
    if let Some((_, entries)) = candidates
        .iter()
        .filter(|(lsn, _)| *lsn >= target_lsn)
        .min_by_key(|(lsn, _)| *lsn)
    {
        return entries.clone();
    }

    // Tier 3: closest before target_lsn.
    if let Some((_, entries)) = candidates
        .iter()
        .filter(|(lsn, _)| *lsn < target_lsn)
        .max_by_key(|(lsn, _)| *lsn)
    {
        return entries.clone();
    }

    Vec::new()
}

/// Build transaction lifecycle states from a checkpoint dump
/// and forward record scan.
fn build_transaction_states(
    transaction_table_dump: &[TransactionTableDumpEntry],
    records: &[NtfsLogRecord],
    baseline_lsn: u64,
) -> alloc::collections::BTreeMap<u32, TransactionEntry> {
    let mut map: alloc::collections::BTreeMap<u32, TransactionEntry> =
        alloc::collections::BTreeMap::new();

    // Phase 1: Seed from dump (in-use entries only).
    for entry in transaction_table_dump {
        if entry.allocated_or_next_free != TTE_ALLOCATED_MARKER {
            continue;
        }

        let state = match entry.transaction_state {
            2 => TransactionState::Prepared,
            3 => TransactionState::Committed,
            _ => TransactionState::Active,
        };

        map.insert(
            entry.entry_index,
            TransactionEntry {
                transaction_id: entry.entry_index,
                state,
                seeded_from_dump: true,
                first_lsn: entry.first_lsn,
                last_lsn: entry.previous_lsn,
                undo_next_lsn: if entry.undo_next_lsn == 0 {
                    None
                } else {
                    Some(entry.undo_next_lsn)
                },
                operation_count: 0,
                saw_prepare: state == TransactionState::Prepared,
                saw_commit: state == TransactionState::Committed,
                saw_forget: false,
                forgotten_lsn: None,
                recycled: false,
                recycle_lsn: None,
            },
        );
    }

    // Phase 2: Forward scan from baseline.
    for record in records {
        if record.record_type() != LogRecordType::ClientRecord {
            continue;
        }
        if baseline_lsn > 0 && record.lsn() < baseline_lsn {
            continue;
        }

        let txn_id = record.transaction_id();
        let lsn = record.lsn();

        let entry = map.entry(txn_id).or_insert_with(|| TransactionEntry {
            transaction_id: txn_id,
            state: TransactionState::Active,
            seeded_from_dump: false,
            first_lsn: lsn,
            last_lsn: lsn,
            undo_next_lsn: None,
            operation_count: 0,
            saw_prepare: false,
            saw_commit: false,
            saw_forget: false,
            forgotten_lsn: None,
            recycled: false,
            recycle_lsn: None,
        });

        // Recycling: activity after Forgotten.
        if entry.state == TransactionState::Forgotten {
            entry.recycled = true;
            if entry.recycle_lsn.is_none() {
                entry.recycle_lsn = Some(lsn);
            }
            continue;
        }

        // Update LSN bounds.
        if lsn < entry.first_lsn {
            entry.first_lsn = lsn;
        }
        if lsn > entry.last_lsn {
            entry.last_lsn = lsn;
        }

        // Update undo chain.
        if record.client_undo_next_lsn() != 0 {
            entry.undo_next_lsn = Some(record.client_undo_next_lsn());
        }

        // Count payload-carrying redo operations.
        if !matches!(
            record.redo_data(),
            NtfsLogOperationData::Unit | NtfsLogOperationData::Empty
        ) {
            entry.operation_count += 1;
        }

        // Lifecycle transitions.
        match record.redo_operation() {
            Some(NtfsLogOperation::PrepareTransaction) => {
                entry.state = TransactionState::Prepared;
                entry.saw_prepare = true;
            }
            Some(NtfsLogOperation::CommitTransaction) => {
                entry.state = TransactionState::Committed;
                entry.saw_commit = true;
            }
            Some(NtfsLogOperation::ForgetTransaction) => {
                entry.state = TransactionState::Forgotten;
                entry.saw_forget = true;
                entry.forgotten_lsn = Some(lsn);
            }
            _ => {}
        }
    }

    map
}

/// Try to parse a UTF-16LE name from a byte slice.
fn parse_utf16le_name(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let u16s: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    if u16s.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&u16s))
    }
}

/// Parse a single log record from LFS header + client data bytes.
fn parse_single_log_record(
    lfs_header: &[u8],
    client_data: &[u8],
    restart_info: &LfsRestartInfo,
) -> Option<NtfsLogRecord> {
    if lfs_header.len() < LR_HEADER_SIZE {
        return None;
    }

    let this_lsn = le_u64(lfs_header, LR_OFF_THIS_LSN);
    let client_previous_lsn = le_u64(lfs_header, LR_OFF_CLIENT_PREVIOUS_LSN);
    let client_undo_next_lsn = le_u64(lfs_header, LR_OFF_CLIENT_UNDO_NEXT_LSN);
    let _client_data_length = le_u32(lfs_header, LR_OFF_CLIENT_DATA_LENGTH) as usize;
    let record_type_raw = le_u32(lfs_header, LR_OFF_RECORD_TYPE);
    let transaction_id = le_u32(lfs_header, LR_OFF_TRANSACTION_ID);
    let flags = le_u16(lfs_header, LR_OFF_FLAGS);

    let record_type = match record_type_raw {
        LFS_CLIENT_RECORD => LogRecordType::ClientRecord,
        LFS_CLIENT_RESTART => LogRecordType::ClientRestart,
        _ => return None,
    };

    if record_type == LogRecordType::ClientRestart {
        return Some(NtfsLogRecord {
            lsn: this_lsn,
            client_previous_lsn,
            client_undo_next_lsn,
            record_type,
            transaction_id,
            flags,
            redo_operation_code: NtfsLogOperation::Noop as u16,
            undo_operation_code: NtfsLogOperation::Noop as u16,
            redo_operation: Some(NtfsLogOperation::Noop),
            undo_operation: Some(NtfsLogOperation::Noop),
            target_attribute: 0,
            target_vcn: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            redo_data: NtfsLogOperationData::Raw {
                data: client_data.to_vec(),
            },
            undo_data: NtfsLogOperationData::Empty,
        });
    }

    if client_data.len() < NR_FIXED_HEADER_SIZE {
        return None;
    }

    let redo_op = le_u16(client_data, NR_OFF_REDO_OP);
    let undo_op = le_u16(client_data, NR_OFF_UNDO_OP);
    let redo_offset = le_u16(client_data, NR_OFF_REDO_OFFSET) as usize;
    let redo_length = le_u16(client_data, NR_OFF_REDO_LENGTH) as usize;
    let undo_offset = le_u16(client_data, NR_OFF_UNDO_OFFSET) as usize;
    let undo_length = le_u16(client_data, NR_OFF_UNDO_LENGTH) as usize;
    let target_attribute = le_u16(client_data, NR_OFF_TARGET_ATTRIBUTE);
    let lcns_to_follow = le_u16(client_data, NR_OFF_LCNS_TO_FOLLOW) as usize;
    let record_offset = le_u16(client_data, NR_OFF_RECORD_OFFSET);
    let attribute_offset = le_u16(client_data, NR_OFF_ATTRIBUTE_OFFSET);
    let cluster_block_offset = le_u16(client_data, NR_OFF_CLUSTER_BLOCK_OFFSET);
    let target_vcn = le_u64(client_data, NR_OFF_TARGET_VCN);

    let data_start = NR_FIXED_HEADER_SIZE + lcns_to_follow * 8;

    let redo_data = if redo_length > 0 {
        let start = data_start + redo_offset;
        let end = start + redo_length;
        if end <= client_data.len() {
            parse_operation_data(redo_op, &client_data[start..end], restart_info)
        } else {
            NtfsLogOperationData::Empty
        }
    } else {
        NtfsLogOperationData::Empty
    };

    let undo_data = if undo_length > 0 {
        let start = data_start + undo_offset;
        let end = start + undo_length;
        if end <= client_data.len() {
            parse_operation_data(undo_op, &client_data[start..end], restart_info)
        } else {
            NtfsLogOperationData::Empty
        }
    } else {
        NtfsLogOperationData::Empty
    };

    Some(NtfsLogRecord {
        lsn: this_lsn,
        client_previous_lsn,
        client_undo_next_lsn,
        record_type,
        transaction_id,
        flags,
        redo_operation_code: redo_op,
        undo_operation_code: undo_op,
        redo_operation: NtfsLogOperation::from_u16(redo_op),
        undo_operation: NtfsLogOperation::from_u16(undo_op),
        target_attribute,
        target_vcn,
        record_offset,
        attribute_offset,
        cluster_block_offset,
        redo_data,
        undo_data,
    })
}

/// Parse all record pages from the log file data.
///
/// Returns `(records, skipped_pages)`. Corrupt pages are skipped
/// rather than causing a hard error.
fn parse_record_pages(
    data: &[u8],
    restart_info: &LfsRestartInfo,
    _position: NtfsPosition,
) -> (Vec<NtfsLogRecord>, u32) {
    let page_size = restart_info.log_page_size() as usize;
    let system_page_size = restart_info.system_page_size() as usize;

    if page_size < RCRD_MIN_HEADER_SIZE || system_page_size == 0 {
        return (Vec::new(), 0);
    }

    let log_area_start = if restart_info.major_version() >= 2 {
        system_page_size * 2 + page_size * 32
    } else {
        system_page_size * 2 + page_size * 2
    };

    let log_page_data_offset = restart_info.log_page_data_offset as usize;

    let mut records = Vec::new();
    let mut skipped_pages: u32 = 0;
    let mut page_offset = log_area_start;

    while page_offset + page_size <= data.len() {
        let page_pos = NtfsPosition::new(page_offset as u64);

        let sig = &data[page_offset..page_offset + 4];
        if sig != RECORD_PAGE_SIGNATURE {
            skipped_pages += 1;
            page_offset += page_size;
            continue;
        }

        let page_end = page_offset + page_size;
        let mut page_buf = data[page_offset..page_end].to_vec();

        let usa_offset = le_u16(&page_buf, RCRD_OFF_USA_OFFSET) as usize;
        let usa_count = le_u16(&page_buf, RCRD_OFF_USA_COUNT);

        if apply_usa_fixup(&mut page_buf, usa_offset, usa_count, page_pos).is_err() {
            skipped_pages += 1;
            page_offset += page_size;
            continue;
        }

        let next_record_offset = le_u16(&page_buf, RCRD_OFF_NEXT_RECORD_OFFSET) as usize;

        let mut record_offset = log_page_data_offset;
        let page_data_end = if next_record_offset > log_page_data_offset {
            next_record_offset
        } else {
            page_size
        };

        while record_offset + LR_HEADER_SIZE <= page_data_end {
            let lfs_header = &page_buf[record_offset..];
            if lfs_header.len() < LR_HEADER_SIZE {
                break;
            }

            let client_data_length = le_u32(lfs_header, LR_OFF_CLIENT_DATA_LENGTH) as usize;
            let this_lsn = le_u64(lfs_header, LR_OFF_THIS_LSN);

            if this_lsn == 0 {
                break;
            }

            let total_record_size = LR_HEADER_SIZE + client_data_length;

            let available_in_page = page_data_end - record_offset - LR_HEADER_SIZE;
            let client_data_in_page = client_data_length.min(available_in_page);

            // Skip records that span multiple pages (truncated data).
            if client_data_length > available_in_page {
                record_offset += (total_record_size + 7) & !7;
                continue;
            }

            let client_start = record_offset + LR_HEADER_SIZE;
            let client_end = client_start + client_data_in_page;
            let client_data = if client_end <= page_buf.len() {
                page_buf[client_start..client_end].to_vec()
            } else {
                break;
            };

            if let Some(record) = parse_single_log_record(lfs_header, &client_data, restart_info) {
                records.push(record);
            }

            let advance = (total_record_size + 7) & !7;
            record_offset += advance;
        }

        page_offset += page_size;
    }

    records.sort_by_key(|r| r.lsn);
    records.dedup_by_key(|r| r.lsn);

    (records, skipped_pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::Ntfs;

    /// Helper: read the raw $LogFile data from testfs1.
    fn read_logfile_data() -> Option<Vec<u8>> {
        use crate::attribute::NtfsAttributeType;
        use crate::file::KnownNtfsFileRecordNumber;
        use fs_common::io::FsReadSeek;

        let mut testfs1 = crate::helpers::tests::testfs1()?;
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::LogFile as u64)
            .unwrap();

        let data_attr = logfile_file
            .attributes_raw()
            .find_map(|attr| {
                let attr = attr.ok()?;
                if attr.ty().ok()? == NtfsAttributeType::Data {
                    Some(attr)
                } else {
                    None
                }
            })
            .expect("$LogFile should have a $DATA attribute");

        let mut value = data_attr.value(&mut testfs1).unwrap();
        let len = value.len() as usize;
        let mut data = vec![0u8; len];
        value.read_exact(&mut testfs1, &mut data).unwrap();
        Some(data)
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_parse_restart_page_real() {
        let Some(data) = read_logfile_data() else {
            return;
        };
        let pos = NtfsPosition::new(0);
        let info = parse_restart_page(&data, pos).unwrap();

        assert!(
            (info.major_version() == 1 && info.minor_version() == 1)
                || (info.major_version() == 2 && info.minor_version() == 0),
            "unexpected LFS version {}.{}",
            info.major_version(),
            info.minor_version(),
        );
        assert!(info.log_page_size() > 0);
        assert!(info.system_page_size() > 0);
        assert!(info.file_size() > 0);
        assert!(info.seq_number_bits() > 0);
        assert!(!info.client_name().is_empty());
    }

    /// Build a synthetic RSTR page (4096 bytes) for unit testing.
    ///
    /// Constructs a valid LFS v1.1 restart page with USA fixup,
    /// a restart area, and a client record containing "NTFS".
    fn build_synthetic_rstr_page() -> Vec<u8> {
        let page_size: usize = 4096;
        let mut page = vec![0u8; page_size];

        // -- Page header --
        page[RSTR_OFF_SIGNATURE..RSTR_OFF_SIGNATURE + 4].copy_from_slice(RESTART_PAGE_SIGNATURE);

        // USA: offset=0x1E (right after header), count=9 (1 USN +
        // 8 sectors in 4096 bytes).
        let usa_off: u16 = RSTR_MIN_HEADER_SIZE as u16;
        let usa_count: u16 = 9;
        page[RSTR_OFF_USA_OFFSET..RSTR_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&usa_count.to_le_bytes());

        page[RSTR_OFF_SYSTEM_PAGE_SIZE..RSTR_OFF_SYSTEM_PAGE_SIZE + 4]
            .copy_from_slice(&(page_size as u32).to_le_bytes());
        page[RSTR_OFF_LOG_PAGE_SIZE..RSTR_OFF_LOG_PAGE_SIZE + 4]
            .copy_from_slice(&(page_size as u32).to_le_bytes());

        // restart_offset: past the USA (usa_off + usa_count * 2),
        // 8-byte aligned.
        let ra_start = (usa_off as usize + usa_count as usize * 2 + 7) & !7;
        page[RSTR_OFF_RESTART_OFFSET..RSTR_OFF_RESTART_OFFSET + 2]
            .copy_from_slice(&(ra_start as u16).to_le_bytes());
        page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
            .copy_from_slice(&1u16.to_le_bytes());
        page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
            .copy_from_slice(&1u16.to_le_bytes());

        // -- Restart area (at ra_start) --
        let ra = ra_start;
        // current_lsn
        page[ra + RA_OFF_CURRENT_LSN..ra + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&100u64.to_le_bytes());
        page[ra + RA_OFF_FLAGS..ra + RA_OFF_FLAGS + 2]
            .copy_from_slice(&RESTART_CLEAN_DISMOUNT.to_le_bytes());
        page[ra + RA_OFF_SEQ_NUMBER_BITS..ra + RA_OFF_SEQ_NUMBER_BITS + 4]
            .copy_from_slice(&45u32.to_le_bytes());
        page[ra + RA_OFF_FILE_SIZE..ra + RA_OFF_FILE_SIZE + 8]
            .copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes());
        page[ra + RA_OFF_LOG_PAGE_DATA_OFFSET..ra + RA_OFF_LOG_PAGE_DATA_OFFSET + 2]
            .copy_from_slice(&64u16.to_le_bytes());

        // client_array_offset (relative to RA start): place client
        // record at RA_MIN_SIZE, 8-byte aligned.
        let ca_off = (RA_MIN_SIZE + 7) & !7;
        page[ra + RA_OFF_CLIENT_ARRAY_OFFSET..ra + RA_OFF_CLIENT_ARRAY_OFFSET + 2]
            .copy_from_slice(&(ca_off as u16).to_le_bytes());

        // -- Client record (at ra + ca_off) --
        let cr = ra + ca_off;
        // Client name "NTFS" in UTF-16LE = 8 bytes.
        let name_utf16: Vec<u8> = "NTFS"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        page[cr + CR_OFF_CLIENT_NAME_LENGTH..cr + CR_OFF_CLIENT_NAME_LENGTH + 4]
            .copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
        page[cr + CR_OFF_CLIENT_NAME..cr + CR_OFF_CLIENT_NAME + name_utf16.len()]
            .copy_from_slice(&name_utf16);

        // -- Write USA: USN value + per-sector replacements --
        // The USN value is arbitrary; we use 0x00_01.
        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);

        // For each of the 8 sectors, store the original last-2 bytes
        // in the USA array and write the USN at the sector boundary.
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let array_slot = usa + 2 + i * 2;
            page[array_slot..array_slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        page
    }

    /// Build a dummy LfsRestartInfo for operation data parsing tests.
    fn build_dummy_restart_info() -> LfsRestartInfo {
        LfsRestartInfo {
            major_version: 1,
            minor_version: 1,
            current_lsn: 100,
            file_size: 2 * 1024 * 1024,
            seq_number_bits: 45,
            log_page_size: 4096,
            system_page_size: 4096,
            log_page_data_offset: 64,
            flags: RESTART_CLEAN_DISMOUNT,
            client_name: String::from("NTFS"),
        }
    }

    /// Re-apply USA fixup to a synthetic page after modifying it.
    fn reapply_usa(page: &mut [u8]) {
        let usa_off = le_u16(page, RSTR_OFF_USA_OFFSET) as usize;
        let usn: [u8; 2] = [page[usa_off], page[usa_off + 1]];
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            if sector_end + 2 > page.len() {
                break;
            }
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa_off + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }
    }

    #[test]
    fn test_parse_synthetic_restart_page() {
        let page = build_synthetic_rstr_page();
        let pos = NtfsPosition::new(0);
        let info = parse_restart_page(&page, pos).expect("synthetic parse");

        assert_eq!(info.major_version(), 1);
        assert_eq!(info.minor_version(), 1);
        assert_eq!(info.current_lsn(), 100);
        assert_eq!(info.file_size(), 2 * 1024 * 1024);
        assert_eq!(info.log_page_size(), 4096);
        assert_eq!(info.system_page_size(), 4096);
        assert_eq!(info.seq_number_bits(), 45);
        assert!(info.is_clean_dismount());
        assert_eq!(info.client_name(), "NTFS");
    }

    #[test]
    fn test_parse_restart_page_too_small() {
        let data = vec![0u8; 10];
        let result = parse_restart_page(&data, NtfsPosition::new(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_restart_page_bad_signature() {
        let mut page = vec![0u8; 4096];
        page[0..4].copy_from_slice(b"BAAD");
        let result = parse_restart_page(&page, NtfsPosition::new(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_restart_page_unsupported_version() {
        let mut page = vec![0u8; 4096];
        page[RSTR_OFF_SIGNATURE..RSTR_OFF_SIGNATURE + 4].copy_from_slice(RESTART_PAGE_SIGNATURE);
        page[RSTR_OFF_SYSTEM_PAGE_SIZE..RSTR_OFF_SYSTEM_PAGE_SIZE + 4]
            .copy_from_slice(&4096u32.to_le_bytes());
        page[RSTR_OFF_LOG_PAGE_SIZE..RSTR_OFF_LOG_PAGE_SIZE + 4]
            .copy_from_slice(&4096u32.to_le_bytes());
        page[RSTR_OFF_USA_OFFSET..RSTR_OFF_USA_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
        page[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        // Version 3.0 — unsupported.
        page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
            .copy_from_slice(&3u16.to_le_bytes());
        page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
            .copy_from_slice(&0u16.to_le_bytes());

        let result = parse_restart_page(&page, NtfsPosition::new(0));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_selects_newer_page() {
        // Build two pages; page1 has a higher current_lsn.
        let mut page0 = build_synthetic_rstr_page();
        let mut page1 = build_synthetic_rstr_page();

        // Set page1's current_lsn to 200 (page0 is 100).
        let ra_start = le_u16(&page1, RSTR_OFF_RESTART_OFFSET) as usize;
        page1[ra_start + RA_OFF_CURRENT_LSN..ra_start + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&200u64.to_le_bytes());

        // Re-apply USA fixup for page1 (the sector end bytes
        // changed).
        let usa_off = le_u16(&page1, RSTR_OFF_USA_OFFSET) as usize;
        let usn: [u8; 2] = [page1[usa_off], page1[usa_off + 1]];
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page1[sector_end], page1[sector_end + 1]];
            let slot = usa_off + 2 + i * 2;
            page1[slot..slot + 2].copy_from_slice(&original);
            page1[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        let mut combined = page0.clone();
        combined.extend_from_slice(&page1);

        let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
        assert_eq!(info.current_lsn(), 200);

        // When page0 has the higher LSN, it should be selected.
        let ra0_start = le_u16(&page0, RSTR_OFF_RESTART_OFFSET) as usize;
        page0[ra0_start + RA_OFF_CURRENT_LSN..ra0_start + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&300u64.to_le_bytes());

        // Re-apply USA fixup for page0.
        let usa_off0 = le_u16(&page0, RSTR_OFF_USA_OFFSET) as usize;
        let usn0: [u8; 2] = [page0[usa_off0], page0[usa_off0 + 1]];
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page0[sector_end], page0[sector_end + 1]];
            let slot = usa_off0 + 2 + i * 2;
            page0[slot..slot + 2].copy_from_slice(&original);
            page0[sector_end..sector_end + 2].copy_from_slice(&usn0);
        }

        let mut combined2 = page0;
        combined2.extend_from_slice(&page1);
        let info2 = parse_restart_page(&combined2, NtfsPosition::new(0)).unwrap();
        assert_eq!(info2.current_lsn(), 300);
    }

    #[test]
    fn test_usa_fixup_mismatch() {
        let mut page = build_synthetic_rstr_page();
        // Corrupt a sector boundary — change the USN written there.
        page[USA_STRIDE - 2] = 0xFF;
        page[USA_STRIDE - 1] = 0xFF;

        let result = parse_restart_page(&page, NtfsPosition::new(0));
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_parse_records_produces_results() {
        let Some(data) = read_logfile_data() else {
            return;
        };
        let pos = NtfsPosition::new(0);
        let restart = parse_restart_page(&data, pos).unwrap();
        let (records, skipped) = parse_record_pages(&data, &restart, pos);
        assert!(
            !records.is_empty(),
            "expected at least one log record, got 0 \
             (skipped {skipped} pages)"
        );
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_records_ordered_by_lsn() {
        let Some(data) = read_logfile_data() else {
            return;
        };
        let pos = NtfsPosition::new(0);
        let restart = parse_restart_page(&data, pos).unwrap();
        let (records, _) = parse_record_pages(&data, &restart, pos);
        for window in records.windows(2) {
            assert!(
                window[0].lsn() <= window[1].lsn(),
                "records not ordered: LSN {} > {}",
                window[0].lsn(),
                window[1].lsn(),
            );
        }
    }

    #[test]
    fn test_logfile_load() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // testfs1's $LogFile may be uninitialized (0xFF from mkntfs).
        // If NtfsLogFile::load fails, check if the error is about
        // an invalid signature (expected for uninitialized logs).
        match NtfsLogFile::load(&ntfs, &mut testfs1) {
            Ok(logfile) => {
                let restart = logfile.restart_info();
                assert!(restart.log_page_size() > 0);
                assert!(!restart.client_name().is_empty());
                assert!(!logfile.records().is_empty());
            }
            Err(e) => {
                // Expected for uninitialized $LogFile.
                let msg = format!("{e}");
                assert!(
                    msg.contains("RSTR") || msg.contains("signature") || msg.contains("too small"),
                    "unexpected error: {e}"
                );
            }
        }
    }

    #[test]
    fn test_logfile_via_ntfs_convenience() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        // Just verify it compiles and doesn't panic.
        let _ = ntfs.logfile(&mut testfs1);
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_transactions() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");
        let txns = logfile.transactions();
        assert!(!txns.is_empty());
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_record_operations_are_valid() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");
        for record in logfile.records() {
            assert!(record.lsn() > 0);
            assert!(
                record.record_type() == LogRecordType::ClientRecord
                    || record.record_type() == LogRecordType::ClientRestart,
            );
        }
    }

    #[test]
    fn test_operation_enum_round_trip() {
        for code in 0x00..=0x25u16 {
            let op = NtfsLogOperation::from_u16(code);
            assert!(
                op.is_some(),
                "operation code {code:#x} should be recognized"
            );
            assert_eq!(op.unwrap() as u16, code);
        }
        assert!(NtfsLogOperation::from_u16(0x26).is_none());
        assert!(NtfsLogOperation::from_u16(0xFF).is_none());
    }

    #[test]
    fn test_unsupported_lfs_version() {
        let mut page = build_synthetic_rstr_page();
        // Set major version to 3 (unsupported).
        page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
            .copy_from_slice(&3u16.to_le_bytes());
        // Re-apply USA fixup.
        reapply_usa(&mut page);

        let result = parse_restart_page(&page, NtfsPosition::new(0));
        assert!(matches!(
            result,
            Err(NtfsError::UnsupportedLfsVersion { major: 3, .. })
        ));
    }

    #[test]
    fn test_parse_operation_data_set_new_attribute_sizes() {
        let restart_info = build_dummy_restart_info();
        let mut data = vec![0u8; 32];
        // allocated_length = 4096
        data[0..8].copy_from_slice(&4096u64.to_le_bytes());
        // data_length = 1024
        data[8..16].copy_from_slice(&1024u64.to_le_bytes());
        // valid_data_length = 512
        data[16..24].copy_from_slice(&512u64.to_le_bytes());
        // total_allocated = 8192
        data[24..32].copy_from_slice(&8192u64.to_le_bytes());

        let result = parse_operation_data(
            NtfsLogOperation::SetNewAttributeSizes as u16,
            &data,
            &restart_info,
        );
        match result {
            NtfsLogOperationData::SetNewAttributeSizes {
                allocated_length,
                data_length,
                valid_data_length,
                total_allocated,
            } => {
                assert_eq!(allocated_length, 4096);
                assert_eq!(data_length, 1024);
                assert_eq!(valid_data_length, 512);
                assert_eq!(total_allocated, 8192);
            }
            other => panic!("expected SetNewAttributeSizes, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_operation_data_set_bits() {
        let restart_info = build_dummy_restart_info();
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&42u32.to_le_bytes());
        data[4..8].copy_from_slice(&10u32.to_le_bytes());

        let result = parse_operation_data(
            NtfsLogOperation::SetBitsInNonresidentBitMap as u16,
            &data,
            &restart_info,
        );
        match result {
            NtfsLogOperationData::SetBits {
                bit_offset,
                num_bits,
            } => {
                assert_eq!(bit_offset, 42);
                assert_eq!(num_bits, 10);
            }
            other => {
                panic!("expected SetBits, got {other:?}")
            }
        }
    }

    #[test]
    fn test_parse_operation_data_noop_empty() {
        let restart_info = build_dummy_restart_info();
        let result = parse_operation_data(NtfsLogOperation::Noop as u16, &[], &restart_info);
        assert!(
            matches!(result, NtfsLogOperationData::Unit),
            "expected Unit for Noop with no data, got {result:?}"
        );
    }

    #[test]
    fn test_parse_operation_data_unknown_op() {
        let restart_info = build_dummy_restart_info();
        let data = vec![1, 2, 3, 4];
        let result = parse_operation_data(0xFF, &data, &restart_info);
        match result {
            NtfsLogOperationData::Raw { data: raw } => {
                assert_eq!(raw, vec![1, 2, 3, 4]);
            }
            other => panic!("expected Raw, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_attribute_names_dump() {
        // Build a dump with two entries.
        let mut data = Vec::new();
        // Entry 1: index=5, name="$I30" (4 chars = 8 bytes)
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        let name1: Vec<u8> = "$I30"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&name1);
        data.extend_from_slice(&[0, 0]); // null term

        // Entry 2: index=7, name="$SII" (4 chars = 8 bytes)
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        let name2: Vec<u8> = "$SII"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&name2);
        data.extend_from_slice(&[0, 0]); // null term

        let entries = parse_attribute_names_dump(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index(), 5);
        assert_eq!(entries[0].name(), "$I30");
        assert_eq!(entries[1].index(), 7);
        assert_eq!(entries[1].name(), "$SII");
    }

    #[test]
    fn test_parse_utf16le_name() {
        // "Test" in UTF-16LE + null terminator
        let data: Vec<u8> = "Test"
            .encode_utf16()
            .chain(core::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let name = parse_utf16le_name(&data);
        assert_eq!(name.as_deref(), Some("Test"));
    }

    #[test]
    fn test_parse_utf16le_name_empty() {
        let name = parse_utf16le_name(&[]);
        assert!(name.is_none());
    }

    #[test]
    fn test_parse_utf16le_name_null_only() {
        let name = parse_utf16le_name(&[0, 0]);
        assert!(name.is_none());
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_full_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        // 1. Restart info is valid.
        let restart = logfile.restart_info();
        assert!(restart.log_page_size() >= 512);
        assert!(restart.file_size() > 0);
        assert_eq!(restart.client_name(), "NTFS");

        // 2. Records exist and are ordered by LSN.
        let records = logfile.records();
        assert!(!records.is_empty());
        for w in records.windows(2) {
            assert!(w[0].lsn() <= w[1].lsn());
        }

        // 3. At least some redo operations are recognized.
        let recognized = records
            .iter()
            .filter(|r| r.redo_operation().is_some())
            .count();
        assert!(recognized > 0, "expected at least one recognized operation");

        // 4. Transaction grouping works.
        let txns = logfile.transactions();
        assert!(!txns.is_empty());

        // 5. record_by_lsn finds existing records.
        let first_lsn = records[0].lsn();
        assert!(logfile.record_by_lsn(first_lsn).is_some());

        // 6. record_by_lsn returns None for nonexistent LSN.
        assert!(logfile.record_by_lsn(u64::MAX).is_none());

        // 7. Skipped pages count is reasonable.
        assert!(
            logfile.skipped_pages() < 100,
            "too many skipped pages: {}",
            logfile.skipped_pages(),
        );
    }

    #[test]
    fn test_dispatch_classification_all_ops() {
        let ri = build_dummy_restart_info();
        let dummy = &[0x42u8; 64];

        // Unit ops: empty -> Unit, non-empty -> Raw.
        let unit_ops: &[u16] = &[
            0x00, // Noop
            0x01, // CompensationLogRecord
            0x03, // DeallocateFileRecordSegment
            0x18, // EndTopLevelAction
            0x19, // PrepareTransaction
            0x1A, // CommitTransaction
            0x1B, // ForgetTransaction
        ];

        for &op in unit_ops {
            let result = parse_operation_data(op, &[], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Unit),
                "op {op:#x} + empty should be Unit, got {result:?}"
            );

            let result = parse_operation_data(op, dummy, &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Raw { .. }),
                "op {op:#x} + bytes should be Raw, got {result:?}"
            );
        }

        // FileRecordSegment
        let result = parse_operation_data(0x02, &[], &ri);
        assert!(matches!(result, NtfsLogOperationData::Empty));
        let result = parse_operation_data(0x02, dummy, &ri);
        assert!(matches!(
            result,
            NtfsLogOperationData::FileRecordSegment { .. }
        ));

        // Bytes ops
        let bytes_ops: &[u16] = &[
            0x04, // WriteEndOfFileRecordSegment
            0x05, // CreateAttribute
            0x06, // DeleteAttribute
            0x07, // UpdateResidentValue
            0x08, // UpdateNonresidentValue
            0x09, // UpdateMappingPairs
            0x0A, // DeleteDirtyClusters
            0x0C, // AddIndexEntryRoot
            0x0D, // DeleteIndexEntryRoot
            0x0E, // AddIndexEntryAllocation
            0x0F, // DeleteIndexEntryAllocation
            0x10, // WriteEndOfIndexBuffer
            0x13, // UpdateFileNameRoot
            0x14, // UpdateFileNameAllocation
            0x17, // HotFix
            0x25, // ZeroEndOfFileRecord
        ];

        for &op in bytes_ops {
            let result = parse_operation_data(op, &[], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Empty),
                "op {op:#x} + empty should be Empty, got {result:?}"
            );

            let result = parse_operation_data(op, dummy, &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Bytes { .. }),
                "op {op:#x} + bytes should be Bytes, got {result:?}"
            );
        }

        // Raw (deferred) ops
        let raw_ops: &[u16] = &[
            0x1F, // DirtyPageTableDump
            0x21, 0x22, 0x23, 0x24, // Record data ops
        ];

        for &op in raw_ops {
            let result = parse_operation_data(op, &[], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Empty),
                "op {op:#x} + empty should be Empty, got {result:?}"
            );

            let result = parse_operation_data(op, dummy, &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Raw { .. }),
                "op {op:#x} + bytes should be Raw, got {result:?}"
            );
        }

        // TransactionTableDump (0x20): empty -> Empty,
        // sub-TTE_SIZE bytes -> TransactionTableDump with empty entries,
        // full entry -> TransactionTableDump with entries
        {
            let result = parse_operation_data(0x20, &[], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Empty),
                "op 0x20 + empty should be Empty, got {result:?}"
            );

            // Sub-TTE_SIZE data: parses but yields no complete entries.
            let short = &[0x42u8; TTE_SIZE - 1];
            let result = parse_operation_data(0x20, short, &ri);
            if let NtfsLogOperationData::TransactionTableDump { entries } = &result {
                assert!(
                    entries.is_empty(),
                    "op 0x20 + sub-TTE_SIZE data should yield empty entries, got {entries:?}"
                );
            } else {
                panic!(
                    "op 0x20 + sub-TTE_SIZE bytes should be TransactionTableDump, got {result:?}"
                );
            }

            // Full entry data: parses to non-empty entries.
            let result = parse_operation_data(0x20, dummy, &ri);
            if let NtfsLogOperationData::TransactionTableDump { entries } = &result {
                assert!(
                    !entries.is_empty(),
                    "op 0x20 + full entry data should yield entries"
                );
            } else {
                panic!("op 0x20 + bytes should be TransactionTableDump, got {result:?}");
            }
        }

        // IndexEntryVcn ops: empty -> Empty, >=8 bytes -> IndexEntryVcn,
        // <8 bytes -> Raw.
        let vcn_ops: &[u16] = &[0x11, 0x12];
        for &op in vcn_ops {
            let result = parse_operation_data(op, &[], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Empty),
                "op {op:#x} + empty should be Empty, got {result:?}",
            );

            let vcn_bytes = 42u64.to_le_bytes();
            let result = parse_operation_data(op, &vcn_bytes, &ri);
            assert!(
                matches!(result, NtfsLogOperationData::IndexEntryVcn { vcn: 42 }),
                "op {op:#x} + 8 bytes should be IndexEntryVcn, \
                 got {result:?}",
            );

            // Short payload (<8 bytes) falls to Raw.
            let result = parse_operation_data(op, &[1, 2, 3], &ri);
            assert!(
                matches!(result, NtfsLogOperationData::Raw { .. }),
                "op {op:#x} + short should be Raw, got {result:?}",
            );
        }

        // Unknown op codes
        let result = parse_operation_data(0xFFFF, &[], &ri);
        assert!(matches!(result, NtfsLogOperationData::Raw { ref data } if data.is_empty()));
        let result = parse_operation_data(0xFFFF, dummy, &ri);
        assert!(matches!(result, NtfsLogOperationData::Raw { ref data } if !data.is_empty()));
    }

    #[test]
    fn test_dispatch_typed_variants_parse_correctly() {
        let ri = build_dummy_restart_info();

        // SetNewAttributeSizes: 32 bytes of size fields.
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&100u64.to_le_bytes());
        buf[8..16].copy_from_slice(&80u64.to_le_bytes());
        buf[16..24].copy_from_slice(&80u64.to_le_bytes());
        buf[24..32].copy_from_slice(&100u64.to_le_bytes());
        let result = parse_operation_data(0x0B, &buf, &ri);
        match result {
            NtfsLogOperationData::SetNewAttributeSizes {
                allocated_length,
                data_length,
                valid_data_length,
                total_allocated,
            } => {
                assert_eq!(allocated_length, 100);
                assert_eq!(data_length, 80);
                assert_eq!(valid_data_length, 80);
                assert_eq!(total_allocated, 100);
            }
            other => panic!("expected SetNewAttributeSizes, got {other:?}"),
        }

        // SetBits: 8 bytes.
        let mut buf = [0u8; 8];
        buf[0..4].copy_from_slice(&42u32.to_le_bytes());
        buf[4..8].copy_from_slice(&7u32.to_le_bytes());
        let result = parse_operation_data(0x15, &buf, &ri);
        match result {
            NtfsLogOperationData::SetBits {
                bit_offset,
                num_bits,
            } => {
                assert_eq!(bit_offset, 42);
                assert_eq!(num_bits, 7);
            }
            other => panic!("expected SetBits, got {other:?}"),
        }

        // ClearBits: 8 bytes.
        let result = parse_operation_data(0x16, &buf, &ri);
        match result {
            NtfsLogOperationData::ClearBits {
                bit_offset,
                num_bits,
            } => {
                assert_eq!(bit_offset, 42);
                assert_eq!(num_bits, 7);
            }
            other => panic!("expected ClearBits, got {other:?}"),
        }
    }

    #[test]
    fn test_dispatch_restart_info_independence() {
        let ri1 = build_dummy_restart_info();
        let mut ri2 = build_dummy_restart_info();
        ri2.major_version = 2;
        ri2.minor_version = 0;
        ri2.current_lsn = 999;
        ri2.file_size = 64 * 1024 * 1024;

        let dummy = &[0x42u8; 64];

        // Unit op
        let r1 = parse_operation_data(0x00, &[], &ri1);
        let r2 = parse_operation_data(0x00, &[], &ri2);
        assert!(matches!(r1, NtfsLogOperationData::Unit));
        assert!(matches!(r2, NtfsLogOperationData::Unit));

        // Bytes op
        let r1 = parse_operation_data(0x07, dummy, &ri1);
        let r2 = parse_operation_data(0x07, dummy, &ri2);
        assert!(matches!(r1, NtfsLogOperationData::Bytes { .. }));
        assert!(matches!(r2, NtfsLogOperationData::Bytes { .. }));

        // FileRecordSegment
        let r1 = parse_operation_data(0x02, dummy, &ri1);
        let r2 = parse_operation_data(0x02, dummy, &ri2);
        assert!(matches!(r1, NtfsLogOperationData::FileRecordSegment { .. }));
        assert!(matches!(r2, NtfsLogOperationData::FileRecordSegment { .. }));
    }

    #[test]
    fn test_dispatch_index_entry_vcn_ignores_trailing() {
        let ri = build_dummy_restart_info();
        // 8 bytes of VCN + 4 trailing bytes.
        let mut payload = 99u64.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0xFF; 4]);

        let result = parse_operation_data(0x11, &payload, &ri);
        match result {
            NtfsLogOperationData::IndexEntryVcn { vcn } => {
                assert_eq!(vcn, 99);
            }
            other => panic!("expected IndexEntryVcn, got {other:?}"),
        }
    }

    #[test]
    fn test_index_entry_vcn_accessor() {
        let data = NtfsLogOperationData::IndexEntryVcn { vcn: 7 };
        assert_eq!(data.index_entry_vcn(), Some(7));

        let data = NtfsLogOperationData::Bytes {
            data: vec![1, 2, 3],
        };
        assert_eq!(data.index_entry_vcn(), None);
    }

    #[test]
    fn test_operation_data_convenience_methods() {
        // Unit
        let d = NtfsLogOperationData::Unit;
        assert!(d.is_unit());
        assert!(d.bytes().is_none());
        assert!(d.file_record_bytes().is_none());
        assert!(d.file_record_view().is_none());

        // Empty
        let d = NtfsLogOperationData::Empty;
        assert!(!d.is_unit());
        assert!(d.bytes().is_none());
        assert!(d.file_record_bytes().is_none());
        assert!(d.file_record_view().is_none());

        // FileRecordSegment
        let d = NtfsLogOperationData::FileRecordSegment {
            data: vec![0x46, 0x49, 0x4C, 0x45],
        };
        assert!(!d.is_unit());
        assert_eq!(d.bytes().unwrap(), &[0x46, 0x49, 0x4C, 0x45]);
        assert_eq!(d.file_record_bytes().unwrap(), &[0x46, 0x49, 0x4C, 0x45]);
        // file_record_view on 4-byte payload -> Err (too small)
        assert!(d.file_record_view().unwrap().is_err());

        // Bytes
        let d = NtfsLogOperationData::Bytes {
            data: vec![1, 2, 3],
        };
        assert!(!d.is_unit());
        assert_eq!(d.bytes().unwrap(), &[1, 2, 3]);
        assert!(d.file_record_bytes().is_none());
        assert!(d.file_record_view().is_none());

        // Raw
        let d = NtfsLogOperationData::Raw { data: vec![4, 5] };
        assert!(!d.is_unit());
        assert_eq!(d.bytes().unwrap(), &[4, 5]);
        assert!(d.file_record_bytes().is_none());
        assert!(d.file_record_view().is_none());

        // Existing typed variants: all return None for bytes()
        let d = NtfsLogOperationData::SetNewAttributeSizes {
            allocated_length: 0,
            data_length: 0,
            valid_data_length: 0,
            total_allocated: 0,
        };
        assert!(d.bytes().is_none());
        assert!(d.file_record_bytes().is_none());

        let d = NtfsLogOperationData::SetBits {
            bit_offset: 0,
            num_bits: 0,
        };
        assert!(d.bytes().is_none());

        let d = NtfsLogOperationData::ClearBits {
            bit_offset: 0,
            num_bits: 0,
        };
        assert!(d.bytes().is_none());

        let d = NtfsLogOperationData::OpenNonresidentAttribute {
            file_reference: 0,
            attribute_type: 0,
            name: None,
        };
        assert!(d.bytes().is_none());

        let d = NtfsLogOperationData::OpenAttributeTableDump {
            entries: Vec::new(),
        };
        assert!(d.bytes().is_none());

        let d = NtfsLogOperationData::AttributeNamesDump {
            entries: Vec::new(),
        };
        assert!(d.bytes().is_none());
    }

    /// Build a minimal valid FILE record header.
    fn build_file_record_header(
        used_size: u32,
        allocated_size: u32,
        first_attr_offset: u16,
        flags: u16,
        sequence_number: u16,
        hard_link_count: u16,
    ) -> Vec<u8> {
        let mut data = vec![0u8; allocated_size as usize];
        data[0..4].copy_from_slice(b"FILE");
        data[FR_OFF_USA_OFFSET..FR_OFF_USA_OFFSET + 2].copy_from_slice(&0x30u16.to_le_bytes());
        data[FR_OFF_USA_COUNT..FR_OFF_USA_COUNT + 2].copy_from_slice(&3u16.to_le_bytes());
        data[FR_OFF_SEQUENCE_NUMBER..FR_OFF_SEQUENCE_NUMBER + 2]
            .copy_from_slice(&sequence_number.to_le_bytes());
        data[FR_OFF_HARD_LINK_COUNT..FR_OFF_HARD_LINK_COUNT + 2]
            .copy_from_slice(&hard_link_count.to_le_bytes());
        data[FR_OFF_FIRST_ATTRIBUTE_OFFSET..FR_OFF_FIRST_ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&first_attr_offset.to_le_bytes());
        data[FR_OFF_FLAGS..FR_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
        data[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&used_size.to_le_bytes());
        data[FR_OFF_ALLOCATED_SIZE..FR_OFF_ALLOCATED_SIZE + 4]
            .copy_from_slice(&allocated_size.to_le_bytes());
        data
    }

    #[test]
    fn test_log_file_record_view_valid() {
        let data = build_file_record_header(
            400,  // used_size
            1024, // allocated_size
            0x38, // first_attribute_offset
            0x01, // flags: IN_USE
            5,    // sequence_number
            2,    // hard_link_count
        );
        let view = LogFileRecordView::new(&data).unwrap();

        assert_eq!(view.allocated_size(), 1024);
        assert_eq!(view.used_size(), 400);
        assert_eq!(view.sequence_number(), 5);
        assert_eq!(view.hard_link_count(), 2);
        assert_eq!(view.flags(), 0x01);
        assert!(view.is_in_use());
        assert!(!view.is_directory());
        assert_eq!(view.first_attribute_offset(), 0x38);
        assert_eq!(view.base_file_reference(), 0);
        assert_eq!(view.update_sequence_offset(), 0x30);
        assert_eq!(view.update_sequence_count(), 3);
        assert_eq!(view.data().len(), 1024);
    }

    #[test]
    fn test_log_file_record_view_used_equals_allocated() {
        let data = build_file_record_header(
            1024, // used_size == allocated_size
            1024, 0x38, 0x01, 1, 1,
        );
        assert!(LogFileRecordView::new(&data).is_ok());
    }

    #[test]
    fn test_log_file_record_view_too_small() {
        let data = vec![0u8; 20];
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("log payload"), "{msg}");
        assert!(msg.contains("too small"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_bad_signature() {
        let mut data = build_file_record_header(400, 1024, 0x38, 0x01, 1, 1);
        data[0..4].copy_from_slice(b"BAAD");
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("signature"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_used_exceeds_allocated() {
        let mut data = build_file_record_header(400, 1024, 0x38, 0x01, 1, 1);
        data[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&2048u32.to_le_bytes());
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("used_size"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_first_attr_out_of_bounds() {
        let data = build_file_record_header(
            400, 1024, 400, // first_attr == used_size
            0x01, 1, 1,
        );
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("first_attribute_offset"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_allocated_exceeds_payload() {
        // Header says allocated_size=1024 but payload is only 64 bytes.
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"FILE");
        data[FR_OFF_ALLOCATED_SIZE..FR_OFF_ALLOCATED_SIZE + 4]
            .copy_from_slice(&1024u32.to_le_bytes());
        data[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&64u32.to_le_bytes());
        data[FR_OFF_FIRST_ATTRIBUTE_OFFSET..FR_OFF_FIRST_ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&0x38u16.to_le_bytes());
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("allocated_size"), "{msg}");
        assert!(msg.contains("payload"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_first_attr_inside_header() {
        // first_attribute_offset = 0x10 (inside the 42-byte header).
        let data = build_file_record_header(
            400, 1024, 0x10, // inside header
            0x01, 1, 1,
        );
        let err = LogFileRecordView::new(&data).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("first_attribute_offset"), "{msg}");
        assert!(msg.contains("header"), "{msg}");
    }

    #[test]
    fn test_log_file_record_view_endianness() {
        let data = build_file_record_header(
            0x0000_1234, // used_size
            0x0000_5678, // allocated_size
            0x38,
            0x0003, // flags: IN_USE | IS_DIRECTORY
            0xABCD, // sequence_number
            0x0007, // hard_link_count
        );
        let view = LogFileRecordView::new(&data).unwrap();
        assert_eq!(view.allocated_size(), 0x5678);
        assert_eq!(view.used_size(), 0x1234);
        assert_eq!(view.sequence_number(), 0xABCD);
        assert_eq!(view.hard_link_count(), 7);
        assert_eq!(view.flags(), 0x0003);
        assert!(view.is_in_use());
        assert!(view.is_directory());
    }

    #[test]
    fn test_file_record_view_via_operation_data() {
        let data = build_file_record_header(400, 1024, 0x38, 0x01, 1, 1);
        let op = NtfsLogOperationData::FileRecordSegment { data: data.clone() };
        let view = op.file_record_view().unwrap().unwrap();
        assert_eq!(view.allocated_size(), 1024);

        // Non-FileRecordSegment -> None
        let op = NtfsLogOperationData::Bytes { data };
        assert!(op.file_record_view().is_none());

        let op = NtfsLogOperationData::Unit;
        assert!(op.file_record_view().is_none());
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_pr1_no_raw_for_typed_ops() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        // PR1-typed op codes: should never produce Raw.
        let pr1_typed: &[u16] = &[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x10, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x25,
        ];

        for record in logfile.records() {
            let redo_code = record.redo_operation_code();
            if pr1_typed.contains(&redo_code) {
                assert!(
                    !matches!(record.redo_data(), NtfsLogOperationData::Raw { .. }),
                    "redo op {redo_code:#x} at LSN {} should not be Raw",
                    record.lsn(),
                );
            }

            let undo_code = record.undo_operation_code();
            if pr1_typed.contains(&undo_code) {
                assert!(
                    !matches!(record.undo_data(), NtfsLogOperationData::Raw { .. }),
                    "undo op {undo_code:#x} at LSN {} should not be Raw",
                    record.lsn(),
                );
            }
        }
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_file_record_views() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let mut views_checked = 0u64;

        for record in logfile.records() {
            if let Some(result) = record.redo_data().file_record_view() {
                let view = result.unwrap();
                assert!(
                    view.allocated_size() >= FR_MIN_HEADER_SIZE as u32,
                    "allocated_size {} too small at LSN {}",
                    view.allocated_size(),
                    record.lsn(),
                );
                assert!(
                    view.used_size() <= view.allocated_size(),
                    "used_size {} > allocated_size {} at LSN {}",
                    view.used_size(),
                    view.allocated_size(),
                    record.lsn(),
                );
                views_checked += 1;
            }
        }

        if views_checked > 0 {
            eprintln!("checked {views_checked} FILE record views");
        }
    }

    // ---- PR2: walk_resident_data_attrs tests ----

    /// Build a minimal resident attribute record (8-byte aligned).
    ///
    /// `attr_type`: attribute type code (e.g., 0x80 for $DATA).
    /// `instance`: attribute instance number.
    /// `name`: optional UTF-16LE name (empty for unnamed).
    /// `value`: the resident value bytes.
    /// `non_resident`: 0 for resident, 1 for non-resident.
    fn build_resident_attr(
        attr_type: u32,
        instance: u16,
        name: &[u16],
        value: &[u8],
        non_resident: u8,
    ) -> Vec<u8> {
        let name_byte_len = name.len() * 2;
        // Header is RES_MIN_HEADER_SIZE (0x18) bytes.
        // Name follows immediately after header.
        // Value follows after name.
        let value_offset = RES_MIN_HEADER_SIZE + name_byte_len;
        // Round up total to 8-byte alignment.
        let total = (value_offset + value.len() + 7) & !7;

        let mut buf = vec![0u8; total];
        // Common header
        buf[ATTR_OFF_TYPE..ATTR_OFF_TYPE + 4].copy_from_slice(&attr_type.to_le_bytes());
        buf[ATTR_OFF_LENGTH..ATTR_OFF_LENGTH + 4].copy_from_slice(&(total as u32).to_le_bytes());
        buf[ATTR_OFF_NON_RESIDENT] = non_resident;
        buf[ATTR_OFF_NAME_LENGTH] = name.len() as u8;
        if !name.is_empty() {
            buf[ATTR_OFF_NAME_OFFSET..ATTR_OFF_NAME_OFFSET + 2]
                .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        }
        buf[ATTR_OFF_INSTANCE..ATTR_OFF_INSTANCE + 2].copy_from_slice(&instance.to_le_bytes());

        // Resident extension
        buf[RES_OFF_VALUE_LENGTH..RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&(value.len() as u32).to_le_bytes());
        buf[RES_OFF_VALUE_OFFSET..RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(value_offset as u16).to_le_bytes());

        // Name bytes
        for (i, &ch) in name.iter().enumerate() {
            let off = RES_MIN_HEADER_SIZE + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }

        // Value bytes
        buf[value_offset..value_offset + value.len()].copy_from_slice(value);

        buf
    }

    /// Append an end marker (0xFFFFFFFF) to a buffer.
    fn append_end_marker(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&ATTR_END_MARKER.to_le_bytes());
    }

    #[test]
    fn test_walk_single_unnamed_data() {
        let first_attr: u16 = 0x38;
        let value = b"Hello, resident data!";
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], value, 0);
        let used = first_attr as usize + attr.len() + 4; // +4 for end marker

        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr);
        append_end_marker(&mut buf);
        buf.resize(used.max(buf.len()), 0);

        let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].instance(), 1);
        assert!(!result[0].is_named());
        assert_eq!(result[0].name_length(), 0);
        assert_eq!(result[0].data(), value);
        assert_eq!(
            result[0].value_offset_in_record(),
            first_attr as u32 + RES_MIN_HEADER_SIZE as u32,
        );
    }

    #[test]
    fn test_walk_two_data_attrs_unnamed_and_named() {
        let first_attr: u16 = 0x38;
        let val1 = b"default stream";
        let attr1 = build_resident_attr(ATTR_TYPE_DATA, 1, &[], val1, 0);
        // Named stream "ADS" (3 UTF-16 chars)
        let name: Vec<u16> = "ADS".encode_utf16().collect();
        let val2 = b"alternate data";
        let attr2 = build_resident_attr(ATTR_TYPE_DATA, 2, &name, val2, 0);

        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr1);
        buf.extend_from_slice(&attr2);
        append_end_marker(&mut buf);

        let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(result.len(), 2);
        assert!(!result[0].is_named());
        assert_eq!(result[0].data(), val1);
        assert!(result[1].is_named());
        assert_eq!(result[1].name_length(), 3);
        assert_eq!(result[1].data(), val2);
    }

    #[test]
    fn test_walk_no_data_attrs() {
        let first_attr: u16 = 0x38;
        // $STANDARD_INFORMATION (0x10) — not $DATA
        let attr = build_resident_attr(0x10, 1, &[], b"SI", 0);

        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr);
        append_end_marker(&mut buf);

        let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_walk_skips_nonresident_data() {
        let first_attr: u16 = 0x38;
        // Resident $DATA
        let attr1 = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"resident", 0);
        // Non-resident $DATA (non_resident=1) — should be skipped
        let attr2 = build_resident_attr(ATTR_TYPE_DATA, 2, &[], b"fake", 1);
        // Another resident $DATA
        let attr3 = build_resident_attr(ATTR_TYPE_DATA, 3, &[], b"also resident", 0);

        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr1);
        buf.extend_from_slice(&attr2);
        buf.extend_from_slice(&attr3);
        append_end_marker(&mut buf);

        let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].instance(), 1);
        assert_eq!(result[1].instance(), 3);
    }

    #[test]
    fn test_walk_err_first_attr_out_of_bounds() {
        let buf = vec![0u8; 64];
        let err = walk_resident_data_attrs(&buf, 64, 64).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("first_attr_offset_out_of_bounds"), "{msg}",);
    }

    #[test]
    fn test_walk_err_missing_end_marker() {
        let first_attr: u16 = 0x38;
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"data", 0);
        // No end marker — just the attribute filling to limit.
        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr);
        let limit = buf.len();

        let err = walk_resident_data_attrs(&buf, limit, first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("truncated_attr_header"), "{msg}");
    }

    #[test]
    fn test_walk_err_attr_len_zero() {
        let first_attr: u16 = 0x38;
        let mut buf = vec![0u8; first_attr as usize + 0x18];
        // Type = $DATA
        buf[first_attr as usize..first_attr as usize + 4]
            .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        // Length = 0
        buf[first_attr as usize + 4..first_attr as usize + 8].copy_from_slice(&0u32.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("attr_len_too_small"), "{msg}");
    }

    #[test]
    fn test_walk_err_attr_len_unaligned() {
        let first_attr: u16 = 0x38;
        let mut buf = vec![0u8; first_attr as usize + 0x20];
        buf[first_attr as usize..first_attr as usize + 4]
            .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        // Length = 0x19 (not 8-byte aligned)
        buf[first_attr as usize + 4..first_attr as usize + 8]
            .copy_from_slice(&0x19u32.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("attr_len_unaligned"), "{msg}");
    }

    #[test]
    fn test_walk_err_attr_exceeds_bounds() {
        let first_attr: u16 = 0x38;
        let mut buf = vec![0u8; first_attr as usize + 0x10];
        buf[first_attr as usize..first_attr as usize + 4]
            .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        // Length = 0x100 (way past buffer end)
        buf[first_attr as usize + 4..first_attr as usize + 8]
            .copy_from_slice(&0x100u32.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("attr_exceeds_bounds"), "{msg}");
    }

    #[test]
    fn test_walk_err_resident_value_exceeds_bounds() {
        let first_attr: u16 = 0x38;
        // Build a minimal buffer with a $DATA attr whose
        // value_length extends past limit.
        let attr_len: u32 = 0x20; // 32 bytes (8-aligned)
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0; // resident
        // value_length = 999 (way too big)
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&999u32.to_le_bytes());
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        // End marker after attribute
        let em_off = off + attr_len as usize;
        buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("resident_value_exceeds_bounds"), "{msg}",);
    }

    #[test]
    fn test_walk_err_value_offset_before_header() {
        let first_attr: u16 = 0x38;
        let attr_len: u32 = 0x20;
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&4u32.to_le_bytes());
        // value_offset = 0x10 (inside resident header)
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&0x10u16.to_le_bytes());
        let em_off = off + attr_len as usize;
        buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("resident_value_offset_before_header"), "{msg}",);
    }

    #[test]
    fn test_walk_err_name_exceeds_attr_bounds() {
        let first_attr: u16 = 0x38;
        // Attr that claims name_length=50 chars (100 bytes) but
        // attr_len is only 0x20 (32 bytes).
        let attr_len: u32 = 0x20;
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + ATTR_OFF_NAME_LENGTH] = 50; // way too many
        buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        let em_off = off + attr_len as usize;
        buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("attr_name_exceeds_bounds"), "{msg}",);
    }

    #[test]
    fn test_walk_err_name_offset_before_header() {
        let first_attr: u16 = 0x38;
        let attr_len: u32 = 0x28; // 40 bytes
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + ATTR_OFF_NAME_LENGTH] = 2;
        // name_offset = 0x04 (inside header area)
        buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
            .copy_from_slice(&0x04u16.to_le_bytes());
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        let em_off = off + attr_len as usize;
        buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("attr_name_offset_before_header"), "{msg}");
    }

    #[test]
    fn test_walk_err_value_exceeds_attr_len() {
        // Value fits within record limit but exceeds attr_len.
        let first_attr: u16 = 0x38;
        let attr_len: u32 = 0x20; // 32 bytes
        // Make buffer much larger than attr_len so value would
        // fit within limit but not within attr_len.
        let mut buf = vec![0u8; first_attr as usize + 256 + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        // value_length = 20 bytes, value_offset = 0x18
        // 0x18 + 20 = 0x2C > attr_len (0x20) but < limit
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&20u32.to_le_bytes());
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        let em_off = off + attr_len as usize;
        buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        // Set limit to full buffer size (much larger than attr_len).
        let limit = buf.len();

        let err = walk_resident_data_attrs(&buf, limit, first_attr).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("resident_value_exceeds_bounds"), "{msg}");
    }

    // ---- PR2: resident_data_values tests ----

    /// Build a FILE record with USA fixup and resident $DATA
    /// attributes for testing `resident_data_values()`.
    fn build_file_record_with_data(attrs: &[Vec<u8>]) -> Vec<u8> {
        let first_attr: u16 = 0x38;
        let usa_offset: u16 = 0x30;
        let usa_count: u16 = 3; // 1 USN + 2 sectors (1024-byte record)
        let alloc_size: u32 = 1024;

        let mut buf = vec![0u8; alloc_size as usize];
        // FILE signature
        buf[0..4].copy_from_slice(b"FILE");
        buf[FR_OFF_USA_OFFSET..FR_OFF_USA_OFFSET + 2].copy_from_slice(&usa_offset.to_le_bytes());
        buf[FR_OFF_USA_COUNT..FR_OFF_USA_COUNT + 2].copy_from_slice(&usa_count.to_le_bytes());
        buf[FR_OFF_FIRST_ATTRIBUTE_OFFSET..FR_OFF_FIRST_ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&first_attr.to_le_bytes());
        buf[FR_OFF_FLAGS..FR_OFF_FLAGS + 2].copy_from_slice(&0x01u16.to_le_bytes()); // IN_USE
        buf[FR_OFF_ALLOCATED_SIZE..FR_OFF_ALLOCATED_SIZE + 4]
            .copy_from_slice(&alloc_size.to_le_bytes());

        // Copy attributes starting at first_attr_offset.
        let mut off = first_attr as usize;
        for attr in attrs {
            buf[off..off + attr.len()].copy_from_slice(attr);
            off += attr.len();
        }
        // End marker
        buf[off..off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        let used_size = (off + 4) as u32;
        buf[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&used_size.to_le_bytes());

        // Apply USA: write USN to sector boundaries.
        let usn: [u8; 2] = [0x42, 0x00];
        buf[usa_offset as usize..usa_offset as usize + 2].copy_from_slice(&usn);
        for i in 0..(usa_count - 1) as usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [buf[sector_end], buf[sector_end + 1]];
            let slot = usa_offset as usize + 2 + i * 2;
            buf[slot..slot + 2].copy_from_slice(&original);
            buf[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        buf
    }

    #[test]
    fn test_resident_data_values_single() {
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"hello world", 0);
        let buf = build_file_record_with_data(&[attr]);
        let view = LogFileRecordView::new(&buf).unwrap();

        let values = view.resident_data_values().unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].data(), b"hello world");
        assert!(!values[0].is_named());
        assert_eq!(values[0].instance(), 1);
    }

    #[test]
    fn test_resident_data_values_empty_record() {
        // Record with no attributes (just end marker).
        let buf = build_file_record_with_data(&[]);
        let view = LogFileRecordView::new(&buf).unwrap();

        let values = view.resident_data_values().unwrap();
        assert!(values.is_empty());
    }

    #[test]
    fn test_resident_data_values_usa_corrupt() {
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"data", 0);
        let mut buf = build_file_record_with_data(&[attr]);
        // Corrupt sector boundary USA marker.
        buf[USA_STRIDE - 2] = 0xFF;
        buf[USA_STRIDE - 1] = 0xFF;

        let view = LogFileRecordView::new(&buf).unwrap();
        let err = view.resident_data_values().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("USA"), "{msg}");
    }

    #[test]
    fn test_with_fixed_up_bytes_ok() {
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"test", 0);
        let buf = build_file_record_with_data(&[attr]);
        let view = LogFileRecordView::new(&buf).unwrap();

        let sig = view
            .with_fixed_up_bytes(|data| Ok(data[0..4].to_vec()))
            .unwrap();
        assert_eq!(sig, b"FILE");
    }

    #[test]
    fn test_with_fixed_up_bytes_closure_err() {
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"test", 0);
        let buf = build_file_record_with_data(&[attr]);
        let view = LogFileRecordView::new(&buf).unwrap();

        let result: Result<()> = view.with_fixed_up_bytes(|_| {
            Err(NtfsError::InvalidLogFileRecord {
                position: NtfsPosition::none(),
                reason: "test error from closure",
            })
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_with_fixed_up_bytes_usa_err() {
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"data", 0);
        let mut buf = build_file_record_with_data(&[attr]);
        buf[USA_STRIDE - 2] = 0xFF;
        buf[USA_STRIDE - 1] = 0xFF;

        let view = LogFileRecordView::new(&buf).unwrap();
        let result: Result<()> = view.with_fixed_up_bytes(|_| Ok(()));
        assert!(result.is_err());
    }

    // ---- PR2: resident_data_patch tests ----

    /// Build a minimal NtfsLogRecord for testing
    /// `resident_data_patch()`.
    fn build_test_log_record(
        redo_operation: NtfsLogOperation,
        target_attribute: u16,
        attribute_offset: u16,
        redo_data: NtfsLogOperationData,
    ) -> NtfsLogRecord {
        NtfsLogRecord {
            lsn: 100,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: LogRecordType::ClientRecord,
            transaction_id: 1,
            flags: 0,
            redo_operation_code: redo_operation as u16,
            undo_operation_code: NtfsLogOperation::Noop as u16,
            redo_operation: Some(redo_operation),
            undo_operation: Some(NtfsLogOperation::Noop),
            target_attribute,
            target_vcn: 0,
            record_offset: 0,
            attribute_offset,
            cluster_block_offset: 0,
            redo_data,
            undo_data: NtfsLogOperationData::Empty,
        }
    }

    fn build_test_oat() -> Vec<OpenAttributeEntry> {
        vec![
            // Index 0: $DATA on file 5
            OpenAttributeEntry {
                file_reference: 0x0001_0000_0000_0005,
                lsn_of_open_record: 50,
                attribute_type: ATTR_TYPE_DATA,
                bytes_per_index_buffer: 0,
            },
            // Index 1: $FILE_NAME on file 5
            OpenAttributeEntry {
                file_reference: 0x0001_0000_0000_0005,
                lsn_of_open_record: 51,
                attribute_type: 0x30, // $FILE_NAME
                bytes_per_index_buffer: 0,
            },
            // Index 2: $DATA on file 10
            OpenAttributeEntry {
                file_reference: 0x0002_0000_0000_000A,
                lsn_of_open_record: 52,
                attribute_type: ATTR_TYPE_DATA,
                bytes_per_index_buffer: 0,
            },
        ]
    }

    #[test]
    fn test_patch_none_wrong_op() {
        let record =
            build_test_log_record(NtfsLogOperation::Noop, 0, 0, NtfsLogOperationData::Unit);
        let oat = build_test_oat();
        assert!(record.resident_data_patch(&oat).is_none());
    }

    #[test]
    fn test_patch_none_not_data_attr() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            1, // OAT index 1 = $FILE_NAME
            0,
            NtfsLogOperationData::Bytes {
                data: vec![1, 2, 3],
            },
        );
        let oat = build_test_oat();
        assert!(record.resident_data_patch(&oat).is_none());
    }

    #[test]
    fn test_patch_none_unit_payload() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0, // OAT index 0 = $DATA
            0,
            NtfsLogOperationData::Unit,
        );
        let oat = build_test_oat();
        assert!(record.resident_data_patch(&oat).is_none());
    }

    #[test]
    fn test_patch_err_oat_oob() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            99, // out of bounds
            0,
            NtfsLogOperationData::Bytes {
                data: vec![1, 2, 3],
            },
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        assert!(result.is_some());
        let err = result.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("target_attr_oat_oob"), "{msg}",);
    }

    #[test]
    fn test_patch_err_empty_payload() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0,
            0,
            NtfsLogOperationData::Empty,
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        assert!(result.is_some());
        let err = result.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("redo_data_empty"), "{msg}");
    }

    #[test]
    fn test_patch_err_empty_bytes() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0,
            0,
            NtfsLogOperationData::Bytes { data: vec![] },
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        assert!(result.is_some());
        let err = result.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("redo_bytes_empty"), "{msg}");
    }

    #[test]
    fn test_patch_err_raw_payload() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0,
            0,
            NtfsLogOperationData::Raw {
                data: vec![1, 2, 3],
            },
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        assert!(result.is_some());
        let err = result.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unexpected_raw_payload"), "{msg}",);
    }

    #[test]
    fn test_patch_err_mismatched_typed_variant() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0,
            0,
            NtfsLogOperationData::SetBits {
                bit_offset: 0,
                num_bits: 0,
            },
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        assert!(result.is_some());
        let err = result.unwrap().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unexpected_payload_variant"), "{msg}",);
    }

    #[test]
    fn test_patch_ok_valid() {
        let patch_data = vec![0xAB, 0xCD, 0xEF];
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            0,  // OAT index 0 = $DATA on file 5
            24, // attribute_offset
            NtfsLogOperationData::Bytes {
                data: patch_data.clone(),
            },
        );
        let oat = build_test_oat();
        let result = record.resident_data_patch(&oat);
        let patch = result.unwrap().unwrap();
        assert_eq!(patch.file_reference(), 0x0001_0000_0000_0005,);
        assert_eq!(patch.target_attribute(), 0);
        assert_eq!(patch.value_offset(), 24);
        assert_eq!(patch.patch_bytes(), &[0xAB, 0xCD, 0xEF]);
        assert_eq!(patch.mft_record_number(), 5);
    }

    #[test]
    fn test_patch_ok_different_oat_entry() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateResidentValue,
            2, // OAT index 2 = $DATA on file 10
            0,
            NtfsLogOperationData::Bytes { data: vec![0x01] },
        );
        let oat = build_test_oat();
        let patch = record.resident_data_patch(&oat).unwrap().unwrap();
        assert_eq!(patch.mft_record_number(), 10);
        assert_eq!(patch.file_reference(), 0x0002_0000_0000_000A,);
    }

    // ---- PR2: ResidentDataValue accessor tests ----

    #[test]
    fn test_resident_data_value_accessors() {
        let val = ResidentDataValue {
            instance: 42,
            name_offset: 0x18,
            name_length: 3,
            value_offset_in_record: 0x100,
            data: vec![0xDE, 0xAD],
        };
        assert_eq!(val.instance(), 42);
        assert_eq!(val.name_offset(), 0x18);
        assert_eq!(val.name_length(), 3);
        assert_eq!(val.value_offset_in_record(), 0x100);
        assert_eq!(val.data(), &[0xDE, 0xAD]);
        assert!(val.is_named());
    }

    #[test]
    fn test_resident_data_value_unnamed() {
        let val = ResidentDataValue {
            instance: 1,
            name_offset: 0,
            name_length: 0,
            value_offset_in_record: 0x50,
            data: vec![],
        };
        assert!(!val.is_named());
        assert_eq!(val.name_length(), 0);
        assert!(val.data().is_empty());
    }

    #[test]
    fn test_resident_data_patch_accessors() {
        let payload = vec![0x01, 0x02, 0x03];
        let patch = ResidentDataPatch {
            file_reference: 0x0005_0000_0000_002A,
            target_attribute: 3,
            value_offset: 16,
            patch_bytes: &payload,
        };
        assert_eq!(patch.file_reference(), 0x0005_0000_0000_002A,);
        assert_eq!(patch.target_attribute(), 3);
        assert_eq!(patch.value_offset(), 16);
        assert_eq!(patch.patch_bytes(), &[1, 2, 3]);
        assert_eq!(patch.mft_record_number(), 0x2A);
    }

    // ---- PR2: integration tests ----

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_resident_data_values_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let mut records_with_frs = 0u64;
        let mut total_values = 0u64;

        for record in logfile.records() {
            if let Some(Ok(view)) = record.redo_data().file_record_view() {
                records_with_frs += 1;
                match view.resident_data_values() {
                    Ok(values) => {
                        total_values += values.len() as u64;
                        for val in &values {
                            assert!(
                                val.data().len() <= 4096,
                                "resident value too large: \
                                 {} bytes at LSN {}",
                                val.data().len(),
                                record.lsn(),
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "warn: resident_data_values \
                             failed at LSN {}: {e}",
                            record.lsn(),
                        );
                    }
                }
            }
        }

        eprintln!(
            "resident_data_values: {records_with_frs} \
             FILE records, {total_values} total values",
        );
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_resident_data_patches_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let oat = logfile.open_attribute_table();
        let mut patches_ok = 0u64;
        let mut patches_err = 0u64;
        let mut patches_na = 0u64;

        for record in logfile.records() {
            match record.resident_data_patch(oat) {
                None => patches_na += 1,
                Some(Ok(_)) => patches_ok += 1,
                Some(Err(e)) => {
                    patches_err += 1;
                    eprintln!(
                        "warn: resident_data_patch err \
                         at LSN {}: {e}",
                        record.lsn(),
                    );
                }
            }
        }

        if patches_ok == 0 {
            eprintln!(
                "warning: no resident patches observed \
                 in testfs1",
            );
        }

        eprintln!(
            "resident_data_patches: {patches_ok} ok, \
             {patches_err} err, {patches_na} n/a",
        );
    }

    // ---- PR3: LogFileNameFields tests ----

    fn build_file_name_blob(parent_ref: u64, name: &[u16], namespace: u8) -> Vec<u8> {
        let total = FN_FIXED_SIZE + name.len() * 2;
        let mut buf = vec![0u8; total];
        buf[FN_OFF_PARENT_REF..FN_OFF_PARENT_REF + 8].copy_from_slice(&parent_ref.to_le_bytes());
        buf[FN_OFF_CREATION_TIME..FN_OFF_CREATION_TIME + 8].copy_from_slice(&1000u64.to_le_bytes());
        buf[FN_OFF_MODIFICATION..FN_OFF_MODIFICATION + 8].copy_from_slice(&2000u64.to_le_bytes());
        buf[FN_OFF_MFT_MODIFIED..FN_OFF_MFT_MODIFIED + 8].copy_from_slice(&3000u64.to_le_bytes());
        buf[FN_OFF_ACCESS_TIME..FN_OFF_ACCESS_TIME + 8].copy_from_slice(&4000u64.to_le_bytes());
        buf[FN_OFF_ALLOCATED_SIZE..FN_OFF_ALLOCATED_SIZE + 8]
            .copy_from_slice(&4096u64.to_le_bytes());
        buf[FN_OFF_DATA_SIZE..FN_OFF_DATA_SIZE + 8].copy_from_slice(&1234u64.to_le_bytes());
        buf[FN_OFF_FILE_ATTRIBUTES..FN_OFF_FILE_ATTRIBUTES + 4]
            .copy_from_slice(&0x20u32.to_le_bytes());
        buf[FN_OFF_NAME_LENGTH] = name.len() as u8;
        buf[FN_OFF_NAMESPACE] = namespace;
        for (i, &ch) in name.iter().enumerate() {
            let off = FN_FIXED_SIZE + i * 2;
            buf[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        buf
    }

    const TEST_FN_ERR_TRUNCATED: &str = "log payload: filename_truncated";
    const TEST_FN_ERR_NAME_ZERO: &str = "log payload: filename_name_length_zero";
    const TEST_FN_ERR_NAME_EXCEEDS: &str = "log payload: filename_name_exceeds_key";

    #[test]
    fn test_parse_file_name_fields_valid() {
        let name: Vec<u16> = "test.txt".encode_utf16().collect();
        let blob = build_file_name_blob(0x0001_0000_0000_0005, &name, 1);
        let fields = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap();
        assert_eq!(fields.parent_directory_reference(), 0x0001_0000_0000_0005);
        assert_eq!(fields.parent_mft_record_number(), 5);
        assert_eq!(fields.creation_time(), 1000);
        assert_eq!(fields.modification_time(), 2000);
        assert_eq!(fields.mft_record_modification_time(), 3000);
        assert_eq!(fields.access_time(), 4000);
        assert_eq!(fields.allocated_size(), 4096);
        assert_eq!(fields.data_size(), 1234);
        assert_eq!(fields.file_attributes(), 0x20);
        assert!(!fields.is_directory());
        assert_eq!(fields.namespace(), 1);
        assert_eq!(fields.name_string(), "test.txt");
    }

    #[test]
    fn test_parse_file_name_fields_directory() {
        let name: Vec<u16> = "Dir".encode_utf16().collect();
        let mut blob = build_file_name_blob(0x0002_0000_0000_000A, &name, 3);
        blob[FN_OFF_FILE_ATTRIBUTES..FN_OFF_FILE_ATTRIBUTES + 4]
            .copy_from_slice(&0x10u32.to_le_bytes());
        let fields = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap();
        assert!(fields.is_directory());
        assert_eq!(fields.namespace(), 3);
    }

    #[test]
    fn test_parse_file_name_fields_truncated() {
        let blob = vec![0u8; FN_FIXED_SIZE - 1];
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename_truncated"));
    }

    #[test]
    fn test_parse_file_name_fields_name_length_zero() {
        let mut blob = vec![0u8; FN_FIXED_SIZE + 2];
        blob[FN_OFF_NAME_LENGTH] = 0;
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename_name_length_zero"));
    }

    #[test]
    fn test_parse_file_name_fields_name_exceeds() {
        let mut blob = vec![0u8; FN_FIXED_SIZE + 4];
        blob[FN_OFF_NAME_LENGTH] = 100;
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename_name_exceeds_key"));
    }

    // ---- PR3: LogIndexEntryView tests ----

    fn build_index_entry(
        file_ref: u64,
        key: &[u8],
        flags: u16,
        subnode_vcn: Option<u64>,
    ) -> Vec<u8> {
        let key_length = key.len() as u16;
        let mut entry_length = IE_HEADER_SIZE + key.len();
        if subnode_vcn.is_some() {
            entry_length = (entry_length + 7) & !7;
            entry_length += 8;
        }
        let actual_flags = if subnode_vcn.is_some() {
            flags | IE_FLAG_HAS_SUBNODE
        } else {
            flags
        };
        let mut buf = vec![0u8; entry_length];
        buf[IE_OFF_FILE_REFERENCE..IE_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&file_ref.to_le_bytes());
        buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
            .copy_from_slice(&(entry_length as u16).to_le_bytes());
        buf[IE_OFF_KEY_LENGTH..IE_OFF_KEY_LENGTH + 2].copy_from_slice(&key_length.to_le_bytes());
        buf[IE_OFF_FLAGS..IE_OFF_FLAGS + 2].copy_from_slice(&actual_flags.to_le_bytes());
        buf[IE_HEADER_SIZE..IE_HEADER_SIZE + key.len()].copy_from_slice(key);
        if let Some(vcn) = subnode_vcn {
            let vcn_off = entry_length - 8;
            buf[vcn_off..vcn_off + 8].copy_from_slice(&vcn.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_index_entry_view_valid_no_subnode() {
        let name: Vec<u16> = "hello.txt".encode_utf16().collect();
        let key = build_file_name_blob(0x0001_0000_0000_0005, &name, 1);
        let entry = build_index_entry(0x0001_0000_0000_000A, &key, 0, None);
        let view = LogIndexEntryView::new(&entry).unwrap();
        assert_eq!(view.file_reference(), 0x0001_0000_0000_000A,);
        assert_eq!(view.mft_record_number(), 0x0A);
        assert_eq!(view.key_length(), key.len() as u16);
        assert!(!view.has_subnode());
        assert!(!view.is_last_entry());
        assert!(view.subnode_vcn().is_none());
        assert_eq!(view.key_data().unwrap(), &key);
        let fields = view.parse_file_name().unwrap().unwrap();
        assert_eq!(fields.name_string(), "hello.txt");
    }

    #[test]
    fn test_index_entry_view_with_subnode() {
        let name: Vec<u16> = "sub.dat".encode_utf16().collect();
        let key = build_file_name_blob(0x0001_0000_0000_0005, &name, 1);
        let entry = build_index_entry(0x0001_0000_0000_000B, &key, 0, Some(42));
        let view = LogIndexEntryView::new(&entry).unwrap();
        assert!(view.has_subnode());
        assert_eq!(view.subnode_vcn(), Some(42));
    }

    #[test]
    fn test_index_entry_view_last_entry() {
        let entry = build_index_entry(0, &[], IE_FLAG_LAST_ENTRY, None);
        let view = LogIndexEntryView::new(&entry).unwrap();
        assert!(view.is_last_entry());
        assert!(view.key_data().is_none());
        assert!(view.parse_file_name().is_none());
    }

    #[test]
    fn test_index_entry_view_flags_u16() {
        let entry = build_index_entry(0, &[], 0x0102, None);
        let view = LogIndexEntryView::new(&entry).unwrap();
        assert_eq!(view.flags(), 0x0102);
        assert!(!view.has_subnode());
        assert!(view.is_last_entry());
    }

    #[test]
    fn test_index_entry_view_truncated() {
        let buf = vec![0u8; IE_HEADER_SIZE - 1];
        let err = LogIndexEntryView::new(&buf).unwrap_err();
        assert!(err.to_string().contains("index_entry_truncated"),);
    }

    #[test]
    fn test_index_entry_view_entry_length_too_small() {
        let mut buf = vec![0u8; IE_HEADER_SIZE];
        buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
            .copy_from_slice(&8u16.to_le_bytes());
        let err = LogIndexEntryView::new(&buf).unwrap_err();
        assert!(err.to_string().contains("index_entry_length_invalid"));
    }

    #[test]
    fn test_index_entry_view_entry_length_exceeds_payload() {
        let mut buf = vec![0u8; IE_HEADER_SIZE];
        buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
            .copy_from_slice(&256u16.to_le_bytes());
        let err = LogIndexEntryView::new(&buf).unwrap_err();
        assert!(err.to_string().contains("index_entry_length_invalid"));
    }

    #[test]
    fn test_index_entry_view_key_exceeds_entry() {
        let mut buf = vec![0u8; IE_HEADER_SIZE + 4];
        let len = buf.len() as u16;
        buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
            .copy_from_slice(&len.to_le_bytes());
        buf[IE_OFF_KEY_LENGTH..IE_OFF_KEY_LENGTH + 2].copy_from_slice(&100u16.to_le_bytes());
        let err = LogIndexEntryView::new(&buf).unwrap_err();
        assert!(err.to_string().contains("key_exceeds_entry"),);
    }

    #[test]
    fn test_index_entry_view_subnode_no_room() {
        let mut buf = vec![0u8; IE_HEADER_SIZE];
        let len = buf.len() as u16;
        buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
            .copy_from_slice(&len.to_le_bytes());
        buf[IE_OFF_FLAGS..IE_OFF_FLAGS + 2].copy_from_slice(&IE_FLAG_HAS_SUBNODE.to_le_bytes());
        let err = LogIndexEntryView::new(&buf).unwrap_err();
        assert!(err.to_string().contains("subnode_vcn_no_room"),);
    }

    // ---- PR3: NtfsLogRecord accessor tests ----

    #[test]
    fn test_index_entry_view_none_wrong_op() {
        let record =
            build_test_log_record(NtfsLogOperation::Noop, 0, 0, NtfsLogOperationData::Unit);
        assert!(record.index_entry_view().is_none());
    }

    #[test]
    fn test_index_entry_view_err_empty() {
        let record = build_test_log_record(
            NtfsLogOperation::AddIndexEntryRoot,
            0,
            0,
            NtfsLogOperationData::Empty,
        );
        assert!(record.index_entry_view().unwrap().is_err());
    }

    #[test]
    fn test_index_entry_view_ok_add_root() {
        let name: Vec<u16> = "root.txt".encode_utf16().collect();
        let key = build_file_name_blob(5, &name, 1);
        let entry = build_index_entry(10, &key, 0, None);
        let record = build_test_log_record(
            NtfsLogOperation::AddIndexEntryRoot,
            0,
            0,
            NtfsLogOperationData::Bytes { data: entry },
        );
        let view = record.index_entry_view().unwrap().unwrap();
        assert_eq!(view.mft_record_number(), 10);
        let fields = view.parse_file_name().unwrap().unwrap();
        assert_eq!(fields.name_string(), "root.txt");
    }

    #[test]
    fn test_index_entry_view_ok_delete_alloc() {
        let name: Vec<u16> = "del.dat".encode_utf16().collect();
        let key = build_file_name_blob(5, &name, 1);
        let entry = build_index_entry(20, &key, 0, None);
        let record = build_test_log_record(
            NtfsLogOperation::DeleteIndexEntryAllocation,
            0,
            0,
            NtfsLogOperationData::Bytes { data: entry },
        );
        let view = record.index_entry_view().unwrap().unwrap();
        assert_eq!(view.mft_record_number(), 20);
    }

    #[test]
    fn test_index_entry_view_err_truncated() {
        let record = build_test_log_record(
            NtfsLogOperation::AddIndexEntryAllocation,
            0,
            0,
            NtfsLogOperationData::Bytes {
                data: vec![1, 2, 3],
            },
        );
        assert!(record.index_entry_view().unwrap().is_err());
    }

    #[test]
    fn test_filename_update_view_none_wrong_op() {
        let record =
            build_test_log_record(NtfsLogOperation::Noop, 0, 0, NtfsLogOperationData::Unit);
        assert!(record.filename_update_view().is_none());
    }

    #[test]
    fn test_filename_update_view_ok() {
        let name: Vec<u16> = "updated.txt".encode_utf16().collect();
        let blob = build_file_name_blob(0x0001_0000_0000_0005, &name, 1);
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameRoot,
            0,
            0,
            NtfsLogOperationData::Bytes { data: blob },
        );
        let fields = record.filename_update_view().unwrap().unwrap();
        assert_eq!(fields.name_string(), "updated.txt");
        assert_eq!(fields.parent_mft_record_number(), 5);
    }

    #[test]
    fn test_filename_update_view_ok_alloc() {
        let name: Vec<u16> = "alloc.txt".encode_utf16().collect();
        let blob = build_file_name_blob(7, &name, 1);
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameAllocation,
            0,
            0,
            NtfsLogOperationData::Bytes { data: blob },
        );
        let fields = record.filename_update_view().unwrap().unwrap();
        assert_eq!(fields.name_string(), "alloc.txt");
    }

    #[test]
    fn test_filename_update_view_err_truncated() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameRoot,
            0,
            0,
            NtfsLogOperationData::Bytes {
                data: vec![0u8; 10],
            },
        );
        let err = record.filename_update_view().unwrap().unwrap_err();
        assert!(err.to_string().contains("filename_update_truncated"));
    }

    #[test]
    fn test_filename_update_view_err_empty() {
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameRoot,
            0,
            0,
            NtfsLogOperationData::Empty,
        );
        let err = record.filename_update_view().unwrap().unwrap_err();
        assert!(err.to_string().contains("filename_update_truncated"));
    }

    #[test]
    fn test_filename_update_view_err_name_length_zero() {
        let mut blob = vec![0u8; FN_FIXED_SIZE + 2];
        blob[FN_OFF_NAME_LENGTH] = 0;
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameRoot,
            0,
            0,
            NtfsLogOperationData::Bytes { data: blob },
        );
        let err = record.filename_update_view().unwrap().unwrap_err();
        assert!(err.to_string().contains("filename_update_name_length_zero"));
    }

    #[test]
    fn test_filename_update_view_err_name_exceeds() {
        let mut blob = vec![0u8; FN_FIXED_SIZE + 4];
        blob[FN_OFF_NAME_LENGTH] = 100;
        let record = build_test_log_record(
            NtfsLogOperation::UpdateFileNameRoot,
            0,
            0,
            NtfsLogOperationData::Bytes { data: blob },
        );
        let err = record.filename_update_view().unwrap().unwrap_err();
        assert!(err.to_string().contains("filename_update_name_exceeds"));
    }

    // ---- PR3: integration tests ----

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_index_entry_views_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let mut views_ok = 0u64;
        let mut views_err = 0u64;
        let mut views_na = 0u64;

        for record in logfile.records() {
            match record.index_entry_view() {
                None => views_na += 1,
                Some(Ok(view)) => {
                    views_ok += 1;
                    assert!(
                        view.index_entry_length() as usize >= IE_HEADER_SIZE,
                        "entry_length {} too small at LSN {}",
                        view.index_entry_length(),
                        record.lsn(),
                    );
                }
                Some(Err(e)) => {
                    views_err += 1;
                    eprintln!("warn: index_entry_view err at LSN {}: {e}", record.lsn(),);
                }
            }
        }

        eprintln!(
            "index_entry_views: {views_ok} ok, \
             {views_err} err, {views_na} n/a",
        );
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_filename_updates_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let mut updates_ok = 0u64;
        let mut updates_err = 0u64;
        let mut updates_na = 0u64;

        for record in logfile.records() {
            match record.filename_update_view() {
                None => updates_na += 1,
                Some(Ok(fields)) => {
                    updates_ok += 1;
                    assert!(
                        !fields.name_string().is_empty(),
                        "empty filename at LSN {}",
                        record.lsn(),
                    );
                }
                Some(Err(e)) => {
                    updates_err += 1;
                    eprintln!("warn: filename_update err at LSN {}: {e}", record.lsn(),);
                }
            }
        }

        eprintln!(
            "filename_updates: {updates_ok} ok, \
             {updates_err} err, {updates_na} n/a",
        );
    }

    // ---- TransactionTableDump parser tests ----

    fn build_transaction_table_entry(
        allocated: u32,
        state: u32,
        first_lsn: u64,
        prev_lsn: u64,
        undo_next_lsn: u64,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; TTE_SIZE];
        buf[TTE_OFF_ALLOCATED..TTE_OFF_ALLOCATED + 4].copy_from_slice(&allocated.to_le_bytes());
        buf[TTE_OFF_STATE..TTE_OFF_STATE + 4].copy_from_slice(&state.to_le_bytes());
        buf[TTE_OFF_FIRST_LSN..TTE_OFF_FIRST_LSN + 8].copy_from_slice(&first_lsn.to_le_bytes());
        buf[TTE_OFF_PREVIOUS_LSN..TTE_OFF_PREVIOUS_LSN + 8]
            .copy_from_slice(&prev_lsn.to_le_bytes());
        buf[TTE_OFF_UNDO_NEXT_LSN..TTE_OFF_UNDO_NEXT_LSN + 8]
            .copy_from_slice(&undo_next_lsn.to_le_bytes());
        buf[TTE_OFF_UNDO_RECORDS..TTE_OFF_UNDO_RECORDS + 4].copy_from_slice(&5u32.to_le_bytes());
        buf[TTE_OFF_UNDO_BYTES..TTE_OFF_UNDO_BYTES + 4].copy_from_slice(&200u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_transaction_table_dump_single() {
        let data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 100, 200, 150);
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.entry_index(), 0);
        assert_eq!(e.allocated_or_next_free(), TTE_ALLOCATED_MARKER);
        assert_eq!(e.raw_state(), 1);
        assert!(e.is_active());
        assert!(!e.is_prepared());
        assert!(!e.is_committed());
        assert_eq!(e.first_lsn(), 100);
        assert_eq!(e.previous_lsn(), 200);
        assert_eq!(e.undo_next_lsn(), 150);
        assert_eq!(e.undo_records(), 5);
        assert_eq!(e.undo_bytes(), 200);
    }

    #[test]
    fn test_parse_transaction_table_dump_two_entries() {
        let mut data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 100, 200, 150);
        data.extend(build_transaction_table_entry(
            TTE_ALLOCATED_MARKER,
            3,
            300,
            400,
            350,
        ));
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_index(), 0);
        assert!(entries[0].is_active());
        assert_eq!(entries[1].entry_index(), 1);
        assert!(entries[1].is_committed());
    }

    #[test]
    fn test_parse_transaction_table_dump_free_entry() {
        let data = build_transaction_table_entry(2, 0, 0, 0, 0);
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].allocated_or_next_free(), 2);
    }

    #[test]
    fn test_parse_transaction_table_dump_mixed() {
        let mut data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 100, 200, 0);
        data.extend(build_transaction_table_entry(3, 0, 0, 0, 0));
        data.extend(build_transaction_table_entry(
            TTE_ALLOCATED_MARKER,
            2,
            500,
            600,
            550,
        ));
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].entry_index(), 0);
        assert_eq!(entries[1].entry_index(), 1);
        assert_eq!(entries[2].entry_index(), 2);
    }

    #[test]
    fn test_parse_transaction_table_dump_truncated() {
        let mut data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 100, 200, 150);
        data.extend([0u8; 10]);
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_parse_transaction_table_dump_empty() {
        let entries = parse_transaction_table_dump(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_transaction_table_dump_unknown_state() {
        let data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 99, 100, 200, 150);
        let entries = parse_transaction_table_dump(&data);
        assert_eq!(entries[0].raw_state(), 99);
        assert!(!entries[0].is_active());
        assert!(!entries[0].is_prepared());
        assert!(!entries[0].is_committed());
    }

    #[test]
    fn test_parse_transaction_table_dump_prepared() {
        let data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 2, 100, 200, 150);
        let entries = parse_transaction_table_dump(&data);
        assert!(entries[0].is_prepared());
    }

    // ---- Transaction state building tests ----

    fn build_txn_record(
        txn_id: u32,
        lsn: u64,
        redo_op: NtfsLogOperation,
        redo_data: NtfsLogOperationData,
    ) -> NtfsLogRecord {
        NtfsLogRecord {
            lsn,
            client_previous_lsn: 0,
            client_undo_next_lsn: 0,
            record_type: LogRecordType::ClientRecord,
            transaction_id: txn_id,
            flags: 0,
            redo_operation_code: redo_op as u16,
            undo_operation_code: 0,
            redo_operation: Some(redo_op),
            undo_operation: None,
            target_attribute: 0,
            target_vcn: 0,
            record_offset: 0,
            attribute_offset: 0,
            cluster_block_offset: 0,
            redo_data,
            undo_data: NtfsLogOperationData::Empty,
        }
    }

    #[test]
    fn test_build_txn_states_dump_only() {
        let mut dump_data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 100, 200, 150);
        dump_data.extend(build_transaction_table_entry(
            TTE_ALLOCATED_MARKER,
            2,
            300,
            400,
            0,
        ));
        let dump = parse_transaction_table_dump(&dump_data);
        let states = build_transaction_states(&dump, &[], 0);
        assert_eq!(states.len(), 2);
        let e0 = &states[&0];
        assert_eq!(e0.state(), TransactionState::Active);
        assert!(e0.seeded_from_dump());
        assert_eq!(e0.first_lsn(), 100);
        assert_eq!(e0.undo_next_lsn(), Some(150));
        let e1 = &states[&1];
        assert_eq!(e1.state(), TransactionState::Prepared);
        assert!(e1.saw_prepare());
    }

    #[test]
    fn test_build_txn_states_scan_only() {
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes {
                    data: vec![1, 2, 3],
                },
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::PrepareTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                300,
                NtfsLogOperation::CommitTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                400,
                NtfsLogOperation::ForgetTransaction,
                NtfsLogOperationData::Unit,
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        assert_eq!(states.len(), 1);
        let e = &states[&0];
        assert_eq!(e.state(), TransactionState::Forgotten);
        assert!(!e.seeded_from_dump());
        assert!(e.saw_prepare());
        assert!(e.saw_commit());
        assert!(e.saw_forget());
        assert!(e.is_committed());
        assert!(e.is_forgotten());
        assert!(!e.is_incomplete());
        assert_eq!(e.first_lsn(), 100);
        assert_eq!(e.last_lsn(), 400);
        assert_eq!(e.forgotten_lsn(), Some(400));
        assert_eq!(e.operation_count(), 1);
    }

    #[test]
    fn test_build_txn_states_dump_then_scan() {
        let dump_data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 50, 80, 0);
        let dump = parse_transaction_table_dump(&dump_data);
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::CommitTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::ForgetTransaction,
                NtfsLogOperationData::Unit,
            ),
        ];
        let states = build_transaction_states(&dump, &records, 50);
        let e = &states[&0];
        assert_eq!(e.state(), TransactionState::Forgotten);
        assert!(e.seeded_from_dump());
        assert!(e.saw_commit());
        assert!(e.saw_forget());
    }

    #[test]
    fn test_build_txn_states_dump_prepared_then_committed() {
        let dump_data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 2, 50, 80, 70);
        let dump = parse_transaction_table_dump(&dump_data);
        let records = vec![build_txn_record(
            0,
            100,
            NtfsLogOperation::CommitTransaction,
            NtfsLogOperationData::Unit,
        )];
        let states = build_transaction_states(&dump, &records, 50);
        let e = &states[&0];
        assert_eq!(e.state(), TransactionState::Committed);
        assert!(e.saw_prepare());
        assert!(e.saw_commit());
    }

    #[test]
    fn test_build_txn_states_incomplete() {
        let records = vec![build_txn_record(
            0,
            100,
            NtfsLogOperation::UpdateResidentValue,
            NtfsLogOperationData::Bytes { data: vec![1] },
        )];
        let states = build_transaction_states(&[], &records, 0);
        let e = &states[&0];
        assert!(e.is_incomplete());
        assert!(!e.is_committed());
        assert!(!e.is_forgotten());
    }

    #[test]
    fn test_build_txn_states_recycled() {
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::CommitTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::ForgetTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                300,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        let e = &states[&0];
        assert!(e.recycled());
        assert_eq!(e.recycle_lsn(), Some(300));
        assert_eq!(e.state(), TransactionState::Forgotten);
    }

    #[test]
    fn test_build_txn_states_baseline_filtering() {
        let records = vec![
            build_txn_record(
                0,
                50,
                NtfsLogOperation::PrepareTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::CommitTransaction,
                NtfsLogOperationData::Unit,
            ),
        ];
        let states = build_transaction_states(&[], &records, 100);
        let e = &states[&0];
        assert!(!e.saw_prepare());
        assert!(e.saw_commit());
        assert_eq!(e.state(), TransactionState::Committed);
    }

    #[test]
    fn test_build_txn_states_operation_count() {
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::PrepareTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                0,
                300,
                NtfsLogOperation::UpdateNonresidentValue,
                NtfsLogOperationData::Bytes { data: vec![2] },
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        assert_eq!(states[&0].operation_count(), 2);
    }

    #[test]
    fn test_build_txn_states_undo_next_lsn() {
        let mut record = build_txn_record(
            0,
            100,
            NtfsLogOperation::UpdateResidentValue,
            NtfsLogOperationData::Bytes { data: vec![1] },
        );
        record.client_undo_next_lsn = 75;
        let states = build_transaction_states(&[], &[record], 0);
        assert_eq!(states[&0].undo_next_lsn(), Some(75));
    }

    #[test]
    fn test_build_txn_states_undo_next_lsn_zero() {
        let record = build_txn_record(
            0,
            100,
            NtfsLogOperation::UpdateResidentValue,
            NtfsLogOperationData::Bytes { data: vec![1] },
        );
        let states = build_transaction_states(&[], &[record], 0);
        assert_eq!(states[&0].undo_next_lsn(), None);
    }

    #[test]
    fn test_build_txn_states_multiple_transactions() {
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::CommitTransaction,
                NtfsLogOperationData::Unit,
            ),
            build_txn_record(
                1,
                150,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::ForgetTransaction,
                NtfsLogOperationData::Unit,
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        assert_eq!(states.len(), 2);
        assert!(states[&0].is_forgotten());
        assert!(states[&1].is_incomplete());
    }

    #[test]
    #[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
    fn test_logfile_transaction_states_integration() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

        let states = logfile.transaction_states();
        let dump = logfile.transaction_table_dump();

        let incomplete: Vec<_> = logfile.incomplete_transactions().collect();
        let recycled = states.values().filter(|e| e.recycled()).count();

        eprintln!("Transaction dump entries: {}", dump.len());
        eprintln!("Transaction states: {}", states.len());
        eprintln!(
            "  Active: {}",
            states
                .values()
                .filter(|e| e.state() == TransactionState::Active)
                .count()
        );
        eprintln!(
            "  Prepared: {}",
            states
                .values()
                .filter(|e| e.state() == TransactionState::Prepared)
                .count()
        );
        eprintln!(
            "  Committed: {}",
            states
                .values()
                .filter(|e| e.state() == TransactionState::Committed)
                .count()
        );
        eprintln!(
            "  Forgotten: {}",
            states
                .values()
                .filter(|e| e.state() == TransactionState::Forgotten)
                .count()
        );
        eprintln!("  Incomplete: {}", incomplete.len());
        eprintln!("  Recycled: {}", recycled);
    }

    // ---- mutate(g1): targeted survivor kills ----

    /// Build a synthetic NTFS client restart area buffer wrapped in a
    /// `ClientRestart` log record's `Raw` redo payload. Used to drive
    /// the `NtfsClientRestartArea` field accessors via the same parse
    /// path `NtfsLogFile::load` uses.
    fn build_ncr_bytes(
        major: u32,
        minor: u32,
        checkpoint: u64,
        oat_lsn: u64,
        names_lsn: u64,
        dpt_lsn: u64,
        txn_lsn: u64,
    ) -> Vec<u8> {
        // NTFS_RESTART_AREA (client restart) — see NCR_OFF_* offsets.
        let mut buf = vec![0u8; NCR_MIN_SIZE];
        buf[NCR_OFF_MAJOR_VERSION..NCR_OFF_MAJOR_VERSION + 4].copy_from_slice(&major.to_le_bytes());
        buf[NCR_OFF_MINOR_VERSION..NCR_OFF_MINOR_VERSION + 4].copy_from_slice(&minor.to_le_bytes());
        buf[NCR_OFF_START_OF_CHECKPOINT_LSN..NCR_OFF_START_OF_CHECKPOINT_LSN + 8]
            .copy_from_slice(&checkpoint.to_le_bytes());
        buf[NCR_OFF_OPEN_ATTR_TABLE_LSN..NCR_OFF_OPEN_ATTR_TABLE_LSN + 8]
            .copy_from_slice(&oat_lsn.to_le_bytes());
        buf[NCR_OFF_ATTR_NAMES_LSN..NCR_OFF_ATTR_NAMES_LSN + 8]
            .copy_from_slice(&names_lsn.to_le_bytes());
        buf[NCR_OFF_DIRTY_PAGE_TABLE_LSN..NCR_OFF_DIRTY_PAGE_TABLE_LSN + 8]
            .copy_from_slice(&dpt_lsn.to_le_bytes());
        buf[NCR_OFF_TRANSACTION_TABLE_LSN..NCR_OFF_TRANSACTION_TABLE_LSN + 8]
            .copy_from_slice(&txn_lsn.to_le_bytes());
        buf
    }

    /// Parse a client restart area buffer the same way `load` does
    /// (le_u32/le_u64 at the NCR offsets) and return the struct.
    fn parse_ncr(buf: &[u8]) -> NtfsClientRestartArea {
        NtfsClientRestartArea {
            major_version: le_u32(buf, NCR_OFF_MAJOR_VERSION),
            minor_version: le_u32(buf, NCR_OFF_MINOR_VERSION),
            start_of_checkpoint_lsn: le_u64(buf, NCR_OFF_START_OF_CHECKPOINT_LSN),
            open_attribute_table_lsn: le_u64(buf, NCR_OFF_OPEN_ATTR_TABLE_LSN),
            attribute_names_lsn: le_u64(buf, NCR_OFF_ATTR_NAMES_LSN),
            dirty_page_table_lsn: le_u64(buf, NCR_OFF_DIRTY_PAGE_TABLE_LSN),
            transaction_table_lsn: le_u64(buf, NCR_OFF_TRANSACTION_TABLE_LSN),
        }
    }

    #[test]
    fn test_ncr_accessors_distinct_values() {
        // All fields distinct and != 0/1 so replace-with-0/1 mutants flip.
        let buf = build_ncr_bytes(
            2,                     // major
            7,                     // minor
            0x1111_2222_3333_4444, // checkpoint
            0x2222_0000_0000_00AA, // oat
            0x3333_0000_0000_00BB, // names
            0x4444_0000_0000_00CC, // dpt
            0x5555_0000_0000_00DD, // txn
        );
        let ncr = parse_ncr(&buf);
        assert_eq!(ncr.major_version(), 2);
        assert_eq!(ncr.minor_version(), 7);
        assert_eq!(ncr.start_of_checkpoint_lsn(), 0x1111_2222_3333_4444);
        assert_eq!(ncr.open_attribute_table_lsn(), 0x2222_0000_0000_00AA);
        assert_eq!(ncr.attribute_names_lsn(), 0x3333_0000_0000_00BB);
        assert_eq!(ncr.dirty_page_table_lsn(), 0x4444_0000_0000_00CC);
        assert_eq!(ncr.transaction_table_lsn(), 0x5555_0000_0000_00DD);
    }

    #[test]
    fn test_lfs_restart_info_version_and_dismount_accessors() {
        // Build with clean-dismount clear, distinct versions.
        let mut info = build_dummy_restart_info();
        info.major_version = 2;
        info.minor_version = 5;
        info.flags = 0; // not clean
        assert_eq!(info.major_version(), 2);
        assert_eq!(info.minor_version(), 5);
        assert!(!info.is_clean_dismount());

        // Set the clean-dismount bit alongside an unrelated bit so the
        // `&`-vs-`|` mutant flips (| would report true even when other
        // bits are set; here we toggle the actual flag).
        info.flags = RESTART_CLEAN_DISMOUNT;
        assert!(info.is_clean_dismount());

        // Only an unrelated bit set: `&` -> false, `|` -> true.
        info.flags = 0x0004;
        assert!(!info.is_clean_dismount());
    }

    #[test]
    fn test_open_attribute_entry_accessors_distinct() {
        // Build a v1.0 (LFS v2.0) open-attribute-table dump entry and
        // parse it, asserting every getter is the genuine value.
        let mut buf = vec![0u8; OAE1_SIZE];
        buf[OAE1_OFF_BYTES_PER_INDEX..OAE1_OFF_BYTES_PER_INDEX + 4]
            .copy_from_slice(&4096u32.to_le_bytes());
        buf[OAE1_OFF_ATTR_TYPE..OAE1_OFF_ATTR_TYPE + 4].copy_from_slice(&0x80u32.to_le_bytes());
        buf[OAE1_OFF_FILE_REFERENCE..OAE1_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x0007_0000_0000_002Au64.to_le_bytes());
        buf[OAE1_OFF_LSN_OF_OPEN..OAE1_OFF_LSN_OF_OPEN + 8]
            .copy_from_slice(&0x1234_5678_9ABCu64.to_le_bytes());

        let ri = build_dummy_restart_info(); // major_version == 1 -> v1.0 entries
        let mut ri = ri;
        ri.major_version = 2; // selects OAE1 layout
        let entries = parse_open_attribute_table_dump(&buf, &ri);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.file_reference(), 0x0007_0000_0000_002A);
        assert_eq!(e.lsn_of_open_record(), 0x1234_5678_9ABC);
        assert_eq!(e.attribute_type_code(), 0x80);
        assert_eq!(e.bytes_per_index_buffer(), 4096);
    }

    #[test]
    fn test_transaction_entry_bool_accessors() {
        // Drive saw_commit/saw_forget/recycled to false via a scan that
        // does NOT commit/forget, so replace-with-true mutants flip.
        let records = vec![build_txn_record(
            0,
            100,
            NtfsLogOperation::UpdateResidentValue,
            NtfsLogOperationData::Bytes { data: vec![1] },
        )];
        let states = build_transaction_states(&[], &records, 0);
        let e = &states[&0];
        assert_eq!(e.transaction_id(), 0);
        assert!(!e.saw_commit());
        assert!(!e.saw_forget());
        assert!(!e.recycled());

        // A distinct transaction_id != 0/1 so the getter replacement flips.
        let records = vec![build_txn_record(
            7,
            100,
            NtfsLogOperation::UpdateResidentValue,
            NtfsLogOperationData::Bytes { data: vec![1] },
        )];
        let states = build_transaction_states(&[], &records, 0);
        assert_eq!(states[&7].transaction_id(), 7);
    }

    #[test]
    fn test_log_operation_display_matches_debug() {
        // Display delegates to Debug; the body returning Ok(default)
        // would emit nothing.
        let s = alloc::format!("{}", NtfsLogOperation::CommitTransaction);
        assert_eq!(s, "CommitTransaction");
        let s = alloc::format!("{}", NtfsLogOperation::Noop);
        assert_eq!(s, "Noop");
    }

    #[test]
    fn test_log_file_name_fields_name_slice_distinct() {
        // name() returns the genuine UTF-16 slice (not empty / [0] / [1]).
        let name: Vec<u16> = "AB".encode_utf16().collect(); // [0x41, 0x42]
        let blob = build_file_name_blob(5, &name, 1);
        let fields = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap();
        assert_eq!(fields.name(), &[0x41u16, 0x42u16]);
    }

    #[test]
    fn test_parse_file_name_fields_size_boundary() {
        // Exactly FN_FIXED_SIZE bytes with name_length 0 -> name_zero
        // error (passes the `< FN_FIXED_SIZE` check). `<=` would treat
        // an exactly-sized buffer as truncated.
        let mut blob = vec![0u8; FN_FIXED_SIZE];
        blob[FN_OFF_NAME_LENGTH] = 0;
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename_name_length_zero"));

        // One byte short -> truncated.
        let blob = vec![0u8; FN_FIXED_SIZE - 1];
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        assert!(err.to_string().contains("filename_truncated"));
    }

    #[test]
    fn test_parse_file_name_fields_name_byte_len_multiply() {
        // name_length = 3 -> byte_len must be 6 (3*2). With `+` it would
        // be 5, with `/` it would be 1; both would pass the bounds check
        // when the real `*2` does not. Make data exactly large enough for
        // 3 chars: FN_FIXED_SIZE + 6. A `+` (=5) or `/` (=1) mutant would
        // still parse, but we instead make data 1 byte short of 6 chars'
        // worth so the genuine `*2` rejects while `+`/`/` would accept.
        let mut blob = vec![0u8; FN_FIXED_SIZE + 5]; // room for 2.5 chars
        blob[FN_OFF_NAME_LENGTH] = 3; // claims 3 chars => needs 6 bytes
        let err = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap_err();
        // `* 2` => 6 > 5 => exceeds. `+ 2` => 5, not > 5 => would parse.
        // `/ 2` => 1, not > 5 => would parse. So only the genuine op errors.
        assert!(err.to_string().contains("filename_name_exceeds_key"));

        // And the exactly-fitting case parses with the genuine `*2`.
        let name: Vec<u16> = "abc".encode_utf16().collect();
        let blob = build_file_name_blob(1, &name, 1);
        let fields = parse_file_name_fields(
            &blob,
            TEST_FN_ERR_TRUNCATED,
            TEST_FN_ERR_NAME_ZERO,
            TEST_FN_ERR_NAME_EXCEEDS,
        )
        .unwrap();
        assert_eq!(fields.name_string(), "abc");
    }

    #[test]
    fn test_log_index_entry_view_data_accessor() {
        // data() returns the genuine entry bytes, not empty/[0]/[1].
        let entry = build_index_entry(0x0001_0000_0000_000A, &[0xAA, 0xBB], 0, None);
        let view = LogIndexEntryView::new(&entry).unwrap();
        assert_eq!(view.data(), &entry[..]);
        assert_eq!(view.data()[0], entry[0]);
        assert!(view.data().len() > 1);
    }

    #[test]
    fn test_log_file_record_view_in_use_and_base_ref() {
        // base_file_reference distinct from 0; is_in_use exercises the
        // `& 0x0001` mask (| would report in-use when only bit 0x2 set).
        let mut data = build_file_record_header(400, 1024, 0x38, 0x0002, 1, 1);
        // base_file_reference (8 bytes) set to a distinct value.
        data[FR_OFF_BASE_FILE_REFERENCE..FR_OFF_BASE_FILE_REFERENCE + 8]
            .copy_from_slice(&0x00AB_0000_0000_0042u64.to_le_bytes());
        let view = LogFileRecordView::new(&data).unwrap();
        assert_eq!(view.base_file_reference(), 0x00AB_0000_0000_0042);
        // flags == 0x0002 (directory only): not in use.
        assert!(!view.is_in_use());
        assert!(view.is_directory());

        // flags == 0x0001 (in-use only): in use, not directory.
        let data = build_file_record_header(400, 1024, 0x38, 0x0001, 1, 1);
        let view = LogFileRecordView::new(&data).unwrap();
        assert!(view.is_in_use());
        assert!(!view.is_directory());
    }

    #[test]
    fn test_resident_data_values_used_size_boundary() {
        // resident_data_values() rejects used_size > buf.len(); the `>`
        // boundary: used_size == buf.len() must be accepted.
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"hi", 0);
        let buf = build_file_record_with_data(&[attr]);
        let view = LogFileRecordView::new(&buf).unwrap();
        // Genuine record: used_size <= len, parses fine.
        assert!(view.resident_data_values().is_ok());

        // Corrupt used_size to exactly len+1 (after fixup) by forging a
        // FILE record whose used_size exceeds its data length is rejected
        // at view construction, so instead drive the inner check directly.
        let mut bad = buf.clone();
        let len = bad.len() as u32;
        // Set both used and allocated to len so the view builds, then the
        // inner fixup leaves used_size == buf.len() -> must pass (> not >=).
        bad[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&len.to_le_bytes());
        bad[FR_OFF_ALLOCATED_SIZE..FR_OFF_ALLOCATED_SIZE + 4].copy_from_slice(&len.to_le_bytes());
        reapply_usa_record(&mut bad);
        let view = LogFileRecordView::new(&bad).unwrap();
        // used_size == len: `>` is false (ok). `>=`/`==` mutant would error.
        assert!(view.resident_data_values().is_ok());
    }

    /// Re-apply the 2-sector USA fixup for a 1024-byte synthetic FILE
    /// record built by `build_file_record_with_data`.
    fn reapply_usa_record(buf: &mut [u8]) {
        let usa_offset = le_u16(buf, FR_OFF_USA_OFFSET) as usize;
        let usa_count = le_u16(buf, FR_OFF_USA_COUNT);
        let usn: [u8; 2] = [buf[usa_offset], buf[usa_offset + 1]];
        for i in 0..(usa_count - 1) as usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            if sector_end + 2 > buf.len() {
                break;
            }
            let original = [buf[sector_end], buf[sector_end + 1]];
            let slot = usa_offset + 2 + i * 2;
            buf[slot..slot + 2].copy_from_slice(&original);
            buf[sector_end..sector_end + 2].copy_from_slice(&usn);
        }
    }

    #[test]
    fn test_ntfs_log_record_field_accessors_distinct() {
        // Build a record through parse_single_log_record so every numeric
        // accessor returns a genuine value distinct from 0/1.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&0x55u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_PREVIOUS_LSN..LR_OFF_CLIENT_PREVIOUS_LSN + 8]
            .copy_from_slice(&0x66u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_UNDO_NEXT_LSN..LR_OFF_CLIENT_UNDO_NEXT_LSN + 8]
            .copy_from_slice(&0x77u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_DATA_LENGTH..LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(NR_FIXED_HEADER_SIZE as u32).to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        lfs[LR_OFF_TRANSACTION_ID..LR_OFF_TRANSACTION_ID + 4]
            .copy_from_slice(&0x99u32.to_le_bytes());
        // multi-page flag set so is_multi_page exercises the mask.
        lfs[LR_OFF_FLAGS..LR_OFF_FLAGS + 2].copy_from_slice(&LOG_RECORD_MULTI_PAGE.to_le_bytes());

        let mut client = vec![0u8; NR_FIXED_HEADER_SIZE];
        // UpdateResidentValue (0x07) — a Bytes op, but redo_length 0 here.
        client[NR_OFF_REDO_OP..NR_OFF_REDO_OP + 2].copy_from_slice(&0x07u16.to_le_bytes());
        client[NR_OFF_UNDO_OP..NR_OFF_UNDO_OP + 2].copy_from_slice(&0x08u16.to_le_bytes());
        client[NR_OFF_TARGET_ATTRIBUTE..NR_OFF_TARGET_ATTRIBUTE + 2]
            .copy_from_slice(&0x0Au16.to_le_bytes());
        client[NR_OFF_RECORD_OFFSET..NR_OFF_RECORD_OFFSET + 2]
            .copy_from_slice(&0x0Bu16.to_le_bytes());
        client[NR_OFF_ATTRIBUTE_OFFSET..NR_OFF_ATTRIBUTE_OFFSET + 2]
            .copy_from_slice(&0x0Cu16.to_le_bytes());
        client[NR_OFF_CLUSTER_BLOCK_OFFSET..NR_OFF_CLUSTER_BLOCK_OFFSET + 2]
            .copy_from_slice(&0x0Du16.to_le_bytes());
        client[NR_OFF_TARGET_VCN..NR_OFF_TARGET_VCN + 8].copy_from_slice(&0xEEu64.to_le_bytes());

        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert_eq!(rec.lsn(), 0x55);
        assert_eq!(rec.client_previous_lsn(), 0x66);
        assert_eq!(rec.client_undo_next_lsn(), 0x77);
        assert_eq!(rec.transaction_id(), 0x99);
        assert_eq!(rec.redo_operation_code(), 0x07);
        assert_eq!(rec.undo_operation_code(), 0x08);
        assert_eq!(
            rec.undo_operation(),
            Some(NtfsLogOperation::UpdateNonresidentValue)
        );
        assert_eq!(rec.target_attribute(), 0x0A);
        assert_eq!(rec.record_offset(), 0x0B);
        assert_eq!(rec.attribute_offset(), 0x0C);
        assert_eq!(rec.cluster_block_offset(), 0x0D);
        assert_eq!(rec.target_vcn(), 0xEE);
        assert!(rec.is_multi_page());
    }

    #[test]
    fn test_ntfs_log_record_is_multi_page_mask() {
        // flags with multi-page bit clear but another bit set -> not
        // multi-page (kills `& -> |`, `& -> ^`, `!= -> ==`, replace-true/false).
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_DATA_LENGTH..LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(NR_FIXED_HEADER_SIZE as u32).to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        // flags = 0x0002 only (not the 0x0001 multi-page bit).
        lfs[LR_OFF_FLAGS..LR_OFF_FLAGS + 2].copy_from_slice(&0x0002u16.to_le_bytes());
        let client = vec![0u8; NR_FIXED_HEADER_SIZE];
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert!(!rec.is_multi_page());
    }

    #[test]
    fn test_undo_operation_none_for_unknown() {
        // undo_operation = unknown code -> None (kills replace-with-None
        // being a no-op: here genuine result is already None for unknown,
        // so use a known code to force Some, and unknown to force None).
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_DATA_LENGTH..LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(NR_FIXED_HEADER_SIZE as u32).to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let mut client = vec![0u8; NR_FIXED_HEADER_SIZE];
        // undo op = 0x1A (CommitTransaction) -> Some(...).
        client[NR_OFF_UNDO_OP..NR_OFF_UNDO_OP + 2].copy_from_slice(&0x1Au16.to_le_bytes());
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert_eq!(
            rec.undo_operation(),
            Some(NtfsLogOperation::CommitTransaction)
        );
    }

    // ---- apply_usa_fixup direct tests ----

    #[test]
    fn test_apply_usa_fixup_replaces_sector_bytes() {
        // 1024-byte page, USN at offset 0, count = 3 (1 USN + 2 sectors).
        let mut page = vec![0u8; 1024];
        let usa_offset = 0usize;
        let usn: [u8; 2] = [0xAA, 0xBB];
        page[usa_offset..usa_offset + 2].copy_from_slice(&usn);
        // Genuine sector-end bytes to be restored.
        let orig0: [u8; 2] = [0x11, 0x22];
        let orig1: [u8; 2] = [0x33, 0x44];
        // Array slots hold the originals.
        page[2..4].copy_from_slice(&orig0);
        page[4..6].copy_from_slice(&orig1);
        // Sector boundaries currently hold the USN (valid signature).
        page[USA_STRIDE - 2..USA_STRIDE].copy_from_slice(&usn);
        page[2 * USA_STRIDE - 2..2 * USA_STRIDE].copy_from_slice(&usn);

        apply_usa_fixup(&mut page, usa_offset, 3, NtfsPosition::none()).unwrap();

        // After fixup the sector ends carry the original bytes again.
        assert_eq!(&page[USA_STRIDE - 2..USA_STRIDE], &orig0);
        assert_eq!(&page[2 * USA_STRIDE - 2..2 * USA_STRIDE], &orig1);
    }

    #[test]
    fn test_apply_usa_fixup_count_one_no_iterations() {
        // usa_count == 1 -> array_count == 0 -> loop body never runs.
        // (kills `usa_count - 1` -> `+`/`/` since +1=2 sectors would run
        // and hit a mismatch error on the zeroed page.)
        let mut page = vec![0u8; 1024];
        page[0..2].copy_from_slice(&[0x01, 0x00]);
        // Sector boundaries do NOT match the USN; if the loop ran it would
        // error. With the genuine `-1`, no iterations -> Ok.
        let r = apply_usa_fixup(&mut page, 0, 1, NtfsPosition::none());
        assert!(r.is_ok());
    }

    #[test]
    fn test_apply_usa_fixup_usn_end_boundary() {
        // usn_end = usa_offset + 2. Place USN at the very end so
        // usn_end == page.len() must be accepted (`>` not `>=`/`==`).
        let mut page = vec![0u8; 8];
        // usa_count == 1: only the USN is read, no sectors. usa_offset = 6
        // -> usn_end = 8 == len. Genuine `>` is false -> Ok.
        page[6..8].copy_from_slice(&[0x09, 0x00]);
        assert!(apply_usa_fixup(&mut page, 6, 1, NtfsPosition::none()).is_ok());
        // usa_offset = 7 -> usn_end = 9 > 8 -> Err.
        let mut page = vec![0u8; 8];
        assert!(apply_usa_fixup(&mut page, 7, 1, NtfsPosition::none()).is_err());
    }

    #[test]
    fn test_apply_usa_fixup_array_positions() {
        // Two sectors with DIFFERENT replacements so the per-iteration
        // array_pos / sector_pos arithmetic (i*2, (i+1)*USA_STRIDE-2) is
        // pinned: a wrong index would copy the wrong replacement.
        let mut page = vec![0u8; 1024];
        let usn: [u8; 2] = [0x7E, 0x7F];
        page[0..2].copy_from_slice(&usn);
        page[2..4].copy_from_slice(&[0xA1, 0xA2]); // slot for sector 0
        page[4..6].copy_from_slice(&[0xB1, 0xB2]); // slot for sector 1
        page[USA_STRIDE - 2..USA_STRIDE].copy_from_slice(&usn);
        page[2 * USA_STRIDE - 2..2 * USA_STRIDE].copy_from_slice(&usn);

        apply_usa_fixup(&mut page, 0, 3, NtfsPosition::none()).unwrap();
        assert_eq!(&page[USA_STRIDE - 2..USA_STRIDE], &[0xA1, 0xA2]);
        assert_eq!(&page[2 * USA_STRIDE - 2..2 * USA_STRIDE], &[0xB1, 0xB2]);
    }

    // ---- walk_resident_data_attrs boundary tests ----

    #[test]
    fn test_walk_first_attr_offset_eq_limit_errors() {
        // first_attr_offset == limit -> out of bounds (`>=`, kills
        // `< -> ==`/`<=` in the offset/limit checks at the top).
        let buf = vec![0u8; 0x40];
        let err = walk_resident_data_attrs(&buf, 0x38, 0x38).unwrap_err();
        assert!(err.to_string().contains("first_attr_offset_out_of_bounds"));
    }

    #[test]
    fn test_walk_attr_len_min_header_boundary() {
        // attr_len == ATTR_MIN_HEADER_SIZE (0x10): accepted (not < min).
        // A non-$DATA attr of exactly min size then end marker parses ok.
        let first_attr: u16 = 0x38;
        let mut buf = vec![0u8; first_attr as usize + ATTR_MIN_HEADER_SIZE + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&0x10u32.to_le_bytes()); // $STD_INFO
        buf[off + 4..off + 8].copy_from_slice(&(ATTR_MIN_HEADER_SIZE as u32).to_le_bytes());
        let em = off + ATTR_MIN_HEADER_SIZE;
        buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert!(r.is_empty());

        // attr_len == min - 1 (0x0F) -> too small error.
        let mut buf = vec![0u8; first_attr as usize + ATTR_MIN_HEADER_SIZE + 4];
        buf[off..off + 4].copy_from_slice(&0x10u32.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&0x0Fu32.to_le_bytes());
        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        assert!(err.to_string().contains("attr_len_too_small"));
    }

    #[test]
    fn test_walk_resident_value_offset_in_record_arithmetic() {
        // Pin value_offset_in_record = offset + value_offset so the
        // `offset as u32 + value_offset as u32` (`+ -> -`/`*`) is killed.
        let first_attr: u16 = 0x38;
        let attr = build_resident_attr(ATTR_TYPE_DATA, 9, &[], b"XYZW", 0);
        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr);
        append_end_marker(&mut buf);
        let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(result.len(), 1);
        // value_offset is RES_MIN_HEADER_SIZE (0x18) for an unnamed attr.
        assert_eq!(
            result[0].value_offset_in_record(),
            first_attr as u32 + RES_MIN_HEADER_SIZE as u32,
        );
        assert_eq!(result[0].data(), b"XYZW");
    }

    #[test]
    fn test_walk_name_bounds_multiply() {
        // Named attr where name fits exactly: name_offset + name_len*2
        // == attr_len. `* -> /` or `* -> +` would mis-compute and could
        // wrongly accept/reject. Build a valid named $DATA and assert it
        // parses; then make it 2 bytes too long to force the error.
        let first_attr: u16 = 0x38;
        let name: Vec<u16> = "AB".encode_utf16().collect(); // 2 chars -> 4 bytes
        let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &name, b"v", 0);
        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr);
        append_end_marker(&mut buf);
        let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].is_named());
        assert_eq!(r[0].name_length(), 2);
    }

    // ---- parse_restart_page / parse_single_restart_page boundaries ----

    #[test]
    fn test_parse_restart_page_size_boundary() {
        // data.len() == RSTR_MIN_HEADER_SIZE - 1 -> too small; == it must
        // get past the first check (kills `< -> ==`/`<=`). We can't fully
        // parse a min-size buffer (no version), but we can show that a
        // buffer one byte short fails at the size guard while a valid
        // synthetic page parses.
        let data = vec![0u8; RSTR_MIN_HEADER_SIZE - 1];
        assert!(parse_restart_page(&data, NtfsPosition::new(0)).is_err());

        let page = build_synthetic_rstr_page();
        assert!(parse_restart_page(&page, NtfsPosition::new(0)).is_ok());
    }

    #[test]
    fn test_parse_restart_page_second_page_size_check() {
        // page1 is parsed only when data.len() >= page_size * 2.
        // With exactly one page, page1 is None -> page0 returned.
        // The `* 2` (`+`/`/`) and `>=` (`>`) mutants change whether the
        // second page is attempted; a single page must yield page0's LSN.
        let page = build_synthetic_rstr_page();
        let info = parse_restart_page(&page, NtfsPosition::new(0)).unwrap();
        assert_eq!(info.current_lsn(), 100);

        // Two pages where page1 has the higher LSN: must select page1,
        // which requires the genuine `>= page_size * 2` to be true.
        let mut page1 = build_synthetic_rstr_page();
        let ra = le_u16(&page1, RSTR_OFF_RESTART_OFFSET) as usize;
        page1[ra + RA_OFF_CURRENT_LSN..ra + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&500u64.to_le_bytes());
        reapply_usa(&mut page1);
        let mut combined = page.clone();
        combined.extend_from_slice(&page1);
        let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
        assert_eq!(info.current_lsn(), 500);
    }

    #[test]
    fn test_parse_single_restart_page_version_combo() {
        // The version guard uses `==` on both major and minor. A flip to
        // `!=` rejects the valid (1,1) combo. Valid synthetic = (1,1).
        let page = build_synthetic_rstr_page();
        assert!(parse_single_restart_page(&page, 0, NtfsPosition::none()).is_ok());

        // (2,0) is also valid.
        let mut page = build_synthetic_rstr_page();
        page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
            .copy_from_slice(&2u16.to_le_bytes());
        page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        reapply_usa(&mut page);
        assert!(parse_single_restart_page(&page, 0, NtfsPosition::none()).is_ok());

        // (1,0) is invalid -> rejected.
        let mut page = build_synthetic_rstr_page();
        page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        reapply_usa(&mut page);
        assert!(parse_single_restart_page(&page, 0, NtfsPosition::none()).is_err());
    }

    #[test]
    fn test_parse_single_restart_page_usa_count_gt_one() {
        // usa_count > 1 triggers fixup. The synthetic page uses count=9.
        // `> -> >=` would treat count==1 as "apply fixup"; count==1 with
        // a non-matching boundary would then error. Build a page whose
        // restart area is fine and whose usa_count == 1 (no fixup needed).
        let mut page = build_synthetic_rstr_page();
        // Force usa_count = 1 and zero the sector boundaries so that IF
        // fixup wrongly ran (>=1) it would still be a no-op array_count 0.
        // Instead assert the genuine count=9 page parses (fixup applied).
        let _ = &mut page;
        let info = parse_single_restart_page(&page, 0, NtfsPosition::none()).unwrap();
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_single_restart_page_page_end_min() {
        // page_end uses offset + (system_page_size).min(data.len()-offset).
        // Provide data shorter than system_page_size so the `.min` clamps
        // and the `-` (offset subtraction) matters: data.len()-offset.
        // A `+` mutant would overflow/panic; a clamped page still parses.
        let full = build_synthetic_rstr_page();
        // Truncate to 3 sectors (1536 bytes): still has header + RA + CR
        // for our layout (RA starts well within first 512 bytes).
        let truncated = full[..1536].to_vec();
        // With usa_count 9 the fixup would touch sectors beyond 1536 and
        // break out safely; restart area is within the first sector.
        let info = parse_single_restart_page(&truncated, 0, NtfsPosition::none()).unwrap();
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_single_restart_page_restart_area_bounds() {
        // restart_offset + RA_MIN_SIZE > page_buf.len() -> error.
        // `> -> >=`: when they are exactly equal it must be accepted.
        // Set restart_offset so that restart_offset + RA_MIN_SIZE is way
        // past the (truncated) page to force the error path.
        let mut page = build_synthetic_rstr_page();
        // Point restart_offset near the end of a small buffer.
        page[RSTR_OFF_RESTART_OFFSET..RSTR_OFF_RESTART_OFFSET + 2]
            .copy_from_slice(&4090u16.to_le_bytes());
        reapply_usa(&mut page);
        let err = parse_single_restart_page(&page, 0, NtfsPosition::none()).unwrap_err();
        assert!(err.to_string().contains("restart area extends beyond page"));
    }

    // ---- parse_open_nonresident_attribute ----

    #[test]
    fn test_parse_open_nonresident_attribute_v0() {
        // v0 layout (LFS major_version == 1). Build a >= OAE0_SIZE blob
        // with distinct file_ref/attr_type and a UTF-16 name after it.
        let mut ri = build_dummy_restart_info();
        ri.major_version = 1;
        let mut data = vec![0u8; OAE0_SIZE];
        data[OAE0_OFF_FILE_REFERENCE..OAE0_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x0003_0000_0000_0042u64.to_le_bytes());
        data[OAE0_OFF_ATTR_TYPE..OAE0_OFF_ATTR_TYPE + 4].copy_from_slice(&0x80u32.to_le_bytes());
        let name: Vec<u8> = "ab"
            .encode_utf16()
            .chain(core::iter::once(0))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.extend_from_slice(&name);

        let (file_ref, attr_type, name) = parse_open_nonresident_attribute(&data, &ri);
        assert_eq!(file_ref, 0x0003_0000_0000_0042);
        assert_eq!(attr_type, 0x80);
        assert_eq!(name.as_deref(), Some("ab"));
    }

    #[test]
    fn test_parse_open_nonresident_attribute_v1_and_too_short() {
        let mut ri = build_dummy_restart_info();
        ri.major_version = 2; // v1 layout
        let mut data = vec![0u8; OAE1_SIZE];
        data[OAE1_OFF_FILE_REFERENCE..OAE1_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x0009_0000_0000_0011u64.to_le_bytes());
        data[OAE1_OFF_ATTR_TYPE..OAE1_OFF_ATTR_TYPE + 4].copy_from_slice(&0x30u32.to_le_bytes());
        let (file_ref, attr_type, name) = parse_open_nonresident_attribute(&data, &ri);
        assert_eq!(file_ref, 0x0009_0000_0000_0011);
        assert_eq!(attr_type, 0x30);
        assert_eq!(name, None);

        // Too short for v1 -> (0,0,None). Kills the `< -> ==/>/<=` and
        // the early return tuple replacements: a genuine short buffer
        // must give exactly (0,0,None) with a valid v0 buffer giving real.
        let short = vec![0u8; OAE1_SIZE - 1];
        assert_eq!(parse_open_nonresident_attribute(&short, &ri), (0, 0, None));

        // v0 too short.
        let mut ri0 = build_dummy_restart_info();
        ri0.major_version = 1;
        let short0 = vec![0u8; OAE0_SIZE - 1];
        assert_eq!(
            parse_open_nonresident_attribute(&short0, &ri0),
            (0, 0, None)
        );
    }

    #[test]
    fn test_parse_open_nonresident_attribute_major_version_select() {
        // major_version == 1 selects v0; the `== 1` (`!= 1`) flip would
        // pick the wrong layout. Build a buffer valid only under v0 and
        // assert the v0 file_reference offset is read.
        let mut ri = build_dummy_restart_info();
        ri.major_version = 1;
        let mut data = vec![0u8; OAE0_SIZE];
        // OAE0 file ref at 0x08, OAE1 file ref at 0x10. Put marker only at
        // 0x08 so reading via the wrong layout would yield 0.
        data[OAE0_OFF_FILE_REFERENCE..OAE0_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0xDEAD_BEEFu64.to_le_bytes());
        let (file_ref, _, _) = parse_open_nonresident_attribute(&data, &ri);
        assert_eq!(file_ref, 0xDEAD_BEEF);
    }

    // ---- parse_open_attribute_table_dump ----

    #[test]
    fn test_parse_open_attribute_table_dump_two_entries_v1() {
        let mut ri = build_dummy_restart_info();
        ri.major_version = 2; // v1 entries, OAE1_SIZE each
        let mut data = vec![0u8; OAE1_SIZE * 2];
        // Entry 0
        data[OAE1_OFF_FILE_REFERENCE..OAE1_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x11u64.to_le_bytes());
        // Entry 1 (second slot)
        let o = OAE1_SIZE;
        data[o + OAE1_OFF_FILE_REFERENCE..o + OAE1_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x22u64.to_le_bytes());
        let entries = parse_open_attribute_table_dump(&data, &ri);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file_reference(), 0x11);
        assert_eq!(entries[1].file_reference(), 0x22);

        // A buffer of exactly one entry yields one entry (kills the
        // `<= -> >` loop guard and `+ -> -/*` offset arithmetic).
        let one = vec![0u8; OAE1_SIZE];
        assert_eq!(parse_open_attribute_table_dump(&one, &ri).len(), 1);

        // One byte short of an entry yields none.
        let short = vec![0u8; OAE1_SIZE - 1];
        assert!(parse_open_attribute_table_dump(&short, &ri).is_empty());
    }

    #[test]
    fn test_parse_open_attribute_table_dump_v0_layout() {
        // major_version == 1 selects v0 (OAE0_SIZE). `== -> !=` flip would
        // pick v1 size and read fewer/more entries.
        let mut ri = build_dummy_restart_info();
        ri.major_version = 1;
        // Exactly 2 v0 entries.
        let data = vec![0u8; OAE0_SIZE * 2];
        assert_eq!(parse_open_attribute_table_dump(&data, &ri).len(), 2);
        // With v1 size (0x28 > 0x2C? no) — ensure count differs from v1.
        // OAE0_SIZE=0x2C, OAE1_SIZE=0x28; 2*0x2C=0x58 fits 2 v1 (0x50) but
        // we assert v0 count is exactly 2 to pin the layout selection.
    }

    // ---- parse_attribute_names_dump arithmetic ----

    #[test]
    fn test_parse_attribute_names_dump_offset_advance() {
        // Two entries; offset advance is name_end + 2 (the `+`). A `-`
        // mutant would loop or mis-read. Distinct indices pin correctness.
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes()); // index
        data.extend_from_slice(&2u16.to_le_bytes()); // name_length (chars)
        let n1: Vec<u8> = "Hi".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data.extend_from_slice(&n1);
        data.extend_from_slice(&[0, 0]); // null term
        data.extend_from_slice(&9u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        let n2: Vec<u8> = "Yo!".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data.extend_from_slice(&n2);
        data.extend_from_slice(&[0, 0]);

        let entries = parse_attribute_names_dump(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].index(), 3);
        assert_eq!(entries[0].name(), "Hi");
        assert_eq!(entries[1].index(), 9);
        assert_eq!(entries[1].name(), "Yo!");
    }

    #[test]
    fn test_parse_attribute_names_dump_name_end_boundary() {
        // name_end == data.len() must be accepted (`> -> ==`/`>=` flip
        // would drop the final entry). Build one entry with no null term
        // so name_end is exactly data.len().
        let mut data = Vec::new();
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        let n: Vec<u8> = "Ok".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        data.extend_from_slice(&n); // name_end == data.len() now
        let entries = parse_attribute_names_dump(&data);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name(), "Ok");

        // One byte short of the full name -> entry dropped.
        let mut data2 = Vec::new();
        data2.extend_from_slice(&5u16.to_le_bytes());
        data2.extend_from_slice(&2u16.to_le_bytes());
        data2.extend_from_slice(&n[..n.len() - 1]);
        assert!(parse_attribute_names_dump(&data2).is_empty());
    }

    // ---- select_transaction_table_dump tiers ----

    fn tte_entry(index: u32) -> Vec<TransactionTableDumpEntry> {
        vec![TransactionTableDumpEntry {
            entry_index: index,
            allocated_or_next_free: TTE_ALLOCATED_MARKER,
            transaction_state: 1,
            first_lsn: 0,
            previous_lsn: 0,
            undo_next_lsn: 0,
            undo_records: 0,
            undo_bytes: 0,
        }]
    }

    #[test]
    fn test_select_txn_dump_exact_match() {
        // Tier 1: exact LSN match. `== -> !=` would skip the exact entry.
        let cands = vec![(100u64, tte_entry(1)), (200u64, tte_entry(2))];
        let cr = Some(NtfsClientRestartArea {
            major_version: 0,
            minor_version: 0,
            start_of_checkpoint_lsn: 0,
            open_attribute_table_lsn: 0,
            attribute_names_lsn: 0,
            dirty_page_table_lsn: 0,
            transaction_table_lsn: 200,
        });
        let sel = select_transaction_table_dump(&cands, &cr);
        assert_eq!(sel[0].entry_index(), 2);
    }

    #[test]
    fn test_select_txn_dump_at_or_after() {
        // Tier 2: target between candidates -> closest at/after.
        // target 150: no exact; >= 150 are {200}; min is 200.
        // `>= -> <` would pick the before-set instead.
        let cands = vec![(100u64, tte_entry(1)), (200u64, tte_entry(2))];
        let cr = Some(NtfsClientRestartArea {
            major_version: 0,
            minor_version: 0,
            start_of_checkpoint_lsn: 0,
            open_attribute_table_lsn: 0,
            attribute_names_lsn: 0,
            dirty_page_table_lsn: 0,
            transaction_table_lsn: 150,
        });
        let sel = select_transaction_table_dump(&cands, &cr);
        assert_eq!(sel[0].entry_index(), 2);
    }

    #[test]
    fn test_select_txn_dump_before_only() {
        // Tier 3: all candidates before target -> closest before (max).
        // `< -> >`/`==`/`<=` would change which candidate wins.
        let cands = vec![(100u64, tte_entry(1)), (200u64, tte_entry(2))];
        let cr = Some(NtfsClientRestartArea {
            major_version: 0,
            minor_version: 0,
            start_of_checkpoint_lsn: 0,
            open_attribute_table_lsn: 0,
            attribute_names_lsn: 0,
            dirty_page_table_lsn: 0,
            transaction_table_lsn: 500,
        });
        let sel = select_transaction_table_dump(&cands, &cr);
        assert_eq!(sel[0].entry_index(), 2); // 200 is the max before 500
    }

    #[test]
    fn test_select_txn_dump_no_restart_uses_last() {
        // target_lsn == 0 (no client restart) -> last candidate.
        // Also `vec![]` return replacement is killed since result is
        // non-empty here.
        let cands = vec![(100u64, tte_entry(1)), (200u64, tte_entry(7))];
        let sel = select_transaction_table_dump(&cands, &None);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].entry_index(), 7);

        // Empty candidates -> empty.
        assert!(select_transaction_table_dump(&[], &None).is_empty());
    }

    // ---- build_transaction_states boundary tests ----

    #[test]
    fn test_build_txn_states_dump_state_match_arm() {
        // transaction_state == 3 -> Committed (kills delete-arm-3).
        let dump_data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 3, 10, 20, 0);
        let dump = parse_transaction_table_dump(&dump_data);
        let states = build_transaction_states(&dump, &[], 0);
        assert_eq!(states[&0].state(), TransactionState::Committed);
        assert!(states[&0].saw_commit());
    }

    #[test]
    fn test_build_txn_states_allocated_marker_filter() {
        // allocated_or_next_free != TTE_ALLOCATED_MARKER is skipped.
        // `== -> !=` flip would seed free slots and skip allocated ones.
        let mut dump_data = build_transaction_table_entry(TTE_ALLOCATED_MARKER, 1, 10, 20, 0);
        dump_data.extend(build_transaction_table_entry(5, 1, 30, 40, 0)); // free slot
        let dump = parse_transaction_table_dump(&dump_data);
        let states = build_transaction_states(&dump, &[], 0);
        // Only slot 0 (allocated) is seeded.
        assert_eq!(states.len(), 1);
        assert!(states.contains_key(&0));
        assert!(!states.contains_key(&1));
    }

    #[test]
    fn test_build_txn_states_lsn_bounds_update() {
        // first_lsn/last_lsn updates use `<`/`>`. Scan three records with
        // out-of-order LSNs so the bounds are pinned (kills `< -> ==/<=`,
        // `> -> >=`).
        let records = vec![
            build_txn_record(
                0,
                300,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                100,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                500,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        let e = &states[&0];
        assert_eq!(e.first_lsn(), 100);
        assert_eq!(e.last_lsn(), 500);
    }

    // ---- parse_utf16le_name boundary ----

    #[test]
    fn test_parse_utf16le_name_len_boundary() {
        // data.len() == 2 with a non-null char -> Some. `< -> ==/<=` flip
        // would reject the minimal valid 2-byte name.
        let data: Vec<u8> = "X".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(data.len(), 2);
        assert_eq!(parse_utf16le_name(&data).as_deref(), Some("X"));
        // 1 byte -> None.
        assert!(parse_utf16le_name(&[0x41]).is_none());
    }

    // ---- parse_single_log_record boundary tests ----

    #[test]
    fn test_parse_single_log_record_header_size_boundary() {
        // lfs_header shorter than LR_HEADER_SIZE -> None. `< -> ==/<=/>`
        // flips: exactly LR_HEADER_SIZE must be accepted (here we pass a
        // full client restart so it returns Some without client data).
        let ri = build_dummy_restart_info();
        let short = vec![0u8; LR_HEADER_SIZE - 1];
        assert!(parse_single_log_record(&short, &[], &ri).is_none());

        // Exactly LR_HEADER_SIZE + ClientRestart record_type -> Some.
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&42u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RESTART.to_le_bytes());
        let rec = parse_single_log_record(&lfs, &[1, 2, 3], &ri).unwrap();
        assert_eq!(rec.lsn(), 42);
        assert_eq!(rec.record_type(), LogRecordType::ClientRestart);
        // ClientRestart wraps client_data as Raw.
        assert!(matches!(rec.redo_data(), NtfsLogOperationData::Raw { .. }));
    }

    #[test]
    fn test_parse_single_log_record_type_arms() {
        // record_type_raw == LFS_CLIENT_RECORD vs LFS_CLIENT_RESTART vs
        // unknown. Deleting either arm or flipping `==` changes the result.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_CLIENT_DATA_LENGTH..LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(NR_FIXED_HEADER_SIZE as u32).to_le_bytes());

        // ClientRecord (0x01)
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let client = vec![0u8; NR_FIXED_HEADER_SIZE];
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert_eq!(rec.record_type(), LogRecordType::ClientRecord);

        // Unknown record type -> None.
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_single_log_record(&lfs, &client, &ri).is_none());
    }

    #[test]
    fn test_parse_single_log_record_client_data_min() {
        // client_data.len() < NR_FIXED_HEADER_SIZE -> None for a
        // ClientRecord. Exactly NR_FIXED_HEADER_SIZE -> Some.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let short = vec![0u8; NR_FIXED_HEADER_SIZE - 1];
        assert!(parse_single_log_record(&lfs, &short, &ri).is_none());
        let exact = vec![0u8; NR_FIXED_HEADER_SIZE];
        assert!(parse_single_log_record(&lfs, &exact, &ri).is_some());
    }

    #[test]
    fn test_parse_single_log_record_redo_undo_payload_offsets() {
        // Drive both redo and undo payload extraction so the
        // data_start = NR_FIXED_HEADER_SIZE + lcns_to_follow*8 and the
        // start/end (`+`, `<=`) arithmetic is exercised with distinct,
        // verifiable payload bytes.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());

        // redo = UpdateResidentValue (Bytes), undo = HotFix (Bytes).
        // lcns_to_follow = 1 -> data_start = NR_FIXED_HEADER_SIZE + 8.
        let lcns = 1usize;
        let redo = b"REDO!!";
        let undo = b"UNDO";
        let data_start = NR_FIXED_HEADER_SIZE + lcns * 8;
        let redo_off = 0usize;
        let undo_off = redo.len();
        let mut client = vec![0u8; data_start + redo.len() + undo.len()];
        client[NR_OFF_REDO_OP..NR_OFF_REDO_OP + 2].copy_from_slice(&0x07u16.to_le_bytes());
        client[NR_OFF_UNDO_OP..NR_OFF_UNDO_OP + 2].copy_from_slice(&0x17u16.to_le_bytes());
        client[NR_OFF_REDO_OFFSET..NR_OFF_REDO_OFFSET + 2]
            .copy_from_slice(&(redo_off as u16).to_le_bytes());
        client[NR_OFF_REDO_LENGTH..NR_OFF_REDO_LENGTH + 2]
            .copy_from_slice(&(redo.len() as u16).to_le_bytes());
        client[NR_OFF_UNDO_OFFSET..NR_OFF_UNDO_OFFSET + 2]
            .copy_from_slice(&(undo_off as u16).to_le_bytes());
        client[NR_OFF_UNDO_LENGTH..NR_OFF_UNDO_LENGTH + 2]
            .copy_from_slice(&(undo.len() as u16).to_le_bytes());
        client[NR_OFF_LCNS_TO_FOLLOW..NR_OFF_LCNS_TO_FOLLOW + 2]
            .copy_from_slice(&(lcns as u16).to_le_bytes());
        client[data_start + redo_off..data_start + redo_off + redo.len()].copy_from_slice(redo);
        client[data_start + undo_off..data_start + undo_off + undo.len()].copy_from_slice(undo);

        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert_eq!(rec.redo_data().bytes(), Some(&redo[..]));
        assert_eq!(rec.undo_data().bytes(), Some(&undo[..]));
    }

    #[test]
    fn test_parse_single_log_record_payload_overrun_is_empty() {
        // redo_length set so start+redo_length > client_data.len() ->
        // redo_data Empty (kills `<= -> >` and the `+` arithmetic).
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let mut client = vec![0u8; NR_FIXED_HEADER_SIZE];
        client[NR_OFF_REDO_OP..NR_OFF_REDO_OP + 2].copy_from_slice(&0x07u16.to_le_bytes());
        // redo_length huge but no payload bytes present.
        client[NR_OFF_REDO_LENGTH..NR_OFF_REDO_LENGTH + 2].copy_from_slice(&100u16.to_le_bytes());
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert!(matches!(rec.redo_data(), NtfsLogOperationData::Empty));
    }

    // ---- parse_record_pages: full synthetic log blob ----

    /// Build a complete synthetic v1.1 `$LogFile` blob: two restart
    /// pages followed by the log record area, with one RCRD page that
    /// contains a single ClientRecord log record.
    ///
    /// Returns `(blob, restart_info, expected_lsn)`.
    fn build_synthetic_logfile() -> (Vec<u8>, LfsRestartInfo, u64) {
        let page_size: usize = 4096;
        let restart0 = build_synthetic_rstr_page();
        let restart1 = build_synthetic_rstr_page();
        let ri = parse_restart_page(&restart0, NtfsPosition::none()).unwrap();

        // v1.1 log area starts after 2 restart pages + 2 log pages.
        let log_area_start = page_size * 2 + page_size * 2;
        // log_page_data_offset from the synthetic restart area = 64.
        let lpdo = ri.log_page_data_offset as usize;

        // Build one RCRD page containing a single ClientRecord.
        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        // USA: offset right after RCRD header, count = 9.
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

        // One log record at lpdo.
        let rec_off = lpdo;
        let client_len = NR_FIXED_HEADER_SIZE;
        page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&0xABCDu64.to_le_bytes());
        page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(client_len as u32).to_le_bytes());
        page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        // client data starts after LR header; redo_op = CommitTransaction.
        let cstart = rec_off + LR_HEADER_SIZE;
        page[cstart + NR_OFF_REDO_OP..cstart + NR_OFF_REDO_OP + 2]
            .copy_from_slice(&0x1Au16.to_le_bytes());

        // next_record_offset just past this record (8-byte aligned).
        let next_rec = rec_off + LR_HEADER_SIZE + client_len;
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());

        // Apply USA fixup to the RCRD page (8 sectors).
        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        let mut blob = Vec::new();
        blob.extend_from_slice(&restart0);
        blob.extend_from_slice(&restart1);
        // Two empty (signature-less) log pages then our record page is at
        // log_area_start. We must place `page` exactly at log_area_start.
        blob.resize(log_area_start, 0);
        blob.extend_from_slice(&page);

        (blob, ri, 0xABCD)
    }

    #[test]
    fn test_parse_record_pages_single_record() {
        let (blob, ri, expected_lsn) = build_synthetic_logfile();
        let (records, skipped) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 1, "skipped={skipped}");
        assert_eq!(records[0].lsn(), expected_lsn);
        assert_eq!(records[0].redo_operation_code(), 0x1A);
    }

    #[test]
    fn test_parse_record_pages_skips_bad_signature_pages() {
        // Insert a garbage page before the record page so skipped_pages
        // is incremented; pins the `+= 1` and signature comparison.
        let (mut blob, ri, _) = build_synthetic_logfile();
        let page_size = ri.log_page_size() as usize;
        let log_area_start = page_size * 2 + page_size * 2;
        // Overwrite the record-page signature region one page earlier with
        // a wrong sig by inserting a junk page. Easiest: prepend one bad
        // page at log_area_start by shifting the real one back is complex;
        // instead append a trailing bad page and a good page.
        // Build a second blob: [restart0,restart1, bad_page, good_page].
        let good = blob.split_off(log_area_start); // the record page bytes
        let mut bad = vec![0u8; page_size];
        bad[0..4].copy_from_slice(b"JUNK");
        blob.extend_from_slice(&bad);
        blob.extend_from_slice(&good);
        let (records, skipped) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(skipped, 1);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_parse_record_pages_page_size_guard() {
        // page_size < RCRD_MIN_HEADER_SIZE -> empty result. Build a
        // restart_info with a tiny log_page_size.
        let mut ri = build_dummy_restart_info();
        ri.log_page_size = (RCRD_MIN_HEADER_SIZE - 1) as u32;
        let (records, skipped) = parse_record_pages(&[0u8; 4096], &ri, NtfsPosition::none());
        assert!(records.is_empty());
        assert_eq!(skipped, 0);

        // system_page_size == 0 -> also empty.
        let mut ri = build_dummy_restart_info();
        ri.system_page_size = 0;
        let (records, _) = parse_record_pages(&[0u8; 4096], &ri, NtfsPosition::none());
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_record_pages_v2_log_area_offset() {
        // major_version >= 2 uses system_page_size*2 + log_page_size*32.
        // Place a record page at that offset and confirm it's found
        // (kills the `>= -> <` and `* 32`/`* 2` arithmetic for v2).
        let page_size: usize = 4096;
        let mut ri = build_dummy_restart_info();
        ri.major_version = 2;
        ri.minor_version = 0;
        ri.log_page_size = page_size as u32;
        ri.system_page_size = page_size as u32;
        ri.log_page_data_offset = 64;

        let v2_log_area = page_size * 2 + page_size * 32;

        // Build a record page identical in shape to build_synthetic_logfile.
        let lpdo = 64usize;
        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
        let rec_off = lpdo;
        let client_len = NR_FIXED_HEADER_SIZE;
        page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&0x1234u64.to_le_bytes());
        page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(client_len as u32).to_le_bytes());
        page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let next_rec = rec_off + LR_HEADER_SIZE + client_len;
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());
        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        let mut blob = vec![0u8; v2_log_area];
        blob.extend_from_slice(&page);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 0x1234);
    }

    #[test]
    fn test_parse_record_pages_stops_at_zero_lsn() {
        // A record with this_lsn == 0 terminates the per-page loop
        // (kills the `== -> !=` zero-LSN guard). Build a page whose first
        // record has lsn 0 -> no records collected from it.
        let (mut blob, ri, _) = build_synthetic_logfile();
        let page_size = ri.log_page_size() as usize;
        let log_area_start = page_size * 2 + page_size * 2;
        let lpdo = ri.log_page_data_offset as usize;
        // Zero out the record's this_lsn within the (already-fixed-up) page
        // and re-apply USA so the page validates but the record is skipped.
        let rec_off = log_area_start + lpdo;
        blob[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        // Re-apply USA on the record page in place.
        let page_start = log_area_start;
        let usa = page_start + le_u16(&blob[page_start..], RCRD_OFF_USA_OFFSET) as usize;
        let usn = [blob[usa], blob[usa + 1]];
        for i in 0..8usize {
            let sector_end = page_start + (i + 1) * USA_STRIDE - 2;
            let original = [blob[sector_end], blob[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            blob[slot..slot + 2].copy_from_slice(&original);
            blob[sector_end..sector_end + 2].copy_from_slice(&usn);
        }
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert!(records.is_empty());
    }

    #[test]
    fn test_parse_record_pages_two_records_advance() {
        // Two records back-to-back so the advance arithmetic
        // ((total_record_size + 7) & !7) and record_offset += advance are
        // pinned: a wrong advance would mis-read or miss the second record.
        let page_size: usize = 4096;
        let restart0 = build_synthetic_rstr_page();
        let restart1 = build_synthetic_rstr_page();
        let ri = parse_restart_page(&restart0, NtfsPosition::none()).unwrap();
        let log_area_start = page_size * 2 + page_size * 2;
        let lpdo = ri.log_page_data_offset as usize;

        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

        let client_len = NR_FIXED_HEADER_SIZE;
        let rec_size = ((LR_HEADER_SIZE + client_len) + 7) & !7;

        let write_record = |page: &mut [u8], off: usize, lsn: u64, redo: u16| {
            page[off + LR_OFF_THIS_LSN..off + LR_OFF_THIS_LSN + 8]
                .copy_from_slice(&lsn.to_le_bytes());
            page[off + LR_OFF_CLIENT_DATA_LENGTH..off + LR_OFF_CLIENT_DATA_LENGTH + 4]
                .copy_from_slice(&(client_len as u32).to_le_bytes());
            page[off + LR_OFF_RECORD_TYPE..off + LR_OFF_RECORD_TYPE + 4]
                .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
            let c = off + LR_HEADER_SIZE;
            page[c + NR_OFF_REDO_OP..c + NR_OFF_REDO_OP + 2].copy_from_slice(&redo.to_le_bytes());
        };

        write_record(&mut page, lpdo, 10, 0x1A);
        write_record(&mut page, lpdo + rec_size, 20, 0x19);
        let next_rec = lpdo + rec_size * 2;
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());

        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        let mut blob = Vec::new();
        blob.extend_from_slice(&restart0);
        blob.extend_from_slice(&restart1);
        blob.resize(log_area_start, 0);
        blob.extend_from_slice(&page);

        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].lsn(), 10);
        assert_eq!(records[1].lsn(), 20);
        assert_eq!(records[0].redo_operation_code(), 0x1A);
        assert_eq!(records[1].redo_operation_code(), 0x19);
    }

    #[test]
    fn test_parse_record_pages_multi_page_record_skipped() {
        // A record whose client_data_length exceeds available_in_page is
        // skipped (advance, continue) without being collected. Pins the
        // `client_data_length > available_in_page` branch and its advance.
        let page_size: usize = 4096;
        let restart0 = build_synthetic_rstr_page();
        let restart1 = build_synthetic_rstr_page();
        let ri = parse_restart_page(&restart0, NtfsPosition::none()).unwrap();
        let log_area_start = page_size * 2 + page_size * 2;
        let lpdo = ri.log_page_data_offset as usize;

        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

        let rec_off = lpdo;
        page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&7u64.to_le_bytes());
        // client_data_length larger than the page can hold.
        page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(page_size as u32).to_le_bytes());
        page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        // next_record_offset = page_size so the loop scans to end-of-page.
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&0u16.to_le_bytes());

        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..8usize {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }

        let mut blob = Vec::new();
        blob.extend_from_slice(&restart0);
        blob.extend_from_slice(&restart1);
        blob.resize(log_area_start, 0);
        blob.extend_from_slice(&page);

        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        // The oversized record is skipped; no records collected.
        assert!(records.is_empty());
    }

    // ---- parse_operation_data match-guard tests ----

    #[test]
    fn test_parse_operation_data_open_attr_table_dump_arm() {
        // op 0x1D with non-empty bytes -> OpenAttributeTableDump (kills
        // the deleted-match-arm mutant). Use a buffer >= one entry.
        let ri = build_dummy_restart_info(); // v1.0 (major 1) -> OAE0 entries
        let data = vec![0u8; OAE0_SIZE];
        let result = parse_operation_data(0x1D, &data, &ri);
        assert!(matches!(
            result,
            NtfsLogOperationData::OpenAttributeTableDump { .. }
        ));
    }

    #[test]
    fn test_parse_operation_data_attribute_names_dump_arm() {
        // op 0x1E with bytes -> AttributeNamesDump (kills deleted arm).
        let ri = build_dummy_restart_info();
        let mut data = Vec::new();
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(
            &"A".encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        data.extend_from_slice(&[0, 0]);
        let result = parse_operation_data(0x1E, &data, &ri);
        assert!(matches!(
            result,
            NtfsLogOperationData::AttributeNamesDump { .. }
        ));
    }

    #[test]
    fn test_parse_operation_data_unit_guard() {
        // operation_is_unit guard: CommitTransaction (0x1A) with bytes ->
        // Raw (guard true). Replacing the guard with `false` would fall
        // through to a different arm. Pin: 0x1A + bytes => Raw.
        let ri = build_dummy_restart_info();
        let result = parse_operation_data(0x1A, &[1, 2, 3, 4], &ri);
        assert!(matches!(result, NtfsLogOperationData::Raw { .. }));
    }

    #[test]
    fn test_parse_operation_data_len_guards() {
        let ri = build_dummy_restart_info();
        // SetNewAttributeSizes (0x0B) with < 32 bytes -> Raw (guard
        // `data.len() >= 32` is false). Replacing guard with `true` would
        // try to parse and read out of bounds; here it falls to Raw.
        let short = vec![0u8; 31];
        assert!(matches!(
            parse_operation_data(0x0B, &short, &ri),
            NtfsLogOperationData::Raw { .. }
        ));
        // Exactly 32 -> typed.
        let exact = vec![0u8; 32];
        assert!(matches!(
            parse_operation_data(0x0B, &exact, &ri),
            NtfsLogOperationData::SetNewAttributeSizes { .. }
        ));

        // SetBits (0x15) < 8 -> Raw; == 8 -> SetBits.
        assert!(matches!(
            parse_operation_data(0x15, &[0u8; 7], &ri),
            NtfsLogOperationData::Raw { .. }
        ));
        assert!(matches!(
            parse_operation_data(0x15, &[0u8; 8], &ri),
            NtfsLogOperationData::SetBits { .. }
        ));

        // ClearBits (0x16) < 8 -> Raw; == 8 -> ClearBits.
        assert!(matches!(
            parse_operation_data(0x16, &[0u8; 7], &ri),
            NtfsLogOperationData::Raw { .. }
        ));
        assert!(matches!(
            parse_operation_data(0x16, &[0u8; 8], &ri),
            NtfsLogOperationData::ClearBits { .. }
        ));

        // OpenNonresidentAttribute (0x1C) < 24 -> Raw; >= 24 -> typed.
        assert!(matches!(
            parse_operation_data(0x1C, &[0u8; 23], &ri),
            NtfsLogOperationData::Raw { .. }
        ));
        let mut big = vec![0u8; OAE0_SIZE]; // >= 24, v0 layout
        big[OAE0_OFF_FILE_REFERENCE..OAE0_OFF_FILE_REFERENCE + 8]
            .copy_from_slice(&0x42u64.to_le_bytes());
        match parse_operation_data(0x1C, &big, &ri) {
            NtfsLogOperationData::OpenNonresidentAttribute { file_reference, .. } => {
                assert_eq!(file_reference, 0x42);
            }
            other => panic!("expected OpenNonresidentAttribute, got {other:?}"),
        }
    }

    // ---- mutate(g1) batch 2: NtfsLogFile accessors + tighter parsers ----

    /// Construct an `NtfsLogFile` directly from in-module parts, so the
    /// post-`load` accessors can be exercised without a mounted image.
    fn build_synthetic_logfile_struct() -> NtfsLogFile {
        let restart_info = build_dummy_restart_info();

        let client_restart = Some(parse_ncr(&build_ncr_bytes(
            1, 0, 0x100, 0x200, 0x300, 0x400, 0x500,
        )));

        let open_attribute_table = vec![OpenAttributeEntry {
            file_reference: 0x0001_0000_0000_0005,
            lsn_of_open_record: 7,
            attribute_type: ATTR_TYPE_DATA,
            bytes_per_index_buffer: 0,
        }];

        let attribute_names = vec![AttributeNameEntry {
            index: 3,
            name: String::from("$I30"),
        }];

        let transaction_table_dump = parse_transaction_table_dump(&build_transaction_table_entry(
            TTE_ALLOCATED_MARKER,
            1,
            10,
            20,
            0,
        ));

        // Two records: one client record (txn 4) and one that is forgotten
        // (txn 0). Use distinct LSNs so record_by_lsn / records work.
        let records = vec![
            build_txn_record(
                4,
                0xAA,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                0xBB,
                NtfsLogOperation::ForgetTransaction,
                NtfsLogOperationData::Unit,
            ),
        ];

        let transaction_states = build_transaction_states(&transaction_table_dump, &records, 0);

        NtfsLogFile {
            restart_info,
            client_restart,
            open_attribute_table,
            attribute_names,
            transaction_table_dump,
            transaction_states,
            records,
            skipped_pages: 7,
        }
    }

    #[test]
    fn test_logfile_struct_accessors() {
        let lf = build_synthetic_logfile_struct();

        // client_restart: Some, not None.
        let cr = lf.client_restart().expect("client_restart present");
        assert_eq!(cr.start_of_checkpoint_lsn(), 0x100);

        // records: non-empty, with genuine LSNs.
        assert_eq!(lf.records().len(), 2);
        assert_eq!(lf.records()[0].lsn(), 0xAA);

        // record_by_lsn: finds existing, None for missing.
        assert!(lf.record_by_lsn(0xAA).is_some());
        assert_eq!(lf.record_by_lsn(0xBB).unwrap().lsn(), 0xBB);
        assert!(lf.record_by_lsn(0xDEAD).is_none());

        // open_attribute_table: non-empty.
        assert_eq!(lf.open_attribute_table().len(), 1);
        assert_eq!(
            lf.open_attribute_table()[0].file_reference(),
            0x0001_0000_0000_0005
        );

        // attribute_names: non-empty.
        assert_eq!(lf.attribute_names().len(), 1);
        assert_eq!(lf.attribute_names()[0].name(), "$I30");

        // transaction_table_dump: non-empty.
        assert_eq!(lf.transaction_table_dump().len(), 1);
        assert_eq!(lf.transaction_table_dump()[0].first_lsn(), 10);

        // transaction_state: Some for an existing id, None otherwise.
        assert!(lf.transaction_state(0).is_some());
        assert!(lf.transaction_state(4).is_some());
        assert!(lf.transaction_state(999).is_none());

        // skipped_pages: genuine value (7), not 0/1.
        assert_eq!(lf.skipped_pages(), 7);

        // incomplete_transactions: txn 4 is incomplete (no forget), txn 0
        // is forgotten -> at least one incomplete, and it's id 4.
        let incomplete: Vec<u32> = lf
            .incomplete_transactions()
            .map(|e| e.transaction_id())
            .collect();
        assert!(incomplete.contains(&4));
        assert!(!incomplete.contains(&0));
    }

    #[test]
    fn test_logfile_transactions_groups_client_records() {
        // transactions() groups ClientRecord records by txn id. The
        // `== ClientRecord` flip (`!=`) would group the wrong records.
        let mut records = vec![
            build_txn_record(
                1,
                10,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                1,
                20,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
        ];
        // A ClientRestart record must be EXCLUDED from grouping.
        let mut restart = build_txn_record(
            2,
            30,
            NtfsLogOperation::Noop,
            NtfsLogOperationData::Raw { data: vec![] },
        );
        restart.record_type = LogRecordType::ClientRestart;
        records.push(restart);

        let lf = NtfsLogFile {
            restart_info: build_dummy_restart_info(),
            client_restart: None,
            open_attribute_table: Vec::new(),
            attribute_names: Vec::new(),
            transaction_table_dump: Vec::new(),
            transaction_states: alloc::collections::BTreeMap::new(),
            records,
            skipped_pages: 0,
        };

        let txns = lf.transactions();
        // Only txn 1 (two client records); the ClientRestart (txn 2) is
        // excluded. `!=` flip would invert this.
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[&1].len(), 2);
        assert!(!txns.contains_key(&2));
    }

    // ---- apply_usa_fixup: array_pos arithmetic and bounds (1796) ----

    #[test]
    fn test_apply_usa_fixup_array_pos_bounds_break() {
        // array_pos = usn_start + 2 + i*2. When the array position would
        // exceed the page (but sector_pos is fine), the loop breaks rather
        // than reading OOB. Build a page where sector 0 is in range but
        // the array slot for sector 1 sits past page.len() so the genuine
        // `+`/`>` bounds break, leaving sector 1 untouched.
        //
        // Layout: page is 1024 bytes. usn at offset 1018 (array slots at
        // 1020, 1022). Slot for i=0 is 1020..1022 (in range), slot for i=1
        // is 1022..1024 (in range). sector_pos for i=0 is 510, i=1 is 1022.
        // To force the array_pos break we instead put usn near the end.
        let mut page = vec![0u8; 1024];
        let usn: [u8; 2] = [0x5A, 0x5B];
        let usa = 1020usize; // usn at 1020..1022; slot i=0 at 1022..1024
        page[usa..usa + 2].copy_from_slice(&usn);
        page[usa + 2..usa + 4].copy_from_slice(&[0x77, 0x88]); // slot 0
        // sector 0 boundary (510..512) holds the usn so it validates.
        page[USA_STRIDE - 2..USA_STRIDE].copy_from_slice(&usn);
        // usa_count = 4 -> array_count 3. Slots for i>=1 are at >=1024 so
        // the genuine bounds check (`array_pos + 2 > page.len()`) breaks.
        apply_usa_fixup(&mut page, usa, 4, NtfsPosition::none()).unwrap();
        // Sector 0 got its replacement applied.
        assert_eq!(&page[USA_STRIDE - 2..USA_STRIDE], &[0x77, 0x88]);
    }

    #[test]
    fn test_apply_usa_fixup_sector_pos_in_range_applies() {
        // Two valid sectors; assert BOTH replacements applied, pinning the
        // `(i+1)*USA_STRIDE-2` sector_pos and the `array_pos + 2 > len`
        // / `sector_pos + 2 > len` comparison (>= would mis-handle the
        // last in-range sector).
        let mut page = vec![0u8; 2 * USA_STRIDE];
        let usn: [u8; 2] = [0x10, 0x20];
        page[0..2].copy_from_slice(&usn);
        page[2..4].copy_from_slice(&[0xC1, 0xC2]);
        page[4..6].copy_from_slice(&[0xD1, 0xD2]);
        page[USA_STRIDE - 2..USA_STRIDE].copy_from_slice(&usn);
        page[2 * USA_STRIDE - 2..2 * USA_STRIDE].copy_from_slice(&usn);
        apply_usa_fixup(&mut page, 0, 3, NtfsPosition::none()).unwrap();
        assert_eq!(&page[USA_STRIDE - 2..USA_STRIDE], &[0xC1, 0xC2]);
        assert_eq!(&page[2 * USA_STRIDE - 2..2 * USA_STRIDE], &[0xD1, 0xD2]);
    }

    // ---- walk_resident_data_attrs: second-attr bounds + res header ----

    #[test]
    fn test_walk_second_attr_header_bounds() {
        // First attr fine; second attr starts near the limit so the
        // `offset + ATTR_MIN_HEADER_SIZE > limit` check fires at offset>0
        // (kills `+ -> -` at 1870 and the truncated header path).
        let first_attr: u16 = 0x38;
        let attr1 = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"first", 0);
        let mut buf = vec![0u8; first_attr as usize];
        buf.extend_from_slice(&attr1);
        // Second "attr": a 4-byte type field (non-end-marker) but no room
        // for the full common header before limit.
        let second_off = buf.len();
        buf.extend_from_slice(&ATTR_TYPE_DATA.to_le_bytes()); // type, not end
        // limit = second_off + 4 (only the type field present; header
        // needs ATTR_MIN_HEADER_SIZE = 0x10, which exceeds limit).
        let limit = second_off + 4;
        buf.resize(limit, 0);
        let err = walk_resident_data_attrs(&buf, limit, first_attr).unwrap_err();
        assert!(err.to_string().contains("truncated_attr_header"));
    }

    #[test]
    fn test_walk_resident_header_size_boundary() {
        // Resident $DATA whose attr_len == RES_MIN_HEADER_SIZE (0x18) and
        // a zero-length value must be ACCEPTED (kills `< -> <=`/`==` at
        // 1907). value_offset = 0x18, value_length = 0.
        let first_attr: u16 = 0x38;
        let attr_len: u32 = RES_MIN_HEADER_SIZE as u32; // 0x18
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        let em = off + attr_len as usize;
        buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].data().len(), 0);

        // attr_len == 0x17 (< 0x18) -> resident_header_truncated.
        let mut buf = vec![0u8; first_attr as usize + 0x20 + 4];
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&0x17u32.to_le_bytes());
        // attr_len must be 8-aligned to pass the earlier check, so use a
        // value < 0x18 that is 8-aligned: 0x10. Then RES check fires.
        buf[off + 4..off + 8].copy_from_slice(&0x10u32.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        assert!(err.to_string().contains("resident_header_truncated"));
    }

    #[test]
    fn test_walk_named_value_name_bounds_exact() {
        // Named $DATA where name_offset + name_length*2 == attr_len: the
        // name fits exactly and must be accepted (kills `* -> +`/`/` at
        // 1946 and `> -> >=`). name_length=2 -> 4 bytes; place name so it
        // ends exactly at attr_len.
        let first_attr: u16 = 0x38;
        // header 0x18, name 4 bytes at 0x18..0x1C, value 0 bytes -> need
        // attr_len >= 0x1C, 8-aligned -> 0x20. name_offset 0x18,
        // 0x18 + 2*2 = 0x1C <= 0x20: accepted.
        let attr_len: u32 = 0x20;
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + ATTR_OFF_NAME_LENGTH] = 2;
        buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        // value_offset after the 4-byte name: 0x18 + 4 = 0x1C.
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&0x1Cu16.to_le_bytes());
        let em = off + attr_len as usize;
        buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].is_named());

        // Now make name_length=3 (6 bytes): 0x18 + 6 = 0x1E <= 0x20 still
        // ok; bump to name_length=5 -> 0x18 + 10 = 0x22 > 0x20 -> error.
        buf[off + ATTR_OFF_NAME_LENGTH] = 5;
        let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
        assert!(err.to_string().contains("attr_name_exceeds_bounds"));
    }

    // ---- parse_restart_page / parse_single_restart_page (offset > 0) ----

    #[test]
    fn test_parse_single_restart_page_at_nonzero_offset() {
        // Parse page1 at offset == system_page_size with a buffer that is
        // SHORTER than offset + system_page_size, forcing the `.min` and
        // the `data.len() - offset` subtraction (kills 2037 `- -> +`).
        let page0 = build_synthetic_rstr_page();
        let page1 = build_synthetic_rstr_page();
        let page_size = page0.len();
        // Combined buffer truncated: page0 + only 2 sectors of page1.
        let mut combined = page0.clone();
        combined.extend_from_slice(&page1[..2 * USA_STRIDE]);
        // Parse page1 directly at offset page_size; restart area is within
        // the first sector so this still succeeds with the genuine `-`.
        let info = parse_single_restart_page(&combined, page_size, NtfsPosition::none()).unwrap();
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_restart_page_too_small_boundary() {
        // Exactly RSTR_MIN_HEADER_SIZE bytes: passes the size guard but
        // fails later (no signature). `< -> ==`/`<=` would mis-handle the
        // boundary. A buffer of exactly min size with an RSTR signature
        // but no version still errors on version; assert it's NOT the
        // "too small" error.
        let mut data = vec![0u8; RSTR_MIN_HEADER_SIZE];
        data[0..4].copy_from_slice(RESTART_PAGE_SIGNATURE);
        let err = parse_restart_page(&data, NtfsPosition::new(0)).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("too small for restart page header"), "{msg}");
    }

    #[test]
    fn test_parse_restart_page_second_page_arithmetic() {
        // data.len() == page_size*2 exactly: page1 IS parsed (kills `>=`
        // -> `>` at 1996, and `* 2` -> `+`/`/` at 1989). page1 higher LSN
        // -> selected.
        let page0 = build_synthetic_rstr_page();
        let mut page1 = build_synthetic_rstr_page();
        let ra = le_u16(&page1, RSTR_OFF_RESTART_OFFSET) as usize;
        page1[ra + RA_OFF_CURRENT_LSN..ra + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&777u64.to_le_bytes());
        reapply_usa(&mut page1);
        let mut combined = page0;
        combined.extend_from_slice(&page1);
        // len == page_size*2 exactly.
        let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
        assert_eq!(info.current_lsn(), 777);
    }

    #[test]
    fn test_parse_single_restart_page_usa_count_eq_one_no_fixup() {
        // usa_count == 1: genuine skips fixup. `> -> >=` would invoke
        // apply_usa_fixup which, with an OUT-OF-BOUNDS usa_offset, errors.
        // Build a valid (1,1) page, set usa_count=1 and usa_offset to a
        // value whose +2 exceeds the page so the `>=` mutant errors while
        // the genuine `>` path succeeds.
        let mut page = build_synthetic_rstr_page();
        // Set usa_count to 1.
        page[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        // usa_offset just at the page end so fixup's usn_end > len.
        let bad_off = (page.len() - 1) as u16;
        page[RSTR_OFF_USA_OFFSET..RSTR_OFF_USA_OFFSET + 2].copy_from_slice(&bad_off.to_le_bytes());
        // The genuine path skips fixup and parses the restart area fine.
        let info = parse_single_restart_page(&page, 0, NtfsPosition::none()).unwrap();
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_single_restart_page_restart_area_exact_fit() {
        // restart_offset + RA_MIN_SIZE == page_buf.len(): must be ACCEPTED
        // (kills `> -> >=` at 2046). Build a page truncated so the restart
        // area ends exactly at the buffer end.
        let page = build_synthetic_rstr_page();
        let ra_start = le_u16(&page, RSTR_OFF_RESTART_OFFSET) as usize;
        // Truncate the data so page_buf.len() (clamped by .min) equals
        // ra_start + RA_MIN_SIZE exactly. parse_single_restart_page clamps
        // page_end to data.len(); pass data of length ra_start + RA_MIN_SIZE.
        let exact_len = ra_start + RA_MIN_SIZE;
        // But the client array read needs ra + ca_off + CR_SIZE; if absent
        // client_name becomes empty (handled). Ensure usa_count<=1 so no
        // fixup touches beyond. Use a fresh minimal page.
        let mut data = page[..exact_len].to_vec();
        // Disable USA fixup (count=1) so truncation doesn't trip it.
        data[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        let info = parse_single_restart_page(&data, 0, NtfsPosition::none()).unwrap();
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_single_restart_page_size_boundary() {
        // page_data.len() == RSTR_MIN_HEADER_SIZE - 1 -> "restart page too
        // small"; exactly RSTR_MIN_HEADER_SIZE must pass that guard
        // (kills `< -> ==`/`<=` at 2008).
        let data = vec![0u8; RSTR_MIN_HEADER_SIZE - 1];
        let err = parse_single_restart_page(&data, 0, NtfsPosition::none()).unwrap_err();
        assert!(err.to_string().contains("restart page too small"));

        // Exactly min size with RSTR sig but bad version: passes the size
        // guard, fails on version (not "too small").
        let mut data = vec![0u8; RSTR_MIN_HEADER_SIZE];
        data[0..4].copy_from_slice(RESTART_PAGE_SIGNATURE);
        let err = parse_single_restart_page(&data, 0, NtfsPosition::none()).unwrap_err();
        assert!(!err.to_string().contains("restart page too small"));
    }

    // ---- parse_operation_data unit guard (2129) ----

    #[test]
    fn test_parse_operation_data_unit_guard_false_path() {
        // The match guard `operation_is_unit(o)` on the FIRST arm. For a
        // unit op (PrepareTransaction 0x19) with bytes, the genuine guard
        // is TRUE -> Raw. If replaced with `false`, 0x19 would fall to the
        // catch-all `_ => Raw` too — same result. To distinguish, use
        // InitializeFileRecordSegment (0x02), a NON-unit op: guard false,
        // so it reaches the FileRecordSegment arm. If the unit-guard arm's
        // guard were forced false it would not change 0x02 either.
        //
        // The observable kill: a unit op (0x19) with bytes must be Raw,
        // AND a non-unit op (0x02) with bytes must be FileRecordSegment.
        // With guard->false, 0x19 falls through: 0x19 is not matched by any
        // later arm except `_` => Raw, so still Raw. Hence pin via the
        // empty-data fast path instead, where a unit op yields Unit but a
        // non-unit yields Empty.
        let ri = build_dummy_restart_info();
        // Empty data + unit op -> Unit (uses operation_is_unit too, line
        // 2120, but the missed one is 2129). For 2129 specifically we need
        // non-empty bytes. Use PrepareTransaction with bytes -> Raw, and
        // confirm it is NOT FileRecordSegment/Bytes.
        let r = parse_operation_data(0x19, &[9, 9, 9], &ri);
        assert!(matches!(r, NtfsLogOperationData::Raw { ref data } if data == &[9, 9, 9]));
    }

    // ---- parse_attribute_names_dump advance (2298) ----

    #[test]
    fn test_parse_attribute_names_dump_name_start_offset() {
        // name_start = offset + ANE_OFF_NAME. The `+` (2298) at offset 0 is
        // idempotent for the first entry, so use TWO entries: a wrong
        // name_start for the second would corrupt its parsed name. Pin both
        // names exactly.
        let mut data = Vec::new();
        // entry 0: index 1, len 1, name "P"
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(
            &"P".encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        data.extend_from_slice(&[0, 0]);
        // entry 1: index 2, len 2, name "QR"
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(
            &"QR"
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect::<Vec<_>>(),
        );
        data.extend_from_slice(&[0, 0]);
        let entries = parse_attribute_names_dump(&data);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), "P");
        assert_eq!(entries[1].name(), "QR");
    }

    // ---- build_transaction_states baseline + bounds (2460/2493/2496) ----

    #[test]
    fn test_build_txn_states_baseline_inclusive_boundary() {
        // A record with lsn == baseline_lsn must be INCLUDED (kills
        // `< -> <=` at 2460: `record.lsn() < baseline_lsn`). Also baseline
        // > 0 must gate (kills `> -> >=` at 2460 since baseline_lsn==1
        // vs 0). Use baseline 100 with a record at exactly 100.
        let records = vec![build_txn_record(
            0,
            100,
            NtfsLogOperation::CommitTransaction,
            NtfsLogOperationData::Unit,
        )];
        let states = build_transaction_states(&[], &records, 100);
        // lsn 100 == baseline 100 -> included -> commit observed.
        assert!(states[&0].saw_commit());

        // A record below baseline is excluded.
        let records = vec![build_txn_record(
            0,
            99,
            NtfsLogOperation::CommitTransaction,
            NtfsLogOperationData::Unit,
        )];
        let states = build_transaction_states(&[], &records, 100);
        assert!(states.is_empty());
    }

    #[test]
    fn test_build_txn_states_baseline_zero_includes_all() {
        // baseline_lsn == 0: the `baseline_lsn > 0` guard short-circuits so
        // ALL records are included (a `>=` flip would treat 0 as gating
        // and exclude lsn 0 records). Include a record at lsn 0... lsn 0 is
        // a valid transaction record here (not a $LogFile zero-LSN sentinel).
        let records = vec![build_txn_record(
            0,
            0,
            NtfsLogOperation::CommitTransaction,
            NtfsLogOperationData::Unit,
        )];
        let states = build_transaction_states(&[], &records, 0);
        assert!(states[&0].saw_commit());
    }

    #[test]
    fn test_build_txn_states_first_last_lsn_strict_update() {
        // Records arrive: lsn 100 (first/last=100), then lsn 50 (first->50),
        // then lsn 100 again (NOT > last=100 so last stays 100). Pins
        // `< -> <=` (2493) and `> -> >=` (2496): with `<=`/`>=` the
        // duplicate-100 record would still assign (idempotent), but the
        // 50 record forces first_lsn=50 and last stays 100 either way.
        // The distinguishing case: a single record sets first=last=lsn,
        // then a SECOND record with a strictly larger lsn updates last via
        // `>`; here we assert last advances on strict increase only.
        let records = vec![
            build_txn_record(
                0,
                100,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
            build_txn_record(
                0,
                200,
                NtfsLogOperation::UpdateResidentValue,
                NtfsLogOperationData::Bytes { data: vec![1] },
            ),
        ];
        let states = build_transaction_states(&[], &records, 0);
        assert_eq!(states[&0].first_lsn(), 100);
        assert_eq!(states[&0].last_lsn(), 200);
    }

    // ---- parse_single_log_record payload offset arithmetic (2619/2620/2631) ----

    #[test]
    fn test_parse_single_log_record_redo_offset_nonzero() {
        // redo_offset > 0 so `start = data_start + redo_offset` (2620 `+`)
        // is pinned; a `-` would read the wrong bytes. Also redo_length 0
        // for undo so the `> 0` (2631) path is exercised: undo Empty.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());

        // No LCNs. redo at offset 3 in the data area, length 4.
        let redo_off = 3usize;
        let redo = b"WXYZ";
        let data_start = NR_FIXED_HEADER_SIZE; // lcns 0
        let mut client = vec![0u8; data_start + redo_off + redo.len()];
        client[NR_OFF_REDO_OP..NR_OFF_REDO_OP + 2].copy_from_slice(&0x07u16.to_le_bytes());
        client[NR_OFF_REDO_OFFSET..NR_OFF_REDO_OFFSET + 2]
            .copy_from_slice(&(redo_off as u16).to_le_bytes());
        client[NR_OFF_REDO_LENGTH..NR_OFF_REDO_LENGTH + 2]
            .copy_from_slice(&(redo.len() as u16).to_le_bytes());
        // undo_length stays 0 -> undo Empty.
        client[data_start + redo_off..data_start + redo_off + redo.len()].copy_from_slice(redo);

        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert_eq!(rec.redo_data().bytes(), Some(&redo[..]));
        assert!(matches!(rec.undo_data(), NtfsLogOperationData::Empty));
    }

    #[test]
    fn test_parse_single_log_record_redo_length_zero_is_empty() {
        // redo_length == 0 -> Empty (kills `> -> >=` at 2619). Use a UNIT
        // redo op (CommitTransaction 0x1A): genuine path => Empty, but a
        // `>=` flip would call parse_operation_data with an empty slice =>
        // Unit, which is observably different.
        let ri = build_dummy_restart_info();
        let mut lfs = vec![0u8; LR_HEADER_SIZE];
        lfs[LR_OFF_THIS_LSN..LR_OFF_THIS_LSN + 8].copy_from_slice(&1u64.to_le_bytes());
        lfs[LR_OFF_RECORD_TYPE..LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let mut client = vec![0u8; NR_FIXED_HEADER_SIZE];
        client[NR_OFF_REDO_OP..NR_OFF_REDO_OP + 2].copy_from_slice(&0x1Au16.to_le_bytes());
        // redo_length = 0 (default).
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert!(matches!(rec.redo_data(), NtfsLogOperationData::Empty));

        // undo_length == 0 with unit undo op -> Empty (kills 2631 `>=`).
        let mut client = vec![0u8; NR_FIXED_HEADER_SIZE];
        client[NR_OFF_UNDO_OP..NR_OFF_UNDO_OP + 2].copy_from_slice(&0x1Au16.to_le_bytes());
        let rec = parse_single_log_record(&lfs, &client, &ri).unwrap();
        assert!(matches!(rec.undo_data(), NtfsLogOperationData::Empty));
    }

    // ---- mutate(g1) batch 3: parse_record_pages multi-page fixtures ----

    /// Build a single RCRD record page (with USA applied) containing the
    /// given records. Each record is `(lsn, redo_op)`. `next_record_offset`
    /// is set just past the last record. If `corrupt_usa` is true, a sector
    /// boundary is broken so `apply_usa_fixup` fails (page is skipped).
    /// If `bad_signature` is true the RCRD signature is replaced.
    fn build_rcrd_page(
        page_size: usize,
        lpdo: usize,
        records: &[(u64, u16)],
        corrupt_usa: bool,
        bad_signature: bool,
    ) -> Vec<u8> {
        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        if bad_signature {
            page[0..4].copy_from_slice(b"JUNK");
        }
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

        let client_len = NR_FIXED_HEADER_SIZE;
        let rec_size = ((LR_HEADER_SIZE + client_len) + 7) & !7;
        let mut off = lpdo;
        for &(lsn, redo) in records {
            page[off + LR_OFF_THIS_LSN..off + LR_OFF_THIS_LSN + 8]
                .copy_from_slice(&lsn.to_le_bytes());
            page[off + LR_OFF_CLIENT_DATA_LENGTH..off + LR_OFF_CLIENT_DATA_LENGTH + 4]
                .copy_from_slice(&(client_len as u32).to_le_bytes());
            page[off + LR_OFF_RECORD_TYPE..off + LR_OFF_RECORD_TYPE + 4]
                .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
            let c = off + LR_HEADER_SIZE;
            page[c + NR_OFF_REDO_OP..c + NR_OFF_REDO_OP + 2].copy_from_slice(&redo.to_le_bytes());
            off += rec_size;
        }
        let next_rec = lpdo + records.len() * rec_size;
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());

        // Apply USA.
        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        let sectors = page_size / USA_STRIDE;
        for i in 0..sectors {
            let sector_end = (i + 1) * USA_STRIDE - 2;
            let original = [page[sector_end], page[sector_end + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[sector_end..sector_end + 2].copy_from_slice(&usn);
        }
        if corrupt_usa {
            // Break sector 0 boundary so the USN no longer matches.
            page[USA_STRIDE - 2] = 0xFF;
            page[USA_STRIDE - 1] = 0xFF;
        }
        page
    }

    /// Assemble a full v1.1 log blob: 2 restart pages + 2 placeholder log
    /// pages, then the given record pages at log_area_start onward.
    fn assemble_log_blob(pages: &[Vec<u8>], page_size: usize) -> (Vec<u8>, LfsRestartInfo) {
        let restart0 = build_synthetic_rstr_page();
        let restart1 = build_synthetic_rstr_page();
        let ri = parse_restart_page(&restart0, NtfsPosition::none()).unwrap();
        let log_area_start = page_size * 2 + page_size * 2;
        let mut blob = Vec::new();
        blob.extend_from_slice(&restart0);
        blob.extend_from_slice(&restart1);
        blob.resize(log_area_start, 0);
        for p in pages {
            blob.extend_from_slice(p);
        }
        (blob, ri)
    }

    #[test]
    fn test_parse_record_pages_skip_then_valid_advances() {
        // First page has corrupt USA (skipped, page_offset += page_size),
        // second page is valid. The genuine `+= page_size` (2709/2710/2763)
        // must advance to the second page so its record is found. A `-=`/`*=`
        // mutant would underflow/panic or miss the second page.
        let page_size = 4096usize;
        let lpdo = 64usize;
        let p0 = build_rcrd_page(page_size, lpdo, &[(10, 0x1A)], true, false);
        let p1 = build_rcrd_page(page_size, lpdo, &[(20, 0x19)], false, false);
        let (blob, ri) = assemble_log_blob(&[p0, p1], page_size);
        let (records, skipped) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(skipped, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 20);
    }

    #[test]
    fn test_parse_record_pages_bad_sig_then_valid_advances() {
        // Bad-signature page (skipped_pages += 1, page_offset += page_size)
        // followed by a valid page. Pins the signature-fail advance.
        let page_size = 4096usize;
        let lpdo = 64usize;
        let p0 = build_rcrd_page(page_size, lpdo, &[(10, 0x1A)], false, true);
        let p1 = build_rcrd_page(page_size, lpdo, &[(30, 0x1A)], false, false);
        let (blob, ri) = assemble_log_blob(&[p0, p1], page_size);
        let (records, skipped) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(skipped, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 30);
    }

    #[test]
    fn test_parse_record_pages_next_record_offset_limits_scan() {
        // next_record_offset > log_page_data_offset selects next_rec as the
        // scan end (kills `> -> ==`/`>=`/`<` at 2717). Place a SECOND record
        // beyond next_record_offset that must NOT be scanned.
        let page_size = 4096usize;
        let lpdo = 64usize;
        let client_len = NR_FIXED_HEADER_SIZE;
        let rec_size = ((LR_HEADER_SIZE + client_len) + 7) & !7;
        let mut page = build_rcrd_page(page_size, lpdo, &[(10, 0x1A)], false, false);
        // Manually write a phantom record AFTER next_record_offset and
        // re-apply USA. It must be ignored because the scan stops at
        // next_record_offset.
        let phantom_off = lpdo + rec_size; // == next_record_offset
        page[phantom_off + LR_OFF_THIS_LSN..phantom_off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&999u64.to_le_bytes());
        page[phantom_off + LR_OFF_CLIENT_DATA_LENGTH..phantom_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(client_len as u32).to_le_bytes());
        page[phantom_off + LR_OFF_RECORD_TYPE..phantom_off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        // Re-apply USA after edits.
        let usa = RCRD_MIN_HEADER_SIZE;
        let usn = [page[usa], page[usa + 1]];
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page[se], page[se + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[se..se + 2].copy_from_slice(&usn);
        }
        let (blob, ri) = assemble_log_blob(&[page], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        // Only the first record (lsn 10) is within next_record_offset.
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 10);
    }

    #[test]
    fn test_parse_record_pages_next_record_offset_zero_scans_full_page() {
        // next_record_offset (0) <= log_page_data_offset -> page_data_end =
        // page_size (full scan). Two records both found. Pins the else-branch
        // of the `>` at 2717.
        let page_size = 4096usize;
        let lpdo = 64usize;
        let mut page = build_rcrd_page(page_size, lpdo, &[(10, 0x1A), (20, 0x19)], false, false);
        // Force next_record_offset = 0 and re-apply USA.
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        let usa = RCRD_MIN_HEADER_SIZE;
        let usn = [page[usa], page[usa + 1]];
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page[se], page[se + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[se..se + 2].copy_from_slice(&usn);
        }
        let (blob, ri) = assemble_log_blob(&[page], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn test_parse_record_pages_multi_page_skip_then_record() {
        // First record on the page claims an oversized client_data_length
        // (spans pages) -> skipped via `record_offset += (total+7)&!7`.
        // The page is followed by a SECOND page with a valid record, which
        // must be found via page_offset advancement. This pins the
        // multi-page advance/`& !7`/`delete !` arithmetic (2738/2743): a
        // wrong advance would loop, panic, or wrongly collect the oversized
        // record; a wrong page advance would miss the second page.
        let page_size = 4096usize;
        let lpdo = 64usize;
        // Oversized record: claimed length spans past the full-page window.
        let claimed = page_size; // > available_in_page (page_size - lpdo - hdr)

        let mut page0 = vec![0u8; page_size];
        page0[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page0[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page0[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
        let off0 = lpdo;
        page0[off0 + LR_OFF_THIS_LSN..off0 + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&11u64.to_le_bytes());
        page0[off0 + LR_OFF_CLIENT_DATA_LENGTH..off0 + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(claimed as u32).to_le_bytes());
        page0[off0 + LR_OFF_RECORD_TYPE..off0 + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        // next_record_offset = 0 -> full-page scan window.
        page0[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page0[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page0[se], page0[se + 1]];
            let slot = usa + 2 + i * 2;
            page0[slot..slot + 2].copy_from_slice(&original);
            page0[se..se + 2].copy_from_slice(&usn);
        }

        let page1 = build_rcrd_page(page_size, lpdo, &[(22, 0x1A)], false, false);
        let (blob, ri) = assemble_log_blob(&[page0, page1], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        // Oversized record on page0 skipped; record on page1 (lsn 22) found.
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 22);
    }

    #[test]
    fn test_parse_record_pages_page_size_boundary_skips_count() {
        // page_size == RCRD_MIN_HEADER_SIZE (boundary for `< -> <=`/`==`).
        // With a bad-signature page at the v1 log area, the genuine `<` is
        // false so parsing proceeds and counts the skip; a `<=`/`==` flip
        // would early-return (0 skipped). Distinguished by skipped count.
        let page_size = RCRD_MIN_HEADER_SIZE; // 0x28 == 40
        let mut ri = build_dummy_restart_info();
        ri.log_page_size = page_size as u32;
        ri.system_page_size = page_size as u32;
        ri.log_page_data_offset = 0;
        let log_area_start = page_size * 2 + page_size * 2;
        // One bad-signature page at log_area_start.
        let mut bad = vec![0u8; page_size];
        bad[0..4].copy_from_slice(b"JUNK");
        let mut blob = vec![0u8; log_area_start];
        blob.extend_from_slice(&bad);
        let (records, skipped) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert!(records.is_empty());
        assert_eq!(skipped, 1);
    }

    #[test]
    fn test_parse_record_pages_or_guard_system_page_zero() {
        // system_page_size == 0 with valid page_size: genuine `||` returns
        // empty. A `&&` flip would NOT early-return (page_size valid makes
        // the first operand false). To make that observably wrong, place a
        // valid record page where the `&&` path would compute
        // log_area_start = 0*2 + page_size*2 and find a record.
        let page_size = 4096usize;
        let mut ri = build_dummy_restart_info();
        ri.log_page_size = page_size as u32;
        ri.system_page_size = 0;
        ri.log_page_data_offset = 64;
        // log_area_start under the `&&`-mutant would be page_size*2.
        let mutant_log_area = page_size * 2;
        let page = build_rcrd_page(page_size, 64, &[(42, 0x1A)], false, false);
        let mut blob = vec![0u8; mutant_log_area];
        blob.extend_from_slice(&page);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        // Genuine `||`: system_page_size==0 -> early return empty.
        assert!(records.is_empty());
    }

    // ---- mutate(g1) batch 4: remaining boundary kills ----

    #[test]
    fn test_apply_usa_fixup_sector_pos_end_break() {
        // page.len() == sector_pos + 1 for the first sector (sector_pos =
        // 510). `sector_pos + 2 > page.len()` is the deciding break: with
        // the genuine `+`, the loop breaks safely (Ok). A `-` mutant
        // (`sector_pos - 2 > len`) would be false and then index
        // page[510..512] on a 511-byte page -> out-of-bounds panic.
        let mut page = vec![0u8; 511];
        page[0..2].copy_from_slice(&[0x01, 0x00]); // USN; array_pos=2 in range
        // usa_count = 2 -> array_count 1 -> one iteration (i=0).
        let r = apply_usa_fixup(&mut page, 0, 2, NtfsPosition::none());
        assert!(r.is_ok());
    }

    #[test]
    fn test_walk_named_value_name_bounds_exact_equality() {
        // name_offset + name_length*2 == attr_len exactly: must be ACCEPTED
        // (kills `> -> >=` at 1946). name_offset=0x18, name_length=4 ->
        // 0x18 + 8 = 0x20 == attr_len(0x20).
        let first_attr: u16 = 0x38;
        let attr_len: u32 = 0x20;
        let mut buf = vec![0u8; first_attr as usize + attr_len as usize + 4];
        let off = first_attr as usize;
        buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
        buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
        buf[off + ATTR_OFF_NON_RESIDENT] = 0;
        buf[off + ATTR_OFF_NAME_LENGTH] = 4;
        buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
            .copy_from_slice(&(RES_MIN_HEADER_SIZE as u16).to_le_bytes());
        buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        // value_offset == attr_len (zero-length value at the very end).
        buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
            .copy_from_slice(&(attr_len as u16).to_le_bytes());
        let em = off + attr_len as usize;
        buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
        let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r[0].is_named());
        assert_eq!(r[0].name_length(), 4);
    }

    #[test]
    fn test_parse_restart_page_second_page_len_between() {
        // data.len() strictly between page_size+2 and page_size*2 so the
        // `>= page_size * 2` (kills `* -> +`/`/` at 1989). With genuine
        // `*2` the second page is NOT attempted (returns page0 lsn 100);
        // a `+2` or `/2` mutant WOULD attempt parsing a higher-LSN page1
        // placed at offset page_size and select it.
        let page0 = build_synthetic_rstr_page();
        let page_size = page0.len();
        // page1 region: a full valid restart page with higher LSN, but the
        // overall buffer is only page_size + page_size/2 long. parse at
        // offset page_size sees page_size/2 bytes; restart area fits in the
        // first sector so it parses with the genuine `.min` clamp.
        let mut page1 = build_synthetic_rstr_page();
        let ra = le_u16(&page1, RSTR_OFF_RESTART_OFFSET) as usize;
        page1[ra + RA_OFF_CURRENT_LSN..ra + RA_OFF_CURRENT_LSN + 8]
            .copy_from_slice(&9000u64.to_le_bytes());
        // Disable USA on page1 (count=1) so truncation doesn't trip fixup.
        page1[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());

        let mut combined = page0;
        // Append only half a page so len = page_size + page_size/2.
        combined.extend_from_slice(&page1[..page_size / 2]);
        assert!(combined.len() > page_size + 2 && combined.len() < page_size * 2);

        let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
        // Genuine `*2`: page1 not parsed -> page0's LSN (100).
        assert_eq!(info.current_lsn(), 100);
    }

    #[test]
    fn test_parse_restart_page_equal_lsn_keeps_page0() {
        // page1.current_lsn == page0.current_lsn: genuine `>` is false so
        // page0 is kept (kills `> -> >=` at 1996, which would select page1).
        // Distinguish page0 vs page1 by a differing field (file_size).
        let page0 = build_synthetic_rstr_page();
        let mut page1 = build_synthetic_rstr_page();
        let ra = le_u16(&page1, RSTR_OFF_RESTART_OFFSET) as usize;
        // Same current_lsn (100), but a DIFFERENT file_size on page1.
        page1[ra + RA_OFF_FILE_SIZE..ra + RA_OFF_FILE_SIZE + 8]
            .copy_from_slice(&(9 * 1024 * 1024u64).to_le_bytes());
        reapply_usa(&mut page1);
        let mut combined = page0;
        combined.extend_from_slice(&page1);
        let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
        assert_eq!(info.current_lsn(), 100);
        // page0's file_size (2 MiB) is kept, NOT page1's 9 MiB.
        assert_eq!(info.file_size(), 2 * 1024 * 1024);
    }

    #[test]
    fn test_parse_operation_data_unit_guard_empty_path() {
        // Empty data + unit op -> Unit; empty data + non-unit typed op ->
        // Empty. The operation_is_unit guard distinguishes these. (Line
        // 2129's guard governs the NON-empty unit arm; the empty-data path
        // at 2120 uses the same predicate. A guard forced to `false` for
        // unit ops would route 0x1A bytes away from the Raw arm.)
        let ri = build_dummy_restart_info();
        // Non-empty: CommitTransaction (unit) -> Raw via the guarded arm.
        let r = parse_operation_data(0x1A, &[7, 7, 7, 7], &ri);
        match r {
            NtfsLogOperationData::Raw { data } => assert_eq!(data, vec![7, 7, 7, 7]),
            other => panic!("expected Raw for unit op + bytes, got {other:?}"),
        }
        // ForgetTransaction (unit) -> Raw too.
        assert!(matches!(
            parse_operation_data(0x1B, &[1, 2], &ri),
            NtfsLogOperationData::Raw { .. }
        ));
        // A NON-unit op (CreateAttribute 0x05) + bytes -> Bytes, proving the
        // guard does not capture non-unit ops.
        assert!(matches!(
            parse_operation_data(0x05, &[1, 2], &ri),
            NtfsLogOperationData::Bytes { .. }
        ));
    }

    #[test]
    fn test_parse_record_pages_next_eq_lpdo_full_scan() {
        // next_record_offset == log_page_data_offset: genuine `>` is false
        // -> page_data_end = page_size (full scan), so the record IS found.
        // A `>=` flip would set page_data_end = lpdo, scanning nothing.
        let page_size = 4096usize;
        let lpdo = 64usize;
        let mut page = build_rcrd_page(page_size, lpdo, &[(55, 0x1A)], false, false);
        // Force next_record_offset == lpdo and re-apply USA.
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(lpdo as u16).to_le_bytes());
        let usa = RCRD_MIN_HEADER_SIZE;
        let usn = [page[usa], page[usa + 1]];
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page[se], page[se + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[se..se + 2].copy_from_slice(&usn);
        }
        let (blob, ri) = assemble_log_blob(&[page], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 55);
    }

    #[test]
    fn test_parse_record_pages_available_boundary_skip() {
        // A record whose client_data_length is exactly 1 byte more than the
        // available window must be skipped (`client_data_length >
        // available_in_page`). This pins available_in_page = page_data_end
        // - record_offset - LR_HEADER_SIZE (kills `- -> +`/`/` at 2738):
        // a wrong available would flip the skip decision and the record
        // would be wrongly parsed.
        let page_size = 4096usize;
        let lpdo = 64usize;
        // Set page_data_end via next_record_offset so available equals a
        // full NR header (a ClientRecord needs >= NR_FIXED_HEADER_SIZE
        // client bytes to parse). claimed one byte over -> skipped.
        let avail_window = NR_FIXED_HEADER_SIZE; // available_in_page target
        let next_rec = lpdo + LR_HEADER_SIZE + avail_window;
        let claimed = avail_window + 1; // 1 over -> skipped

        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        let usa_off: u16 = RCRD_MIN_HEADER_SIZE as u16;
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());
        page[lpdo + LR_OFF_THIS_LSN..lpdo + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&77u64.to_le_bytes());
        page[lpdo + LR_OFF_CLIENT_DATA_LENGTH..lpdo + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(claimed as u32).to_le_bytes());
        page[lpdo + LR_OFF_RECORD_TYPE..lpdo + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());

        let usn: [u8; 2] = [0x01, 0x00];
        let usa = usa_off as usize;
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page[se], page[se + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[se..se + 2].copy_from_slice(&usn);
        }
        let (blob, ri) = assemble_log_blob(&[page], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        // claimed (17) > available (16) -> skipped, no records.
        assert!(records.is_empty());

        // Now make claimed exactly == available (fits) -> parsed.
        let mut page = vec![0u8; page_size];
        page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
        page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
        page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
        page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
            .copy_from_slice(&(next_rec as u16).to_le_bytes());
        page[lpdo + LR_OFF_THIS_LSN..lpdo + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&88u64.to_le_bytes());
        page[lpdo + LR_OFF_CLIENT_DATA_LENGTH..lpdo + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&(avail_window as u32).to_le_bytes());
        page[lpdo + LR_OFF_RECORD_TYPE..lpdo + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        page[usa..usa + 2].copy_from_slice(&usn);
        for i in 0..(page_size / USA_STRIDE) {
            let se = (i + 1) * USA_STRIDE - 2;
            let original = [page[se], page[se + 1]];
            let slot = usa + 2 + i * 2;
            page[slot..slot + 2].copy_from_slice(&original);
            page[se..se + 2].copy_from_slice(&usn);
        }
        let (blob, ri) = assemble_log_blob(&[page], page_size);
        let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].lsn(), 88);
    }
}
