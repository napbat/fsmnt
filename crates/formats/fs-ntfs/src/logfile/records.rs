use super::{
    FN_FIXED_SIZE, FN_OFF_ACCESS_TIME, FN_OFF_ALLOCATED_SIZE, FN_OFF_CREATION_TIME,
    FN_OFF_DATA_SIZE, FN_OFF_FILE_ATTRIBUTES, FN_OFF_MFT_MODIFIED, FN_OFF_MODIFICATION,
    FN_OFF_NAME_LENGTH, FN_OFF_NAMESPACE, FN_OFF_PARENT_REF, LogFileRecordView, NtfsError,
    NtfsPosition, RESTART_CLEAN_DISMOUNT, Result, String, Vec, fmt, le_u16, le_u32, le_u64,
};

/// NTFS `$LogFile` operation codes.
///
/// Each log record contains a redo and an undo operation that describe
/// the forward and backward transformation for crash recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum NtfsLogOperation {
    /// Performs no filesystem mutation.
    Noop = 0x00,
    /// Compensates for an earlier operation during rollback.
    CompensationLogRecord = 0x01,
    /// Initializes a newly allocated MFT file-record segment.
    InitializeFileRecordSegment = 0x02,
    /// Deallocates an MFT file-record segment.
    DeallocateFileRecordSegment = 0x03,
    /// Updates the used end of an MFT file-record segment.
    WriteEndOfFileRecordSegment = 0x04,
    /// Creates an attribute within a file record.
    CreateAttribute = 0x05,
    /// Deletes an attribute from a file record.
    DeleteAttribute = 0x06,
    /// Replaces bytes in a resident attribute value.
    UpdateResidentValue = 0x07,
    /// Replaces bytes in a non-resident attribute value.
    UpdateNonresidentValue = 0x08,
    /// Updates a non-resident attribute's mapping pairs.
    UpdateMappingPairs = 0x09,
    /// Removes clusters from the dirty-page tracking table.
    DeleteDirtyClusters = 0x0A,
    /// Updates an attribute's allocated, valid, and data sizes.
    SetNewAttributeSizes = 0x0B,
    /// Adds an entry to a resident index root.
    AddIndexEntryRoot = 0x0C,
    /// Deletes an entry from a resident index root.
    DeleteIndexEntryRoot = 0x0D,
    /// Adds an entry to a non-resident index allocation.
    AddIndexEntryAllocation = 0x0E,
    /// Deletes an entry from a non-resident index allocation.
    DeleteIndexEntryAllocation = 0x0F,
    /// Updates the used end of an index buffer.
    WriteEndOfIndexBuffer = 0x10,
    /// Sets the child VCN stored in an index-root entry.
    SetIndexEntryVcnRoot = 0x11,
    /// Sets the child VCN stored in an index-allocation entry.
    SetIndexEntryVcnAllocation = 0x12,
    /// Updates a file-name key in an index root.
    UpdateFileNameRoot = 0x13,
    /// Updates a file-name key in an index allocation.
    UpdateFileNameAllocation = 0x14,
    /// Marks a range of bits in a non-resident bitmap.
    SetBitsInNonresidentBitMap = 0x15,
    /// Clears a range of bits in a non-resident bitmap.
    ClearBitsInNonresidentBitMap = 0x16,
    /// Records relocation of data away from a damaged cluster.
    HotFix = 0x17,
    /// Closes the current top-level logged action.
    EndTopLevelAction = 0x18,
    /// Marks a transaction as prepared.
    PrepareTransaction = 0x19,
    /// Marks a transaction as committed.
    CommitTransaction = 0x1A,
    /// Releases bookkeeping for a completed transaction.
    ForgetTransaction = 0x1B,
    /// Records opening a non-resident attribute.
    OpenNonresidentAttribute = 0x1C,
    /// Captures an open-attribute table checkpoint.
    OpenAttributeTableDump = 0x1D,
    /// Captures attribute names associated with open table entries.
    AttributeNamesDump = 0x1E,
    /// Captures the dirty-page table checkpoint.
    DirtyPageTableDump = 0x1F,
    /// Captures the transaction table checkpoint.
    TransactionTableDump = 0x20,
    /// Updates record data stored in an index root.
    UpdateRecordDataRoot = 0x21,
    /// Updates record data stored in an index allocation.
    UpdateRecordDataAllocation = 0x22,
    /// Updates relative index data in a resident root.
    UpdateRelativeDataIndex = 0x23,
    /// Updates relative index data in a non-resident allocation.
    UpdateRelativeDataAllocation = 0x24,
    /// Zeroes the unused tail of an MFT file record.
    ZeroEndOfFileRecord = 0x25,
}

impl NtfsLogOperation {
    /// Convert a raw `u16` operation code to a known variant, or
    /// `None` if the code is unrecognized.
    #[must_use]
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
    pub(super) major_version: u16,
    pub(super) minor_version: u16,
    pub(super) current_lsn: u64,
    pub(super) file_size: u64,
    pub(super) seq_number_bits: u32,
    pub(super) log_page_size: u32,
    pub(super) system_page_size: u32,
    pub(super) log_page_data_offset: u16,
    pub(super) flags: u16,
    pub(super) client_name: String,
}

impl LfsRestartInfo {
    /// LFS major version (1 or 2).
    #[must_use]
    pub fn major_version(&self) -> u16 {
        self.major_version
    }

    /// LFS minor version.
    #[must_use]
    pub fn minor_version(&self) -> u16 {
        self.minor_version
    }

    /// Most recent LSN at the time the restart page was written.
    #[must_use]
    pub fn current_lsn(&self) -> u64 {
        self.current_lsn
    }

    /// Total log file size in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Bits reserved for the sequence number portion of an LSN.
    #[must_use]
    pub fn seq_number_bits(&self) -> u32 {
        self.seq_number_bits
    }

    /// Size of each log record page in bytes (typically 4096).
    #[must_use]
    pub fn log_page_size(&self) -> u32 {
        self.log_page_size
    }

    /// Size of each restart page in bytes.
    #[must_use]
    pub fn system_page_size(&self) -> u32 {
        self.system_page_size
    }

    /// Whether the log was cleanly dismounted.
    #[must_use]
    pub fn is_clean_dismount(&self) -> bool {
        self.flags & RESTART_CLEAN_DISMOUNT != 0
    }

    /// The LFS client name (always "NTFS" for NTFS volumes).
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.client_name
    }
}

/// NTFS client restart area (checkpoint data).
#[derive(Clone, Debug)]
pub struct NtfsClientRestartArea {
    pub(super) major_version: u32,
    pub(super) minor_version: u32,
    pub(super) start_of_checkpoint_lsn: u64,
    pub(super) open_attribute_table_lsn: u64,
    pub(super) attribute_names_lsn: u64,
    pub(super) dirty_page_table_lsn: u64,
    pub(super) transaction_table_lsn: u64,
}

impl NtfsClientRestartArea {
    /// NTFS client format major version (0 or 1).
    #[must_use]
    pub fn major_version(&self) -> u32 {
        self.major_version
    }

    /// NTFS client format minor version.
    #[must_use]
    pub fn minor_version(&self) -> u32 {
        self.minor_version
    }

    /// LSN of the start of the last checkpoint.
    #[must_use]
    pub fn start_of_checkpoint_lsn(&self) -> u64 {
        self.start_of_checkpoint_lsn
    }

    /// LSN of the open attribute table dump (0 if absent).
    #[must_use]
    pub fn open_attribute_table_lsn(&self) -> u64 {
        self.open_attribute_table_lsn
    }

    /// LSN of the attribute names dump (0 if absent).
    #[must_use]
    pub fn attribute_names_lsn(&self) -> u64 {
        self.attribute_names_lsn
    }

    /// LSN of the dirty page table dump (0 if absent).
    #[must_use]
    pub fn dirty_page_table_lsn(&self) -> u64 {
        self.dirty_page_table_lsn
    }

    /// LSN of the transaction table dump (0 if absent).
    #[must_use]
    pub fn transaction_table_lsn(&self) -> u64 {
        self.transaction_table_lsn
    }
}

/// An entry in the open attribute table, mapping a target attribute
/// index to a file reference and attribute type.
#[derive(Clone, Debug)]
pub struct OpenAttributeEntry {
    pub(super) file_reference: u64,
    pub(super) lsn_of_open_record: u64,
    pub(super) attribute_type: u32,
    pub(super) bytes_per_index_buffer: u32,
}

impl OpenAttributeEntry {
    /// The MFT file reference for this open attribute.
    #[must_use]
    pub fn file_reference(&self) -> u64 {
        self.file_reference
    }

    /// LSN of the log record that opened this attribute.
    #[must_use]
    pub fn lsn_of_open_record(&self) -> u64 {
        self.lsn_of_open_record
    }

    /// The attribute type code.
    #[must_use]
    pub fn attribute_type_code(&self) -> u32 {
        self.attribute_type
    }

    /// Bytes per index buffer (for index attributes).
    #[must_use]
    pub fn bytes_per_index_buffer(&self) -> u32 {
        self.bytes_per_index_buffer
    }
}

/// An entry mapping an open attribute index to its Unicode name.
#[derive(Clone, Debug)]
pub struct AttributeNameEntry {
    pub(super) index: u16,
    pub(super) name: String,
}

impl AttributeNameEntry {
    /// The open attribute table index this name belongs to.
    #[must_use]
    pub fn index(&self) -> u16 {
        self.index
    }

    /// The Unicode attribute name.
    #[must_use]
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
    pub(super) entry_index: u32,
    pub(super) allocated_or_next_free: u32,
    pub(super) transaction_state: u32,
    pub(super) first_lsn: u64,
    pub(super) previous_lsn: u64,
    pub(super) undo_next_lsn: u64,
    pub(super) undo_records: u32,
    pub(super) undo_bytes: u32,
}

impl TransactionTableDumpEntry {
    /// Slot position in the transaction table array.
    #[must_use]
    pub fn entry_index(&self) -> u32 {
        self.entry_index
    }

    /// Allocation marker. In-use if `== 0xFFFF_FFFF`.
    #[must_use]
    pub fn allocated_or_next_free(&self) -> u32 {
        self.allocated_or_next_free
    }

    /// Raw transaction state value.
    #[must_use]
    pub fn raw_state(&self) -> u32 {
        self.transaction_state
    }

    /// True if transaction state is Active (1).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.transaction_state == 1
    }

    /// True if transaction state is Prepared (2).
    #[must_use]
    pub fn is_prepared(&self) -> bool {
        self.transaction_state == 2
    }

    /// True if transaction state is Committed (3).
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.transaction_state == 3
    }

    /// First LSN for this transaction.
    #[must_use]
    pub fn first_lsn(&self) -> u64 {
        self.first_lsn
    }

    /// Previous (most recent) LSN in the transaction chain.
    #[must_use]
    pub fn previous_lsn(&self) -> u64 {
        self.previous_lsn
    }

    /// Next LSN to process during undo/rollback.
    #[must_use]
    pub fn undo_next_lsn(&self) -> u64 {
        self.undo_next_lsn
    }

    /// Count of pending undo records.
    #[must_use]
    pub fn undo_records(&self) -> u32 {
        self.undo_records
    }

    /// Total bytes in pending undo records.
    #[must_use]
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
#[allow(
    clippy::struct_excessive_bools,
    reason = "the booleans record independent transaction lifecycle observations"
)]
pub struct TransactionEntry {
    pub(super) transaction_id: u32,
    pub(super) state: TransactionState,
    pub(super) seeded_from_dump: bool,
    pub(super) first_lsn: u64,
    pub(super) last_lsn: u64,
    pub(super) undo_next_lsn: Option<u64>,
    pub(super) operation_count: u32,
    pub(super) saw_prepare: bool,
    pub(super) saw_commit: bool,
    pub(super) saw_forget: bool,
    pub(super) forgotten_lsn: Option<u64>,
    pub(super) recycled: bool,
    pub(super) recycle_lsn: Option<u64>,
}

impl TransactionEntry {
    /// Transaction table slot index.
    #[must_use]
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// True if seeded from checkpoint `TransactionTableDump`.
    #[must_use]
    pub fn seeded_from_dump(&self) -> bool {
        self.seeded_from_dump
    }

    /// Earliest LSN observed for this transaction.
    #[must_use]
    pub fn first_lsn(&self) -> u64 {
        self.first_lsn
    }

    /// Latest LSN observed for this transaction.
    #[must_use]
    pub fn last_lsn(&self) -> u64 {
        self.last_lsn
    }

    /// Latest undo chain pointer. `None` when absent (raw 0).
    #[must_use]
    pub fn undo_next_lsn(&self) -> Option<u64> {
        self.undo_next_lsn
    }

    /// Payload-carrying redo operations (not Unit or Empty).
    #[must_use]
    pub fn operation_count(&self) -> u32 {
        self.operation_count
    }

    /// Evidence of `PrepareTransaction` (dump or scan).
    #[must_use]
    pub fn saw_prepare(&self) -> bool {
        self.saw_prepare
    }

    /// Evidence of `CommitTransaction` (dump or scan).
    #[must_use]
    pub fn saw_commit(&self) -> bool {
        self.saw_commit
    }

    /// Evidence of `ForgetTransaction` (dump or scan).
    #[must_use]
    pub fn saw_forget(&self) -> bool {
        self.saw_forget
    }

    /// True if `CommitTransaction` was observed.
    #[must_use]
    pub fn is_committed(&self) -> bool {
        self.saw_commit
    }

    /// True if `ForgetTransaction` was observed.
    #[must_use]
    pub fn is_forgotten(&self) -> bool {
        self.saw_forget
    }

    /// True if the transaction never reached end-of-life.
    #[must_use]
    pub fn is_incomplete(&self) -> bool {
        !self.saw_forget
    }

    /// LSN of the `ForgetTransaction` record, if seen.
    #[must_use]
    pub fn forgotten_lsn(&self) -> Option<u64> {
        self.forgotten_lsn
    }

    /// True if activity was observed after `ForgetTransaction`
    /// (transaction ID was recycled).
    #[must_use]
    pub fn recycled(&self) -> bool {
        self.recycled
    }

    /// LSN of first record after `ForgetTransaction` (recycling).
    #[must_use]
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
    Raw {
        /// Uninterpreted bytes preserved for callers.
        data: Vec<u8>,
    },
    /// `SetNewAttributeSizes` (0x0B) -- parsed size fields.
    SetNewAttributeSizes {
        /// Reserved space allocated to the attribute.
        allocated_length: u64,
        /// Logical length visible to readers.
        data_length: u64,
        /// Prefix containing initialized data.
        valid_data_length: u64,
        /// Total allocation recorded for compressed or sparse data.
        total_allocated: u64,
    },
    /// `SetBitsInNonresidentBitMap` (0x15) -- bitmap range.
    SetBits {
        /// First bit affected by the operation.
        bit_offset: u32,
        /// Number of consecutive bits to set.
        num_bits: u32,
    },
    /// `ClearBitsInNonresidentBitMap` (0x16) -- bitmap range.
    ClearBits {
        /// First bit affected by the operation.
        bit_offset: u32,
        /// Number of consecutive bits to clear.
        num_bits: u32,
    },
    /// `OpenNonresidentAttribute` (0x1C) -- file ref + type.
    OpenNonresidentAttribute {
        /// MFT reference of the file containing the attribute.
        file_reference: u64,
        /// Raw NTFS attribute type code.
        attribute_type: u32,
        /// Optional UTF-16 attribute name decoded to UTF-8.
        name: Option<String>,
    },
    /// `OpenAttributeTableDump` (0x1D) -- parsed entries.
    OpenAttributeTableDump {
        /// Open attributes captured by the checkpoint.
        entries: Vec<OpenAttributeEntry>,
    },
    /// `AttributeNamesDump` (0x1E) -- parsed entries.
    AttributeNamesDump {
        /// Names associated with open-attribute table slots.
        entries: Vec<AttributeNameEntry>,
    },
    /// Operation that does not carry payload data by design.
    /// Which operation this is comes from the [`NtfsLogRecord`]
    /// operation code.
    Unit,
    /// Complete MFT FILE record from
    /// `InitializeFileRecordSegment`.
    FileRecordSegment {
        /// Complete serialized MFT file-record bytes.
        data: Vec<u8>,
    },
    /// Raw bytes for value updates, attribute operations, mapping
    /// pairs, and other operations whose semantics depend on the
    /// operation code and target fields on [`NtfsLogRecord`].
    Bytes {
        /// Operation-specific payload bytes.
        data: Vec<u8>,
    },
    /// VCN from `SetIndexEntryVcnRoot` (0x11) or
    /// `SetIndexEntryVcnAllocation` (0x12).
    IndexEntryVcn {
        /// Child index-buffer virtual cluster number.
        vcn: u64,
    },
    /// `TransactionTableDump` (0x20) -- parsed entries.
    TransactionTableDump {
        /// Transaction slots captured by the checkpoint.
        entries: Vec<TransactionTableDumpEntry>,
    },
}

impl NtfsLogOperationData {
    /// Returns the raw bytes for `Bytes`, `FileRecordSegment`, or
    /// `Raw` variants. `None` for `Unit`, `Empty`, and typed
    /// variants.
    #[must_use]
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
    #[must_use]
    pub fn file_record_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::FileRecordSegment { data } => Some(data),
            _ => None,
        }
    }

    /// Returns `true` if this is a `Unit` (no-payload) variant.
    #[must_use]
    pub fn is_unit(&self) -> bool {
        matches!(self, Self::Unit)
    }

    /// Returns a lightweight header view over a
    /// `FileRecordSegment` payload.
    ///
    /// Returns `None` if this is not a `FileRecordSegment`.
    /// Returns `Some(Err(...))` if the payload is corrupt or
    /// truncated.
    #[must_use]
    pub fn file_record_view(&self) -> Option<Result<LogFileRecordView<'_>>> {
        match self {
            Self::FileRecordSegment { data } => Some(LogFileRecordView::new(data)),
            _ => None,
        }
    }

    /// Returns the VCN if this is an `IndexEntryVcn`. `None`
    /// otherwise.
    #[must_use]
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
    pub(super) instance: u16,
    pub(super) name_offset: u16,
    pub(super) name_length: u8,
    pub(super) value_offset_in_record: u32,
    pub(super) data: Vec<u8>,
}

impl ResidentDataValue {
    /// Attribute instance number (unique within the FILE record).
    #[must_use]
    pub fn instance(&self) -> u16 {
        self.instance
    }

    /// Offset of the attribute name from the start of the
    /// attribute record. Meaningful only when `is_named()` is
    /// true; unspecified otherwise.
    #[must_use]
    pub fn name_offset(&self) -> u16 {
        self.name_offset
    }

    /// Name length in UTF-16 code units. Zero for the default
    /// unnamed `$DATA` stream.
    #[must_use]
    pub fn name_length(&self) -> u8 {
        self.name_length
    }

    /// Absolute byte offset of the value within the FILE record.
    #[must_use]
    pub fn value_offset_in_record(&self) -> u32 {
        self.value_offset_in_record
    }

    /// The resident value bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Whether this is a named `$DATA` stream (alternate data
    /// stream). Returns `true` when `name_length > 0`.
    #[must_use]
    pub fn is_named(&self) -> bool {
        self.name_length != 0
    }
}

/// Patch bytes from an `UpdateResidentValue` log record
/// targeting a `$DATA` attribute, attributed to a file via the
/// open attribute table.
#[derive(Clone, Debug)]
pub struct ResidentDataPatch<'a> {
    pub(super) file_reference: u64,
    pub(super) target_attribute: u16,
    pub(super) value_offset: u16,
    pub(super) patch_bytes: &'a [u8],
}

impl ResidentDataPatch<'_> {
    /// 8-byte MFT file reference from the OAT entry.
    /// Lower 48 bits are the MFT record number; upper 16 bits
    /// are the sequence number.
    #[must_use]
    pub fn file_reference(&self) -> u64 {
        self.file_reference
    }

    /// OAT index from the log record. Identity key for
    /// correlating patches to the same open attribute.
    #[must_use]
    pub fn target_attribute(&self) -> u16 {
        self.target_attribute
    }

    /// Byte offset within the attribute value where the patch
    /// applies.
    #[must_use]
    pub fn value_offset(&self) -> u16 {
        self.value_offset
    }

    /// The patch bytes (borrowed from the redo payload).
    #[must_use]
    pub fn patch_bytes(&self) -> &[u8] {
        self.patch_bytes
    }

    /// MFT record number (lower 48 bits of `file_reference`).
    #[must_use]
    pub fn mft_record_number(&self) -> u64 {
        self.file_reference & 0x0000_FFFF_FFFF_FFFF
    }
}

/// Parsed `FILE_NAME` attribute fields from an index entry key or
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
    #[must_use]
    pub fn parent_directory_reference(&self) -> u64 {
        self.parent_directory_reference
    }

    /// Parent MFT record number (lower 48 bits).
    #[must_use]
    pub fn parent_mft_record_number(&self) -> u64 {
        self.parent_directory_reference & 0x0000_FFFF_FFFF_FFFF
    }

    /// NTFS creation timestamp (100-ns intervals since 1601).
    #[must_use]
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }

    /// NTFS last-modification timestamp.
    #[must_use]
    pub fn modification_time(&self) -> u64 {
        self.modification_time
    }

    /// MFT record modification timestamp.
    #[must_use]
    pub fn mft_record_modification_time(&self) -> u64 {
        self.mft_record_modification_time
    }

    /// NTFS last-access timestamp.
    #[must_use]
    pub fn access_time(&self) -> u64 {
        self.access_time
    }

    /// Allocated size in bytes.
    #[must_use]
    pub fn allocated_size(&self) -> u64 {
        self.allocated_size
    }

    /// Actual data size in bytes.
    #[must_use]
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    /// DOS file attribute flags.
    #[must_use]
    pub fn file_attributes(&self) -> u32 {
        self.file_attributes
    }

    /// Whether the directory attribute bit (0x10) is set.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_attributes & 0x10 != 0
    }

    /// `FILE_NAME` namespace (0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS).
    #[must_use]
    pub fn namespace(&self) -> u8 {
        self.namespace
    }

    /// Filename as raw UTF-16 code units.
    #[must_use]
    pub fn name(&self) -> &[u16] {
        &self.name
    }

    /// Filename decoded as a lossy UTF-16 string.
    #[must_use]
    pub fn name_string(&self) -> String {
        String::from_utf16_lossy(&self.name)
    }
}

pub(super) fn parse_file_name_fields(
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

    let name_length = usize::from(data[FN_OFF_NAME_LENGTH]);
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
