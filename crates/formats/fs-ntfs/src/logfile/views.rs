use super::parser::usize_from_u32;
use super::{
    ATTR_TYPE_DATA, FILE_SIGNATURE, FR_MIN_HEADER_SIZE, FR_OFF_ALLOCATED_SIZE,
    FR_OFF_BASE_FILE_REFERENCE, FR_OFF_FIRST_ATTRIBUTE_OFFSET, FR_OFF_FLAGS,
    FR_OFF_HARD_LINK_COUNT, FR_OFF_SEQUENCE_NUMBER, FR_OFF_USA_COUNT, FR_OFF_USA_OFFSET,
    FR_OFF_USED_SIZE, IE_FLAG_HAS_SUBNODE, IE_FLAG_LAST_ENTRY, IE_HEADER_SIZE,
    IE_OFF_FILE_REFERENCE, IE_OFF_FLAGS, IE_OFF_INDEX_ENTRY_LENGTH, IE_OFF_KEY_LENGTH,
    LOG_RECORD_MULTI_PAGE, LogFileNameFields, LogRecordType, NtfsError, NtfsLogOperation,
    NtfsLogOperationData, NtfsPosition, OpenAttributeEntry, ResidentDataPatch, ResidentDataValue,
    Result, Vec, apply_usa_fixup, le_u16, le_u32, le_u64, parse_file_name_fields,
    walk_resident_data_attrs,
};

/// Lightweight view into an index entry payload from
/// Add/Delete index entry log operations.
#[derive(Clone, Debug)]
pub struct LogIndexEntryView<'a> {
    data: &'a [u8],
}

impl<'a> LogIndexEntryView<'a> {
    pub(super) fn new(data: &'a [u8]) -> Result<Self> {
        let position = NtfsPosition::none();

        if data.len() < IE_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: index_entry_truncated",
            });
        }

        let entry_length = usize::from(le_u16(data, IE_OFF_INDEX_ENTRY_LENGTH));
        if entry_length < IE_HEADER_SIZE || entry_length > data.len() {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: index_entry_length_invalid",
            });
        }

        let key_length = usize::from(le_u16(data, IE_OFF_KEY_LENGTH));
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
    #[must_use]
    pub fn file_reference(&self) -> u64 {
        le_u64(self.data, IE_OFF_FILE_REFERENCE)
    }

    /// MFT record number (lower 48 bits of `file_reference`).
    #[must_use]
    pub fn mft_record_number(&self) -> u64 {
        self.file_reference() & 0x0000_FFFF_FFFF_FFFF
    }

    /// Total length of this index entry in bytes.
    #[must_use]
    pub fn index_entry_length(&self) -> u16 {
        le_u16(self.data, IE_OFF_INDEX_ENTRY_LENGTH)
    }

    /// Length of the key (`FILE_NAME`) portion in bytes.
    #[must_use]
    pub fn key_length(&self) -> u16 {
        le_u16(self.data, IE_OFF_KEY_LENGTH)
    }

    /// Raw index entry flags.
    #[must_use]
    pub fn flags(&self) -> u16 {
        le_u16(self.data, IE_OFF_FLAGS)
    }

    /// Whether this entry has a subnode VCN pointer.
    #[must_use]
    pub fn has_subnode(&self) -> bool {
        self.flags() & IE_FLAG_HAS_SUBNODE != 0
    }

    /// Whether this is the last (sentinel) entry in the node.
    #[must_use]
    pub fn is_last_entry(&self) -> bool {
        self.flags() & IE_FLAG_LAST_ENTRY != 0
    }

    /// Subnode VCN, if the has-subnode flag is set.
    #[must_use]
    pub fn subnode_vcn(&self) -> Option<u64> {
        if !self.has_subnode() {
            return None;
        }
        let entry_len = usize::from(self.index_entry_length());
        Some(le_u64(self.data, entry_len - 8))
    }

    /// Key bytes (typically a `FILE_NAME` structure), or `None`
    /// for zero-length keys (sentinel entries).
    #[must_use]
    pub fn key_data(&self) -> Option<&[u8]> {
        let key_len = usize::from(self.key_length());
        if key_len == 0 {
            return None;
        }
        Some(&self.data[IE_HEADER_SIZE..IE_HEADER_SIZE + key_len])
    }

    /// Parse the key as a `FILE_NAME` structure.
    /// Returns `None` if the key is empty.
    #[must_use]
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
    #[must_use]
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
    pub(super) fn new(data: &'a [u8]) -> Result<Self> {
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

        if usize_from_u32(allocated_size) > data.len() {
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
        if usize::from(first_attr_offset) < FR_MIN_HEADER_SIZE {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: first_attribute_offset \
                         inside header",
            });
        }
        if u32::from(first_attr_offset) >= used_size {
            return Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: first_attribute_offset \
                         out of bounds",
            });
        }

        Ok(Self { data })
    }

    /// Allocated size of this MFT record in bytes.
    #[must_use]
    pub fn allocated_size(&self) -> u32 {
        le_u32(self.data, FR_OFF_ALLOCATED_SIZE)
    }

    /// Used (logical) size in bytes.
    #[must_use]
    pub fn used_size(&self) -> u32 {
        le_u32(self.data, FR_OFF_USED_SIZE)
    }

    /// Sequence number (incremented each time the record is
    /// reused).
    #[must_use]
    pub fn sequence_number(&self) -> u16 {
        le_u16(self.data, FR_OFF_SEQUENCE_NUMBER)
    }

    /// Hard link count.
    #[must_use]
    pub fn hard_link_count(&self) -> u16 {
        le_u16(self.data, FR_OFF_HARD_LINK_COUNT)
    }

    /// MFT record flags (in-use, directory).
    #[must_use]
    pub fn flags(&self) -> u16 {
        le_u16(self.data, FR_OFF_FLAGS)
    }

    /// Whether the FILE record is marked in-use.
    #[must_use]
    pub fn is_in_use(&self) -> bool {
        self.flags() & 0x0001 != 0
    }

    /// Whether the FILE record is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.flags() & 0x0002 != 0
    }

    /// Offset to the first attribute within the record.
    #[must_use]
    pub fn first_attribute_offset(&self) -> u16 {
        le_u16(self.data, FR_OFF_FIRST_ATTRIBUTE_OFFSET)
    }

    /// Base file reference (non-zero for extension records).
    #[must_use]
    pub fn base_file_reference(&self) -> u64 {
        le_u64(self.data, FR_OFF_BASE_FILE_REFERENCE)
    }

    /// Update sequence array offset within the record.
    #[must_use]
    pub fn update_sequence_offset(&self) -> u16 {
        le_u16(self.data, FR_OFF_USA_OFFSET)
    }

    /// Update sequence array count.
    #[must_use]
    pub fn update_sequence_count(&self) -> u16 {
        le_u16(self.data, FR_OFF_USA_COUNT)
    }

    /// Raw bytes of the entire FILE record payload.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Clone the payload, apply USA fixup, and pass the fixed-up
    /// bytes to a closure.
    ///
    /// The closure receives the full fixed-up record as `&[u8]`,
    /// valid only for the duration of the call. Returns `Err` if
    /// USA fixup fails; otherwise returns the closure's result.
    ///
    /// # Errors
    ///
    /// Returns an error if the NTFS log data is malformed or cannot be read from the underlying stream.
    pub fn with_fixed_up_bytes<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&[u8]) -> Result<T>,
    {
        let mut buf = self.data.to_vec();
        let usa_offset = usize::from(le_u16(self.data, FR_OFF_USA_OFFSET));
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
    ///
    /// # Errors
    ///
    /// Returns an error if the NTFS log data is malformed or cannot be read from the underlying stream.
    pub fn resident_data_values(&self) -> Result<Vec<ResidentDataValue>> {
        self.with_fixed_up_bytes(|buf| {
            let used_size = usize_from_u32(le_u32(buf, FR_OFF_USED_SIZE));
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
    pub(super) lsn: u64,
    pub(super) client_previous_lsn: u64,
    pub(super) client_undo_next_lsn: u64,
    pub(super) record_type: LogRecordType,
    pub(super) transaction_id: u32,
    pub(super) flags: u16,
    pub(super) redo_operation_code: u16,
    pub(super) undo_operation_code: u16,
    pub(super) redo_operation: Option<NtfsLogOperation>,
    pub(super) undo_operation: Option<NtfsLogOperation>,
    pub(super) target_attribute: u16,
    pub(super) target_vcn: u64,
    pub(super) record_offset: u16,
    pub(super) attribute_offset: u16,
    pub(super) cluster_block_offset: u16,
    pub(super) redo_data: NtfsLogOperationData,
    pub(super) undo_data: NtfsLogOperationData,
}

impl NtfsLogRecord {
    /// The LSN (Log Sequence Number) of this record.
    #[must_use]
    pub fn lsn(&self) -> u64 {
        self.lsn
    }

    /// LSN of the previous record in the same transaction.
    #[must_use]
    pub fn client_previous_lsn(&self) -> u64 {
        self.client_previous_lsn
    }

    /// LSN of the next record to undo on rollback.
    #[must_use]
    pub fn client_undo_next_lsn(&self) -> u64 {
        self.client_undo_next_lsn
    }

    /// Whether this is a normal record or a client restart.
    #[must_use]
    pub fn record_type(&self) -> LogRecordType {
        self.record_type
    }

    /// Transaction ID grouping records in a single transaction.
    #[must_use]
    pub fn transaction_id(&self) -> u32 {
        self.transaction_id
    }

    /// The redo operation code.
    #[must_use]
    pub fn redo_operation(&self) -> Option<NtfsLogOperation> {
        self.redo_operation
    }

    /// The raw redo operation code (useful for unknown operations).
    #[must_use]
    pub fn redo_operation_code(&self) -> u16 {
        self.redo_operation_code
    }

    /// The undo operation code.
    #[must_use]
    pub fn undo_operation(&self) -> Option<NtfsLogOperation> {
        self.undo_operation
    }

    /// The raw undo operation code.
    #[must_use]
    pub fn undo_operation_code(&self) -> u16 {
        self.undo_operation_code
    }

    /// Index into the open attribute table.
    #[must_use]
    pub fn target_attribute(&self) -> u16 {
        self.target_attribute
    }

    /// Target virtual cluster number.
    #[must_use]
    pub fn target_vcn(&self) -> u64 {
        self.target_vcn
    }

    /// Byte offset within the target record.
    #[must_use]
    pub fn record_offset(&self) -> u16 {
        self.record_offset
    }

    /// Byte offset within the target attribute.
    #[must_use]
    pub fn attribute_offset(&self) -> u16 {
        self.attribute_offset
    }

    /// Cluster block offset for sparse or compressed targets.
    #[must_use]
    pub fn cluster_block_offset(&self) -> u16 {
        self.cluster_block_offset
    }

    /// The typed redo payload.
    #[must_use]
    pub fn redo_data(&self) -> &NtfsLogOperationData {
        &self.redo_data
    }

    /// The typed undo payload.
    #[must_use]
    pub fn undo_data(&self) -> &NtfsLogOperationData {
        &self.undo_data
    }

    /// Whether this record spans multiple pages.
    #[must_use]
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
    /// Returns `Some(Ok(...))` with `file_reference` from the OAT,
    /// `value_offset` from `attribute_offset`, and `patch_bytes`
    /// borrowed from the redo payload.
    #[must_use]
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
        let Some(entry) = oat.get(usize::from(self.target_attribute)) else {
            return Some(Err(NtfsError::InvalidLogFileRecord {
                position,
                reason: "log payload: \
                             target_attr_oat_oob",
            }));
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
    #[must_use]
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
    /// redo payload as `FILE_NAME` fields.
    ///
    /// Returns `None` if the redo operation is not
    /// `UpdateFileNameRoot` or `UpdateFileNameAllocation`.
    ///
    /// Returns `Some(Err(...))` if the payload is truncated
    /// or corrupt.
    ///
    /// Returns `Some(Ok(fields))` with parsed fields.
    #[must_use]
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
