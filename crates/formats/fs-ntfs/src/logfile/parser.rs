use super::{
    ATTR_END_MARKER, ATTR_MIN_HEADER_SIZE, ATTR_OFF_INSTANCE, ATTR_OFF_LENGTH,
    ATTR_OFF_NAME_LENGTH, ATTR_OFF_NAME_OFFSET, ATTR_OFF_NON_RESIDENT, ATTR_OFF_TYPE,
    ATTR_TYPE_DATA, CR_OFF_CLIENT_NAME, CR_OFF_CLIENT_NAME_LENGTH, CR_SIZE, LfsRestartInfo,
    NtfsError, NtfsLogOperation, NtfsLogOperationData, NtfsPosition, RA_MIN_SIZE,
    RA_OFF_CLIENT_ARRAY_OFFSET, RA_OFF_CURRENT_LSN, RA_OFF_FILE_SIZE, RA_OFF_FLAGS,
    RA_OFF_LOG_PAGE_DATA_OFFSET, RA_OFF_SEQ_NUMBER_BITS, RES_MIN_HEADER_SIZE, RES_OFF_VALUE_LENGTH,
    RES_OFF_VALUE_OFFSET, RESTART_PAGE_SIGNATURE, RSTR_MIN_HEADER_SIZE, RSTR_OFF_LOG_PAGE_SIZE,
    RSTR_OFF_MAJOR_VERSION, RSTR_OFF_MINOR_VERSION, RSTR_OFF_RESTART_OFFSET, RSTR_OFF_SIGNATURE,
    RSTR_OFF_SYSTEM_PAGE_SIZE, RSTR_OFF_USA_COUNT, RSTR_OFF_USA_OFFSET, ResidentDataValue, Result,
    String, USA_STRIDE, Vec, parse_attribute_names_dump, parse_open_attribute_table_dump,
    parse_open_nonresident_attribute, parse_transaction_table_dump,
};

/// Apply Update Sequence Array fixup to a page buffer.
pub(super) fn apply_usa_fixup(
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

    for i in 0..usize::from(array_count) {
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
pub(super) fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

/// Read a little-endian u32 from a byte slice at `offset`.
pub(super) fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from a byte slice at `offset`.
pub(super) fn le_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub(super) fn usize_from_u32(value: u32) -> usize {
    usize::try_from(value).expect("u32 NTFS log sizes fit usize on supported targets")
}

pub(super) fn u64_from_usize(value: usize) -> u64 {
    u64::try_from(value).expect("supported Rust targets have at most 64-bit pointers")
}

fn invalid_resident_attribute(reason: &'static str) -> NtfsError {
    NtfsError::InvalidLogFileRecord {
        position: NtfsPosition::none(),
        reason,
    }
}

fn parse_resident_data_value(
    buf: &[u8],
    offset: usize,
    attr_len: usize,
    name_length: u8,
    name_offset: u16,
    instance: u16,
) -> Result<ResidentDataValue> {
    if attr_len < RES_MIN_HEADER_SIZE {
        return Err(invalid_resident_attribute(
            "log payload: resident_header_truncated",
        ));
    }

    let value_length = usize::try_from(le_u32(buf, offset + RES_OFF_VALUE_LENGTH))
        .map_err(|_| invalid_resident_attribute("log payload: resident value is too large"))?;
    let value_offset = le_u16(buf, offset + RES_OFF_VALUE_OFFSET);
    let value_offset_usize = usize::from(value_offset);
    if value_offset_usize < RES_MIN_HEADER_SIZE {
        return Err(invalid_resident_attribute(
            "log payload: resident_value_offset_before_header",
        ));
    }

    let value_end = value_offset_usize
        .checked_add(value_length)
        .filter(|end| *end <= attr_len)
        .ok_or_else(|| invalid_resident_attribute("log payload: resident_value_exceeds_bounds"))?;

    if name_length > 0 {
        let name_offset = usize::from(name_offset);
        if name_offset < RES_MIN_HEADER_SIZE {
            return Err(invalid_resident_attribute(
                "log payload: attr_name_offset_before_header",
            ));
        }
        let name_byte_length = usize::from(name_length) * 2;
        if name_offset
            .checked_add(name_byte_length)
            .is_none_or(|end| end > attr_len)
        {
            return Err(invalid_resident_attribute(
                "log payload: attr_name_exceeds_bounds",
            ));
        }
    }

    let value_start = offset + value_offset_usize;
    let value_offset_in_record = u32::try_from(value_start).map_err(|_| {
        invalid_resident_attribute("log payload: resident value offset exceeds u32")
    })?;

    Ok(ResidentDataValue {
        instance,
        name_offset,
        name_length,
        value_offset_in_record,
        data: buf[value_start..offset + value_end].to_vec(),
    })
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
pub(super) fn walk_resident_data_attrs(
    buf: &[u8],
    limit: usize,
    first_attr_offset: u16,
) -> Result<Vec<ResidentDataValue>> {
    let first_attr_offset = usize::from(first_attr_offset);
    if first_attr_offset >= limit {
        return Err(invalid_resident_attribute(
            "log payload: first_attr_offset_out_of_bounds",
        ));
    }

    let mut values = Vec::new();
    let mut offset = first_attr_offset;

    loop {
        // Need at least 4 bytes to read the type field.
        if offset.saturating_add(4) > limit {
            return Err(invalid_resident_attribute(
                "log payload: truncated_attr_header",
            ));
        }

        let attr_type = le_u32(buf, offset + ATTR_OFF_TYPE);
        if attr_type == ATTR_END_MARKER {
            break;
        }

        // Need full common header to proceed.
        if offset.saturating_add(ATTR_MIN_HEADER_SIZE) > limit {
            return Err(invalid_resident_attribute(
                "log payload: truncated_attr_header",
            ));
        }

        let attr_len = usize::try_from(le_u32(buf, offset + ATTR_OFF_LENGTH))
            .map_err(|_| invalid_resident_attribute("log payload: attr_len_too_large"))?;

        if attr_len < ATTR_MIN_HEADER_SIZE {
            return Err(invalid_resident_attribute(
                "log payload: attr_len_too_small",
            ));
        }

        if !attr_len.is_multiple_of(8) {
            return Err(invalid_resident_attribute(
                "log payload: attr_len_unaligned",
            ));
        }

        if offset.saturating_add(attr_len) > limit {
            return Err(invalid_resident_attribute(
                "log payload: attr_exceeds_bounds",
            ));
        }

        let non_resident = buf[offset + ATTR_OFF_NON_RESIDENT];
        let name_length = buf[offset + ATTR_OFF_NAME_LENGTH];
        let name_offset = le_u16(buf, offset + ATTR_OFF_NAME_OFFSET);
        let instance = le_u16(buf, offset + ATTR_OFF_INSTANCE);

        // Only collect resident $DATA attributes.
        if attr_type == ATTR_TYPE_DATA && non_resident == 0 {
            values.push(parse_resident_data_value(
                buf,
                offset,
                attr_len,
                name_length,
                name_offset,
                instance,
            )?);
        }

        let next_offset = offset + attr_len;
        debug_assert!(next_offset > offset);
        offset = next_offset;
    }

    Ok(values)
}

/// Parse an LFS restart page from the raw log file data.
///
/// Selects the more recent of the two restart pages (by `current_lsn`).
pub(super) fn parse_restart_page(data: &[u8], position: NtfsPosition) -> Result<LfsRestartInfo> {
    if data.len() < RSTR_MIN_HEADER_SIZE {
        return Err(NtfsError::InvalidLogFileRecord {
            position,
            reason: "log file too small for restart page header",
        });
    }

    let page0 = parse_single_restart_page(data, 0, position)?;

    let page_size = usize_from_u32(page0.system_page_size);
    let page1 = if data.len() >= page_size * 2 {
        parse_single_restart_page(
            data,
            page_size,
            NtfsPosition::new(u64_from_usize(page_size)),
        )
        .ok()
    } else {
        None
    };

    match page1 {
        Some(p1) if p1.current_lsn > page0.current_lsn => Ok(p1),
        _ => Ok(page0),
    }
}

/// Parse a single `LFS_RESTART_PAGE` at the given offset.
pub(super) fn parse_single_restart_page(
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
    let restart_offset = usize::from(le_u16(page_data, RSTR_OFF_RESTART_OFFSET));
    let minor_version = le_u16(page_data, RSTR_OFF_MINOR_VERSION);
    let major_version = le_u16(page_data, RSTR_OFF_MAJOR_VERSION);

    if !((major_version == 1 && minor_version == 1) || (major_version == 2 && minor_version == 0)) {
        return Err(NtfsError::UnsupportedLfsVersion {
            position,
            major: major_version,
            minor: minor_version,
        });
    }

    let page_end = offset + usize_from_u32(system_page_size).min(data.len() - offset);
    let mut page_buf = data[offset..page_end].to_vec();

    let usa_offset = usize::from(le_u16(&page_buf, RSTR_OFF_USA_OFFSET));
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
    let client_array_offset = usize::from(le_u16(ra, RA_OFF_CLIENT_ARRAY_OFFSET));
    let file_size = le_u64(ra, RA_OFF_FILE_SIZE);
    let log_page_data_offset = le_u16(ra, RA_OFF_LOG_PAGE_DATA_OFFSET);

    let client_name = if client_array_offset + CR_SIZE <= ra.len() {
        let cr = &ra[client_array_offset..];
        let name_len = usize_from_u32(le_u32(cr, CR_OFF_CLIENT_NAME_LENGTH));
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
#[must_use]
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
pub(super) fn parse_operation_data(
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
