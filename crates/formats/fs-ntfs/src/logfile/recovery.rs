use super::parser::{u64_from_usize, usize_from_u32};
use super::{
    ANE_OFF_INDEX, ANE_OFF_NAME, ANE_OFF_NAME_LENGTH, AttributeNameEntry, LFS_CLIENT_RECORD,
    LFS_CLIENT_RESTART, LR_HEADER_SIZE, LR_OFF_CLIENT_DATA_LENGTH, LR_OFF_CLIENT_PREVIOUS_LSN,
    LR_OFF_CLIENT_UNDO_NEXT_LSN, LR_OFF_FLAGS, LR_OFF_RECORD_TYPE, LR_OFF_THIS_LSN,
    LR_OFF_TRANSACTION_ID, LfsRestartInfo, LogRecordType, NR_FIXED_HEADER_SIZE,
    NR_OFF_ATTRIBUTE_OFFSET, NR_OFF_CLUSTER_BLOCK_OFFSET, NR_OFF_LCNS_TO_FOLLOW,
    NR_OFF_RECORD_OFFSET, NR_OFF_REDO_LENGTH, NR_OFF_REDO_OFFSET, NR_OFF_REDO_OP,
    NR_OFF_TARGET_ATTRIBUTE, NR_OFF_TARGET_VCN, NR_OFF_UNDO_LENGTH, NR_OFF_UNDO_OFFSET,
    NR_OFF_UNDO_OP, NtfsClientRestartArea, NtfsLogOperation, NtfsLogOperationData, NtfsLogRecord,
    NtfsPosition, OAE0_OFF_ATTR_TYPE, OAE0_OFF_BYTES_PER_INDEX, OAE0_OFF_FILE_REFERENCE,
    OAE0_OFF_LSN_OF_OPEN, OAE0_SIZE, OAE1_OFF_ATTR_TYPE, OAE1_OFF_BYTES_PER_INDEX,
    OAE1_OFF_FILE_REFERENCE, OAE1_OFF_LSN_OF_OPEN, OAE1_SIZE, OpenAttributeEntry,
    RCRD_MIN_HEADER_SIZE, RCRD_OFF_NEXT_RECORD_OFFSET, RCRD_OFF_USA_COUNT, RCRD_OFF_USA_OFFSET,
    RECORD_PAGE_SIGNATURE, String, TTE_ALLOCATED_MARKER, TTE_OFF_ALLOCATED, TTE_OFF_FIRST_LSN,
    TTE_OFF_PREVIOUS_LSN, TTE_OFF_STATE, TTE_OFF_UNDO_BYTES, TTE_OFF_UNDO_NEXT_LSN,
    TTE_OFF_UNDO_RECORDS, TTE_SIZE, TransactionEntry, TransactionState, TransactionTableDumpEntry,
    Vec, apply_usa_fixup, le_u16, le_u32, le_u64, parse_operation_data,
};

/// Parse an `OpenNonresidentAttribute` redo payload.
pub(super) fn parse_open_nonresident_attribute(
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

/// Parse an `OpenAttributeTableDump` payload into entries.
pub(super) fn parse_open_attribute_table_dump(
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

/// Parse an `AttributeNamesDump` payload into entries.
pub(super) fn parse_attribute_names_dump(data: &[u8]) -> Vec<AttributeNameEntry> {
    let mut entries = Vec::new();
    let mut offset = 0;

    while offset + ANE_OFF_NAME <= data.len() {
        let index = le_u16(data, offset + ANE_OFF_INDEX);
        let name_length = usize::from(le_u16(data, offset + ANE_OFF_NAME_LENGTH));
        let name_start = offset + ANE_OFF_NAME;
        let name_byte_len = name_length * 2;
        let name_end = name_start + name_byte_len;

        if name_end > data.len() {
            break;
        }

        let name_bytes = &data[name_start..name_end];
        let u16s: Vec<u16> = name_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let name = String::from_utf16_lossy(&u16s);

        entries.push(AttributeNameEntry { index, name });

        offset = name_end + 2;
    }

    entries
}

/// Parse a `TransactionTableDump` (0x20) payload into entries.
///
/// Each entry is `TTE_SIZE` (0x28) bytes. Entries with
/// `allocated_or_next_free != TTE_ALLOCATED_MARKER` are
/// free-list slots and are included with their raw values
/// (filtering is left to callers).
pub(super) fn parse_transaction_table_dump(data: &[u8]) -> Vec<TransactionTableDumpEntry> {
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
pub(super) fn select_transaction_table_dump(
    candidates: &[(u64, Vec<TransactionTableDumpEntry>)],
    client_restart: Option<&NtfsClientRestartArea>,
) -> Vec<TransactionTableDumpEntry> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let target_lsn = client_restart.map_or(
        0,
        super::records::NtfsClientRestartArea::transaction_table_lsn,
    );

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
pub(super) fn build_transaction_states(
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
pub(super) fn parse_utf16le_name(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }
    let u16s: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&c| c != 0)
        .collect();
    if u16s.is_empty() {
        None
    } else {
        Some(String::from_utf16_lossy(&u16s))
    }
}

/// Parse a single log record from LFS header + client data bytes.
pub(super) fn parse_single_log_record(
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
    let _client_data_length = le_u32(lfs_header, LR_OFF_CLIENT_DATA_LENGTH);
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
            redo_operation_code: 0,
            undo_operation_code: 0,
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
    let redo_offset = usize::from(le_u16(client_data, NR_OFF_REDO_OFFSET));
    let redo_length = usize::from(le_u16(client_data, NR_OFF_REDO_LENGTH));
    let undo_offset = usize::from(le_u16(client_data, NR_OFF_UNDO_OFFSET));
    let undo_length = usize::from(le_u16(client_data, NR_OFF_UNDO_LENGTH));
    let target_attribute = le_u16(client_data, NR_OFF_TARGET_ATTRIBUTE);
    let lcns_to_follow = usize::from(le_u16(client_data, NR_OFF_LCNS_TO_FOLLOW));
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
pub(super) fn parse_record_pages(
    data: &[u8],
    restart_info: &LfsRestartInfo,
    _position: NtfsPosition,
) -> (Vec<NtfsLogRecord>, u32) {
    let page_size = usize_from_u32(restart_info.log_page_size());
    let system_page_size = usize_from_u32(restart_info.system_page_size());

    if page_size < RCRD_MIN_HEADER_SIZE || system_page_size == 0 {
        return (Vec::new(), 0);
    }

    let log_area_start = if restart_info.major_version() >= 2 {
        system_page_size * 2 + page_size * 32
    } else {
        system_page_size * 2 + page_size * 2
    };

    let log_page_data_offset = usize::from(restart_info.log_page_data_offset);

    let mut records = Vec::new();
    let mut skipped_pages: u32 = 0;
    let mut page_offset = log_area_start;

    while page_offset + page_size <= data.len() {
        let page_pos = NtfsPosition::new(u64_from_usize(page_offset));

        let sig = &data[page_offset..page_offset + 4];
        if sig != RECORD_PAGE_SIGNATURE {
            skipped_pages += 1;
            page_offset += page_size;
            continue;
        }

        let page_end = page_offset + page_size;
        let mut page_buf = data[page_offset..page_end].to_vec();

        let usa_offset = usize::from(le_u16(&page_buf, RCRD_OFF_USA_OFFSET));
        let usa_count = le_u16(&page_buf, RCRD_OFF_USA_COUNT);

        if apply_usa_fixup(&mut page_buf, usa_offset, usa_count, page_pos).is_err() {
            skipped_pages += 1;
            page_offset += page_size;
            continue;
        }

        let next_record_offset = usize::from(le_u16(&page_buf, RCRD_OFF_NEXT_RECORD_OFFSET));

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

            let client_data_length = usize_from_u32(le_u32(lfs_header, LR_OFF_CLIENT_DATA_LENGTH));
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
