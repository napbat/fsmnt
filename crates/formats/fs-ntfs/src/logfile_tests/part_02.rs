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
    let mut data = vec![0u8; test_usize_from_u32(allocated_size)];
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
                view.allocated_size() >= u32::try_from(FR_MIN_HEADER_SIZE).expect("test value fits u32"),
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
    buf[ATTR_OFF_LENGTH..ATTR_OFF_LENGTH + 4].copy_from_slice(&u32::try_from(total).expect("test value fits u32").to_le_bytes());
    buf[ATTR_OFF_NON_RESIDENT] = non_resident;
    buf[ATTR_OFF_NAME_LENGTH] = u8::try_from(name.len()).expect("test value fits u8");
    if !name.is_empty() {
        buf[ATTR_OFF_NAME_OFFSET..ATTR_OFF_NAME_OFFSET + 2]
            .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    }
    buf[ATTR_OFF_INSTANCE..ATTR_OFF_INSTANCE + 2].copy_from_slice(&instance.to_le_bytes());

    // Resident extension
    buf[RES_OFF_VALUE_LENGTH..RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&u32::try_from(value.len()).expect("test value fits u32").to_le_bytes());
    buf[RES_OFF_VALUE_OFFSET..RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(value_offset).expect("test value fits u16").to_le_bytes());

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
    let used = usize::from(first_attr) + attr.len() + 4; // +4 for end marker

    let mut buf = vec![0u8; usize::from(first_attr)];
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
        u32::from(first_attr) + u32::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u32"),
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

    let mut buf = vec![0u8; usize::from(first_attr)];
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

    let mut buf = vec![0u8; usize::from(first_attr)];
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

    let mut buf = vec![0u8; usize::from(first_attr)];
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
    assert!(msg.contains("first_attr_offset_out_of_bounds"), "{msg}");
}

#[test]
fn test_walk_err_missing_end_marker() {
    let first_attr: u16 = 0x38;
    let attr = build_resident_attr(ATTR_TYPE_DATA, 1, &[], b"data", 0);
    // No end marker — just the attribute filling to limit.
    let mut buf = vec![0u8; usize::from(first_attr)];
    buf.extend_from_slice(&attr);
    let limit = buf.len();

    let err = walk_resident_data_attrs(&buf, limit, first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("truncated_attr_header"), "{msg}");
}

#[test]
fn test_walk_err_attr_len_zero() {
    let first_attr: u16 = 0x38;
    let first_attr_offset = usize::from(first_attr);
    let mut buf = vec![0u8; first_attr_offset + 0x18];
    // Type = $DATA
    buf[first_attr_offset..first_attr_offset + 4]
        .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    // Length = 0
    buf[first_attr_offset + 4..first_attr_offset + 8]
        .copy_from_slice(&0u32.to_le_bytes());

    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("attr_len_too_small"), "{msg}");
}

#[test]
fn test_walk_err_attr_len_unaligned() {
    let first_attr: u16 = 0x38;
    let first_attr_offset = usize::from(first_attr);
    let mut buf = vec![0u8; first_attr_offset + 0x20];
    buf[first_attr_offset..first_attr_offset + 4]
        .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    // Length = 0x19 (not 8-byte aligned)
    buf[first_attr_offset + 4..first_attr_offset + 8]
        .copy_from_slice(&0x19u32.to_le_bytes());

    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("attr_len_unaligned"), "{msg}");
}

#[test]
fn test_walk_err_attr_exceeds_bounds() {
    let first_attr: u16 = 0x38;
    let first_attr_offset = usize::from(first_attr);
    let mut buf = vec![0u8; first_attr_offset + 0x10];
    buf[first_attr_offset..first_attr_offset + 4]
        .copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    // Length = 0x100 (way past buffer end)
    buf[first_attr_offset + 4..first_attr_offset + 8]
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
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0; // resident
    // value_length = 999 (way too big)
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&999u32.to_le_bytes());
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    // End marker after attribute
    let em_off = off + test_usize_from_u32(attr_len);
    buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("resident_value_exceeds_bounds"), "{msg}");
}

#[test]
fn test_walk_err_value_offset_before_header() {
    let first_attr: u16 = 0x38;
    let attr_len: u32 = 0x20;
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&4u32.to_le_bytes());
    // value_offset = 0x10 (inside resident header)
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&0x10u16.to_le_bytes());
    let em_off = off + test_usize_from_u32(attr_len);
    buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("resident_value_offset_before_header"), "{msg}");
}

#[test]
fn test_walk_err_name_exceeds_attr_bounds() {
    let first_attr: u16 = 0x38;
    // Attr that claims name_length=50 chars (100 bytes) but
    // attr_len is only 0x20 (32 bytes).
    let attr_len: u32 = 0x20;
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    buf[off + ATTR_OFF_NAME_LENGTH] = 50; // way too many
    buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&1u32.to_le_bytes());
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    let em_off = off + test_usize_from_u32(attr_len);
    buf[em_off..em_off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());

    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("attr_name_exceeds_bounds"), "{msg}");
}

#[test]
fn test_walk_err_name_offset_before_header() {
    let first_attr: u16 = 0x38;
    let attr_len: u32 = 0x28; // 40 bytes
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
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
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    let em_off = off + test_usize_from_u32(attr_len);
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
    let mut buf = vec![0u8; usize::from(first_attr) + 256 + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    // value_length = 20 bytes, value_offset = 0x18
    // 0x18 + 20 = 0x2C > attr_len (0x20) but < limit
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&20u32.to_le_bytes());
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    let em_off = off + test_usize_from_u32(attr_len);
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

    let mut buf = vec![0u8; test_usize_from_u32(alloc_size)];
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
    let mut off = usize::from(first_attr);
    for attr in attrs {
        buf[off..off + attr.len()].copy_from_slice(attr);
        off += attr.len();
    }
    // End marker
    buf[off..off + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
    let used_size = u32::try_from(off + 4).expect("test value fits u32");
    buf[FR_OFF_USED_SIZE..FR_OFF_USED_SIZE + 4].copy_from_slice(&used_size.to_le_bytes());

    // Apply USA: write USN to sector boundaries.
    let usn: [u8; 2] = [0x42, 0x00];
    let usa_offset = usize::from(usa_offset);
    buf[usa_offset..usa_offset + 2].copy_from_slice(&usn);
    for i in 0..usize::from(usa_count - 1) {
        let sector_end = (i + 1) * USA_STRIDE - 2;
        let original = [buf[sector_end], buf[sector_end + 1]];
        let slot = usa_offset + 2 + i * 2;
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
