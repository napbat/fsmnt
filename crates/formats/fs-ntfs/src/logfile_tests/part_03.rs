// ---- PR2: resident_data_patch tests ----

/// Build a minimal `NtfsLogRecord` for testing
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
        redo_operation_code: redo_operation.as_u16(),
        undo_operation_code: NtfsLogOperation::Noop.as_u16(),
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
    assert!(msg.contains("target_attr_oat_oob"), "{msg}");
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
    assert!(msg.contains("unexpected_raw_payload"), "{msg}");
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
    assert!(msg.contains("unexpected_payload_variant"), "{msg}");
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
                    total_values += test_u64_from_usize(values.len());
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
    buf[FN_OFF_NAME_LENGTH] = u8::try_from(name.len()).expect("test value fits u8");
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
    let key_length = u16::try_from(key.len()).expect("test value fits u16");
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
        .copy_from_slice(&u16::try_from(entry_length).expect("test value fits u16").to_le_bytes());
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
    assert_eq!(view.key_length(), u16::try_from(key.len()).expect("test value fits u16"));
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
    let len = u16::try_from(buf.len()).expect("test value fits u16");
    buf[IE_OFF_INDEX_ENTRY_LENGTH..IE_OFF_INDEX_ENTRY_LENGTH + 2]
        .copy_from_slice(&len.to_le_bytes());
    buf[IE_OFF_KEY_LENGTH..IE_OFF_KEY_LENGTH + 2].copy_from_slice(&100u16.to_le_bytes());
    let err = LogIndexEntryView::new(&buf).unwrap_err();
    assert!(err.to_string().contains("key_exceeds_entry"),);
}

#[test]
fn test_index_entry_view_subnode_no_room() {
    let mut buf = vec![0u8; IE_HEADER_SIZE];
    let len = u16::try_from(buf.len()).expect("test value fits u16");
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
                    usize::from(view.index_entry_length()) >= IE_HEADER_SIZE,
                    "entry_length {} too small at LSN {}",
                    view.index_entry_length(),
                    record.lsn(),
                );
            }
            Some(Err(e)) => {
                views_err += 1;
                eprintln!("warn: index_entry_view err at LSN {}: {e}", record.lsn());
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
                eprintln!("warn: filename_update err at LSN {}: {e}", record.lsn());
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
