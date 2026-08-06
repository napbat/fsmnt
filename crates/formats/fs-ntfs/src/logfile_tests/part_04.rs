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
        redo_operation_code: redo_op.as_u16(),
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
    eprintln!("  Recycled: {recycled}");
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
/// (`le_u32/le_u64` at the NCR offsets) and return the struct.
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
    let len = u32::try_from(bad.len()).expect("test value fits u32");
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
    let usa_offset = usize::from(le_u16(buf, FR_OFF_USA_OFFSET));
    let usa_count = le_u16(buf, FR_OFF_USA_COUNT);
    let usn: [u8; 2] = [buf[usa_offset], buf[usa_offset + 1]];
    for i in 0..usize::from(usa_count - 1) {
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
        .copy_from_slice(&u32::try_from(NR_FIXED_HEADER_SIZE).expect("test value fits u32").to_le_bytes());
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
        .copy_from_slice(&u32::try_from(NR_FIXED_HEADER_SIZE).expect("test value fits u32").to_le_bytes());
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
        .copy_from_slice(&u32::try_from(NR_FIXED_HEADER_SIZE).expect("test value fits u32").to_le_bytes());
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
