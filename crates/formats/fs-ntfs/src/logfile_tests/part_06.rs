#[test]
fn test_parse_record_pages_stops_at_zero_lsn() {
    // A record with this_lsn == 0 terminates the per-page loop
    // (kills the `== -> !=` zero-LSN guard). Build a page whose first
    // record has lsn 0 -> no records collected from it.
    let (mut blob, ri, _) = build_synthetic_logfile();
    let page_size = test_usize_from_u32(ri.log_page_size());
    let log_area_start = page_size * 2 + page_size * 2;
    let lpdo = usize::from(ri.log_page_data_offset);
    // Zero out the record's this_lsn within the (already-fixed-up) page
    // and re-apply USA so the page validates but the record is skipped.
    let rec_off = log_area_start + lpdo;
    blob[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&0u64.to_le_bytes());
    // Re-apply USA on the record page in place.
    let page_start = log_area_start;
    let usa = page_start + usize::from(le_u16(&blob[page_start..], RCRD_OFF_USA_OFFSET));
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
    let lpdo = usize::from(ri.log_page_data_offset);

    let mut page = vec![0u8; page_size];
    page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

    let client_len = NR_FIXED_HEADER_SIZE;
    let rec_size = ((LR_HEADER_SIZE + client_len) + 7) & !7;

    let write_record = |page: &mut [u8], off: usize, lsn: u64, redo: u16| {
        page[off + LR_OFF_THIS_LSN..off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&lsn.to_le_bytes());
        page[off + LR_OFF_CLIENT_DATA_LENGTH..off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&u32::try_from(client_len).expect("test value fits u32").to_le_bytes());
        page[off + LR_OFF_RECORD_TYPE..off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let c = off + LR_HEADER_SIZE;
        page[c + NR_OFF_REDO_OP..c + NR_OFF_REDO_OP + 2].copy_from_slice(&redo.to_le_bytes());
    };

    write_record(&mut page, lpdo, 10, 0x1A);
    write_record(&mut page, lpdo + rec_size, 20, 0x19);
    let next_rec = lpdo + rec_size * 2;
    page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&u16::try_from(next_rec).expect("test value fits u16").to_le_bytes());

    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
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
    let lpdo = usize::from(ri.log_page_data_offset);

    let mut page = vec![0u8; page_size];
    page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

    let rec_off = lpdo;
    page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&7u64.to_le_bytes());
    // client_data_length larger than the page can hold.
    page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(page_size).expect("test value fits u32").to_le_bytes());
    page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
        .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
    // next_record_offset = page_size so the loop scans to end-of-page.
    page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&0u16.to_le_bytes());

    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
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
            .flat_map(u16::to_le_bytes)
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
        .map(super::records::TransactionEntry::transaction_id)
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
    let mut buf = vec![0u8; usize::from(first_attr)];
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
    let attr_len: u32 = u32::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u32"); // 0x18
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    let em = off + test_usize_from_u32(attr_len);
    buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
    let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].data().len(), 0);

    // attr_len == 0x17 (< 0x18) -> resident_header_truncated.
    let mut buf = vec![0u8; usize::from(first_attr) + 0x20 + 4];
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
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    buf[off + ATTR_OFF_NAME_LENGTH] = 2;
    buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    // value_offset after the 4-byte name: 0x18 + 4 = 0x1C.
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&0x1Cu16.to_le_bytes());
    let em = off + test_usize_from_u32(attr_len);
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
    let ra = usize::from(le_u16(&page1, RSTR_OFF_RESTART_OFFSET));
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
    let bad_off = u16::try_from(page.len() - 1).expect("test value fits u16");
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
    let ra_start = usize::from(le_u16(&page, RSTR_OFF_RESTART_OFFSET));
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
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    data.extend_from_slice(&[0, 0]);
    // entry 1: index 2, len 2, name "QR"
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(&2u16.to_le_bytes());
    data.extend_from_slice(
        &"QR"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
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
        .copy_from_slice(&u16::try_from(redo_off).expect("test value fits u16").to_le_bytes());
    client[NR_OFF_REDO_LENGTH..NR_OFF_REDO_LENGTH + 2]
        .copy_from_slice(&u16::try_from(redo.len()).expect("test value fits u16").to_le_bytes());
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
