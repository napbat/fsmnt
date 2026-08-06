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
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

    let client_len = NR_FIXED_HEADER_SIZE;
    let rec_size = ((LR_HEADER_SIZE + client_len) + 7) & !7;
    let mut off = lpdo;
    for &(lsn, redo) in records {
        page[off + LR_OFF_THIS_LSN..off + LR_OFF_THIS_LSN + 8]
            .copy_from_slice(&lsn.to_le_bytes());
        page[off + LR_OFF_CLIENT_DATA_LENGTH..off + LR_OFF_CLIENT_DATA_LENGTH + 4]
            .copy_from_slice(&u32::try_from(client_len).expect("test value fits u32").to_le_bytes());
        page[off + LR_OFF_RECORD_TYPE..off + LR_OFF_RECORD_TYPE + 4]
            .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
        let c = off + LR_HEADER_SIZE;
        page[c + NR_OFF_REDO_OP..c + NR_OFF_REDO_OP + 2].copy_from_slice(&redo.to_le_bytes());
        off += rec_size;
    }
    let next_rec = lpdo + records.len() * rec_size;
    page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&u16::try_from(next_rec).expect("test value fits u16").to_le_bytes());

    // Apply USA.
    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
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
/// pages, then the given record pages at `log_area_start` onward.
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
        .copy_from_slice(&u32::try_from(client_len).expect("test value fits u32").to_le_bytes());
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
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page0[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page0[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
    let off0 = lpdo;
    page0[off0 + LR_OFF_THIS_LSN..off0 + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&11u64.to_le_bytes());
    page0[off0 + LR_OFF_CLIENT_DATA_LENGTH..off0 + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(claimed).expect("test value fits u32").to_le_bytes());
    page0[off0 + LR_OFF_RECORD_TYPE..off0 + LR_OFF_RECORD_TYPE + 4]
        .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
    // next_record_offset = 0 -> full-page scan window.
    page0[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&0u16.to_le_bytes());
    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
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
    ri.log_page_size = u32::try_from(page_size).expect("test value fits u32");
    ri.system_page_size = u32::try_from(page_size).expect("test value fits u32");
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
    ri.log_page_size = u32::try_from(page_size).expect("test value fits u32");
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
    let mut buf =
        vec![0u8; usize::from(first_attr) + test_usize_from_u32(attr_len) + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&ATTR_TYPE_DATA.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&attr_len.to_le_bytes());
    buf[off + ATTR_OFF_NON_RESIDENT] = 0;
    buf[off + ATTR_OFF_NAME_LENGTH] = 4;
    buf[off + ATTR_OFF_NAME_OFFSET..off + ATTR_OFF_NAME_OFFSET + 2]
        .copy_from_slice(&u16::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u16").to_le_bytes());
    buf[off + RES_OFF_VALUE_LENGTH..off + RES_OFF_VALUE_LENGTH + 4]
        .copy_from_slice(&0u32.to_le_bytes());
    // value_offset == attr_len (zero-length value at the very end).
    buf[off + RES_OFF_VALUE_OFFSET..off + RES_OFF_VALUE_OFFSET + 2]
        .copy_from_slice(&u16::try_from(attr_len).expect("test value fits u16").to_le_bytes());
    let em = off + test_usize_from_u32(attr_len);
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
    let ra = usize::from(le_u16(&page1, RSTR_OFF_RESTART_OFFSET));
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
    let ra = usize::from(le_u16(&page1, RSTR_OFF_RESTART_OFFSET));
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
        .copy_from_slice(&u16::try_from(lpdo).expect("test value fits u16").to_le_bytes());
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
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
    page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&u16::try_from(next_rec).expect("test value fits u16").to_le_bytes());
    page[lpdo + LR_OFF_THIS_LSN..lpdo + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&77u64.to_le_bytes());
    page[lpdo + LR_OFF_CLIENT_DATA_LENGTH..lpdo + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(claimed).expect("test value fits u32").to_le_bytes());
    page[lpdo + LR_OFF_RECORD_TYPE..lpdo + LR_OFF_RECORD_TYPE + 4]
        .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());

    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
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
        .copy_from_slice(&u16::try_from(next_rec).expect("test value fits u16").to_le_bytes());
    page[lpdo + LR_OFF_THIS_LSN..lpdo + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&88u64.to_le_bytes());
    page[lpdo + LR_OFF_CLIENT_DATA_LENGTH..lpdo + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(avail_window).expect("test value fits u32").to_le_bytes());
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
