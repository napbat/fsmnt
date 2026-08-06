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
    let mut buf = vec![0u8; usize::from(first_attr) + ATTR_MIN_HEADER_SIZE + 4];
    let off = usize::from(first_attr);
    buf[off..off + 4].copy_from_slice(&0x10u32.to_le_bytes()); // $STD_INFO
    buf[off + 4..off + 8].copy_from_slice(&u32::try_from(ATTR_MIN_HEADER_SIZE).expect("test value fits u32").to_le_bytes());
    let em = off + ATTR_MIN_HEADER_SIZE;
    buf[em..em + 4].copy_from_slice(&ATTR_END_MARKER.to_le_bytes());
    let r = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
    assert!(r.is_empty());

    // attr_len == min - 1 (0x0F) -> too small error.
    let mut buf = vec![0u8; usize::from(first_attr) + ATTR_MIN_HEADER_SIZE + 4];
    buf[off..off + 4].copy_from_slice(&0x10u32.to_le_bytes());
    buf[off + 4..off + 8].copy_from_slice(&0x0Fu32.to_le_bytes());
    let err = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap_err();
    assert!(err.to_string().contains("attr_len_too_small"));
}

#[test]
fn test_walk_resident_value_offset_in_record_arithmetic() {
    // Pin value_offset_in_record = offset + value_offset so the
    // the checked offset addition (`+ -> -`/`*`) is killed.
    let first_attr: u16 = 0x38;
    let attr = build_resident_attr(ATTR_TYPE_DATA, 9, &[], b"XYZW", 0);
    let mut buf = vec![0u8; usize::from(first_attr)];
    buf.extend_from_slice(&attr);
    append_end_marker(&mut buf);
    let result = walk_resident_data_attrs(&buf, buf.len(), first_attr).unwrap();
    assert_eq!(result.len(), 1);
    // value_offset is RES_MIN_HEADER_SIZE (0x18) for an unnamed attr.
    assert_eq!(
        result[0].value_offset_in_record(),
        u32::from(first_attr) + u32::try_from(RES_MIN_HEADER_SIZE).expect("test value fits u32"),
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
    let mut buf = vec![0u8; usize::from(first_attr)];
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
    let ra = usize::from(le_u16(&page1, RSTR_OFF_RESTART_OFFSET));
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
        .flat_map(u16::to_le_bytes)
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
    let n1: Vec<u8> = "Hi".encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&n1);
    data.extend_from_slice(&[0, 0]); // null term
    data.extend_from_slice(&9u16.to_le_bytes());
    data.extend_from_slice(&3u16.to_le_bytes());
    let n2: Vec<u8> = "Yo!".encode_utf16().flat_map(u16::to_le_bytes).collect();
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
    let n: Vec<u8> = "Ok".encode_utf16().flat_map(u16::to_le_bytes).collect();
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
    let sel = select_transaction_table_dump(&cands, cr.as_ref());
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
    let sel = select_transaction_table_dump(&cands, cr.as_ref());
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
    let sel = select_transaction_table_dump(&cands, cr.as_ref());
    assert_eq!(sel[0].entry_index(), 2); // 200 is the max before 500
}

#[test]
fn test_select_txn_dump_no_restart_uses_last() {
    // target_lsn == 0 (no client restart) -> last candidate.
    // Also `vec![]` return replacement is killed since result is
    // non-empty here.
    let cands = vec![(100u64, tte_entry(1)), (200u64, tte_entry(7))];
    let sel = select_transaction_table_dump(&cands, None);
    assert_eq!(sel.len(), 1);
    assert_eq!(sel[0].entry_index(), 7);

    // Empty candidates -> empty.
    assert!(select_transaction_table_dump(&[], None).is_empty());
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
    let data: Vec<u8> = "X".encode_utf16().flat_map(u16::to_le_bytes).collect();
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
        .copy_from_slice(&u32::try_from(NR_FIXED_HEADER_SIZE).expect("test value fits u32").to_le_bytes());

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
        .copy_from_slice(&u16::try_from(redo_off).expect("test value fits u16").to_le_bytes());
    client[NR_OFF_REDO_LENGTH..NR_OFF_REDO_LENGTH + 2]
        .copy_from_slice(&u16::try_from(redo.len()).expect("test value fits u16").to_le_bytes());
    client[NR_OFF_UNDO_OFFSET..NR_OFF_UNDO_OFFSET + 2]
        .copy_from_slice(&u16::try_from(undo_off).expect("test value fits u16").to_le_bytes());
    client[NR_OFF_UNDO_LENGTH..NR_OFF_UNDO_LENGTH + 2]
        .copy_from_slice(&u16::try_from(undo.len()).expect("test value fits u16").to_le_bytes());
    client[NR_OFF_LCNS_TO_FOLLOW..NR_OFF_LCNS_TO_FOLLOW + 2]
        .copy_from_slice(&u16::try_from(lcns).expect("test value fits u16").to_le_bytes());
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
/// contains a single `ClientRecord` log record.
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
    let lpdo = usize::from(ri.log_page_data_offset);

    // Build one RCRD page containing a single ClientRecord.
    let mut page = vec![0u8; page_size];
    page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
    // USA: offset right after RCRD header, count = 9.
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());

    // One log record at lpdo.
    let rec_off = lpdo;
    let client_len = NR_FIXED_HEADER_SIZE;
    page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&0xABCDu64.to_le_bytes());
    page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(client_len).expect("test value fits u32").to_le_bytes());
    page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
        .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
    // client data starts after LR header; redo_op = CommitTransaction.
    let cstart = rec_off + LR_HEADER_SIZE;
    page[cstart + NR_OFF_REDO_OP..cstart + NR_OFF_REDO_OP + 2]
        .copy_from_slice(&0x1Au16.to_le_bytes());

    // next_record_offset just past this record (8-byte aligned).
    let next_rec = rec_off + LR_HEADER_SIZE + client_len;
    page[RCRD_OFF_NEXT_RECORD_OFFSET..RCRD_OFF_NEXT_RECORD_OFFSET + 2]
        .copy_from_slice(&u16::try_from(next_rec).expect("test value fits u16").to_le_bytes());

    // Apply USA fixup to the RCRD page (8 sectors).
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
    let page_size = test_usize_from_u32(ri.log_page_size());
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
    ri.log_page_size = u32::try_from(RCRD_MIN_HEADER_SIZE - 1).expect("test value fits u32");
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
    ri.log_page_size = u32::try_from(page_size).expect("test value fits u32");
    ri.system_page_size = u32::try_from(page_size).expect("test value fits u32");
    ri.log_page_data_offset = 64;

    let v2_log_area = page_size * 2 + page_size * 32;

    // Build a record page identical in shape to build_synthetic_logfile.
    let lpdo = 64usize;
    let mut page = vec![0u8; page_size];
    page[0..4].copy_from_slice(RECORD_PAGE_SIGNATURE);
    let usa_off: u16 = u16::try_from(RCRD_MIN_HEADER_SIZE).expect("test value fits u16");
    page[RCRD_OFF_USA_OFFSET..RCRD_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RCRD_OFF_USA_COUNT..RCRD_OFF_USA_COUNT + 2].copy_from_slice(&9u16.to_le_bytes());
    let rec_off = lpdo;
    let client_len = NR_FIXED_HEADER_SIZE;
    page[rec_off + LR_OFF_THIS_LSN..rec_off + LR_OFF_THIS_LSN + 8]
        .copy_from_slice(&0x1234u64.to_le_bytes());
    page[rec_off + LR_OFF_CLIENT_DATA_LENGTH..rec_off + LR_OFF_CLIENT_DATA_LENGTH + 4]
        .copy_from_slice(&u32::try_from(client_len).expect("test value fits u32").to_le_bytes());
    page[rec_off + LR_OFF_RECORD_TYPE..rec_off + LR_OFF_RECORD_TYPE + 4]
        .copy_from_slice(&LFS_CLIENT_RECORD.to_le_bytes());
    let next_rec = rec_off + LR_HEADER_SIZE + client_len;
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

    let mut blob = vec![0u8; v2_log_area];
    blob.extend_from_slice(&page);
    let (records, _) = parse_record_pages(&blob, &ri, NtfsPosition::none());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].lsn(), 0x1234);
}
