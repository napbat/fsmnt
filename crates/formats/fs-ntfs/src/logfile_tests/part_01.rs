use super::*;
use crate::ntfs::Ntfs;

/// Helper: read the raw $`LogFile` data from testfs1.
fn read_logfile_data() -> Option<Vec<u8>> {
    use crate::attribute::NtfsAttributeType;
    use crate::file::KnownNtfsFileRecordNumber;
    use fs_common::io::FsReadSeek;

    let mut testfs1 = crate::helpers::tests::testfs1()?;
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let logfile_file = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::LogFile.as_u64())
        .unwrap();

    let data_attr = logfile_file
        .attributes_raw()
        .find_map(|attr| {
            let attr = attr.ok()?;
            if attr.ty().ok()? == NtfsAttributeType::Data {
                Some(attr)
            } else {
                None
            }
        })
        .expect("$LogFile should have a $DATA attribute");

    let mut value = data_attr.value(&mut testfs1).unwrap();
    let len = usize::try_from(value.len()).expect("test value fits usize");
    let mut data = vec![0u8; len];
    value.read_exact(&mut testfs1, &mut data).unwrap();
    Some(data)
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_parse_restart_page_real() {
    let Some(data) = read_logfile_data() else {
        return;
    };
    let pos = NtfsPosition::new(0);
    let info = parse_restart_page(&data, pos).unwrap();

    assert!(
        (info.major_version() == 1 && info.minor_version() == 1)
            || (info.major_version() == 2 && info.minor_version() == 0),
        "unexpected LFS version {}.{}",
        info.major_version(),
        info.minor_version(),
    );
    assert!(info.log_page_size() > 0);
    assert!(info.system_page_size() > 0);
    assert!(info.file_size() > 0);
    assert!(info.seq_number_bits() > 0);
    assert!(!info.client_name().is_empty());
}

/// Build a synthetic RSTR page (4096 bytes) for unit testing.
///
/// Constructs a valid LFS v1.1 restart page with USA fixup,
/// a restart area, and a client record containing "NTFS".
fn build_synthetic_rstr_page() -> Vec<u8> {
    let page_size: usize = 4096;
    let mut page = vec![0u8; page_size];

    // -- Page header --
    page[RSTR_OFF_SIGNATURE..RSTR_OFF_SIGNATURE + 4].copy_from_slice(RESTART_PAGE_SIGNATURE);

    // USA: offset=0x1E (right after header), count=9 (1 USN +
    // 8 sectors in 4096 bytes).
    let usa_off: u16 = u16::try_from(RSTR_MIN_HEADER_SIZE).expect("test value fits u16");
    let usa_count: u16 = 9;
    page[RSTR_OFF_USA_OFFSET..RSTR_OFF_USA_OFFSET + 2].copy_from_slice(&usa_off.to_le_bytes());
    page[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&usa_count.to_le_bytes());

    page[RSTR_OFF_SYSTEM_PAGE_SIZE..RSTR_OFF_SYSTEM_PAGE_SIZE + 4]
        .copy_from_slice(&u32::try_from(page_size).expect("test value fits u32").to_le_bytes());
    page[RSTR_OFF_LOG_PAGE_SIZE..RSTR_OFF_LOG_PAGE_SIZE + 4]
        .copy_from_slice(&u32::try_from(page_size).expect("test value fits u32").to_le_bytes());

    // restart_offset: past the USA (usa_off + usa_count * 2),
    // 8-byte aligned.
    let ra_start = (usize::from(usa_off) + usize::from(usa_count) * 2 + 7) & !7;
    page[RSTR_OFF_RESTART_OFFSET..RSTR_OFF_RESTART_OFFSET + 2]
        .copy_from_slice(&u16::try_from(ra_start).expect("test value fits u16").to_le_bytes());
    page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
        .copy_from_slice(&1u16.to_le_bytes());
    page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
        .copy_from_slice(&1u16.to_le_bytes());

    // -- Restart area (at ra_start) --
    let ra = ra_start;
    // current_lsn
    page[ra + RA_OFF_CURRENT_LSN..ra + RA_OFF_CURRENT_LSN + 8]
        .copy_from_slice(&100u64.to_le_bytes());
    page[ra + RA_OFF_FLAGS..ra + RA_OFF_FLAGS + 2]
        .copy_from_slice(&RESTART_CLEAN_DISMOUNT.to_le_bytes());
    page[ra + RA_OFF_SEQ_NUMBER_BITS..ra + RA_OFF_SEQ_NUMBER_BITS + 4]
        .copy_from_slice(&45u32.to_le_bytes());
    page[ra + RA_OFF_FILE_SIZE..ra + RA_OFF_FILE_SIZE + 8]
        .copy_from_slice(&(2 * 1024 * 1024u64).to_le_bytes());
    page[ra + RA_OFF_LOG_PAGE_DATA_OFFSET..ra + RA_OFF_LOG_PAGE_DATA_OFFSET + 2]
        .copy_from_slice(&64u16.to_le_bytes());

    // client_array_offset (relative to RA start): place client
    // record at RA_MIN_SIZE, 8-byte aligned.
    let ca_off = (RA_MIN_SIZE + 7) & !7;
    page[ra + RA_OFF_CLIENT_ARRAY_OFFSET..ra + RA_OFF_CLIENT_ARRAY_OFFSET + 2]
        .copy_from_slice(&u16::try_from(ca_off).expect("test value fits u16").to_le_bytes());

    // -- Client record (at ra + ca_off) --
    let cr = ra + ca_off;
    // Client name "NTFS" in UTF-16LE = 8 bytes.
    let name_utf16: Vec<u8> = "NTFS"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    page[cr + CR_OFF_CLIENT_NAME_LENGTH..cr + CR_OFF_CLIENT_NAME_LENGTH + 4]
        .copy_from_slice(&u32::try_from(name_utf16.len()).expect("test value fits u32").to_le_bytes());
    page[cr + CR_OFF_CLIENT_NAME..cr + CR_OFF_CLIENT_NAME + name_utf16.len()]
        .copy_from_slice(&name_utf16);

    // -- Write USA: USN value + per-sector replacements --
    // The USN value is arbitrary; we use 0x00_01.
    let usn: [u8; 2] = [0x01, 0x00];
    let usa = usize::from(usa_off);
    page[usa..usa + 2].copy_from_slice(&usn);

    // For each of the 8 sectors, store the original last-2 bytes
    // in the USA array and write the USN at the sector boundary.
    for i in 0..8usize {
        let sector_end = (i + 1) * USA_STRIDE - 2;
        let original = [page[sector_end], page[sector_end + 1]];
        let array_slot = usa + 2 + i * 2;
        page[array_slot..array_slot + 2].copy_from_slice(&original);
        page[sector_end..sector_end + 2].copy_from_slice(&usn);
    }

    page
}

/// Build a dummy `LfsRestartInfo` for operation data parsing tests.
fn build_dummy_restart_info() -> LfsRestartInfo {
    LfsRestartInfo {
        major_version: 1,
        minor_version: 1,
        current_lsn: 100,
        file_size: 2 * 1024 * 1024,
        seq_number_bits: 45,
        log_page_size: 4096,
        system_page_size: 4096,
        log_page_data_offset: 64,
        flags: RESTART_CLEAN_DISMOUNT,
        client_name: String::from("NTFS"),
    }
}

/// Re-apply USA fixup to a synthetic page after modifying it.
fn reapply_usa(page: &mut [u8]) {
    let usa_off = usize::from(le_u16(page, RSTR_OFF_USA_OFFSET));
    let usn: [u8; 2] = [page[usa_off], page[usa_off + 1]];
    for i in 0..8usize {
        let sector_end = (i + 1) * USA_STRIDE - 2;
        if sector_end + 2 > page.len() {
            break;
        }
        let original = [page[sector_end], page[sector_end + 1]];
        let slot = usa_off + 2 + i * 2;
        page[slot..slot + 2].copy_from_slice(&original);
        page[sector_end..sector_end + 2].copy_from_slice(&usn);
    }
}

#[test]
fn test_parse_synthetic_restart_page() {
    let page = build_synthetic_rstr_page();
    let pos = NtfsPosition::new(0);
    let info = parse_restart_page(&page, pos).expect("synthetic parse");

    assert_eq!(info.major_version(), 1);
    assert_eq!(info.minor_version(), 1);
    assert_eq!(info.current_lsn(), 100);
    assert_eq!(info.file_size(), 2 * 1024 * 1024);
    assert_eq!(info.log_page_size(), 4096);
    assert_eq!(info.system_page_size(), 4096);
    assert_eq!(info.seq_number_bits(), 45);
    assert!(info.is_clean_dismount());
    assert_eq!(info.client_name(), "NTFS");
}

#[test]
fn test_parse_restart_page_too_small() {
    let data = vec![0u8; 10];
    let result = parse_restart_page(&data, NtfsPosition::new(0));
    assert!(result.is_err());
}

#[test]
fn test_parse_restart_page_bad_signature() {
    let mut page = vec![0u8; 4096];
    page[0..4].copy_from_slice(b"BAAD");
    let result = parse_restart_page(&page, NtfsPosition::new(0));
    assert!(result.is_err());
}

#[test]
fn test_parse_restart_page_unsupported_version() {
    let mut page = vec![0u8; 4096];
    page[RSTR_OFF_SIGNATURE..RSTR_OFF_SIGNATURE + 4].copy_from_slice(RESTART_PAGE_SIGNATURE);
    page[RSTR_OFF_SYSTEM_PAGE_SIZE..RSTR_OFF_SYSTEM_PAGE_SIZE + 4]
        .copy_from_slice(&4096u32.to_le_bytes());
    page[RSTR_OFF_LOG_PAGE_SIZE..RSTR_OFF_LOG_PAGE_SIZE + 4]
        .copy_from_slice(&4096u32.to_le_bytes());
    page[RSTR_OFF_USA_OFFSET..RSTR_OFF_USA_OFFSET + 2].copy_from_slice(&30u16.to_le_bytes());
    page[RSTR_OFF_USA_COUNT..RSTR_OFF_USA_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
    // Version 3.0 — unsupported.
    page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    page[RSTR_OFF_MINOR_VERSION..RSTR_OFF_MINOR_VERSION + 2]
        .copy_from_slice(&0u16.to_le_bytes());

    let result = parse_restart_page(&page, NtfsPosition::new(0));
    assert!(result.is_err());
}

#[test]
fn test_parse_selects_newer_page() {
    // Build two pages; page1 has a higher current_lsn.
    let mut page0 = build_synthetic_rstr_page();
    let mut page1 = build_synthetic_rstr_page();

    // Set page1's current_lsn to 200 (page0 is 100).
    let ra_start = usize::from(le_u16(&page1, RSTR_OFF_RESTART_OFFSET));
    page1[ra_start + RA_OFF_CURRENT_LSN..ra_start + RA_OFF_CURRENT_LSN + 8]
        .copy_from_slice(&200u64.to_le_bytes());

    // Re-apply USA fixup for page1 (the sector end bytes
    // changed).
    let usa_off = usize::from(le_u16(&page1, RSTR_OFF_USA_OFFSET));
    let usn: [u8; 2] = [page1[usa_off], page1[usa_off + 1]];
    for i in 0..8usize {
        let sector_end = (i + 1) * USA_STRIDE - 2;
        let original = [page1[sector_end], page1[sector_end + 1]];
        let slot = usa_off + 2 + i * 2;
        page1[slot..slot + 2].copy_from_slice(&original);
        page1[sector_end..sector_end + 2].copy_from_slice(&usn);
    }

    let mut combined = page0.clone();
    combined.extend_from_slice(&page1);

    let info = parse_restart_page(&combined, NtfsPosition::new(0)).unwrap();
    assert_eq!(info.current_lsn(), 200);

    // When page0 has the higher LSN, it should be selected.
    let page0_restart_area = usize::from(le_u16(&page0, RSTR_OFF_RESTART_OFFSET));
    page0[page0_restart_area + RA_OFF_CURRENT_LSN..page0_restart_area + RA_OFF_CURRENT_LSN + 8]
        .copy_from_slice(&300u64.to_le_bytes());

    // Re-apply USA fixup for page0.
    let usa_off0 = usize::from(le_u16(&page0, RSTR_OFF_USA_OFFSET));
    let usn0: [u8; 2] = [page0[usa_off0], page0[usa_off0 + 1]];
    for i in 0..8usize {
        let sector_end = (i + 1) * USA_STRIDE - 2;
        let original = [page0[sector_end], page0[sector_end + 1]];
        let slot = usa_off0 + 2 + i * 2;
        page0[slot..slot + 2].copy_from_slice(&original);
        page0[sector_end..sector_end + 2].copy_from_slice(&usn0);
    }

    let mut combined2 = page0;
    combined2.extend_from_slice(&page1);
    let info2 = parse_restart_page(&combined2, NtfsPosition::new(0)).unwrap();
    assert_eq!(info2.current_lsn(), 300);
}

#[test]
fn test_usa_fixup_mismatch() {
    let mut page = build_synthetic_rstr_page();
    // Corrupt a sector boundary — change the USN written there.
    page[USA_STRIDE - 2] = 0xFF;
    page[USA_STRIDE - 1] = 0xFF;

    let result = parse_restart_page(&page, NtfsPosition::new(0));
    assert!(result.is_err());
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_parse_records_produces_results() {
    let Some(data) = read_logfile_data() else {
        return;
    };
    let pos = NtfsPosition::new(0);
    let restart = parse_restart_page(&data, pos).unwrap();
    let (records, skipped) = parse_record_pages(&data, &restart, pos);
    assert!(
        !records.is_empty(),
        "expected at least one log record, got 0 \
         (skipped {skipped} pages)"
    );
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_records_ordered_by_lsn() {
    let Some(data) = read_logfile_data() else {
        return;
    };
    let pos = NtfsPosition::new(0);
    let restart = parse_restart_page(&data, pos).unwrap();
    let (records, _) = parse_record_pages(&data, &restart, pos);
    for window in records.windows(2) {
        assert!(
            window[0].lsn() <= window[1].lsn(),
            "records not ordered: LSN {} > {}",
            window[0].lsn(),
            window[1].lsn(),
        );
    }
}

#[test]
fn test_logfile_load() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // testfs1's $LogFile may be uninitialized (0xFF from mkntfs).
    // If NtfsLogFile::load fails, check if the error is about
    // an invalid signature (expected for uninitialized logs).
    match NtfsLogFile::load(&ntfs, &mut testfs1) {
        Ok(logfile) => {
            let restart = logfile.restart_info();
            assert!(restart.log_page_size() > 0);
            assert!(!restart.client_name().is_empty());
            assert!(!logfile.records().is_empty());
        }
        Err(e) => {
            // Expected for uninitialized $LogFile.
            let msg = format!("{e}");
            assert!(
                msg.contains("RSTR") || msg.contains("signature") || msg.contains("too small"),
                "unexpected error: {e}"
            );
        }
    }
}

#[test]
fn test_logfile_via_ntfs_convenience() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    // Just verify it compiles and doesn't panic.
    let _ = ntfs.logfile(&mut testfs1);
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_logfile_transactions() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");
    let txns = logfile.transactions();
    assert!(!txns.is_empty());
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_logfile_record_operations_are_valid() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");
    for record in logfile.records() {
        assert!(record.lsn() > 0);
        assert!(
            record.record_type() == LogRecordType::ClientRecord
                || record.record_type() == LogRecordType::ClientRestart,
        );
    }
}

#[test]
fn test_operation_enum_round_trip() {
    for code in 0x00..=0x25u16 {
        let op = NtfsLogOperation::from_u16(code);
        assert!(
            op.is_some(),
            "operation code {code:#x} should be recognized"
        );
        assert_eq!(op.expect("known test operation").as_u16(), code);
    }
    assert!(NtfsLogOperation::from_u16(0x26).is_none());
    assert!(NtfsLogOperation::from_u16(0xFF).is_none());
}

#[test]
fn test_unsupported_lfs_version() {
    let mut page = build_synthetic_rstr_page();
    // Set major version to 3 (unsupported).
    page[RSTR_OFF_MAJOR_VERSION..RSTR_OFF_MAJOR_VERSION + 2]
        .copy_from_slice(&3u16.to_le_bytes());
    // Re-apply USA fixup.
    reapply_usa(&mut page);

    let result = parse_restart_page(&page, NtfsPosition::new(0));
    assert!(matches!(
        result,
        Err(NtfsError::UnsupportedLfsVersion { major: 3, .. })
    ));
}

#[test]
fn test_parse_operation_data_set_new_attribute_sizes() {
    let restart_info = build_dummy_restart_info();
    let mut data = vec![0u8; 32];
    // allocated_length = 4096
    data[0..8].copy_from_slice(&4096u64.to_le_bytes());
    // data_length = 1024
    data[8..16].copy_from_slice(&1024u64.to_le_bytes());
    // valid_data_length = 512
    data[16..24].copy_from_slice(&512u64.to_le_bytes());
    // total_allocated = 8192
    data[24..32].copy_from_slice(&8192u64.to_le_bytes());

    let result = parse_operation_data(
        NtfsLogOperation::SetNewAttributeSizes.as_u16(),
        &data,
        &restart_info,
    );
    match result {
        NtfsLogOperationData::SetNewAttributeSizes {
            allocated_length,
            data_length,
            valid_data_length,
            total_allocated,
        } => {
            assert_eq!(allocated_length, 4096);
            assert_eq!(data_length, 1024);
            assert_eq!(valid_data_length, 512);
            assert_eq!(total_allocated, 8192);
        }
        other => panic!("expected SetNewAttributeSizes, got {other:?}"),
    }
}

#[test]
fn test_parse_operation_data_set_bits() {
    let restart_info = build_dummy_restart_info();
    let mut data = vec![0u8; 8];
    data[0..4].copy_from_slice(&42u32.to_le_bytes());
    data[4..8].copy_from_slice(&10u32.to_le_bytes());

    let result = parse_operation_data(
        NtfsLogOperation::SetBitsInNonresidentBitMap.as_u16(),
        &data,
        &restart_info,
    );
    match result {
        NtfsLogOperationData::SetBits {
            bit_offset,
            num_bits,
        } => {
            assert_eq!(bit_offset, 42);
            assert_eq!(num_bits, 10);
        }
        other => {
            panic!("expected SetBits, got {other:?}")
        }
    }
}

#[test]
fn test_parse_operation_data_noop_empty() {
    let restart_info = build_dummy_restart_info();
    let result = parse_operation_data(NtfsLogOperation::Noop.as_u16(), &[], &restart_info);
    assert!(
        matches!(result, NtfsLogOperationData::Unit),
        "expected Unit for Noop with no data, got {result:?}"
    );
}

#[test]
fn test_parse_operation_data_unknown_op() {
    let restart_info = build_dummy_restart_info();
    let data = vec![1, 2, 3, 4];
    let result = parse_operation_data(0xFF, &data, &restart_info);
    match result {
        NtfsLogOperationData::Raw { data: raw } => {
            assert_eq!(raw, vec![1, 2, 3, 4]);
        }
        other => panic!("expected Raw, got {other:?}"),
    }
}

#[test]
fn test_parse_attribute_names_dump() {
    // Build a dump with two entries.
    let mut data = Vec::new();
    // Entry 1: index=5, name="$I30" (4 chars = 8 bytes)
    data.extend_from_slice(&5u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    let name1: Vec<u8> = "$I30"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    data.extend_from_slice(&name1);
    data.extend_from_slice(&[0, 0]); // null term

    // Entry 2: index=7, name="$SII" (4 chars = 8 bytes)
    data.extend_from_slice(&7u16.to_le_bytes());
    data.extend_from_slice(&4u16.to_le_bytes());
    let name2: Vec<u8> = "$SII"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    data.extend_from_slice(&name2);
    data.extend_from_slice(&[0, 0]); // null term

    let entries = parse_attribute_names_dump(&data);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].index(), 5);
    assert_eq!(entries[0].name(), "$I30");
    assert_eq!(entries[1].index(), 7);
    assert_eq!(entries[1].name(), "$SII");
}

#[test]
fn test_parse_utf16le_name() {
    // "Test" in UTF-16LE + null terminator
    let data: Vec<u8> = "Test"
        .encode_utf16()
        .chain(core::iter::once(0u16))
        .flat_map(u16::to_le_bytes)
        .collect();
    let name = parse_utf16le_name(&data);
    assert_eq!(name.as_deref(), Some("Test"));
}

#[test]
fn test_parse_utf16le_name_empty() {
    let name = parse_utf16le_name(&[]);
    assert!(name.is_none());
}

#[test]
fn test_parse_utf16le_name_null_only() {
    let name = parse_utf16le_name(&[0, 0]);
    assert!(name.is_none());
}

#[test]
#[ignore = "testfs1 $LogFile is uninitialized (mkntfs)"]
fn test_logfile_full_integration() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let logfile = NtfsLogFile::load(&ntfs, &mut testfs1).expect("$LogFile should load");

    // 1. Restart info is valid.
    let restart = logfile.restart_info();
    assert!(restart.log_page_size() >= 512);
    assert!(restart.file_size() > 0);
    assert_eq!(restart.client_name(), "NTFS");

    // 2. Records exist and are ordered by LSN.
    let records = logfile.records();
    assert!(!records.is_empty());
    for w in records.windows(2) {
        assert!(w[0].lsn() <= w[1].lsn());
    }

    // 3. At least some redo operations are recognized.
    let recognized = records
        .iter()
        .filter(|r| r.redo_operation().is_some())
        .count();
    assert!(recognized > 0, "expected at least one recognized operation");

    // 4. Transaction grouping works.
    let txns = logfile.transactions();
    assert!(!txns.is_empty());

    // 5. record_by_lsn finds existing records.
    let first_lsn = records[0].lsn();
    assert!(logfile.record_by_lsn(first_lsn).is_some());

    // 6. record_by_lsn returns None for nonexistent LSN.
    assert!(logfile.record_by_lsn(u64::MAX).is_none());

    // 7. Skipped pages count is reasonable.
    assert!(
        logfile.skipped_pages() < 100,
        "too many skipped pages: {}",
        logfile.skipped_pages(),
    );
}

#[test]
fn test_dispatch_classification_unit_and_file_record_ops() {
    let ri = build_dummy_restart_info();
    let dummy = &[0x42u8; 64];

    // Unit ops: empty -> Unit, non-empty -> Raw.
    let unit_ops: &[u16] = &[
        0x00, // Noop
        0x01, // CompensationLogRecord
        0x03, // DeallocateFileRecordSegment
        0x18, // EndTopLevelAction
        0x19, // PrepareTransaction
        0x1A, // CommitTransaction
        0x1B, // ForgetTransaction
    ];

    for &op in unit_ops {
        let result = parse_operation_data(op, &[], &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Unit),
            "op {op:#x} + empty should be Unit, got {result:?}"
        );

        let result = parse_operation_data(op, dummy, &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Raw { .. }),
            "op {op:#x} + bytes should be Raw, got {result:?}"
        );
    }

    // FileRecordSegment
    let result = parse_operation_data(0x02, &[], &ri);
    assert!(matches!(result, NtfsLogOperationData::Empty));
    let result = parse_operation_data(0x02, dummy, &ri);
    assert!(matches!(
        result,
        NtfsLogOperationData::FileRecordSegment { .. }
    ));
}

#[test]
fn test_dispatch_classification_byte_and_raw_ops() {
    let ri = build_dummy_restart_info();
    let dummy = &[0x42u8; 64];

    // Bytes ops
    let bytes_ops: &[u16] = &[
        0x04, // WriteEndOfFileRecordSegment
        0x05, // CreateAttribute
        0x06, // DeleteAttribute
        0x07, // UpdateResidentValue
        0x08, // UpdateNonresidentValue
        0x09, // UpdateMappingPairs
        0x0A, // DeleteDirtyClusters
        0x0C, // AddIndexEntryRoot
        0x0D, // DeleteIndexEntryRoot
        0x0E, // AddIndexEntryAllocation
        0x0F, // DeleteIndexEntryAllocation
        0x10, // WriteEndOfIndexBuffer
        0x13, // UpdateFileNameRoot
        0x14, // UpdateFileNameAllocation
        0x17, // HotFix
        0x25, // ZeroEndOfFileRecord
    ];

    for &op in bytes_ops {
        let result = parse_operation_data(op, &[], &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Empty),
            "op {op:#x} + empty should be Empty, got {result:?}"
        );

        let result = parse_operation_data(op, dummy, &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Bytes { .. }),
            "op {op:#x} + bytes should be Bytes, got {result:?}"
        );
    }

    // Raw (deferred) ops
    let raw_ops: &[u16] = &[
        0x1F, // DirtyPageTableDump
        0x21, 0x22, 0x23, 0x24, // Record data ops
    ];

    for &op in raw_ops {
        let result = parse_operation_data(op, &[], &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Empty),
            "op {op:#x} + empty should be Empty, got {result:?}"
        );

        let result = parse_operation_data(op, dummy, &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Raw { .. }),
            "op {op:#x} + bytes should be Raw, got {result:?}"
        );
    }
}

#[test]
fn test_dispatch_classification_transaction_table_dump() {
    let ri = build_dummy_restart_info();
    let dummy = &[0x42u8; 64];

    // TransactionTableDump (0x20): empty -> Empty,
    // sub-TTE_SIZE bytes -> TransactionTableDump with empty entries,
    // full entry -> TransactionTableDump with entries
    let result = parse_operation_data(0x20, &[], &ri);
    assert!(
        matches!(result, NtfsLogOperationData::Empty),
        "op 0x20 + empty should be Empty, got {result:?}"
    );

    // Sub-TTE_SIZE data: parses but yields no complete entries.
    let short = &[0x42u8; TTE_SIZE - 1];
    let result = parse_operation_data(0x20, short, &ri);
    if let NtfsLogOperationData::TransactionTableDump { entries } = &result {
        assert!(
            entries.is_empty(),
            "op 0x20 + sub-TTE_SIZE data should yield empty entries, got {entries:?}"
        );
    } else {
        panic!("op 0x20 + sub-TTE_SIZE bytes should be TransactionTableDump, got {result:?}");
    }

    // Full entry data: parses to non-empty entries.
    let result = parse_operation_data(0x20, dummy, &ri);
    if let NtfsLogOperationData::TransactionTableDump { entries } = &result {
        assert!(
            !entries.is_empty(),
            "op 0x20 + full entry data should yield entries"
        );
    } else {
        panic!("op 0x20 + bytes should be TransactionTableDump, got {result:?}");
    }
}

#[test]
fn test_dispatch_classification_vcn_and_unknown_ops() {
    let ri = build_dummy_restart_info();
    let dummy = &[0x42u8; 64];

    // IndexEntryVcn ops: empty -> Empty, >=8 bytes -> IndexEntryVcn,
    // <8 bytes -> Raw.
    let vcn_ops: &[u16] = &[0x11, 0x12];
    for &op in vcn_ops {
        let result = parse_operation_data(op, &[], &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Empty),
            "op {op:#x} + empty should be Empty, got {result:?}",
        );

        let vcn_bytes = 42u64.to_le_bytes();
        let result = parse_operation_data(op, &vcn_bytes, &ri);
        assert!(
            matches!(result, NtfsLogOperationData::IndexEntryVcn { vcn: 42 }),
            "op {op:#x} + 8 bytes should be IndexEntryVcn, \
             got {result:?}",
        );

        // Short payload (<8 bytes) falls to Raw.
        let result = parse_operation_data(op, &[1, 2, 3], &ri);
        assert!(
            matches!(result, NtfsLogOperationData::Raw { .. }),
            "op {op:#x} + short should be Raw, got {result:?}",
        );
    }

    // Unknown op codes
    let result = parse_operation_data(0xFFFF, &[], &ri);
    assert!(matches!(result, NtfsLogOperationData::Raw { ref data } if data.is_empty()));
    let result = parse_operation_data(0xFFFF, dummy, &ri);
    assert!(matches!(result, NtfsLogOperationData::Raw { ref data } if !data.is_empty()));
}

#[test]
fn test_dispatch_typed_variants_parse_correctly() {
    let ri = build_dummy_restart_info();

    // SetNewAttributeSizes: 32 bytes of size fields.
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&100u64.to_le_bytes());
    buf[8..16].copy_from_slice(&80u64.to_le_bytes());
    buf[16..24].copy_from_slice(&80u64.to_le_bytes());
    buf[24..32].copy_from_slice(&100u64.to_le_bytes());
    let result = parse_operation_data(0x0B, &buf, &ri);
    match result {
        NtfsLogOperationData::SetNewAttributeSizes {
            allocated_length,
            data_length,
            valid_data_length,
            total_allocated,
        } => {
            assert_eq!(allocated_length, 100);
            assert_eq!(data_length, 80);
            assert_eq!(valid_data_length, 80);
            assert_eq!(total_allocated, 100);
        }
        other => panic!("expected SetNewAttributeSizes, got {other:?}"),
    }

    // SetBits: 8 bytes.
    let mut buf = [0u8; 8];
    buf[0..4].copy_from_slice(&42u32.to_le_bytes());
    buf[4..8].copy_from_slice(&7u32.to_le_bytes());
    let result = parse_operation_data(0x15, &buf, &ri);
    match result {
        NtfsLogOperationData::SetBits {
            bit_offset,
            num_bits,
        } => {
            assert_eq!(bit_offset, 42);
            assert_eq!(num_bits, 7);
        }
        other => panic!("expected SetBits, got {other:?}"),
    }

    // ClearBits: 8 bytes.
    let result = parse_operation_data(0x16, &buf, &ri);
    match result {
        NtfsLogOperationData::ClearBits {
            bit_offset,
            num_bits,
        } => {
            assert_eq!(bit_offset, 42);
            assert_eq!(num_bits, 7);
        }
        other => panic!("expected ClearBits, got {other:?}"),
    }
}
