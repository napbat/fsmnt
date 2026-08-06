use super::*;
use crate::attribute::NtfsAttributeType;
use crate::data_run_map::DataRunMap;
use crate::time::NTFS_TIMESTAMP_1997;
use fsmnt_testkit::Cursor;

const FRS: u32 = 1024; // file record size
const CLUSTER: u32 = 512; // cluster size
const MFT_START: u64 = 8192; // physical byte offset of MFT record 0
const BITMAP_START: u64 = 4096; // physical byte offset of bitmap data

/// A plausible NTFS timestamp inside the default 1997..2030 bounds.
const GOOD_TIME: u64 = NTFS_TIMESTAMP_1997 + 1_000_000;

fn make_boot_sector() -> [u8; 512] {
    let mut bs = [0u8; 512];
    bs[3..11].copy_from_slice(b"NTFS    ");
    bs[0x0B..0x0D].copy_from_slice(
        &u16::try_from(CLUSTER)
            .expect("test value fits u16")
            .to_le_bytes(),
    );
    bs[0x0D] = 1; // sectors_per_cluster
    bs[0x28..0x30].copy_from_slice(&65536u64.to_le_bytes()); // total_sectors
    bs[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
    bs[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
    bs[0x40] = 0xF6; // -10 => 1024-byte records
    bs[510] = 0x55;
    bs[511] = 0xAA;
    bs
}

/// Resident `$STANDARD_INFORMATION` (48-byte value) with all four
/// timestamps set to `time`.
fn si_attribute(time: u64) -> Vec<u8> {
    let mut value = [0u8; 48];
    value[0..8].copy_from_slice(&time.to_le_bytes()); // creation
    value[8..16].copy_from_slice(&time.to_le_bytes()); // modification
    value[16..24].copy_from_slice(&time.to_le_bytes()); // mft modification
    value[24..32].copy_from_slice(&time.to_le_bytes()); // access
    resident_attribute(NtfsAttributeType::StandardInformation, &value)
}

/// Resident `$FILE_NAME` attribute (`Win32AndDos` namespace) naming the
/// file `name`, parented to `parent`, reporting logical size `data_size`.
fn fn_attribute(name: &str, parent: u64, data_size: u64) -> Vec<u8> {
    let chars: Vec<u16> = name.encode_utf16().collect();
    let mut value = vec![0u8; 66 + chars.len() * 2];
    value[0..8].copy_from_slice(&parent.to_le_bytes()); // parent reference
    value[8..16].copy_from_slice(&GOOD_TIME.to_le_bytes()); // creation
    value[16..24].copy_from_slice(&GOOD_TIME.to_le_bytes()); // modification
    value[24..32].copy_from_slice(&GOOD_TIME.to_le_bytes()); // mft modification
    value[32..40].copy_from_slice(&GOOD_TIME.to_le_bytes()); // access
    value[40..48].copy_from_slice(&data_size.to_le_bytes()); // allocated_size
    value[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
    value[64] = u8::try_from(chars.len()).expect("test value fits u8"); // name_length (chars)
    value[65] = 3; // namespace = Win32AndDos
    for (i, c) in chars.iter().enumerate() {
        value[66 + i * 2..66 + i * 2 + 2].copy_from_slice(&c.to_le_bytes());
    }
    resident_attribute(NtfsAttributeType::FileName, &value)
}

/// Resident attribute (no name) of `ty` carrying `value`.
fn resident_attribute(ty: NtfsAttributeType, value: &[u8]) -> Vec<u8> {
    let value_offset = 24usize;
    let attribute_length = value_offset + value.len();
    let mut attr = vec![0u8; attribute_length];
    attr[0..4].copy_from_slice(&ty.as_u32().to_le_bytes());
    attr[4..8].copy_from_slice(
        &u32::try_from(attribute_length)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    attr[8] = 0; // resident
    attr[14..16].copy_from_slice(&1u16.to_le_bytes()); // instance
    attr[16..20].copy_from_slice(
        &u32::try_from(value.len())
            .expect("test value fits u32")
            .to_le_bytes(),
    ); // value_length
    attr[20..22].copy_from_slice(
        &u16::try_from(value_offset)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // value_offset
    attr[value_offset..attribute_length].copy_from_slice(value);
    attr
}

/// Non-resident `$DATA` attribute holding `runs`, with `data_size`.
fn data_attribute_non_resident(runs: &[u8], data_size: u64) -> Vec<u8> {
    let data_runs_offset = 64usize;
    let attribute_length = data_runs_offset + runs.len();
    let mut attr = vec![0u8; attribute_length];
    attr[0..4].copy_from_slice(&NtfsAttributeType::Data.as_u32().to_le_bytes());
    attr[4..8].copy_from_slice(
        &u32::try_from(attribute_length)
            .expect("test value fits u32")
            .to_le_bytes(),
    );
    attr[8] = 1; // non-resident
    attr[14..16].copy_from_slice(&2u16.to_le_bytes()); // instance
    attr[32..34].copy_from_slice(
        &u16::try_from(data_runs_offset)
            .expect("test value fits u16")
            .to_le_bytes(),
    ); // data_runs_offset
    attr[40..48].copy_from_slice(&data_size.to_le_bytes()); // allocated_size
    attr[48..56].copy_from_slice(&data_size.to_le_bytes()); // data_size
    attr[56..64].copy_from_slice(&data_size.to_le_bytes()); // initialized_size
    attr[data_runs_offset..attribute_length].copy_from_slice(runs);
    attr
}

/// Resident `$DATA` attribute (in-MFT data) of length `value.len()`.
fn data_attribute_resident(value: &[u8]) -> Vec<u8> {
    resident_attribute(NtfsAttributeType::Data, value)
}

/// Builds a 1 KiB FILE record from a list of attribute byte blobs and
/// the given `flags`. Applies the update-sequence fixup.
fn make_file_record(flags: u16, attributes: &[Vec<u8>]) -> Vec<u8> {
    let file_record_size = usize::try_from(FRS).expect("test record size fits usize");
    let mut rec = vec![0u8; file_record_size];
    rec[0..4].copy_from_slice(b"FILE");
    rec[4..6].copy_from_slice(&0x30u16.to_le_bytes());
    rec[6..8].copy_from_slice(&3u16.to_le_bytes());
    let usn = 0x0001u16;
    rec[0x30..0x32].copy_from_slice(&usn.to_le_bytes());
    rec[0x32..0x34].copy_from_slice(&0xAAAAu16.to_le_bytes());
    rec[0x34..0x36].copy_from_slice(&0xBBBBu16.to_le_bytes());
    rec[510..512].copy_from_slice(&usn.to_le_bytes());
    rec[1022..1024].copy_from_slice(&usn.to_le_bytes());
    rec[16..18].copy_from_slice(&1u16.to_le_bytes()); // sequence_number
    rec[18..20].copy_from_slice(&1u16.to_le_bytes()); // hard_link_count
    rec[20..22].copy_from_slice(&56u16.to_le_bytes()); // first_attribute_offset
    rec[22..24].copy_from_slice(&flags.to_le_bytes());
    rec[24..28].copy_from_slice(&FRS.to_le_bytes()); // data_size
    rec[28..32].copy_from_slice(&FRS.to_le_bytes()); // allocated_size

    let mut pos = 56usize;
    for attr in attributes {
        rec[pos..pos + attr.len()].copy_from_slice(attr);
        pos += attr.len();
    }
    rec[pos..pos + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // End marker
    rec
}

/// Single-run data: header byte 0x21 (1 length byte, 1 offset byte),
/// `clusters` length, LCN offset `lcn`, terminator.
fn one_data_run(clusters: u8, lcn: u8) -> [u8; 4] {
    [0x21, clusters, lcn, 0x00]
}

/// Single SPARSE run: header byte 0x01 (1 length byte, 0 offset bytes
/// => VCN 0 => sparse), `clusters` length, terminator.
fn one_sparse_run(clusters: u8) -> [u8; 3] {
    [0x01, clusters, 0x00]
}

/// Assembles an image and a scanner over `records` (record N at
/// `MFT_START + N*FRS`). `bitmap_bytes` seeds the bitmap region (bit
/// per cluster). `config` controls scanning behaviour.
fn build_scanner(
    records: &[Vec<u8>],
    bitmap_bytes: &[u8],
    config: DeletedFileScanConfig,
) -> (NtfsDeletedFileScanner, Ntfs, Cursor<Vec<u8>>) {
    let count = u64::try_from(records.len()).expect("test record count fits u64");
    let region_len = count * u64::from(FRS);
    let total_len = usize::try_from(MFT_START + region_len).expect("test image fits usize");
    let file_record_size = usize::try_from(FRS).expect("test record size fits usize");
    let cluster_size = usize::try_from(CLUSTER).expect("test cluster size fits usize");
    let bitmap_end =
        usize::try_from(BITMAP_START).expect("test bitmap offset fits usize") + cluster_size;
    let mut data = vec![0u8; total_len.max(bitmap_end)];
    data[0..512].copy_from_slice(&make_boot_sector());
    for (i, rec) in records.iter().enumerate() {
        let off =
            usize::try_from(MFT_START).expect("test MFT offset fits usize") + i * file_record_size;
        data[off..off + file_record_size].copy_from_slice(rec);
    }
    // Seed the bitmap region.
    let bm_off = usize::try_from(BITMAP_START).expect("test value fits usize");
    data[bm_off..bm_off + bitmap_bytes.len()].copy_from_slice(bitmap_bytes);

    let mut fs = Cursor::new(data);
    let ntfs = Ntfs::new(&mut fs).unwrap();

    let mft_map = DataRunMap::from_segments_for_test(&[(Some(MFT_START), region_len)]);
    let mft_entries = NtfsMftEntries::from_parts_for_test(mft_map, count, FRS);

    let bitmap_map =
        DataRunMap::from_segments_for_test(&[(Some(BITMAP_START), u64::from(CLUSTER))]);
    let bitmap =
        NtfsClusterBitmap::from_parts_for_test(bitmap_map, u64::from(CLUSTER) * 8, CLUSTER);

    let scanner = NtfsDeletedFileScanner::from_parts_for_test(mft_entries, bitmap, config, CLUSTER);
    (scanner, ntfs, fs)
}

fn config_keep_system() -> DeletedFileScanConfig {
    DeletedFileScanConfig {
        skip_system_records: false,
        skip_directories: false,
        ..DeletedFileScanConfig::default()
    }
}

#[test]
fn synthetic_timestamps_plausible_delegates() {
    let (scanner, _ntfs, _fs) = build_scanner(
        &[make_file_record(0, &[])],
        &[0u8; 16],
        config_keep_system(),
    );
    // In-range timestamps are plausible; an out-of-range one is not
    // (line 205 returns the genuine bool, not true/false constants).
    // Note: an empty set and a far-future timestamp are both
    // implausible, while a non-zero in-range value is plausible.
    assert!(scanner.timestamps_plausible(&[NtfsTime::from(GOOD_TIME)]));
    assert!(!scanner.timestamps_plausible(&[NtfsTime::from(u64::MAX)]));
    assert!(!scanner.timestamps_plausible(&[]));
}

#[test]
fn synthetic_next_returns_none_when_exhausted() {
    // Single in-use record: skipped, so next yields None (line 310).
    let rec = make_file_record(NtfsFileFlags::IN_USE.bits(), &[]);
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());
    assert!(scanner.next(&ntfs, &mut fs).is_none());
}

#[test]
fn synthetic_next_skips_in_use_records() {
    // First record in use (skipped via line 319), second deleted and
    // returned.
    let in_use = make_file_record(
        NtfsFileFlags::IN_USE.bits(),
        &[si_attribute(GOOD_TIME), fn_attribute("live.txt", 5, 0)],
    );
    let deleted = make_file_record(
        0,
        &[si_attribute(GOOD_TIME), fn_attribute("gone.txt", 5, 0)],
    );
    let (mut scanner, ntfs, mut fs) =
        build_scanner(&[in_use, deleted], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.record_number, 1);
    assert_eq!(result.name.as_deref(), Some("gone.txt"));
    assert!(scanner.next(&ntfs, &mut fs).is_none());
}

#[test]
fn synthetic_skip_system_records_boundary() {
    // 25 records (0..=24); only record 24 is non-system. With
    // skip_system_records, records 0..24 are skipped (line 323 `<`),
    // leaving record 24 (== SYSTEM_RECORD_COUNT, not skipped).
    let mut records = Vec::new();
    for _ in 0..=SYSTEM_RECORD_COUNT {
        records.push(make_file_record(
            0,
            &[si_attribute(GOOD_TIME), fn_attribute("f.txt", 5, 0)],
        ));
    }
    let config = DeletedFileScanConfig {
        skip_system_records: true,
        skip_directories: false,
        ..DeletedFileScanConfig::default()
    };
    let (mut scanner, ntfs, mut fs) = build_scanner(&records, &[0u8; 16], config);

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.record_number, SYSTEM_RECORD_COUNT);
    assert!(scanner.next(&ntfs, &mut fs).is_none());
}

#[test]
fn synthetic_skip_directories() {
    // A deleted directory is skipped when skip_directories is set
    // (line 329), but returned otherwise.
    let dir = make_file_record(
        NtfsFileFlags::IS_DIRECTORY.bits(),
        &[si_attribute(GOOD_TIME), fn_attribute("adir", 5, 0)],
    );

    let config_skip = DeletedFileScanConfig {
        skip_system_records: false,
        skip_directories: true,
        ..DeletedFileScanConfig::default()
    };
    let (mut scanner, ntfs, mut fs) =
        build_scanner(std::slice::from_ref(&dir), &[0u8; 16], config_skip);
    assert!(scanner.next(&ntfs, &mut fs).is_none());

    let (mut scanner, ntfs, mut fs) = build_scanner(&[dir], &[0u8; 16], config_keep_system());
    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert!(result.is_directory);
}

#[test]
fn synthetic_extract_data_runs_all_free() {
    // A deleted file with a non-resident $DATA run over 5 clusters that
    // are all unallocated (bitmap all zero). extract_data_runs reports
    // the run with AllFree, clusters_free=true, data_runs_present=true.
    let runs = one_data_run(5, 2); // 5 clusters at LCN 2
    let data_size = 5 * u64::from(CLUSTER);
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("d.bin", 5, data_size),
            data_attribute_non_resident(&runs, data_size),
        ],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.data_runs.len(), 1);
    let run = &result.data_runs[0];
    // cluster_offset = byte_offset / cluster_size (line 268); LCN 2 *
    // 512 / 512 = 2.
    assert_eq!(run.cluster_offset, 2);
    // cluster_count = allocated_size / cluster_size (line 269) = 5.
    assert_eq!(run.cluster_count, 5);
    assert_eq!(run.status, ClusterStatus::AllFree);
    assert!(result.assessment.data_runs_present());
    assert!(result.assessment.clusters_free());
    // logical_size comes from $DATA (line 375 `>`).
    assert_eq!(result.logical_size, data_size);
}

#[test]
fn synthetic_extract_data_runs_all_allocated() {
    // Same run but every cluster is allocated => AllAllocated and
    // clusters_free=false (lines 273/275 `==`).
    let runs = one_data_run(5, 2);
    let data_size = 5 * u64::from(CLUSTER);
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("d.bin", 5, data_size),
            data_attribute_non_resident(&runs, data_size),
        ],
    );
    // Mark clusters 2..7 allocated (bits 2..6 of byte 0).
    let bitmap = [0b1111_1100u8; 16];
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &bitmap, config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.data_runs[0].status, ClusterStatus::AllAllocated);
    assert!(!result.assessment.clusters_free());
}

#[test]
fn synthetic_extract_data_runs_mixed() {
    // Some clusters allocated, some free => Mixed (lines 273/275 both
    // false).
    let runs = one_data_run(4, 2); // clusters 2,3,4,5
    let data_size = 4 * u64::from(CLUSTER);
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("d.bin", 5, data_size),
            data_attribute_non_resident(&runs, data_size),
        ],
    );
    // Allocate cluster 2 only (bit 2 of byte 0).
    let bitmap = [0b0000_0100u8; 16];
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &bitmap, config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.data_runs[0].status, ClusterStatus::Mixed);
    assert!(!result.assessment.clusters_free());
}

#[test]
fn synthetic_resident_data_has_no_runs() {
    // A deleted file with resident $DATA: no data runs present
    // (line 296/297 set all_free=false because runs is empty), but a
    // non-zero logical size from the resident value.
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("small.txt", 5, 4),
            data_attribute_resident(b"data"),
        ],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert!(result.data_runs.is_empty());
    assert!(!result.assessment.data_runs_present());
    assert!(!result.assessment.clusters_free());
    // sizes_consistent: fn_data_size (4) == data_logical_size (4) => true
    // (line 384 `==`).
    assert!(result.assessment.sizes_consistent());
    assert_eq!(result.logical_size, 4);
}

#[test]
fn synthetic_sizes_inconsistent_when_fn_and_data_disagree() {
    // $FILE_NAME reports data_size 99 but resident $DATA is 4 bytes:
    // sizes_consistent is false (line 384 `==`).
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("x.txt", 5, 99),
            data_attribute_resident(b"data"),
        ],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert!(!result.assessment.sizes_consistent());
}

#[test]
fn synthetic_attributes_parseable_from_name_only() {
    // A deleted record with a $FILE_NAME but no $STANDARD_INFORMATION:
    // attributes_parseable is true because name.is_some() (line 370
    // `||`), and timestamps_plausible reflects the empty timestamp set.
    let rec = make_file_record(0, &[fn_attribute("named.txt", 5, 0)]);
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert!(result.assessment.attributes_parseable());
    assert!(result.assessment.name_recovered());
    assert_eq!(result.name.as_deref(), Some("named.txt"));
    assert!(result.created.is_none());
}

#[test]
fn synthetic_extract_data_runs_sparse() {
    // A sparse $DATA run: status Unknown, cluster_count derived from the
    // sparse branch `allocated_size / cluster_size` (line 278). 3 sparse
    // clusters => allocated_size 1536, cluster_count 1536/512 = 3.
    let runs = one_sparse_run(3);
    let data_size = 3 * u64::from(CLUSTER);
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("s.bin", 5, data_size),
            data_attribute_non_resident(&runs, data_size),
        ],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.data_runs.len(), 1);
    let run = &result.data_runs[0];
    assert_eq!(run.status, ClusterStatus::Unknown);
    assert_eq!(run.cluster_offset, 0);
    assert_eq!(run.cluster_count, 3);
    // A sparse run cannot be confirmed free.
    assert!(!result.assessment.clusters_free());
}

#[test]
fn synthetic_logical_size_prefers_data_over_fn() {
    // data_logical_size > 0 (line 392 `>`): logical_size uses the $DATA
    // size, not the (different) $FILE_NAME size. With data_size 2560 and
    // fn_data_size 1234, a `<`/`==` mutation of the comparison would
    // select fn_data_size instead.
    let runs = one_data_run(5, 2);
    let data_size = 5 * u64::from(CLUSTER); // 2560
    let rec = make_file_record(
        0,
        &[
            si_attribute(GOOD_TIME),
            fn_attribute("d.bin", 5, 1234),
            data_attribute_non_resident(&runs, data_size),
        ],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.logical_size, data_size);
}

#[test]
fn synthetic_logical_size_falls_back_to_fn_when_data_zero() {
    // data_logical_size == 0 (no $DATA attribute) and a non-zero
    // $FILE_NAME size: `data_logical_size > 0` is false (line 392), so
    // logical_size falls back to the $FILE_NAME size. A `>=`/`==`
    // mutation would (wrongly) pick the zero $DATA size. The same flag
    // drives `has_data_size` (line 399 `>`): with no data runs and a
    // name, `(has_fn_size, has_data_size) == (true, false)` makes
    // sizes_consistent true; a `>=` mutation would force a (true,true)
    // mismatch check that fails.
    let rec = make_file_record(
        0,
        &[si_attribute(GOOD_TIME), fn_attribute("n.txt", 5, 4321)],
    );
    let (mut scanner, ntfs, mut fs) = build_scanner(&[rec], &[0u8; 16], config_keep_system());

    let result = scanner.next(&ntfs, &mut fs).expect("a record").expect("ok");
    assert_eq!(result.logical_size, 4321);
    assert!(!result.assessment.data_runs_present());
    assert!(result.assessment.sizes_consistent());
}

fn all_pass() -> RecoveryAssessment {
    let checks = RecoveryChecks::VALID_SIGNATURE
        | RecoveryChecks::ATTRIBUTES_PARSEABLE
        | RecoveryChecks::NAME_RECOVERED
        | RecoveryChecks::TIMESTAMPS_PLAUSIBLE
        | RecoveryChecks::DATA_RUNS_PRESENT
        | RecoveryChecks::CLUSTERS_FREE
        | RecoveryChecks::SIZES_CONSISTENT;
    RecoveryAssessment { checks }
}

fn all_fail() -> RecoveryAssessment {
    RecoveryAssessment {
        checks: RecoveryChecks::empty(),
    }
}

#[test]
fn test_recovery_assessment_all_pass() {
    let a = all_pass();
    assert_eq!(a.score(), 7);
    assert!(a.fully_recoverable());
}

#[test]
fn test_recovery_assessment_all_fail() {
    let a = all_fail();
    assert_eq!(a.score(), 0);
    assert!(!a.fully_recoverable());
}

#[test]
fn test_recovery_assessment_partial() {
    let a = RecoveryAssessment {
        checks: RecoveryChecks::VALID_SIGNATURE
            | RecoveryChecks::ATTRIBUTES_PARSEABLE
            | RecoveryChecks::NAME_RECOVERED,
    };
    assert_eq!(a.score(), 3);
    assert!(!a.fully_recoverable());
}

#[test]
fn test_config_defaults() {
    let config = DeletedFileScanConfig::default();
    assert!(config.skip_system_records);
    assert!(!config.skip_directories);
    assert!(config.timestamp_bounds.min > 0);
    assert!(config.timestamp_bounds.max > config.timestamp_bounds.min);
}

#[test]
fn test_cluster_status_variants_are_distinct() {
    assert_ne!(ClusterStatus::AllFree, ClusterStatus::AllAllocated);
    assert_ne!(ClusterStatus::AllFree, ClusterStatus::Mixed);
    assert_ne!(ClusterStatus::AllFree, ClusterStatus::Unknown);
}

#[test]
fn test_recovery_assessment_one_field_at_a_time() {
    let base = all_fail();
    assert_eq!(base.score(), 0);

    let fields = [
        RecoveryChecks::VALID_SIGNATURE,
        RecoveryChecks::ATTRIBUTES_PARSEABLE,
        RecoveryChecks::NAME_RECOVERED,
        RecoveryChecks::TIMESTAMPS_PLAUSIBLE,
        RecoveryChecks::DATA_RUNS_PRESENT,
        RecoveryChecks::CLUSTERS_FREE,
        RecoveryChecks::SIZES_CONSISTENT,
    ]
    .map(|checks| RecoveryAssessment { checks });

    for (i, field) in fields.iter().enumerate() {
        assert_eq!(
            field.score(),
            1,
            "field index {i} should contribute 1 to score",
        );
    }
}

#[test]
fn test_deleted_data_run_debug_format() {
    let run = DeletedDataRun {
        cluster_offset: 1000,
        cluster_count: 50,
        status: ClusterStatus::AllFree,
    };
    let debug = alloc::format!("{run:?}");
    assert!(debug.contains("1000"));
    assert!(debug.contains("50"));
    assert!(debug.contains("AllFree"));
}

#[test]
fn test_deleted_file_default_state() {
    let file = NtfsDeletedFile {
        record_number: 42,
        sequence_number: 3,
        is_directory: false,
        name: None,
        parent_record_number: None,
        created: None,
        modified: None,
        accessed: None,
        mft_modified: None,
        logical_size: 0,
        data_runs: Vec::new(),
        assessment: RecoveryAssessment {
            checks: RecoveryChecks::VALID_SIGNATURE,
        },
    };
    assert_eq!(file.record_number, 42);
    assert_eq!(file.sequence_number, 3);
    assert!(!file.is_directory);
    assert!(file.name.is_none());
    assert_eq!(file.assessment.score(), 1);
}

mod integration {
    use super::*;

    #[test]
    fn test_scanner_construction() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let scanner = NtfsDeletedFileScanner::new(&ntfs, &mut testfs1);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_custom_config() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let config = DeletedFileScanConfig {
            skip_system_records: false,
            skip_directories: true,
            ..DeletedFileScanConfig::default()
        };
        let scanner = NtfsDeletedFileScanner::with_config(&ntfs, &mut testfs1, config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scanner_runs_to_completion() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut scanner = ntfs
            .deleted_files(&mut testfs1)
            .expect("scanner construction");
        let mut count = 0u64;
        while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
            match result {
                Ok(deleted) => {
                    count += 1;
                    assert!(
                        deleted.assessment.score() >= 1,
                        "record {} has score 0",
                        deleted.record_number,
                    );
                }
                Err(e) => panic!("scanner error: {e}"),
            }
        }
        eprintln!("Found {count} deleted file records");
    }

    #[test]
    fn test_scanner_skips_in_use_records() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut scanner = ntfs
            .deleted_files(&mut testfs1)
            .expect("scanner construction");
        while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
            let deleted = result.expect("scan error");
            assert_ne!(
                deleted.record_number, 5,
                "in-use root directory record yielded"
            );
        }
    }

    #[test]
    fn test_scanner_skips_system_records_by_default() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut scanner = ntfs
            .deleted_files(&mut testfs1)
            .expect("scanner construction");
        while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
            let deleted = result.expect("scan error");
            assert!(
                deleted.record_number >= SYSTEM_RECORD_COUNT,
                "system record {} not skipped",
                deleted.record_number,
            );
        }
    }

    #[test]
    fn test_deleted_file_metadata_populated() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut scanner = ntfs
            .deleted_files(&mut testfs1)
            .expect("scanner construction");
        if let Some(Ok(deleted)) = scanner.next(&ntfs, &mut testfs1) {
            assert!(deleted.sequence_number > 0 || deleted.record_number > 0);
        }
    }

    #[test]
    fn test_scanner_includes_system_records_when_configured() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let config = DeletedFileScanConfig {
            skip_system_records: false,
            ..DeletedFileScanConfig::default()
        };
        let mut scanner = NtfsDeletedFileScanner::with_config(&ntfs, &mut testfs1, config)
            .expect("scanner construction");

        let mut has_system = false;
        while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
            if let Ok(deleted) = result
                && deleted.record_number < SYSTEM_RECORD_COUNT
            {
                has_system = true;
                break;
            }
        }
        assert!(
            has_system,
            "expected at least one unused system record in testfs1"
        );
    }

    #[test]
    fn test_scanner_propagates_mft_parse_errors() {
        use crate::error::NtfsError;

        // Load test filesystem into a mutable buffer.
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let file_record_size =
            usize::try_from(ntfs.file_record_size()).expect("file record size fits usize");

        // Build a DataRunMap for fragmentation-safe offset resolution.
        let mft_file = ntfs.file(&mut testfs1, 0).unwrap();
        let mft_data_item = mft_file.data(&mut testfs1, "").unwrap().unwrap();
        let mft_attr = mft_data_item.to_attribute().unwrap();
        let nrv = mft_attr.non_resident_value().unwrap();
        let map = crate::data_run_map::DataRunMap::from_data_runs(nrv.data_runs()).unwrap();

        // Find a non-in-use record beyond system range (record >= 24)
        // by scanning the clean image first.
        let mut iter = ntfs.mft_entries(&mut testfs1).unwrap();
        let total = iter.total_records();
        let mut target_record = None;
        for record_num in SYSTEM_RECORD_COUNT..total {
            iter.seek_to_record(record_num);
            if let Some(Ok(file)) = iter.next(&ntfs, &mut testfs1)
                && !file.flags().contains(crate::file::NtfsFileFlags::IN_USE)
            {
                target_record = Some(record_num);
                break;
            }
        }

        // If no deleted record found, we can still corrupt any non-system
        // record. The scanner will encounter the error regardless.
        let corrupt_record = target_record.unwrap_or(SYSTEM_RECORD_COUNT);

        // Resolve physical offset via DataRunMap (handles fragmented MFTs).
        let file_record_size_u64 =
            u64::try_from(file_record_size).expect("file record size fits u64");
        let logical_offset = corrupt_record * file_record_size_u64;
        let (pos, _) = map.resolve_position(logical_offset).unwrap();
        let offset = pos.value().unwrap().get();
        let buf = testfs1.get_mut();
        buf[usize::try_from(offset).expect("test value fits usize")
            ..usize::try_from(offset).expect("test value fits usize") + 4]
            .copy_from_slice(&[0xDE, 0xAD, 0x00, 0x00]);

        // Re-parse and scan — the corrupted record should surface as Err.
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mut scanner = ntfs
            .deleted_files(&mut testfs1)
            .expect("scanner construction");

        let mut found_error = false;
        while let Some(result) = scanner.next(&ntfs, &mut testfs1) {
            if let Err(NtfsError::MftRecordParseFailed {
                record_number,
                source,
            }) = &result
            {
                assert_eq!(*record_number, corrupt_record);
                assert!(matches!(**source, NtfsError::InvalidFileSignature { .. }),);
                found_error = true;
            }
        }
        assert!(
            found_error,
            "scanner should have yielded an error for corrupted record {corrupt_record}",
        );
    }
}
