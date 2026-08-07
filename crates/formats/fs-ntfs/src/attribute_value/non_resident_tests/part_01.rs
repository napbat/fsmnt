use crate::io::{Read, Seek, SeekFrom};

use fsmnt_parser_core::io::FsReadSeek;

use super::{NtfsDataRun, NtfsDataRuns, NtfsNonResidentAttributeValue, StreamState};
use crate::indexes::NtfsFileNameIndex;
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;
use fsmnt_testkit::Cursor;

/// Builds a synthetic, valid NTFS boot sector with sector size 512 and a
/// single sector per cluster (cluster size = 512 bytes).
///
/// Only the fields read by `Ntfs::new` are populated:
/// - 0x03  OEM ID "NTFS    "
/// - 0x0B  `bytes_per_sector` = 512
/// - 0x0D  `sectors_per_cluster` = 1
/// - 0x28  `total_sectors` = 0x100000
/// - 0x30  `mft_lcn` = 1
/// - 0x38  `mft_mirror_lcn` = 2
/// - 0x40  `clusters_per_mft_record` = -10 (1024-byte records)
/// - 0x1FE boot signature 0x55 0xAA
fn synthetic_boot_sector() -> [u8; 512] {
    let mut buf = [0u8; 512];
    buf[0] = 0xEB;
    buf[1] = 0x52;
    buf[2] = 0x90;
    buf[3..11].copy_from_slice(b"NTFS    ");
    buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    buf[0x0D] = 1; // sectors_per_cluster -> cluster_size = 512
    buf[0x28..0x30].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    buf[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // mft_lcn
    buf[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
    buf[0x40] = (-10i8).cast_unsigned(); // clusters_per_mft_record = -10 => 1024 bytes
    buf[0x44] = (-12i8).cast_unsigned(); // clusters_per_index_buffer = -12
    buf[510] = 0x55;
    buf[511] = 0xAA;
    buf
}

/// Builds a 4 KiB synthetic disk whose first sector is a valid NTFS boot
/// sector, returns the parsed `Ntfs` (cluster size 512) and the backing
/// cursor. Byte `i` of the disk equals the low byte of `i` so reads are verifiable.
fn make_ntfs() -> (Ntfs, Cursor<Vec<u8>>) {
    let mut disk = vec![0u8; 4096];
    let boot = synthetic_boot_sector();
    disk[..512].copy_from_slice(&boot);
    for (i, byte) in disk.iter_mut().enumerate() {
        if i >= 512 {
            *byte = i.to_le_bytes()[0];
        }
    }
    let mut cursor = Cursor::new(disk);
    let ntfs = Ntfs::new(&mut cursor).unwrap();
    (ntfs, cursor)
}

/// Encoded data runs (cluster size 512):
/// - `21 02 05 00`: count len 1 = 2 clusters (1024 bytes), VCN len 2 = +5
///   => LCN 5, disk position 5*512 = 2560.
/// - `01 03`: count len 1 = 3 clusters (1536 bytes), VCN len 0 => sparse.
/// - `11 01 02`: count len 1 = 1 cluster (512 bytes), VCN len 1 = +2
///   => LCN 7, disk position 7*512 = 3584.
/// - `00`: terminator.
const DATA_RUNS: &[u8] = &[0x21, 0x02, 0x05, 0x00, 0x01, 0x03, 0x11, 0x01, 0x02, 0x00];

#[test]
fn test_data_runs_iterator_parses_runs() {
    let (ntfs, _disk) = make_ntfs();
    let mut runs = NtfsDataRuns::new(&ntfs, DATA_RUNS, NtfsPosition::new(0x4000));

    // Run 1: real data, 1024 bytes at disk position 2560.
    let r1 = runs.next().unwrap().unwrap();
    assert_eq!(r1.allocated_size(), 1024);
    assert_eq!(r1.data_position().value().unwrap().get(), 2560);

    // Run 2: sparse, 1536 bytes, no disk position.
    let r2 = runs.next().unwrap().unwrap();
    assert_eq!(r2.allocated_size(), 1536);
    assert!(r2.data_position().value().is_none());

    // Run 3: real data, 512 bytes at disk position 3584.
    let r3 = runs.next().unwrap().unwrap();
    assert_eq!(r3.allocated_size(), 512);
    assert_eq!(r3.data_position().value().unwrap().get(), 3584);

    // Terminator.
    assert!(runs.next().is_none());
    // Fused: still None after the end.
    assert!(runs.next().is_none());
}

#[test]
fn test_data_runs_position_advances() {
    // The data-run header position is `base + offset`, exercising the `+`
    // in `position()`. base 0x4000; after consuming run 1 (4 bytes) the
    // offset is 4.
    let (ntfs, _disk) = make_ntfs();
    let mut runs = NtfsDataRuns::new(&ntfs, DATA_RUNS, NtfsPosition::new(0x4000));
    assert_eq!(runs.position().value().unwrap().get(), 0x4000);
    let _ = runs.next().unwrap().unwrap();
    assert_eq!(runs.position().value().unwrap().get(), 0x4000 + 4);
}

#[test]
fn test_data_runs_zero_cluster_count_is_error() {
    // header 0x11 (count len 1, vcn len 1), count byte 0 => invalid cluster count.
    let (ntfs, _disk) = make_ntfs();
    let data = [0x11u8, 0x00, 0x01];
    let mut runs = NtfsDataRuns::new(&ntfs, &data, NtfsPosition::new(0x10));
    assert!(runs.next().unwrap().is_err());
}

#[test]
fn test_data_runs_byte_count_too_large_is_error() {
    // Lower nibble 9 => cluster_count_byte_count 9 > MAX_BYTE_COUNT (8) => error.
    let (ntfs, _disk) = make_ntfs();
    let data = [0x09u8, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let mut runs = NtfsDataRuns::new(&ntfs, &data, NtfsPosition::new(0x10));
    assert!(runs.next().unwrap().is_err());

    // A byte_count of exactly MAX_BYTE_COUNT (8) is accepted (not an error
    // from validate_byte_count) provided enough bytes follow.
    let data_ok = [0x08u8, 1, 0, 0, 0, 0, 0, 0, 0, 0x00];
    let mut runs_ok = NtfsDataRuns::new(&ntfs, &data_ok, NtfsPosition::new(0x10));
    let run = runs_ok.next().unwrap().unwrap();
    assert_eq!(run.allocated_size(), 512); // 1 cluster (count = 1) * 512
}

#[test]
fn test_parse_variable_length_signed_integer_negative() {
    // A single byte 0xFF must sign-extend to -1, not 255 (validates the
    // shl/shr sign-extension arithmetic).
    let value = NtfsDataRuns::parse_variable_length_signed_integer(&[0xFF]);
    assert_eq!(value, -1);

    // Two-byte 0x00 0x80 => 0x8000 sign-extends to -32768.
    let value = NtfsDataRuns::parse_variable_length_signed_integer(&[0x00, 0x80]);
    assert_eq!(value, -32768);

    // A clearly positive multi-byte value is preserved exactly.
    let value = NtfsDataRuns::parse_variable_length_signed_integer(&[0x01, 0x02, 0x03]);
    assert_eq!(value, 0x0003_0201);
}

#[test]
fn test_parse_variable_length_unsigned_integer() {
    assert_eq!(
        NtfsDataRuns::parse_variable_length_unsigned_integer(&[0xFF]),
        255
    );
    assert_eq!(
        NtfsDataRuns::parse_variable_length_unsigned_integer(&[0x34, 0x12]),
        0x1234
    );
    assert_eq!(NtfsDataRuns::parse_variable_length_unsigned_integer(&[]), 0);
}

#[test]
fn test_data_run_read_real_and_position() {
    // A real data run at disk position 2560, 1024 bytes.
    let (_ntfs, mut disk) = make_ntfs();
    let mut run = NtfsDataRun::new(NtfsPosition::new(2560), 1024);

    assert_eq!(run.allocated_size(), 1024);
    assert_eq!(FsReadSeek::<Cursor<Vec<u8>>>::len(&run), 1024);
    assert_eq!(run.remaining_len(), 1024);
    assert_eq!(run.stream_position(), 0);

    // Reading 4 bytes returns disk bytes 2560..2564 (each byte == its index).
    let mut buf = [0u8; 4];
    let n = run.read(&mut disk, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(
        buf,
        [
            2560_u32.to_le_bytes()[0],
            2561_u32.to_le_bytes()[0],
            2562_u32.to_le_bytes()[0],
            2563_u32.to_le_bytes()[0],
        ]
    );

    // Stream position advanced; remaining shrank.
    assert_eq!(run.stream_position(), 4);
    assert_eq!(run.remaining_len(), 1020);
    // data_position = base + stream_position.
    assert_eq!(run.data_position().value().unwrap().get(), 2564);
}

#[test]
fn test_data_run_read_clamps_to_remaining() {
    // Allocated size 3; a 10-byte buffer reads only 3 bytes, then 0.
    let (_ntfs, mut disk) = make_ntfs();
    let mut run = NtfsDataRun::new(NtfsPosition::new(600), 3);
    let mut buf = [0u8; 10];
    let n = run.read(&mut disk, &mut buf).unwrap();
    assert_eq!(n, 3);
    assert_eq!(run.remaining_len(), 0);
    // A further read returns 0 (the `remaining_len() == 0` branch).
    let n2 = run.read(&mut disk, &mut buf).unwrap();
    assert_eq!(n2, 0);
}

#[test]
fn test_data_run_read_sparse_zero_fills() {
    let (_ntfs, mut disk) = make_ntfs();
    let mut run = NtfsDataRun::new(NtfsPosition::none(), 8);
    let mut buf = [0xAAu8; 8];
    let n = run.read(&mut disk, &mut buf).unwrap();
    assert_eq!(n, 8);
    assert_eq!(buf, [0u8; 8]);
    assert_eq!(run.stream_position(), 8);
}

#[test]
fn test_data_run_seek_and_data_position_past_end() {
    let (_ntfs, mut disk) = make_ntfs();
    let mut run = NtfsDataRun::new(NtfsPosition::new(2560), 512);

    let pos = run.seek(&mut disk, SeekFrom::Start(100)).unwrap();
    assert_eq!(pos, 100);
    assert_eq!(run.stream_position(), 100);
    assert_eq!(FsReadSeek::<Cursor<Vec<u8>>>::stream_position(&run), 100);
    assert_eq!(run.data_position().value().unwrap().get(), 2660);

    // Seek exactly to allocated_size: still a valid data position (<=).
    run.seek(&mut disk, SeekFrom::Start(512)).unwrap();
    assert_eq!(run.data_position().value().unwrap().get(), 2560 + 512);

    // Seek past allocated_size: data_position becomes None.
    run.seek(&mut disk, SeekFrom::Start(513)).unwrap();
    assert!(run.data_position().value().is_none());
}

#[test]
fn test_stream_state_data_size_and_stream_position() {
    let state = StreamState::new(4096, 4096);
    assert_eq!(state.data_size(), 4096);
    assert_eq!(state.stream_position(), 0);
}

#[test]
fn test_stream_state_simplify_seek() {
    let state = StreamState::new(1000, 1000);

    // Start passes through unchanged.
    assert!(matches!(
        state.simplify_seek(SeekFrom::Start(42), 1000).unwrap(),
        SeekFrom::Start(42)
    ));
    // End(0) => Start(data_size).
    assert!(matches!(
        state.simplify_seek(SeekFrom::End(0), 1000).unwrap(),
        SeekFrom::Start(1000)
    ));
    // End(+5) => Start(data_size + 5).
    assert!(matches!(
        state.simplify_seek(SeekFrom::End(5), 1000).unwrap(),
        SeekFrom::Start(1005)
    ));
    // End(-10) => Start(data_size - 10).
    assert!(matches!(
        state.simplify_seek(SeekFrom::End(-10), 1000).unwrap(),
        SeekFrom::Start(990)
    ));
    // Current(+0) at position 0 stays Current(0).
    assert!(matches!(
        state.simplify_seek(SeekFrom::Current(7), 1000).unwrap(),
        SeekFrom::Current(7)
    ));
    // Current(-1) from position 0 underflows => error.
    assert!(state.simplify_seek(SeekFrom::Current(-1), 1000).is_err());
}

/// Helper: build a non-resident attribute value reader over `DATA_RUNS`
/// with the given used data size and initialized size.
fn make_value(
    ntfs: &Ntfs,
    data_size: u64,
    initialized_size: u64,
) -> NtfsNonResidentAttributeValue<'_, '_> {
    NtfsNonResidentAttributeValue::new(
        ntfs,
        DATA_RUNS,
        NtfsPosition::new(0x4000),
        data_size,
        initialized_size,
    )
    .unwrap()
}

#[test]
fn test_non_resident_value_len_and_position() {
    let (ntfs, _disk) = make_ntfs();
    // Used data size 3072 spans all three runs (1024 + 1536 + 512).
    let value = make_value(&ntfs, 3072, 3072);
    assert_eq!(value.len(), 3072);
    assert_eq!(FsReadSeek::<Cursor<Vec<u8>>>::len(&value), 3072);
    assert!(!value.is_empty());
    assert_eq!(value.stream_position(), 0);
    assert_eq!(FsReadSeek::<Cursor<Vec<u8>>>::stream_position(&value), 0);
    // The reader starts positioned at the first run's disk position (2560).
    assert_eq!(value.data_position().value().unwrap().get(), 2560);
}

#[test]
fn test_non_resident_value_is_empty_true() {
    let (ntfs, _disk) = make_ntfs();
    let value = make_value(&ntfs, 0, 0);
    assert!(value.is_empty());
    assert_eq!(value.len(), 0);
}

#[test]
fn test_non_resident_value_read_across_runs() {
    let (ntfs, mut disk) = make_ntfs();
    // data_size 3072 (= all three runs); initialized to full size.
    let mut value = make_value(&ntfs, 3072, 3072);

    let mut buf = [0u8; 3072];
    value.read_exact(&mut disk, &mut buf).unwrap();

    // First 1024 bytes come from disk position 2560.. (byte i == its index).
    for (i, b) in buf[..1024].iter().enumerate() {
        assert_eq!(*b, (2560 + i).to_le_bytes()[0]);
    }
    // Next 1536 bytes are the sparse run: all zeros.
    assert!(buf[1024..2560].iter().all(|&b| b == 0));
    // Final 512 bytes come from disk position 3584.. .
    for (i, b) in buf[2560..3072].iter().enumerate() {
        assert_eq!(*b, (3584 + i).to_le_bytes()[0]);
    }
    assert_eq!(value.stream_position(), 3072);
}

#[test]
fn test_non_resident_value_initialized_size_zero_fill() {
    let (ntfs, mut disk) = make_ntfs();
    // data_size 1024 but only the first 16 bytes are initialized; the rest
    // must read back as zeros even though the run has real disk backing.
    let mut value = make_value(&ntfs, 1024, 16);

    let mut buf = [0xCCu8; 1024];
    let n = value.read(&mut disk, &mut buf).unwrap();
    assert_eq!(n, 1024);
    for (i, b) in buf[..16].iter().enumerate() {
        assert_eq!(*b, (2560 + i).to_le_bytes()[0]);
    }
    assert!(buf[16..].iter().all(|&b| b == 0));
}

#[test]
fn test_non_resident_value_seek_and_read() {
    let (ntfs, mut disk) = make_ntfs();
    let mut value = make_value(&ntfs, 3072, 3072);

    // Seek into the third run (offset 2560 + 4 = 2564) and read 4 bytes.
    let p = value.seek(&mut disk, SeekFrom::Start(2564)).unwrap();
    assert_eq!(p, 2564);
    assert_eq!(value.stream_position(), 2564);
    assert_eq!(FsReadSeek::<Cursor<Vec<u8>>>::stream_position(&value), 2564);

    let mut buf = [0u8; 4];
    value.read_exact(&mut disk, &mut buf).unwrap();
    // Third run starts at disk 3584; offset within run = 2564 - 2560 = 4.
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, (3584 + 4 + i).to_le_bytes()[0]);
    }

    // Seek back to the start re-reads run 1.
    value.seek(&mut disk, SeekFrom::Start(0)).unwrap();
    assert_eq!(value.stream_position(), 0);
    value.read_exact(&mut disk, &mut buf).unwrap();
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, (2560 + i).to_le_bytes()[0]);
    }
}

#[test]
fn test_non_resident_value_seek_from_end() {
    let (ntfs, mut disk) = make_ntfs();
    let mut value = make_value(&ntfs, 3072, 3072);

    // Seek to 4 bytes before the end (offset 3068) within the third run.
    value.seek(&mut disk, SeekFrom::End(-4)).unwrap();
    assert_eq!(value.stream_position(), 3068);
    let mut buf = [0u8; 4];
    value.read_exact(&mut disk, &mut buf).unwrap();
    // offset within third run = 3068 - 2560 = 508; disk = 3584 + 508.
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, (3584 + 508 + i).to_le_bytes()[0]);
    }
}

#[test]
fn test_non_resident_attached_read_seek() {
    let (ntfs, mut disk) = make_ntfs();
    let value = make_value(&ntfs, 3072, 3072);
    let mut attached = value.attach(&mut disk);

    assert_eq!(attached.len(), 3072);
    assert!(!attached.is_empty());

    let mut buf = [0u8; 4];
    attached.read_exact(&mut buf).unwrap();
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, (2560 + i).to_le_bytes()[0]);
    }

    let pos = attached.seek(SeekFrom::Start(2560)).unwrap();
    assert_eq!(pos, 2560);
    attached.read_exact(&mut buf).unwrap();
    for (i, b) in buf.iter().enumerate() {
        assert_eq!(*b, (3584 + i).to_le_bytes()[0]);
    }
}

#[test]
fn test_non_resident_attached_is_empty() {
    // An attached value over a zero-length attribute reports is_empty() == true.
    let (ntfs, mut disk) = make_ntfs();
    let value = make_value(&ntfs, 0, 0);
    let attached = value.attach(&mut disk);
    assert!(attached.is_empty());
    assert_eq!(attached.len(), 0);
}

/// Builds a `StreamState` with the given sizes and a single real data run
/// (disk position 600, the given allocated size) installed as the current run.
fn stream_state_with_run(
    data_size: u64,
    initialized_size: u64,
    allocated_size: u64,
) -> StreamState {
    let mut state = StreamState::new(data_size, initialized_size);
    state.set_stream_data_run(Some(NtfsDataRun::new(
        NtfsPosition::new(600),
        allocated_size,
    )));
    state
}

#[test]
fn test_read_data_run_zero_fill_with_nonzero_offset() {
    // initialized_size == 0 with stream_position 0 forces the zero-fill
    // branch. bytes_read starts at 5 so `start` is nonzero.
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = stream_state_with_run(100, 0, 100);

    let mut buf = [0xAAu8; 20];
    let mut bytes_read = 5usize;
    let progressed = state
        .read_data_run(&mut disk, &mut buf, &mut bytes_read)
        .unwrap();
    assert!(progressed);

    // remaining_buf_len = 20 - 5 = 15; remaining_data_size = 100.
    // bytes_to_zero = 15. buf[5..20] zeroed, buf[0..5] untouched.
    assert_eq!(&buf[..5], &[0xAA; 5]);
    assert!(buf[5..20].iter().all(|&b| b == 0));
    assert_eq!(bytes_read, 20);
    assert_eq!(state.stream_position(), 15);

    // The current data run advanced by 15 (its data position moved 600 -> 615).
    assert_eq!(state.data_position().value().unwrap().get(), 615);
}

#[test]
fn test_read_data_run_initialized_partial_offset() {
    // initialized_size 50 with stream_position 0 takes the disk-read branch.
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = stream_state_with_run(100, 50, 100);

    let mut buf = [0u8; 30];
    let mut bytes_read = 10usize;
    let progressed = state
        .read_data_run(&mut disk, &mut buf, &mut bytes_read)
        .unwrap();
    assert!(progressed);

    // end = 10 + min(30 - 10, 100) = 30; initialized_read_len = min(20, 50) = 20.
    // 20 bytes read from disk position 600..620 into buf[10..30].
    for (i, b) in buf[10..30].iter().enumerate() {
        assert_eq!(*b, (600 + i).to_le_bytes()[0]);
    }
    assert_eq!(bytes_read, 30);
    assert_eq!(state.stream_position(), 20);
}

#[test]
fn test_read_data_run_no_current_run() {
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = StreamState::new(100, 100);
    let mut buf = [0u8; 8];
    let mut bytes_read = 0usize;
    // No data run installed: returns false without touching the buffer.
    assert!(
        !state
            .read_data_run(&mut disk, &mut buf, &mut bytes_read)
            .unwrap()
    );
    assert_eq!(bytes_read, 0);
}

#[test]
fn test_seek_data_run_inside_run() {
    // bytes_left_to_seek (30) < remaining_len (100): seek inside this run.
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = stream_state_with_run(100, 100, 100);
    let mut left = 30u64;
    // SeekFrom::Start selects the `SeekFrom::Start(*bytes_left_to_seek)` arm.
    let done = state
        .seek_data_run(&mut disk, SeekFrom::Start(0), &mut left)
        .unwrap();
    assert!(done);
    // The run was seeked to offset 30 (disk position 630).
    assert_eq!(state.data_position().value().unwrap().get(), 630);
    // bytes_left_to_seek is unchanged because we stopped inside this run.
    assert_eq!(left, 30);
}

#[test]
fn test_seek_data_run_skip_whole_run_at_boundary() {
    // bytes_left_to_seek (100) == remaining_len (100): the `<` test is false,
    // so the whole run is skipped (returns false, subtracts remaining_len).
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = stream_state_with_run(100, 100, 100);
    let mut left = 100u64;
    let done = state
        .seek_data_run(&mut disk, SeekFrom::Start(0), &mut left)
        .unwrap();
    assert!(!done);
    assert_eq!(left, 0);
}

#[test]
fn test_seek_loop_zero_with_exhausted_run() {
    // bytes_left_to_seek starts at 0. The genuine `while bytes_left_to_seek > 0`
    // skips the loop body, leaving the (exhausted) current run installed.
    let (_ntfs, mut disk) = make_ntfs();
    let mut state = stream_state_with_run(100, 100, 10);
    // Exhaust the current run so remaining_len() == 0.
    {
        let mut run = NtfsDataRun::new(NtfsPosition::new(600), 10);
        run.seek(&mut disk, SeekFrom::Start(10)).unwrap();
        state.set_stream_data_run(Some(run));
    }

    let pos = state
        .seek_loop(&mut disk, SeekFrom::Current(0), 0, |_fs| Ok(None))
        .unwrap();
    assert_eq!(pos, 0);
    // The current run is still installed (data position 600 + 10 = 610),
    // because the loop body never ran. A `>=` mutation would run one extra
    // iteration, exhaust the run, call advance() -> None, and clear the run.
    assert_eq!(state.data_position().value().unwrap().get(), 610);
}

#[test]
fn test_read_and_seek() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "1000-bytes-file".
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "1000-bytes-file")
            .unwrap()
            .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Get its data attribute.
    let data_attribute_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    assert!(!data_attribute.is_resident());
    assert_eq!(data_attribute.value_length(), 1000);

    let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
    assert_eq!(data_attribute_value.stream_position(), 0);
    assert_eq!(data_attribute_value.len(), 1000);

    // TEST READING
    let data_position_before = data_attribute_value.data_position().value().unwrap();

    // We have a 1001 bytes buffer, but the file is only 1000 bytes long.
    // The last byte should be untouched.
    let mut buf = [0xCCu8; 1001];
    let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
    assert_eq!(bytes_read, 1000);
    assert_eq!(&buf[..1000], &b"12345".repeat(200));
    assert_eq!(buf[1000], 0xCC);

    // The internal position should have stopped directly after the last byte of the file,
    // and must also yield a valid data position.
    assert_eq!(data_attribute_value.stream_position(), 1000);

    let data_position_after = data_attribute_value.data_position().value().unwrap();
    assert_eq!(
        data_position_after,
        data_position_before.checked_add(1000).unwrap()
    );

    // TEST SEEKING
    // A seek to the beginning should yield the data position before the read.
    data_attribute_value
        .seek(&mut testfs1, SeekFrom::Start(0))
        .unwrap();
    assert_eq!(data_attribute_value.stream_position(), 0);
    assert_eq!(
        data_attribute_value.data_position().value().unwrap(),
        data_position_before
    );

    // A seek to one byte after the last read byte should yield the data position
    // after the read.
    data_attribute_value
        .seek(&mut testfs1, SeekFrom::Start(1000))
        .unwrap();
    assert_eq!(data_attribute_value.stream_position(), 1000);
    assert_eq!(
        data_attribute_value.data_position().value().unwrap(),
        data_position_after
    );

    // A seek beyond the allocated size of the data run (1024 bytes) must yield
    // no valid data position.
    data_attribute_value
        .seek(&mut testfs1, SeekFrom::Start(1026))
        .unwrap();
    assert_eq!(data_attribute_value.stream_position(), 1026);
    assert_eq!(data_attribute_value.data_position().value(), None);
}

#[test]
fn test_sparse_file() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "sparse-file".
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "sparse-file")
            .unwrap()
            .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Get its data attribute.
    let data_attribute_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    assert!(!data_attribute.is_resident());
    assert_eq!(data_attribute.value_length(), 500_005);

    // Check its Data Runs.
    // The first one has data, the second one is sparse, the third one has data again.
    let non_resident_value = data_attribute.non_resident_value().unwrap();
    let mut data_runs = non_resident_value.data_runs();

    let first_data_run = data_runs.next().unwrap().unwrap();
    let second_data_run = data_runs.next().unwrap().unwrap();
    let third_data_run = data_runs.next().unwrap().unwrap();
    assert!(data_runs.next().is_none());

    assert!(first_data_run.data_position().value().is_some());
    assert!(second_data_run.data_position().value().is_none());
    assert!(third_data_run.data_position().value().is_some());

    // Read the data and validate it.
    let mut data_attribute_value = data_attribute.value(&mut testfs1).unwrap();
    assert_eq!(data_attribute_value.stream_position(), 0);
    assert_eq!(data_attribute_value.len(), 500_005);

    let mut buf = vec![0u8; 500_005];
    let bytes_read = data_attribute_value.read(&mut testfs1, &mut buf).unwrap();
    assert_eq!(bytes_read, 500_005);
    assert_eq!(buf[..5], [b'1', b'2', b'3', b'4', b'5']);
    assert_eq!(buf[5..500_000], [0u8].repeat(499_995));
    assert_eq!(buf[500_000..500_005], [b'1', b'1', b'1', b'1', b'1']);
}

#[test]
fn test_seek_to_middle_and_back() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find 1000-bytes-file (non-resident, content is "12345" repeated 200 times).
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "1000-bytes-file")
        .unwrap()
        .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
    let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attr = data_item.to_attribute().unwrap();
    let mut value = data_attr.value(&mut testfs1).unwrap();

    // Seek to middle (offset 500).
    value.seek(&mut testfs1, SeekFrom::Start(500)).unwrap();
    assert_eq!(value.stream_position(), 500);

    // Read 5 bytes from the middle.
    let mut buf = [0u8; 5];
    value.read_exact(&mut testfs1, &mut buf).unwrap();
    assert_eq!(&buf, b"12345");
    assert_eq!(value.stream_position(), 505);

    // Seek back to start.
    value.seek(&mut testfs1, SeekFrom::Start(0)).unwrap();
    assert_eq!(value.stream_position(), 0);

    // Read first 5 bytes.
    value.read_exact(&mut testfs1, &mut buf).unwrap();
    assert_eq!(&buf, b"12345");
}

#[test]
fn test_seek_from_end() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "1000-bytes-file")
        .unwrap()
        .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
    let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attr = data_item.to_attribute().unwrap();
    let mut value = data_attr.value(&mut testfs1).unwrap();

    // Seek to 5 bytes before the end.
    value.seek(&mut testfs1, SeekFrom::End(-5)).unwrap();
    assert_eq!(value.stream_position(), 995);

    let mut buf = [0u8; 5];
    value.read_exact(&mut testfs1, &mut buf).unwrap();
    assert_eq!(&buf, b"12345");
    assert_eq!(value.stream_position(), 1000);
}

#[test]
fn test_seek_current_forward() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "1000-bytes-file")
        .unwrap()
        .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
    let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attr = data_item.to_attribute().unwrap();
    let mut value = data_attr.value(&mut testfs1).unwrap();

    // Read 5 bytes, then seek forward by 5 more.
    let mut buf = [0u8; 5];
    value.read_exact(&mut testfs1, &mut buf).unwrap();
    assert_eq!(value.stream_position(), 5);

    value.seek(&mut testfs1, SeekFrom::Current(5)).unwrap();
    assert_eq!(value.stream_position(), 10);

    value.read_exact(&mut testfs1, &mut buf).unwrap();
    assert_eq!(&buf, b"12345");
}

#[test]
fn test_non_resident_is_empty() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "1000-bytes-file")
        .unwrap()
        .unwrap();
    let file = entry.to_file(&ntfs, &mut testfs1).unwrap();
    let data_item = file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attr = data_item.to_attribute().unwrap();
    let value = data_attr.value(&mut testfs1).unwrap();

    assert!(!value.is_empty());
    assert_eq!(value.len(), 1000);
}
