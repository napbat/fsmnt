use super::*;
use crate::ntfs::Ntfs;
use alloc::string::ToString;

/// Builds a minimal V2 USN record of `len` bytes (8-byte aligned),
/// with the given major/minor version and a 2-byte (1-char) name.
fn make_v2_record(len: u32, minor: u16) -> Vec<u8> {
    let record_length = usize::try_from(len).expect("test record length fits usize");
    let mut data = vec![0u8; record_length];
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&len.to_le_bytes());
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&minor.to_le_bytes());
    data[OFF_V2_FILE_NAME_LENGTH..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_V2_FILE_NAME_OFFSET..][..2].copy_from_slice(
        &u16::try_from(USN_RECORD_V2_HEADER_SIZE)
            .expect("test value fits u16")
            .to_le_bytes(),
    );
    data[USN_RECORD_V2_HEADER_SIZE] = b'A';
    data
}

/// Builds a minimal V3 USN record of `len` bytes (8-byte aligned).
fn make_v3_record(len: u32) -> Vec<u8> {
    let record_length = usize::try_from(len).expect("test record length fits usize");
    let mut data = vec![0u8; record_length];
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&len.to_le_bytes());
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&3u16.to_le_bytes());
    data[OFF_V3_FILE_NAME_LENGTH..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_V3_FILE_NAME_OFFSET..][..2].copy_from_slice(
        &u16::try_from(USN_RECORD_V3_HEADER_SIZE)
            .expect("test value fits u16")
            .to_le_bytes(),
    );
    data[USN_RECORD_V3_HEADER_SIZE] = b'B';
    data
}

/// Builds a journal whose `$J` stream is a single non-sparse segment at
/// disk byte `disk_pos`, containing `stream` bytes. Returns the journal
/// plus a cursor whose backing buffer holds `stream` at `disk_pos`.
fn journal_with_stream(disk_pos: u64, stream: &[u8]) -> (NtfsUsnJournal, std::io::Cursor<Vec<u8>>) {
    let mut buf =
        vec![0u8; usize::try_from(disk_pos).expect("test value fits usize") + stream.len()];
    buf[usize::try_from(disk_pos).expect("test value fits usize")..].copy_from_slice(stream);
    let stream_length = u64::try_from(stream.len()).expect("test stream length fits u64");
    let map = DataRunMap::from_segments_for_test(&[(Some(disk_pos), stream_length)]);
    let journal = NtfsUsnJournal {
        metadata: UsnJournalMetadata {
            maximum_size: 1 << 20,
            allocation_delta: 4096,
            journal_id: 7,
            lowest_valid_usn: 0,
        },
        map,
        j_size: stream_length,
    };
    (journal, std::io::Cursor::new(buf))
}

#[test]
fn test_usn_reason_display() {
    // Display renders the active flag names; the Ok(Default::default())
    // mutant would render an empty string.
    let reason = UsnReason::FILE_CREATE;
    let rendered = reason.to_string();
    assert_eq!(rendered, "FILE_CREATE");
    assert!(!rendered.is_empty());
}

#[test]
fn test_usn_source_info_display() {
    let info = UsnSourceInfo::DATA_MANAGEMENT;
    let rendered = info.to_string();
    assert_eq!(rendered, "DATA_MANAGEMENT");
    assert!(!rendered.is_empty());
}

#[test]
fn test_v2_minor_version_and_ids() {
    // minor_version, security_id, file_attributes carry distinct
    // non-0/1 values so return-value replacements are caught.
    let record_length: u32 = 64;
    let record_length_usize =
        usize::try_from(record_length).expect("test record length fits usize");
    let mut data = vec![0u8; record_length_usize];
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&record_length.to_le_bytes());
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&9u16.to_le_bytes());
    data[OFF_V2_SECURITY_ID..][..4].copy_from_slice(&12345u32.to_le_bytes());
    data[OFF_V2_FILE_ATTRIBUTES..][..4].copy_from_slice(&0x2020u32.to_le_bytes());
    data[OFF_V2_FILE_NAME_LENGTH..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_V2_FILE_NAME_OFFSET..][..2].copy_from_slice(&60u16.to_le_bytes());
    data[60] = b'X';

    let rec = UsnRecord::from_bytes(&data, NtfsPosition::none()).unwrap();
    assert_eq!(rec.minor_version(), 9);
    assert_eq!(rec.security_id(), 12345);
    assert_eq!(rec.file_attributes(), 0x2020);
}

#[test]
fn test_v3_minor_version() {
    let record_length: u32 = 80;
    let record_length_usize =
        usize::try_from(record_length).expect("test record length fits usize");
    let mut data = vec![0u8; record_length_usize];
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&record_length.to_le_bytes());
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&3u16.to_le_bytes());
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&7u16.to_le_bytes());
    data[OFF_V3_FILE_NAME_LENGTH..][..2].copy_from_slice(&2u16.to_le_bytes());
    data[OFF_V3_FILE_NAME_OFFSET..][..2].copy_from_slice(&76u16.to_le_bytes());
    data[76] = b'Y';

    let rec = UsnRecordV3::from_bytes(&data, NtfsPosition::none()).unwrap();
    assert_eq!(rec.minor_version(), 7);
}

#[test]
fn test_journal_j_size_and_current_offset() {
    let stream = make_v2_record(64, 0);
    let (journal, _cursor) = journal_with_stream(4096, &stream);
    // j_size returns the genuine stream length (distinct from 0/1).
    assert_eq!(journal.j_size(), 64);

    // records_from sets the starting offset; current_offset reflects it.
    let iter = journal.records_from(8);
    assert_eq!(iter.current_offset(), 8);

    let iter0 = journal.records();
    assert_eq!(iter0.current_offset(), 0);
}

#[test]
fn test_iterator_reads_v2_records() {
    // Two back-to-back V2 records (64 bytes each) at disk byte 4096.
    let mut stream = make_v2_record(64, 0);
    stream.extend_from_slice(&make_v2_record(64, 0));
    let (journal, mut cursor) = journal_with_stream(4096, &stream);

    let mut iter = journal.records();
    let mut buf = Vec::new();

    let r1 = iter.next(&mut cursor, &mut buf).unwrap().unwrap();
    assert_eq!(r1.record_length(), 64);
    assert_eq!(r1.major_version(), 2);
    // position = current offset (64) minus the buffer length (64) = 0.
    assert_eq!(r1.position().value().map(core::num::NonZero::get), None);

    // Offset advanced by the record length.
    assert_eq!(iter.current_offset(), 64);

    let r2 = iter.next(&mut cursor, &mut buf).unwrap().unwrap();
    assert_eq!(r2.record_length(), 64);
    assert_eq!(iter.current_offset(), 128);

    // Stream exhausted.
    assert!(iter.next(&mut cursor, &mut buf).is_none());
}

#[test]
fn test_iterator_next_skips_v3() {
    // A V3 record followed by a V2 record. `next` (V2-only) must skip
    // the V3 and return the V2 (exercises the `major == 2` check and
    // the loop's continue).
    let mut stream = make_v3_record(80);
    stream.extend_from_slice(&make_v2_record(64, 0));
    let (journal, mut cursor) = journal_with_stream(4096, &stream);

    let mut iter = journal.records();
    let mut buf = Vec::new();
    let r = iter.next(&mut cursor, &mut buf).unwrap().unwrap();
    assert_eq!(r.major_version(), 2);
    // Both records consumed: 80 (V3 skipped) + 64 (V2) = 144.
    assert_eq!(iter.current_offset(), 144);
}

#[test]
fn test_iterator_next_versioned_dispatches_v2_and_v3() {
    // A V3 then a V2 record; next_versioned yields both in order.
    let mut stream = make_v3_record(80);
    stream.extend_from_slice(&make_v2_record(64, 0));
    let (journal, mut cursor) = journal_with_stream(4096, &stream);

    let mut iter = journal.records();
    let mut buf = Vec::new();

    let first = iter.next_versioned(&mut cursor, &mut buf).unwrap().unwrap();
    match first {
        UsnRecordVersion::V3(r) => {
            // First record starts at virtual offset 0 (offset 80 - len 80).
            assert!(r.position().value().is_none());
        }
        UsnRecordVersion::V2(_) => panic!("expected V3 first"),
    }

    let second = iter.next_versioned(&mut cursor, &mut buf).unwrap().unwrap();
    match second {
        UsnRecordVersion::V2(r) => {
            // Second record starts at virtual offset 80 (offset 144 - len 64).
            // Guards `self.offset - buf.len()` (the `- with +` / `- with /` mutants).
            assert_eq!(r.position().value().map(core::num::NonZero::get), Some(80));
        }
        UsnRecordVersion::V3(_) => panic!("expected V2 second"),
    }

    assert!(iter.next_versioned(&mut cursor, &mut buf).is_none());
}

#[test]
fn test_iterator_zero_length_terminates() {
    // A V2 record followed by a zero-length field. Reading the zero
    // length ends iteration (no infinite loop).
    let mut stream = make_v2_record(64, 0);
    stream.extend_from_slice(&[0u8; 8]); // zero record_length
    let (journal, mut cursor) = journal_with_stream(4096, &stream);

    let mut iter = journal.records();
    let mut buf = Vec::new();
    assert!(iter.next(&mut cursor, &mut buf).is_some());
    // The zero-length record terminates iteration.
    assert!(iter.next(&mut cursor, &mut buf).is_none());
}

#[test]
fn test_iterator_too_small_record_skips_to_segment_end() {
    // A record_length below the 8-byte common header is invalid; the
    // iterator advances to the segment end and then terminates.
    let mut stream = vec![0u8; 16];
    stream[0..4].copy_from_slice(&4u32.to_le_bytes()); // record_length = 4 (< 8)
    let (journal, mut cursor) = journal_with_stream(4096, &stream);

    let mut iter = journal.records();
    let mut buf = Vec::new();
    assert!(iter.next(&mut cursor, &mut buf).is_none());
    // Advanced to the segment end (the whole 16-byte stream).
    assert_eq!(iter.current_offset(), 16);
}

/// Builds a journal from explicit `(disk_pos, size)` segments, writing
/// `records` contiguously starting at virtual offset 0 mapped to the
/// first segment's disk position. `segments` describes the layout;
/// the backing image places `data` at `data_disk_pos`.
fn journal_from_segments(
    segments: &[(Option<u64>, u64)],
    data_disk_pos: u64,
    data: &[u8],
    j_size: u64,
) -> (NtfsUsnJournal, std::io::Cursor<Vec<u8>>) {
    let mut image =
        vec![0u8; usize::try_from(data_disk_pos).expect("test value fits usize") + data.len()];
    image[usize::try_from(data_disk_pos).expect("test value fits usize")..].copy_from_slice(data);
    let map = DataRunMap::from_segments_for_test(segments);
    let journal = NtfsUsnJournal {
        metadata: UsnJournalMetadata {
            maximum_size: 1 << 20,
            allocation_delta: 4096,
            journal_id: 1,
            lowest_valid_usn: 0,
        },
        map,
        j_size,
    };
    (journal, std::io::Cursor::new(image))
}

#[test]
fn test_iterator_remaining_below_four_terminates() {
    // The single real segment has only 3 bytes; `remaining < 4` must
    // return None before attempting to read a 4-byte length. Guards the
    // `remaining < 4` comparison (line 811).
    let (journal, mut cursor) = journal_from_segments(&[(Some(4096), 3)], 4096, &[1u8, 2, 3], 3);
    let mut iter = journal.records();
    let mut buf = Vec::new();
    assert!(iter.next(&mut cursor, &mut buf).is_none());
    // Offset unchanged (no skip occurred for a too-small tail).
    assert_eq!(iter.current_offset(), 0);
}

#[test]
fn test_iterator_remaining_exactly_four_reads_length() {
    // The segment has exactly 4 bytes (remaining == 4), so `remaining < 4`
    // is false and the 4-byte length IS read. The length (4) is below the
    // 8-byte header minimum, so the record is skipped to the segment end,
    // advancing the offset to 4. With `remaining <= 4` the read would be
    // skipped and the offset would stay at 0 — so current_offset
    // distinguishes `<` from `<=` (line 811).
    let mut stream = vec![0u8; 4];
    stream[0..4].copy_from_slice(&4u32.to_le_bytes()); // record_length = 4 (< 8)
    let (journal, mut cursor) = journal_from_segments(&[(Some(4096), 4)], 4096, &stream, 4);
    let mut iter = journal.records();
    let mut buf = Vec::new();
    assert!(iter.next(&mut cursor, &mut buf).is_none());
    // The length was read and the record skipped to the 4-byte segment end.
    assert_eq!(iter.current_offset(), 4);
}

#[test]
fn test_iterator_record_length_exceeds_remaining_skips() {
    // record_length (64) exceeds the segment's remaining bytes (16), so
    // the record is invalid and the iterator skips to the segment end.
    // Guards `record_length_u64 > remaining` and the
    // `seg_end > self.offset` advance (line 839).
    let mut stream = vec![0u8; 16];
    stream[0..4].copy_from_slice(&64u32.to_le_bytes()); // record_length = 64 > 16
    stream[OFF_MAJOR_VERSION..][..2].copy_from_slice(&2u16.to_le_bytes());
    let (journal, mut cursor) = journal_from_segments(&[(Some(4096), 16)], 4096, &stream, 16);
    let mut iter = journal.records();
    let mut buf = Vec::new();
    assert!(iter.next(&mut cursor, &mut buf).is_none());
    // Skipped to the 16-byte segment end.
    assert_eq!(iter.current_offset(), 16);
}

#[test]
fn test_iterator_record_length_exactly_min_header_is_read() {
    // record_length == 8 (the minimum common header) must NOT be skipped:
    // `record_length < 8` is false at the boundary. Guards `< with <=`
    // (line 837). We give a valid 8-byte V2-versioned record padded so
    // the read of `record_length` bytes succeeds.
    let mut stream = vec![0u8; 8];
    stream[0..4].copy_from_slice(&8u32.to_le_bytes()); // record_length = 8
    stream[OFF_MAJOR_VERSION..][..2].copy_from_slice(&2u16.to_le_bytes());
    let (journal, mut cursor) = journal_from_segments(&[(Some(4096), 8)], 4096, &stream, 8);
    let mut iter = journal.records();
    let mut buf = Vec::new();
    // read_next_record reads the 8-byte record and reports major version 2.
    // `next` (V2-only) then tries UsnRecord::new which rejects the short
    // record, surfacing an Err — but read_next_record itself advanced.
    let result = iter.next(&mut cursor, &mut buf);
    // The record was read (offset advanced by 8), then V2 parsing of the
    // 8-byte buffer fails (< 62 bytes) -> Some(Err(..)).
    assert!(result.is_some());
    assert_eq!(iter.current_offset(), 8);
}

#[test]
fn test_iterator_zero_length_crosses_to_next_segment() {
    // Layout: real segment [0..16) with a zero-length record, a sparse
    // hole [16..32), then a real segment [32..96) with a V2 record.
    // Reading the zero length triggers segment_end -> next_non_sparse_offset
    // which must jump past the hole to offset 32. Guards line 825's
    // `next > self.offset` and `> with <`/`==`.
    let v2 = make_v2_record(64, 0);
    // First real segment: 16 bytes, all zero (record_length 0).
    // Stored at disk 4096; second real segment stored at disk 8192.
    let mut image = vec![0u8; 8192 + v2.len()];
    // first segment bytes already zero at 4096..4112.
    image[8192..8192 + v2.len()].copy_from_slice(&v2);
    let map = DataRunMap::from_segments_for_test(&[
        (Some(4096), 16), // virtual 0..16, zero-length record
        (None, 16),       // virtual 16..32, sparse hole
        (Some(8192), 64), // virtual 32..96, the V2 record
    ]);
    let journal = NtfsUsnJournal {
        metadata: UsnJournalMetadata {
            maximum_size: 1 << 20,
            allocation_delta: 4096,
            journal_id: 1,
            lowest_valid_usn: 0,
        },
        map,
        j_size: 96,
    };
    let mut cursor = std::io::Cursor::new(image);
    let mut iter = journal.records();
    let mut buf = Vec::new();
    let r = iter.next(&mut cursor, &mut buf).unwrap().unwrap();
    assert_eq!(r.record_length(), 64);
    // Jumped from the zero-length segment (end 16), past the sparse hole,
    // to the real segment at 32, then advanced by 64.
    assert_eq!(iter.current_offset(), 96);
}

#[test]
fn test_iterator_skips_leading_sparse_hole() {
    // A sparse hole (512 bytes) followed by a non-sparse segment holding
    // one V2 record. The iterator must skip the hole and read the record.
    let record = make_v2_record(64, 0);
    let disk_pos = 4096u64;
    let mut buf_image =
        vec![0u8; usize::try_from(disk_pos).expect("test value fits usize") + record.len()];
    buf_image[usize::try_from(disk_pos).expect("test value fits usize")..].copy_from_slice(&record);
    let map = DataRunMap::from_segments_for_test(&[
        (None, 512),          // sparse hole at virtual 0..512
        (Some(disk_pos), 64), // real data at virtual 512..576
    ]);
    let journal = NtfsUsnJournal {
        metadata: UsnJournalMetadata {
            maximum_size: 1 << 20,
            allocation_delta: 4096,
            journal_id: 1,
            lowest_valid_usn: 0,
        },
        map,
        j_size: 576,
    };
    let mut cursor = std::io::Cursor::new(buf_image);

    let mut iter = journal.records();
    let mut rec_buf = Vec::new();
    let r = iter.next(&mut cursor, &mut rec_buf).unwrap().unwrap();
    assert_eq!(r.record_length(), 64);
    // Offset jumped past the hole (512) then advanced by 64.
    assert_eq!(iter.current_offset(), 576);
}

#[test]
fn test_find_named_data_attribute() {
    // A synthetic file with two named $DATA attributes ($Max, $J).
    use crate::file::synthetic;
    let attrs = [
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 0,
            name: "$Max",
            value: vec![0u8; 32],
        },
        synthetic::ResidentAttr {
            ty: NtfsAttributeType::Data,
            instance: 1,
            name: "$J",
            value: vec![0u8; 8],
        },
    ];
    let record = synthetic::file_record(0x0001, 1, 1, &attrs);
    let (ntfs, mut cursor) = synthetic::load(&record, 30);
    let file = synthetic::open_file(&ntfs, &mut cursor, 30);

    let max_item = find_named_data_attribute(&file, &mut cursor, "$Max").unwrap();
    assert_eq!(max_item.to_attribute().unwrap().name().unwrap(), "$Max");

    let j_item = find_named_data_attribute(&file, &mut cursor, "$J").unwrap();
    assert_eq!(j_item.to_attribute().unwrap().name().unwrap(), "$J");

    // A name that doesn't exist errors with AttributeNotFound.
    assert!(matches!(
        find_named_data_attribute(&file, &mut cursor, "$Nope").unwrap_err(),
        NtfsError::AttributeNotFound { .. }
    ));
}

#[test]
fn test_usn_reason_flags() {
    let reason = UsnReason::FILE_CREATE | UsnReason::CLOSE;
    assert!(reason.contains(UsnReason::FILE_CREATE));
    assert!(reason.contains(UsnReason::CLOSE));
    assert!(!reason.contains(UsnReason::FILE_DELETE));
}

#[test]
fn test_usn_source_info_flags() {
    let info = UsnSourceInfo::DATA_MANAGEMENT | UsnSourceInfo::AUXILIARY_DATA;
    assert!(info.contains(UsnSourceInfo::DATA_MANAGEMENT));
    assert!(info.contains(UsnSourceInfo::AUXILIARY_DATA));
    assert!(!info.contains(UsnSourceInfo::REPLICATION_MANAGEMENT));
}

#[test]
fn test_usn_journal_metadata_from_bytes() {
    // Build a minimal 56-byte $Max buffer.
    let mut data = vec![0u8; 32];
    // maximum_size = 1024
    data[0..8].copy_from_slice(&1024u64.to_le_bytes());
    // allocation_delta = 256
    data[8..16].copy_from_slice(&256u64.to_le_bytes());
    // journal_id = 42
    data[16..24].copy_from_slice(&42u64.to_le_bytes());
    // lowest_valid_usn = 100
    data[24..32].copy_from_slice(&100u64.to_le_bytes());

    let meta = UsnJournalMetadata::from_bytes(&data, NtfsPosition::none()).unwrap();
    assert_eq!(meta.maximum_size, 1024);
    assert_eq!(meta.allocation_delta, 256);
    assert_eq!(meta.journal_id, 42);
    assert_eq!(meta.lowest_valid_usn, 100);
}

#[test]
fn test_usn_journal_metadata_too_small() {
    let data = vec![0u8; 10];
    let result = UsnJournalMetadata::from_bytes(&data, NtfsPosition::none());
    assert!(result.is_err());
}

#[test]
fn test_usn_record_v2_parse() {
    // Build a minimal V2 record with a 4-byte (2-char) file name.
    let record_length: u32 = 64; // 60 + 4, already 8-byte aligned
    let record_length_usize =
        usize::try_from(record_length).expect("test record length fits usize");
    let mut data = vec![0u8; record_length_usize];

    // RecordLength
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&record_length.to_le_bytes());
    // MajorVersion = 2
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&2u16.to_le_bytes());
    // MinorVersion = 0
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&0u16.to_le_bytes());
    // FileReference: record 42, seq 1
    // Encoded as: (seq << 48) | record_number, in little-endian.
    let file_ref_val = 0x2A_u64 | (0x01_u64 << 48);
    data[OFF_V2_FILE_REFERENCE..OFF_V2_FILE_REFERENCE + 8]
        .copy_from_slice(&file_ref_val.to_le_bytes());
    // ParentReference: record 5, seq 1
    let parent_ref_val = 0x05_u64 | (0x01_u64 << 48);
    data[OFF_V2_PARENT_REFERENCE..OFF_V2_PARENT_REFERENCE + 8]
        .copy_from_slice(&parent_ref_val.to_le_bytes());
    // USN = 1000
    data[OFF_V2_USN..][..8].copy_from_slice(&1000u64.to_le_bytes());
    // Reason = FILE_CREATE | CLOSE
    let reason_bits = 0x0000_0100u32 | 0x8000_0000u32;
    data[OFF_V2_REASON..][..4].copy_from_slice(&reason_bits.to_le_bytes());
    // FileNameLength = 4 bytes (2 UTF-16 chars)
    data[OFF_V2_FILE_NAME_LENGTH..][..2].copy_from_slice(&4u16.to_le_bytes());
    // FileNameOffset = 0x3C (60)
    data[OFF_V2_FILE_NAME_OFFSET..][..2].copy_from_slice(&60u16.to_le_bytes());
    // FileName = "AB" in UTF-16LE
    data[60] = b'A';
    data[61] = 0;
    data[62] = b'B';
    data[63] = 0;

    let record = UsnRecord::new(&data, NtfsPosition::none()).unwrap();

    assert_eq!(record.record_length(), 64);
    assert_eq!(record.major_version(), 2);
    assert_eq!(record.minor_version(), 0);
    assert_eq!(record.file_reference().file_record_number(), 42);
    assert_eq!(record.file_reference().sequence_number(), 1);
    assert_eq!(record.parent_reference().file_record_number(), 5);
    assert_eq!(record.usn(), 1000);
    assert!(record.is_create());
    assert!(record.is_close());
    assert!(!record.is_delete());
    assert!(!record.is_rename());
    assert_eq!(record.file_name().to_string().unwrap(), "AB");
}

#[test]
fn test_usn_record_too_small() {
    let data = vec![0u8; 10];
    let result = UsnRecord::new(&data, NtfsPosition::none());
    assert!(result.is_err());
}

#[test]
fn test_usn_record_v3_parse() {
    // Build a minimal V3 record with a 4-byte (2-char) file name.
    let record_length: u32 = 80; // 76 + 4, 8-byte aligned
    let record_length_usize =
        usize::try_from(record_length).expect("test record length fits usize");
    let mut data = vec![0u8; record_length_usize];

    // RecordLength
    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&record_length.to_le_bytes());
    // MajorVersion = 3
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&3u16.to_le_bytes());
    // MinorVersion = 0
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&0u16.to_le_bytes());
    // FileReferenceNumber: 128-bit, put a recognizable pattern
    let mut file_ref = [0u8; 16];
    file_ref[0] = 0xAA;
    file_ref[15] = 0xBB;
    data[OFF_V3_FILE_REFERENCE..OFF_V3_FILE_REFERENCE + 16].copy_from_slice(&file_ref);
    // ParentFileReferenceNumber: 128-bit
    let mut parent_ref = [0u8; 16];
    parent_ref[0] = 0xCC;
    parent_ref[15] = 0xDD;
    data[OFF_V3_PARENT_REFERENCE..OFF_V3_PARENT_REFERENCE + 16].copy_from_slice(&parent_ref);
    // USN = 2000
    data[OFF_V3_USN..][..8].copy_from_slice(&2000u64.to_le_bytes());
    // Timestamp = 132_000_000_000_000_000
    let ts_val = 132_000_000_000_000_000u64;
    data[OFF_V3_TIMESTAMP..][..8].copy_from_slice(&ts_val.to_le_bytes());
    // Reason = FILE_DELETE | CLOSE
    let reason_bits = 0x0000_0200u32 | 0x8000_0000u32;
    data[OFF_V3_REASON..][..4].copy_from_slice(&reason_bits.to_le_bytes());
    // SourceInfo = DATA_MANAGEMENT
    data[OFF_V3_SOURCE_INFO..][..4].copy_from_slice(&0x01u32.to_le_bytes());
    // SecurityId = 99
    data[OFF_V3_SECURITY_ID..][..4].copy_from_slice(&99u32.to_le_bytes());
    // FileAttributes = 0x20 (ARCHIVE)
    data[OFF_V3_FILE_ATTRIBUTES..][..4].copy_from_slice(&0x20u32.to_le_bytes());
    // FileNameLength = 4 bytes (2 UTF-16 chars)
    data[OFF_V3_FILE_NAME_LENGTH..][..2].copy_from_slice(&4u16.to_le_bytes());
    // FileNameOffset = 0x4C (76)
    data[OFF_V3_FILE_NAME_OFFSET..][..2].copy_from_slice(&76u16.to_le_bytes());
    // FileName = "CD" in UTF-16LE
    data[76] = b'C';
    data[77] = 0;
    data[78] = b'D';
    data[79] = 0;

    let record =
        UsnRecordV3::from_bytes(&data, NtfsPosition::none()).expect("should parse V3 record");

    assert_eq!(record.record_length(), 80);
    assert_eq!(record.major_version(), 3);
    assert_eq!(record.minor_version(), 0);
    assert_eq!(record.file_reference()[0], 0xAA);
    assert_eq!(record.file_reference()[15], 0xBB);
    assert_eq!(record.parent_reference()[0], 0xCC);
    assert_eq!(record.parent_reference()[15], 0xDD);
    assert_eq!(record.usn(), 2000);
    assert_eq!(record.security_id(), 99);
    assert_eq!(record.file_attributes(), 0x20);
    assert!(record.is_delete());
    assert!(record.is_close());
    assert!(!record.is_create());
    assert!(!record.is_rename());
    assert_eq!(record.source_info(), UsnSourceInfo::DATA_MANAGEMENT);
}

#[test]
fn test_usn_record_v3_too_small() {
    // V3 minimum is 78 bytes (76 header + 2 for 1-char name).
    // Provide only 50 bytes — should fail.
    let data = vec![0u8; 50];
    let result = UsnRecordV3::from_bytes(&data, NtfsPosition::none());
    assert!(result.is_err());
}

#[test]
fn test_usn_record_v3_file_name() {
    // Build a V3 record with a longer file name: "Hello" (5 UTF-16 chars = 10 bytes).
    let name_bytes = 10u16;
    let record_length: u32 = 88; // 76 + 10 = 86, rounded up to 88 for 8-byte alignment
    let record_length_usize =
        usize::try_from(record_length).expect("test record length fits usize");
    let mut data = vec![0u8; record_length_usize];

    data[OFF_RECORD_LENGTH..][..4].copy_from_slice(&record_length.to_le_bytes());
    data[OFF_MAJOR_VERSION..][..2].copy_from_slice(&3u16.to_le_bytes());
    data[OFF_MINOR_VERSION..][..2].copy_from_slice(&0u16.to_le_bytes());
    // FileNameLength
    data[OFF_V3_FILE_NAME_LENGTH..][..2].copy_from_slice(&name_bytes.to_le_bytes());
    // FileNameOffset = 76
    data[OFF_V3_FILE_NAME_OFFSET..][..2].copy_from_slice(&76u16.to_le_bytes());
    // FileName = "Hello" in UTF-16LE
    let name_utf16: Vec<u8> = "Hello".encode_utf16().flat_map(u16::to_le_bytes).collect();
    data[76..76 + name_utf16.len()].copy_from_slice(&name_utf16);

    let record = UsnRecordV3::from_bytes(&data, NtfsPosition::none())
        .expect("should parse V3 record with long name");

    assert_eq!(record.file_name().to_string().unwrap(), "Hello");
    assert_eq!(record.file_name_length(), 10);
    assert_eq!(record.file_name_offset(), 76);
}

#[test]
fn test_usn_journal_open() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // The test filesystem may or may not have a USN journal.
    // mkntfs typically does not create one, so we accept NotFound gracefully.
    let result = NtfsUsnJournal::open(&ntfs, &mut testfs1);
    match result {
        Ok(journal) => {
            // If the journal exists, verify metadata is sane.
            assert!(journal.metadata().maximum_size > 0);
            assert!(journal.j_size() > 0);
        }
        Err(NtfsError::AttributeNotFound { .. } | NtfsError::NotADirectory { .. }) => {}
        Err(e) => panic!("unexpected error opening USN journal: {e}"),
    }
}

#[test]
fn test_usn_journal_iterate() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let Ok(journal) = NtfsUsnJournal::open(&ntfs, &mut testfs1) else {
        return; // No journal on this test image.
    };

    let mut iter = journal.records();
    let mut buf = Vec::new();
    let mut count = 0u64;

    while let Some(result) = iter.next(&mut testfs1, &mut buf) {
        let record = result.unwrap();
        // Every record should have a nonzero file name length.
        assert!(record.file_name_length() > 0);
        assert_eq!(record.major_version(), 2);
        count += 1;

        // Safety limit for tests.
        if count >= 10_000 {
            break;
        }
    }

    // If the journal has data, we should have parsed some records.
    // (But it might be empty for a fresh image.)
}
