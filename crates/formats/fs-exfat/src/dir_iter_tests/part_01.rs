use super::*;
use crate::entry_set::compute_set_checksum;
use crate::test_helpers::*;
use alloc::vec;
use alloc::vec::Vec;

/// Writes a correct `SetChecksum` into bytes 2-3 of the raw
/// entry set.
fn write_set_checksum(raw: &mut [u8]) {
    let checksum = compute_set_checksum(raw);
    raw[2..4].copy_from_slice(&checksum.to_le_bytes());
}

/// Builds a minimal file entry set (0x85 + 0xC0 + 0xC1) for
/// the given name, returning the raw bytes. The `SetChecksum`
/// is written correctly.
fn build_file_entry_set(name: &str) -> Vec<u8> {
    let utf16: Vec<u16> = name.encode_utf16().collect();
    let name_entry_count = utf16.len().div_ceil(15);
    let secondary_count = 1 + name_entry_count;
    let total = 1 + secondary_count;
    let mut raw = vec![0u8; total * DIR_ENTRY_SIZE];

    // Primary entry (0x85)
    raw[0] = ENTRY_TYPE_FILE;
    raw[1] = u8::try_from(secondary_count).expect("test secondary count fits u8");
    // set_checksum at bytes 2-3 (filled later)
    // file_attributes at bytes 4-5: 0x0020 (archive)
    raw[4] = 0x20;
    raw[5] = 0x00;

    // Stream extension entry (0xC0) at offset 32
    let stream_off = DIR_ENTRY_SIZE;
    raw[stream_off] = ENTRY_TYPE_STREAM;
    raw[stream_off + 1] = 0x01; // AllocationPossible flag
    raw[stream_off + 3] =
        u8::try_from(utf16.len()).expect("test name fits the exFAT length field");
    // first_cluster at offset 20 within stream entry
    raw[stream_off + 20..stream_off + 24].copy_from_slice(&5u32.to_le_bytes());
    // data_length at offset 24 within stream entry
    raw[stream_off + 24..stream_off + 32].copy_from_slice(&1024u64.to_le_bytes());
    // valid_data_length at offset 8 within stream entry
    raw[stream_off + 8..stream_off + 16].copy_from_slice(&1024u64.to_le_bytes());

    // File name entries (0xC1)
    for ne_idx in 0..name_entry_count {
        let ne_off = (2 + ne_idx) * DIR_ENTRY_SIZE;
        raw[ne_off] = ENTRY_TYPE_NAME;
        raw[ne_off + 1] = 0x00; // general_flags
        for ch_idx in 0..15 {
            let global_idx = ne_idx * 15 + ch_idx;
            if global_idx >= utf16.len() {
                break;
            }
            let [lo, hi] = utf16[global_idx].to_le_bytes();
            raw[ne_off + 2 + ch_idx * 2] = lo;
            raw[ne_off + 2 + ch_idx * 2 + 1] = hi;
        }
    }

    write_set_checksum(&mut raw);
    raw
}

/// Writes directory entry bytes into the root directory cluster
/// of the image.
fn write_dir_entries(image: &mut [u8], cluster: u32, entries: &[u8]) {
    let off = cluster_heap_offset(cluster);
    image[off..off + entries.len()].copy_from_slice(entries);
}

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

#[test]
fn iter_file_entry_basic() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF); // EOC

    let entry_set = build_file_entry_set("test.txt");
    let mut dir_data = entry_set;
    // Append end-of-directory marker.
    dir_data.resize(dir_data.len() + DIR_ENTRY_SIZE, 0x00);
    write_dir_entries(&mut image, 2, &dir_data);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "test.txt");
            assert!(es.checksum_valid());
            assert_eq!(es.secondary_count(), 2);
            assert_eq!(es.first_cluster(), 5);
            assert_eq!(es.data_length(), 1024);
        }
        other => panic!("Expected FileEntry, got: {other:?}"),
    }

    // Should be done (end-of-directory).
    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_volume_label() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Write volume label entry (0x83).
    image[off] = ENTRY_TYPE_VOLUME_LABEL;
    image[off + 1] = 8; // character_count
    let label = "MYVOLUME";
    let utf16: Vec<u16> = label.encode_utf16().collect();
    for (i, &ch) in utf16.iter().enumerate() {
        let [lo, hi] = ch.to_le_bytes();
        image[off + 2 + i * 2] = lo;
        image[off + 2 + i * 2 + 1] = hi;
    }
    // End-of-directory marker at next entry.
    // (The rest of the cluster is already zeroed.)

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::VolumeLabel(label))) => {
            assert_eq!(label, "MYVOLUME");
        }
        other => panic!("Expected VolumeLabel, got: {other:?}"),
    }

    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_end_of_directory() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
    // Root directory cluster is already zeroed (0x00 = end).

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();
    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_skips_bitmap_upcase() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Bitmap entry (0x81).
    image[off] = ENTRY_TYPE_BITMAP;
    // Upcase entry (0x82) at next slot.
    image[off + DIR_ENTRY_SIZE] = ENTRY_TYPE_UPCASE;
    // File entry set at slot 2.
    let entry_set = build_file_entry_set("hello.dat");
    let es_start = off + 2 * DIR_ENTRY_SIZE;
    image[es_start..es_start + entry_set.len()].copy_from_slice(&entry_set);
    // End-of-directory after the entry set (already zeroed).

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "hello.dat");
        }
        other => panic!("Expected FileEntry, got: {other:?}"),
    }

    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_skips_unused_entries() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Write an unused entry (bit 7 clear, e.g. 0x05).
    image[off] = 0x05;
    // Fill remaining 31 bytes with nonzero to prove they are
    // skipped.
    for b in &mut image[off + 1..off + DIR_ENTRY_SIZE] {
        *b = 0xFF;
    }
    // File entry set at slot 1.
    let entry_set = build_file_entry_set("file.bin");
    let es_start = off + DIR_ENTRY_SIZE;
    image[es_start..es_start + entry_set.len()].copy_from_slice(&entry_set);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "file.bin");
        }
        other => panic!("Expected FileEntry, got: {other:?}"),
    }

    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_unknown_critical_error() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Write an unknown critical entry (0x86: InUse=1,
    // Category=0 primary, Importance=0 critical, TypeCode=6).
    image[off] = 0x86;

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::UnknownCriticalEntry {
            entry_type: 0x86, ..
        })) => {}
        other => panic!(
            "Expected UnknownCriticalEntry(0x86), got: \
             {other:?}"
        ),
    }
}

#[test]
fn iter_unknown_benign_skipped() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // 0xA0 = InUse=1, Category=0 (primary), Importance=1
    // (benign), TypeCode=0.
    image[off] = 0xA0;
    // File entry set at slot 1.
    let entry_set = build_file_entry_set("ok.txt");
    let es_start = off + DIR_ENTRY_SIZE;
    image[es_start..es_start + entry_set.len()].copy_from_slice(&entry_set);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "ok.txt");
        }
        other => panic!("Expected FileEntry, got: {other:?}"),
    }

    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_checksum_mismatch_still_yields() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let mut entry_set = build_file_entry_set("bad.txt");
    // Corrupt the checksum (bytes 2-3 in the primary entry).
    entry_set[2] = 0xFF;
    entry_set[3] = 0xFF;

    let mut dir_data = entry_set;
    dir_data.resize(dir_data.len() + DIR_ENTRY_SIZE, 0x00);
    write_dir_entries(&mut image, 2, &dir_data);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "bad.txt");
            assert!(!es.checksum_valid(), "checksum should be invalid");
        }
        other => panic!(
            "Expected FileEntry with bad checksum, got: \
             {other:?}"
        ),
    }
}

#[test]
fn iter_truncated_entry_set() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF); // single cluster, no next

    // Fill all slots with unused entries except the last one
    let off = cluster_heap_offset(2);
    let entries_per_cluster = BPS / DIR_ENTRY_SIZE; // 16
    for i in 0..(entries_per_cluster - 1) {
        image[off + i * DIR_ENTRY_SIZE] = 0x05; // unused
    }

    // Put primary entry (0x85) in the LAST slot of the only
    // cluster. secondary_count=2 but the cluster chain ends,
    // so secondaries can't be read.
    let last_slot = off + (entries_per_cluster - 1) * DIR_ENTRY_SIZE;
    image[last_slot] = ENTRY_TYPE_FILE;
    image[last_slot + 1] = 2; // secondary_count

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::TruncatedEntrySet {
            expected: 2,
            actual: 0,
            ..
        })) => {}
        other => panic!("Expected TruncatedEntrySet, got: {other:?}"),
    }
}

#[test]
fn iter_invalid_secondary_count_too_low() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    image[off] = ENTRY_TYPE_FILE;
    image[off + 1] = 1; // secondary_count < 2

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::InvalidEntrySet { reason, .. })) => {
            assert!(reason.contains("at least 2"));
        }
        other => panic!("Expected InvalidEntrySet, got: {other:?}"),
    }
}

#[test]
fn iter_invalid_secondary_count_too_high() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    image[off] = ENTRY_TYPE_FILE;
    image[off + 1] = 19; // secondary_count > 18

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::InvalidEntrySet { reason, .. })) => {
            assert!(reason.contains("18"));
        }
        other => panic!("Expected InvalidEntrySet, got: {other:?}"),
    }
}

#[test]
fn iter_invalid_first_secondary_not_stream() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    image[off] = ENTRY_TYPE_FILE;
    image[off + 1] = 2; // secondary_count
    // First secondary should be 0xC0, write 0xC1 instead
    image[off + DIR_ENTRY_SIZE] = ENTRY_TYPE_NAME;

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::InvalidEntrySet { reason, .. })) => {
            assert!(reason.contains("StreamExtension"));
        }
        other => panic!("Expected InvalidEntrySet, got: {other:?}"),
    }
}

#[test]
fn iter_invalid_secondary_not_name() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    image[off] = ENTRY_TYPE_FILE;
    image[off + 1] = 2; // secondary_count
    // First secondary = valid stream (0xC0)
    image[off + DIR_ENTRY_SIZE] = ENTRY_TYPE_STREAM;
    image[off + DIR_ENTRY_SIZE + 3] = 1; // name_length
    // Second secondary should be 0xC1, write 0xC0 instead
    image[off + 2 * DIR_ENTRY_SIZE] = ENTRY_TYPE_STREAM;

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::InvalidEntrySet { reason, .. })) => {
            assert!(reason.contains("FileName"));
        }
        other => panic!("Expected InvalidEntrySet, got: {other:?}"),
    }
}

#[test]
fn iter_entry_set_spans_cluster_boundary() {
    let mut image = make_image();
    // Cluster 2 -> cluster 3 -> EOC
    set_fat_entry(&mut image, 2, 3);
    set_fat_entry(&mut image, 3, 0xFFFF_FFFF);

    let cluster2_off = cluster_heap_offset(2);
    let entries_per_cluster = BPS / DIR_ENTRY_SIZE; // 16
    let last_slot = cluster2_off + (entries_per_cluster - 1) * DIR_ENTRY_SIZE;

    // Fill slots 0..14 with unused entries (0x05, bit 7 clear)
    // so the iterator skips them instead of hitting end-of-dir.
    for i in 0..(entries_per_cluster - 1) {
        image[cluster2_off + i * DIR_ENTRY_SIZE] = 0x05;
    }

    // Place entry set primary at last slot of cluster 2,
    // secondaries spill into cluster 3.
    let entry_set = build_file_entry_set("span.txt");
    image[last_slot..last_slot + DIR_ENTRY_SIZE].copy_from_slice(&entry_set[..DIR_ENTRY_SIZE]);

    let cluster3_off = cluster_heap_offset(3);
    image[cluster3_off..cluster3_off + 2 * DIR_ENTRY_SIZE]
        .copy_from_slice(&entry_set[DIR_ENTRY_SIZE..]);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "span.txt");
            assert!(es.checksum_valid());
        }
        other => panic!("Expected FileEntry spanning clusters, got: {other:?}"),
    }
}

#[test]
fn iter_deleted_entry_when_enabled() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Write a deleted file entry (0x05 = deleted 0x85)
    image[off] = 0x05;
    // Fill with recognizable pattern
    for i in 1..DIR_ENTRY_SIZE {
        image[off + i] = 0xAB;
    }
    // End-of-directory at next slot (already zeroed)

    let (exfat, mut cursor) = make_exfat(image);

    // Without include_deleted: should skip it
    let mut iter = exfat.root_dir_entries();
    assert!(iter.next(&mut cursor).is_none());

    // With include_deleted: should yield it
    let mut iter = exfat.root_dir_entries().with_deleted();
    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::DeletedEntry {
            entry_type: 0x05,
            data,
            ..
        })) => {
            assert_eq!(data[0], 0x05);
            assert_eq!(data[1], 0xAB);
        }
        other => panic!("Expected DeletedEntry, got: {other:?}"),
    }
    // Next should be end-of-directory
    assert!(iter.next(&mut cursor).is_none());
}

#[test]
fn iter_benign_entry_when_enabled() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Write a benign primary entry (0xA0 = Volume GUID)
    image[off] = 0xA0;
    image[off + 1] = 0x42; // recognizable byte

    let (exfat, mut cursor) = make_exfat(image);

    // Without include_benign: should skip it
    let mut iter = exfat.root_dir_entries();
    assert!(iter.next(&mut cursor).is_none());

    // With include_benign: should yield it
    let mut iter = exfat.root_dir_entries().with_benign();
    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::BenignEntry {
            entry_type: 0xA0,
            data,
            ..
        })) => {
            assert_eq!(data[0], 0xA0);
            assert_eq!(data[1], 0x42);
        }
        other => panic!("Expected BenignEntry, got: {other:?}"),
    }
    assert!(iter.next(&mut cursor).is_none());
}

/// Spec §6.2 caps a file entry set at 1 stream + 17 name
/// secondaries (= 18). `assemble_file_entry` rejects anything
/// above 18 with the "spec maximum" message. At exactly 18 the
/// validation must pass and downstream errors (truncation, here)
/// take over. Mutating `>` to `>=` would short-circuit at 18 with
/// the wrong error reason.
#[test]
fn iter_invalid_secondary_count_at_boundary_18_passes_validation() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    image[off] = ENTRY_TYPE_FILE;
    image[off + 1] = 18; // secondary_count == spec maximum

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    // With original `> 18`: validation passes, secondaries are
    // read, none are valid → TruncatedEntrySet.
    // With mutated `>= 18`: validation fails with "spec maximum".
    match iter.next(&mut cursor) {
        Some(Err(ExFatError::TruncatedEntrySet { expected: 18, .. })) => {}
        Some(Err(ExFatError::InvalidEntrySet { reason, .. })) => {
            assert!(
                !reason.contains("spec maximum"),
                "secondary_count == 18 must not trigger the spec-max guard"
            );
        }
        other => panic!("Expected truncation at secondary_count=18, got: {other:?}"),
    }
}

/// `last_entry_byte_offset` returns the disk offset of the most
/// recently read entry. Asserting it equals an exact, manually
/// computed offset kills every mutation that replaces the body
/// with a constant or swaps the `+` with another operator. The
/// offset must be non-zero **and** non-equal to the cluster
/// origin: slot 0 happens to coincide with `current_cluster_offset`
/// where the `+` mutation is invisible, so we put a deleted-entry
/// sentinel at slot 0 and the unknown critical entry at slot 1.
#[test]
fn last_entry_byte_offset_reports_exact_disk_offset() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let base = cluster_heap_offset(2);
    image[base] = 0x05; // deleted entry, skipped without .with_deleted()
    image[base + DIR_ENTRY_SIZE] = 0x86; // unknown critical entry at slot 1

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    match iter.next(&mut cursor) {
        Some(Err(ExFatError::UnknownCriticalEntry {
            entry_type: 0x86,
            byte_offset,
        })) => {
            assert_eq!(
                byte_offset,
                u64::try_from(base + DIR_ENTRY_SIZE).expect("test offset fits u64"),
                "byte_offset must point to the slot containing 0x86"
            );
        }
        other => panic!("Expected UnknownCriticalEntry at slot 1, got: {other:?}"),
    }
}

/// `read_entry_bytes` returns the next 32-byte slice from the
/// cluster buffer. Mutations that replace the body with a fixed
/// `[1; 32]` array would never reflect the actual on-disk content;
/// asserting the first byte matches a deliberately-written marker
/// catches the constant-replacement (which would otherwise loop).
#[test]
fn read_entry_bytes_returns_actual_buffer_contents() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
    let off = cluster_heap_offset(2);
    image[off] = 0x85; // distinct marker for slot 0

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    let bytes = iter
        .read_entry_bytes(&mut cursor)
        .expect("first entry available")
        .expect("read should succeed");
    assert_eq!(bytes[0], 0x85);
}

/// `buffer_offset` must advance by exactly `DIR_ENTRY_SIZE` per
/// successful call so successive reads yield successive entries.
/// Mutating `+= DIR_ENTRY_SIZE` to `*= DIR_ENTRY_SIZE` leaves
/// `buffer_offset` at zero (since `0 * 32 == 0`), causing the
/// second read to repeat the first entry.
#[test]
fn read_entry_bytes_advances_offset_between_calls() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
    let off = cluster_heap_offset(2);
    image[off] = 0x85;
    image[off + DIR_ENTRY_SIZE] = 0xC0; // distinct marker for slot 1

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries();

    let first = iter
        .read_entry_bytes(&mut cursor)
        .expect("first entry")
        .expect("read ok");
    let second = iter
        .read_entry_bytes(&mut cursor)
        .expect("second entry")
        .expect("read ok");
    assert_eq!(first[0], 0x85);
    assert_eq!(second[0], 0xC0);
}

#[test]
fn iter_deleted_entries_mixed_with_active() {
    let mut image = make_image();
    set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

    let off = cluster_heap_offset(2);
    // Slot 0: deleted entry (0x05)
    image[off] = 0x05;

    // Slot 1: active file entry set
    let entry_set = build_file_entry_set("active.txt");
    let es_start = off + DIR_ENTRY_SIZE;
    image[es_start..es_start + entry_set.len()].copy_from_slice(&entry_set);

    let (exfat, mut cursor) = make_exfat(image);
    let mut iter = exfat.root_dir_entries().with_deleted();

    // First: deleted entry
    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::DeletedEntry {
            entry_type: 0x05, ..
        })) => {}
        other => panic!("Expected DeletedEntry, got: {other:?}"),
    }
    // Second: active file
    match iter.next(&mut cursor) {
        Some(Ok(ExFatDirItem::FileEntry(es))) => {
            assert_eq!(es.name_string(), "active.txt");
        }
        other => panic!("Expected FileEntry, got: {other:?}"),
    }
    // Done
    assert!(iter.next(&mut cursor).is_none());
}
