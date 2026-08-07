use super::*;
use crate::time::{NTFS_TIMESTAMP_1997, NtfsTime};
use crate::types::NtfsPosition;
use fsmnt_parser_core::iter::FsTryIterator;

/// An NTFS timestamp comfortably inside the default plausible range
/// (2021-01-01).
const PLAUSIBLE_TS: u64 = 132_539_328_000_000_000;

/// Encodes an MFT record number into the 8-byte file-reference wire
/// format (48-bit record number, sequence number 1 in the high 16 bits).
fn file_reference_bytes(record: u64) -> [u8; 8] {
    ((record & 0xffff_ffff_ffff) | (1u64 << 48)).to_le_bytes()
}

/// Builds a 66-byte `FILE_NAME` header + UTF-16LE name with caller-chosen
/// fields. Layout follows `FileNameHeader` (`file_name.rs)`:
/// 0..8 parent ref, 8..16 creation, 16..24 modification,
/// 24..32 mft-record-mod, 32..40 access, 40..48 allocated,
/// 48..56 data, 56..60 attrs, 60..64 reparse, 64 `name_length`, 65 namespace.
fn build_file_name_key(
    parent_record: u64,
    timestamp: u64,
    allocated_size: u64,
    data_size: u64,
    namespace: u8,
    name_utf16: &[u8],
) -> Vec<u8> {
    assert!(name_utf16.len().is_multiple_of(2));
    let name_chars = u8::try_from(name_utf16.len() / 2 ).expect("test value fits u8");
    let mut key = vec![0u8; FILE_NAME_HEADER_SIZE];
    key[0..8].copy_from_slice(&file_reference_bytes(parent_record));
    for off in [8usize, 16, 24, 32] {
        key[off..off + 8].copy_from_slice(&timestamp.to_le_bytes());
    }
    key[40..48].copy_from_slice(&allocated_size.to_le_bytes());
    key[48..56].copy_from_slice(&data_size.to_le_bytes());
    key[64] = name_chars;
    key[65] = namespace;
    key.extend_from_slice(name_utf16);
    key
}

/// Wraps a `FILE_NAME` key in a 16-byte index-entry header.
/// `file_record` is the MFT reference; `entry_length` and `key_length`
/// are written verbatim so callers can craft malformed entries.
fn build_index_entry(
    file_record: u64,
    entry_length: u16,
    key_length: u16,
    key: &[u8],
) -> Vec<u8> {
    let mut entry = vec![0u8; INDEX_ENTRY_HEADER_SIZE];
    entry[0..8].copy_from_slice(&file_reference_bytes(file_record));
    entry[8..10].copy_from_slice(&entry_length.to_le_bytes());
    entry[10..12].copy_from_slice(&key_length.to_le_bytes());
    entry.extend_from_slice(key);
    entry
}

/// Like [`build_file_name_key`] but with four independent timestamps
/// (creation, modification, mft-record-mod, access) so tests can flip
/// exactly one out of range.
fn build_file_name_key_ts4(
    parent_record: u64,
    timestamps: [u64; 4],
    name_utf16: &[u8],
) -> Vec<u8> {
    let name_chars = u8::try_from(name_utf16.len() / 2 ).expect("test value fits u8");
    let mut key = vec![0u8; FILE_NAME_HEADER_SIZE];
    key[0..8].copy_from_slice(&file_reference_bytes(parent_record));
    for (i, off) in [8usize, 16, 24, 32].into_iter().enumerate() {
        key[off..off + 8].copy_from_slice(&timestamps[i].to_le_bytes());
    }
    key[40..48].copy_from_slice(&4096u64.to_le_bytes()); // allocated
    key[48..56].copy_from_slice(&4096u64.to_le_bytes()); // data
    key[64] = name_chars;
    key[65] = 1; // Win32 namespace
    key.extend_from_slice(name_utf16);
    key
}

/// A fully valid recovered entry: parent=5, plausible timestamps,
/// allocated>=data, 1-char name, Win32 namespace, entry length 84.
fn valid_entry_bytes(parent_record: u64, file_record: u64) -> Vec<u8> {
    let name = [b'A', 0]; // "A" in UTF-16LE
    let key = build_file_name_key(parent_record, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let key_len = u16::try_from(key.len()).expect("test value fits u16"); // 68
    build_index_entry(file_record, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), key_len, &key)
}

fn scan(data: &[u8], parent_record: u64) -> Vec<NtfsRecoveredEntry> {
    let config = SlackRecoveryConfig::default();
    NtfsSlackEntryScanner::new(data, NtfsPosition::new(0x1000), config, parent_record).collect()
}

#[test]
fn test_all_valid_requires_every_check() {
    // Toggle each field off in turn; all_valid() must become false.
    let base = EntryValidation {
        namespace_valid: true,
        name_valid: true,
        sizes_consistent: true,
        timestamps_plausible: true,
        parent_matches: true,
        mft_ref_in_range: true,
    };
    assert!(base.all_valid());

    let mut variants = [
        base.clone(),
        base.clone(),
        base.clone(),
        base.clone(),
        base.clone(),
        base,
    ];
    variants[0].namespace_valid = false;
    variants[1].name_valid = false;
    variants[2].sizes_consistent = false;
    variants[3].timestamps_plausible = false;
    variants[4].parent_matches = false;
    variants[5].mft_ref_in_range = false;
    for (i, v) in variants.iter().enumerate() {
        assert!(
            !v.all_valid(),
            "field {i} off should make all_valid() false"
        );
        assert_eq!(v.score(), 5, "exactly one failing check expected");
    }
}

#[test]
fn test_directory_entry_recovered_round_trips() {
    // Build a recovered entry synthetically (no testfs1 needed) and
    // verify is_active/is_recovered/file_name on the Recovered variant.
    use crate::indexes::NtfsFileNameIndex;

    let bytes = valid_entry_bytes(5, 42);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1, "expected exactly one recovered entry");
    let re = recovered.into_iter().next().unwrap();

    let entry: NtfsDirectoryEntry<'_, NtfsFileNameIndex> =
        NtfsDirectoryEntry::Recovered(Box::new(re));
    assert!(entry.is_recovered());
    assert!(!entry.is_active());
    let fname = entry.file_name().expect("some").expect("ok");
    assert_eq!(fname.name().to_string_lossy(), "A");
}

#[test]
fn test_recovered_entry_fields_match_fixture() {
    let bytes = valid_entry_bytes(5, 42);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1);
    let re = &recovered[0];

    assert_eq!(re.file_reference().file_record_number(), 42);
    assert_eq!(re.file_name().name().to_string_lossy(), "A");
    // position = scanner base (0x1000) + offset (0).
    assert_eq!(re.position(), NtfsPosition::new(0x1000));
    // Every heuristic should pass for this carefully-built entry.
    assert!(re.validation().all_valid(), "{:?}", re.validation());
    assert_eq!(re.validation().score(), 6);
}

#[test]
fn test_validate_parent_mismatch() {
    // Parent ref in the FILE_NAME is 5, but expected parent is 99.
    let bytes = valid_entry_bytes(5, 42);
    let recovered = scan(&bytes, 99);
    assert_eq!(recovered.len(), 1);
    let v = recovered[0].validation();
    assert!(!v.parent_matches, "parent should not match");
    // Every other check still passes.
    assert!(v.namespace_valid && v.name_valid && v.sizes_consistent);
    assert!(v.timestamps_plausible && v.mft_ref_in_range);
}

#[test]
fn test_validate_sizes_inconsistent() {
    // allocated_size (10) < data_size (20) -> sizes_consistent false.
    let name = [b'A', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 10, 20, 1, &name);
    let bytes = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1);
    assert!(!recovered[0].validation().sizes_consistent);

    // Boundary: allocated == data -> consistent (>= boundary).
    let key_eq = build_file_name_key(5, PLAUSIBLE_TS, 20, 20, 1, &name);
    let bytes_eq = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key_eq.len()).expect("test value fits u16"), &key_eq);
    let rec_eq = scan(&bytes_eq, 5);
    assert!(rec_eq[0].validation().sizes_consistent);
}

#[test]
fn test_validate_mft_ref_in_range_boundary() {
    let max = SlackRecoveryConfig::default().max_mft_record;
    let name = [b'A', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);

    // Exactly at the max -> in range (<= boundary).
    let at_max = build_index_entry(max, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    let rec_at = scan(&at_max, 5);
    assert!(rec_at[0].validation().mft_ref_in_range);

    // One above the max -> out of range.
    let over = build_index_entry(max + 1, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    let rec_over = scan(&over, 5);
    assert!(!rec_over[0].validation().mft_ref_in_range);
}

#[test]
fn test_validate_timestamps_out_of_range() {
    // Timestamp below the plausible lower bound -> timestamps_plausible false.
    let name = [b'A', 0];
    let key = build_file_name_key(5, NTFS_TIMESTAMP_1997 - 1, 4096, 4096, 1, &name);
    let bytes = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1);
    assert!(!recovered[0].validation().timestamps_plausible);
}

#[test]
fn test_timestamp_in_range_lower_bound() {
    let config = SlackRecoveryConfig::default();
    let scanner = NtfsSlackEntryScanner::new(&[], NtfsPosition::none(), config, 5);
    // Exactly at the inclusive lower bound -> in range.
    assert!(scanner.timestamp_in_range(NtfsTime::from(NTFS_TIMESTAMP_1997)));
    // One below -> out of range.
    assert!(!scanner.timestamp_in_range(NtfsTime::from(NTFS_TIMESTAMP_1997 - 1)));
}

#[test]
fn test_try_parse_normal_rejects_unaligned_entry_length() {
    // entry_length 85 is not a multiple of 4 -> rejected, no entry found.
    let name = [b'A', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let bytes = build_index_entry(42, 85, u16::try_from(key.len()).expect("test value fits u16"), &key);
    // Pad so remaining stays >= entry length but the entry itself is invalid.
    let mut data = bytes;
    data.resize(200, 0);
    let recovered = scan(&data, 5);
    // The crafted entry at offset 0 is unaligned, so it is skipped; the
    // remaining zeros never form a valid entry.
    assert!(
        recovered
            .iter()
            .all(|e| e.position() != NtfsPosition::new(0x1000)),
        "unaligned entry at offset 0 must be rejected"
    );
}

#[test]
fn test_try_parse_normal_rejects_short_key_length() {
    // key_length 67 < 68 minimum -> rejected.
    let name = [b'A', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), 67, &key);
    data.resize(200, 0);
    let recovered = scan(&data, 5);
    assert!(
        recovered
            .iter()
            .all(|e| e.position() != NtfsPosition::new(0x1000)),
        "key_length below 68 must be rejected"
    );
}

#[test]
fn test_try_parse_zeroed_key_reconstructs_entry() {
    // key_length field is zero; scanner reconstructs from name_length at
    // entry offset 80. Use a 2-char name so the reconstructed key/entry
    // are distinct from the 1-char minimum.
    let name = [b'A', 0, b'B', 0]; // "AB"
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    // estimated_key_length = 66 + 2*2 = 70; entry = round_up_4(16+70) = 88.
    let mut data = build_index_entry(42, 0, 0, &key);
    data.resize(88, 0);
    let recovered = scan(&data, 5);
    assert_eq!(recovered.len(), 1, "zeroed-key entry should be recovered");
    assert_eq!(recovered[0].file_name().name().to_string_lossy(), "AB");
    assert_eq!(recovered[0].file_reference().file_record_number(), 42);
}

#[test]
fn test_try_parse_zeroed_key_rejects_zero_name_length() {
    // key_length zero AND name_length zero -> nothing recoverable.
    let data = vec![0u8; 200];
    assert!(scan(&data, 5).is_empty());
}

#[test]
fn test_scanner_advances_past_consumed_entry() {
    // Two valid entries back-to-back. The scanner must advance by the
    // first entry's length (84), not by 4, so both are returned with
    // the correct distinct positions.
    let mut data = valid_entry_bytes(5, 42);
    data.extend_from_slice(&valid_entry_bytes(5, 43));
    let recovered = scan(&data, 5);
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[0].position(), NtfsPosition::new(0x1000));
    assert_eq!(recovered[0].file_reference().file_record_number(), 42);
    // Second entry begins at offset 84.
    assert_eq!(recovered[1].position(), NtfsPosition::new(0x1000 + 84));
    assert_eq!(recovered[1].file_reference().file_record_number(), 43);
}

#[test]
fn test_scanner_skips_garbage_then_finds_entry() {
    // 4 bytes of leading garbage (still 4-aligned) before a valid entry.
    // The scanner advances by 4 until it locks onto the real entry.
    let mut data = vec![0xFFu8; 4];
    data.extend_from_slice(&valid_entry_bytes(5, 77));
    let recovered = scan(&data, 5);
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].position(), NtfsPosition::new(0x1000 + 4));
    assert_eq!(recovered[0].file_reference().file_record_number(), 77);
}

/// Builds a valid normal-path entry with a 2-char name so the
/// `index_entry_length` is 88 (> the 84-byte minimum). This distinguishes
/// `index_entry_length < MIN` from `> MIN`.
fn valid_entry_len88(parent_record: u64, file_record: u64) -> Vec<u8> {
    let name = [b'A', 0, b'B', 0]; // "AB", key_length = 70
    let key = build_file_name_key(parent_record, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let key_len = u16::try_from(key.len()).expect("test value fits u16"); // 70
    let entry_len = u16::try_from(round_up_4(INDEX_ENTRY_HEADER_SIZE + usize::from(key_len)))
        .expect("test value fits u16"); // 88
    let mut entry = build_index_entry(file_record, entry_len, key_len, &key);
    entry.resize(usize::from(entry_len), 0);
    entry
}

#[test]
fn test_normal_path_recovers_above_minimum_length() {
    // index_entry_length = 88 (> MIN 84). Catches `< MIN` -> `> MIN`.
    let bytes = valid_entry_len88(5, 42);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1, "88-byte entry should be recovered");
    assert_eq!(recovered[0].file_name().name().to_string_lossy(), "AB");
    // Scanner advanced by the full 88 bytes (not 4), so no second entry.
    assert_eq!(recovered[0].position(), NtfsPosition::new(0x1000));
}

#[test]
fn test_normal_path_rejects_entry_length_exceeding_data() {
    // index_entry_length claims 88 but only 84 bytes of data remain.
    // Catches `index_entry_length > remaining` direction flips and the
    // `|| with &&` at the guard.
    let name = [b'A', 0, b'B', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut bytes = build_index_entry(42, 88, u16::try_from(key.len()).expect("test value fits u16"), &key);
    bytes.truncate(84); // remaining = 84 < claimed 88
    let recovered = scan(&bytes, 5);
    // 84 bytes < MIN? No (==MIN). But entry_length 88 > remaining 84 ->
    // rejected at offset 0. Advancing by 4 leaves < MIN, so nothing.
    assert!(recovered.is_empty());
}

#[test]
fn test_normal_path_key_length_at_entry_capacity() {
    // key_length exactly equals index_entry_length - 16 (the upper bound).
    // entry_length 88, key_length 72 (= 88 - 16). Catches `key_length >
    // index_entry_length - 16` boundary and the `- with +` at 266:63.
    let name = [b'A', 0, b'B', 0, b'C', 0]; // 3 chars -> key 72 bytes
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    assert_eq!(key.len(), 72);
    let mut bytes = build_index_entry(42, 88, 72, &key);
    bytes.resize(88, 0);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1, "key_length == entry_len-16 is valid");
    assert_eq!(recovered[0].file_name().name().to_string_lossy(), "ABC");
}

#[test]
fn test_normal_path_rejects_key_length_over_capacity() {
    // key_length 76 > index_entry_length(88) - 16 = 72 -> rejected.
    // Together with the previous test this pins the `>` boundary.
    let name = [b'A', 0, b'B', 0, b'C', 0]; // key 72 bytes
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut bytes = build_index_entry(42, 88, 76, &key);
    bytes.resize(200, 0);
    let recovered = scan(&bytes, 5);
    assert!(
        recovered
            .iter()
            .all(|e| e.position() != NtfsPosition::new(0x1000)),
        "key_length over capacity must be rejected"
    );
}

#[test]
fn test_try_parse_at_boundary_direct() {
    // Directly exercise try_parse_at at a nonzero offset so the
    // `remaining = data.len() - offset` arithmetic is observable.
    let config = SlackRecoveryConfig::default();
    let mut data = vec![0u8; 8]; // 8 bytes of padding before the entry
    data.extend_from_slice(&valid_entry_bytes(5, 42));
    let total = data.len(); // 8 + 84 = 92
    let scanner = NtfsSlackEntryScanner::new(&data, NtfsPosition::new(0x1000), config, 5);

    // offset 8: remaining = 92 - 8 = 84 == MIN -> parses the entry.
    let parsed = scanner.try_parse_at(8);
    assert!(parsed.is_some(), "entry at offset 8 should parse");
    let (entry, advance) = parsed.unwrap();
    assert_eq!(entry.file_reference().file_record_number(), 42);
    assert_eq!(advance, 84);

    // offset = total - 1: remaining = 1 < MIN -> None. With `+` the
    // computed remaining would be total + offset (huge), wrongly
    // proceeding; with `/` it would divide. Either way the genuine
    // subtraction yields None here.
    assert!(scanner.try_parse_at(total - 1).is_none());
}

#[test]
fn test_timestamps_each_field_independently_checked() {
    // Flip exactly one of the four timestamps out of range at a time.
    // Each case must drive timestamps_plausible to false, killing the
    // `&&` chain mutations (363-366).
    let bad = NTFS_TIMESTAMP_1997 - 1;
    let good = PLAUSIBLE_TS;
    let name = [b'A', 0];
    for i in 0..4 {
        let mut ts = [good; 4];
        ts[i] = bad;
        let key = build_file_name_key_ts4(5, ts, &name);
        let bytes = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
        let recovered = scan(&bytes, 5);
        assert_eq!(recovered.len(), 1);
        assert!(
            !recovered[0].validation().timestamps_plausible,
            "timestamp field {i} out of range should fail plausibility"
        );
    }
    // All four good -> plausible.
    let key = build_file_name_key_ts4(5, [good; 4], &name);
    let bytes = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    assert!(scan(&bytes, 5)[0].validation().timestamps_plausible);
}

#[test]
fn test_zeroed_key_too_small_remaining() {
    // key_length zero; remaining 80 < 81 -> None. Catches the `< 81`
    // boundary direction flips (303).
    let name = [b'A', 0, b'B', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, 0, 0, &key);
    data.truncate(80); // remaining = 80
    assert!(
        scan(&data, 5).is_empty(),
        "remaining 80 (<81) yields nothing"
    );

    // remaining exactly 81 still needs a valid name_length at offset 80;
    // byte 80 here is the FILE_NAME name_length (1 for our 2-char... )
    // Build a precise 81-byte buffer with name_length=8 at offset 80 so
    // the estimated entry fits and parses below.
}

#[test]
fn test_zeroed_key_name_length_scales_entry() {
    // name_length 8 -> estimated_key_length = 66 + 8*2 = 82,
    // estimated_entry_length = round_up_4(16 + 82) = 100.
    // Catches `* 2` (312), `+` (313), and the size guards (315/321).
    let mut name = Vec::new();
    for _ in 0..8 {
        name.extend_from_slice(&[b'X', 0]);
    }
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, 0, 0, &key); // 16 + 82 = 98 bytes
    data.resize(100, 0);
    let recovered = scan(&data, 5);
    assert_eq!(recovered.len(), 1, "8-char zeroed-key entry recovered");
    assert_eq!(
        recovered[0].file_name().name().to_string_lossy(),
        "XXXXXXXX"
    );
}

#[test]
fn test_zeroed_key_estimated_entry_exceeds_remaining() {
    // name_length 8 needs a 100-byte entry, but only 96 bytes remain.
    // estimated_entry_length(100) > remaining(96) -> rejected.
    let mut name = Vec::new();
    for _ in 0..8 {
        name.extend_from_slice(&[b'X', 0]);
    }
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, 0, 0, &key);
    data.truncate(96);
    assert!(
        scan(&data, 5).is_empty(),
        "entry estimated at 100 bytes must be rejected with 96 remaining"
    );
}

#[test]
fn test_name_valid_false_for_nul_name() {
    // A name consisting of a single NUL UTF-16 char parses (name_length
    // = 2 > 0) but is not a real name. name_valid must be false. This
    // exercises the `&&` / `!` operators inside the name_valid block.
    let name = [0u8, 0u8]; // single NUL char
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let bytes = build_index_entry(42, u16::try_from(MIN_ENTRY_SIZE).expect("test value fits u16"), u16::try_from(key.len()).expect("test value fits u16"), &key);
    let recovered = scan(&bytes, 5);
    assert_eq!(recovered.len(), 1);
    assert!(
        !recovered[0].validation().name_valid,
        "a NUL-only name must not count as a valid name"
    );
    // Every other heuristic still passes, isolating name_valid.
    let v = recovered[0].validation();
    assert!(v.sizes_consistent && v.timestamps_plausible);
    assert!(v.parent_matches && v.mft_ref_in_range);
}

#[test]
fn test_name_valid_true_for_real_name() {
    // Contrast with a normal printable name -> name_valid true.
    let bytes = valid_entry_bytes(5, 42);
    let recovered = scan(&bytes, 5);
    assert!(recovered[0].validation().name_valid);
}

#[test]
fn test_active_directory_entry_variant() {
    // Construct an Active variant from a synthetic index-entry slice so
    // is_active()/is_recovered() are exercised on BOTH variants.
    use crate::index_entry::NtfsIndexEntry;
    use crate::indexes::NtfsFileNameIndex;

    let bytes = valid_entry_bytes(5, 42);
    let index_entry: NtfsIndexEntry<'_, NtfsFileNameIndex> =
        NtfsIndexEntry::new(&bytes, NtfsPosition::new(0x2000)).expect("valid index entry");
    let active: NtfsDirectoryEntry<'_, NtfsFileNameIndex> =
        NtfsDirectoryEntry::Active(index_entry);
    assert!(active.is_active());
    assert!(!active.is_recovered());
    // file_name() reads the key from the active index entry.
    let fname = active.file_name().expect("some").expect("ok");
    assert_eq!(fname.name().to_string_lossy(), "A");
}

fn make_scanner(data: &[u8]) -> NtfsSlackEntryScanner<'_> {
    NtfsSlackEntryScanner::new(
        data,
        NtfsPosition::new(0x1000),
        SlackRecoveryConfig::default(),
        5,
    )
}

#[test]
fn test_try_parse_normal_entry_length_exceeds_remaining_but_key_fits() {
    // index_entry_length (200) exceeds the available data (100 bytes),
    // but the 1-char FILE_NAME key (68 bytes) fits entirely within the
    // remaining bytes. The guard is `entry_len < MIN || entry_len >
    // remaining`: only the second operand is true here, so `||` rejects
    // while `&&` would wrongly accept and parse the key.
    let name = [b'A', 0];
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, 200, 68, &key); // 16 + 68 = 84
    data.resize(100, 0); // remaining = 100, < claimed 200
    let scanner = make_scanner(&data);
    // Direct call isolates try_parse_normal from the iterator's retry.
    assert!(
        scanner.try_parse_at(0).is_none(),
        "entry_length exceeding remaining must be rejected"
    );
}

#[test]
fn test_try_parse_zeroed_key_remaining_below_81_direct() {
    // Direct call with only 80 bytes: the `remaining < 81` guard returns
    // None. Under `< -> ==` the guard would be false and the code would
    // index byte 80 of an 80-byte slice. Pinning None here proves the
    // guard fires for short buffers.
    let data = vec![0u8; 80];
    let scanner = make_scanner(&data);
    assert!(scanner.try_parse_zeroed_key(&data, 0).is_none());
}

/// Builds a zeroed-key index entry whose `FILE_NAME` has `name_chars`
/// characters, padded/truncated to `total_len` bytes. `key_length` is left
/// zero so the scanner takes the reconstruction path.
fn zeroed_key_entry(name_chars: usize, total_len: usize) -> Vec<u8> {
    let mut name = Vec::new();
    for _ in 0..name_chars {
        name.extend_from_slice(&[b'A', 0]);
    }
    let key = build_file_name_key(5, PLAUSIBLE_TS, 4096, 4096, 1, &name);
    let mut data = build_index_entry(42, 0, 0, &key);
    data.resize(total_len, 0);
    data
}

#[test]
fn test_zeroed_key_exact_minimum_entry() {
    // 1-char name -> estimated_key_length 68, estimated_entry_length 84
    // (== MIN), key_end 84. Buffer is exactly 84 bytes so key_end ==
    // remaining. This must parse (the `< MIN` and `key_end > remaining`
    // guards are both strict), catching `< -> ==/<=` at 315 and
    // `> -> ==/>=` at 321.
    let data = zeroed_key_entry(1, 84);
    let recovered = scan(&data, 5);
    assert_eq!(recovered.len(), 1, "exact-minimum zeroed entry recovered");
    assert_eq!(recovered[0].file_name().name().to_string_lossy(), "A");
}

#[test]
fn test_zeroed_key_estimated_exceeds_remaining_rejected() {
    // 2-char name -> estimated_key_length 70, estimated_entry_length 88,
    // key_end 86. Buffer is 87 bytes: estimated_entry_length (88) >
    // remaining (87) so the entry is rejected, but key_end (86) <=
    // remaining (87). This isolates the `estimated_entry_length >
    // remaining` operand (catches `> -> <` at 315:35 and `|| -> &&` at
    // 315:47, which would otherwise parse).
    let data = zeroed_key_entry(2, 87);
    let scanner = make_scanner(&data);
    assert!(
        scanner.try_parse_zeroed_key(&data, 0).is_none(),
        "estimated entry length exceeding remaining must be rejected"
    );
}

#[test]
fn test_zeroed_key_estimated_below_remaining_parses() {
    // Same 2-char entry but with ample remaining (200 bytes):
    // estimated_entry_length (88) < remaining, so it parses. Pairs with
    // the previous test to pin the comparison direction.
    let data = zeroed_key_entry(2, 200);
    let scanner = make_scanner(&data);
    let parsed = scanner.try_parse_zeroed_key(&data, 0);
    assert!(parsed.is_some());
    let (entry, advance) = parsed.unwrap();
    assert_eq!(entry.file_name().name().to_string_lossy(), "AA");
    assert_eq!(advance, 88);
}

#[test]
fn test_slack_recovery_config_default() {
    let config = SlackRecoveryConfig::default();
    // 1997-01-01 should be a reasonable lower bound
    assert!(config.timestamp_bounds.min > 0);
    // 2030-01-01 should be above 2025
    assert!(config.timestamp_bounds.max > config.timestamp_bounds.min);
    assert!(config.require_parent_match);
    assert_eq!(config.max_mft_record, 1_000_000);
}

#[test]
fn test_entry_validation_score() {
    let all_valid = EntryValidation {
        namespace_valid: true,
        name_valid: true,
        sizes_consistent: true,
        timestamps_plausible: true,
        parent_matches: true,
        mft_ref_in_range: true,
    };
    assert_eq!(all_valid.score(), 6);
    assert!(all_valid.all_valid());

    let some_valid = EntryValidation {
        namespace_valid: true,
        name_valid: true,
        sizes_consistent: false,
        timestamps_plausible: false,
        parent_matches: true,
        mft_ref_in_range: true,
    };
    assert_eq!(some_valid.score(), 4);
    assert!(!some_valid.all_valid());

    let none_valid = EntryValidation {
        namespace_valid: false,
        name_valid: false,
        sizes_consistent: false,
        timestamps_plausible: false,
        parent_matches: false,
        mft_ref_in_range: false,
    };
    assert_eq!(none_valid.score(), 0);
    assert!(!none_valid.all_valid());
}

#[test]
fn test_scanner_on_empty_slack() {
    let config = SlackRecoveryConfig::default();
    let scanner = NtfsSlackEntryScanner::new(&[], NtfsPosition::none(), config, 5);
    let entries: Vec<_> = scanner.collect();
    assert!(entries.is_empty());
}

#[test]
fn test_scanner_on_small_slack() {
    let config = SlackRecoveryConfig::default();
    // Less than MIN_ENTRY_SIZE (84 bytes)
    let data = [0u8; 80];
    let scanner = NtfsSlackEntryScanner::new(&data, NtfsPosition::none(), config, 5);
    let entries: Vec<_> = scanner.collect();
    assert!(entries.is_empty());
}

#[test]
fn test_scanner_on_real_index() {
    use crate::attribute::NtfsAttributeType;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::ntfs::Ntfs;
    use crate::structured_values::{NtfsIndexAllocation, NtfsIndexRoot};

    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let config = SlackRecoveryConfig {
        require_parent_match: false,
        ..SlackRecoveryConfig::default()
    };

    // Get the INDEX_ROOT attribute for the $I30 index
    let mut attrs = root_dir.attributes();
    let mut index_root_item = None;
    let mut index_alloc_item = None;
    while let Some(item) = attrs.try_next(&mut testfs1).unwrap() {
        let attr = item.to_attribute().unwrap();
        let ty = attr.ty().unwrap();
        if ty == NtfsAttributeType::IndexRoot {
            index_root_item = Some(item);
        } else if ty == NtfsAttributeType::IndexAllocation {
            index_alloc_item = Some(item);
        }
    }

    // Scan INDEX_ROOT slack
    let index_root_item = index_root_item.expect("root dir should have INDEX_ROOT");
    let index_root_attr = index_root_item.to_attribute().unwrap();
    let index_root = index_root_attr
        .resident_structured_value::<NtfsIndexRoot>()
        .unwrap();

    let scanner = NtfsSlackEntryScanner::new(
        index_root.slack_data(),
        index_root.slack_position(),
        config,
        KnownNtfsFileRecordNumber::RootDirectory.as_u64(),
    );
    // Even if no deleted entries exist, the scanner should complete without panic
    for entry in scanner {
        assert!(entry.file_name().name_length() > 0);
    }

    // Also scan INDX allocation records if present
    if let Some(alloc_item) = index_alloc_item {
        let alloc_attr = alloc_item.to_attribute().unwrap();
        let index_alloc = alloc_attr
            .structured_value::<_, NtfsIndexAllocation>(&mut testfs1)
            .unwrap();
        let index_record_size = index_root.index_record_size();
        let mut record_iter = index_alloc.records(index_record_size);
        while let Some(record) = record_iter.try_next(&mut testfs1).unwrap() {
            let scanner = NtfsSlackEntryScanner::new(
                record.slack_data(),
                record.slack_position(),
                config,
                KnownNtfsFileRecordNumber::RootDirectory.as_u64(),
            );
            for entry in scanner {
                assert!(entry.file_name().name_length() > 0);
            }
        }
    }
}
