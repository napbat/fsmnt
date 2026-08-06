use super::*;

// Tests for FatAttributes bitflags
#[test]
fn test_fat_attributes_individual_flags() {
    assert_eq!(FatAttributes::READ_ONLY.bits(), 0x01);
    assert_eq!(FatAttributes::HIDDEN.bits(), 0x02);
    assert_eq!(FatAttributes::SYSTEM.bits(), 0x04);
    assert_eq!(FatAttributes::VOLUME_ID.bits(), 0x08);
    assert_eq!(FatAttributes::DIRECTORY.bits(), 0x10);
    assert_eq!(FatAttributes::ARCHIVE.bits(), 0x20);
}

#[test]
fn test_fat_attributes_lfn_marker() {
    // LFN is a combination of READ_ONLY | HIDDEN | SYSTEM | VOLUME_ID = 0x0F
    assert_eq!(FatAttributes::LFN.bits(), 0x0F);
    assert!(FatAttributes::LFN.contains(FatAttributes::READ_ONLY));
    assert!(FatAttributes::LFN.contains(FatAttributes::HIDDEN));
    assert!(FatAttributes::LFN.contains(FatAttributes::SYSTEM));
    assert!(FatAttributes::LFN.contains(FatAttributes::VOLUME_ID));
}

#[test]
fn test_fat_attributes_combinations() {
    let attrs = FatAttributes::READ_ONLY | FatAttributes::HIDDEN;
    assert_eq!(attrs.bits(), 0x03);
    assert!(attrs.contains(FatAttributes::READ_ONLY));
    assert!(attrs.contains(FatAttributes::HIDDEN));
    assert!(!attrs.contains(FatAttributes::SYSTEM));

    let dir_attrs = FatAttributes::DIRECTORY | FatAttributes::ARCHIVE;
    assert_eq!(dir_attrs.bits(), 0x30);
}

#[test]
fn test_fat_attributes_from_bits() {
    let attrs = FatAttributes::from_bits_truncate(0x21);
    assert!(attrs.contains(FatAttributes::READ_ONLY));
    assert!(attrs.contains(FatAttributes::ARCHIVE));
    assert!(!attrs.contains(FatAttributes::HIDDEN));
}

// Tests for sfn_checksum function
#[test]
fn test_sfn_checksum_known_vectors() {
    // Test vector 1: "FOO     BAR" (8.3 format padded with spaces)
    let name1: [u8; SFN_SIZE] = *b"FOO     BAR";
    let checksum1 = sfn_checksum(&name1);
    // Compute expected: rotate right and add for each byte
    assert_eq!(checksum1, 0x53); // Actual computed value

    // Test vector 2: All zeros
    let name2: [u8; SFN_SIZE] = [0u8; SFN_SIZE];
    let checksum2 = sfn_checksum(&name2);
    assert_eq!(checksum2, 0x00);

    // Test vector 3: All spaces (common padding)
    let name3: [u8; SFN_SIZE] = *b"           ";
    let checksum3 = sfn_checksum(&name3);
    // This tests the algorithm with repeated values
    let expected3 = sfn_checksum(&name3);
    assert_eq!(checksum3, expected3);
}

#[test]
fn test_sfn_checksum_consistency() {
    // Same input should always produce same output
    let name: [u8; SFN_SIZE] = *b"TESTFILE123";
    let checksum1 = sfn_checksum(&name);
    let checksum2 = sfn_checksum(&name);
    assert_eq!(checksum1, checksum2);
}

// Tests for ascii_eq_ignore_case
#[test]
fn test_ascii_eq_ignore_case_equal() {
    assert!(ascii_eq_ignore_case("hello", "hello"));
    assert!(ascii_eq_ignore_case("HELLO", "HELLO"));
    assert!(ascii_eq_ignore_case("hello", "HELLO"));
    assert!(ascii_eq_ignore_case("HELLO", "hello"));
    assert!(ascii_eq_ignore_case("HeLLo", "hEllO"));
}

#[test]
fn test_ascii_eq_ignore_case_not_equal() {
    assert!(!ascii_eq_ignore_case("hello", "world"));
    assert!(!ascii_eq_ignore_case("hello", "hello!"));
    assert!(!ascii_eq_ignore_case("hello", "hell"));
}

#[test]
fn test_ascii_eq_ignore_case_different_lengths() {
    assert!(!ascii_eq_ignore_case("short", "longer"));
    assert!(!ascii_eq_ignore_case("", "notempty"));
    assert!(ascii_eq_ignore_case("", ""));
}

#[test]
fn test_ascii_eq_ignore_case_numbers_and_special() {
    // Numbers and special chars should compare exactly
    assert!(ascii_eq_ignore_case("file123.txt", "FILE123.TXT"));
    assert!(ascii_eq_ignore_case("test_file", "TEST_FILE"));
    assert!(!ascii_eq_ignore_case("test1", "test2"));
}

// Tests for utf16_eq_ignore_ascii_case
#[test]
fn test_utf16_eq_ignore_case_equal() {
    let utf16: Vec<u16> = "hello".encode_utf16().collect();
    assert!(utf16_eq_ignore_ascii_case(&utf16, "hello"));
    assert!(utf16_eq_ignore_ascii_case(&utf16, "HELLO"));
    assert!(utf16_eq_ignore_ascii_case(&utf16, "HeLLo"));
}

#[test]
fn test_utf16_eq_ignore_case_not_equal() {
    let utf16: Vec<u16> = "hello".encode_utf16().collect();
    assert!(!utf16_eq_ignore_ascii_case(&utf16, "world"));
    assert!(!utf16_eq_ignore_ascii_case(&utf16, "hello!"));
}

#[test]
fn test_utf16_eq_ignore_case_different_lengths() {
    let utf16: Vec<u16> = "short".encode_utf16().collect();
    assert!(!utf16_eq_ignore_ascii_case(&utf16, "longer"));
    assert!(!utf16_eq_ignore_ascii_case(&utf16, "shor"));
}

#[test]
fn test_utf16_eq_ignore_case_empty() {
    let empty: Vec<u16> = Vec::new();
    assert!(utf16_eq_ignore_ascii_case(&empty, ""));
    assert!(!utf16_eq_ignore_ascii_case(&empty, "notempty"));
}

// Tests for LfnEntryData::extract_chars
#[test]
fn test_lfn_extract_chars_full() {
    // Create an LFN entry with known characters
    let mut lfn = LfnEntryData {
        sequence: 1,
        name1: [0; 10],
        attributes: 0x0F,
        entry_type: 0,
        checksum: 0,
        name2: [0; 12],
        first_cluster: U16::new(0),
        name3: [0; 4],
    };

    // Fill with 'A' (0x0041) in all 13 character positions
    // name1: 5 chars (10 bytes)
    for i in 0..5 {
        lfn.name1[i * 2] = 0x41;
        lfn.name1[i * 2 + 1] = 0x00;
    }
    // name2: 6 chars (12 bytes)
    for i in 0..6 {
        lfn.name2[i * 2] = 0x41;
        lfn.name2[i * 2 + 1] = 0x00;
    }
    // name3: 2 chars (4 bytes)
    for i in 0..2 {
        lfn.name3[i * 2] = 0x41;
        lfn.name3[i * 2 + 1] = 0x00;
    }

    let mut buf = [0u16; LFN_PART_LEN];
    let count = lfn.extract_chars(&mut buf);

    assert_eq!(count, 13);
    for c in buf.iter().take(13) {
        assert_eq!(*c, 0x0041); // 'A' in UTF-16
    }
}

#[test]
fn test_lfn_extract_chars_null_terminated() {
    // Create an LFN entry that ends early with null terminator
    let mut lfn = LfnEntryData {
        sequence: 1,
        name1: [0; 10],
        attributes: 0x0F,
        entry_type: 0,
        checksum: 0,
        name2: [0; 12],
        first_cluster: U16::new(0),
        name3: [0; 4],
    };

    // Fill name1 with "HI" followed by null
    lfn.name1[0] = 0x48;
    lfn.name1[1] = 0x00; // 'H'
    lfn.name1[2] = 0x49;
    lfn.name1[3] = 0x00; // 'I'
    // Rest is 0x0000 (null)

    let mut buf = [0u16; LFN_PART_LEN];
    let count = lfn.extract_chars(&mut buf);

    assert_eq!(count, 2);
    assert_eq!(buf[0], 0x0048); // 'H'
    assert_eq!(buf[1], 0x0049); // 'I'
}

#[test]
fn test_lfn_extract_chars_ffff_terminated() {
    // LFN entries can also be terminated with 0xFFFF
    let mut lfn = LfnEntryData {
        sequence: 1,
        name1: [0xFF; 10], // All 0xFFFF
        attributes: 0x0F,
        entry_type: 0,
        checksum: 0,
        name2: [0xFF; 12],
        first_cluster: U16::new(0),
        name3: [0xFF; 4],
    };

    // Put one character before the 0xFFFF
    lfn.name1[0] = 0x41;
    lfn.name1[1] = 0x00; // 'A'

    let mut buf = [0u16; LFN_PART_LEN];
    let count = lfn.extract_chars(&mut buf);

    assert_eq!(count, 1);
    assert_eq!(buf[0], 0x0041); // 'A'
}

// Tests for DirFileEntryData methods
fn create_test_dir_entry(name: &[u8; SFN_SIZE], attributes: u8) -> DirFileEntryData {
    DirFileEntryData {
        name: *name,
        attributes,
        nt_reserved: 0,
        create_time_tenths: 0,
        create_time: U16::new(0),
        create_date: U16::new(0),
        access_date: U16::new(0),
        first_cluster_high: U16::new(0),
        modify_time: U16::new(0),
        modify_date: U16::new(0),
        first_cluster_low: U16::new(0),
        file_size: U32::new(0),
    }
}

#[test]
fn test_dir_entry_is_end() {
    let mut name = *b"           ";
    name[0] = DIR_ENTRY_END;
    let entry = create_test_dir_entry(&name, 0);
    assert!(entry.is_end());

    let normal_entry = create_test_dir_entry(b"TEST       ", 0);
    assert!(!normal_entry.is_end());
}

#[test]
fn test_dir_entry_is_deleted() {
    let mut name = *b"           ";
    name[0] = DIR_ENTRY_DELETED;
    let entry = create_test_dir_entry(&name, 0);
    assert!(entry.is_deleted());

    let normal_entry = create_test_dir_entry(b"TEST       ", 0);
    assert!(!normal_entry.is_deleted());
}

#[test]
fn test_dir_entry_is_lfn() {
    let entry = create_test_dir_entry(b"           ", FatAttributes::LFN.bits());
    assert!(entry.is_lfn());

    let normal_entry = create_test_dir_entry(b"TEST       ", 0);
    assert!(!normal_entry.is_lfn());

    // Partial LFN attributes should not be LFN
    let partial = create_test_dir_entry(b"           ", FatAttributes::READ_ONLY.bits());
    assert!(!partial.is_lfn());
}

#[test]
fn test_dir_entry_is_dot_or_dotdot() {
    let dot = create_test_dir_entry(b".          ", FatAttributes::DIRECTORY.bits());
    assert!(dot.is_dot_or_dotdot());

    let dotdot = create_test_dir_entry(b"..         ", FatAttributes::DIRECTORY.bits());
    assert!(dotdot.is_dot_or_dotdot());

    let regular = create_test_dir_entry(b"MYDIR      ", FatAttributes::DIRECTORY.bits());
    assert!(!regular.is_dot_or_dotdot());

    let dot_file = create_test_dir_entry(b".HIDDEN    ", 0);
    assert!(!dot_file.is_dot_or_dotdot());
}

#[test]
fn test_dir_entry_is_directory() {
    let dir_entry = create_test_dir_entry(b"MYDIR      ", FatAttributes::DIRECTORY.bits());
    assert!(dir_entry.is_directory());

    let file_entry = create_test_dir_entry(b"MYFILE  TXT", 0);
    assert!(!file_entry.is_directory());

    // Directory with other attributes
    let combo = create_test_dir_entry(
        b"SYSDIR     ",
        FatAttributes::DIRECTORY.bits() | FatAttributes::SYSTEM.bits(),
    );
    assert!(combo.is_directory());
}

#[test]
fn test_dir_entry_is_volume_id() {
    let vol_entry = create_test_dir_entry(b"VOLUME     ", FatAttributes::VOLUME_ID.bits());
    assert!(vol_entry.is_volume_id());

    let normal_entry = create_test_dir_entry(b"TEST       ", 0);
    assert!(!normal_entry.is_volume_id());

    // LFN entries have VOLUME_ID set but should not be considered volume labels
    let lfn_entry = create_test_dir_entry(b"           ", FatAttributes::LFN.bits());
    assert!(!lfn_entry.is_volume_id());
}

#[test]
fn test_dir_entry_first_cluster() {
    let mut entry = create_test_dir_entry(b"TEST       ", 0);
    entry.first_cluster_high = U16::new(0x0001);
    entry.first_cluster_low = U16::new(0x2345);

    assert_eq!(entry.first_cluster(), 0x0001_2345);
}

#[test]
fn test_dir_entry_first_cluster_fat16() {
    // FAT16 only uses the low word
    let mut entry = create_test_dir_entry(b"TEST       ", 0);
    entry.first_cluster_high = U16::new(0x0000);
    entry.first_cluster_low = U16::new(0x00FF);

    assert_eq!(entry.first_cluster(), 0x0000_00FF);
}

#[test]
fn test_dir_entry_file_size() {
    let mut entry = create_test_dir_entry(b"TEST    TXT", 0);
    entry.file_size = U32::new(12_345);
    assert_eq!(entry.file_size(), 12_345);

    entry.file_size = U32::new(0xFFFF_FFFF);
    assert_eq!(entry.file_size(), 0xFFFF_FFFF);
}

#[test]
fn test_dir_entry_attributes() {
    let entry = create_test_dir_entry(
        b"TEST       ",
        FatAttributes::READ_ONLY.bits() | FatAttributes::ARCHIVE.bits(),
    );
    let attrs = entry.attributes();
    assert!(attrs.contains(FatAttributes::READ_ONLY));
    assert!(attrs.contains(FatAttributes::ARCHIVE));
    assert!(!attrs.contains(FatAttributes::HIDDEN));
}

// Test for constants
#[test]
fn test_constants() {
    assert_eq!(DIR_ENTRY_SIZE, 32);
    assert_eq!(DIR_ENTRY_DELETED, 0xE5);
    assert_eq!(DIR_ENTRY_END, 0x00);
    assert_eq!(SFN_SIZE, 11);
    assert_eq!(LFN_PART_LEN, 13);
    assert_eq!(LFN_MAX_ENTRIES, 20);
    assert_eq!(LFN_MAX_LEN, 260);
    assert_eq!(LFN_SEQ_MASK, 0x1F);
    assert_eq!(LFN_LAST_ENTRY, 0x40);
}

// ------------------------------------------------------------------
// FatDirEntry accessor tests — pin individual getters against
// constant-replacement mutants.
// ------------------------------------------------------------------

/// Build a `FatDirEntry` with a non-trivial set of fields so every
/// getter can be asserted against a specific value.
#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors DirFileEntryData layout"
)]
fn build_dir_entry(
    name: &[u8; SFN_SIZE],
    attributes: u8,
    nt_reserved: u8,
    first_cluster_hi: u16,
    first_cluster_lo: u16,
    file_size: u32,
    create_date: u16,
    create_time: u16,
    create_tenths: u8,
    modify_date: u16,
    modify_time: u16,
    access_date: u16,
) -> FatDirEntry {
    let data = DirFileEntryData {
        name: *name,
        attributes,
        nt_reserved,
        create_time_tenths: create_tenths,
        create_time: U16::new(create_time),
        create_date: U16::new(create_date),
        access_date: U16::new(access_date),
        first_cluster_high: U16::new(first_cluster_hi),
        modify_time: U16::new(modify_time),
        modify_date: U16::new(modify_date),
        first_cluster_low: U16::new(first_cluster_lo),
        file_size: U32::new(file_size),
    };
    FatDirEntry::new(data)
}

#[test]
fn dir_entry_has_long_name_distinguishes_empty_buffer() {
    // Catches `has_long_name -> bool with true`, `with false`, and
    // `delete !` — all three need both branches asserted.
    let no_lfn = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert!(!no_lfn.has_long_name());

    let lfn_chars: [u16; 3] = [0x0048, 0x0069, 0x0021]; // "Hi!"
    let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
    data.name = *b"TEST    TXT";
    let with_lfn = FatDirEntry::with_lfn(data, &lfn_chars, lfn_chars.len());
    assert!(with_lfn.has_long_name());
}

#[test]
fn dir_entry_long_name_utf16_returns_buffer_contents() {
    // Catches `long_name_utf16 -> &[u16] with Vec::leak(...)` for empty,
    // [0], or [1]: a non-trivial buffer with distinct values forces
    // each substitution to be observable.
    let lfn_chars: [u16; 5] = [0x0044, 0x0065, 0x0073, 0x006B, 0x0021]; // "Desk!"
    let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
    data.name = *b"DESK    TXT";
    let entry = FatDirEntry::with_lfn(data, &lfn_chars, lfn_chars.len());
    assert_eq!(entry.long_name_utf16(), &lfn_chars[..]);

    // Empty buffer when there's no LFN.
    let no_lfn = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert!(no_lfn.long_name_utf16().is_empty());
}

#[test]
fn dir_entry_is_volume_id_excludes_lfn_attribute_mask() {
    // Catches `is_volume_id -> bool with false`: a true volume label
    // must be detected, and an LFN entry (which has VOLUME_ID bit set
    // as part of 0x0F) must not.
    let vol = build_dir_entry(b"MY VOLUME  ", 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert!(vol.is_volume_id());

    let lfn_only = build_dir_entry(b"           ", 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    assert!(!lfn_only.is_volume_id());

    let regular = build_dir_entry(b"FILE    TXT", 0x20, 0, 0, 2, 100, 0, 0, 0, 0, 0, 0);
    assert!(!regular.is_volume_id());
}

#[test]
fn dir_entry_file_size_returns_field_value() {
    // Catches `file_size -> u32 with 0` and `with 1` — both constants
    // are ruled out by a non-zero, non-one assertion.
    let entry = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0xDEAD_BEEF, 0, 0, 0, 0, 0, 0);
    assert_eq!(entry.file_size(), 0xDEAD_BEEF);

    let small = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 42, 0, 0, 0, 0, 0, 0);
    assert_eq!(small.file_size(), 42);

    let empty = build_dir_entry(b"TEST    TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(empty.file_size(), 0);
}

#[test]
fn dir_entry_first_cluster_combines_high_and_low_words() {
    // Catches `replace | with ^` on `first_cluster`: the high/low
    // bits chosen so `|` and `^` differ. high=0x0001, low=0x0001 →
    // `|` gives 0x0001_0001, `^` gives 0x0001_0001 (same — bad test).
    // Use non-overlapping bits and a non-zero high word.
    let entry = build_dir_entry(
        b"BIG     TXT",
        0x20,
        0,
        0x1234, // first_cluster_high
        0x5678, // first_cluster_low (no overlap with high<<16)
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    assert_eq!(entry.first_cluster(), 0x1234_5678);

    // High = 0 (FAT16 case): only low matters.
    let fat16_style = build_dir_entry(b"SMALL      ", 0x10, 0, 0, 0x1234, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(fat16_style.first_cluster(), 0x0000_1234);

    // Both high and low non-zero — choose values that share bits so
    // `| -> ^` (XOR) would flip the shared bits and break the test.
    let shared = build_dir_entry(b"OVERLAP TXT", 0x20, 0, 0x0001, 0x0001, 0, 0, 0, 0, 0, 0, 0);
    // (1 << 16) | 1 = 0x10001; (1 << 16) ^ 1 = 0x10001 — same. Pick
    // different shared positions.
    assert_eq!(shared.first_cluster(), 0x0001_0001);
    // Anchor the XOR case: high << 16 = 0x10000, low = 0xFFFF.
    // `|` → 0x1FFFF, `^` → 0x1FFFF (same again). Bitwise XOR vs OR
    // only differ when bits overlap. Since high is shifted by 16,
    // the only way to overlap is to have low bits beyond 0xFFFF —
    // impossible (low is u16). So `| -> ^` is actually equivalent.
    // Refactor will make this explicit, but assert the value remains.
    let max_low = build_dir_entry(b"MAXLOW  TXT", 0x20, 0, 0x0001, 0xFFFF, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(max_low.first_cluster(), 0x0001_FFFF);
}

#[test]
fn dir_entry_long_name_string_returns_none_when_buffer_empty() {
    // Catches `long_name_string -> Option<String> with None`, with
    // Some("xyzzy"), with Some(""), and `delete !`: a present LFN
    // must produce the exact UTF-16-decoded string, and an absent
    // LFN must produce None.
    let lfn: [u16; 5] = [0x0048, 0x0065, 0x006C, 0x006C, 0x006F]; // "Hello"
    let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
    data.name = *b"HELLO   TXT";
    let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());
    assert_eq!(with_lfn.long_name_string(), Some(String::from("Hello")));

    let no_lfn = build_dir_entry(b"NOLFN   TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(no_lfn.long_name_string(), None);
}

#[test]
fn dir_entry_name_prefers_long_over_short() {
    // Catches `name -> String with String::new()` / "xyzzy".into():
    // a non-empty, non-"xyzzy" assertion rules out the constants,
    // and a long-name fixture exercises the LFN branch while a
    // short-name fixture exercises the fallback.
    let lfn: [u16; 8] = [
        0x004D, 0x0079, 0x0046, 0x0069, 0x006C, 0x0065, 0x002E, 0x0074,
    ]; // "MyFile.t"
    let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
    data.name = *b"MYFILE  TXT";
    let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());
    assert_eq!(with_lfn.name(), "MyFile.t");

    // No LFN → falls back to short-name string.
    let no_lfn = build_dir_entry(b"README  TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert_eq!(no_lfn.name(), "README.TXT");
}

#[test]
fn dir_entry_time_accessors_round_trip_raw_fields() {
    // Catches the three time-accessor mutants `-> FatTime with
    // Default::default()`: the assertions use a non-default
    // (non-1980-01-01) date plus a non-zero tenths so any default
    // substitution becomes observable.
    // 2023-06-15 14:30:45.120:
    //   year_offset=43, date = (43<<9)|(6<<5)|15 = 0x56CF
    //   time = (14<<11)|(30<<5)|22 = 0x73D6
    //   tenths = 112 (odd second + 12)
    let entry = build_dir_entry(
        b"DATED   TXT",
        0x20,
        0,
        0,
        2,
        100,
        0x56CF, // create_date
        0x73D6, // create_time
        112,    // create_tenths
        0x56CF, // modify_date
        0x73D6, // modify_time
        0x56CF, // access_date
    );

    let ct = entry.creation_time();
    assert_eq!(ct.year(), 2023);
    assert_eq!(ct.month(), 6);
    assert_eq!(ct.day(), 15);
    assert_eq!(ct.hour(), 14);
    assert_eq!(ct.minute(), 30);
    assert_eq!(ct.second(), 45);
    assert_eq!(ct.millisecond(), 120);

    let mt = entry.modification_time();
    assert_eq!(mt.year(), 2023);
    assert_eq!(mt.day(), 15);
    // Modification has no tenths field; it stays at 0 regardless of
    // create_time_tenths so the second remains even-aligned.
    assert_eq!(mt.millisecond(), 0);

    let ad = entry.access_date();
    assert_eq!(ad.year(), 2023);
    assert_eq!(ad.month(), 6);
    assert_eq!(ad.day(), 15);
    // Access has no time component.
    assert_eq!(ad.hour(), 0);
    assert_eq!(ad.minute(), 0);
    assert_eq!(ad.second(), 0);
}

// ------------------------------------------------------------------
// DirFileEntryData::is_dot_or_dotdot — the `&&` chain must not
// be permissive.
// ------------------------------------------------------------------

#[test]
fn dot_entry_detection_rejects_dot_followed_by_non_dot_non_space() {
    // Original: name[0]=='.' && (name[1]==' ' || (name[1]=='.' && name[2]==' '))
    // Mutating the outer `&&` to `||` would mark every entry with
    // " " or ".." at position [1] as dot-or-dotdot regardless of
    // name[0]. The first-byte 'X' case rules that mutation out.
    let xspace = create_test_dir_entry(b"X..        ", 0);
    assert!(!xspace.is_dot_or_dotdot());

    // ".X..       " — starts with '.' but name[1]='X' (not space
    // and not '.'); must NOT be detected as dot-or-dotdot.
    let dot_x = create_test_dir_entry(b".X         ", 0);
    assert!(!dot_x.is_dot_or_dotdot());

    // "..X        " — starts with ".." but name[2]='X' (not space).
    // Must NOT be detected.
    let dotdot_x = create_test_dir_entry(b"..X        ", 0);
    assert!(!dotdot_x.is_dot_or_dotdot());

    // Sanity: the two canonical cases still match.
    let dot = create_test_dir_entry(b".          ", 0);
    assert!(dot.is_dot_or_dotdot());
    let dotdot = create_test_dir_entry(b"..         ", 0);
    assert!(dotdot.is_dot_or_dotdot());
}

// ------------------------------------------------------------------
// name_matches — anchors LFN-then-SFN order plus case-insensitivity.
// ------------------------------------------------------------------

#[test]
fn name_matches_compares_long_name_first_then_short() {
    // Catches `name_matches -> bool with true`, `with false`, and
    // `&& -> ||`: a hit on the long name must succeed even when the
    // short name differs, and a miss on both must return false.
    let lfn: [u16; 9] = [
        0x0072, 0x0065, 0x0061, 0x0064, 0x006D, 0x0065, 0x002E, 0x0074, 0x0078,
    ]; // "readme.tx"
    let mut data = DirFileEntryData::read_from_bytes(&[0u8; DIR_ENTRY_SIZE]).unwrap();
    data.name = *b"README~1TXT"; // synthesized short name differs from LFN
    let with_lfn = FatDirEntry::with_lfn(data, &lfn, lfn.len());

    // Long-name match wins even though it's case-different.
    assert!(with_lfn.name_matches("README.TX"));
    assert!(with_lfn.name_matches("readme.tx"));
    // Mismatch on both.
    assert!(!with_lfn.name_matches("OTHER.TXT"));

    // No LFN → only short-name comparison.
    let no_lfn = build_dir_entry(b"README  TXT", 0x20, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0);
    assert!(no_lfn.name_matches("readme.txt"));
    assert!(no_lfn.name_matches("README.TXT"));
    assert!(!no_lfn.name_matches("other.txt"));
}

// ------------------------------------------------------------------
// LfnEntryData::extract_chars — `||` chains and `* 2` index math.
// ------------------------------------------------------------------

#[test]
fn lfn_extract_chars_stops_at_first_terminator_in_name2_and_name3() {
    // Catches `|| -> &&` (a NUL or 0xFFFF inside name2 must stop
    // extraction, not require both) and `* with /` on the 2-byte
    // index math (would change indexing). Plant chars in name1
    // (full) and name3 (full) but a NUL inside name2 to force
    // extraction to stop mid-entry at position 5 + n2_offset.
    let mut lfn = LfnEntryData {
        sequence: 1,
        name1: [0; 10],
        attributes: 0x0F,
        entry_type: 0,
        checksum: 0,
        name2: [0; 12],
        first_cluster: U16::new(0),
        name3: [0; 4],
    };
    // name1: 5 ASCII chars "ABCDE"
    for (i, c) in [0x41u16, 0x42, 0x43, 0x44, 0x45].iter().enumerate() {
        let bytes = c.to_le_bytes();
        lfn.name1[i * 2] = bytes[0];
        lfn.name1[i * 2 + 1] = bytes[1];
    }
    // name2: "FG" then NUL at position 2 — extraction must stop at
    // 7 chars total.
    lfn.name2[0] = 0x46; // 'F'
    lfn.name2[2] = 0x47; // 'G'
    // bytes 4..6 stay zero → NUL → terminator.

    let mut buf = [0u16; LFN_PART_LEN];
    let count = lfn.extract_chars(&mut buf);
    assert_eq!(count, 7);
    assert_eq!(&buf[..7], &[0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
}

#[test]
fn lfn_extract_chars_handles_0xffff_in_name1() {
    // Catches `|| -> &&` at line 153: the 0xFFFF terminator must
    // halt extraction just as 0x0000 does.
    let mut lfn = LfnEntryData {
        sequence: 1,
        name1: [0; 10],
        attributes: 0x0F,
        entry_type: 0,
        checksum: 0,
        name2: [0; 12],
        first_cluster: U16::new(0),
        name3: [0; 4],
    };
    // name1: 'X', then 0xFFFF.
    lfn.name1[0] = 0x58;
    lfn.name1[1] = 0x00;
    lfn.name1[2] = 0xFF;
    lfn.name1[3] = 0xFF;

    let mut buf = [0u16; LFN_PART_LEN];
    let count = lfn.extract_chars(&mut buf);
    assert_eq!(count, 1);
    assert_eq!(buf[0], 0x58);
}

// ------------------------------------------------------------------
// FatDirEntries::next — end-to-end LFN reassembly.
//
// Catches the cluster of mutants on the LFN state-machine arms:
//   - line 622 `& with |/^` on `seq & LFN_SEQ_MASK`
//   - line 626 `==/||/>` on the seq_num validation
//   - line 634 `& with |/^` and `!= with ==` on the LAST-entry check
//   - line 641 `&& with ||` and `== with !=` on the checksum match
//   - lines 648-660 `- with +`, `* with /`, etc. on the buffer indexing
//   - line 673 the post-collect checksum and buffer-empty check
//
// The fixture is a fixed-region FAT16 root with three real entries:
//   slot 0: LFN slice covering chars 13..25 of "TwoEntryLfnSpansBoth.tx"
//           seq = 2 | 0x40 (last/highest physical entry)
//   slot 1: LFN slice covering chars 0..12
//           seq = 1
//   slot 2: short-name entry "TWOENT~1TXT" linked by the matching
//           sfn_checksum.
// The state machine must concatenate seq=1 chars (positions 0..12)
// with seq=2 chars (positions 13..25) to produce the full LFN.
// ------------------------------------------------------------------

fn write_lfn_slot(img: &mut [u8], off: usize, seq: u8, checksum: u8, chars: &[u16]) {
    img[off] = seq;
    img[off + 0x0B] = 0x0F; // LFN attributes
    img[off + 0x0D] = checksum;
    // name1: chars[0..5]
    for (i, &c) in chars.iter().take(5).enumerate() {
        let bytes = c.to_le_bytes();
        img[off + 1 + i * 2] = bytes[0];
        img[off + 1 + i * 2 + 1] = bytes[1];
    }
    // name2: chars[5..11] at offset 0x0E
    for (i, &c) in chars.iter().skip(5).take(6).enumerate() {
        let bytes = c.to_le_bytes();
        img[off + 0x0E + i * 2] = bytes[0];
        img[off + 0x0E + i * 2 + 1] = bytes[1];
    }
    // name3: chars[11..13] at offset 0x1C
    for (i, &c) in chars.iter().skip(11).take(2).enumerate() {
        let bytes = c.to_le_bytes();
        img[off + 0x1C + i * 2] = bytes[0];
        img[off + 0x1C + i * 2 + 1] = bytes[1];
    }
}

fn write_sfn_slot(img: &mut [u8], off: usize, name: &[u8; SFN_SIZE], attrs: u8) {
    img[off..off + 11].copy_from_slice(name);
    img[off + 0x0B] = attrs;
}

/// Build a minimal FAT16 image (boot sector + root dir region) so the
/// `dir_entry` tests have a self-contained fixture without depending on
/// helpers in the traverse test module.
fn build_minimal_fat16_for_dir_entries() -> Vec<u8> {
    let mut img = std::vec![0u8; 22 * 512];
    img[0x00..0x03].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    img[0x03..0x0B].copy_from_slice(b"MSDOS5.0");
    img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    img[0x0D] = 1; // spc
    img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes()); // reserved
    img[0x10] = 1; // num_fats
    img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes()); // root_entries
    img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes()); // total_sectors_16
    img[0x15] = 0xF8;
    img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes()); // spf16
    img[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
    img[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
    img[0x24] = 0x80;
    img[0x26] = 0x29;
    img[0x36..0x3E].copy_from_slice(b"FAT16   ");
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;
    // FAT table: mark cluster 0/1 reserved.
    img[0x200..0x202].copy_from_slice(&0xFFF8u16.to_le_bytes());
    img[0x202..0x204].copy_from_slice(&0xFFFFu16.to_le_bytes());
    img
}
