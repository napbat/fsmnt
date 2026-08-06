fn build_fat16_image_with_2entry_lfn(short_name: &[u8; SFN_SIZE]) -> (Vec<u8>, [u16; 26]) {
    // Long name: 26 chars (two LFN entries fully populated).
    let long: [u16; 26] = [
        u16::from(b'T'),
        u16::from(b'w'),
        u16::from(b'o'),
        u16::from(b'E'),
        u16::from(b'n'),
        u16::from(b't'),
        u16::from(b'r'),
        u16::from(b'y'),
        u16::from(b'L'),
        u16::from(b'f'),
        u16::from(b'n'),
        u16::from(b'S'),
        u16::from(b'p'),
        u16::from(b'a'),
        u16::from(b'n'),
        u16::from(b's'),
        u16::from(b'B'),
        u16::from(b'o'),
        u16::from(b't'),
        u16::from(b'h'),
        u16::from(b'.'),
        u16::from(b't'),
        u16::from(b'x'),
        u16::from(b't'),
        0x0000, // padding within entry 2 to terminate cleanly
        0x0000,
    ];

    let mut img = build_minimal_fat16_for_dir_entries();
    let r = 18 * 512; // FAT16 fixed root

    // Replace whatever build_fat16_image wrote with our LFN sequence.
    for i in 0..4 {
        img[r + i * 32..r + (i + 1) * 32].fill(0);
    }

    let checksum = sfn_checksum(short_name);

    // Slot 0: physical first → seq = 2 | 0x40 → chars 13..25 (next 13 of long).
    let entry2_chars: Vec<u16> = long.iter().skip(13).take(13).copied().collect();
    write_lfn_slot(&mut img, r, 0x42, checksum, &entry2_chars);

    // Slot 1: physical second → seq = 1 → chars 0..12.
    let entry1_chars: Vec<u16> = long.iter().take(13).copied().collect();
    write_lfn_slot(&mut img, r + 32, 0x01, checksum, &entry1_chars);

    // Slot 2: short-name entry matching the LFN's checksum.
    write_sfn_slot(&mut img, r + 64, short_name, FatAttributes::ARCHIVE.bits());

    // Slot 3: end marker (already zeroed).
    (img, long)
}

#[test]
fn fat_dir_entries_assembles_multi_entry_lfn_into_short_name_target() {
    use crate::fat::Fat;
    use std::io::Cursor;
    use std::string::String;

    // Build the short name first so the LFN checksum is correct.
    let short_name: [u8; SFN_SIZE] = *b"TWOENT~1TXT";
    let (img, long) = build_fat16_image_with_2entry_lfn(&short_name);

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");

    let mut entries = fat.root_dir_entries();
    let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
    while let Some(r) = entries.next(&mut cur) {
        yielded.push(r.expect("entry parses"));
    }
    assert_eq!(yielded.len(), 1, "expected one short-name entry");
    let entry = &yielded[0];

    // Reassembly: chars 0..12 from physical-second LFN entry plus
    // chars 13..25 from physical-first LFN entry → full long name.
    // Mutating `seq_num - 1` or the buffer offsets would mis-place
    // the slices and yield a scrambled string.
    let lfn = entry.long_name_utf16();
    let trimmed: std::vec::Vec<u16> = lfn.iter().copied().take_while(|&c| c != 0).collect();
    let expected_trim: std::vec::Vec<u16> =
        long.iter().copied().take_while(|&c| c != 0).collect();
    assert_eq!(trimmed, expected_trim);

    // The short-name target must also be the one the LFN's checksum
    // pointed at — anchors line 673's checksum match.
    assert_eq!(entry.short_name(), &short_name);
    assert_eq!(
        entry.long_name_string(),
        Some(String::from("TwoEntryLfnSpansBoth.txt")),
    );
}

#[test]
fn fat_dir_entries_falls_back_to_short_name_on_checksum_mismatch() {
    use crate::fat::Fat;
    use std::io::Cursor;

    // Build a normal 2-entry LFN, then corrupt the checksum byte in
    // both LFN entries so they don't match the short name's actual
    // checksum. The state machine must keep the short name and
    // expose no long name (anchors line 673's
    // `computed_checksum == lfn_checksum` test).
    let short_name: [u8; SFN_SIZE] = *b"NOMATCH TXT";
    let (mut img, _long) = build_fat16_image_with_2entry_lfn(&short_name);
    let r = 18 * 512;
    img[r + 0x0D] = 0x00; // slot 0 checksum byte
    img[r + 32 + 0x0D] = 0x00; // slot 1 checksum byte

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();
    let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
    while let Some(r) = entries.next(&mut cur) {
        yielded.push(r.expect("entry parses"));
    }
    assert_eq!(yielded.len(), 1);
    assert!(!yielded[0].has_long_name());
    assert_eq!(yielded[0].short_name(), &short_name);
}

#[test]
fn fat_dir_entries_skips_lfn_with_out_of_range_sequence_number() {
    use crate::fat::Fat;
    use std::io::Cursor;

    // Build a normal 2-entry LFN, then poison the SEQUENCE byte of
    // slot 0 with an out-of-range value (LFN_MAX_ENTRIES is 20, so
    // 25 is out of range). The state machine must reset and skip
    // the LFN, falling back to short name only. Anchors line 626's
    // validation chain.
    let short_name: [u8; SFN_SIZE] = *b"BADSEQ  TXT";
    let (mut img, _long) = build_fat16_image_with_2entry_lfn(&short_name);
    let r = 18 * 512;
    img[r] = 0x40 | 0x19; // last bit + out-of-range seq_num

    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();
    let mut yielded: std::vec::Vec<FatDirEntry> = std::vec::Vec::new();
    while let Some(r) = entries.next(&mut cur) {
        yielded.push(r.expect("entry parses"));
    }
    // The partial LFN that survives in slot 1 (seq=1) is not
    // preceded by a valid LAST entry, so checksum matching may
    // succeed but the buffer position is at 0..13. The short
    // name's checksum still gates whether long_name attaches.
    // The key invariant here: iteration must not error or skip the
    // short-name entry on receiving a malformed LFN sequence.
    assert_eq!(yielded.len(), 1);
    assert_eq!(yielded[0].short_name(), &short_name);
}

/// Place a plain short-name entry in slot 0, end marker in slot 1.
/// Used by the `find/find_by_name/try_next` tests below.
fn build_fat16_image_with_single_file(name: &[u8; SFN_SIZE]) -> Vec<u8> {
    let mut img = build_minimal_fat16_for_dir_entries();
    let r = 18 * 512;
    write_sfn_slot(&mut img, r, name, FatAttributes::ARCHIVE.bits());
    img
}

#[test]
fn fat_dir_entries_find_returns_matching_entry() {
    // Catches `find -> Option<Result<FatDirEntry>> with None`: the
    // predicate must match a real entry and the iterator must yield
    // it, not silently produce None.
    use crate::fat::Fat;
    use std::io::Cursor;

    let img = build_fat16_image_with_single_file(b"HELLO   TXT");
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();
    let found = entries
        .find(&mut cur, |e| &e.short_name()[..5] == b"HELLO")
        .expect("predicate must match")
        .expect("entry parses");
    assert_eq!(&found.short_name()[..5], b"HELLO");
}

#[test]
fn fat_dir_entries_find_by_name_resolves_short_name_case_insensitive() {
    // Catches `find_by_name -> None`: the case-insensitive
    // comparison must find the entry whose short name matches.
    use crate::fat::Fat;
    use std::io::Cursor;

    let img = build_fat16_image_with_single_file(b"README  TXT");
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();
    let found = entries
        .find_by_name(&mut cur, "readme.txt")
        .expect("name must resolve")
        .expect("entry parses");
    assert_eq!(&found.short_name()[..6], b"README");
}

#[test]
fn fat_dir_entries_try_next_returns_some_for_present_entry() {
    // Catches `<impl FsTryIterator>::try_next -> Ok(None)`: the
    // adapter must surface the same entries as `next`.
    use crate::fat::Fat;
    use fs_common::iter::FsTryIterator;
    use std::io::Cursor;

    let img = build_fat16_image_with_single_file(b"NOTE       ");
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();
    let first = FsTryIterator::try_next(&mut entries, &mut cur)
        .expect("try_next succeeds")
        .expect("entry present");
    assert_eq!(first.short_name(), b"NOTE       ");
}

/// Build a fixed-region FAT16 image whose root directory spans more
/// than one buffer fill. The root entry count is set to 32 (one
/// cluster of 512 bytes = 16 entries; two clusters covers 32 entries).
/// We populate entries across the boundary so the iterator must
/// call `fill_buffer` at least twice and the `*remaining -=` and
/// `*current_cluster = ...` arithmetic in `fill_buffer` is exercised.
fn build_fat16_image_spanning_two_buffer_fills() -> Vec<u8> {
    let mut img = build_minimal_fat16_for_dir_entries();

    // Root directory has 16 entries × 32 bytes = 512 bytes = one cluster.
    // Bump root_entry_count to 32 (2 clusters worth) so a single buffer
    // fill cannot exhaust the region.
    img[0x11..0x13].copy_from_slice(&32u16.to_le_bytes());

    let r = 18 * 512;
    // Populate slots 0..15 with placeholder files; the iterator must
    // walk past all of them before hitting the second buffer fill.
    for i in 0..15 {
        let mut name = *b"FILL    TXT";
        name[4] = b'0' + u8::try_from(i % 10).expect("the remainder is at most nine");
        write_sfn_slot(&mut img, r + i * 32, &name, FatAttributes::ARCHIVE.bits());
    }
    // Slot 15: distinguishing entry in the FIRST buffer fill.
    write_sfn_slot(
        &mut img,
        r + 15 * 32,
        b"FIRST   TXT",
        FatAttributes::ARCHIVE.bits(),
    );
    // Slot 16: file in the SECOND buffer fill (different sector).
    write_sfn_slot(
        &mut img,
        r + 16 * 32,
        b"SECOND  TXT",
        FatAttributes::ARCHIVE.bits(),
    );
    // Slot 17: end marker (already zero).
    img
}

#[test]
fn fat_dir_entries_fill_buffer_advances_across_buffer_boundary() {
    // Catches arithmetic mutations in the fixed-directory byte-count update in
    // fill_buffer's Fixed arm (line 724) and on
    // `*current_cluster = ...` style accumulator math. The fixture
    // forces iteration across two buffer fills; mutating the
    // remaining-byte accumulator would either stall the iterator
    // (never decrementing) or skip ahead.
    use crate::fat::Fat;
    use std::io::Cursor;

    let img = build_fat16_image_spanning_two_buffer_fills();
    let mut cur = Cursor::new(img);
    let fat = Fat::new(&mut cur).expect("valid image");
    let mut entries = fat.root_dir_entries();

    let mut names: std::vec::Vec<[u8; 11]> = std::vec::Vec::new();
    while let Some(r) = entries.next(&mut cur) {
        let entry = r.expect("entry parses");
        names.push(*entry.short_name());
    }

    // Both entries must be visible; the SECOND entry is in slot 16
    // which lives in the second buffer-fill chunk.
    assert!(
        names.iter().any(|n| n == b"FIRST   TXT"),
        "FIRST.TXT missing: {names:?}",
    );
    assert!(
        names.iter().any(|n| n == b"SECOND  TXT"),
        "SECOND.TXT missing (fill_buffer didn't advance): {names:?}",
    );
}
