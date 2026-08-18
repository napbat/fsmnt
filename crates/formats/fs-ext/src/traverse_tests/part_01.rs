use super::*;

#[test]
fn raw_entry_marks_encryption_state() {
    let plain = ExtRawDirEntry {
        name: b"plain.txt",
        inode_number: 1,
        file_type: 1,
        encrypted: false,
        dirhash: [0, 0],
    };
    assert!(!plain.is_encrypted_name());

    let encrypted = ExtRawDirEntry {
        name: b"\x12\x34\x56\x78ciphertextxxxx",
        inode_number: 2,
        file_type: 1,
        encrypted: true,
        dirhash: [0, 0],
    };
    assert!(encrypted.is_encrypted_name());
}

#[test]
fn resolve_kind_with_filetype_maps_each_ext4_ft() {
    // fs/ext4/ext4.h:2405-2412.
    // The filetype-byte branch is a pure function of the input byte;
    // child_inode and reader are unused. Use a dummy Ext + empty Cursor.
    let ext = Ext::dummy_for_test();
    let mut cur = fsmnt_testkit::Cursor::new(alloc::vec::Vec::<u8>::new());
    for (ft, expected) in [
        (0u8, EntryKind::Other),
        (1, EntryKind::File),
        (2, EntryKind::Directory),
        (3, EntryKind::CharDevice),
        (4, EntryKind::BlockDevice),
        (5, EntryKind::Fifo),
        (6, EntryKind::Socket),
        (7, EntryKind::Symlink),
        (8, EntryKind::Other),
        (255, EntryKind::Other),
    ] {
        let kind = resolve_kind(ext, &mut cur, ft, 0, true).unwrap();
        assert_eq!(kind, expected, "file_type={ft}");
    }
}

/// Mirrors kernel `fscrypt_fname_disk_to_usr`'s
/// `if (fscrypt_is_dot_dotdot(&qname)) { ...; return 0; }`
/// short-circuit even on encrypted directories. Defensive against
/// a future iterator that surfaces dot entries (today they are
/// filtered earlier by `parse_next_entry`).
#[cfg(feature = "fscrypt")]
#[test]
fn name_nokey_encoded_passes_through_dot_entries_in_encrypted_dirs() {
    for dot in [b"." as &[u8], b".."] {
        let entry = ExtRawDirEntry {
            name: dot,
            inode_number: 2,
            file_type: 2,
            encrypted: true,
            dirhash: [0, 0],
        };
        assert_eq!(
            entry.name_nokey_encoded(),
            dot,
            "{:?} entry must pass through unchanged in encrypted dir",
            core::str::from_utf8(dot).unwrap(),
        );
    }
}

/// `name_nokey_encoded` must forward the entry's dirhash trailer
/// into `fscrypt_nokey_name` — not the old hardcoded `[0, 0]`.
#[cfg(feature = "fscrypt")]
#[test]
fn name_nokey_encoded_forwards_dirhash_trailer() {
    let name: &[u8] = b"ciphertext-name!";
    let cf_entry = ExtRawDirEntry {
        name,
        inode_number: 7,
        file_type: 1,
        encrypted: true,
        dirhash: [0x1122_3344, 0x5566_7788],
    };
    // The no-key string matches a direct encode with the same
    // dirhash, and differs from the zero-dirhash encoding — proving
    // the trailer reaches the wire form rather than being dropped.
    assert_eq!(
        cf_entry.name_nokey_encoded(),
        crate::fscrypt::encode_nokey_name([0x1122_3344, 0x5566_7788], name),
    );
    assert_ne!(
        cf_entry.name_nokey_encoded(),
        crate::fscrypt::encode_nokey_name([0, 0], name),
    );

    // A non-casefolded encrypted entry keeps the zero dirhash.
    let plain_enc = ExtRawDirEntry {
        name,
        inode_number: 7,
        file_type: 1,
        encrypted: true,
        dirhash: [0, 0],
    };
    assert_eq!(
        plain_enc.name_nokey_encoded(),
        crate::fscrypt::encode_nokey_name([0, 0], name),
    );
}

/// `extract_dirhash_trailer` reads the 8-byte (hash, `minor_hash`)
/// suffix at the 4-byte-rounded offset after the name, and
/// fail-closes when `rec_len` is too small to hold it.
#[test]
fn extract_dirhash_trailer_reads_rounded_suffix() {
    // Entry layout: 8-byte header, 5-byte name, 3 pad bytes,
    // 8-byte trailer → rec_len 24. name_start = 8, name_end = 13,
    // next_offset = 24. Trailer at 8 + ((5 + 3) & !3) = 16.
    let mut buf = [0u8; 24];
    buf[8..13].copy_from_slice(b"abcde");
    buf[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    buf[20..24].copy_from_slice(&0x0BAD_F00Du32.to_le_bytes());
    let trailer = extract_dirhash_trailer(&buf, 8, 13, 24, 42).unwrap();
    assert_eq!(trailer, [0xDEAD_BEEF, 0x0BAD_F00D]);
}

#[test]
fn extract_dirhash_trailer_rejects_short_rec_len() {
    // rec_len leaves no room for the 8-byte trailer after the
    // rounded name → fail-closed without touching the name bytes.
    let buf = [0u8; 24];
    // name_start 8, name_end 13 → trailer would be at 16..24, but
    // next_offset is only 20.
    let err = extract_dirhash_trailer(&buf, 8, 13, 20, 42).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidDirectoryEntry { inode: 42, .. }
    ));
}
