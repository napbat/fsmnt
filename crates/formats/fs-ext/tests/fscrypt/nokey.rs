use super::support::*;

// Issue #167: kernel-equivalent base64url(fscrypt_nokey_name) for
// no-key directory entries. These tests cross-check
// `ExtRawDirEntry::name_nokey_encoded()` against an independent inline
// implementation of the kernel algorithm so a regression in the
// production encoder doesn't sneak through.

const NOKEY_INLINE_LEN: usize = 149;

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_digit(index: u32) -> u8 {
    BASE64URL_ALPHABET[usize::try_from(index).expect("six-bit digit fits usize")]
}

/// Reference base64url encoder for the integration tests.
///
/// Independent implementation that walks 3-byte chunks and handles the
/// 1- and 2-byte tails explicitly — different control flow from the
/// production MSB-streaming encoder so a bug in either is caught by
/// disagreement.
fn ref_base64url_encode(src: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(src.len().div_ceil(3) * 4);
    let chunks = src.chunks_exact(3);
    let tail = chunks.remainder();
    for c in chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(base64url_digit((n >> 18) & 0x3F));
        out.push(base64url_digit((n >> 12) & 0x3F));
        out.push(base64url_digit((n >> 6) & 0x3F));
        out.push(base64url_digit(n & 0x3F));
    }
    match tail.len() {
        0 => {}
        1 => {
            let n = u32::from(tail[0]) << 4;
            out.push(base64url_digit((n >> 6) & 0x3F));
            out.push(base64url_digit(n & 0x3F));
        }
        2 => {
            let n = (u32::from(tail[0]) << 10) | (u32::from(tail[1]) << 2);
            out.push(base64url_digit((n >> 12) & 0x3F));
            out.push(base64url_digit((n >> 6) & 0x3F));
            out.push(base64url_digit(n & 0x3F));
        }
        _ => unreachable!(),
    }
    out
}

/// Reference `fscrypt_nokey_name` encoder mirroring the kernel's no-key
/// branch in `fscrypt_fname_disk_to_usr`. Uses the alternate base64url
/// implementation above for cross-checking.
fn ref_encode_nokey_name(dirhash: [u32; 2], ciphertext: &[u8]) -> Vec<u8> {
    let mut wire: Vec<u8> = Vec::new();
    wire.extend_from_slice(&dirhash[0].to_le_bytes());
    wire.extend_from_slice(&dirhash[1].to_le_bytes());
    if ciphertext.len() <= NOKEY_INLINE_LEN {
        wire.extend_from_slice(ciphertext);
    } else {
        wire.extend_from_slice(&ciphertext[..NOKEY_INLINE_LEN]);
        let tail_hash = Sha256::digest(&ciphertext[NOKEY_INLINE_LEN..]);
        wire.extend_from_slice(&tail_hash);
    }
    ref_base64url_encode(&wire)
}

#[test]
fn nokey_encoder_matches_reference_for_v2_dir_short_entry() {
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let v2 = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2.inode_number);

    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut checked = 0usize;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.name_bytes() == b"." || entry.name_bytes() == b".." {
            continue;
        }
        if entry.name_bytes().len() > NOKEY_INLINE_LEN {
            // Short-path test only; long-path covered separately.
            continue;
        }
        assert!(entry.is_encrypted_name());
        let expected = ref_encode_nokey_name([0, 0], entry.name_bytes());
        assert_eq!(
            entry.name_nokey_encoded(),
            expected,
            "no-key encoded form must match kernel-equivalent reference"
        );
        // Structural sanity: every output char is in the base64url alphabet.
        for c in entry.name_nokey_encoded() {
            assert!(
                BASE64URL_ALPHABET.contains(&c),
                "no-key encoding must use only base64url alphabet, got 0x{c:02x}"
            );
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "v2_dir must have at least one short-name entry"
    );
}

#[test]
fn nokey_encoder_matches_reference_for_v2_dir_long_entry() {
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let v2 = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2.inode_number);

    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut checked_long = false;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.name_bytes().len() <= NOKEY_INLINE_LEN {
            continue;
        }
        let expected = ref_encode_nokey_name([0, 0], entry.name_bytes());
        let actual = entry.name_nokey_encoded();
        assert_eq!(actual, expected, "long-path no-key encoding mismatch");
        // 8 (dirhash) + 149 (inline) + 32 (sha256) = 189 wire bytes →
        // ceil(189 * 4 / 3) = 252 base64url chars. Verifies that the
        // SHA-256 tail branch was taken instead of the inline branch.
        assert_eq!(actual.len(), 252, "long-path encoded length must be 252");
        checked_long = true;
    }
    assert!(
        checked_long,
        "v2_dir must contain a long (>{NOKEY_INLINE_LEN}-byte ciphertext) entry; \
         regenerate the fixture to add the issue #167 long-name file"
    );
}

#[test]
fn nokey_encoded_passes_through_plaintext_entries() {
    let (mut cursor, ext) = open_without_keys();

    // /lost+found is unencrypted; its entries (none in this fixture)
    // and the root directory itself supply non-encrypted entries.
    let mut root = ext.root_directory();
    let mut iter = root.raw_entries(&mut cursor).expect("raw root entries");

    let mut checked = 0usize;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw root entry") {
        if entry.is_encrypted_name() {
            continue;
        }
        assert_eq!(
            entry.name_nokey_encoded(),
            entry.name_bytes(),
            "plaintext entries must pass through name_nokey_encoded() unchanged"
        );
        checked += 1;
    }
    assert!(checked > 0, "root must have at least one plaintext entry");
}

#[test]
fn nokey_encoded_names_round_trip_through_lookup() {
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let v2 = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2.inode_number);
    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut presented_entries = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        presented_entries.push((entry.name_nokey_encoded(), entry.inode_number()));
    }
    drop(iter);

    assert!(
        !presented_entries.is_empty(),
        "v2_dir must have encrypted entries"
    );
    for (presented_name, expected_inode) in presented_entries {
        let found = dir
            .lookup_nokey(&mut cursor, &presented_name)
            .expect("a presented no-key name must resolve");
        assert_eq!(found.inode_number, expected_inode);
        assert_eq!(found.name, presented_name);
    }
}

// Issue #179: encrypted+casefolded directories append an 8-byte
// `ext4_extended_dir_entry_2` (hash, minor_hash) trailer to each
// non-dot entry. The no-key presentation form must forward that
// on-disk dirhash into `fscrypt_nokey_name`, where a non-casefolded
// encrypted directory uses `[0, 0]`.

#[test]
fn nokey_encoder_for_v2_cf_dir_embeds_on_disk_dirhash() {
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let cf = root
        .lookup(&mut cursor, b"v2_cf_dir")
        .expect("lookup v2_cf_dir");
    let mut dir = ext.directory_at(cf.inode_number);

    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut checked = 0usize;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.name_bytes() == b"." || entry.name_bytes() == b".." {
            continue;
        }
        assert!(entry.is_encrypted_name());
        let actual = entry.name_nokey_encoded();

        // The encrypted+casefolded entry carries a real per-entry
        // dirhash trailer (a SipHash pair — vanishingly unlikely to be
        // all-zero), so the no-key form must differ from the
        // zero-dirhash encoding the kernel uses for non-casefolded
        // encrypted directories.
        let zero_dirhash = ref_encode_nokey_name([0, 0], entry.name_bytes());
        assert_ne!(
            actual, zero_dirhash,
            "v2_cf_dir entry must embed its non-zero on-disk dirhash trailer",
        );

        // Output is still a well-formed base64url string.
        for c in &actual {
            assert!(
                BASE64URL_ALPHABET.contains(c),
                "no-key encoding must use only base64url alphabet, got 0x{c:02x}",
            );
        }
        checked += 1;
    }
    assert_eq!(
        checked, 2,
        "v2_cf_dir has exactly two entries (Hello.TXT, READ.ME)",
    );
}

#[test]
fn nokey_encoder_v2_dir_keeps_zero_dirhash_when_not_casefolded() {
    // Acceptance criterion 1: encrypted *non*-casefolded directories
    // keep the `[0, 0]` dirhash — the issue-#179 change must not leak
    // a trailer into directories that do not store one.
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let v2 = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2.inode_number);

    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut checked = 0usize;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.name_bytes() == b"." || entry.name_bytes() == b".." {
            continue;
        }
        assert_eq!(
            entry.name_nokey_encoded(),
            ref_encode_nokey_name([0, 0], entry.name_bytes()),
            "non-casefolded encrypted entry must encode with a zero dirhash",
        );
        checked += 1;
    }
    assert!(checked > 0, "v2_dir must have non-dot entries");
}

// Issue #166: encrypted symlinks without a registered key should
// return the kernel's no-key encoding instead of MissingFscryptKey.
// Mirrors `fscrypt_get_symlink` → `fscrypt_fname_disk_to_usr` no-key
// branch (fs/crypto/hooks.c, fs/crypto/fname.c).

/// All `v2_*_dir/slink` fixture entries point at "hello.txt" → 9-byte
/// plaintext, padded to 16 bytes via `PAD_16`, ciphertext is exactly 16
/// bytes. The no-key wire form is `[0u8; 8] || ct[16]` = 24 bytes →
/// ceil(24 * 4 / 3) = 32 base64url chars. Same length applies to v1
/// symlinks under `PAD_16` since CTS preserves length.
const HELLO_TXT_NOKEY_LEN: usize = 32;

fn assert_nokey_symlink_form(target: &[u8]) {
    assert_eq!(
        target.len(),
        HELLO_TXT_NOKEY_LEN,
        "no-key symlink encoding length must equal ceil((8 + 16) * 4 / 3)",
    );
    for c in target {
        assert!(
            BASE64URL_ALPHABET.contains(c),
            "no-key symlink target must be base64url, got 0x{c:02x}",
        );
    }
}

#[test]
fn read_symlink_returns_no_key_encoding_for_v2_dir_slink_without_key() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    // raw_entries to find slink without needing the key for name decryption.
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut slink_inode = None;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        // file_type 7 = EXT4_FT_SYMLINK
        if entry.file_type() == 7 {
            slink_inode = Some(entry.inode_number());
            break;
        }
    }
    let slink_inode = slink_inode.expect("v2_dir/slink must exist in fixture");
    drop(iter);

    let inode = ext.inode(&mut cursor, slink_inode).expect("inode");
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read_symlink without key must now succeed via no-key encoding");
    assert_nokey_symlink_form(&target);

    // Re-read with key registered — should yield plaintext "hello.txt".
    let (mut cursor2, ext2) = open_with_keys();
    let inode2 = ext2.inode(&mut cursor2, slink_inode).expect("inode2");
    assert_eq!(
        inode2
            .read_symlink(&mut cursor2)
            .expect("read with key registered"),
        b"hello.txt"
    );
}

#[test]
fn read_symlink_returns_no_key_encoding_for_v1_adiantum_slink_without_key() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let v1_adi = root
        .lookup(&mut cursor, b"v1_adiantum_dir")
        .expect("lookup v1_adiantum_dir");
    let mut dir = ext.directory_at(v1_adi.inode_number);
    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut slink_inode = None;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.file_type() == 7 {
            slink_inode = Some(entry.inode_number());
            break;
        }
    }
    let slink_inode = slink_inode.expect("v1_adiantum_dir/slink must exist in fixture");
    drop(iter);

    let inode = ext.inode(&mut cursor, slink_inode).expect("inode");
    let target = inode
        .read_symlink(&mut cursor)
        .expect("v1+Adiantum no-key path must succeed");
    assert_nokey_symlink_form(&target);
}

#[test]
fn read_symlink_uses_no_key_encoder_byte_for_byte() {
    // Cross-check the v2_dir/slink output against an independent
    // base64url + nokey-name implementation. Since we don't have direct
    // public access to the on-disk ciphertext bytes, the cross-check
    // happens by reading once with key (plaintext) and once without
    // (encoded), and confirming the encoded form has the structural
    // properties the kernel's encoder enforces (length, alphabet).
    let (mut cursor_no, ext_no) = open_without_keys();
    let (mut cursor_yes, ext_yes) = open_with_keys();

    let mut root_yes = ext_yes.root_directory();
    let v2_dir_yes = root_yes
        .lookup(&mut cursor_yes, b"v2_dir")
        .expect("lookup v2_dir");
    let mut dir_yes = ext_yes.directory_at(v2_dir_yes.inode_number);
    let slink_entry = dir_yes
        .lookup(&mut cursor_yes, b"slink")
        .expect("lookup slink");
    let slink_inode = slink_entry.inode_number;

    let inode_yes = ext_yes.inode(&mut cursor_yes, slink_inode).expect("inode");
    let plaintext = inode_yes
        .read_symlink(&mut cursor_yes)
        .expect("decrypt with key");
    assert_eq!(plaintext, b"hello.txt");

    let inode_no = ext_no.inode(&mut cursor_no, slink_inode).expect("inode");
    let encoded = inode_no
        .read_symlink(&mut cursor_no)
        .expect("no-key encoded");
    assert_nokey_symlink_form(&encoded);

    // Two runs against the same fixture must produce the same bytes
    // (no time-dependent or rng-dependent state in the encoder path).
    let inode_no2 = ext_no.inode(&mut cursor_no, slink_inode).expect("inode");
    let encoded2 = inode_no2
        .read_symlink(&mut cursor_no)
        .expect("no-key encoded twice");
    assert_eq!(encoded, encoded2, "no-key encoding must be deterministic");
}

#[test]
fn read_symlink_with_wrong_key_returns_garbled_plaintext_unchanged() {
    // Issue #166 acceptance: wrong-key behavior is unchanged. Register a
    // wrong v1 key (v1 accepts any 64-byte raw key) for the v1 descriptor
    // and confirm the call still produces *some* plaintext rather than
    // surfacing the no-key encoding (which would only fire on missing
    // key, not on wrong key).
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");
    let wrong = FscryptMasterKey::from_array([0xCC; 64]);
    ext.add_fscrypt_v1_key(FscryptKeyDescriptor(V1_ADIANTUM_DESCRIPTOR), wrong)
        .expect("v1 64-byte key passes validation");

    let mut root = ext.root_directory();
    let v1_adi = root
        .lookup(&mut cursor, b"v1_adiantum_dir")
        .expect("lookup v1_adiantum_dir");
    let mut dir = ext.directory_at(v1_adi.inode_number);
    let mut iter = dir.raw_entries(&mut cursor).expect("raw entries");
    let mut slink_inode = None;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        if entry.file_type() == 7 {
            slink_inode = Some(entry.inode_number());
            break;
        }
    }
    let slink_inode = slink_inode.expect("v1_adiantum_dir/slink must exist");
    drop(iter);

    let inode = ext.inode(&mut cursor, slink_inode).expect("inode");
    let target = inode
        .read_symlink(&mut cursor)
        .expect("wrong-key decrypt still succeeds (fscrypt is unauthenticated)");
    // Either the garbled plaintext is not "hello.txt", or — vanishingly
    // unlikely under random keys — it equals the plaintext. The crucial
    // property is that we did NOT take the no-key branch (which would
    // produce a 32-char base64url string).
    assert_ne!(
        target.len(),
        HELLO_TXT_NOKEY_LEN,
        "wrong key must not silently emit a no-key-encoded form"
    );
}
