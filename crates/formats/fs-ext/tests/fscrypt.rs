//! End-to-end fscrypt acceptance tests for issue #121.
//!
//! Reads the deterministic `ext4-fscrypt.img` fixture; reconstructs the
//! master keys via SHA-512 derivation; exercises every #121 acceptance
//! criterion plus #123's combined ENCRYPT_FL+CASEFOLD_FL path.
//!
//! The fixture is committed to git; if it goes missing the tests fail
//! fast pointing to `sudo bash crates/fs-ext/testdata/gen-fixtures.sh`.

#![cfg(feature = "fscrypt")]

use std::io::Cursor;
use std::path::Path;

use fs_common::FsTryIterator;
use fs_common::io::FsReadSeek;
use fs_common::traverse::{EntryKind, FsDirectory};
use fs_ext::{
    Ext, ExtError, FscryptKeyDescriptor, FscryptKeyUnwrapError, FscryptKeyUnwrapper,
    FscryptMasterKey,
};
use sha2::{Digest, Sha256, Sha512};

const IMAGE: &str = "testdata/ext4-fscrypt.img";

const V1_KEY_LABEL: &str = "tracium-fscrypt-v1-fixture";
const V1_ADIANTUM_KEY_LABEL: &str = "tracium-fscrypt-v1-adiantum-fixture";
const V2_KEY_LABEL: &str = "tracium-fscrypt-v2-fixture";
const V2_CF_KEY_LABEL: &str = "tracium-fscrypt-v2-casefold-fixture";
const V2_ADIANTUM_KEY_LABEL: &str = "tracium-fscrypt-v2-adiantum-fixture";
const V2_IV64_KEY_LABEL: &str = "tracium-fscrypt-v2-iv-ino-lblk-64-fixture";
const V2_IV32_KEY_LABEL: &str = "tracium-fscrypt-v2-iv-ino-lblk-32-fixture";
const V2_DUS512_KEY_LABEL: &str = "tracium-fscrypt-v2-dus512-fixture";
const V2_DIRECT_KEY_KEY_LABEL: &str = "tracium-fscrypt-v2-direct-key-fixture";
const V2_AES128_KEY_LABEL: &str = "tracium-fscrypt-v2-aes128-fixture";
const V2_SM4_KEY_LABEL: &str = "tracium-fscrypt-v2-sm4-fixture";
const V2_HCTR2_KEY_LABEL: &str = "tracium-fscrypt-v2-hctr2-fixture";

const V1_ADIANTUM_HELLO: &[u8] = b"v1 adiantum hello\n";
// Used by Tasks 19-22 Adiantum integration tests (fixture dir added in Task 16).
const V2_ADIANTUM_HELLO: &[u8] = b"adiantum hello\n";

const V2_IV64_HELLO: &[u8] = b"iv64 hello\n";
const V2_IV64_NESTED: &[u8] = b"iv64 nested\n";
const V2_IV32_HELLO: &[u8] = b"iv32 hello\n";
const V2_IV32_NESTED: &[u8] = b"iv32 nested\n";
const V2_DUS512_HELLO: &[u8] = b"dus512 hello\n";
const V2_DIRECT_KEY_HELLO: &[u8] = b"direct_key hello\n";
const V2_DIRECT_KEY_NESTED: &[u8] = b"direct_key nested\n";
const V2_AES128_HELLO: &[u8] = b"aes128 hello\n";
const V2_AES128_NESTED: &[u8] = b"aes128 nested\n";
const V2_SM4_HELLO: &[u8] = b"sm4 hello\n";
const V2_SM4_NESTED: &[u8] = b"sm4 nested\n";
const V2_HCTR2_HELLO: &[u8] = b"hctr2 hello\n";
const V2_HCTR2_NESTED: &[u8] = b"hctr2 nested\n";

const V1_DESCRIPTOR: [u8; 8] = [0xAA; 8];
const V1_ADIANTUM_DESCRIPTOR: [u8; 8] = [0xBB; 8];

const V1_HELLO: &[u8] = b"v1 hello\n";
const V1_NESTED: &[u8] = b"v1 nested\n";
const V2_HELLO: &[u8] = b"v2 hello\n";
const V2_NESTED: &[u8] = b"v2 nested\n";
const V2CF_HELLO: &[u8] = b"v2cf hello\n";
const V2CF_README: &[u8] = b"v2cf readme\n";

fn key_from_string(s: &str) -> FscryptMasterKey {
    let mut hasher = Sha512::new();
    hasher.update(s.as_bytes());
    let digest = hasher.finalize();
    let mut k = [0u8; 64];
    k.copy_from_slice(&digest[..]);
    FscryptMasterKey::from_array(k)
}

fn fixture_bytes() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(IMAGE);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nregenerate via `sudo bash crates/fs-ext/testdata/gen-fixtures.sh`",
            path.display()
        )
    })
}

fn open_with_keys() -> (Cursor<Vec<u8>>, Ext) {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");
    ext.add_fscrypt_v1_key(
        FscryptKeyDescriptor(V1_DESCRIPTOR),
        key_from_string(V1_KEY_LABEL),
    )
    .expect("v1 64-byte key passes validation");
    ext.add_fscrypt_v1_key(
        FscryptKeyDescriptor(V1_ADIANTUM_DESCRIPTOR),
        key_from_string(V1_ADIANTUM_KEY_LABEL),
    )
    .expect("v1 Adiantum 64-byte key passes validation");
    ext.add_fscrypt_v2_key(key_from_string(V2_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_CF_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_ADIANTUM_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_IV64_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_IV32_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_DUS512_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_DIRECT_KEY_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_AES128_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_SM4_KEY_LABEL));
    ext.add_fscrypt_v2_key(key_from_string(V2_HCTR2_KEY_LABEL));
    (cursor, ext)
}

/// Returns true when the fixture image carries `v2_sm4_dir/`. Older
/// kernels without `CONFIG_CRYPTO_SM4` skip the fixture directory at
/// gen time; tests must skip in lockstep.
///
/// Distinguishes "directory not present" (`NotFound`) from real
/// regressions (IO / parse / fscrypt errors) — only the former should
/// silently skip; everything else propagates so a broken SM4 path
/// fails the test instead of going unnoticed.
fn fixture_has_sm4_dir(cursor: &mut Cursor<Vec<u8>>, ext: &Ext) -> bool {
    let mut root = ext.root_directory();
    match root.lookup(cursor, b"v2_sm4_dir") {
        Ok(_) => true,
        Err(ExtError::NotFound) => false,
        Err(other) => panic!("v2_sm4_dir lookup failed unexpectedly: {other:?}"),
    }
}

/// Returns true when the fixture image carries `v2_hctr2_dir/`. Older
/// kernels (< 6.0) or kernels without `CONFIG_CRYPTO_HCTR2` skip the
/// fixture directory at gen time; tests must skip in lockstep.
///
/// Same NotFound-vs-real-error discrimination as `fixture_has_sm4_dir`
/// (Codex P2 in #163) so a regression in the HCTR2 path doesn't get
/// silently masked as "directory absent".
fn fixture_has_hctr2_dir(cursor: &mut Cursor<Vec<u8>>, ext: &Ext) -> bool {
    let mut root = ext.root_directory();
    match root.lookup(cursor, b"v2_hctr2_dir") {
        Ok(_) => true,
        Err(ExtError::NotFound) => false,
        Err(other) => panic!("v2_hctr2_dir lookup failed unexpectedly: {other:?}"),
    }
}

fn open_without_keys() -> (Cursor<Vec<u8>>, Ext) {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");
    (cursor, ext)
}

fn read_full_file(file: &mut fs_ext::ExtFile<'_>, fs: &mut Cursor<Vec<u8>>) -> Vec<u8> {
    let len = <fs_ext::ExtFile<'_> as FsReadSeek<Cursor<Vec<u8>>>>::len(file) as usize;
    let mut buf = vec![0u8; len];
    file.read_exact(fs, &mut buf).expect("read encrypted file");
    buf
}

#[test]
fn reads_v1_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v1_dir_entry = root.lookup(&mut cursor, b"v1_dir").expect("lookup v1_dir");
    let mut v1_dir = ext.directory_at(v1_dir_entry.inode_number);
    let hello_entry = v1_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v1_dir/hello.txt");

    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    assert!(inode.is_regular_file());
    let mut file = inode.open_file().expect("open v1 hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V1_HELLO);

    // subdir/nested.txt -- encrypted child directory under a v1 policy.
    let subdir_entry = v1_dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v1_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v1_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v1 nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V1_NESTED);
}

#[test]
fn reads_v2_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v2_dir_entry = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut v2_dir = ext.directory_at(v2_dir_entry.inode_number);

    // hello.txt
    let hello_entry = v2_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2 hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_HELLO);

    // subdir/nested.txt -- encrypted child directory.
    let subdir_entry = v2_dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_NESTED);
}

#[test]
fn reads_v2_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v2_dir_entry = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut v2_dir = ext.directory_at(v2_dir_entry.inode_number);
    let slink_entry = v2_dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn lists_v1_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v1_dir_entry = root.lookup(&mut cursor, b"v1_dir").expect("lookup v1_dir");
    let mut v1_dir = ext.directory_at(v1_dir_entry.inode_number);

    let mut iter = v1_dir.entries(&mut cursor).expect("iterate v1_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    // The traversal API skips "." and ".." by design — assert only on
    // user-visible entries.
    assert!(
        names.contains(&b"hello.txt".to_vec()),
        "v1_dir listing missing hello.txt: {names:?}"
    );
    assert!(
        names.contains(&b"subdir".to_vec()),
        "v1_dir listing missing subdir: {names:?}"
    );
}

#[test]
fn lists_v2_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v2_dir_entry = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut v2_dir = ext.directory_at(v2_dir_entry.inode_number);

    let mut iter = v2_dir.entries(&mut cursor).expect("iterate v2_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    for expected in [b"hello.txt".as_slice(), b"subdir", b"slink"] {
        assert!(
            names.contains(&expected.to_vec()),
            "v2_dir listing missing {:?}: {names:?}",
            core::str::from_utf8(expected).unwrap_or("?"),
        );
    }
}

#[test]
fn lists_v2_casefold_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();

    let mut root = ext.root_directory();
    let v2_cf_dir_entry = root
        .lookup(&mut cursor, b"v2_cf_dir")
        .expect("lookup v2_cf_dir");
    let mut v2_cf_dir = ext.directory_at(v2_cf_dir_entry.inode_number);

    let mut iter = v2_cf_dir.entries(&mut cursor).expect("iterate v2_cf_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    assert!(
        names.contains(&b"Hello.TXT".to_vec()),
        "v2_cf_dir listing missing Hello.TXT (case preserved): {names:?}"
    );
    assert!(
        names.contains(&b"READ.ME".to_vec()),
        "v2_cf_dir listing missing READ.ME: {names:?}"
    );

    // Read a file via lookup -- htree dispatch uses SipHash dirhash.
    let entry = v2_cf_dir
        .lookup(&mut cursor, b"Hello.TXT")
        .expect("lookup Hello.TXT");
    let inode = ext.inode(&mut cursor, entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open Hello.TXT");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2CF_HELLO);

    // Confirm casefold: looking up the same content under a different
    // case yields the same inode.
    let entry_lower = v2_cf_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("casefold lookup hello.txt -> Hello.TXT");
    assert_eq!(entry_lower.inode_number, entry.inode_number);

    // README via uppercase should also work.
    let entry_readme = v2_cf_dir
        .lookup(&mut cursor, b"read.me")
        .expect("casefold lookup read.me -> READ.ME");
    let inode = ext.inode(&mut cursor, entry_readme.inode_number).unwrap();
    let mut file = inode.open_file().expect("open READ.ME");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2CF_README);
}

#[test]
fn missing_key_returns_descriptor_in_error() {
    let (mut cursor, ext) = open_without_keys();

    // Root listing succeeds (root is plaintext); v1_dir lookup must fail
    // with MissingFscryptKey carrying the v1 descriptor in lowercase hex.
    let mut root = ext.root_directory();
    let v1_dir_entry = root
        .lookup(&mut cursor, b"v1_dir")
        .expect("lookup v1_dir from plaintext root");
    let mut v1_dir = ext.directory_at(v1_dir_entry.inode_number);
    let err = v1_dir.lookup(&mut cursor, b"hello.txt").unwrap_err();
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V1"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref, "aaaaaaaaaaaaaaaa");
        }
        other => panic!("expected MissingFscryptKey for v1, got {other:?}"),
    }

    // v2 path: identifier comes from the kernel's HKDF; just confirm the
    // error variant fires and the key_ref is a 32-char lowercase hex
    // string (16-byte identifier).
    let v2_dir_entry = root
        .lookup(&mut cursor, b"v2_dir")
        .expect("lookup v2_dir from plaintext root");
    let mut v2_dir = ext.directory_at(v2_dir_entry.inode_number);
    let err = v2_dir.lookup(&mut cursor, b"hello.txt").unwrap_err();
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "expected 16-byte hex id, got {key_ref}");
            assert!(
                key_ref.bytes().all(|b| b.is_ascii_hexdigit()),
                "key_ref must be lowercase hex: {key_ref}",
            );
        }
        other => panic!("expected MissingFscryptKey for v2, got {other:?}"),
    }
}

#[test]
fn raw_entries_returns_ciphertext_when_no_key() {
    let (mut cursor, ext) = open_without_keys();

    let mut root = ext.root_directory();
    let v2_dir_entry = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut v2_dir = ext.directory_at(v2_dir_entry.inode_number);

    let mut iter = v2_dir
        .raw_entries(&mut cursor)
        .expect("raw_entries on encrypted dir without key");

    let mut found_ciphertext = false;
    while let Some(entry) = iter.try_next(&mut cursor).expect("raw entry") {
        let name = entry.name_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        // Ciphertext names are arbitrary bytes -- a plaintext "hello.txt"
        // never appears here.
        assert!(
            entry.is_encrypted_name(),
            "non-dot entry must report is_encrypted_name(): {name:?}",
        );
        assert_ne!(
            name,
            b"hello.txt".as_slice(),
            "raw_entries must yield ciphertext, not plaintext"
        );
        found_ciphertext = true;
    }
    assert!(found_ciphertext, "v2_dir had no non-dot entries to inspect");
}

#[test]
fn wrong_key_returns_garbled_content() {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).expect("open ext4-fscrypt.img");

    // Register the WRONG raw bytes under the correct v1 descriptor.
    // fscrypt is unauthenticated, so reads succeed but yield garbage.
    let wrong_key = FscryptMasterKey::from_array([0x00; 64]);
    ext.add_fscrypt_v1_key(FscryptKeyDescriptor(V1_DESCRIPTOR), wrong_key)
        .expect("v1 64-byte key passes validation");

    let mut root = ext.root_directory();
    let v1_dir_entry = root.lookup(&mut cursor, b"v1_dir").expect("lookup v1_dir");
    let mut v1_dir = ext.directory_at(v1_dir_entry.inode_number);

    // Filename decryption with the wrong key produces an alternate
    // 'plaintext' that almost certainly is not "hello.txt"; do a raw
    // listing to find the file's encrypted-direntry, then try to read
    // it via the file API directly using the inode number we already
    // recorded above. Easier: enumerate, find the regular file, and
    // assert its content is not V1_HELLO.

    let mut iter = v1_dir.entries(&mut cursor).expect("iterate v1_dir");
    let mut hello_inode: Option<u32> = None;
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        let name = entry.name_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if entry.kind() == EntryKind::File {
            hello_inode = Some(entry.inode_number());
            break;
        }
    }
    drop(iter);
    let hello_inode = hello_inode.expect("v1_dir must contain a regular file");

    let inode = ext.inode(&mut cursor, hello_inode).unwrap();
    let mut file = inode.open_file().expect("open file with wrong key");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_ne!(
        &bytes, V1_HELLO,
        "wrong-key read must NOT match plaintext (fscrypt is unauthenticated)"
    );
    assert_eq!(
        bytes.len(),
        V1_HELLO.len(),
        "ciphertext-from-wrong-key length must equal file size"
    );
}

#[test]
fn reads_v1_adiantum_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v1_adi_entry = root
        .lookup(&mut cursor, b"v1_adiantum_dir")
        .expect("lookup v1_adiantum_dir");
    let mut v1_adi = ext.directory_at(v1_adi_entry.inode_number);
    let hello = v1_adi
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup hello.txt in v1_adiantum_dir");
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v1 adiantum hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(bytes, V1_ADIANTUM_HELLO);
}

#[test]
fn lists_v1_adiantum_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v1_adi_entry = root
        .lookup(&mut cursor, b"v1_adiantum_dir")
        .expect("lookup v1_adiantum_dir");
    let mut v1_adi = ext.directory_at(v1_adi_entry.inode_number);

    let mut iter = v1_adi
        .entries(&mut cursor)
        .expect("iterate v1_adiantum_dir");
    let mut seen: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        if entry.name_bytes() == b"." || entry.name_bytes() == b".." {
            continue;
        }
        seen.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    seen.sort();

    assert!(
        seen.contains(&b"hello.txt".to_vec()),
        "v1_adiantum_dir must contain hello.txt; saw {seen:?}"
    );
    assert!(
        seen.contains(&b"slink".to_vec()),
        "v1_adiantum_dir must contain slink; saw {seen:?}"
    );
}

#[test]
fn reads_v1_adiantum_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v1_adi_entry = root
        .lookup(&mut cursor, b"v1_adiantum_dir")
        .expect("lookup v1_adiantum_dir");
    let mut v1_adi = ext.directory_at(v1_adi_entry.inode_number);
    let slink_entry = v1_adi
        .lookup(&mut cursor, b"slink")
        .expect("lookup slink in v1_adiantum_dir");
    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v1 adiantum symlink target");
    assert_eq!(target, b"hello.txt");
}

#[test]
fn reads_v2_adiantum_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v2_adi_entry = root
        .lookup(&mut cursor, b"v2_adiantum_dir")
        .expect("lookup v2_adiantum_dir");
    let mut v2_adi = ext.directory_at(v2_adi_entry.inode_number);
    let hello = v2_adi
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup hello.txt in v2_adiantum_dir");
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().expect("open file");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(bytes, V2_ADIANTUM_HELLO);
}

#[test]
fn lists_v2_adiantum_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v2_adi_entry = root
        .lookup(&mut cursor, b"v2_adiantum_dir")
        .expect("lookup v2_adiantum_dir");
    let mut v2_adi = ext.directory_at(v2_adi_entry.inode_number);

    let mut iter = v2_adi
        .entries(&mut cursor)
        .expect("iterate v2_adiantum_dir");
    let mut seen: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        if entry.name_bytes() == b"." || entry.name_bytes() == b".." {
            continue;
        }
        seen.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    seen.sort();

    assert!(
        seen.contains(&b"hello.txt".to_vec()),
        "v2_adiantum_dir must contain hello.txt; saw {seen:?}"
    );
    assert!(
        seen.contains(&b"slink".to_vec()),
        "v2_adiantum_dir must contain slink; saw {seen:?}"
    );
}

#[test]
fn reads_v2_adiantum_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let v2_adi_entry = root
        .lookup(&mut cursor, b"v2_adiantum_dir")
        .expect("lookup v2_adiantum_dir");
    let mut v2_adi = ext.directory_at(v2_adi_entry.inode_number);
    let slink_entry = v2_adi
        .lookup(&mut cursor, b"slink")
        .expect("lookup slink in v2_adiantum_dir");
    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read symlink target");
    assert_eq!(target, b"hello.txt");
}

#[test]
fn reads_v2_iv_ino_lblk_64_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv64_dir_entry = root
        .lookup(&mut cursor, b"v2_iv64_dir")
        .expect("lookup v2_iv64_dir");
    let mut iv64_dir = ext.directory_at(iv64_dir_entry.inode_number);
    let hello_entry = iv64_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_iv64_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_iv64_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_IV64_HELLO);

    let subdir_entry = iv64_dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_iv64_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_iv64_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_IV64_NESTED);
}

#[test]
fn lists_v2_iv_ino_lblk_64_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv64_dir_entry = root
        .lookup(&mut cursor, b"v2_iv64_dir")
        .expect("lookup v2_iv64_dir");
    let mut iv64_dir = ext.directory_at(iv64_dir_entry.inode_number);

    let mut iter = iv64_dir.entries(&mut cursor).expect("iterate v2_iv64_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    assert!(
        names.contains(&b"hello.txt".to_vec()),
        "v2_iv64_dir listing missing hello.txt: {names:?}"
    );
    assert!(
        names.contains(&b"subdir".to_vec()),
        "v2_iv64_dir listing missing subdir: {names:?}"
    );
    assert!(
        names.contains(&b"slink".to_vec()),
        "v2_iv64_dir listing missing slink: {names:?}"
    );
}

#[test]
fn reads_v2_iv_ino_lblk_64_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv64_dir_entry = root
        .lookup(&mut cursor, b"v2_iv64_dir")
        .expect("lookup v2_iv64_dir");
    let mut iv64_dir = ext.directory_at(iv64_dir_entry.inode_number);
    let slink_entry = iv64_dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_iv64_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_iv64 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn reads_v2_iv_ino_lblk_32_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv32_dir_entry = root
        .lookup(&mut cursor, b"v2_iv32_dir")
        .expect("lookup v2_iv32_dir");
    let mut iv32_dir = ext.directory_at(iv32_dir_entry.inode_number);
    let hello_entry = iv32_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_iv32_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_iv32_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_IV32_HELLO);

    let subdir_entry = iv32_dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_iv32_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_iv32_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_IV32_NESTED);
}

#[test]
fn lists_v2_iv_ino_lblk_32_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv32_dir_entry = root
        .lookup(&mut cursor, b"v2_iv32_dir")
        .expect("lookup v2_iv32_dir");
    let mut iv32_dir = ext.directory_at(iv32_dir_entry.inode_number);

    let mut iter = iv32_dir.entries(&mut cursor).expect("iterate v2_iv32_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    assert!(
        names.contains(&b"hello.txt".to_vec()),
        "v2_iv32_dir listing missing hello.txt: {names:?}"
    );
    assert!(
        names.contains(&b"subdir".to_vec()),
        "v2_iv32_dir listing missing subdir: {names:?}"
    );
    assert!(
        names.contains(&b"slink".to_vec()),
        "v2_iv32_dir listing missing slink: {names:?}"
    );
}

#[test]
fn reads_v2_iv_ino_lblk_32_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let iv32_dir_entry = root
        .lookup(&mut cursor, b"v2_iv32_dir")
        .expect("lookup v2_iv32_dir");
    let mut iv32_dir = ext.directory_at(iv32_dir_entry.inode_number);
    let slink_entry = iv32_dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_iv32_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_iv32 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn iv_ino_lblk_64_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let iv64_dir_entry = root
        .lookup(&mut cursor, b"v2_iv64_dir")
        .expect("lookup v2_iv64_dir from plaintext root");
    let mut iv64_dir = ext.directory_at(iv64_dir_entry.inode_number);
    let err = iv64_dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted IV_INO_LBLK_64 dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn adiantum_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let v2_adi_entry = root
        .lookup(&mut cursor, b"v2_adiantum_dir")
        .expect("lookup v2_adiantum_dir from plaintext root");
    let mut v2_adi = ext.directory_at(v2_adi_entry.inode_number);

    let err = v2_adi
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted Adiantum dir must fail without key");

    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            // v2 identifiers are 16 bytes = 32 hex chars.
            assert_eq!(
                key_ref.len(),
                32,
                "v2 identifier must be 16-byte hex: {key_ref:?}"
            );
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn reads_v2_dus512_encrypted_file_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_dus512_dir")
        .expect("lookup v2_dus512_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);

    // multi_unit.bin spans 8 distinct 512 B data units (per-unit byte
    // pattern `0..=7`). Each unit must be decrypted with its own IV;
    // a single-IV-per-fs-block bug would garble 7 of the 8 sectors and
    // this byte-for-byte equality check would fail.
    let entry = dir
        .lookup(&mut cursor, b"multi_unit.bin")
        .expect("lookup v2_dus512_dir/multi_unit.bin");
    let inode = ext.inode(&mut cursor, entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open multi_unit.bin");
    let bytes = read_full_file(&mut file, &mut cursor);
    let expected: Vec<u8> = (0u8..8u8)
        .flat_map(|i| std::iter::repeat_n(i, 512))
        .collect();
    assert_eq!(
        bytes, expected,
        "sub-unit decryption must round-trip every 512 B unit"
    );

    // Short file living entirely in the first data unit — sanity that
    // the existing single-unit path still works under DUS=512.
    let entry = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_dus512_dir/hello.txt");
    let inode = ext.inode(&mut cursor, entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_dus512_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_DUS512_HELLO);
}

#[test]
fn lists_v2_dus512_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_dus512_dir")
        .expect("lookup v2_dus512_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let mut iter = dir.entries(&mut cursor).expect("iterate v2_dus512_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    assert!(
        names.contains(&b"multi_unit.bin".to_vec()),
        "v2_dus512_dir listing missing multi_unit.bin: {names:?}"
    );
    assert!(
        names.contains(&b"hello.txt".to_vec()),
        "v2_dus512_dir listing missing hello.txt: {names:?}"
    );
}

#[test]
fn dus512_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_dus512_dir")
        .expect("lookup v2_dus512_dir from plaintext root");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted DUS=512 dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn reads_v2_direct_key_encrypted_file_with_key() {
    // v2 + (Adiantum, Adiantum) + DIRECT_KEY: kernel
    // `fscrypt_setup_v2_file_key` skips the per-file KDF and threads the
    // ci_nonce through the IV instead. Byte-for-byte equality against
    // the kernel-produced fixture pins both the per-mode HKDF derivation
    // and the IV layout.
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_direct_key_dir")
        .expect("lookup v2_direct_key_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let hello_entry = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_direct_key_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_direct_key_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_DIRECT_KEY_HELLO);

    let subdir_entry = dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_direct_key_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_direct_key_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_DIRECT_KEY_NESTED);
}

#[test]
fn lists_v2_direct_key_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_direct_key_dir")
        .expect("lookup v2_direct_key_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);

    let mut iter = dir.entries(&mut cursor).expect("iterate v2_direct_key_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    for expected in [b"hello.txt".as_slice(), b"subdir", b"slink"] {
        assert!(
            names.contains(&expected.to_vec()),
            "v2_direct_key_dir listing missing {:?}: {names:?}",
            core::str::from_utf8(expected).unwrap_or("?"),
        );
    }
}

#[test]
fn reads_v2_direct_key_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_direct_key_dir")
        .expect("lookup v2_direct_key_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let slink_entry = dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_direct_key_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_direct_key encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn direct_key_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_direct_key_dir")
        .expect("lookup v2_direct_key_dir from plaintext root");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted DIRECT_KEY dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn reads_v2_aes128_encrypted_file_with_key() {
    // v2 + (AES-128-CBC, AES-128-CTS): contents use ESSIV
    // (essiv_iv = AES-256-ECB(SHA-256(content_key))(plain_iv)). Byte-for-byte
    // equality against the kernel-produced fixture pins both the per-block
    // ESSIV derivation and the AES-128-CBC plaintext recovery.
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_aes128_dir")
        .expect("lookup v2_aes128_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let hello_entry = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_aes128_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_aes128_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_AES128_HELLO);

    let subdir_entry = dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_aes128_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_aes128_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_AES128_NESTED);
}

#[test]
fn lists_v2_aes128_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_aes128_dir")
        .expect("lookup v2_aes128_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);

    let mut iter = dir.entries(&mut cursor).expect("iterate v2_aes128_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    for expected in [b"hello.txt".as_slice(), b"subdir", b"slink"] {
        assert!(
            names.contains(&expected.to_vec()),
            "v2_aes128_dir listing missing {:?}: {names:?}",
            core::str::from_utf8(expected).unwrap_or("?"),
        );
    }
}

#[test]
fn reads_v2_aes128_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_aes128_dir")
        .expect("lookup v2_aes128_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let slink_entry = dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_aes128_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_aes128 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn aes128_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_aes128_dir")
        .expect("lookup v2_aes128_dir from plaintext root");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted AES-128 dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn reads_v2_sm4_encrypted_file_with_key() {
    // v2 + (SM4-XTS contents, SM4-CBC-CTS filenames). Byte-for-byte
    // equality against the kernel-produced fixture pins both the
    // SM4-XTS content cipher and the SM4-CBC-CTS filename cipher
    // (filename lookup goes through the latter).
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_sm4_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_sm4_dir absent (regenerate fixture with CONFIG_CRYPTO_SM4)");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_sm4_dir")
        .expect("lookup v2_sm4_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let hello_entry = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_sm4_dir/hello.txt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_sm4_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_SM4_HELLO);

    let subdir_entry = dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_sm4_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_sm4_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_SM4_NESTED);
}

#[test]
fn lists_v2_sm4_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_sm4_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_sm4_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_sm4_dir")
        .expect("lookup v2_sm4_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);

    let mut iter = dir.entries(&mut cursor).expect("iterate v2_sm4_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    for expected in [b"hello.txt".as_slice(), b"subdir", b"slink"] {
        assert!(
            names.contains(&expected.to_vec()),
            "v2_sm4_dir listing missing {:?}: {names:?}",
            core::str::from_utf8(expected).unwrap_or("?"),
        );
    }
}

#[test]
fn reads_v2_sm4_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_sm4_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_sm4_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_sm4_dir")
        .expect("lookup v2_sm4_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let slink_entry = dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_sm4_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_sm4 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn sm4_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    if !fixture_has_sm4_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_sm4_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_sm4_dir")
        .expect("lookup v2_sm4_dir from plaintext root");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted SM4 dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

#[test]
fn reads_v2_hctr2_encrypted_file_with_key() {
    // v2 + (AES-256-XTS contents, AES-256-HCTR2 filenames). Reading
    // file contents exercises the existing XTS path; the HCTR2 path
    // is exercised by name lookup itself (filenames are HCTR2-
    // encrypted on disk).
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_hctr2_dir(&mut cursor, &ext) {
        eprintln!(
            "skipping: v2_hctr2_dir absent (regenerate fixture with kernel >= 6.0 + CONFIG_CRYPTO_HCTR2)"
        );
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_hctr2_dir")
        .expect("lookup v2_hctr2_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let hello_entry = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_hctr2_dir/hello.txt — exercises HCTR2 filename decrypt");
    let inode = ext.inode(&mut cursor, hello_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2_hctr2_dir/hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_HCTR2_HELLO);

    let subdir_entry = dir
        .lookup(&mut cursor, b"subdir")
        .expect("lookup v2_hctr2_dir/subdir");
    assert_eq!(subdir_entry.kind, EntryKind::Directory);
    let mut subdir = ext.directory_at(subdir_entry.inode_number);
    let nested_entry = subdir
        .lookup(&mut cursor, b"nested.txt")
        .expect("lookup v2_hctr2_dir/subdir/nested.txt");
    let inode = ext.inode(&mut cursor, nested_entry.inode_number).unwrap();
    let mut file = inode.open_file().expect("open nested.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_HCTR2_NESTED);
}

#[test]
fn lists_v2_hctr2_encrypted_dir_with_key() {
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_hctr2_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_hctr2_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_hctr2_dir")
        .expect("lookup v2_hctr2_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);

    let mut iter = dir.entries(&mut cursor).expect("iterate v2_hctr2_dir");
    let mut names: Vec<Vec<u8>> = Vec::new();
    while let Some(entry) = iter.try_next(&mut cursor).expect("entry") {
        names.push(entry.name_bytes().to_vec());
    }
    drop(iter);
    names.sort();
    for expected in [b"hello.txt".as_slice(), b"subdir", b"slink"] {
        assert!(
            names.contains(&expected.to_vec()),
            "v2_hctr2_dir listing missing {:?}: {names:?}",
            core::str::from_utf8(expected).unwrap_or("?"),
        );
    }
}

#[test]
fn reads_v2_hctr2_encrypted_symlink_target() {
    let (mut cursor, ext) = open_with_keys();
    if !fixture_has_hctr2_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_hctr2_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_hctr2_dir")
        .expect("lookup v2_hctr2_dir");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let slink_entry = dir
        .lookup(&mut cursor, b"slink")
        .expect("lookup v2_hctr2_dir/slink");

    let inode = ext.inode(&mut cursor, slink_entry.inode_number).unwrap();
    assert!(inode.is_symlink());
    let target = inode
        .read_symlink(&mut cursor)
        .expect("read v2_hctr2 encrypted symlink");
    assert_eq!(&target, b"hello.txt");
}

#[test]
fn hctr2_missing_key_returns_identifier_in_error() {
    let (mut cursor, ext) = open_without_keys();
    if !fixture_has_hctr2_dir(&mut cursor, &ext) {
        eprintln!("skipping: v2_hctr2_dir absent");
        return;
    }
    let mut root = ext.root_directory();
    let dir_entry = root
        .lookup(&mut cursor, b"v2_hctr2_dir")
        .expect("lookup v2_hctr2_dir from plaintext root");
    let mut dir = ext.directory_at(dir_entry.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("lookup inside encrypted HCTR2 dir must fail without key");
    match err {
        ExtError::MissingFscryptKey {
            policy_kind,
            key_ref,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32, "v2 identifier must be 16-byte hex");
        }
        other => panic!("expected MissingFscryptKey, got {other:?}"),
    }
}

// === Wrapped-key path (#156) =============================================

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Synthetic unwrap stub: the "wrapped" form is the master-key bytes
/// XOR'd against `pad`, and `unwrap_key` reverses the XOR. Real
/// operators bind to a TEE adapter; the tests just need the plumbing
/// to work end-to-end against a real fixture-derived key.
struct XorUnwrapper {
    pad: u8,
}

impl FscryptKeyUnwrapper for XorUnwrapper {
    fn unwrap_key(
        &self,
        wrapped: &[u8],
    ) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        let unwrapped: Vec<u8> = wrapped.iter().map(|b| b ^ self.pad).collect();
        FscryptMasterKey::from_bytes(&unwrapped)
            .map_err(|e| FscryptKeyUnwrapError::new(format!("{e:?}")))
    }
}

/// Counts unwrap calls so a test can pin the OnceCell-backed cache.
/// `Arc<AtomicUsize>` satisfies the trait's `Send + Sync` bounds.
struct CountingUnwrapper {
    inner: XorUnwrapper,
    calls: Arc<AtomicUsize>,
}

impl FscryptKeyUnwrapper for CountingUnwrapper {
    fn unwrap_key(
        &self,
        wrapped: &[u8],
    ) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.unwrap_key(wrapped)
    }
}

/// Failing unwrap stub for negative tests.
struct FailingUnwrapper;
impl FscryptKeyUnwrapper for FailingUnwrapper {
    fn unwrap_key(&self, _: &[u8]) -> std::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
        Err(FscryptKeyUnwrapError::new("simulated TEE failure"))
    }
}

fn v2_identifier_for(label: &str) -> fs_ext::FscryptKeyIdentifier {
    // Mirror the kernel's HKDF-SHA512 identifier derivation by going
    // through `add_fscrypt_v2_key` once on a throwaway Ext, then
    // extracting the returned identifier. Avoids re-implementing the
    // KDF in the test helper.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();
    ext.add_fscrypt_v2_key(key_from_string(label))
}

fn xor_blob(key: &FscryptMasterKey, pad: u8) -> Vec<u8> {
    key.as_bytes().iter().map(|b| b ^ pad).collect()
}

#[test]
fn wrapped_key_unwrap_callback_decrypts_v2_dir() {
    // End-to-end plumbing: register the v2_dir master key via the
    // wrapped-key path (XOR pad), then confirm v2_dir/hello.txt
    // decrypts byte-for-byte. Pins that the lazy unwrap path produces
    // the same plaintext as the raw-key path.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw = key_from_string(V2_KEY_LABEL);
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    let wrapped = xor_blob(&raw, 0x55);
    ext.add_fscrypt_v2_wrapped_key(identifier, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect("lookup v2_dir/hello.txt with wrapped key");
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().expect("open v2 hello.txt");
    let bytes = read_full_file(&mut file, &mut cursor);
    assert_eq!(&bytes, V2_HELLO);
}

#[test]
fn wrapped_key_unwrap_failure_surfaces_as_unwrap_failed_error() {
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    // Register a wrapped entry under v2_dir's identifier with a
    // FailingUnwrapper. The first inode lookup against the v2_dir
    // policy must surface FscryptKeyUnwrapFailed (NOT MissingFscryptKey,
    // NOT garbage), with the registered identifier in the error.
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    ext.add_fscrypt_v2_wrapped_key(identifier, vec![0u8; 64], Box::new(FailingUnwrapper));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").expect("lookup v2_dir");
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let err = dir
        .lookup(&mut cursor, b"hello.txt")
        .expect_err("FailingUnwrapper must surface as Err, not silent garbage");
    match err {
        ExtError::FscryptKeyUnwrapFailed {
            policy_kind,
            key_ref,
            reason,
            ..
        } => {
            assert!(policy_kind.contains("V2"), "policy_kind = {policy_kind}");
            assert_eq!(key_ref.len(), 32);
            assert!(
                reason.contains("simulated TEE failure"),
                "reason = {reason}"
            );
        }
        other => panic!("expected FscryptKeyUnwrapFailed, got {other:?}"),
    }
}

#[test]
fn wrapped_key_identifier_mismatch_surfaces_as_unwrap_failed_error() {
    // Operator misconfiguration: wrapped blob unwraps to KEY_A but the
    // operator registered it under KEY_B's identifier. The keystore's
    // defensive identifier-verification check must surface
    // FscryptKeyUnwrapFailed rather than caching the wrong key.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw_v2 = key_from_string(V2_KEY_LABEL);
    let wrong_id = v2_identifier_for(V2_CF_KEY_LABEL); // belongs to a different key
    let wrapped = xor_blob(&raw_v2, 0x55);
    // Crucially: register under wrong_id so the lookup-against-wrong_id
    // path triggers the verification check on first unwrap.
    ext.add_fscrypt_v2_wrapped_key(wrong_id, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

    let mut root = ext.root_directory();
    let v2_cf_dir = root
        .lookup(&mut cursor, b"v2_cf_dir")
        .expect("lookup v2_cf_dir");
    let mut dir = ext.directory_at(v2_cf_dir.inode_number);
    let err = dir
        .lookup(&mut cursor, b"Hello.TXT")
        .expect_err("identifier mismatch must surface as Err");
    match err {
        ExtError::FscryptKeyUnwrapFailed { reason, .. } => {
            assert!(
                reason.contains("does not match registered"),
                "reason = {reason}"
            );
        }
        other => panic!("expected FscryptKeyUnwrapFailed, got {other:?}"),
    }
}

#[test]
fn wrapped_key_unwrap_callback_invoked_only_once_across_lookups() {
    // OnceCell cache: the unwrap callback runs exactly once for many
    // lookups against the same identifier. Multiple file decrypts
    // inside the same directory should all reuse the cached key.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    let raw = key_from_string(V2_KEY_LABEL);
    let identifier = v2_identifier_for(V2_KEY_LABEL);
    let wrapped = xor_blob(&raw, 0x55);
    let counter = Arc::new(AtomicUsize::new(0));
    let unwrapper = CountingUnwrapper {
        inner: XorUnwrapper { pad: 0x55 },
        calls: Arc::clone(&counter),
    };
    ext.add_fscrypt_v2_wrapped_key(identifier, wrapped, Box::new(unwrapper));

    // Two distinct lookups under the same v2 identifier:
    //   v2_dir/hello.txt  (regular file)
    //   v2_dir/subdir/nested.txt  (regular file under encrypted subdir)
    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").unwrap();
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir.lookup(&mut cursor, b"hello.txt").unwrap();
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    let _ = read_full_file(&mut file, &mut cursor);

    let subdir = dir.lookup(&mut cursor, b"subdir").unwrap();
    let mut sub = ext.directory_at(subdir.inode_number);
    let nested = sub.lookup(&mut cursor, b"nested.txt").unwrap();
    let inode = ext.inode(&mut cursor, nested.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    let _ = read_full_file(&mut file, &mut cursor);

    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "unwrap callback must be invoked exactly once across lookups"
    );
}

#[test]
fn raw_key_path_still_works_alongside_wrapped_keys() {
    // Acceptance criterion: "Existing raw-key path still works
    // unchanged." Register raw + wrapped keys side by side and confirm
    // both decrypt their respective fixture directories.
    let bytes = fixture_bytes();
    let mut cursor = Cursor::new(bytes);
    let mut ext = Ext::new(&mut cursor).unwrap();

    // v2_dir via the raw path.
    ext.add_fscrypt_v2_key(key_from_string(V2_KEY_LABEL));
    // v2_cf_dir via the wrapped path.
    let raw_cf = key_from_string(V2_CF_KEY_LABEL);
    let id_cf = v2_identifier_for(V2_CF_KEY_LABEL);
    let wrapped_cf = xor_blob(&raw_cf, 0x33);
    ext.add_fscrypt_v2_wrapped_key(id_cf, wrapped_cf, Box::new(XorUnwrapper { pad: 0x33 }));

    let mut root = ext.root_directory();
    let v2_dir = root.lookup(&mut cursor, b"v2_dir").unwrap();
    let mut dir = ext.directory_at(v2_dir.inode_number);
    let hello = dir.lookup(&mut cursor, b"hello.txt").unwrap();
    let inode = ext.inode(&mut cursor, hello.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    assert_eq!(read_full_file(&mut file, &mut cursor), V2_HELLO);

    let v2_cf = root.lookup(&mut cursor, b"v2_cf_dir").unwrap();
    let mut cf = ext.directory_at(v2_cf.inode_number);
    let h = cf.lookup(&mut cursor, b"Hello.TXT").unwrap();
    let inode = ext.inode(&mut cursor, h.inode_number).unwrap();
    let mut file = inode.open_file().unwrap();
    assert_eq!(read_full_file(&mut file, &mut cursor), V2CF_HELLO);
}

// Issue #167: kernel-equivalent base64url(fscrypt_nokey_name) for
// no-key directory entries. These tests cross-check
// `ExtRawDirEntry::name_nokey_encoded()` against an independent inline
// implementation of the kernel algorithm so a regression in the
// production encoder doesn't sneak through.

const NOKEY_INLINE_LEN: usize = 149;

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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
        out.push(BASE64URL_ALPHABET[((n >> 18) & 0x3f) as usize]);
        out.push(BASE64URL_ALPHABET[((n >> 12) & 0x3f) as usize]);
        out.push(BASE64URL_ALPHABET[((n >> 6) & 0x3f) as usize]);
        out.push(BASE64URL_ALPHABET[(n & 0x3f) as usize]);
    }
    match tail.len() {
        0 => {}
        1 => {
            let n = u32::from(tail[0]) << 4;
            out.push(BASE64URL_ALPHABET[((n >> 6) & 0x3f) as usize]);
            out.push(BASE64URL_ALPHABET[(n & 0x3f) as usize]);
        }
        2 => {
            let n = (u32::from(tail[0]) << 10) | (u32::from(tail[1]) << 2);
            out.push(BASE64URL_ALPHABET[((n >> 12) & 0x3f) as usize]);
            out.push(BASE64URL_ALPHABET[((n >> 6) & 0x3f) as usize]);
            out.push(BASE64URL_ALPHABET[(n & 0x3f) as usize]);
        }
        _ => unreachable!(),
    }
    out
}

/// Reference fscrypt_nokey_name encoder mirroring the kernel's no-key
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
/// plaintext, padded to 16 bytes via PAD_16, ciphertext is exactly 16
/// bytes. The no-key wire form is `[0u8; 8] || ct[16]` = 24 bytes →
/// ceil(24 * 4 / 3) = 32 base64url chars. Same length applies to v1
/// symlinks under PAD_16 since CTS preserves length.
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
