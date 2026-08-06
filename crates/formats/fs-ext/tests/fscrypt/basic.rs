use super::support::*;

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
