use super::support::*;

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
