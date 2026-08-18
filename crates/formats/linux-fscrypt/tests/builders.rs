//! The `keystore + policy + FsParams` entry points, which replaced the
//! `&Ext`-shaped builders when fscrypt moved out of `fs-ext`.
//!
//! Each round-trip test decrypts the same buffer twice — once through
//! the builder, once through the primitive it is supposed to assemble
//! (`kdf_*` for the key, `IvDerivation` for the IV, `data_unit_size` for
//! the chunking) — and demands the bytes agree. That pins key
//! selection, IV selection, and data-unit size together without needing
//! an encryptor: any wrong wire in the builder changes the output.

use linux_fscrypt::{
    ContentCipher, FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_256_CTS, FSCRYPT_MODE_AES_256_XTS,
    FSCRYPT_POLICY_FLAG_DIRECT_KEY, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, FilenameCipher, FsParams,
    FscryptError, FscryptKeyDescriptor, FscryptKeyIdentifier, FscryptKeystore, FscryptMasterKey,
    FscryptPolicy, FscryptPolicyKind, IvDerivation, build_content_cipher, build_filename_cipher,
    data_unit_size, derive_dirhash_key, dirhash_key, kdf_v1, kdf_v2, mode_keysize,
};

const BLOCK_SIZE: u32 = 4096;
const FS_UUID: [u8; 16] = [0x55; 16];
const NONCE: [u8; 16] = [0xBB; 16];
const INODE: u32 = 12;

fn params() -> FsParams {
    FsParams {
        block_size: BLOCK_SIZE,
        uuid: FS_UUID,
        has_stable_inodes: true,
    }
}

fn master_key() -> FscryptMasterKey {
    FscryptMasterKey::from_array([0x11; 64])
}

fn v2_policy(flags: u8, id: FscryptKeyIdentifier) -> FscryptPolicy {
    FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_AES_256_CTS,
        flags,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(id),
        nonce: NONCE,
    }
}

/// A recognisable, non-repeating buffer: XTS and CBC both diffuse, so
/// two ciphers differing in key or IV cannot agree on its plaintext.
fn sample_block() -> Vec<u8> {
    (0..BLOCK_SIZE).map(|i| (i % 251) as u8).collect()
}

fn decrypted(cipher: &ContentCipher, block_index: u128) -> Vec<u8> {
    let mut buf = sample_block();
    cipher
        .decrypt_block(&mut buf, block_index)
        .expect("block length matches the data-unit size");
    buf
}

fn decrypted_name(cipher: &FilenameCipher) -> Vec<u8> {
    // 32 bytes exercises the CS3 last-two-block swap rather than the
    // degenerate single-block path.
    let ct: Vec<u8> = (0..32u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    cipher.decrypt_name(&ct).expect("32-byte CS3 ciphertext")
}

#[test]
fn content_cipher_for_default_v2_policy_uses_per_file_key_and_block_index_iv() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let policy = v2_policy(0x02, id);

    let built = build_content_cipher(&keys, &policy, INODE, &params()).expect("policy supported");

    let key_size = mode_keysize(policy.contents_mode).expect("XTS is a known mode");
    let expected_key = kdf_v2::derive(
        &master_key(),
        kdf_v2::ctx::PER_FILE_ENC_KEY,
        &NONCE,
        key_size,
    );
    let expected = ContentCipher::with_iv(
        &policy,
        &expected_key,
        IvDerivation::PerFileBlockIndex,
        BLOCK_SIZE as usize,
    )
    .expect("hand-built cipher");

    assert_eq!(decrypted(&built, 7), decrypted(&expected, 7));
}

#[test]
fn content_cipher_for_v1_policy_uses_the_v1_kdf() {
    let descriptor = FscryptKeyDescriptor([0xAA; 8]);
    let mut keys = FscryptKeystore::default();
    keys.add_v1(descriptor, master_key());
    let policy = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_AES_256_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: Some(descriptor),
        key_identifier: None,
        nonce: NONCE,
    };

    let built = build_content_cipher(&keys, &policy, INODE, &params()).expect("policy supported");

    let key_size = mode_keysize(policy.contents_mode).expect("XTS is a known mode");
    let expected_key = kdf_v1::derive(&master_key(), &NONCE, key_size).expect("64-byte v1 key");
    let expected = ContentCipher::with_iv(
        &policy,
        &expected_key,
        IvDerivation::PerFileBlockIndex,
        BLOCK_SIZE as usize,
    )
    .expect("hand-built cipher");

    assert_eq!(decrypted(&built, 3), decrypted(&expected, 3));
}

#[test]
fn content_cipher_for_iv_ino_lblk_64_mixes_the_uuid_and_the_inode() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let policy = v2_policy(0x02 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, id);

    let built = build_content_cipher(&keys, &policy, INODE, &params()).expect("policy supported");

    let key_size = mode_keysize(policy.contents_mode).expect("XTS is a known mode");
    let expected_key =
        kdf_v2::derive_iv_ino_lblk_64_key(&master_key(), policy.contents_mode, &FS_UUID, key_size);
    let expected = ContentCipher::with_iv(
        &policy,
        &expected_key,
        IvDerivation::InoLblk64 {
            inode_number: INODE,
        },
        BLOCK_SIZE as usize,
    )
    .expect("hand-built cipher");

    assert_eq!(decrypted(&built, 5), decrypted(&expected, 5));

    // The inode really does reach the IV: another inode under the same
    // per-mode key must decrypt the same bytes differently.
    let other = build_content_cipher(&keys, &policy, INODE + 1, &params()).expect("supported");
    assert_ne!(decrypted(&built, 5), decrypted(&other, 5));
}

#[test]
fn content_cipher_honours_sub_block_data_units() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let mut policy = v2_policy(0x02, id);
    policy.log2_data_unit_size = 9; // 512 B units inside a 4 KiB block

    assert_eq!(data_unit_size(&policy, BLOCK_SIZE), 512);

    let built = build_content_cipher(&keys, &policy, INODE, &params()).expect("DUS=512 supported");

    let key_size = mode_keysize(policy.contents_mode).expect("XTS is a known mode");
    let key = kdf_v2::derive(
        &master_key(),
        kdf_v2::ctx::PER_FILE_ENC_KEY,
        &NONCE,
        key_size,
    );
    let per_unit =
        ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 512).expect("512");
    let per_block =
        ContentCipher::with_iv(&policy, &key, IvDerivation::PerFileBlockIndex, 4096).expect("4096");

    assert_eq!(decrypted(&built, 2), decrypted(&per_unit, 2));
    assert_ne!(decrypted(&built, 2), decrypted(&per_block, 2));
}

#[test]
fn filename_cipher_for_direct_key_adiantum_uses_the_per_mode_key_and_nonce_iv() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let mut policy = v2_policy(0x02 | FSCRYPT_POLICY_FLAG_DIRECT_KEY, id);
    policy.contents_mode = FSCRYPT_MODE_ADIANTUM;
    policy.filenames_mode = FSCRYPT_MODE_ADIANTUM;

    let built = build_filename_cipher(&keys, &policy, INODE, &params()).expect("v2 + Adiantum");

    let key_size = mode_keysize(policy.filenames_mode).expect("Adiantum is a known mode");
    let expected_key = kdf_v2::derive_direct_key(&master_key(), policy.filenames_mode, key_size);
    let expected = FilenameCipher::new(
        &policy,
        &expected_key,
        IvDerivation::DirectKey { nonce: NONCE },
    )
    .expect("hand-built cipher");

    assert_eq!(decrypted_name(&built), decrypted_name(&expected));
}

#[test]
fn missing_key_names_the_identifier_in_hex() {
    let keys = FscryptKeystore::default();
    let policy = v2_policy(0x02, FscryptKeyIdentifier([0xAB; 16]));

    let Err(err) = build_content_cipher(&keys, &policy, INODE, &params()) else {
        panic!("an empty keystore cannot build a cipher");
    };
    match err {
        FscryptError::MissingKey {
            inode,
            policy_kind,
            key_ref,
        } => {
            assert_eq!(inode, INODE);
            assert_eq!(policy_kind, "V2");
            assert_eq!(key_ref, "ab".repeat(16));
        }
        other => panic!("expected MissingKey, got {other:?}"),
    }
}

#[test]
fn iv_ino_lblk_is_rejected_without_stable_inodes() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let policy = v2_policy(0x02 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, id);
    let unstable = FsParams {
        has_stable_inodes: false,
        ..params()
    };

    let Err(err) = build_content_cipher(&keys, &policy, INODE, &unstable) else {
        panic!("IV_INO_LBLK_64 without stable inodes must fail closed");
    };
    assert!(
        matches!(err, FscryptError::UnsupportedMode { inode, .. } if inode == INODE),
        "expected UnsupportedMode, got {err:?}"
    );
}

#[test]
fn dirhash_key_matches_the_direct_derivation_and_degrades_without_a_key() {
    let mut keys = FscryptKeystore::default();
    let id = keys.add_v2(master_key());
    let policy = v2_policy(0x02, id);

    let got = dirhash_key(&keys, &policy, INODE, &params()).expect("v2 policy");
    assert_eq!(got, Some(derive_dirhash_key(&master_key(), &NONCE)));

    // No key registered: a fallback signal, not an error — the caller
    // scans the directory sequentially instead.
    let empty = FscryptKeystore::default();
    assert_eq!(
        dirhash_key(&empty, &policy, INODE, &params()).expect("v2 policy"),
        None
    );
}

#[test]
fn dirhash_key_rejects_v1_policies() {
    let descriptor = FscryptKeyDescriptor([0xAA; 8]);
    let mut keys = FscryptKeystore::default();
    keys.add_v1(descriptor, master_key());
    let policy = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_AES_256_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: Some(descriptor),
        key_identifier: None,
        nonce: NONCE,
    };

    let err = dirhash_key(&keys, &policy, INODE, &params()).unwrap_err();
    assert!(
        matches!(err, FscryptError::InvalidPolicy { inode, .. } if inode == INODE),
        "expected InvalidPolicy, got {err:?}"
    );
}
