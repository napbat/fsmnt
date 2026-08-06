use super::*;

#[test]
fn parse_v1_well_formed() {
    let mut buf = [0u8; 28];
    buf[0] = 1; // version
    buf[1] = 1; // contents = AES-256-XTS
    buf[2] = 4; // filenames = AES-256-CTS
    buf[3] = 0x02; // flags: PAD_16
    buf[4..12].copy_from_slice(&[0xAA; 8]);
    buf[12..28].copy_from_slice(&[0xBB; 16]);
    let p = parse_context(&buf, 5).unwrap();
    assert_eq!(p.kind, FscryptPolicyKind::V1);
    assert_eq!(p.contents_mode, 1);
    assert_eq!(p.filenames_mode, 4);
    assert_eq!(p.flags, 0x02);
    assert_eq!(p.padding_bytes(), 16);
    assert_eq!(p.key_descriptor.unwrap().0, [0xAA; 8]);
    assert_eq!(p.nonce, [0xBB; 16]);
}

#[test]
fn parse_v2_well_formed() {
    let mut buf = [0u8; 40];
    buf[0] = 2;
    buf[1] = 1;
    buf[2] = 4;
    buf[3] = 0x01; // flags: PAD_8
    buf[4] = 0; // log2_data_unit_size
    buf[5..8].copy_from_slice(&[0, 0, 0]);
    buf[8..24].copy_from_slice(&[0xCC; 16]);
    buf[24..40].copy_from_slice(&[0xDD; 16]);
    let p = parse_context(&buf, 7).unwrap();
    assert_eq!(p.kind, FscryptPolicyKind::V2);
    assert_eq!(p.padding_bytes(), 8);
    assert_eq!(p.key_identifier.unwrap().0, [0xCC; 16]);
    assert_eq!(p.nonce, [0xDD; 16]);
}

#[test]
fn parse_v1_wrong_size_rejected() {
    let buf = [1u8; 27];
    let err = parse_context(&buf, 1).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidFscryptPolicy { inode: 1, .. }
    ));
}

#[test]
fn parse_v2_nonzero_reserved_rejected() {
    let mut buf = [0u8; 40];
    buf[0] = 2;
    buf[5] = 1; // pollute reserved
    let err = parse_context(&buf, 9).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidFscryptPolicy { inode: 9, .. }
    ));
}

#[test]
fn parse_unknown_version_rejected() {
    let buf = [3u8; 28];
    let err = parse_context(&buf, 11).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidFscryptPolicy { inode: 11, .. }
    ));
}

#[test]
fn parse_empty_rejected() {
    let buf: [u8; 0] = [];
    let err = parse_context(&buf, 13).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidFscryptPolicy { inode: 13, .. }
    ));
}

#[test]
fn validate_supported_accepts_default_modes() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(validate_supported(&p, 1, 12, true).is_ok());
}

#[test]
fn validate_supported_rejects_direct_key_with_xts() {
    // Kernel `supported_direct_key_modes` rejects AES-256-XTS because
    // its 16-byte ivsize is < offsetofend(union fscrypt_iv, nonce) = 24.
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_DIRECT_KEY,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_accepts_v2_adiantum_direct_key() {
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: 0x02 | FSCRYPT_POLICY_FLAG_DIRECT_KEY,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    validate_supported(&p, 1, 12, true)
        .expect("v2 (Adiantum, Adiantum) + DIRECT_KEY is supported");
}

#[test]
fn validate_supported_rejects_v1_direct_key() {
    // Kernel allows v1 + DIRECT_KEY but issue #154 scopes our work to v2.
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: 0x02 | FSCRYPT_POLICY_FLAG_DIRECT_KEY,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0u8; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_rejects_direct_key_with_iv_ino_lblk_64() {
    // Kernel `fscrypt_supported_v2_policy` mutex (count > 1).
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: FSCRYPT_POLICY_FLAG_DIRECT_KEY | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_rejects_direct_key_with_iv_ino_lblk_32() {
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: FSCRYPT_POLICY_FLAG_DIRECT_KEY | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_accepts_iv_ino_lblk_64_on_v2_xts() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,                                 // AES-256-XTS
        filenames_mode: 4,                                // AES-256-CTS
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | 0x02, // + PAD_16
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v2 + XTS/CTS + IV_INO_LBLK_64 is supported");
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_64_without_stable_inodes() {
    // Mirrors kernel `supported_iv_ino_lblk_policy`: rejects when
    // `s_cop->has_stable_inodes(sb)` is false. ext4 sources that
    // hook from `EXT4_FEATURE_COMPAT_STABLE_INODES` (0x0800).
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(matches!(
        validate_supported(&p, 7, 12, false).unwrap_err(),
        ExtError::UnsupportedFscryptMode { inode: 7, .. }
    ));
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_32_without_stable_inodes() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 | 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(matches!(
        validate_supported(&p, 9, 12, false).unwrap_err(),
        ExtError::UnsupportedFscryptMode { inode: 9, .. }
    ));
}

#[test]
fn validate_supported_accepts_default_v2_xts_without_stable_inodes() {
    // Without IV_INO_LBLK_*, the stable_inodes gate does not apply —
    // a default-IV v2 policy decrypts correctly regardless of
    // inode renumbering because the per-file key derivation does
    // not mix in the inode number.
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    validate_supported(&p, 1, 12, false)
        .expect("default v2 XTS/CTS is supported regardless of stable_inodes");
}

#[test]
fn validate_supported_accepts_iv_ino_lblk_32_on_v2_xts() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 | 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v2 + XTS/CTS + IV_INO_LBLK_32 is supported");
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_both_set() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_on_v1() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: 1,
        filenames_mode: 4,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0; 16],
    };
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_on_adiantum() {
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_rejects_unsupported_modes() {
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 9,
        filenames_mode: 4,
        flags: 0,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_rejects_unknown_high_bits() {
    // Bit 5 (0x20) is reserved; reject.
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: 0x20,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

fn baseline_v2_xts() -> FscryptPolicy {
    FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: 1,
        filenames_mode: 4,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0; 16])),
        nonce: [0; 16],
    }
}

#[test]
fn validate_supported_accepts_v2_dus_512_on_4k_block() {
    let mut p = baseline_v2_xts();
    p.log2_data_unit_size = 9; // 512 B
    validate_supported(&p, 1, 12, true).expect("DUS=512 on 4 KiB block is supported");
}

#[test]
fn validate_supported_accepts_dus_equal_fs_block_size() {
    let mut p = baseline_v2_xts();
    p.log2_data_unit_size = 12; // exactly the block size — kernel accepts
    validate_supported(&p, 1, 12, true).expect("DUS == block size is supported");
}

#[test]
fn validate_supported_rejects_dus_below_sector_shift() {
    let mut p = baseline_v2_xts();
    p.log2_data_unit_size = 8; // 256 B, below SECTOR_SHIFT
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_rejects_dus_above_fs_block_size() {
    let mut p = baseline_v2_xts();
    p.log2_data_unit_size = 13; // 8 KiB, larger than the 4 KiB fs block
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_32_with_sub_block_dus() {
    let mut p = baseline_v2_xts();
    p.flags = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 | 0x02;
    p.log2_data_unit_size = 9;
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_accepts_iv_ino_lblk_32_with_block_sized_dus() {
    // Equal to fs_block_size_log2 — kernel allows because the data
    // unit is still the full fs block.
    let mut p = baseline_v2_xts();
    p.flags = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 | 0x02;
    p.log2_data_unit_size = 12;
    validate_supported(&p, 1, 12, true)
        .expect("IV_INO_LBLK_32 + DUS == block size is supported");
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_64_with_sub_block_dus() {
    // Kernel guard `fscrypt_max_file_dun_bits > 32` rejects this
    // combo on filesystems whose max file size exceeds 2^32 data
    // units — true for any ext4 image with sub-block DUS.
    let mut p = baseline_v2_xts();
    p.flags = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | 0x02;
    p.log2_data_unit_size = 9;
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_accepts_iv_ino_lblk_64_with_block_sized_dus() {
    // DUS == fs_block_size makes IV_INO_LBLK_64 safe: the data-unit
    // index equals the fs-block index, well within 32 bits for any
    // realistic file.
    let mut p = baseline_v2_xts();
    p.flags = FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 | 0x02;
    p.log2_data_unit_size = 12;
    validate_supported(&p, 1, 12, true)
        .expect("IV_INO_LBLK_64 + DUS == block size is supported");
}

#[test]
fn validate_supported_rejects_v1_dus_non_default() {
    // v1 has no on-wire DUS field; any non-zero value is impossible
    // from a parser perspective but must still fail-closed.
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: 1,
        filenames_mode: 4,
        flags: 0x02,
        log2_data_unit_size: 9,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0; 16],
    };
    assert!(validate_supported(&p, 1, 12, true).is_err());
}

#[test]
fn validate_supported_accepts_adiantum_pair() {
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: 0x02, // PAD_16
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    validate_supported(&p, 42, 12, true).expect("v2 (Adiantum, Adiantum) is supported");
}

#[test]
fn validate_supported_accepts_v2_aes128_pair() {
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_AES_128_CBC,
        filenames_mode: FSCRYPT_MODE_AES_128_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v2 (AES-128-CBC, AES-128-CTS) is supported");
}

#[test]
fn validate_supported_accepts_v1_aes128_pair() {
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_AES_128_CBC,
        filenames_mode: FSCRYPT_MODE_AES_128_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0u8; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v1 (AES-128-CBC, AES-128-CTS) is supported");
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_with_aes128() {
    // Kernel `fscrypt_supported_iv_ino_lblk_policy` only allows
    // IV_INO_LBLK_* with AES-256-XTS contents — AES-128-CBC has no
    // inline-crypto wiring.
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS};
    for flag in [
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
    ] {
        let p = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_128_CBC,
            filenames_mode: FSCRYPT_MODE_AES_128_CTS,
            flags: flag,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        assert!(
            validate_supported(&p, 1, 12, true).is_err(),
            "IV_INO_LBLK + AES-128 must be rejected (flag = {flag:#x})"
        );
    }
}

#[test]
fn validate_supported_accepts_v2_sm4_pair() {
    use crate::fscrypt::types::{FSCRYPT_MODE_SM4_CTS, FSCRYPT_MODE_SM4_XTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_SM4_XTS,
        filenames_mode: FSCRYPT_MODE_SM4_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v2 (SM4-XTS, SM4-CTS) is supported");
}

#[test]
fn validate_supported_rejects_v1_sm4_pair() {
    // Kernel `fscrypt_valid_enc_modes_v1` does not list SM4.
    use crate::fscrypt::types::{FSCRYPT_MODE_SM4_CTS, FSCRYPT_MODE_SM4_XTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_SM4_XTS,
        filenames_mode: FSCRYPT_MODE_SM4_CTS,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0u8; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_with_sm4() {
    // Kernel `supported_iv_ino_lblk_policy` requires AES-256-XTS
    // contents; SM4-XTS does not qualify.
    use crate::fscrypt::types::{FSCRYPT_MODE_SM4_CTS, FSCRYPT_MODE_SM4_XTS};
    for flag in [
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
    ] {
        let p = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_SM4_XTS,
            filenames_mode: FSCRYPT_MODE_SM4_CTS,
            flags: flag | 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        assert!(
            validate_supported(&p, 1, 12, true).is_err(),
            "(SM4-XTS, SM4-CTS) + IV_INO_LBLK must be rejected (flag = {flag:#x})"
        );
    }
}

#[test]
fn validate_supported_accepts_v2_xts_hctr2_pair() {
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_256_HCTR2, FSCRYPT_MODE_AES_256_XTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_AES_256_HCTR2,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    validate_supported(&p, 1, 12, true).expect("v2 (AES-256-XTS, AES-256-HCTR2) is supported");
}

#[test]
fn validate_supported_rejects_v1_xts_hctr2_pair() {
    // Kernel `fscrypt_valid_enc_modes_v1` does not list HCTR2;
    // mirror that even though the (XTS, HCTR2) pair is in
    // SUPPORTED_PAIRS at the version-agnostic layer.
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_256_HCTR2, FSCRYPT_MODE_AES_256_XTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_AES_256_HCTR2,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0; 8])),
        key_identifier: None,
        nonce: [0u8; 16],
    };
    assert!(matches!(
        validate_supported(&p, 1, 12, true).unwrap_err(),
        ExtError::UnsupportedFscryptMode { .. }
    ));
}

#[test]
fn validate_supported_rejects_iv_ino_lblk_with_hctr2() {
    // Kernel allows IV_INO_LBLK_* with (XTS, HCTR2) — contents is
    // XTS, which is the mode the kernel `supported_iv_ino_lblk_policy`
    // explicitly whitelists. fs-ext scopes this combo out per
    // issue #153 ("Out of scope: HCTR2 + IV_INO_LBLK_*").
    use crate::fscrypt::types::{FSCRYPT_MODE_AES_256_HCTR2, FSCRYPT_MODE_AES_256_XTS};
    for flag in [
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
        FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
    ] {
        let p = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: FSCRYPT_MODE_AES_256_HCTR2,
            flags: flag | 0x02,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        assert!(
            validate_supported(&p, 1, 12, true).is_err(),
            "(XTS, HCTR2) + IV_INO_LBLK must be rejected (flag = {flag:#x})"
        );
    }
}

#[test]
fn validate_supported_accepts_v1_adiantum() {
    use crate::fscrypt::types::FSCRYPT_MODE_ADIANTUM;
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode: FSCRYPT_MODE_ADIANTUM,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: 0x02, // PAD_16
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor([0u8; 8])),
        key_identifier: None,
        nonce: [0u8; 16],
    };
    validate_supported(&p, 42, 12, true).expect("v1 (Adiantum, Adiantum) is supported");
}

#[test]
fn validate_supported_rejects_mismatched_pair() {
    // (XTS contents, Adiantum filenames) — not in SUPPORTED_PAIRS.
    use crate::fscrypt::types::{FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_256_XTS};
    let p = FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode: FSCRYPT_MODE_AES_256_XTS,
        filenames_mode: FSCRYPT_MODE_ADIANTUM,
        flags: 0x02,
        log2_data_unit_size: 0,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
        nonce: [0u8; 16],
    };
    let err = validate_supported(&p, 7, 12, true).unwrap_err();
    assert!(matches!(err, ExtError::UnsupportedFscryptMode { .. }));
}
