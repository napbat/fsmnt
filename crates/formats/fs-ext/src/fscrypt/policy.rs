//! Parses on-disk `fscrypt_context_v1` (28 bytes) and `fscrypt_context_v2`
//! (40 bytes) into the public `FscryptPolicy` summary.

#![cfg(feature = "fscrypt")]

use crate::error::{ExtError, Result};
use crate::fscrypt::types::{
    FscryptKeyDescriptor, FscryptKeyIdentifier, FscryptPolicy, FscryptPolicyKind,
};

/// Kernel constant FSCRYPT_CONTEXT_V1.
const FSCRYPT_CONTEXT_V1: u8 = 1;
/// Kernel constant FSCRYPT_CONTEXT_V2.
const FSCRYPT_CONTEXT_V2: u8 = 2;

/// Parse a serialized fscrypt context xattr payload (the value of the
/// `encryption.c` xattr) into a [`FscryptPolicy`].
///
/// `inode` is used solely for error context.
pub fn parse_context(bytes: &[u8], inode: u32) -> Result<FscryptPolicy> {
    if bytes.is_empty() {
        return Err(ExtError::InvalidFscryptPolicy {
            inode,
            reason: "empty fscrypt context",
        });
    }
    match bytes[0] {
        FSCRYPT_CONTEXT_V1 => parse_v1(bytes, inode),
        FSCRYPT_CONTEXT_V2 => parse_v2(bytes, inode),
        _ => Err(ExtError::InvalidFscryptPolicy {
            inode,
            reason: "unknown fscrypt context version",
        }),
    }
}

fn parse_v1(bytes: &[u8], inode: u32) -> Result<FscryptPolicy> {
    if bytes.len() != 28 {
        return Err(ExtError::InvalidFscryptPolicy {
            inode,
            reason: "fscrypt v1 context must be exactly 28 bytes",
        });
    }
    let contents_mode = bytes[1];
    let filenames_mode = bytes[2];
    let flags = bytes[3];
    let mut descriptor = [0u8; 8];
    descriptor.copy_from_slice(&bytes[4..12]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[12..28]);
    Ok(FscryptPolicy {
        kind: FscryptPolicyKind::V1,
        contents_mode,
        filenames_mode,
        flags,
        log2_data_unit_size: 0,
        key_descriptor: Some(FscryptKeyDescriptor(descriptor)),
        key_identifier: None,
        nonce,
    })
}

fn parse_v2(bytes: &[u8], inode: u32) -> Result<FscryptPolicy> {
    if bytes.len() != 40 {
        return Err(ExtError::InvalidFscryptPolicy {
            inode,
            reason: "fscrypt v2 context must be exactly 40 bytes",
        });
    }
    let contents_mode = bytes[1];
    let filenames_mode = bytes[2];
    let flags = bytes[3];
    let log2_data_unit_size = bytes[4];
    if bytes[5] != 0 || bytes[6] != 0 || bytes[7] != 0 {
        return Err(ExtError::InvalidFscryptPolicy {
            inode,
            reason: "fscrypt v2 reserved bytes must be zero",
        });
    }
    let mut identifier = [0u8; 16];
    identifier.copy_from_slice(&bytes[8..24]);
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[24..40]);
    Ok(FscryptPolicy {
        kind: FscryptPolicyKind::V2,
        contents_mode,
        filenames_mode,
        flags,
        log2_data_unit_size,
        key_descriptor: None,
        key_identifier: Some(FscryptKeyIdentifier(identifier)),
        nonce,
    })
}

/// `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64` (kernel `include/uapi/linux/fscrypt.h`).
pub(crate) const FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64: u8 = 0x08;
/// `FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32` (kernel `include/uapi/linux/fscrypt.h`).
pub(crate) const FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32: u8 = 0x10;
/// `FSCRYPT_POLICY_FLAG_DIRECT_KEY` (kernel `include/uapi/linux/fscrypt.h`).
pub(crate) const FSCRYPT_POLICY_FLAG_DIRECT_KEY: u8 = 0x04;

/// Single source of truth for which fscrypt policies this crate
/// supports. Called by every decrypt entry point (content key, filename
/// key, symlink decode, dirhash key) immediately after parsing the
/// policy and before any keystore lookup.
///
/// `fs_block_size_log2` is the `log2` of the filesystem block size
/// (e.g. 12 for a 4 KiB block) so the kernel's
/// `fscrypt_supported_v2_policy` upper bound on `log2_data_unit_size`
/// can be mirrored exactly.
///
/// Rejects:
///   - any (contents_mode, filenames_mode) pair not in `SUPPORTED_PAIRS`,
///   - DIRECT_KEY on v1 policies (the upstream kernel allows v1 +
///     DIRECT_KEY; tracium scopes DIRECT_KEY to v2 + Adiantum per
///     issue #154),
///   - DIRECT_KEY with any mode other than Adiantum, or with mismatched
///     contents/filenames modes (mirrors kernel
///     `supported_direct_key_modes`: contents_mode == filenames_mode AND
///     `mode->ivsize >= offsetofend(union fscrypt_iv, nonce)` = 24;
///     of our supported modes only Adiantum has a 32-byte ivsize),
///   - DIRECT_KEY combined with IV_INO_LBLK_64 / IV_INO_LBLK_32
///     (kernel `fscrypt_supported_v2_policy` enforces mutual exclusion
///     across the three "key derivation strategy" flags),
///   - IV_INO_LBLK_* on v1 (kernel rejects, v2-only),
///   - Adiantum + IV_INO_LBLK_* (kernel does not allow this combination),
///   - both IV_INO_LBLK_64 and IV_INO_LBLK_32 set simultaneously
///     (kernel `fscrypt_supported_v2_policy` rejects),
///   - any unknown / reserved bits in `flags` (i.e. anything outside the
///     0x1F mask of PAD<<0 | DIRECT_KEY | IV_INO_LBLK_64 | IV_INO_LBLK_32
///     per `include/uapi/linux/fscrypt.h`),
///   - log2_data_unit_size != 0 on v1 (no on-wire field),
///   - log2_data_unit_size on v2 outside `[SECTOR_SHIFT (9), fs_block_size_log2]`,
///   - IV_INO_LBLK_64 / IV_INO_LBLK_32 combined with a sub-block
///     log2_data_unit_size — both flags reserve only 32 bits for the
///     data-unit index, and the kernel's `fscrypt_max_file_dun_bits >
///     32` guard rejects the policy when the filesystem's max file
///     size in data units could exceed `u32::MAX`. ext4's max file size
///     (≥ 16 TiB) overflows that bound for any sub-block DUS, so we
///     reject both flags conservatively whenever DUS is sub-block.
///
/// v1 + Adiantum is accepted: the upstream kernel
/// (`fscrypt_valid_enc_modes_v1` in `fs/crypto/policy.c`) explicitly
/// whitelists the (Adiantum, Adiantum) pair on v1 policies.
pub fn validate_supported(
    policy: &FscryptPolicy,
    inode_number: u32,
    fs_block_size_log2: u8,
    has_stable_inodes: bool,
) -> Result<()> {
    use crate::fscrypt::types::{
        FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS,
        FSCRYPT_MODE_AES_256_CTS, FSCRYPT_MODE_AES_256_HCTR2, FSCRYPT_MODE_AES_256_XTS,
        FSCRYPT_MODE_SM4_CTS, FSCRYPT_MODE_SM4_XTS,
    };

    const SUPPORTED_PAIRS: &[(u8, u8)] = &[
        (FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS),
        (FSCRYPT_MODE_AES_128_CBC, FSCRYPT_MODE_AES_128_CTS),
        (FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_ADIANTUM),
        // Kernel `fscrypt_valid_enc_modes_v2` (lines 88-90) only — SM4
        // is not listed in `fscrypt_valid_enc_modes_v1`.
        (FSCRYPT_MODE_SM4_XTS, FSCRYPT_MODE_SM4_CTS),
        // Kernel `fscrypt_valid_enc_modes_v2` (lines 84-86) accepts only
        // (AES-256-XTS contents, AES-256-HCTR2 filenames) — HCTR2 is the
        // wide-block filename cipher, paired with the standard XTS
        // contents cipher. v2-only (no v1 fallback for HCTR2 in the
        // kernel: `fscrypt_valid_enc_modes_v1` does not list it).
        (FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_HCTR2),
    ];
    /// Kernel `SECTOR_SHIFT`: minimum `log2_data_unit_size` is 512 B (=9).
    const SECTOR_SHIFT: u8 = 9;

    let unsupported = || ExtError::UnsupportedFscryptMode {
        inode: inode_number,
        contents: policy.contents_mode,
        filenames: policy.filenames_mode,
        flags: policy.flags,
    };

    let pair = (policy.contents_mode, policy.filenames_mode);
    if !SUPPORTED_PAIRS.contains(&pair) {
        return Err(unsupported());
    }

    // Reject unknown / reserved bits. Valid `flags` mask = PAD bits 0..1 |
    // DIRECT_KEY 0x04 | IV_INO_LBLK_64 0x08 | IV_INO_LBLK_32 0x10 → 0x1F.
    const VALID_FLAGS_MASK: u8 = 0x1F;
    if policy.flags & !VALID_FLAGS_MASK != 0 {
        return Err(unsupported());
    }

    let iv64 = policy.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 != 0;
    let iv32 = policy.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 != 0;
    let direct = policy.flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY != 0;

    if direct {
        // Kernel `fscrypt_supported_v2_policy` mutex:
        //   count = !!DIRECT_KEY + !!IV_INO_LBLK_64 + !!IV_INO_LBLK_32;
        //   if (count > 1) return false;
        if iv64 || iv32 {
            return Err(unsupported());
        }
        // Kernel allows v1 + DIRECT_KEY, but issue #154 scopes our
        // implementation to v2 + Adiantum (the only deployed combination
        // on real fscrypt-bearing devices). Fail closed for v1.
        if policy.kind == FscryptPolicyKind::V1 {
            return Err(unsupported());
        }
        // Kernel `supported_direct_key_modes`:
        //   if (contents_mode != filenames_mode) return false;
        //   if (mode->ivsize < offsetofend(union fscrypt_iv, nonce)) return false;
        // offsetofend(..., nonce) = 8 (index) + 16 (nonce) = 24. Of the
        // modes in SUPPORTED_PAIRS, only Adiantum (ivsize = 32) clears
        // that bar; AES-256-XTS (ivsize = 16) does not.
        if policy.contents_mode != policy.filenames_mode {
            return Err(unsupported());
        }
        if policy.contents_mode != FSCRYPT_MODE_ADIANTUM {
            return Err(unsupported());
        }
    }

    // Kernel rejects both flags set simultaneously
    // (`fscrypt_supported_v2_policy`).
    if iv64 && iv32 {
        return Err(unsupported());
    }

    // IV_INO_LBLK_* requires v2 (kernel `fscrypt_supported_v1_policy` is
    // unaware of these flags).
    if (iv64 || iv32) && policy.kind == FscryptPolicyKind::V1 {
        return Err(unsupported());
    }

    // The kernel only wires IV_INO_LBLK_* up for AES-256-XTS contents
    // (`fscrypt_supported_iv_ino_lblk_policy` lines 136-141). Adiantum,
    // AES-128-CBC, and SM4-XTS contents are rejected outright. For
    // (XTS, HCTR2) the kernel allows IV_INO_LBLK_* (contents is XTS),
    // but issue #153 scopes HCTR2 + IV_INO_LBLK_* out as a separate
    // follow-up, so reject it fail-closed here.
    if (iv64 || iv32)
        && (policy.contents_mode == FSCRYPT_MODE_ADIANTUM
            || policy.contents_mode == FSCRYPT_MODE_AES_128_CBC
            || policy.contents_mode == FSCRYPT_MODE_SM4_XTS
            || policy.filenames_mode == FSCRYPT_MODE_AES_256_HCTR2)
    {
        return Err(unsupported());
    }

    // Kernel `supported_iv_ino_lblk_policy` (`fs/crypto/policy.c`):
    //     if (!sb->s_cop->has_stable_inodes ||
    //         !sb->s_cop->has_stable_inodes(sb)) { return false; }
    // ext4 satisfies this hook via `ext4_has_stable_inodes` →
    // `ext4_has_feature_stable_inodes` → `EXT4_FEATURE_COMPAT_STABLE_INODES`
    // (0x0800). On a filesystem without that compat bit, the inode
    // number is not guaranteed to remain constant across operations
    // like `tune2fs -E inode_resize`, so the IV (which mixes the inode
    // number) would decrypt to wrong content for any renumbered inode.
    // Reject fail-closed to avoid silently producing garbage on a
    // corrupt or hand-crafted image.
    if (iv64 || iv32) && !has_stable_inodes {
        return Err(unsupported());
    }

    // SM4 and HCTR2 are v2-only: kernel `fscrypt_valid_enc_modes_v1`
    // does not list either. Mirror that fail-closed even though
    // SUPPORTED_PAIRS is version-agnostic at the pair-membership layer.
    if (policy.contents_mode == FSCRYPT_MODE_SM4_XTS
        || policy.filenames_mode == FSCRYPT_MODE_SM4_CTS
        || policy.contents_mode == FSCRYPT_MODE_AES_256_HCTR2
        || policy.filenames_mode == FSCRYPT_MODE_AES_256_HCTR2)
        && policy.kind == FscryptPolicyKind::V1
    {
        return Err(unsupported());
    }

    // log2_data_unit_size validation (mirrors kernel
    // `fscrypt_supported_v2_policy`).
    if policy.log2_data_unit_size != 0 {
        if policy.kind == FscryptPolicyKind::V1 {
            // v1 has no on-wire log2_data_unit_size field; any non-zero
            // value would be impossible from a parser perspective. Keep
            // the check fail-closed defensively.
            return Err(unsupported());
        }
        if policy.log2_data_unit_size < SECTOR_SHIFT
            || policy.log2_data_unit_size > fs_block_size_log2
        {
            return Err(unsupported());
        }
        // Both IV_INO_LBLK_32 and IV_INO_LBLK_64 encode only 32 bits of
        // the data-unit index in the IV. The kernel guards this via
        // `fscrypt_max_file_dun_bits(sb, du_bits) > 32` (see
        // `fscrypt_supported_v2_policy`); for ext4 the max file size is
        // at least 2^44 bytes, so any sub-block DUS overflows the 32-bit
        // window and the kernel rejects the policy. Mirror that here.
        let sub_block_dus = policy.log2_data_unit_size != fs_block_size_log2;
        if (iv64 || iv32) && sub_block_dus {
            return Err(unsupported());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
}
