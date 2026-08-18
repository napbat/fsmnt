//! Encrypted symlink target decoding.
//!
//! On-disk layout (`struct fscrypt_symlink_data`):
//!     u16 le len;          // size of `encrypted_path`
//!     u8  `encrypted_path`[len];
//!
//! The framing is fscrypt's, not any one filesystem's: the host reads
//! the raw symlink target bytes however it stores them, then hands the
//! whole payload here. This module parses the 2-byte length, takes
//! exactly `len` ciphertext bytes, decrypts via [`crate::FilenameCipher`]
//! (CBC-CTS, Adiantum, or HCTR2 per the policy), and strips the trailing
//! NUL pad.

use crate::error::{FscryptError, Result};

/// Parse the on-disk `fscrypt_symlink_data` length prefix and return a
/// borrow of the ciphertext slice.
///
/// Shared between the decrypt path ([`decode_symlink`]) and the host's
/// no-key presentation path so both apply the same length validation.
/// Mirrors the kernel's `fscrypt_get_symlink` (`fs/crypto/hooks.c`):
/// too-short payload, `cstr.len == 0`, and
/// `cstr.len + sizeof(*sd) > max_size` all surface as `-EUCLEAN`
/// upstream. `inode` is error context only.
///
/// # Errors
///
/// Returns [`FscryptError::InvalidPolicy`] when the payload is shorter
/// than the length prefix, declares a zero length, or declares more
/// ciphertext than `raw` holds.
pub fn parse_symlink_ciphertext(inode: u32, raw: &[u8]) -> Result<&[u8]> {
    if raw.len() < 2 {
        return Err(FscryptError::InvalidPolicy {
            inode,
            reason: "encrypted symlink too short for length prefix",
        });
    }
    let len = u16::from_le_bytes([raw[0], raw[1]]) as usize;
    // Mirrors kernel `fscrypt_get_symlink`: `if (cstr.len == 0) return
    // ERR_PTR(-EUCLEAN);`. Without this guard the new no-key fallback
    // would surface a malformed zero-length payload as a successful
    // 11-byte base64url encoding of `[0u8; 8]`.
    if len == 0 {
        return Err(FscryptError::InvalidPolicy {
            inode,
            reason: "encrypted symlink ciphertext length is zero",
        });
    }
    if 2 + len > raw.len() {
        return Err(FscryptError::InvalidPolicy {
            inode,
            reason: "encrypted symlink length exceeds available bytes",
        });
    }
    Ok(&raw[2..2 + len])
}

/// Decode an encrypted symlink target.
///
/// `raw` is the full on-disk symlink payload (length prefix + ciphertext).
/// `cipher` is the filename cipher built from the derived filenames key and
/// the inode's fscrypt policy.
///
/// # Errors
///
/// Returns [`FscryptError::InvalidPolicy`] for a malformed length prefix
/// (see [`parse_symlink_ciphertext`]) or a ciphertext too short for the
/// cipher.
pub fn decode_symlink(raw: &[u8], cipher: &crate::FilenameCipher) -> Result<alloc::vec::Vec<u8>> {
    let ct = parse_symlink_ciphertext(0, raw)?;
    // NOTE: trailing-NUL strip is owned by FilenameCipher::decrypt_name —
    // do NOT strip again here (was a double-strip risk).
    cipher.decrypt_name(ct)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filename::FilenameCipher;
    use crate::policy::{FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64};
    use crate::types::{
        FSCRYPT_MODE_AES_256_CTS, FSCRYPT_MODE_AES_256_XTS, FscryptKeyIdentifier, FscryptPolicy,
        FscryptPolicyKind, IvDerivation,
    };
    use aes::Aes256;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    /// AES-256-CBC ciphertext of "/etc/passwd\0\0\0\0\0" (16 bytes,
    /// 5 NUL-byte pad) under the 32-byte all-zero key with a zero IV.
    /// For a single 16-byte block, CS3 collapses to plain CBC.
    ///
    /// Computed via:
    ///     openssl enc -aes-256-cbc -nopad -K 00..00 -iv 00..00
    const REFERENCE_TARGET_CT_HEX: &str = "7f1e6072f171d83f4f59dd9fde35aa97";

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn make_aes_cts_cipher(key: [u8; 32]) -> FilenameCipher {
        make_aes_cts_cipher_with_iv(key, 0x02, IvDerivation::PerFileBlockIndex)
    }

    fn make_aes_cts_cipher_with_iv(key: [u8; 32], flags: u8, iv: IvDerivation) -> FilenameCipher {
        let policy = FscryptPolicy {
            kind: FscryptPolicyKind::V2,
            contents_mode: FSCRYPT_MODE_AES_256_XTS,
            filenames_mode: FSCRYPT_MODE_AES_256_CTS,
            flags,
            log2_data_unit_size: 0,
            key_descriptor: None,
            key_identifier: Some(FscryptKeyIdentifier([0u8; 16])),
            nonce: [0u8; 16],
        };
        FilenameCipher::new(&policy, &key, iv).unwrap()
    }

    fn raw_symlink_payload(ct: &[u8]) -> alloc::vec::Vec<u8> {
        let mut raw = alloc::vec::Vec::with_capacity(2 + ct.len());
        raw.extend_from_slice(
            &(u16::try_from(ct.len()).expect("the test fixture value fits in u16")).to_le_bytes(),
        );
        raw.extend_from_slice(ct);
        raw
    }

    fn encrypt_single_cbc_block(key: &[u8; 32], iv: &[u8; 16], pt: &[u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new_from_slice(key).expect("32-byte key valid");
        let mut block = *pt;
        for i in 0..16 {
            block[i] ^= iv[i];
        }
        cipher.encrypt_block(GenericArray::from_mut_slice(&mut block));
        block
    }

    fn padded_reference_target() -> [u8; 16] {
        let mut pt = [0u8; 16];
        pt[..b"/etc/passwd".len()].copy_from_slice(b"/etc/passwd");
        pt
    }

    #[test]
    fn decode_symlink_strips_nul_pad_and_honors_length_prefix() {
        let ct = hex(REFERENCE_TARGET_CT_HEX);
        let mut raw = alloc::vec::Vec::with_capacity(2 + ct.len());
        raw.extend_from_slice(
            &(u16::try_from(ct.len()).expect("the test fixture value fits in u16")).to_le_bytes(),
        );
        raw.extend_from_slice(&ct);

        let cipher = make_aes_cts_cipher([0u8; 32]);
        let pt = decode_symlink(&raw, &cipher).unwrap();
        assert_eq!(pt.as_slice(), b"/etc/passwd");
    }

    #[test]
    fn decode_symlink_uses_iv_ino_lblk_64_filename_iv() {
        let key = [0u8; 32];
        let iv = IvDerivation::InoLblk64 { inode_number: 12 };
        let ct = encrypt_single_cbc_block(&key, &iv.xts_tweak(0), &padded_reference_target());
        let raw = raw_symlink_payload(&ct);

        let cipher =
            make_aes_cts_cipher_with_iv(key, 0x02 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, iv);
        let pt = decode_symlink(&raw, &cipher).unwrap();
        assert_eq!(pt.as_slice(), b"/etc/passwd");
    }

    #[test]
    fn decode_symlink_uses_iv_ino_lblk_32_filename_iv() {
        let key = [0u8; 32];
        let iv = IvDerivation::InoLblk32 {
            hashed_ino: 0x378f_3ff6,
        };
        let ct = encrypt_single_cbc_block(&key, &iv.xts_tweak(0), &padded_reference_target());
        let raw = raw_symlink_payload(&ct);

        let cipher =
            make_aes_cts_cipher_with_iv(key, 0x02 | FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32, iv);
        let pt = decode_symlink(&raw, &cipher).unwrap();
        assert_eq!(pt.as_slice(), b"/etc/passwd");
    }

    #[test]
    fn decode_symlink_rejects_short_input() {
        let cipher = make_aes_cts_cipher([0u8; 32]);
        let err = decode_symlink(&[0x10], &cipher).unwrap_err();
        assert!(matches!(err, FscryptError::InvalidPolicy { .. }));
    }

    /// Mirrors kernel `fscrypt_get_symlink`: `if (cstr.len == 0) return
    /// ERR_PTR(-EUCLEAN);`. Both the decrypt path and the new no-key
    /// fall-back rely on `parse_symlink_ciphertext`, so the
    /// rejection lands in both code paths simultaneously.
    #[test]
    fn parse_symlink_ciphertext_rejects_zero_length() {
        let raw = [0u8, 0u8];
        let err = parse_symlink_ciphertext(13, &raw).unwrap_err();
        assert!(matches!(err, FscryptError::InvalidPolicy { inode: 13, .. }));
    }

    #[test]
    fn decode_symlink_rejects_zero_length_payload() {
        let cipher = make_aes_cts_cipher([0u8; 32]);
        let raw = [0u8, 0u8];
        let err = decode_symlink(&raw, &cipher).unwrap_err();
        assert!(matches!(err, FscryptError::InvalidPolicy { .. }));
    }

    #[test]
    fn decode_symlink_rejects_length_overflow() {
        // Prefix says 32 bytes but we only have 16.
        let mut raw = alloc::vec::Vec::with_capacity(2 + 16);
        raw.extend_from_slice(&32u16.to_le_bytes());
        raw.extend_from_slice(&[0u8; 16]);
        let cipher = make_aes_cts_cipher([0u8; 32]);
        let err = decode_symlink(&raw, &cipher).unwrap_err();
        assert!(matches!(err, FscryptError::InvalidPolicy { .. }));
    }
}
