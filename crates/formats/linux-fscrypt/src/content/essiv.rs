//! AES-128-CBC-ESSIV support for fscrypt content blocks.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use sha2::{Digest, Sha256};

/// AES-128-CBC-ESSIV cipher state for fscrypt content blocks.
///
/// Per kernel `crypto/essiv.c::essiv_skcipher_setkey`, the inner ECB
/// "salt cipher" is keyed with the **full** 32-byte SHA-256 digest of
/// the content key — i.e. AES-256-ECB, not AES-128-ECB. The standard
/// IV that fscrypt passes through (`union fscrypt_iv` low 16 bytes,
/// per `fscrypt_generate_iv`) is encrypted under that salt cipher to
/// derive the per-block CBC IV; the data unit then CBC-decrypts under
/// the AES-128 content key.
pub(super) struct Aes128CbcEssivCipher {
    cbc: Aes128,
    /// Keyed with `SHA-256(content_key)` (32 bytes → AES-256-ECB).
    essiv_inner: Aes256,
}

impl Aes128CbcEssivCipher {
    pub(super) fn new(content_key: &[u8; 16]) -> Self {
        let salt = Sha256::digest(content_key);
        let essiv_inner =
            Aes256::new_from_slice(&salt).expect("32-byte SHA-256 digest is a valid AES-256 key");
        let cbc = Aes128::new_from_slice(content_key)
            .expect("16-byte content key is a valid AES-128 key");
        Self { cbc, essiv_inner }
    }

    /// Decrypt one fscrypt data unit in place. `unit.len()` must be a
    /// non-zero multiple of 16; `plain_iv` is the kernel's `union
    /// fscrypt_iv` view (low 16 bytes of [`crate::types::IvDerivation::full_iv`]).
    pub(super) fn decrypt_unit(&self, unit: &mut [u8], plain_iv: [u8; 16]) {
        // ESSIV: essiv_iv = AES-ECB(SHA-256(key))(plain_iv).
        let mut essiv_iv = plain_iv;
        self.essiv_inner
            .encrypt_block(GenericArray::from_mut_slice(&mut essiv_iv));
        // Standard CBC decrypt: each ciphertext block ECB-decrypts then
        // XORs with the previous ciphertext (or essiv_iv for the first).
        let mut prev = essiv_iv;
        for chunk in unit.as_chunks_mut::<16>().0 {
            let saved = *chunk;
            self.cbc.decrypt_block(GenericArray::from_mut_slice(chunk));
            for i in 0..16 {
                chunk[i] ^= prev[i];
            }
            prev = saved;
        }
    }
}
