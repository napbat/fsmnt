//! AES-128-ECB-based key derivation for fscrypt v1.
//!
//! Mirrors `fs/crypto/keysetup_v1.c::derive_key_aes`: AES-128 keyed by
//! the file nonce, used to encrypt the master-key bytes block-by-block.

#![cfg(feature = "fscrypt")]

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};

use crate::error::{ExtError, Result};
use crate::fscrypt::types::FscryptMasterKey;

/// Derive `out_len` bytes per the kernel v1 KDF.
///
/// `out_len` must be a positive multiple of 16, ≤ master_key length.
pub fn derive(
    master_key: &FscryptMasterKey,
    nonce: &[u8; 16],
    out_len: usize,
) -> Result<alloc::vec::Vec<u8>> {
    if out_len == 0 || !out_len.is_multiple_of(16) {
        return Err(ExtError::InvalidFscryptPolicy {
            inode: 0,
            reason: "v1 KDF output length must be a positive multiple of 16",
        });
    }
    if out_len > master_key.as_bytes().len() {
        return Err(ExtError::InvalidFscryptPolicy {
            inode: 0,
            reason: "v1 KDF output length exceeds master key length",
        });
    }
    let cipher = Aes128::new_from_slice(nonce).expect("16-byte nonce is a valid AES-128 key");
    let mut out = master_key.as_bytes()[..out_len].to_vec();
    for chunk in out.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AES-128-ECB(nonce=0..15) over the master key
    /// (sixteen 0x00, then 0x01, then 0x02, then 0x03 bytes), computed
    /// via pycryptodome (see plan T7 Step 1).
    const KERNEL_V1_PFK_HEX: &str = "c6a13b37878f5b826f4f8162a1c8d879c352805754237f311ac0fff4e3e03e78bd862ffb97ad2fb8f8b891f6032f36cbc1a7aba1a23a94065807a08cc8eed06e";

    fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn derive_matches_pycryptodome_reference() {
        let nonce: [u8; 16] = core::array::from_fn(|i| i as u8);
        let mut mk_bytes = [0u8; 64];
        for b in 0..4 {
            for i in 0..16 {
                mk_bytes[b * 16 + i] = b as u8;
            }
        }
        let mk = FscryptMasterKey::from_array(mk_bytes);
        let out = derive(&mk, &nonce, 64).unwrap();
        assert_eq!(out, hex_to_bytes(KERNEL_V1_PFK_HEX));
    }

    #[test]
    fn derive_rejects_zero_length() {
        let mk = FscryptMasterKey::from_array([0u8; 64]);
        assert!(derive(&mk, &[0u8; 16], 0).is_err());
    }

    #[test]
    fn derive_rejects_non_multiple_of_16() {
        let mk = FscryptMasterKey::from_array([0u8; 64]);
        assert!(derive(&mk, &[0u8; 16], 31).is_err());
    }

    #[test]
    fn derive_rejects_oversize() {
        let mk = FscryptMasterKey::from_bytes(&[0u8; 32]).unwrap();
        assert!(derive(&mk, &[0u8; 16], 64).is_err());
    }
}
