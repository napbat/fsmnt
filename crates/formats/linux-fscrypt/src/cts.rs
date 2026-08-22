//! AES-CBC-CTS (CS3) decrypt for fscrypt filename and symlink-target
//! encryption.
//!
//! CS3 (NIST SP 800-38A Addendum) is the kernel default. For inputs
//! whose length is an exact multiple of the AES block size, the last
//! two ciphertext blocks are unconditionally swapped relative to plain
//! CBC. For inputs with a partial trailing block (length > 16, length
//! mod 16 != 0), the ciphertext layout is:
//!
//!   `head_ct || c_partial (tail_len bytes) || c_last_full (16 bytes)`
//!
//! where `c_partial` equals the first `tail_len` bytes of the AES-ECB
//! encryption of the (XOR-with-prev) last full plaintext block, and
//! `c_last_full` is the AES-ECB encryption of the zero-padded partial
//! block `XORed` with that same intermediate. See `fs/crypto/fname.c`
//! `__fname_encrypt` for the kernel's call into `cts(cbc(aes))`.
//!
//! Generic over the underlying AES variant: AES-256-CBC-CTS for
//! `FSCRYPT_MODE_AES_256_CTS` (32-byte key) and AES-128-CBC-CTS for
//! `FSCRYPT_MODE_AES_128_CTS` (16-byte key) share this implementation.

use aes::cipher::consts::U16;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockSizeUser, KeyInit, KeySizeUser};

use crate::error::{FscryptError, Result};

/// Decrypt `ct` with AES-CBC-CTS (CS3) under the AES variant `C`.
///
/// `key` must be exactly `C::key_size()` bytes (16 for AES-128, 32 for
/// AES-256). `iv` is the 16-byte CBC IV. Returns the plaintext, same
/// length as the ciphertext (padding bytes are caller's responsibility
/// to strip). Rejects ciphertext shorter than one AES block.
#[cfg(test)]
pub fn decrypt_cs3<C>(key: &[u8], iv: &[u8; 16], ct: &[u8]) -> Result<alloc::vec::Vec<u8>>
where
    C: BlockDecrypt + KeyInit + BlockSizeUser<BlockSize = U16> + KeySizeUser,
{
    let mut out = alloc::vec::Vec::with_capacity(ct.len());
    decrypt_cs3_into::<C>(key, iv, ct, &mut out)?;
    Ok(out)
}

/// Decrypt `ct` with AES-CBC-CTS (CS3) into reusable storage.
///
/// The output buffer is cleared before use and retains its allocation between
/// calls. It contains the plaintext on success and is empty when input or key
/// validation fails.
///
/// # Errors
///
/// Returns [`FscryptError::InvalidPolicy`] when `ct` is shorter than one AES
/// block or `key` does not match the selected cipher's key size.
pub(crate) fn decrypt_cs3_into<C>(
    key: &[u8],
    iv: &[u8; 16],
    ct: &[u8],
    out: &mut alloc::vec::Vec<u8>,
) -> Result<()>
where
    C: BlockDecrypt + KeyInit + BlockSizeUser<BlockSize = U16> + KeySizeUser,
{
    out.clear();
    if ct.len() < 16 {
        return Err(FscryptError::InvalidPolicy {
            inode: 0,
            reason: "CS3 ciphertext shorter than one AES block",
        });
    }
    let cipher = C::new_from_slice(key).map_err(|_| FscryptError::InvalidPolicy {
        inode: 0,
        reason: "AES-CBC-CTS key length does not match the cipher",
    })?;
    out.extend_from_slice(ct);

    let n = ct.len();
    if n == 16 {
        // Single block: degenerate to plain CBC.
        cbc_decrypt_full_in_place(&cipher, iv, out);
        return Ok(());
    }
    if n.is_multiple_of(16) {
        // Even multiple of 16, > 16: undo the CS3 last-two-block swap,
        // then plain CBC decrypt in the caller's reusable buffer.
        let tail = out.len() - 32;
        // Swap the two trailing 16-byte blocks back to standard CBC order.
        for i in 0..16 {
            out.swap(tail + i, tail + 16 + i);
        }
        cbc_decrypt_full_in_place(&cipher, iv, out);
        return Ok(());
    }
    decrypt_cs3_partial(&cipher, iv, ct, out);
    Ok(())
}

fn cbc_decrypt_full_in_place<C>(cipher: &C, iv: &[u8; 16], buffer: &mut [u8])
where
    C: BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    let mut prev = *iv;
    for block in buffer.as_chunks_mut::<16>().0 {
        let ciphertext = *block;
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        prev = ciphertext;
    }
}

fn decrypt_cs3_partial<C>(cipher: &C, iv: &[u8; 16], ct: &[u8], out: &mut [u8])
where
    C: BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    // Layout: head_ct (multiple of 16) || c_partial (tail_len) || c_last_full (16)
    let n = ct.len();
    let tail_len = n % 16;
    let head_end = n - tail_len - 16;

    // 1) Plain CBC-decrypt the head, recording `prev` for the last full block.
    let mut prev = *iv;
    if head_end > 0 {
        for i in (0..head_end).step_by(16) {
            let ct_blk = &ct[i..i + 16];
            let mut block = [0u8; 16];
            block.copy_from_slice(ct_blk);
            cipher.decrypt_block(GenericArray::from_mut_slice(&mut block));
            for j in 0..16 {
                out[i + j] = block[j] ^ prev[j];
            }
            prev.copy_from_slice(ct_blk);
        }
    }

    let c_partial = &ct[head_end..head_end + tail_len];
    let c_last_full = &ct[head_end + tail_len..];

    // 2) AES-ECB-decrypt c_last_full to obtain `d_last_full = p_pad XOR e_last`,
    //    where p_pad = tail || zero-pad(16 - tail_len) and e_last is the
    //    intermediate block under the kernel's CTS construction.
    let mut d_last_full = [0u8; 16];
    d_last_full.copy_from_slice(c_last_full);
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut d_last_full));

    // 3) Recover the full `e_last`: its first tail_len bytes are exactly
    //    `c_partial` (the partial ciphertext is the truncated e_last from
    //    encrypt), and its remaining bytes are `d_last_full[tail_len..]`
    //    because p_pad's zero suffix means D and e_last agree there.
    let mut e_last = [0u8; 16];
    e_last[..tail_len].copy_from_slice(c_partial);
    e_last[tail_len..].copy_from_slice(&d_last_full[tail_len..]);

    // 4) tail = D[:tail_len] XOR c_partial
    for i in 0..tail_len {
        out[head_end + 16 + i] = d_last_full[i] ^ c_partial[i];
    }

    // 5) AES-ECB-decrypt e_last to get last_full XOR prev, then XOR prev to
    //    recover the last full plaintext block.
    let mut last_full = e_last;
    cipher.decrypt_block(GenericArray::from_mut_slice(&mut last_full));
    for j in 0..16 {
        out[head_end + j] = last_full[j] ^ prev[j];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::{Aes128, Aes256};
    use sm4::Sm4;

    /// AES-256-CBC-CTS (CS3) reference key/iv shared by both AES-256 tests.
    const REFERENCE_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const REFERENCE_IV_HEX: &str = "00000000000000000000000000000000";

    /// 34-byte plaintext (partial-block path; matches openssl
    /// `aes-256-cbc-cts` and pycryptodome CS3 reconstruction).
    const REFERENCE_PT_PARTIAL: &[u8] = b"the quick brown fox jumps over....";
    const REFERENCE_CT_PARTIAL_HEX: &str =
        "0a0e7bd98cd0ed18cf725a18dc2e0d93157dad9ab65d30822fbca2f56770b1cacc50";

    /// 32-byte plaintext (full-block path; CS3 swap of the two trailing
    /// CBC blocks).
    const REFERENCE_PT_FULL: &[u8] = b"abcdefghijklmnopABCDEFGHIJKLMNOP";
    const REFERENCE_CT_FULL_HEX: &str =
        "3e064f3e60b3417b527f8202f9c45ef80b0bfa882c3df2f57aff3fd9601ef4ce";

    /// AES-128-CBC-CTS (CS3) reference vectors, computed via
    /// `cryptography` AES-128-CBC of the zero-padded plaintext under
    /// key = (0..16) and IV = 0, then applying the same CS3
    /// reconstruction (swap last two CT blocks, truncate to PT length).
    const REFERENCE_KEY128_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const REFERENCE_CT128_PARTIAL_HEX: &str =
        "e2228e7dafd51dc06aa04110722be127c607e0c7fd0b2adad14592627ab531e8d098";
    const REFERENCE_CT128_FULL_HEX: &str =
        "fbcfc60bc261dd864166b6233b08a087d25363fc721337648a68f34abef3b405";

    /// SM4-CBC-CTS (CS3) reference vectors, computed via
    /// `cryptography.hazmat.primitives.ciphers.algorithms.SM4` under
    /// the same key (0..16) and zero IV with the same CS3 reconstruction
    /// the AES vectors use. SM4 shares the 16-byte block size of AES, so
    /// the CS3 layout is byte-for-byte identical — only the inner block
    /// cipher differs.
    const REFERENCE_SM4_CT_PARTIAL_HEX: &str =
        "635a64ac6bd4ef3cacd587b5083db8bb422eb28bd0aea2b8b84fc104657c772eaabd";
    const REFERENCE_SM4_CT_FULL_HEX: &str =
        "9acbfa13cc4ea7d3e284fe56d5786cd31da791b129af402a79f7f24bb077fbe5";

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key256_and_iv() -> ([u8; 32], [u8; 16]) {
        let mut key = [0u8; 32];
        key.copy_from_slice(&hex(REFERENCE_KEY_HEX));
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&hex(REFERENCE_IV_HEX));
        (key, iv)
    }

    fn key128_and_iv() -> ([u8; 16], [u8; 16]) {
        let mut key = [0u8; 16];
        key.copy_from_slice(&hex(REFERENCE_KEY128_HEX));
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&hex(REFERENCE_IV_HEX));
        (key, iv)
    }

    #[test]
    fn decrypt_aes256_round_trips_reference_partial_block() {
        let (key, iv) = key256_and_iv();
        let ct = hex(REFERENCE_CT_PARTIAL_HEX);
        let pt = decrypt_cs3::<Aes256>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_PARTIAL);
    }

    #[test]
    fn decrypt_aes256_full_block_multiple_round_trips() {
        let (key, iv) = key256_and_iv();
        let ct = hex(REFERENCE_CT_FULL_HEX);
        let pt = decrypt_cs3::<Aes256>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_FULL);
    }

    #[test]
    fn decrypt_aes128_round_trips_reference_partial_block() {
        let (key, iv) = key128_and_iv();
        let ct = hex(REFERENCE_CT128_PARTIAL_HEX);
        let pt = decrypt_cs3::<Aes128>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_PARTIAL);
    }

    #[test]
    fn decrypt_aes128_full_block_multiple_round_trips() {
        let (key, iv) = key128_and_iv();
        let ct = hex(REFERENCE_CT128_FULL_HEX);
        let pt = decrypt_cs3::<Aes128>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_FULL);
    }

    #[test]
    fn decrypt_sm4_round_trips_reference_partial_block() {
        // SM4 plugs into the same generic CS3 path as AES, with a
        // 16-byte key. The reference vector was computed with the
        // pyca-cryptography SM4 backend under the same construction
        // used for the AES vectors above.
        let (key, iv) = key128_and_iv();
        let ct = hex(REFERENCE_SM4_CT_PARTIAL_HEX);
        let pt = decrypt_cs3::<Sm4>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_PARTIAL);
    }

    #[test]
    fn decrypt_sm4_full_block_multiple_round_trips() {
        let (key, iv) = key128_and_iv();
        let ct = hex(REFERENCE_SM4_CT_FULL_HEX);
        let pt = decrypt_cs3::<Sm4>(&key, &iv, &ct).unwrap();
        assert_eq!(pt, REFERENCE_PT_FULL);
    }

    #[test]
    fn decrypt_too_short_rejected() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        assert!(decrypt_cs3::<Aes256>(&key, &iv, &[0u8; 15]).is_err());
    }

    #[test]
    fn decrypt_wrong_key_size_rejected() {
        // Generic API is type-checked at the cipher level, but a slice
        // of the wrong length for the chosen variant must surface as a
        // structured error rather than a panic.
        let iv = [0u8; 16];
        assert!(decrypt_cs3::<Aes256>(&[0u8; 16], &iv, &[0u8; 16]).is_err());
        assert!(decrypt_cs3::<Aes128>(&[0u8; 32], &iv, &[0u8; 16]).is_err());
    }

    #[test]
    fn decrypt_into_reuses_capacity_for_full_block_ciphertext() {
        let (key, iv) = key256_and_iv();
        let ct = hex(REFERENCE_CT_FULL_HEX);
        let mut out = alloc::vec::Vec::with_capacity(ct.len());
        let allocation = out.as_ptr();

        decrypt_cs3_into::<Aes256>(&key, &iv, &ct, &mut out).unwrap();

        assert_eq!(out, REFERENCE_PT_FULL);
        assert_eq!(out.as_ptr(), allocation);
    }
}
