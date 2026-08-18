//! HCTR2 length-preserving wide-block decryption for fscrypt v2 +
//! `FSCRYPT_MODE_AES_256_HCTR2` filenames.
//!
//! Mirrors `crypto/hctr2.c` (Linux ≥ 6.0). HCTR2 is built from
//! AES-256 (the inner block cipher), POLYVAL (the universal hash),
//! and XCTR (a CTR-mode keystream variant). The kernel uses a fixed
//! 32-byte tweak length for fscrypt; this module hard-codes the same
//! `TWEAK_SIZE = 32` to match the on-wire format.
//!
//! References:
//!   - Crowley & Biggers, "Length-preserving encryption with HCTR2"
//!     (IACR ePrint 2021/1441).
//!   - `crypto/hctr2.c` (kernel implementation).
//!   - `crypto/xctr.c` (kernel XCTR implementation).
//!
//! This module is private to the `fscrypt` parent module; callers use
//! [`Hctr2Cipher::new`] + [`Hctr2Cipher::decrypt_in_place`] only.

use aes::Aes256;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use polyval::Polyval;
use polyval::universal_hash::UniversalHash;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{FscryptError, Result};

/// HCTR2 master key length: AES-256 → 32 bytes.
pub(crate) const HCTR2_KEY_SIZE: usize = 32;

/// HCTR2 fscrypt tweak length: kernel `crypto/hctr2.c` defines
/// `TWEAK_SIZE = 32` (two POLYVAL blocks). The kernel's HCTR2 instance
/// is hard-wired to this length so the precomputed POLYVAL state for
/// the length-encoding block is fixed.
pub(crate) const HCTR2_TWEAK_SIZE: usize = 32;

/// AES / POLYVAL block size.
const BLOCK: usize = 16;

/// Bits in the fscrypt HCTR2 tweak (= `HCTR2_TWEAK_SIZE * 8`).
const HCTR2_TWEAK_LEN_BITS: u64 = (HCTR2_TWEAK_SIZE as u64) * 8;

/// First u64 of the POLYVAL length-encoding block per kernel
/// `hctr2_hash_tweaklen`:
///     `cpu_to_le64(TWEAK_SIZE * 8 * 2 + 2 + has_remainder)`.
/// `has_remainder = (bulk_len % BLOCK) != 0`, where `bulk_len` is the
/// portion of the message past the first 16 bytes.
const TWEAK_LEN_NO_REM: u64 = HCTR2_TWEAK_LEN_BITS * 2 + 2;
const TWEAK_LEN_REM: u64 = HCTR2_TWEAK_LEN_BITS * 2 + 3;

/// One HCTR2 cipher instance, bound to a single 32-byte AES-256 key.
///
/// The cached values are derived once via the kernel `hctr2_setkey`
/// recipe: `H = E(0)` (POLYVAL key), `L = E([0x01 || zero[15]])`
/// (XCTR IV mask). The AES key itself is stored so per-call AES
/// instances can be reconstructed without holding a `Aes256` value
/// directly (`Aes256` does not implement `Zeroize`).
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Hctr2Cipher {
    aes_key: [u8; HCTR2_KEY_SIZE],
    h: [u8; BLOCK],
    l: [u8; BLOCK],
}

impl Hctr2Cipher {
    /// Build a cipher instance from a 32-byte master key.
    ///
    /// Mirrors kernel `hctr2_setkey`: `H = AES_256_E_K(zero[16])`,
    /// `L = AES_256_E_K([0x01 || zero[15]])`. The same key is used by
    /// the inner AES (E for setup + finish, D for the middle pass) and
    /// by the XCTR keystream.
    pub(crate) fn new(key: &[u8; HCTR2_KEY_SIZE]) -> Self {
        let aes = Aes256::new_from_slice(key).expect("32-byte key is a valid AES-256 key");
        let mut h = [0u8; BLOCK];
        aes.encrypt_block(GenericArray::from_mut_slice(&mut h));
        let mut l = [0u8; BLOCK];
        l[0] = 0x01;
        aes.encrypt_block(GenericArray::from_mut_slice(&mut l));
        Self {
            aes_key: *key,
            h,
            l,
        }
    }

    /// Decrypt one HCTR2 ciphertext block in place. `buf.len()` must
    /// be at least 16 bytes (one AES block); the kernel rejects shorter
    /// inputs the same way.
    ///
    /// HCTR2 decrypt (paper §5, kernel `hctr2_crypt(req, enc=false)`):
    ///   1. `U = C[0..16]`, `V = C[16..]`
    ///   2. `h_TV = POLYVAL(H, len_block || T || V_padded)`
    ///   3. `UU = U ⊕ h_TV`
    ///   4. `MM = D_K(UU)`
    ///   5. `S = MM ⊕ UU ⊕ L`
    ///   6. `N = V ⊕ XCTR(K, S, |V|)`
    ///   7. `h_TN = POLYVAL(H, len_block || T || N_padded)`
    ///   8. `M = MM ⊕ h_TN`
    ///   9. Output: `M || N`
    pub(crate) fn decrypt_in_place(
        &self,
        tweak: &[u8; HCTR2_TWEAK_SIZE],
        buf: &mut [u8],
    ) -> Result<()> {
        if buf.len() < BLOCK {
            return Err(FscryptError::InvalidPolicy {
                inode: 0,
                reason: "HCTR2 ciphertext < 16 bytes",
            });
        }

        let aes =
            Aes256::new_from_slice(&self.aes_key).expect("32-byte key is a valid AES-256 key");
        let n = buf.len();
        let bulk_len = n - BLOCK;
        let has_remainder = !bulk_len.is_multiple_of(BLOCK);

        // Step 2: h_TV over the ciphertext bulk V.
        let mut ciphertext_bulk_hash = polyval_hash(&self.h, has_remainder, tweak, &buf[BLOCK..]);

        // Step 3: UU = U ⊕ h_TV
        let mut uu = [0u8; BLOCK];
        for i in 0..BLOCK {
            uu[i] = buf[i] ^ ciphertext_bulk_hash[i];
        }

        // Step 4: MM = D(UU)
        let mut mm = uu;
        aes.decrypt_block(GenericArray::from_mut_slice(&mut mm));

        // Step 5: S = MM ⊕ UU ⊕ L
        let mut s = Zeroizing::new([0u8; BLOCK]);
        for i in 0..BLOCK {
            s[i] = mm[i] ^ uu[i] ^ self.l[i];
        }

        // Step 6: N = V ⊕ XCTR(K, S, bulk_len). Updates `buf[BLOCK..]`
        // in place from V to N.
        if bulk_len > 0 {
            xctr_in_place(&aes, &s, &mut buf[BLOCK..]);
        }

        // Step 7: h_TN over the now-recovered plaintext bulk N.
        let plaintext_bulk_hash = polyval_hash(&self.h, has_remainder, tweak, &buf[BLOCK..]);

        // Step 8: M = MM ⊕ h_TN. Overwrite the first 16 bytes of buf.
        for i in 0..BLOCK {
            buf[i] = mm[i] ^ plaintext_bulk_hash[i];
        }

        // Scrub locals that held secret intermediates. `s` is already
        // in a `Zeroizing` wrapper.
        ciphertext_bulk_hash.zeroize();
        uu.zeroize();
        mm.zeroize();

        Ok(())
    }
}

/// Compute `POLYVAL(H, len_block || tweak || bulk_padded)` per kernel
/// HCTR2's hash construction.
///
/// `bulk_padded`: full 16-byte blocks of `bulk` are fed verbatim; if
/// `has_remainder` is true the trailing partial block is extended with
/// `0x01 || zero...` (HCTR2's specific padding scheme — note this is
/// **not** zero-padding, so we cannot use `update_padded` from the
/// `universal-hash` crate).
fn polyval_hash(
    h: &[u8; BLOCK],
    has_remainder: bool,
    tweak: &[u8; HCTR2_TWEAK_SIZE],
    bulk: &[u8],
) -> [u8; BLOCK] {
    let key = polyval::Key::from_slice(h);
    // Use the inherent constructor; equivalent to `<Polyval as
    // KeyInit>::new(key)` but avoids importing the universal-hash
    // KeyInit trait just for one call site.
    let mut polyval = Polyval::new_with_init_block(key, 0);

    // Length-encoding block: `cpu_to_le64(TWEAK_SIZE * 8 * 2 + 2 + has_rem) || cpu_to_le64(0)`.
    let mut len_block = [0u8; BLOCK];
    let v = if has_remainder {
        TWEAK_LEN_REM
    } else {
        TWEAK_LEN_NO_REM
    };
    len_block[..8].copy_from_slice(&v.to_le_bytes());
    update_one_block(&mut polyval, &len_block);

    // Tweak: always exactly 32 bytes = 2 POLYVAL blocks.
    update_one_block(
        &mut polyval,
        &tweak[0..BLOCK].try_into().expect("16-byte half"),
    );
    update_one_block(
        &mut polyval,
        &tweak[BLOCK..2 * BLOCK].try_into().expect("16-byte half"),
    );

    // Bulk: full blocks.
    let n_full = bulk.len() / BLOCK;
    for i in 0..n_full {
        let block_bytes: [u8; BLOCK] = bulk[i * BLOCK..(i + 1) * BLOCK]
            .try_into()
            .expect("16-byte chunk");
        update_one_block(&mut polyval, &block_bytes);
    }

    // Bulk remainder: HCTR2 pads the trailing partial block with
    // `0x01 || zero...` (kernel `hctr2_hash_message` uses
    // `padding = { 0x1 }` and updates `BLOCKCIPHER_BLOCK_SIZE -
    // remainder` bytes from it).
    if has_remainder {
        let r = bulk.len() % BLOCK;
        let mut last = [0u8; BLOCK];
        last[..r].copy_from_slice(&bulk[bulk.len() - r..]);
        last[r] = 0x01;
        update_one_block(&mut polyval, &last);
    }

    let tag = polyval.finalize();
    let mut out = [0u8; BLOCK];
    out.copy_from_slice(tag.as_slice());
    out
}

fn update_one_block(polyval: &mut Polyval, block: &[u8; BLOCK]) {
    let ga = GenericArray::clone_from_slice(block);
    polyval.update(&[ga]);
}

/// XCTR in place over `buf`. Per kernel `crypto_xctr_crypt_inplace`:
///   for each 16-byte block i (0-indexed):
///     ctr32 = (i + 1) as little-endian u32
///     `iv_xor` = S; `iv_xor`[0..4] ^= ctr32
///     keystream = `AES_E_K(iv_xor)`
///     `buf_block` ^= keystream
///   For a partial trailing block, same with truncation.
fn xctr_in_place(aes: &Aes256, s: &[u8; BLOCK], buf: &mut [u8]) {
    let n_full = buf.len() / BLOCK;
    let tail = buf.len() % BLOCK;
    for i in 0..n_full {
        let counter =
            u32::try_from(i).expect("one fscrypt data unit cannot contain u32::MAX AES blocks") + 1;
        apply_xctr_block(aes, s, counter, &mut buf[i * BLOCK..(i + 1) * BLOCK]);
    }
    if tail > 0 {
        let start = n_full * BLOCK;
        let mut iv_xor = *s;
        let ctr_le = (u32::try_from(n_full)
            .expect("one fscrypt data unit cannot contain u32::MAX AES blocks")
            + 1)
        .to_le_bytes();
        for j in 0..4 {
            iv_xor[j] ^= ctr_le[j];
        }
        let mut ks = iv_xor;
        aes.encrypt_block(GenericArray::from_mut_slice(&mut ks));
        for j in 0..tail {
            buf[start + j] ^= ks[j];
        }
    }
}

fn apply_xctr_block(aes: &Aes256, s: &[u8; BLOCK], ctr: u32, dst: &mut [u8]) {
    let mut iv_xor = *s;
    let ctr_le = ctr.to_le_bytes();
    for j in 0..4 {
        iv_xor[j] ^= ctr_le[j];
    }
    let mut ks = iv_xor;
    aes.encrypt_block(GenericArray::from_mut_slice(&mut ks));
    for j in 0..BLOCK {
        dst[j] ^= ks[j];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_array_32(s: &str) -> [u8; 32] {
        hex(s).try_into().expect("32-byte hex string")
    }

    /// Kernel `aes_hctr2_tv_template` first AES-256 vector (klen=32,
    /// len=16, `bulk_len=0` → no XCTR call, no remainder). Source:
    /// `crypto/testmgr.h` (linux 6.17).
    #[test]
    fn decrypt_matches_kernel_testmgr_aes256_len16() {
        let key = hex_array_32("9eebb2493c1cf5f46a99c2c4dfb1f4dd752057ea2c4fcdb2a53d7b491eabfd0f");
        let tweak =
            hex_array_32("df63d4abd249f3d8338137607dfa7308d8496d80e82f6254eb0ea9395b457f8a");
        let pt = hex("67c9f23084418e43fbf3b33e79367fe8");
        let ct = hex("2738784716d971352e7edd7e433cb840");
        let mut buf: alloc::vec::Vec<u8> = ct.clone();
        Hctr2Cipher::new(&key)
            .decrypt_in_place(&tweak, &mut buf)
            .unwrap();
        assert_eq!(buf, pt);
    }

    /// Kernel `aes_hctr2_tv_template` AES-256 + len=17 vector
    /// (`bulk_len=1` byte, `has_remainder=1`; exercises POLYVAL HCTR2
    /// padding and the XCTR partial-block tail simultaneously).
    #[test]
    fn decrypt_matches_kernel_testmgr_aes256_len17() {
        let key = hex_array_32("93fa7ee20e67c439e7ca4795689d5e5a7c2619abc6ca6a4c45a69642ae6cffe7");
        let tweak =
            hex_array_32("ea8247953b22a13a6aca244c507e23cd0e50e541b66529d8302300d254a7d656");
        let pt = hex("db1f1fecad836e5d19a5f63bb4935a576f");
        let ct = hex("f1466e9db301f06bc2ac5788486d407268");
        assert_eq!(pt.len(), 17);
        let mut buf: alloc::vec::Vec<u8> = ct.clone();
        Hctr2Cipher::new(&key)
            .decrypt_in_place(&tweak, &mut buf)
            .unwrap();
        assert_eq!(buf, pt);
    }

    /// Kernel `aes_hctr2_tv_template` AES-256 + len=31 vector
    /// (`bulk_len=15`, `has_remainder=1`; exercises XCTR over a 15-byte
    /// trailing tail directly with no full bulk block).
    #[test]
    fn decrypt_matches_kernel_testmgr_aes256_len31() {
        let key = hex_array_32("362b5797f85dcd995f1a5a441d920f27cc16d72b856399d3ba96a1dbd26068da");
        let tweak =
            hex_array_32("ef5869b12c5e9a4724c1b169e112938f433d6d00db5ed8d9129afed9ff2daac4");
        let pt = hex("5ea8681985981223260accdb0a04b9df4db3487bb0e3c819435a4606942df2");
        let ct = hex("dbfdc803d0ecc1febd6437b88243624e7e54a3e224a727e8a4d5b36cb226b4");
        assert_eq!(pt.len(), 31);
        let mut buf: alloc::vec::Vec<u8> = ct.clone();
        Hctr2Cipher::new(&key)
            .decrypt_in_place(&tweak, &mut buf)
            .unwrap();
        assert_eq!(buf, pt);
    }

    #[test]
    fn decrypt_too_short_rejected() {
        let cipher = Hctr2Cipher::new(&[0u8; HCTR2_KEY_SIZE]);
        let tweak = [0u8; HCTR2_TWEAK_SIZE];
        let mut buf = [0u8; 15];
        assert!(matches!(
            cipher.decrypt_in_place(&tweak, &mut buf).unwrap_err(),
            FscryptError::InvalidPolicy { .. }
        ));
    }
}
