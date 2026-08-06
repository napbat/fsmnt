use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::SectorDecryptor;

/// AES-CBC sector decryptor with ESSIV IV generation.
///
/// All key expansion and the ESSIV key (`SHA-256(FVEK)`) are computed once at
/// construction.  Per-sector work is just one AES-ECB block encrypt (for the
/// IV) plus the CBC decrypt — no hashing, no key setup, no allocations.
///
/// `Zeroize` / `ZeroizeOnDrop` are implemented manually because the `aes`
/// crate's cipher types don't implement `Zeroize`.  We keep the raw key
/// bytes alongside the expanded schedule so we can zeroize them on drop.
#[derive(Debug)]
pub struct AesCbcDecryptor {
    inner: CbcInner,
    /// Pre-expanded AES-256 key derived from `SHA-256(FVEK)`, used for ESSIV.
    essiv_cipher: aes::Aes256,
    /// Raw key bytes kept for zeroization on drop.
    raw_key: Vec<u8>,
}

/// Holds the pre-expanded CBC key schedule.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "expanded AES schedules remain inline to avoid heap allocation in sector decryption"
)]
enum CbcInner {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

impl Zeroize for AesCbcDecryptor {
    fn zeroize(&mut self) {
        self.raw_key.zeroize();
    }
}

impl Drop for AesCbcDecryptor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AesCbcDecryptor {}

impl AesCbcDecryptor {
    /// Create a new AES-CBC decryptor.
    ///
    /// Key expansion and ESSIV key derivation happen here — once.
    ///
    /// # Errors
    ///
    /// Returns `SectorLayoutError` if key is not 16 or 32 bytes.
    pub fn new(key: Vec<u8>) -> crate::Result<Self> {
        let essiv_hash = Sha256::digest(&key);
        let essiv_cipher = aes::Aes256::new(&essiv_hash);

        let inner = match key.len() {
            16 => CbcInner::Aes128(aes::Aes128::new(key[..16].into())),
            32 => CbcInner::Aes256(aes::Aes256::new(key[..32].into())),
            _ => {
                return Err(crate::BitLockerError::SectorLayoutError {
                    detail: "AES-CBC key must be 16 or 32 bytes",
                });
            }
        };
        Ok(Self {
            inner,
            essiv_cipher,
            raw_key: key,
        })
    }

    /// Compute the ESSIV IV for a given sector number.
    ///
    /// One AES-ECB block encrypt — no hashing, no key expansion.
    fn compute_essiv_iv(&self, sector_num: u64) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&sector_num.to_le_bytes());
        let mut aes_block = aes::Block::from(block);
        self.essiv_cipher.encrypt_block(&mut aes_block);
        aes_block.into()
    }
}

impl SectorDecryptor for AesCbcDecryptor {
    fn decrypt_sector_in_place(&self, sector_num: u64, data: &mut [u8]) {
        let iv = self.compute_essiv_iv(sector_num);
        // Hand-rolled CBC decrypt: walk blocks in reverse so each block's
        // "previous ciphertext" (needed for XOR) is still intact when we
        // reach it.  No key clone, no wrapper allocation.
        cbc_decrypt_in_place(&self.inner, &iv, data);
    }
}

/// CBC-decrypt `data` in-place using the pre-expanded key in `inner`.
///
/// Two-pass approach that enables AES-NI pipelining:
///
/// 1. **Batch ECB decrypt** — save a copy of each ciphertext block, then
///    decrypt all blocks in-place via `decrypt_blocks_mut`.  AES-NI can
///    pipeline 8 blocks per call (~4× throughput vs one-at-a-time).
///
/// 2. **XOR pass** — walk backwards `XORing` each decrypted block with the
///    *original* ciphertext of the previous block (or the IV for block 0).
///
/// The saved ciphertext costs one stack-allocated array per sector (512 bytes
/// for a 512-byte sector), but eliminates all per-block function calls in
/// the decrypt pass.
fn cbc_decrypt_in_place(key: &CbcInner, iv: &[u8; 16], data: &mut [u8]) {
    let n_blocks = data.len() / 16;
    if n_blocks == 0 {
        return;
    }

    // Save original ciphertext for the XOR pass (stack-allocated for
    // typical 512-byte sectors; heap-fallback for larger sector sizes).
    let mut ct_copy = [0u8; 512];
    let ct: &[u8] = if data.len() <= 512 {
        ct_copy[..data.len()].copy_from_slice(data);
        &ct_copy[..data.len()]
    } else {
        // Sector sizes > 512 are rare (4096 at most).  One allocation
        // per sector in this path is acceptable.
        &Box::from(&*data)
    };

    // Pass 1: batch ECB-decrypt all blocks in-place.
    // Process 8 blocks at a time — `decrypt_blocks` pipelines AES-NI
    // rounds across all 8 blocks for ~4× throughput.
    let mut i = 0;
    while i + 8 <= n_blocks {
        let off = i * 16;
        let mut batch: [aes::Block; 8] = Default::default();
        for (j, b) in batch.iter_mut().enumerate() {
            b.copy_from_slice(&data[off + j * 16..off + j * 16 + 16]);
        }
        match key {
            CbcInner::Aes128(c) => c.decrypt_blocks(&mut batch),
            CbcInner::Aes256(c) => c.decrypt_blocks(&mut batch),
        }
        for (j, b) in batch.iter().enumerate() {
            data[off + j * 16..off + j * 16 + 16].copy_from_slice(b);
        }
        i += 8;
    }
    // Remaining blocks (< 8).
    for idx in i..n_blocks {
        let off = idx * 16;
        let mut b = aes::Block::default();
        b.copy_from_slice(&data[off..off + 16]);
        match key {
            CbcInner::Aes128(c) => c.decrypt_block(&mut b),
            CbcInner::Aes256(c) => c.decrypt_block(&mut b),
        }
        data[off..off + 16].copy_from_slice(&b);
    }

    // Pass 2: XOR each decrypted block with the previous ciphertext.
    // Block 0 XORs with the IV; blocks 1..n XOR with ct[i-1].
    for i in (1..n_blocks).rev() {
        let ct_off = (i - 1) * 16;
        let d_off = i * 16;
        for j in 0..16 {
            data[d_off + j] ^= ct[ct_off + j];
        }
    }
    for j in 0..16 {
        data[j] ^= iv[j];
    }
}

/// XOR the per-sector tweak key directly into `data` (in-place, zero alloc).
///
/// Generates AES-ECB(counter) blocks and XORs them into `data` one 16-byte
/// block at a time.  The counter starts at the sector number (LE, 128-bit)
/// and increments for each block.
fn xor_sector_key_in_place(tweak_cipher: &TweakCipher, sector_num: u64, data: &mut [u8]) {
    let mut counter = [0u8; 16];
    counter[..8].copy_from_slice(&sector_num.to_le_bytes());

    for chunk in data.chunks_exact_mut(16) {
        let mut b = aes::Block::from(counter);
        match tweak_cipher {
            TweakCipher::Aes128(c) => c.encrypt_block(&mut b),
            TweakCipher::Aes256(c) => c.encrypt_block(&mut b),
        }
        for (d, s) in chunk.iter_mut().zip(b.iter()) {
            *d ^= s;
        }
        let val = u128::from_le_bytes(counter);
        counter = val.wrapping_add(1).to_le_bytes();
    }
}

/// Pre-expanded tweak key for the Elephant diffuser.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "expanded AES tweak schedules remain inline to avoid per-sector heap indirection"
)]
enum TweakCipher {
    Aes128(aes::Aes128),
    Aes256(aes::Aes256),
}

impl Zeroize for TweakCipher {
    fn zeroize(&mut self) {
        // The expanded key schedule lives inside the aes cipher struct.
        // We can't zeroize it directly, but the raw key bytes are zeroized
        // via AesCbcDiffuserDecryptor's raw_tweak_key field.
    }
}

impl Drop for TweakCipher {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for TweakCipher {}

/// AES-CBC + Elephant diffuser sector decryptor.
///
/// Used for encryption methods 0x8000 (AES-128) and 0x8001 (AES-256).
/// The FVEK is split: first half is the AES-CBC key, second half is the
/// Elephant tweak key.
///
/// All key expansion happens at construction.  Per-sector work:
/// AES-CBC decrypt → Diffuser B → Diffuser A → XOR sector key (all in-place).
#[derive(Debug)]
pub struct AesCbcDiffuserDecryptor {
    cbc: AesCbcDecryptor,
    tweak_cipher: TweakCipher,
    /// Raw tweak key bytes kept for zeroization on drop.
    raw_tweak_key: Vec<u8>,
}

impl Zeroize for AesCbcDiffuserDecryptor {
    fn zeroize(&mut self) {
        self.cbc.zeroize();
        self.raw_tweak_key.zeroize();
    }
}

impl Drop for AesCbcDiffuserDecryptor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AesCbcDiffuserDecryptor {}

impl AesCbcDiffuserDecryptor {
    /// Create a new AES-CBC + Elephant diffuser decryptor.
    ///
    /// # Errors
    ///
    /// Returns `SectorLayoutError` if `cbc_key` is not 16/32 bytes
    /// or `tweak_key` is not 16/32 bytes.
    pub fn new(cbc_key: Vec<u8>, tweak_key: Vec<u8>) -> crate::Result<Self> {
        let tweak_cipher = match tweak_key.len() {
            16 => TweakCipher::Aes128(aes::Aes128::new(tweak_key[..16].into())),
            32 => TweakCipher::Aes256(aes::Aes256::new(tweak_key[..32].into())),
            _ => {
                return Err(crate::BitLockerError::SectorLayoutError {
                    detail: "Elephant tweak key must be 16 or 32 bytes",
                });
            }
        };

        Ok(Self {
            cbc: AesCbcDecryptor::new(cbc_key)?,
            tweak_cipher,
            raw_tweak_key: tweak_key,
        })
    }
}

impl SectorDecryptor for AesCbcDiffuserDecryptor {
    fn decrypt_sector_in_place(&self, sector_num: u64, data: &mut [u8]) {
        // Step 1: AES-CBC decrypt with ESSIV (in-place)
        self.cbc.decrypt_sector_in_place(sector_num, data);
        // Step 2: Diffuser B decrypt (in-place)
        super::diffuser::diffuser_b_decrypt(data);
        // Step 3: Diffuser A decrypt (in-place)
        super::diffuser::diffuser_a_decrypt(data);
        // Step 4: XOR with sector key (in-place, zero alloc)
        xor_sector_key_in_place(&self.tweak_cipher, sector_num, data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn essiv_deterministic() {
        let dec = AesCbcDecryptor::new(vec![0x42u8; 32]).unwrap();
        let iv1 = dec.compute_essiv_iv(0);
        let iv2 = dec.compute_essiv_iv(0);
        assert_eq!(iv1, iv2);
    }

    #[test]
    fn essiv_different_sectors_different_iv() {
        let dec = AesCbcDecryptor::new(vec![0x42u8; 32]).unwrap();
        let iv1 = dec.compute_essiv_iv(0);
        let iv2 = dec.compute_essiv_iv(1);
        assert_ne!(iv1, iv2);
    }

    /// Hand-roll CBC encrypt (forward direction) to test our decrypt.
    fn cbc_encrypt_in_place(key: &CbcInner, iv: &[u8; 16], data: &mut [u8]) {
        let mut prev = *iv;
        for chunk in data.chunks_exact_mut(16) {
            for (d, p) in chunk.iter_mut().zip(prev.iter()) {
                *d ^= p;
            }
            let mut b = aes::Block::default();
            b.copy_from_slice(chunk);
            match key {
                CbcInner::Aes128(c) => c.encrypt_block(&mut b),
                CbcInner::Aes256(c) => c.encrypt_block(&mut b),
            }
            chunk.copy_from_slice(&b);
            prev.copy_from_slice(chunk);
        }
    }

    #[test]
    fn cbc_round_trip_256() {
        let key = CbcInner::Aes256(aes::Aes256::new([0x42u8; 32].as_ref().into()));
        let iv = [0u8; 16];
        let plaintext = [0xABu8; 512];

        let mut data = plaintext;
        cbc_encrypt_in_place(&key, &iv, &mut data);
        assert_ne!(data, plaintext);

        cbc_decrypt_in_place(&key, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn cbc_round_trip_128() {
        let key = CbcInner::Aes128(aes::Aes128::new([0x42u8; 16].as_ref().into()));
        let iv = [0x99u8; 16];
        let plaintext = [0xCDu8; 512];

        let mut data = plaintext;
        cbc_encrypt_in_place(&key, &iv, &mut data);
        assert_ne!(data, plaintext);

        cbc_decrypt_in_place(&key, &iv, &mut data);
        assert_eq!(data, plaintext);
    }

    #[test]
    fn decrypt_sector_produces_output() {
        let key = vec![0x42u8; 32];
        let dec = AesCbcDecryptor::new(key).unwrap();
        let mut data = [0xFFu8; 512];
        dec.decrypt_sector_in_place(0, &mut data);
        assert_ne!(data, [0xFFu8; 512]);
    }

    #[test]
    fn reject_invalid_key_size() {
        let key = vec![0x42u8; 24]; // invalid
        let err = AesCbcDecryptor::new(key).unwrap_err();
        assert!(matches!(
            err,
            crate::BitLockerError::SectorLayoutError { .. }
        ));
    }

    #[test]
    fn xor_sector_key_deterministic() {
        let tc = TweakCipher::Aes256(aes::Aes256::new([0x42u8; 32].as_ref().into()));
        let mut d1 = [0u8; 512];
        let mut d2 = [0u8; 512];
        xor_sector_key_in_place(&tc, 0, &mut d1);
        xor_sector_key_in_place(&tc, 0, &mut d2);
        assert_eq!(d1, d2);
    }

    #[test]
    fn xor_sector_key_different_sectors() {
        let tc = TweakCipher::Aes256(aes::Aes256::new([0x42u8; 32].as_ref().into()));
        let mut d1 = [0u8; 512];
        let mut d2 = [0u8; 512];
        xor_sector_key_in_place(&tc, 0, &mut d1);
        xor_sector_key_in_place(&tc, 1, &mut d2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn diffuser_decryptor_modifies_output() {
        let cbc_key = vec![0x42u8; 32];
        let tweak_key = vec![0x99u8; 32];
        let dec = AesCbcDiffuserDecryptor::new(cbc_key, tweak_key).unwrap();
        let mut data = [0xFFu8; 512];
        dec.decrypt_sector_in_place(0, &mut data);
        assert_ne!(data, [0xFFu8; 512]);
        assert_ne!(data, [0u8; 512]);
    }
}
