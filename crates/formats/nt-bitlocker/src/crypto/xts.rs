use aes::cipher::KeyInit;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::SectorDecryptor;

/// AES-XTS sector decryptor with pre-expanded key schedule.
///
/// Key expansion happens once at construction.  Each `decrypt_sector_in_place`
/// call only computes the per-sector tweak — no allocations, no key setup.
#[derive(Debug)]
pub struct AesXtsDecryptor {
    inner: XtsInner,
    /// Raw key bytes kept for zeroization on drop.
    raw_key: Vec<u8>,
}

#[expect(clippy::large_enum_variant)]
enum XtsInner {
    Aes128(xts_mode::Xts128<aes::Aes128>),
    Aes256(xts_mode::Xts128<aes::Aes256>),
}

impl std::fmt::Debug for XtsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128(_) => f.write_str("XtsInner::Aes128(...)"),
            Self::Aes256(_) => f.write_str("XtsInner::Aes256(...)"),
        }
    }
}

impl Zeroize for AesXtsDecryptor {
    fn zeroize(&mut self) {
        self.raw_key.zeroize();
    }
}

impl Drop for AesXtsDecryptor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AesXtsDecryptor {}

impl AesXtsDecryptor {
    /// Create a new AES-XTS decryptor.
    ///
    /// Key expansion is performed once here.
    ///
    /// # Errors
    ///
    /// Returns `SectorLayoutError` if key is not 32 or 64 bytes.
    pub fn new(key: Vec<u8>) -> crate::Result<Self> {
        let inner = match key.len() {
            32 => {
                let c1 = aes::Aes128::new(key[..16].into());
                let c2 = aes::Aes128::new(key[16..32].into());
                XtsInner::Aes128(xts_mode::Xts128::new(c1, c2))
            }
            64 => {
                let c1 = aes::Aes256::new(key[..32].into());
                let c2 = aes::Aes256::new(key[32..64].into());
                XtsInner::Aes256(xts_mode::Xts128::new(c1, c2))
            }
            _ => {
                return Err(crate::BitLockerError::SectorLayoutError {
                    detail: "AES-XTS key must be 32 or 64 bytes",
                });
            }
        };
        Ok(Self {
            inner,
            raw_key: key,
        })
    }

    /// Build a 16-byte tweak from the sector number.
    pub(crate) fn sector_tweak(sector_num: u64) -> [u8; 16] {
        let mut tweak = [0u8; 16];
        tweak[..8].copy_from_slice(&sector_num.to_le_bytes());
        tweak
    }
}

impl SectorDecryptor for AesXtsDecryptor {
    fn decrypt_sector_in_place(&self, sector_num: u64, data: &mut [u8]) {
        let tweak = Self::sector_tweak(sector_num);
        match &self.inner {
            XtsInner::Aes128(xts) => xts.decrypt_sector(data, tweak),
            XtsInner::Aes256(xts) => xts.decrypt_sector(data, tweak),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    #[test]
    fn xts_128_round_trip() {
        let key = [0x42u8; 32];
        let plaintext_orig = [0xABu8; 512];
        let tweak = AesXtsDecryptor::sector_tweak(42);

        let cipher1 = aes::Aes128::new(key[..16].into());
        let cipher2 = aes::Aes128::new(key[16..32].into());
        let xts = xts_mode::Xts128::<aes::Aes128>::new(cipher1, cipher2);

        let mut data = plaintext_orig;
        xts.encrypt_sector(&mut data, tweak);
        assert_ne!(data, plaintext_orig);

        let dec = AesXtsDecryptor::new(key.to_vec()).unwrap();
        dec.decrypt_sector_in_place(42, &mut data);
        assert_eq!(data, plaintext_orig);
    }

    #[test]
    fn xts_256_round_trip() {
        let key = [0x42u8; 64];
        let plaintext_orig = [0xCDu8; 512];
        let tweak = AesXtsDecryptor::sector_tweak(99);

        let cipher1 = aes::Aes256::new(key[..32].into());
        let cipher2 = aes::Aes256::new(key[32..64].into());
        let xts = xts_mode::Xts128::<aes::Aes256>::new(cipher1, cipher2);

        let mut data = plaintext_orig;
        xts.encrypt_sector(&mut data, tweak);
        assert_ne!(data, plaintext_orig);

        let dec = AesXtsDecryptor::new(key.to_vec()).unwrap();
        dec.decrypt_sector_in_place(99, &mut data);
        assert_eq!(data, plaintext_orig);
    }

    #[test]
    fn different_sectors_different_ciphertext() {
        let key = vec![0x42u8; 32];
        let dec = AesXtsDecryptor::new(key).unwrap();
        let mut d1 = [0xFFu8; 512];
        let mut d2 = [0xFFu8; 512];
        dec.decrypt_sector_in_place(0, &mut d1);
        dec.decrypt_sector_in_place(1, &mut d2);
        assert_ne!(d1, d2);
    }

    #[test]
    fn invalid_key_size_rejected() {
        let key = vec![0x42u8; 24];
        let err = AesXtsDecryptor::new(key).unwrap_err();
        assert!(matches!(
            err,
            crate::BitLockerError::SectorLayoutError { .. }
        ));
    }
}
