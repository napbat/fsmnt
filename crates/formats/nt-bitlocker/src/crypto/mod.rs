pub mod cbc;
/// Elephant diffuser transformations used by legacy CBC+diffuser volumes.
pub mod diffuser;
pub mod xts;

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Internal trait for sector-level decryption dispatch.
///
/// All implementations decrypt **in-place**: the caller fills the buffer with
/// ciphertext and the method overwrites it with plaintext.  No intermediate
/// copies, no allocations.
pub(crate) trait SectorDecryptor: Zeroize + ZeroizeOnDrop {
    fn decrypt_sector_in_place(&self, sector_num: u64, data: &mut [u8]);
}

/// Enum-based sector decryptor dispatch (avoids object safety issues).
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "decryptors remain inline so key-bearing cipher schedules are not separately allocated"
)]
pub enum Decryptor {
    /// AES-CBC sector decryption without the legacy diffuser.
    Cbc(cbc::AesCbcDecryptor),
    /// AES-CBC sector decryption followed by Elephant diffusion.
    CbcDiffuser(cbc::AesCbcDiffuserDecryptor),
    /// AES-XTS sector decryption.
    Xts(xts::AesXtsDecryptor),
}

impl Zeroize for Decryptor {
    fn zeroize(&mut self) {
        match self {
            Self::Cbc(d) => d.zeroize(),
            Self::CbcDiffuser(d) => d.zeroize(),
            Self::Xts(d) => d.zeroize(),
        }
    }
}

impl Drop for Decryptor {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Decryptor {}

impl Decryptor {
    /// Decrypt a single sector in-place.
    ///
    /// `data` must contain the ciphertext on entry; it is overwritten with
    /// plaintext on return.  `sector_num` is the logical sector number used
    /// to derive the per-sector tweak / IV.
    pub fn decrypt_sector_in_place(&self, sector_num: u64, data: &mut [u8]) {
        match self {
            Self::Cbc(d) => d.decrypt_sector_in_place(sector_num, data),
            Self::CbcDiffuser(d) => d.decrypt_sector_in_place(sector_num, data),
            Self::Xts(d) => d.decrypt_sector_in_place(sector_num, data),
        }
    }
}
