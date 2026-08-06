use crate::{BitLockerError, Result};
use zeroize::Zeroizing;

/// Unwrap a key encrypted with AES-CCM (16-byte MAC tag, 12-byte nonce).
///
/// The `wrapped` input must be `encrypted_data || mac(16)` — the caller is
/// responsible for reordering from the on-disk format (`mac(16) || encrypted_data`).
///
/// # Errors
///
/// Returns `KeyUnwrapFailed` if authentication fails (wrong key or corrupt data).
/// Returns `InvalidCredentialFormat` if key or nonce sizes are invalid.
pub fn unwrap_aes_ccm(kek: &[u8], nonce: &[u8; 12], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    use ccm::aead::{Aead, KeyInit};

    type Aes128Ccm16 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U12>;
    type Aes256Ccm16 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U12>;

    let plaintext = match kek.len() {
        16 => Aes128Ccm16::new(kek.into())
            .decrypt(nonce.into(), wrapped)
            .map_err(|_| BitLockerError::KeyUnwrapFailed)?,
        32 => Aes256Ccm16::new(kek.into())
            .decrypt(nonce.into(), wrapped)
            .map_err(|_| BitLockerError::KeyUnwrapFailed)?,
        _ => {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "AES-CCM key must be 16 or 32 bytes",
            });
        }
    };

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ccm::aead::{Aead, KeyInit};

    type Aes256Ccm16 = ccm::Ccm<aes::Aes256, ccm::consts::U16, ccm::consts::U12>;

    #[test]
    fn unwrap_aes_ccm_round_trip() {
        let kek = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext_key = [0xABu8; 32];

        let cipher = Aes256Ccm16::new((&kek).into());
        let wrapped = cipher
            .encrypt((&nonce).into(), plaintext_key.as_ref())
            .unwrap();

        let unwrapped = unwrap_aes_ccm(&kek, &nonce, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &plaintext_key);
    }

    #[test]
    fn unwrap_aes_ccm_wrong_key() {
        let kek = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0xABu8; 32];
        let cipher = Aes256Ccm16::new((&kek).into());
        let wrapped = cipher.encrypt((&nonce).into(), plaintext.as_ref()).unwrap();

        let wrong_kek = [0x99u8; 32];
        let err = unwrap_aes_ccm(&wrong_kek, &nonce, &wrapped).unwrap_err();
        assert!(matches!(err, BitLockerError::KeyUnwrapFailed));
    }

    #[test]
    fn unwrap_aes_ccm_bad_key_size() {
        let kek = [0x42u8; 24]; // neither 16 nor 32
        let nonce = [0u8; 12];
        let wrapped = [0u8; 48];
        let err = unwrap_aes_ccm(&kek, &nonce, &wrapped).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn unwrap_aes_ccm_128_round_trip() {
        type Aes128Ccm16 = ccm::Ccm<aes::Aes128, ccm::consts::U16, ccm::consts::U12>;

        let kek = [0x42u8; 16];
        let nonce = [0u8; 12];
        let plaintext_key = [0xCDu8; 16];

        let cipher = Aes128Ccm16::new((&kek).into());
        let wrapped = cipher
            .encrypt((&nonce).into(), plaintext_key.as_ref())
            .unwrap();

        let unwrapped = unwrap_aes_ccm(&kek, &nonce, &wrapped).unwrap();
        assert_eq!(&*unwrapped, &plaintext_key);
    }
}
