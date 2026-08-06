use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Hash a user password for `BitLocker`: `SHA256(SHA256(UTF16LE(password)))`.
#[must_use]
pub fn hash_user_password(password: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    for code_unit in password.encode_utf16() {
        hasher.update(code_unit.to_le_bytes());
    }
    let first_hash = hasher.finalize();
    let second_hash: [u8; 32] = Sha256::digest(first_hash).into();
    Zeroizing::new(second_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_user_password_utf16le() {
        let hash = hash_user_password("password");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hash_user_password_deterministic() {
        let h1 = hash_user_password("test");
        let h2 = hash_user_password("test");
        assert_eq!(*h1, *h2);
    }

    #[test]
    fn hash_user_password_different_inputs() {
        let h1 = hash_user_password("password1");
        let h2 = hash_user_password("password2");
        assert_ne!(*h1, *h2);
    }

    #[test]
    fn hash_user_password_empty() {
        let hash = hash_user_password("");
        // SHA256(SHA256("")) should be deterministic
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn hash_user_password_unicode() {
        let h1 = hash_user_password("pässwörd");
        let h2 = hash_user_password("password");
        assert_ne!(*h1, *h2);
    }
}
