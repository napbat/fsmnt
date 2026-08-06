use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Size of the chain-hash structure used by `BitLocker` key stretching.
///
/// Layout: `updated_hash(32) || password_hash(32) || salt(16) || hash_count(8)`
const CHAIN_HASH_SIZE: usize = 32 + 32 + 16 + 8; // 88 bytes

/// `BitLocker` key stretching: custom iterative SHA-256 chain hash.
///
/// **NOT PBKDF2.** Matches dislocker's `stretch_key()` in `stretch_key.c`:
///
/// ```text
/// struct { updated_hash[32], password_hash[32], salt[16], hash_count: u64 }
/// for count in 0..0x100000:
///     updated_hash = SHA-256(entire 88-byte struct)
///     hash_count += 1
/// return updated_hash
/// ```
///
/// The `password_hash` and `salt` fields are constant throughout; only
/// `updated_hash` and `hash_count` change each iteration.
#[must_use]
pub fn stretch_key(
    initial_hash: &[u8; 32],
    salt: &[u8; 16],
    iterations: u32,
) -> Zeroizing<[u8; 32]> {
    let mut ch = Zeroizing::new([0u8; CHAIN_HASH_SIZE]);

    // ch[0..32]  = updated_hash  (starts zeroed)
    // ch[32..64] = password_hash (constant)
    // ch[64..80] = salt          (constant)
    // ch[80..88] = hash_count    (incremented each iteration)
    ch[32..64].copy_from_slice(initial_hash);
    ch[64..80].copy_from_slice(salt);

    let mut hasher = Sha256::new();
    for count in 0..u64::from(iterations) {
        ch[80..88].copy_from_slice(&count.to_le_bytes());
        hasher.update(&ch[..]);
        let hash = hasher.finalize_reset();
        ch[..32].copy_from_slice(&hash);
    }

    let mut result = Zeroizing::new([0u8; 32]);
    result.copy_from_slice(&ch[..32]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stretch_key_deterministic() {
        let initial_hash = [0x42u8; 32];
        let salt = [0x01u8; 16];
        let k1 = stretch_key(&initial_hash, &salt, 100);
        let k2 = stretch_key(&initial_hash, &salt, 100);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn stretch_key_different_salt_different_result() {
        let initial_hash = [0x42u8; 32];
        let s1 = [0x01u8; 16];
        let s2 = [0x02u8; 16];
        let k1 = stretch_key(&initial_hash, &s1, 100);
        let k2 = stretch_key(&initial_hash, &s2, 100);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn stretch_key_produces_32_bytes() {
        let hash = [0u8; 32];
        let salt = [0u8; 16];
        let key = stretch_key(&hash, &salt, 10);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn stretch_key_different_iterations_different_result() {
        let hash = [0x42u8; 32];
        let salt = [0x01u8; 16];
        let k1 = stretch_key(&hash, &salt, 10);
        let k2 = stretch_key(&hash, &salt, 20);
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn stretch_key_zero_iterations() {
        let hash = [0x42u8; 32];
        let salt = [0x01u8; 16];
        // Zero iterations: updated_hash stays zeroed (no SHA256 calls).
        let key = stretch_key(&hash, &salt, 0);
        assert_eq!(*key, [0u8; 32]);
    }
}
