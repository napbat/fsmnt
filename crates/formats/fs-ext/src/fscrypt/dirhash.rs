//! Directory-hash key derivation and dispatch for fscrypt v2 + casefold
//! (htree hash version 6 = SipHash-2-4).

#![cfg(feature = "fscrypt")]

use core::hash::Hasher;
use siphasher::sip::SipHasher24;

use crate::fscrypt::kdf_v2;
use crate::fscrypt::types::{FscryptMasterKey, FscryptPolicyKind};

/// Derive the 16-byte `SipHash` key for an encrypted+casefolded directory
/// (v2 only; v1 + casefold is rejected by the kernel).
pub(crate) fn derive_dirhash_key(master_key: &FscryptMasterKey, nonce: &[u8; 16]) -> [u8; 16] {
    use zeroize::Zeroizing;

    // Zeroizing wraps the heap derivation buffer so the bytes are
    // scrubbed once we copy into the caller's [u8; 16] return value.
    let okm: Zeroizing<alloc::vec::Vec<u8>> = Zeroizing::new(kdf_v2::derive(
        master_key,
        kdf_v2::ctx::DIRHASH_KEY,
        nonce,
        16,
    ));
    let mut key = [0u8; 16];
    key.copy_from_slice(&okm);
    key
}

/// SipHash-2-4 of `inode_number` as 8-byte little-endian under
/// `ino_hash_key`. Returns the low 32 bits, mirroring the kernel's
/// `(u32)siphash_1u64(ci_inode->i_ino, ino_hash_key)` used by
/// `IV_INO_LBLK_32` to derive `ci_hashed_ino`.
pub(crate) fn inode_hash_low32(ino_hash_key: &[u8; 16], inode_number: u32) -> u32 {
    siphash24(ino_hash_key, &u64::from(inode_number).to_le_bytes()).1
}

/// Compute the SipHash-2-4 digest of `name` keyed by `key`.
/// Returns (major, minor) — major = top 32 bits, minor = bottom 32 bits.
pub(crate) fn siphash24(key: &[u8; 16], name: &[u8]) -> (u32, u32) {
    let k0 = u64::from_le_bytes(
        key[0..8]
            .try_into()
            .expect("slice of length 8 converts to [u8; 8]"),
    );
    let k1 = u64::from_le_bytes(
        key[8..16]
            .try_into()
            .expect("slice of length 8 converts to [u8; 8]"),
    );
    let mut h = SipHasher24::new_with_keys(k0, k1);
    h.write(name);
    let v = h.finish();
    // Intentional truncation: the 64-bit SipHash digest is split into the
    // (major, minor) 32-bit halves htree expects.
    let major = u32::try_from(v >> 32).expect("v >> 32 fits in u32");
    let minor = u32::try_from(v & 0xFFFF_FFFF).expect("masked low 32 bits fit in u32");
    (major, minor)
}

/// Compute the v2 dirhash SipHash-2-4 key for an encrypted+casefolded
/// directory inode. Returns `Ok(None)` when:
///   - the directory is not encrypted/casefolded,
///   - no fscrypt key is registered for the policy.
///
/// Returns `Err(InvalidFscryptPolicy)` for v1 policies on
/// casefolded directories (the kernel rejects this combination), and
/// `Err(UnsupportedFscryptMode)` via `validate_supported` for any
/// unsupported mode/flag combination.
pub(crate) fn dirhash_key_for_directory<R: crate::io::Read + crate::io::Seek>(
    ext: &crate::ext::Ext,
    fs: &mut R,
    inode: &crate::inode::ExtInode<'_>,
) -> crate::error::Result<Option<[u8; 16]>> {
    let Some(policy) = inode.fscrypt_policy(fs)? else {
        return Ok(None);
    };
    crate::fscrypt::policy::validate_supported(
        &policy,
        inode.inode_number(),
        u8::try_from(ext.block_size.trailing_zeros())
            .expect("a u32 trailing-zero count never exceeds 32"),
        ext.compat
            .contains(crate::feature_flags::CompatFeatures::STABLE_INODES),
    )?;
    if policy.kind != FscryptPolicyKind::V2 {
        return Err(crate::error::ExtError::InvalidFscryptPolicy {
            inode: inode.inode_number(),
            reason: "v1 policies do not support htree-v6 (kernel rejects v1+casefold)",
        });
    }
    let id = policy
        .key_identifier
        .expect("v2 policy has identifier per parse_context");
    // `?` here propagates a wrapped-key unwrap failure (broken TEE
    // adapter, mismatched identifier) loudly. A missing entry (no
    // wrap or unwrap involved) still degrades gracefully to
    // `Ok(None)` so callers can fall back to non-decryptable dirhash.
    let Some(mk) = ext.fscrypt_keys.get_v2(&id)? else {
        return Ok(None);
    };
    Ok(Some(derive_dirhash_key(mk, &policy.nonce)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SipHash-2-4 standard test vector: key=0..15, msg=empty -> 0x726fdb47dd0e0e31
    #[test]
    fn standard_test_vector_empty() {
        let key: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).expect("0..16 fits in u8"));
        let (major, minor) = siphash24(&key, b"");
        assert_eq!(major, 0x726f_db47);
        assert_eq!(minor, 0xdd0e_0e31);
    }

    /// SipHash-2-4: key=0..15, msg=0x00 -> 0x74f839c593dc67fd
    #[test]
    fn standard_test_vector_one_byte() {
        let key: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).expect("0..16 fits in u8"));
        let (major, minor) = siphash24(&key, &[0x00]);
        assert_eq!(major, 0x74f8_39c5);
        assert_eq!(minor, 0x93dc_67fd);
    }

    #[test]
    fn dirhash_key_is_16_bytes_and_deterministic() {
        let mk = FscryptMasterKey::from_array([0xAA; 64]);
        let nonce = [0xBB; 16];
        let k1 = derive_dirhash_key(&mk, &nonce);
        let k2 = derive_dirhash_key(&mk, &nonce);
        assert_eq!(k1, k2);
        let other_nonce = [0xCC; 16];
        let k3 = derive_dirhash_key(&mk, &other_nonce);
        assert_ne!(k1, k3);
    }
}
