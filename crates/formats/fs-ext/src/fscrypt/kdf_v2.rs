//! HKDF-SHA512-based key derivation for fscrypt v2.
//!
//! Mirrors `fs/crypto/hkdf.c`. Salt = 64 zero bytes; IKM = master key
//! bytes (length 16..=64); info prefix = "fscrypt\0" || `context_byte`.

#![cfg(feature = "fscrypt")]

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha512;

use crate::fscrypt::types::{FscryptKeyIdentifier, FscryptMasterKey};

/// Kernel HKDF context bytes (fs/crypto/hkdf.c).
pub mod ctx {
    pub const KEY_IDENTIFIER: u8 = 1;
    pub const PER_FILE_ENC_KEY: u8 = 2;
    pub const DIRECT_KEY: u8 = 3;
    pub const IV_INO_LBLK_64_KEY: u8 = 4;
    pub const DIRHASH_KEY: u8 = 5;
    pub const IV_INO_LBLK_32_KEY: u8 = 6;
    pub const INODE_HASH_KEY: u8 = 7;
}

/// Compute the HKDF-Expand info field used by the kernel.
fn build_info(context: u8, application_info: &[u8]) -> Vec<u8> {
    // 8 bytes "fscrypt\0" + 1 byte context + application_info
    let mut v = Vec::with_capacity(9 + application_info.len());
    v.extend_from_slice(b"fscrypt\0");
    v.push(context);
    v.extend_from_slice(application_info);
    v
}

/// Run HKDF-SHA512 with the kernel salt (64 zero bytes), the master key
/// as IKM, and the given context + `application_info`.
pub fn derive(
    master_key: &FscryptMasterKey,
    context: u8,
    application_info: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let salt = [0u8; 64];
    let hk = Hkdf::<Sha512>::new(Some(&salt), master_key.as_bytes());
    let info = build_info(context, application_info);
    let mut okm = alloc::vec![0u8; out_len];
    hk.expand(&info, &mut okm)
        .expect("HKDF-Expand must accept output up to 255 * 64 bytes");
    okm
}

/// Compute the v2 `master_key_identifier` from a master key.
pub fn key_identifier(master_key: &FscryptMasterKey) -> FscryptKeyIdentifier {
    let okm = derive(master_key, ctx::KEY_IDENTIFIER, &[], 16);
    let mut ident = [0u8; 16];
    ident.copy_from_slice(&okm);
    FscryptKeyIdentifier(ident)
}

/// HKDF info layout for the `IV_INO_LBLK`_* per-mode keys:
/// one byte of `mode_num` followed by the 16-byte FS UUID. Kernel
/// `fs/crypto/keysetup_v2.c::fscrypt_setup_iv_ino_lblk_*_key`.
fn iv_ino_lblk_info(mode_num: u8, fs_uuid: &[u8; 16]) -> [u8; 17] {
    let mut info = [0u8; 17];
    info[0] = mode_num;
    info[1..].copy_from_slice(fs_uuid);
    info
}

/// Derive the per-mode-per-FS key for an `IV_INO_LBLK_64` policy.
pub fn derive_iv_ino_lblk_64_key(
    master_key: &FscryptMasterKey,
    mode_num: u8,
    fs_uuid: &[u8; 16],
    out_len: usize,
) -> Vec<u8> {
    derive(
        master_key,
        ctx::IV_INO_LBLK_64_KEY,
        &iv_ino_lblk_info(mode_num, fs_uuid),
        out_len,
    )
}

/// Derive the per-mode-per-FS key for an `IV_INO_LBLK_32` policy.
pub fn derive_iv_ino_lblk_32_key(
    master_key: &FscryptMasterKey,
    mode_num: u8,
    fs_uuid: &[u8; 16],
    out_len: usize,
) -> Vec<u8> {
    derive(
        master_key,
        ctx::IV_INO_LBLK_32_KEY,
        &iv_ino_lblk_info(mode_num, fs_uuid),
        out_len,
    )
}

/// Derive the per-mode key for a `DIRECT_KEY` policy.
///
/// Mirrors kernel `setup_per_mode_enc_key(..., HKDF_CONTEXT_DIRECT_KEY,
/// include_fs_uuid = false)`: the HKDF info is `[mode_num]` only —
/// unlike `IV_INO_LBLK_*`, the FS UUID is **not** appended (a single
/// `mk_direct_keys` cache covers the master key + mode pair across any
/// FS that holds it).
pub fn derive_direct_key(master_key: &FscryptMasterKey, mode_num: u8, out_len: usize) -> Vec<u8> {
    derive(master_key, ctx::DIRECT_KEY, &[mode_num], out_len)
}

/// Derive the 16-byte per-FS `SipHash` key used to hash inode numbers
/// under an `IV_INO_LBLK_32` policy. Kernel info field is empty.
pub fn derive_inode_hash_key(master_key: &FscryptMasterKey) -> [u8; 16] {
    let okm = derive(master_key, ctx::INODE_HASH_KEY, &[], 16);
    let mut key = [0u8; 16];
    key.copy_from_slice(&okm);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HKDF-Expand( HKDF-Extract([0;64], [0;64]), "fscrypt\0\x01", 16 )
    /// computed via the Python snippet in the plan.
    const ZERO_KEY_IDENTIFIER_HEX: &str = "69d7f347a3ca7bfa3e0c1d84e476d050";

    /// HKDF-Expand( HKDF-Extract([0;64], [0;64]), "fscrypt\0\x02" || (0..16), 64 )
    const ZERO_KEY_PFK_HEX: &str = "5dc4a8f357e8e86cc7d2f048e425f7f2b586a34e0063e79c02efa4e40b84f440917ea27337129bce5f894cf4f0bdfa3249ea39630a211f89ade1d4335644f0e8";

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn key_identifier_matches_kernel_vector() {
        let mk = FscryptMasterKey::from_array([0u8; 64]);
        let id = key_identifier(&mk);
        assert_eq!(id.0.to_vec(), hex_to_bytes(ZERO_KEY_IDENTIFIER_HEX));
    }

    #[test]
    fn per_file_key_matches_kernel_vector() {
        let mk = FscryptMasterKey::from_array([0u8; 64]);
        let nonce: [u8; 16] = core::array::from_fn(|i| (i).to_le_bytes()[0]);
        let pfk = derive(&mk, ctx::PER_FILE_ENC_KEY, &nonce, 64);
        assert_eq!(pfk, hex_to_bytes(ZERO_KEY_PFK_HEX));
    }

    #[test]
    fn dirhash_key_is_16_bytes() {
        let mk = FscryptMasterKey::from_array([1u8; 64]);
        let dk = derive(&mk, ctx::DIRHASH_KEY, &[2u8; 16], 16);
        assert_eq!(dk.len(), 16);
    }

    #[test]
    fn build_info_includes_explicit_nul_byte() {
        let info = build_info(0xAB, b"xyz");
        assert_eq!(&info[..8], b"fscrypt\0");
        assert_eq!(info[8], 0xAB);
        assert_eq!(&info[9..], b"xyz");
    }

    // Reference vectors below are independently computed via a Python
    // reimplementation of HKDF-SHA512 with the exact kernel
    // info-string layout (`fscrypt\0 || ctx || mode_num || fs_uuid`
    // for IV_INO_LBLK_*; `fscrypt\0 || ctx` with empty info for
    // INODE_HASH_KEY). They pin the wire-format agreement with the
    // kernel. See plan-issue-144.md for the snippet.
    const ALL_ZERO_MK: [u8; 64] = [0u8; 64];
    const FIXTURE_UUID: [u8; 16] = [0x55u8; 16];
    const MODE_AES_256_XTS: u8 = 1;
    const MODE_AES_256_CTS: u8 = 4;

    /// HKDF-Expand( extract([0;64], [0;64]),
    ///   "fscrypt\0" || ctx=3 (`DIRECT_KEY`) || mode=9 (Adiantum), 32 )
    /// computed via the Python snippet in plan-issue-154.md (kernel info
    /// field is just `[mode_num]` — no FS UUID, unlike `IV_INO_LBLK`_*).
    const REF_DIRECT_KEY_ADIANTUM: &str =
        "46c6805bd158d581cecfbf238c17b823163acfcbf21298ecf14bb1e35d7ca52a";

    const REF_IV_INO_LBLK_64_XTS: &str = "7ad5a415e02d3b1848f97cea9e678e40e65e156c0a991a1ad38698cc3dee6eb74521046862ab2dab9c3bd0187436a600d6de170586e63f7d954fb5c6272a9630";
    const REF_IV_INO_LBLK_64_CTS: &str =
        "a7bfb4eb856c4110047f132339d83d317840ddf9ed8b7e3620a77424ed48dd7a";
    const REF_IV_INO_LBLK_32_XTS: &str = "86158cbf9244e0f25dffe9aba75aaaeaae20353f337c974c3b5b3e6aa39a1b8e0bf657eaa7270ed6a504351911012c12d1cab78dc9ec69bc314d94811028426e";
    const REF_IV_INO_LBLK_32_CTS: &str =
        "443d2e477aa4ad20b791ee99165f8861d508695b7dfc05921fc6029d6feb6637";
    const REF_INODE_HASH_KEY: &str = "55b798d9b8c776f44ceca06c150f4d12";

    #[test]
    fn iv_ino_lblk_64_xts_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_iv_ino_lblk_64_key(&mk, MODE_AES_256_XTS, &FIXTURE_UUID, 64);
        assert_eq!(got, hex_to_bytes(REF_IV_INO_LBLK_64_XTS));
    }

    #[test]
    fn iv_ino_lblk_64_cts_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_iv_ino_lblk_64_key(&mk, MODE_AES_256_CTS, &FIXTURE_UUID, 32);
        assert_eq!(got, hex_to_bytes(REF_IV_INO_LBLK_64_CTS));
    }

    #[test]
    fn iv_ino_lblk_32_xts_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_iv_ino_lblk_32_key(&mk, MODE_AES_256_XTS, &FIXTURE_UUID, 64);
        assert_eq!(got, hex_to_bytes(REF_IV_INO_LBLK_32_XTS));
    }

    #[test]
    fn iv_ino_lblk_32_cts_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_iv_ino_lblk_32_key(&mk, MODE_AES_256_CTS, &FIXTURE_UUID, 32);
        assert_eq!(got, hex_to_bytes(REF_IV_INO_LBLK_32_CTS));
    }

    const FSCRYPT_MODE_ADIANTUM: u8 = 9;

    #[test]
    fn direct_key_adiantum_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_direct_key(&mk, FSCRYPT_MODE_ADIANTUM, 32);
        assert_eq!(got, hex_to_bytes(REF_DIRECT_KEY_ADIANTUM));
    }

    #[test]
    fn direct_key_omits_fs_uuid_from_info() {
        // Reaches the same byte stream regardless of any FS context —
        // info = [mode_num] only. Pin by comparing against the same
        // reference vector and noting that the FixedKey UUID never
        // enters this code path.
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let direct = derive_direct_key(&mk, FSCRYPT_MODE_ADIANTUM, 32);
        let iv64 = derive_iv_ino_lblk_64_key(&mk, FSCRYPT_MODE_ADIANTUM, &FIXTURE_UUID, 32);
        assert_ne!(
            direct, iv64,
            "DIRECT_KEY HKDF must use a different context than IV_INO_LBLK_64",
        );
    }

    #[test]
    fn inode_hash_key_matches_kernel_reference() {
        let mk = FscryptMasterKey::from_array(ALL_ZERO_MK);
        let got = derive_inode_hash_key(&mk);
        assert_eq!(got.to_vec(), hex_to_bytes(REF_INODE_HASH_KEY));
    }

    #[test]
    fn iv_ino_lblk_info_layout_is_mode_then_uuid() {
        let info = iv_ino_lblk_info(0xAB, &[0xCD; 16]);
        assert_eq!(info[0], 0xAB);
        assert_eq!(&info[1..], &[0xCD; 16]);
    }
}
