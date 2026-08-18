//! The one place a master key becomes a per-object key and an IV.
//!
//! Contents and filenames follow the same three-branch derivation and
//! differ only in which mode byte they feed it, so both cipher builders
//! call [`derive_file_key`] and pass `policy.contents_mode` or
//! `policy.filenames_mode`. Callers must have run
//! [`crate::policy::validate_supported`] first — the `expect`s below
//! rest on the guarantees it establishes.

use alloc::string::String;
use alloc::vec::Vec;

use zeroize::Zeroizing;

use crate::error::{FscryptError, Result};
use crate::keystore::FscryptKeystore;
use crate::params::FsParams;
use crate::policy::{
    FSCRYPT_POLICY_FLAG_DIRECT_KEY, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
    FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
};
use crate::types::{FscryptPolicy, FscryptPolicyKind, IvDerivation, mode_keysize};
use crate::{dirhash, kdf_v1, kdf_v2};

/// Derive the key and IV strategy for one object under `policy`.
///
/// `mode` is the policy's `contents_mode` or `filenames_mode` — the
/// derivation is otherwise identical, matching the kernel, which runs
/// both through the same `fscrypt_setup_v1_file_key` /
/// `fscrypt_setup_v2_file_key` paths.
///
/// `inode_number` anchors the object: for `IV_INO_LBLK_*` it feeds the
/// IV, and everywhere else it is error context only.
pub(crate) fn derive_file_key(
    keys: &FscryptKeystore,
    policy: &FscryptPolicy,
    inode_number: u32,
    params: &FsParams,
    mode: u8,
) -> Result<(Zeroizing<Vec<u8>>, IvDerivation)> {
    // `validate_supported` rejects any mode outside SUPPORTED_PAIRS, so
    // `mode_keysize` is guaranteed to answer here. The length check on
    // the derived buffer happens in the cipher constructor.
    let key_size = mode_keysize(mode).expect("validate_supported guarantees a known mode");

    let iv64 = policy.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 != 0;
    let iv32 = policy.flags & FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32 != 0;
    let direct = policy.flags & FSCRYPT_POLICY_FLAG_DIRECT_KEY != 0;

    // The derivation buffer lives in `Zeroizing` so it is scrubbed when
    // the caller drops it, whether or not the cipher constructor
    // succeeded in copying the bytes into its own fixed-size state.
    if direct {
        // `validate_supported` has restricted DIRECT_KEY to v2 +
        // (Adiantum, Adiantum). Mirror kernel
        // `setup_per_mode_enc_key(HKDF_CONTEXT_DIRECT_KEY,
        // include_fs_uuid=false)`: HKDF info = [mode_num] only, no FS
        // UUID. The per-file nonce enters via the IV
        // (`fscrypt_generate_iv` writes ci_nonce into bytes 8..24),
        // not the key derivation.
        let id = policy.key_identifier.expect("v2 policy carries identifier");
        let mk = keys
            .get_v2(&id)?
            .ok_or_else(|| missing_key(inode_number, policy, &id.0))?;
        let key_bytes = kdf_v2::derive_direct_key(mk, mode, key_size);
        let iv = IvDerivation::DirectKey {
            nonce: policy.nonce,
        };
        return Ok((Zeroizing::new(key_bytes), iv));
    }

    if iv64 || iv32 {
        // v2 is guaranteed by `validate_supported` for either flag. Look
        // up the master key by identifier and derive a per-mode-per-FS
        // key whose HKDF info is `mode_num || fs_uuid`.
        let id = policy.key_identifier.expect("v2 policy carries identifier");
        let mk = keys
            .get_v2(&id)?
            .ok_or_else(|| missing_key(inode_number, policy, &id.0))?;
        let key_bytes = if iv64 {
            kdf_v2::derive_iv_ino_lblk_64_key(mk, mode, &params.uuid, key_size)
        } else {
            kdf_v2::derive_iv_ino_lblk_32_key(mk, mode, &params.uuid, key_size)
        };
        let iv = if iv64 {
            IvDerivation::InoLblk64 { inode_number }
        } else {
            let ino_hash_key = kdf_v2::derive_inode_hash_key(mk);
            let hashed_ino = dirhash::inode_hash_low32(&ino_hash_key, inode_number);
            IvDerivation::InoLblk32 { hashed_ino }
        };
        return Ok((Zeroizing::new(key_bytes), iv));
    }

    let key_bytes = match policy.kind {
        FscryptPolicyKind::V1 => {
            let desc = policy.key_descriptor.expect("v1 policy carries descriptor");
            let mk = keys
                .get_v1(desc)
                .ok_or_else(|| missing_key(inode_number, policy, &desc.0))?;
            kdf_v1::derive(mk, &policy.nonce, key_size)?
        }
        FscryptPolicyKind::V2 => {
            let id = policy.key_identifier.expect("v2 policy carries identifier");
            let mk = keys
                .get_v2(&id)?
                .ok_or_else(|| missing_key(inode_number, policy, &id.0))?;
            kdf_v2::derive(mk, kdf_v2::ctx::PER_FILE_ENC_KEY, &policy.nonce, key_size)
        }
    };
    Ok((Zeroizing::new(key_bytes), IvDerivation::PerFileBlockIndex))
}

/// Build the "no key registered" error for a descriptor or identifier.
fn missing_key(inode: u32, policy: &FscryptPolicy, key_ref: &[u8]) -> FscryptError {
    FscryptError::MissingKey {
        inode,
        policy_kind: alloc::format!("{:?}", policy.kind),
        key_ref: hex(key_ref),
    }
}

/// Lowercase hex, the form every `key_ref` in this crate's errors takes.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02x}").expect("string write infallible");
    }
    s
}
