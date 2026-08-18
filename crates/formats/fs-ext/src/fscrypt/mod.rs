//! ext4's half of fscrypt: everything the format-neutral
//! [`linux_fscrypt`] crate cannot know.
//!
//! fscrypt lives above the filesystem drivers in the kernel, and the
//! crypto is identical wherever it is wired up, so it lives in its own
//! crate here too. What is genuinely ext4-specific is small and all of
//! it is in this module: the policy arrives as the `encryption.c`
//! xattr, the stable-inode guarantee `IV_INO_LBLK_*` needs comes from
//! the `STABLE_INODES` compat feature, and the keystore hangs off
//! [`Ext`]. Everything downstream of a parsed [`FscryptPolicy`] —
//! validation, both KDFs, every cipher, the no-key encodings — is the
//! crate's.
//!
//! See `crates/formats/linux-fscrypt/docs/fscrypt.md` for the kernel
//! reference and the supported-mode matrix.

#![cfg(feature = "fscrypt")]

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::feature_flags::CompatFeatures;
use crate::inode::{ExtInode, InodeFlags};

pub(crate) use linux_fscrypt::{
    ContentCipher, FilenameCipher, FscryptKeystore, decode_symlink, encode_nokey_name,
    parse_context, parse_symlink_ciphertext, siphash24,
};

pub use linux_fscrypt::{
    FSCRYPT_MAX_KEY_SIZE, FSCRYPT_MIN_KEY_SIZE, FscryptKeyDescriptor, FscryptKeyIdentifier,
    FscryptKeyUnwrapError, FscryptKeyUnwrapper, FscryptMasterKey, FscryptPolicy, FscryptPolicyKind,
};

use linux_fscrypt::FsParams;

/// Describe this filesystem to the fscrypt crate.
///
/// The stable-inode answer mirrors ext4's `has_stable_inodes` hook
/// (`ext4_has_feature_stable_inodes` → `EXT4_FEATURE_COMPAT_STABLE_INODES`),
/// which kernel `supported_iv_ino_lblk_policy` consults before allowing
/// an `IV_INO_LBLK_*` policy: without the guarantee, renumbering an
/// inode would silently decrypt its blocks to the wrong plaintext.
fn fs_params(ext: &Ext) -> FsParams {
    FsParams {
        block_size: ext.block_size,
        uuid: *ext.uuid(),
        has_stable_inodes: ext.compat.contains(CompatFeatures::STABLE_INODES),
    }
}

/// Build the content cipher for an encrypted inode.
///
/// `inode_xattr_lookup` fetches the raw `encryption.c` xattr value —
/// passed as a closure because the callers that need this sit mid-read
/// and already hold the reader.
pub(crate) fn build_cipher_for_inode<R: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut R,
    inode_number: u32,
    inode_xattr_lookup: impl FnOnce(&mut R) -> Result<alloc::vec::Vec<u8>>,
) -> Result<ContentCipher> {
    let bytes = inode_xattr_lookup(fs)?;
    let policy = parse_context(&bytes, inode_number)?;
    Ok(linux_fscrypt::build_content_cipher(
        &ext.fscrypt_keys,
        &policy,
        inode_number,
        &fs_params(ext),
    )?)
}

/// Build the filename cipher anchoring on `inode_number` — the
/// directory for dirent decryption, the symlink for its target.
pub(crate) fn build_filename_cipher_for_inode(
    ext: &Ext,
    inode_number: u32,
    policy: &FscryptPolicy,
) -> Result<FilenameCipher> {
    Ok(linux_fscrypt::build_filename_cipher(
        &ext.fscrypt_keys,
        policy,
        inode_number,
        &fs_params(ext),
    )?)
}

/// Compute the htree-v6 `SipHash` key for an encrypted casefolded
/// directory, or `Ok(None)` when the inode is not encrypted or no key
/// is registered.
pub(crate) fn dirhash_key_for_directory<R: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut R,
    inode: &ExtInode<'_>,
) -> Result<Option<[u8; 16]>> {
    let Some(policy) = inode.fscrypt_policy(fs)? else {
        return Ok(None);
    };
    Ok(linux_fscrypt::dirhash_key(
        &ext.fscrypt_keys,
        &policy,
        inode.inode_number(),
        &fs_params(ext),
    )?)
}

/// Cached crypto state for a directory iterator.
///
/// Captured once when the iterator is built so that every emitted entry
/// can be decrypted (or forwarded as ciphertext) without re-deriving
/// the filenames key on every step.
pub(crate) enum DirCryptoState {
    /// Directory is plaintext; iterator emits on-disk bytes directly.
    Plaintext,
    /// Directory is encrypted and a key is registered; iterator decrypts
    /// each name via the cipher.
    EncryptedDecryptable {
        /// Filenames cipher derived from the directory's policy.
        cipher: FilenameCipher,
    },
    /// Directory is encrypted but no key is registered. The default API
    /// path errors with `MissingFscryptKey` before iteration starts; the
    /// raw API path forwards the on-disk ciphertext bytes.
    EncryptedMissingKey {
        /// Policy version, for the error the default path raises.
        policy_kind: FscryptPolicyKind,
        /// Hex descriptor or identifier the operator must supply.
        key_ref: alloc::string::String,
    },
}

/// Compute the [`DirCryptoState`] for a directory inode.
pub(crate) fn directory_decryption_state<R: crate::io::Read + crate::io::Seek>(
    ext: &Ext,
    fs: &mut R,
    dir_inode: &ExtInode<'_>,
) -> Result<DirCryptoState> {
    if !dir_inode.flags().contains(InodeFlags::ENCRYPT_FL) {
        return Ok(DirCryptoState::Plaintext);
    }
    let p = dir_inode
        .fscrypt_policy(fs)?
        .ok_or(ExtError::InvalidFscryptPolicy {
            inode: dir_inode.inode_number(),
            reason: "ENCRYPT_FL set but missing context",
        })?;
    // The kernel rejects ENCRYPT_FL+CASEFOLD_FL with v1 policies because
    // there is no v1 path to derive a dirhash key. Reject the
    // combination here so a crafted on-disk image cannot proceed through
    // dirent decryption with v1 keys silently.
    if dir_inode.flags().contains(InodeFlags::CASEFOLD_FL) && p.kind == FscryptPolicyKind::V1 {
        return Err(ExtError::InvalidFscryptPolicy {
            inode: dir_inode.inode_number(),
            reason: "v1 policy on casefolded directory not supported by kernel",
        });
    }
    match build_filename_cipher_for_inode(ext, dir_inode.inode_number(), &p) {
        Ok(cipher) => Ok(DirCryptoState::EncryptedDecryptable { cipher }),
        Err(ExtError::MissingFscryptKey { key_ref, .. }) => {
            Ok(DirCryptoState::EncryptedMissingKey {
                policy_kind: p.kind,
                key_ref,
            })
        }
        Err(e) => Err(e),
    }
}
