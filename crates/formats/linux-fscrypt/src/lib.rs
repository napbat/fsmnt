//! Read-only Linux fscrypt — the kernel's file-based encryption layer.
//!
//! fscrypt encrypts file contents, filenames, and symlink targets
//! per-directory-tree, leaving the filesystem's own metadata in the
//! clear. It lives in `fs/crypto/`, above the filesystem drivers rather
//! than inside any one of them, and ext4, f2fs, UBIFS, and Ceph all
//! call into the same code: an encryption policy written by ext4 and one
//! written by f2fs differ only in where the filesystem stashes the
//! policy xattr and how it frames a symlink. Android keeps `/data`
//! encrypted this way — on ext4 historically, on f2fs for newer devices.
//!
//! So this crate is the format-neutral half: policy contexts (v1 and
//! v2), both KDFs, every content and filename cipher the kernel wires
//! up, the IV derivations, the no-key name encoding, the casefold
//! dirhash, and an in-memory keystore that accepts raw or
//! hardware-wrapped master keys. It knows nothing about inodes beyond
//! the numbers callers hand it, and nothing about xattrs at all. A
//! filesystem parser supplies the glue: read the policy blob out of
//! wherever that filesystem keeps it, fill in [`FsParams`], and call the
//! cipher builders here.
//!
//! What is supported, and the kernel sources each piece mirrors, is
//! catalogued in `docs/fscrypt.md`.
//!
//! # Scope
//!
//! Decryption only. Nothing here writes, and fscrypt is unauthenticated
//! — reading with the wrong key succeeds and yields garbage, so callers
//! that need tamper detection must layer their own integrity check on
//! top.
//!
//! # Example
//!
//! ```rust,ignore
//! use linux_fscrypt::{FscryptKeystore, FscryptMasterKey, FsParams, build_content_cipher, parse_context};
//!
//! let mut keys = FscryptKeystore::default();
//! keys.add_v2(FscryptMasterKey::from_bytes(&master_key_bytes)?);
//!
//! let params = FsParams { block_size: 4096, uuid: fs_uuid, has_stable_inodes: true };
//! let policy = parse_context(&policy_xattr, inode_number)?;
//! let cipher = build_content_cipher(&keys, &policy, inode_number, &params)?;
//! cipher.decrypt_block(&mut block, 0)?;
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod adiantum;
mod content;
mod cts;
mod dirhash;
mod filename;
mod hctr2;
mod keyderive;
mod keystore;
mod nokey;
mod symlink;

pub mod error;
pub mod kdf_v1;
pub mod kdf_v2;
pub mod params;
pub mod policy;
pub mod types;

pub use content::{ContentCipher, build_content_cipher, data_unit_size};
pub use dirhash::{derive_dirhash_key, dirhash_key, inode_hash_low32, siphash24};
pub use error::{FscryptError, Result};
pub use filename::{FilenameCipher, build_filename_cipher};
pub use keystore::{FscryptKeyUnwrapError, FscryptKeyUnwrapper, FscryptKeystore};
pub use nokey::encode_nokey_name;
pub use params::FsParams;
pub use policy::{
    FSCRYPT_POLICY_FLAG_DIRECT_KEY, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
    FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64, parse_context, validate_supported,
};
pub use symlink::{decode_symlink, parse_symlink_ciphertext};
pub use types::{
    FSCRYPT_MAX_KEY_SIZE, FSCRYPT_MIN_KEY_SIZE, FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_AES_128_CBC,
    FSCRYPT_MODE_AES_128_CTS, FSCRYPT_MODE_AES_256_CTS, FSCRYPT_MODE_AES_256_HCTR2,
    FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_SM4_CTS, FSCRYPT_MODE_SM4_XTS, FscryptKeyDescriptor,
    FscryptKeyIdentifier, FscryptMasterKey, FscryptPolicy, FscryptPolicyKind, IvDerivation,
    mode_keysize,
};
