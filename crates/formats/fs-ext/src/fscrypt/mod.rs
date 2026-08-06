//! Linux fscrypt v1 / v2 read-only support for ext4.
//!
//! See `crates/fs-ext/docs/fscrypt.md` for the kernel reference and
//! supported-modes scope.

#![cfg(feature = "fscrypt")]

mod adiantum;
pub(crate) mod content;
pub(crate) mod cts;
pub(crate) mod dirhash;
pub(crate) mod filename;
pub(crate) mod hctr2;
pub(crate) mod kdf_v1;
pub(crate) mod kdf_v2;
pub(crate) mod keystore;
pub(crate) mod nokey;
pub(crate) mod policy;
pub(crate) mod symlink;
pub(crate) mod types;

// Re-exported for use within fscrypt submodules; filename.rs imports directly.
#[allow(unused_imports)]
pub(crate) use adiantum::{ADIANTUM_KEY_SIZE, ADIANTUM_TWEAK_SIZE, AdiantumCipher};

pub(crate) use content::ContentCipher;
pub(crate) use dirhash::{dirhash_key_for_directory, siphash24};
pub(crate) use filename::{
    DirCryptoState, FilenameCipher, build_filename_cipher_for_inode, directory_decryption_state,
};

pub use keystore::{FscryptKeyUnwrapError, FscryptKeyUnwrapper};
pub use types::{
    FSCRYPT_MAX_KEY_SIZE, FSCRYPT_MIN_KEY_SIZE, FscryptKeyDescriptor, FscryptKeyIdentifier,
    FscryptMasterKey, FscryptPolicy, FscryptPolicyKind,
};
