//! Read-only `BitLocker` metadata parsing and transparent volume decryption.
//!
//! The crate validates all three FVE metadata copies, identifies the selected
//! encryption method and key protectors, unwraps a volume master key from a
//! supplied credential, and exposes decrypted volume bytes through
//! [`std::io::Read`] and [`std::io::Seek`].
//!
//! `BitLocker` cryptographic keys are held in zeroizing containers where
//! practical. This crate is the workspace's intentionally `std`-only format
//! component because unlocked volumes wrap seekable host readers.

#![forbid(unsafe_code)]

mod crypto;
mod error;
mod keys;
mod metadata;
mod unlock;

pub use crypto::Decryptor;
pub use crypto::cbc::{AesCbcDecryptor, AesCbcDiffuserDecryptor};
pub use crypto::diffuser;
pub use crypto::xts::AesXtsDecryptor;
pub use error::{BitLockerError, MetadataFailure, Result};
pub use keys::bek::BekFile;
pub use keys::password::hash_user_password;
pub use keys::protector::unwrap_aes_ccm;
pub use keys::recovery::parse_recovery_password;
pub use keys::stretch::stretch_key;
pub use keys::{Credential, SecretBytes, UnlockMethod};
pub use metadata::entry::{DatumHeader, DatumIter};
pub use metadata::fve_block::FveBlock;
pub use metadata::header::VolumeHeader;
pub use metadata::vmk::{AesCcmDatum, ExternalKeyDatum, StretchKeyDatum, VmkDatum};
pub use metadata::{
    BitLockerMetadata, BitLockerVolume, BlockStatus, EncryptionMethod, EncryptionState,
    KeyProtectorInfo, MetadataDiagnostics, ProtectorType,
};
pub use unlock::{UnlockError, UnlockedVolume};
