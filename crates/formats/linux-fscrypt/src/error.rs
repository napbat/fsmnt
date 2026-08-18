//! Failures this crate reports to the filesystem that hosts it.
//!
//! The four variants mirror the four ways an fscrypt read can fail:
//! the on-disk policy is malformed, no master key matches it, a
//! hardware-wrapped key would not unwrap, or the policy names a cipher
//! or flag combination outside the supported matrix. Host filesystems
//! map them onto their own error type at the glue boundary — `fs-ext`
//! turns them into `ExtError::{InvalidFscryptPolicy, MissingFscryptKey,
//! FscryptKeyUnwrapFailed, UnsupportedFscryptMode}`.
//!
//! Every variant carries an inode number for operator context. The
//! crate fills it in wherever the caller supplied one and leaves it
//! zero where the failure is anchored to something other than a single
//! inode (a key-length check at registration time, a keystore unwrap).

use alloc::string::String;

use thiserror::Error;

/// Result type of this crate.
pub type Result<T, E = FscryptError> = core::result::Result<T, E>;

/// Why an fscrypt operation could not produce plaintext.
///
/// Deliberately not `#[non_exhaustive]`: every host has to map the whole
/// set onto its own error type, and a new variant here should break that
/// mapping at compile time rather than fall into a catch-all arm.
#[derive(Debug, Error)]
pub enum FscryptError {
    /// An object's fscrypt policy bytes are malformed or inconsistent.
    #[error("inode {inode} fscrypt policy: {reason}")]
    InvalidPolicy {
        /// Inode carrying the invalid policy, or zero when the failure
        /// is not anchored to one (a key or buffer length check).
        inode: u32,
        /// Description of the policy violation.
        reason: &'static str,
    },
    /// No registered master key matches an object's policy.
    #[error("inode {inode}: missing fscrypt master key (policy {policy_kind}, ref {key_ref})")]
    MissingKey {
        /// Inode whose key lookup failed.
        inode: u32,
        /// Human-readable fscrypt policy version.
        policy_kind: String,
        /// Hexadecimal descriptor or identifier used for lookup.
        key_ref: String,
    },
    /// A hardware-wrapped key was registered for this identifier but the
    /// operator-supplied unwrap callback failed, or the unwrapped key
    /// did not derive the registered identifier.
    ///
    /// `inode` is zero here: the unwrap is keystore-internal and does
    /// not see the calling inode. `key_ref` plus `reason` are the
    /// actionable fields.
    #[error("fscrypt key unwrap failed (policy {policy_kind}, ref {key_ref}): {reason}")]
    KeyUnwrapFailed {
        /// Calling inode, or zero when the failure occurred inside the keystore.
        inode: u32,
        /// Human-readable fscrypt policy version.
        policy_kind: String,
        /// Hexadecimal v2 key identifier used for lookup.
        key_ref: String,
        /// Operator-facing failure returned by the unwrap callback.
        reason: String,
    },
    /// A policy selects a cipher or flag combination this crate does not
    /// implement, or one the kernel itself rejects.
    #[error(
        "inode {inode}: unsupported fscrypt mode (contents={contents}, filenames={filenames}, flags=0x{flags:02x})"
    )]
    UnsupportedMode {
        /// Inode carrying the unsupported policy.
        inode: u32,
        /// Raw content-encryption mode identifier.
        contents: u8,
        /// Raw filename-encryption mode identifier.
        filenames: u8,
        /// Raw fscrypt policy flags.
        flags: u8,
    },
}
