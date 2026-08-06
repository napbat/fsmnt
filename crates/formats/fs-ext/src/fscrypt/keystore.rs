//! In-memory master-key store hung off `Ext`.
//!
//! Keys are added explicitly via `Ext::add_fscrypt_v1_key` /
//! `add_fscrypt_v2_key` (raw paths), or via
//! `Ext::add_fscrypt_v2_wrapped_key` (hardware-wrapped path that
//! defers the unwrap to an operator-supplied callback). There is no
//! auto-discovery; an operator supplies keys out-of-band.

#![cfg(feature = "fscrypt")]

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::OnceCell;

use zeroize::Zeroizing;

use crate::error::{ExtError, Result};
use crate::fscrypt::kdf_v2;
use crate::fscrypt::types::{
    FscryptKeyDescriptor, FscryptKeyIdentifier, FscryptMasterKey, FscryptPolicyKind,
};

/// Operator-supplied unwrap callback for hardware-wrapped fscrypt
/// master keys. Real implementations bind to a TEE / Keymaster /
/// Keymint adapter; tests can stub with a synthetic transformation
/// (e.g. XOR pad) for plumbing coverage.
///
/// `unwrap_key` is invoked at most once per registered key per session
/// — the keystore caches the unwrapped bytes after the first lookup
/// and returns the cached value on subsequent calls.
///
/// `Send + Sync` are required because [`crate::Ext`] is part of the
/// `agent-core` `TargetFilesystem: Send` contract; the trait object
/// lives inside the keystore which lives inside `Ext`. Real TEE
/// adapters are typically stateless wrappers around an OS handle and
/// satisfy these bounds trivially.
pub trait FscryptKeyUnwrapper: Send + Sync {
    /// Convert a wrapped blob into the raw fscrypt master-key bytes.
    /// Errors surface to the caller as
    /// [`ExtError::FscryptKeyUnwrapFailed`] with the supplied reason.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined [`FscryptKeyUnwrapError`] when the
    /// wrapped blob cannot be authenticated or unwrapped.
    fn unwrap_key(
        &self,
        wrapped: &[u8],
    ) -> core::result::Result<FscryptMasterKey, FscryptKeyUnwrapError>;
}

/// Reason a [`FscryptKeyUnwrapper`] failed to recover the master key.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct FscryptKeyUnwrapError {
    /// Operator-facing explanation returned by the unwrap implementation.
    pub reason: String,
}

impl FscryptKeyUnwrapError {
    /// Creates an unwrap failure with the supplied operator-facing reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// One v2 keystore entry: either a raw master key (the legacy path
/// from `add_fscrypt_v2_key`) or a wrapped blob plus its unwrapper
/// (the new path from `add_fscrypt_v2_wrapped_key`).
enum FscryptV2Entry {
    Raw(FscryptMasterKey),
    Wrapped {
        wrapped_blob: Zeroizing<Vec<u8>>,
        unwrapper: Box<dyn FscryptKeyUnwrapper>,
        // `core::cell::OnceCell` is single-threaded, matching the
        // existing `&Ext` access pattern. Lazy init: empty until the
        // first `get_v2(identifier)` triggers the unwrap; once set,
        // subsequent lookups return the cached `&FscryptMasterKey`
        // directly. ZeroizeOnDrop on `FscryptMasterKey` scrubs the
        // bytes when the entry (and the keystore) drops.
        cached: OnceCell<FscryptMasterKey>,
    },
}

#[derive(Default)]
pub(crate) struct FscryptKeystore {
    v1: BTreeMap<FscryptKeyDescriptor, FscryptMasterKey>,
    v2: BTreeMap<FscryptKeyIdentifier, FscryptV2Entry>,
}

impl core::fmt::Debug for FscryptKeystore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FscryptKeystore")
            .field("v1_keys", &self.v1.len())
            .field("v2_keys", &self.v2.len())
            .finish()
    }
}

impl FscryptKeystore {
    pub(crate) fn add_v1(&mut self, descriptor: FscryptKeyDescriptor, key: FscryptMasterKey) {
        self.v1.insert(descriptor, key);
    }

    pub(crate) fn add_v2(&mut self, key: FscryptMasterKey) -> FscryptKeyIdentifier {
        let id = kdf_v2::key_identifier(&key);
        self.v2.insert(id, FscryptV2Entry::Raw(key));
        id
    }

    /// Register a hardware-wrapped v2 master-key blob with an explicit
    /// unwrap callback. The unwrapped key bytes never enter the
    /// keystore until a lookup against `identifier` triggers the first
    /// unwrap; the unwrapped bytes are cached for subsequent lookups
    /// and zeroized when the keystore is dropped.
    pub(crate) fn add_v2_wrapped(
        &mut self,
        identifier: FscryptKeyIdentifier,
        wrapped_blob: Vec<u8>,
        unwrapper: Box<dyn FscryptKeyUnwrapper>,
    ) {
        self.v2.insert(
            identifier,
            FscryptV2Entry::Wrapped {
                wrapped_blob: Zeroizing::new(wrapped_blob),
                unwrapper,
                cached: OnceCell::new(),
            },
        );
    }

    pub(crate) fn get_v1(&self, descriptor: FscryptKeyDescriptor) -> Option<&FscryptMasterKey> {
        self.v1.get(&descriptor)
    }

    /// Look up a v2 master key by identifier. Returns:
    ///   - `Ok(Some(&key))` for a raw entry, or for a wrapped entry
    ///     where the unwrap callback succeeded and the unwrapped key
    ///     derives the registered identifier.
    ///   - `Ok(None)` when no entry is registered for `identifier`.
    ///   - `Err(FscryptKeyUnwrapFailed)` when a wrapped entry's
    ///     unwrap callback errored or returned a key whose derived
    ///     identifier doesn't match the registered one.
    ///
    /// Callers map `Ok(None)` to [`ExtError::MissingFscryptKey`] (no
    /// key registered at all) and propagate the `Err` straight through.
    pub(crate) fn get_v2(
        &self,
        identifier: &FscryptKeyIdentifier,
    ) -> Result<Option<&FscryptMasterKey>> {
        let Some(entry) = self.v2.get(identifier) else {
            return Ok(None);
        };
        match entry {
            FscryptV2Entry::Raw(k) => Ok(Some(k)),
            FscryptV2Entry::Wrapped {
                wrapped_blob,
                unwrapper,
                cached,
            } => {
                if cached.get().is_none() {
                    let unwrapped = unwrapper.unwrap_key(wrapped_blob).map_err(|e| {
                        ExtError::FscryptKeyUnwrapFailed {
                            inode: 0,
                            policy_kind: alloc::format!("{:?}", FscryptPolicyKind::V2),
                            key_ref: hex_id(identifier),
                            reason: e.reason,
                        }
                    })?;
                    // Defensive: the unwrapped key must derive the
                    // registered identifier (kernel HKDF context
                    // KEY_IDENTIFIER). Catches operator misconfiguration
                    // (wrong identifier, swapped wrapped blobs, etc.)
                    // before it surfaces as garbled plaintext, since
                    // fscrypt is unauthenticated.
                    let derived = kdf_v2::key_identifier(&unwrapped);
                    if &derived != identifier {
                        return Err(ExtError::FscryptKeyUnwrapFailed {
                            inode: 0,
                            policy_kind: alloc::format!("{:?}", FscryptPolicyKind::V2),
                            key_ref: hex_id(identifier),
                            reason: alloc::format!(
                                "unwrapped key derives identifier {} which does not match registered {}",
                                hex_id(&derived),
                                hex_id(identifier),
                            ),
                        });
                    }
                    let _ = cached.set(unwrapped);
                }
                Ok(cached.get())
            }
        }
    }

    pub(crate) fn iter_v1(&self) -> impl Iterator<Item = FscryptKeyDescriptor> + '_ {
        self.v1.keys().copied()
    }

    pub(crate) fn iter_v2(&self) -> impl Iterator<Item = FscryptKeyIdentifier> + '_ {
        self.v2.keys().copied()
    }
}

fn hex_id(id: &FscryptKeyIdentifier) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(id.0.len() * 2);
    for b in id.0 {
        write!(&mut s, "{b:02x}").expect("string write infallible");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_v1_then_lookup_round_trips() {
        let mut store = FscryptKeystore::default();
        let desc = FscryptKeyDescriptor([0x77; 8]);
        let key = FscryptMasterKey::from_array([0xEE; 64]);
        store.add_v1(desc, key.clone());
        assert_eq!(
            store.get_v1(desc).map(|k| k.as_bytes() == key.as_bytes()),
            Some(true)
        );
    }

    #[test]
    fn add_v2_returns_identifier_and_round_trips() {
        let mut store = FscryptKeystore::default();
        let key = FscryptMasterKey::from_array([0xEE; 64]);
        let id = store.add_v2(key.clone());
        assert_eq!(id, kdf_v2::key_identifier(&key));
        assert_eq!(
            store
                .get_v2(&id)
                .unwrap()
                .map(|k| k.as_bytes() == key.as_bytes()),
            Some(true)
        );
    }

    #[test]
    fn iter_v1_lists_registered_descriptors() {
        let mut store = FscryptKeystore::default();
        store.add_v1(
            FscryptKeyDescriptor([1; 8]),
            FscryptMasterKey::from_array([0; 64]),
        );
        store.add_v1(
            FscryptKeyDescriptor([2; 8]),
            FscryptMasterKey::from_array([0; 64]),
        );
        let mut got: alloc::vec::Vec<_> = store.iter_v1().collect();
        got.sort_by_key(|d| d.0);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, [1; 8]);
        assert_eq!(got[1].0, [2; 8]);
    }

    /// Test stub: returns the wrapped bytes XOR'd against `pad` as the
    /// unwrapped key. Useful for plumbing tests without dragging in a
    /// real TEE adapter.
    struct XorUnwrapper {
        pad: u8,
    }

    impl FscryptKeyUnwrapper for XorUnwrapper {
        fn unwrap_key(
            &self,
            wrapped: &[u8],
        ) -> core::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
            let unwrapped: Vec<u8> = wrapped.iter().map(|b| b ^ self.pad).collect();
            FscryptMasterKey::from_bytes(&unwrapped)
                .map_err(|e| FscryptKeyUnwrapError::new(alloc::format!("{e:?}")))
        }
    }

    /// Failing unwrapper for negative tests.
    struct ErrorUnwrapper;
    impl FscryptKeyUnwrapper for ErrorUnwrapper {
        fn unwrap_key(
            &self,
            _: &[u8],
        ) -> core::result::Result<FscryptMasterKey, FscryptKeyUnwrapError> {
            Err(FscryptKeyUnwrapError::new("simulated TEE failure"))
        }
    }

    fn xor_blob(key: &FscryptMasterKey, pad: u8) -> Vec<u8> {
        key.as_bytes().iter().map(|b| b ^ pad).collect()
    }

    #[test]
    fn add_v2_wrapped_then_lookup_unwraps_and_caches() {
        let mut store = FscryptKeystore::default();
        let raw = FscryptMasterKey::from_array([0x11; 64]);
        let id = kdf_v2::key_identifier(&raw);
        let wrapped = xor_blob(&raw, 0x55);
        store.add_v2_wrapped(id, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

        let mk1 = store
            .get_v2(&id)
            .expect("unwrap succeeds")
            .expect("entry exists");
        assert_eq!(mk1.as_bytes(), raw.as_bytes());

        // Second lookup hits the OnceCell cache and returns the same
        // pointer (no re-unwrap).
        let mk2 = store.get_v2(&id).unwrap().unwrap();
        assert!(core::ptr::eq(mk1, mk2));
    }

    #[test]
    fn wrapped_lookup_with_failing_unwrapper_surfaces_error() {
        let mut store = FscryptKeystore::default();
        let id = FscryptKeyIdentifier([0xAB; 16]);
        store.add_v2_wrapped(id, alloc::vec![0u8; 64], Box::new(ErrorUnwrapper));

        let err = store.get_v2(&id).unwrap_err();
        assert!(
            matches!(&err, ExtError::FscryptKeyUnwrapFailed { reason, .. }
                if reason.contains("simulated TEE failure")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn wrapped_lookup_with_mismatched_identifier_surfaces_error() {
        // Register the wrapped key under a DIFFERENT identifier than
        // the unwrapped key actually derives. The keystore must reject
        // the lookup rather than returning a key that would silently
        // produce garbled plaintext.
        let mut store = FscryptKeystore::default();
        let raw = FscryptMasterKey::from_array([0x22; 64]);
        let wrong_id = FscryptKeyIdentifier([0xCD; 16]);
        let wrapped = xor_blob(&raw, 0x55);
        store.add_v2_wrapped(wrong_id, wrapped, Box::new(XorUnwrapper { pad: 0x55 }));

        let err = store.get_v2(&wrong_id).unwrap_err();
        assert!(
            matches!(&err, ExtError::FscryptKeyUnwrapFailed { reason, .. }
                if reason.contains("does not match registered")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn get_v2_returns_none_for_unregistered_identifier() {
        let store = FscryptKeystore::default();
        let id = FscryptKeyIdentifier([0; 16]);
        assert!(store.get_v2(&id).unwrap().is_none());
    }
}
