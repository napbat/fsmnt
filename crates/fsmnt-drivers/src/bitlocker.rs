//! `BitLocker` driver over the vendored `nt-bitlocker` crate.
//!
//! [`BitLockerDriver`] unlocks an FVE-encrypted volume and hands the
//! decrypted stream to [`NtfsFilesystem`], which is what every
//! `BitLocker`-protected Windows volume contains.
//!
//! [`FilesystemDriver::open`] takes no credentials, so they live on the
//! driver: build one with [`BitLockerDriver::new`] and the
//! `with_*` methods, then register it (see
//! [`registry_with_bitlocker`](crate::registry_with_bitlocker)).

use nt_bitlocker::{BitLockerVolume, Credential, UnlockMethod};

use fsmnt_core::{FsError, FsResult, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};
use tracing::debug;

use crate::ntfs::NtfsFilesystem;

/// The name of an unlock method's protector, for diagnostics.
///
/// Only the *kind* of credential is named: the password, BEK bytes and
/// every derived key stay out of the logs.
const fn protector_name(method: &UnlockMethod) -> &'static str {
    match method {
        UnlockMethod::Credential(Credential::ClearKey) => "clear key",
        UnlockMethod::Credential(Credential::RecoveryPassword(_)) => "recovery password",
        UnlockMethod::Credential(Credential::UserPassword(_)) => "user password",
        UnlockMethod::Credential(Credential::BekFile(_)) => "BEK startup key",
        UnlockMethod::Vmk(_) => "volume master key",
        UnlockMethod::Fvek(_) => "full-volume encryption key",
    }
}

/// [`FilesystemDriver`] for `BitLocker`-encrypted volumes.
///
/// Unlock attempts run in a fixed order:
/// 1. **Clear key** — always tried first. It costs nothing and succeeds on
///    a volume whose protection is suspended.
/// 2. **Recovery password**, if one was supplied.
/// 3. **BEK startup key**, if one was supplied.
///
/// When every attempt fails, the returned error names the key protectors
/// the volume actually carries, so the operator can tell which credential
/// is missing.
///
/// ```rust
/// use fsmnt_drivers::BitLockerDriver;
///
/// // Clear key only — enough for a suspended volume.
/// let suspended = BitLockerDriver::new();
///
/// // Clear key, then a recovery password.
/// let with_password = BitLockerDriver::new()
///     .with_recovery_password("000000-111111-222222-333333-444444-555555-666666-777777");
/// ```
#[derive(Debug, Default)]
pub struct BitLockerDriver {
    recovery_password: Option<String>,
    bek_file: Option<Vec<u8>>,
}

impl BitLockerDriver {
    /// A driver with no credentials: clear key only.
    ///
    /// Unlocks volumes whose protection is suspended, which is the state
    /// left behind by `manage-bde -protectors -disable`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a 48-digit recovery password (eight dash-separated groups of
    /// six digits).
    #[must_use]
    pub fn with_recovery_password(mut self, password: impl Into<String>) -> Self {
        self.recovery_password = Some(password.into());
        self
    }

    /// Add the raw contents of a `.BEK` startup-key file.
    #[must_use]
    pub fn with_bek_file(mut self, data: Vec<u8>) -> Self {
        self.bek_file = Some(data);
        self
    }

    /// Whether any credential beyond the clear key was configured.
    #[must_use]
    pub fn has_credentials(&self) -> bool {
        self.recovery_password.is_some() || self.bek_file.is_some()
    }

    /// The unlock methods to try, in priority order.
    fn unlock_methods(&self) -> Vec<UnlockMethod> {
        let mut methods = vec![UnlockMethod::Credential(Credential::ClearKey)];
        if let Some(password) = &self.recovery_password {
            methods.push(UnlockMethod::Credential(Credential::RecoveryPassword(
                password.clone().into(),
            )));
        }
        if let Some(data) = &self.bek_file {
            methods.push(UnlockMethod::Credential(Credential::BekFile(
                data.clone().into(),
            )));
        }
        methods
    }
}

impl FilesystemDriver for BitLockerDriver {
    fn name(&self) -> &'static str {
        "bitlocker"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::BitLocker
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let volume = BitLockerVolume::open(reader)
            .map_err(|e| FsError::Filesystem(format!("failed to parse BitLocker metadata: {e}")))?;

        // Captured before the unlock attempts consume the volume, so the
        // failure path can still report what the volume offers.
        let protectors: Vec<String> = volume
            .metadata()
            .key_protectors()
            .iter()
            .map(|p| format!("{:?}", p.protector_type()))
            .collect();

        debug!(
            protectors = ?protectors,
            "parsed the BitLocker metadata; trying the configured credentials in order"
        );

        // Each failed attempt hands the volume back for the next one.
        let mut current_volume = volume;
        let mut last_error = String::new();

        for method in &self.unlock_methods() {
            match current_volume.unlock(method) {
                Ok(unlocked) => {
                    debug!(
                        protector = protector_name(method),
                        "unlocked the BitLocker volume; opening the NTFS filesystem inside"
                    );
                    return Ok(Box::new(NtfsFilesystem::new(unlocked)?));
                }
                Err(unlock_err) => {
                    last_error = unlock_err.source.to_string();
                    debug!(
                        protector = protector_name(method),
                        "this protector did not unlock the volume"
                    );
                    current_volume = unlock_err.volume;
                }
            }
        }

        let protector_list = if protectors.is_empty() {
            "none found".to_string()
        } else {
            protectors.join(", ")
        };
        Err(FsError::Filesystem(format!(
            "BitLocker volume is locked ({last_error}). \
             Available protectors: [{protector_list}]"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn driver_supports_only_bitlocker() {
        let driver = BitLockerDriver::new();
        assert!(driver.supports(DetectedBootSector::BitLocker));
        for other in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
            DetectedBootSector::Btrfs,
            DetectedBootSector::GptPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(!driver.supports(other), "must not claim {other:?}");
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(BitLockerDriver::new().name(), "bitlocker");
    }

    #[test]
    fn a_bare_driver_carries_no_credentials_and_only_tries_the_clear_key() {
        let driver = BitLockerDriver::new();
        assert!(!driver.has_credentials());
        assert_eq!(driver.unlock_methods().len(), 1);
    }

    #[test]
    fn builders_append_methods_after_the_clear_key() {
        let driver = BitLockerDriver::new().with_recovery_password("1-2-3");
        assert!(driver.has_credentials());
        assert_eq!(driver.unlock_methods().len(), 2);

        let driver = BitLockerDriver::new().with_bek_file(vec![0u8; 32]);
        assert!(driver.has_credentials());
        assert_eq!(driver.unlock_methods().len(), 2);

        let driver = BitLockerDriver::new()
            .with_recovery_password("1-2-3")
            .with_bek_file(vec![0u8; 32]);
        assert_eq!(driver.unlock_methods().len(), 3);
    }

    #[test]
    fn builders_are_last_write_wins() {
        let driver = BitLockerDriver::new()
            .with_recovery_password("first")
            .with_recovery_password("second");
        assert_eq!(driver.recovery_password.as_deref(), Some("second"));
        assert_eq!(driver.unlock_methods().len(), 2);
    }

    #[test]
    fn clear_key_is_always_the_first_method_tried() {
        let driver = BitLockerDriver::new()
            .with_recovery_password("1-2-3")
            .with_bek_file(vec![0u8; 32]);
        assert!(matches!(
            driver.unlock_methods().first(),
            Some(UnlockMethod::Credential(Credential::ClearKey))
        ));
    }

    #[test]
    fn opening_a_non_bitlocker_image_reports_a_metadata_failure() {
        let reader = Box::new(Cursor::new(vec![0u8; 8192]));
        let Err(err) = BitLockerDriver::new().open(reader, DetectedBootSector::BitLocker) else {
            panic!("an all-zero image must not parse as a BitLocker volume");
        };
        assert!(
            matches!(&err, FsError::Filesystem(msg) if msg.contains("BitLocker metadata")),
            "expected a metadata parse error, got {err:?}"
        );
    }
}
