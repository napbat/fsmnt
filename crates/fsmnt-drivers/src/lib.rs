//! Filesystem-parser adapters for the `fsmnt` mount stack.
//!
//! This crate is the std boundary between the vendored, `no_std`-capable
//! format parsers under `crates/formats/` (and their shared
//! `fsmnt-parser-core` foundation) and the two traits the mount stack is
//! built on:
//!
//! - [`TargetFilesystem`](fsmnt_core::TargetFilesystem) — the read-only
//!   file-tree interface the mount backends consume.
//! - [`FilesystemDriver`](fsmnt_device::FilesystemDriver) — the plug-in
//!   point that turns a partition-scoped reader plus a
//!   [`DetectedBootSector`](fsmnt_device::DetectedBootSector) into a
//!   mountable filesystem.
//!
//! | Format          | Adapter                | Driver                |
//! |-----------------|------------------------|-----------------------|
//! | NTFS            | [`NtfsFilesystem`]     | [`NtfsDriver`]        |
//! | FAT12/16/32     | [`FatFilesystem`]      | [`FatDriver`]         |
//! | `exFAT`         | [`ExFatFilesystem`]    | [`ExFatDriver`]       |
//! | ext2/3/4        | [`ExtFilesystem`]      | [`ExtDriver`]         |
//! | APFS            | [`ApfsFilesystem`]     | [`ApfsDriver`]        |
//! | Btrfs           | superblock only        | [`BtrfsDriver`]       |
//! | `BitLocker`     | (unlocks to NTFS)      | [`BitLockerDriver`]   |
//!
//! # Quick start
//!
//! ```rust,no_run
//! use fsmnt_device::DetectedBootSector;
//! use fsmnt_drivers::default_registry;
//!
//! let registry = default_registry();
//! let reader = Box::new(std::io::Cursor::new(Vec::new()));
//! let fs = registry.open(reader, DetectedBootSector::Ntfs)?;
//! # Ok::<(), fsmnt_core::FsError>(())
//! ```
//!
//! # `BitLocker` credentials
//!
//! [`FilesystemDriver::open`](fsmnt_device::FilesystemDriver::open) takes no
//! credentials, so they live on the driver itself.  Build a
//! [`BitLockerDriver`] with the credentials you have and hand it to
//! [`registry_with_bitlocker`]:
//!
//! ```rust
//! use fsmnt_drivers::{BitLockerDriver, registry_with_bitlocker};
//!
//! let driver = BitLockerDriver::new()
//!     .with_recovery_password("000000-111111-222222-333333-444444-555555-666666-777777");
//! let registry = registry_with_bitlocker(driver);
//! ```
//!
//! # Registering your own driver
//!
//! [`DriverRegistry`] stays open: start from [`default_registry`] and push
//! additional [`FilesystemDriver`](fsmnt_device::FilesystemDriver)
//! implementations, or build an empty registry and register only what you
//! need.  Drivers are consulted in registration order, so a driver added
//! before the defaults wins for the types it claims.

mod adapter;
mod apfs;
mod bitlocker;
mod btrfs;
mod exfat;
mod ext;
mod fat;
mod ntfs;

pub use apfs::{ApfsDriver, ApfsFilesystem, VolumeSelector};
pub use bitlocker::BitLockerDriver;
pub use btrfs::BtrfsDriver;
pub use exfat::{ExFatDriver, ExFatFilesystem};
pub use ext::{ExtDriver, ExtFilesystem};
pub use fat::{FatDriver, FatFilesystem};
pub use ntfs::{NtfsDriver, NtfsFilesystem};

use fsmnt_device::DriverRegistry;

/// A registry holding every driver that needs no configuration.
///
/// Registration order is NTFS, FAT, `exFAT`, ext, APFS, Btrfs. The Btrfs
/// driver validates its superblock but reports traversal as unimplemented.
/// `BitLocker` partitions are *not* covered — that driver carries
/// credentials, so use [`registry_with_bitlocker`] (a clear-key-only
/// [`BitLockerDriver::new`] still unlocks suspended volumes).
#[must_use]
pub fn default_registry() -> DriverRegistry {
    let mut registry = DriverRegistry::new();
    registry.register(Box::new(NtfsDriver));
    registry.register(Box::new(FatDriver));
    registry.register(Box::new(ExFatDriver));
    registry.register(Box::new(ExtDriver));
    registry.register(Box::new(ApfsDriver));
    registry.register(Box::new(BtrfsDriver));
    registry
}

/// [`default_registry`] plus a configured [`BitLockerDriver`].
///
/// The `BitLocker` driver is registered last, so it only sees partitions
/// none of the plaintext drivers claim.
#[must_use]
pub fn registry_with_bitlocker(driver: BitLockerDriver) -> DriverRegistry {
    let mut registry = default_registry();
    registry.register(Box::new(driver));
    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsmnt_device::DetectedBootSector as D;

    #[test]
    fn default_registry_lists_every_plaintext_driver() {
        let registry = default_registry();
        assert!(!registry.is_empty());
        assert_eq!(
            registry.names(),
            ["ntfs", "fat", "exfat", "ext", "apfs", "btrfs"],
            "registration order is part of the dispatch contract"
        );
    }

    #[test]
    fn default_registry_dispatches_each_detected_filesystem() {
        let registry = default_registry();
        for (detected, expected) in [
            (D::Ntfs, "ntfs"),
            (D::Fat12, "fat"),
            (D::Fat16, "fat"),
            (D::Fat32, "fat"),
            (D::ExFat, "exfat"),
            (D::Ext, "ext"),
            (D::Apfs, "apfs"),
            (D::Btrfs, "btrfs"),
        ] {
            let driver = registry
                .find(detected)
                .unwrap_or_else(|| panic!("no driver for {detected:?}"));
            assert_eq!(driver.name(), expected, "wrong driver for {detected:?}");
        }
    }

    #[test]
    fn default_registry_has_no_bitlocker_driver() {
        assert!(default_registry().find(D::BitLocker).is_none());
    }

    #[test]
    fn default_registry_rejects_partition_tables_and_unknown() {
        let registry = default_registry();
        for detected in [D::MbrPartitioned, D::GptPartitioned, D::Unknown] {
            assert!(
                registry.find(detected).is_none(),
                "{detected:?} must not resolve to a driver"
            );
        }
    }

    #[test]
    fn open_without_a_matching_driver_reports_the_available_ones() {
        let registry = default_registry();
        let reader = Box::new(std::io::Cursor::new(vec![0u8; 512]));
        let Err(err) = registry.open(reader, D::Unknown) else {
            panic!("expected an error for an unsupported type");
        };
        let msg = err.to_string();
        assert!(msg.contains("no filesystem driver"), "{msg}");
        assert!(msg.contains("ntfs"), "{msg}");
    }

    #[test]
    fn registry_with_bitlocker_appends_the_bitlocker_driver() {
        let registry = registry_with_bitlocker(BitLockerDriver::new());
        assert_eq!(
            registry.names(),
            ["ntfs", "fat", "exfat", "ext", "apfs", "btrfs", "bitlocker"]
        );
        let driver = registry.find(D::BitLocker).expect("bitlocker driver");
        assert_eq!(driver.name(), "bitlocker");
    }

    #[test]
    fn bitlocker_driver_does_not_shadow_plaintext_ntfs() {
        let registry = registry_with_bitlocker(BitLockerDriver::new());
        assert_eq!(
            registry.find(D::Ntfs).expect("ntfs driver").name(),
            "ntfs",
            "plaintext NTFS must keep winning over the BitLocker driver"
        );
    }
}
