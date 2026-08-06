//! macOS block-device access for `fsmnt`.
//!
//! Enumerates whole disks (`/dev/disk0`, `/dev/disk1`, …), reads geometry
//! via `ioctl` and hardware metadata via `IOKit`, and opens drives for raw
//! read-only access, implementing
//! [`HostDriveEnumerator`](fsmnt_device::HostDriveEnumerator).
//!
//! On non-macOS targets this crate compiles to an empty library so that
//! workspace-wide builds work everywhere.

#[cfg(target_os = "macos")]
mod drives;

#[cfg(target_os = "macos")]
mod iokit;

#[cfg(target_os = "macos")]
pub use drives::MacOsHostDrives;
