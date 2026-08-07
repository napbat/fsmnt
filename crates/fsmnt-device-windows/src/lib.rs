//! Windows block-device access for `fsmnt`.
//!
//! Enumerates physical drives (`\\.\PhysicalDrive<N>`) and opens them for
//! raw read-only access, implementing
//! [`HostDriveEnumerator`](fsmnt_device::HostDriveEnumerator). It also
//! resolves every physical extent of a Windows volume to its volume GUID so
//! OS-decrypted data can be read without assuming one volume has one backing
//! disk. Raw opens fall back to
//! `fsmnt-proxy-server` when direct access is denied.
//!
//! On non-Windows targets this crate compiles to an empty library so that
//! workspace-wide builds work everywhere.

#[cfg(windows)]
mod drives;

#[cfg(windows)]
mod volumes;

#[cfg(windows)]
pub use drives::WindowsHostDrives;

#[cfg(windows)]
pub use volumes::{VolumeInfo, enumerate_volumes, find_volumes_for_extent};
