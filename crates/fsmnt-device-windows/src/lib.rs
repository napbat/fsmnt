//! Windows block-device access for `fsmnt`.
//!
//! Enumerates physical drives (`\\.\PhysicalDrive<N>`) and opens them for
//! raw read-only access, implementing
//! [`HostDriveEnumerator`](fsmnt_device::HostDriveEnumerator).  Also maps
//! physical-disk extents to mounted volumes (`\\.\C:`) so OS-decrypted
//! data (e.g. unlocked `BitLocker` partitions) can be read through the
//! volume instead of the raw drive.
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
pub use volumes::{VolumeInfo, enumerate_volumes, find_volume_for_extent};
