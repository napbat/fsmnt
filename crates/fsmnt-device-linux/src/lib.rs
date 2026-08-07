//! Linux block-device access for `fsmnt`.
//!
//! Enumerates physical drives via sysfs (`/sys/block`) and opens them for
//! raw read-only access, implementing
//! [`HostDriveEnumerator`](fsmnt_device::HostDriveEnumerator). It follows
//! sysfs `holders` and `slaves` to resolve partitions through device-mapper,
//! MD, and other stacked block devices. Raw opens fall back to
//! `fsmnt-proxy-server` when direct access is denied.
//!
//! On non-Linux targets this crate compiles to an empty library so that
//! workspace-wide builds work everywhere.

#[cfg(target_os = "linux")]
mod drives;

#[cfg(target_os = "linux")]
mod volumes;

#[cfg(target_os = "linux")]
pub use drives::LinuxHostDrives;
