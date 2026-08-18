//! macOS physical drive enumeration and raw access.
//!
//! Provides functionality to enumerate physical drives (whole disks) and
//! open them for raw **read-only** access, suitable for use with the
//! `fsmnt` filesystem parsers.
//!
//! This module implements the [`HostDriveEnumerator`] trait from
//! `fsmnt-device` for macOS-specific drive enumeration.
//!
//! Drive geometry (size, block size) is obtained via `ioctl` on the block
//! device (`DKIOCGETBLOCKSIZE`, `DKIOCGETBLOCKCOUNT`).  Device properties
//! (model, serial number, bus type, removable flag) are obtained via the
//! `IOKit` framework (see [`crate::iokit`]).
//!
//! Opens are attempted directly first. On permission failure they fall back
//! to the default `fsmnt-proxy-server`, which passes back a read-only file
//! descriptor.

use std::fs::{self, File};
use std::io::BufReader;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use fsmnt_device::{
    HostDriveBusType, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo,
    HostDriveResult,
};
use fsmnt_proxy::{OpenMode, open_with_proxy_fallback};
use tracing::debug;

use crate::iokit;

// ---------------------------------------------------------------------------
// ioctl request codes from <sys/disk.h>
// ---------------------------------------------------------------------------
// _IOR('d', 24, uint32_t) → direction=IOC_OUT(0x40), size=4, group='d'(0x64), nr=24(0x18)
// Encoding: (IOC_OUT << 29) | (size << 16) | (group << 8) | nr
const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x4004_6418;
// _IOR('d', 25, uint64_t) → direction=IOC_OUT(0x40), size=8, group='d'(0x64), nr=25(0x19)
const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x4008_6419;

/// macOS host drive enumerator.
///
/// Implements the [`HostDriveEnumerator`] trait for macOS systems.
/// Drive IDs are BSD device names like `"disk0"`, `"disk1"`, etc.
///
/// Drive geometry is obtained via `ioctl` (`DKIOCGETBLOCKSIZE`,
/// `DKIOCGETBLOCKCOUNT`).  Device properties (model, serial, bus type)
/// are obtained via the `IOKit` framework.
pub struct MacOsHostDrives;

impl MacOsHostDrives {
    /// Open a physical drive for **read-only** raw access by path
    /// (e.g., `"/dev/disk0"`).
    ///
    /// Uses `O_RDONLY | O_NONBLOCK` to prevent the kernel from triggering
    /// automount or media checks — forensically safe. If a direct open is
    /// denied, it tries the default `fsmnt-proxy-server`.
    ///
    /// # Errors
    ///
    /// Returns [`HostDriveError::AccessDenied`] if permission is denied,
    /// [`HostDriveError::NotFound`] if the device does not exist, or
    /// [`HostDriveError::Io`] for other I/O failures.
    pub fn open_drive_path(path: &str) -> HostDriveResult<BufReader<File>> {
        Ok(BufReader::new(open_device(path)?))
    }

    /// Open a raw volume (partition slice) for **read-only** access.
    ///
    /// Accepts a BSD slice name such as `"disk0s1"` or `"disk0s2"` and opens
    /// the corresponding **raw character device** (`/dev/rdisk0s1`).  The raw
    /// device bypasses the macOS buffer cache, which is preferred for
    /// forensic reads.
    ///
    /// If the raw device is not available (e.g. on some virtualised setups),
    /// falls back to the block device (`/dev/disk0s1`).
    ///
    /// # Errors
    ///
    /// Returns [`HostDriveError::NotFound`] if `slice` is not a valid
    /// partition slice name or the device does not exist,
    /// [`HostDriveError::AccessDenied`] if permission is denied, or
    /// [`HostDriveError::Io`] for other I/O failures.
    pub fn open_raw_volume(slice: &str) -> HostDriveResult<BufReader<File>> {
        let name = slice
            .strip_prefix("/dev/r")
            .or_else(|| slice.strip_prefix("/dev/"))
            .unwrap_or(slice);

        if !is_partition_slice(name) {
            return Err(HostDriveError::NotFound(format!(
                "not a valid partition slice: {name}"
            )));
        }

        // Prefer the raw character device.
        let raw_path = format!("/dev/r{name}");
        if Path::new(&raw_path).exists() {
            return Ok(BufReader::new(open_device(&raw_path)?));
        }

        let block_path = format!("/dev/{name}");
        Ok(BufReader::new(open_device(&block_path)?))
    }
}

impl HostDriveEnumerator for MacOsHostDrives {
    type Reader = File;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        let mut drives = Vec::new();

        let dev_entries = fs::read_dir("/dev").map_err(HostDriveError::Io)?;

        for entry in dev_entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_whole_disk(&name) {
                continue;
            }

            // Only include real physical devices — skip synthesized APFS
            // volumes, disk images, and other virtual devices.
            if !iokit::disk_properties(&name).is_some_and(|p| p.is_physical) {
                continue;
            }

            let id = HostDriveId::new(name.as_str());
            if let Ok(info) = Self::get_drive_info(&id) {
                drives.push(info);
            }
        }

        drives.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));

        debug!(count = drives.len(), "enumerated physical drives");
        for drive in &drives {
            debug!(
                drive = %drive.id,
                size_bytes = ?drive.size_bytes,
                accessible = drive.accessible,
                "physical drive"
            );
        }

        Ok(drives)
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        let name = id.as_str();
        let path = PathBuf::from(format!("/dev/{name}"));

        if !path.exists() {
            return Err(HostDriveError::NotFound(name.to_string()));
        }

        let mut info = HostDriveInfo::new(id.clone(), path);

        // Probe the device directly (read-only, `O_NONBLOCK`), then use
        // ioctls on the raw fd to get sector size + block count.
        // seek(End(0)) returns 0 on macOS block devices — ioctls are the
        // only reliable way.
        match open_device(&info.path.to_string_lossy()) {
            Ok(file) => {
                info.accessible = true;
                let fd = file.as_raw_fd();
                if let Some(block_size) = ioctl_get_block_size(fd) {
                    info = info.with_sector_size(block_size);
                    if let Some(block_count) = ioctl_get_block_count(fd) {
                        info = info.with_size(block_count * u64::from(block_size));
                    }
                }
            }
            Err(HostDriveError::AccessDenied) => {
                info = info.with_error("Access denied (start fsmnt-proxy-server as root)");
            }
            Err(e) => {
                info = info.with_error(&format!("I/O error: {e}"));
            }
        }

        // Query IOKit for hardware metadata (model, serial, bus type).
        if let Some(props) = iokit::disk_properties(name) {
            if let Some(model) = props.model {
                info = info.with_model(model);
            }
            if let Some(serial) = props.serial_number {
                info = info.with_serial(serial);
            }
            if let Some(bus) = props.bus_type {
                info = info.with_bus_type(bus);
            }
            // IOKit's "Removable" refers to removable *media* (e.g. CD,
            // SD card), not removable devices.  USB-attached drives report
            // Removable=false even though the device itself is removable.
            // Override: any USB-bus drive is removable.
            let removable =
                props.removable.unwrap_or(false) || props.bus_type == Some(HostDriveBusType::Usb);
            info = info.with_removable(removable);
        }

        Ok(info)
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<File> {
        open_device(&format!("/dev/{}", id.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Device opening
// ---------------------------------------------------------------------------

/// Open a device node for **read-only** access with `O_NONBLOCK`.
///
/// `O_NONBLOCK` prevents the kernel from blocking on media checks or
/// triggering automount side-effects. Access denial triggers a fallback to
/// the default `fsmnt-proxy-server`.
pub(crate) fn open_device(path: &str) -> HostDriveResult<File> {
    open_with_proxy_fallback(path, OpenMode::ReadOnly, libc::O_NONBLOCK).map_err(
        |error| match error.kind() {
            std::io::ErrorKind::PermissionDenied => HostDriveError::AccessDenied,
            std::io::ErrorKind::NotFound => HostDriveError::NotFound(path.to_string()),
            _ => HostDriveError::Io(error),
        },
    )
}

// ---------------------------------------------------------------------------
// Device-name classification
// ---------------------------------------------------------------------------

/// Returns `true` if the device name is a whole disk (e.g. "disk0").
fn is_whole_disk(name: &str) -> bool {
    if let Some(suffix) = name.strip_prefix("disk") {
        !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}

/// Returns `true` if the device name is a partition slice (e.g. "disk0s1").
fn is_partition_slice(name: &str) -> bool {
    let Some(after_disk) = name.strip_prefix("disk") else {
        return false;
    };
    let Some(s_pos) = after_disk.find('s') else {
        return false;
    };
    let disk_num = &after_disk[..s_pos];
    let slice_num = &after_disk[s_pos + 1..];
    !disk_num.is_empty()
        && disk_num.chars().all(|c| c.is_ascii_digit())
        && !slice_num.is_empty()
        && slice_num.chars().all(|c| c.is_ascii_digit())
}

// ---------------------------------------------------------------------------
// ioctl helpers
// ---------------------------------------------------------------------------

/// Query the block (sector) size of a device via `DKIOCGETBLOCKSIZE`.
fn ioctl_get_block_size(fd: i32) -> Option<u32> {
    let mut block_size: u32 = 0;
    // SAFETY: `fd` is a valid open file descriptor and `DKIOCGETBLOCKSIZE`
    // writes a `uint32_t` through the provided pointer.
    let ret = unsafe { libc::ioctl(fd, DKIOCGETBLOCKSIZE, &raw mut block_size) };
    if ret == 0 && block_size > 0 {
        Some(block_size)
    } else {
        None
    }
}

/// Query the block count of a device via `DKIOCGETBLOCKCOUNT`.
fn ioctl_get_block_count(fd: i32) -> Option<u64> {
    let mut block_count: u64 = 0;
    // SAFETY: `fd` is a valid open file descriptor and `DKIOCGETBLOCKCOUNT`
    // writes a `uint64_t` through the provided pointer.
    let ret = unsafe { libc::ioctl(fd, DKIOCGETBLOCKCOUNT, &raw mut block_count) };
    if ret == 0 { Some(block_count) } else { None }
}

#[cfg(test)]
mod tests {
    use super::{is_partition_slice, is_whole_disk};

    #[test]
    fn is_whole_disk_accepts_disk_with_digits() {
        assert!(is_whole_disk("disk0"));
        assert!(is_whole_disk("disk1"));
        assert!(is_whole_disk("disk12"));
    }

    #[test]
    fn is_whole_disk_rejects_partitions_and_junk() {
        assert!(!is_whole_disk("disk0s1"));
        assert!(!is_whole_disk("disk0s2"));
        assert!(!is_whole_disk("disk"));
        assert!(!is_whole_disk("rdisk0"));
        assert!(!is_whole_disk("sda"));
        assert!(!is_whole_disk(""));
    }

    #[test]
    fn is_partition_slice_accepts_valid_slices() {
        assert!(is_partition_slice("disk0s1"));
        assert!(is_partition_slice("disk0s2"));
        assert!(is_partition_slice("disk2s3"));
        assert!(is_partition_slice("disk12s10"));
    }

    #[test]
    fn is_partition_slice_rejects_whole_disks_and_junk() {
        assert!(!is_partition_slice("disk0"));
        assert!(!is_partition_slice("disk1"));
        assert!(!is_partition_slice("disk"));
        assert!(!is_partition_slice("disks1"));
        assert!(!is_partition_slice("disk0s"));
        assert!(!is_partition_slice("rdisk0s1"));
        assert!(!is_partition_slice("sda1"));
        assert!(!is_partition_slice(""));
    }
}
