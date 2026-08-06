//! Linux physical drive enumeration and raw access.
//!
//! Enumerates physical drives (block devices) via sysfs (`/sys/block`) and
//! opens the corresponding `/dev` nodes for **read-only** raw access,
//! implementing [`HostDriveEnumerator`] for Linux.
//!
//! Devices are opened with `O_RDONLY | O_NONBLOCK` to prevent kernel
//! side-effects.  Opening raw block devices typically requires root
//! privileges (or membership in the `disk` group); drives that cannot be
//! opened are reported by enumeration with `accessible = false` rather
//! than being omitted.

use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use fsmnt_device::{
    HostDriveBusType, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo,
    HostDriveResult,
};

/// Linux host drive enumerator.
///
/// Implements the [`HostDriveEnumerator`] trait for Linux systems.
/// Drive IDs are kernel block-device names like `"sda"` or `"nvme0n1"`.
pub struct LinuxHostDrives;

impl LinuxHostDrives {
    /// Open a physical drive for **read-only** raw access by path
    /// (e.g., `"/dev/sda"`).
    ///
    /// Uses `O_RDONLY | O_NONBLOCK` to prevent kernel side-effects.
    ///
    /// # Errors
    ///
    /// Returns [`HostDriveError::AccessDenied`] if the caller lacks
    /// permission to open the device, [`HostDriveError::NotFound`] if the
    /// device node does not exist, or [`HostDriveError::Io`] for any other
    /// I/O failure.
    pub fn open_drive_path(path: &str) -> HostDriveResult<BufReader<File>> {
        Ok(BufReader::new(open_device(path)?))
    }
}

impl HostDriveEnumerator for LinuxHostDrives {
    type Reader = File;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        let mut drives = Vec::new();

        // Read /sys/block to find block devices.
        let block_dir = Path::new("/sys/block");
        if !block_dir.exists() {
            return Ok(drives);
        }

        for entry in fs::read_dir(block_dir)?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !is_physical_disk_name(&name) {
                continue;
            }

            let id = HostDriveId::new(&name);
            if let Ok(info) = Self::get_drive_info(&id) {
                drives.push(info);
            }
        }

        Ok(drives)
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        let name = id.as_str();
        let dev_path = format!("/dev/{name}");
        let sys_path = PathBuf::from(format!("/sys/block/{name}"));

        // Check if the device exists in /sys/block.
        if !sys_path.exists() {
            return Err(HostDriveError::NotFound(name.to_string()));
        }

        // Gather all available sysfs info.
        let bus_type = detect_bus_type(name, &sys_path);

        let mut info = HostDriveInfo::new(id.clone(), PathBuf::from(&dev_path));
        if let Some(size) = read_sysfs_size(&sys_path) {
            info = info.with_size(size);
        }
        if let Some(sector_size) = read_sysfs_sector_size(&sys_path) {
            info = info.with_sector_size(sector_size);
        }
        if let Some(model) = read_sysfs_model(&sys_path) {
            info = info.with_model(model);
        }
        if let Some(serial) = read_sysfs_serial(&sys_path) {
            info = info.with_serial(serial);
        }
        if let Some(bus) = bus_type {
            info = info.with_bus_type(bus);
        }

        // sysfs "removable" refers to removable media (e.g. an SD card),
        // not removable devices.  USB-attached drives report 0 even though
        // the device itself is removable, so override for USB.
        let removable = read_sysfs_removable(&sys_path).unwrap_or(false)
            || bus_type == Some(HostDriveBusType::Usb);
        info = info.with_removable(removable);

        // Probe accessibility with a direct read-only open.  If sysfs did
        // not provide a size, try to get it from the opened device.
        match open_device(&dev_path) {
            Ok(mut file) => {
                info.accessible = true;
                if (info.size_bytes.is_none() || info.size_bytes == Some(0))
                    && let Ok(size) = file.seek(SeekFrom::End(0))
                {
                    info = info.with_size(size);
                }
            }
            Err(HostDriveError::AccessDenied) => {
                info = info.with_error("Access denied (requires root privileges)");
            }
            Err(e) => {
                info = info.with_error(&e.to_string());
            }
        }

        Ok(info)
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<File> {
        open_device(&format!("/dev/{id}"))
    }
}

/// Open a device node **read-only** with `O_NONBLOCK`.
///
/// Direct open only: on permission denied this returns
/// [`HostDriveError::AccessDenied`] (no privileged-helper fallback).
fn open_device(path: &str) -> HostDriveResult<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| map_io_error(e, path))
}

/// Map an I/O error to a [`HostDriveError`].
fn map_io_error(e: std::io::Error, path: &str) -> HostDriveError {
    match e.kind() {
        std::io::ErrorKind::PermissionDenied => HostDriveError::AccessDenied,
        std::io::ErrorKind::NotFound => HostDriveError::NotFound(path.to_string()),
        _ => HostDriveError::Io(e),
    }
}

/// Whether a `/sys/block` entry name looks like a real physical disk.
///
/// Accepts `sd*`, `hd*`, `nvme*`, `vd*`, and `xvd*`.  Virtual and
/// non-disk devices (`loop*`, `ram*`, `dm-*`, `sr*`, `fd*`, …) do not
/// match any of these prefixes and are implicitly excluded.
fn is_physical_disk_name(name: &str) -> bool {
    name.starts_with("sd")
        || name.starts_with("hd")
        || name.starts_with("nvme")
        || name.starts_with("vd")
        || name.starts_with("xvd")
}

/// Read the device size from sysfs (in bytes).
fn read_sysfs_size(sys_path: &Path) -> Option<u64> {
    let content = fs::read_to_string(sys_path.join("size")).ok()?;
    parse_size_bytes(&content)
}

/// Parse `/sys/block/<dev>/size` content (a count of 512-byte sectors)
/// into a byte count.
fn parse_size_bytes(content: &str) -> Option<u64> {
    let sectors: u64 = content.trim().parse().ok()?;
    sectors.checked_mul(512)
}

/// Read the logical sector size from sysfs (in bytes).
fn read_sysfs_sector_size(sys_path: &Path) -> Option<u32> {
    let content = fs::read_to_string(sys_path.join("queue/logical_block_size")).ok()?;
    content.trim().parse().ok()
}

/// Read the device model from sysfs.
///
/// Tries `device/model` first (SCSI/SATA), then `device/name` (used by
/// some other device types).
fn read_sysfs_model(sys_path: &Path) -> Option<String> {
    read_first_nonempty(&[sys_path.join("device/model"), sys_path.join("device/name")])
}

/// Read the device serial number from sysfs.
///
/// Tries `device/serial` first, then `device/wwid` (World Wide ID) as a
/// fallback.
fn read_sysfs_serial(sys_path: &Path) -> Option<String> {
    read_first_nonempty(&[sys_path.join("device/serial"), sys_path.join("device/wwid")])
}

/// Return the trimmed content of the first candidate file that exists and
/// is non-empty.
fn read_first_nonempty(candidates: &[PathBuf]) -> Option<String> {
    for path in candidates {
        if let Ok(content) = fs::read_to_string(path) {
            let value = content.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Read the removable-media flag from sysfs.
fn read_sysfs_removable(sys_path: &Path) -> Option<bool> {
    let content = fs::read_to_string(sys_path.join("removable")).ok()?;
    parse_removable(&content)
}

/// Parse `/sys/block/<dev>/removable` content (`"0"` or `"1"`).
fn parse_removable(content: &str) -> Option<bool> {
    match content.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Detect the bus type from the device name and sysfs.
///
/// Note: this is heuristic-based and may return `None` for some devices,
/// particularly virtualized environments like WSL2 where the sysfs
/// symlinks don't contain identifiable transport information.  The model
/// name (e.g., "Virtual Disk") may be more reliable for identifying
/// virtual drives.
fn detect_bus_type(name: &str, sys_path: &Path) -> Option<HostDriveBusType> {
    // NVMe devices.
    if name.starts_with("nvme") {
        return Some(HostDriveBusType::Nvme);
    }

    // MMC/SD devices: distinguish via the sysfs device type.
    if name.starts_with("mmcblk") {
        if let Ok(content) = fs::read_to_string(sys_path.join("device/type")) {
            match content.trim() {
                "SD" => return Some(HostDriveBusType::Sd),
                "MMC" => return Some(HostDriveBusType::Mmc),
                _ => {}
            }
        }
        return Some(HostDriveBusType::Mmc); // Default to MMC.
    }

    // Virtio and Xen virtual devices.
    if name.starts_with("vd") || name.starts_with("xvd") {
        return Some(HostDriveBusType::Virtual);
    }

    // For sd*/hd* devices, inspect the device symlink to determine the
    // transport.
    if name.starts_with("sd") || name.starts_with("hd") {
        if let Ok(link_target) = fs::read_link(sys_path.join("device"))
            && let Some(bus) = bus_type_from_device_link(&link_target.to_string_lossy())
        {
            return Some(bus);
        }

        // Legacy hd* devices are typically ATA/IDE.
        if name.starts_with("hd") {
            return Some(HostDriveBusType::Ata);
        }
    }

    None
}

/// Infer the bus type from the target of the `/sys/block/<dev>/device`
/// symlink.
fn bus_type_from_device_link(link: &str) -> Option<HostDriveBusType> {
    if link.contains("/usb") {
        return Some(HostDriveBusType::Usb);
    }
    if link.contains("/ata") || link.contains("/sata") {
        return Some(HostDriveBusType::Sata);
    }
    if link.contains("/scsi") {
        return Some(HostDriveBusType::Scsi);
    }
    if link.contains("/sas") {
        return Some(HostDriveBusType::Sas);
    }
    if link.contains("/iscsi") {
        return Some(HostDriveBusType::Iscsi);
    }
    if link.contains("/virtual") || link.contains("MSFT") {
        return Some(HostDriveBusType::Virtual);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use fsmnt_device::{
        HostDriveBusType, HostDriveEnumerator, HostDriveId, HostDriveInfo, HostDriveResult,
    };

    use super::{
        LinuxHostDrives, bus_type_from_device_link, is_physical_disk_name, parse_removable,
        parse_size_bytes,
    };

    // Compile-time check that `LinuxHostDrives` implements the trait with
    // `Reader = File`.
    const _ENUMERATE: fn() -> HostDriveResult<Vec<HostDriveInfo>> =
        <LinuxHostDrives as HostDriveEnumerator>::enumerate_drives;
    const _OPEN: fn(&HostDriveId) -> HostDriveResult<File> =
        <LinuxHostDrives as HostDriveEnumerator>::open_drive;

    #[test]
    fn physical_disk_name_filter() {
        for name in ["sda", "sdb", "hda", "nvme0n1", "vda", "xvda"] {
            assert!(is_physical_disk_name(name), "{name} should match");
        }
        for name in ["loop0", "ram0", "dm-0", "sr0", "fd0", "mmcblk0", "zram0"] {
            assert!(!is_physical_disk_name(name), "{name} should not match");
        }
    }

    #[test]
    fn size_parsing() {
        assert_eq!(parse_size_bytes("1024\n"), Some(524_288));
        assert_eq!(parse_size_bytes("0"), Some(0));
        assert_eq!(parse_size_bytes("garbage"), None);
        assert_eq!(parse_size_bytes(""), None);
    }

    #[test]
    fn removable_parsing() {
        assert_eq!(parse_removable("1\n"), Some(true));
        assert_eq!(parse_removable("0\n"), Some(false));
        assert_eq!(parse_removable("2"), None);
        assert_eq!(parse_removable(""), None);
    }

    #[test]
    fn device_link_bus_detection() {
        assert_eq!(
            bus_type_from_device_link("../../devices/pci0000:00/0000:00:14.0/usb2/2-1/2-1:1.0"),
            Some(HostDriveBusType::Usb)
        );
        assert_eq!(
            bus_type_from_device_link(
                "../../devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0"
            ),
            Some(HostDriveBusType::Sata)
        );
        assert_eq!(
            bus_type_from_device_link("../../devices/pci0000:00/0000:00:10.0/scsi_host/host0"),
            Some(HostDriveBusType::Scsi)
        );
        assert_eq!(
            bus_type_from_device_link("../../devices/platform/none"),
            None
        );
    }
}
