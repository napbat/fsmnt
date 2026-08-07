//! Mount any [`TargetFilesystem`] as a read-only virtual volume.
//!
//! Presents a filesystem implementation as a browsable read-only volume so
//! users can inspect and copy files with standard OS tools.
//!
//! | Platform       | Backend  | Mount target                |
//! |----------------|----------|-----------------------------|
//! | macOS / Linux  | FUSE     | directory mountpoint        |
//! | Windows        | Dokan    | drive letter or directory   |
//!
//! # Mounting a directory
//!
//! ```rust,no_run
//! use fsmnt::{DirFilesystem, mount};
//!
//! let fs = DirFilesystem::new("./export");
//! mount(
//!     Box::new(fs),
//!     "Z:",
//!     "fsmnt",
//!     "Evidence",
//!     0,
//!     || println!("mounted"),
//! )
//! .unwrap();
//! ```
//!
//! # Mounting block devices
//!
//! The [`device`] layer provides cross-platform block-device access:
//! enumeration and raw opening of physical drives ([`HostDrives`] on
//! Windows/Linux/macOS), GPT/MBR partition-table parsing, partition-scoped
//! readers, and boot-sector filesystem detection. Platform openers use the
//! [`proxy`] helper automatically when direct raw-device access is denied.
//!
//! The [`drivers`] layer supplies the parser adapters: NTFS, FAT12/16/32,
//! `exFAT`, ext2/3/4, APFS, and `BitLocker` (which unlocks to NTFS).
//! [`drivers::default_registry`] returns a [`device::DriverRegistry`] with
//! every driver that needs no configuration; `BitLocker` credentials ride
//! on [`drivers::BitLockerDriver`], which
//! [`drivers::registry_with_bitlocker`] adds.
//!
//! ```rust,no_run
//! use fsmnt::device::HostDriveId;
//! use fsmnt::{HostDrives, drivers, mount, open_device_partition};
//!
//! let drive = HostDriveId::new("0");
//! let opened = open_device_partition::<HostDrives>(&drive, 0, &drivers::default_registry())?;
//! mount(opened.filesystem, "Z:", "ntfs", "Evidence", opened.size_bytes, || {})?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`device::DriverRegistry`] remains the plug-in point: consumers can
//! register their own [`device::FilesystemDriver`] implementations
//! alongside (or instead of) the built-in ones, and
//! [`open_device_partition`] uses whichever registry it is handed.

pub use fsmnt_core::{
    DirFilesystem, FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, TargetFilesystem,
    filter_entries, normalize_path,
};

pub use fsmnt_device as device;
pub use fsmnt_drivers as drivers;
pub use fsmnt_proxy as proxy;

#[cfg(target_os = "linux")]
pub use fsmnt_device_linux::LinuxHostDrives as HostDrives;
#[cfg(target_os = "macos")]
pub use fsmnt_device_macos::MacOsHostDrives as HostDrives;
#[cfg(windows)]
pub use fsmnt_device_windows::WindowsHostDrives as HostDrives;

use fsmnt_device::{
    DetectedBootSector, Disk, DiskLayout, DriverRegistry, HostDriveEnumerator, HostDriveId,
    PartitionReader,
};

/// Mount a [`TargetFilesystem`] as a read-only volume.
///
/// - `mountpoint` — directory path (Unix) or drive letter / directory
///   (Windows, e.g. `"Z:"`).
/// - `fsname` — filesystem type label (e.g. `"ntfs"`, `"fat32"`).
/// - `volname` — volume label shown in the OS file manager.
/// - `total_bytes` — total size of the underlying volume in bytes, reported
///   by the OS in volume properties.  Pass 0 to fall back to the
///   filesystem's [`TargetFilesystem::total_size`].
/// - `on_mount` — called once the volume is successfully mounted and
///   accessible, *before* blocking on Ctrl+C.
///
/// Blocks until Ctrl+C (or `umount` on Unix).  The volume is automatically
/// unmounted when the function returns.
///
/// # Errors
///
/// Returns an error if the platform mount backend fails to create the
/// volume (e.g. missing FUSE/Dokan driver or an invalid mountpoint), or on
/// platforms with no mount backend.
pub fn mount(
    fs: Box<dyn TargetFilesystem>,
    mountpoint: &str,
    fsname: &str,
    volname: &str,
    total_bytes: u64,
    on_mount: impl FnOnce(),
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        fsmnt_fuse::mount(fs, mountpoint, fsname, volname, total_bytes, on_mount)
    }
    #[cfg(windows)]
    {
        fsmnt_dokan::mount(fs, mountpoint, fsname, volname, total_bytes, on_mount)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (fs, mountpoint, fsname, volname, total_bytes, on_mount);
        Err("fsmnt is not supported on this platform".into())
    }
}

/// A partition opened from a block device, ready to mount.
pub struct OpenedPartition {
    /// The filesystem opened by a registered driver.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// The detected boot-sector type of the partition.
    pub detected: DetectedBootSector,
    /// Size of the partition in bytes (0 if unknown).
    pub size_bytes: u64,
}

/// Open partition `partition` (0-based, counting non-empty entries) on
/// `drive` using the filesystem drivers in `drivers`.
///
/// Works with GPT and MBR partition tables; for a bare (unpartitioned)
/// filesystem, pass `partition = 0` to open the whole disk.  The drive is
/// opened twice: once to read the partition table, once for the returned
/// filesystem's own reader.
///
/// The enumerator type parameter selects the platform: on Windows, Linux,
/// and macOS, use [`HostDrives`].
///
/// # Errors
///
/// Returns an error if the drive cannot be opened, the partition does not
/// exist, the disk layout is unrecognized, or no registered driver can open
/// the detected filesystem (see
/// [`DriverRegistry::open`](fsmnt_device::DriverRegistry::open)).
pub fn open_device_partition<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let info = E::get_drive_info(drive).ok();
    let sector_size = info.as_ref().and_then(|i| i.sector_size).unwrap_or(512);

    let reader = E::open_drive(drive)?;
    let mut disk = Disk::with_sector_size(reader, sector_size)?;

    let (offset, size) = match disk.layout().clone() {
        DiskLayout::Gpt { header } => {
            let count = usize::try_from(header.num_partition_entries.get()).unwrap_or(usize::MAX);
            let mut ordinal = 0;
            let mut found = None;
            for i in 0..count {
                let entry = disk.gpt_partition(i)?;
                if entry.is_empty() {
                    continue;
                }
                if ordinal == partition {
                    found = Some((
                        entry.start_offset(disk.sector_size()),
                        entry.size_bytes(disk.sector_size()),
                    ));
                    break;
                }
                ordinal += 1;
            }
            found.ok_or_else(|| format!("partition {partition} not found on drive {drive}"))?
        }
        DiskLayout::Mbr { .. } => {
            let sector_size = disk.sector_size();
            let extents: Vec<(u64, u64)> = disk
                .mbr_partitions()
                .map(|e| (e.start_offset(sector_size), e.size_bytes(sector_size)))
                .collect();
            *extents
                .get(partition)
                .ok_or_else(|| format!("partition {partition} not found on drive {drive}"))?
        }
        DiskLayout::Bare(_) => {
            if partition != 0 {
                return Err(format!(
                    "drive {drive} has no partition table; only partition 0 is valid"
                )
                .into());
            }
            let size = info.as_ref().and_then(|i| i.size_bytes).unwrap_or(0);
            (0, if size == 0 { u64::MAX } else { size })
        }
        DiskLayout::Unknown => {
            return Err(format!("unrecognized disk layout on drive {drive}").into());
        }
    };

    let detected = disk.detect_boot_sector_at(offset)?;

    // Re-open the device so the filesystem owns an independent reader.
    let reader = E::open_drive(drive)?;
    let part_reader = PartitionReader::new(reader, offset, size);
    let filesystem = drivers.open(Box::new(part_reader), detected)?;

    Ok(OpenedPartition {
        filesystem,
        detected,
        size_bytes: if size == u64::MAX { 0 } else { size },
    })
}
