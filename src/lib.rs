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
//! [`mount`] blocks until the process is asked to stop or the volume is
//! unmounted; [`unmount`] does the latter from anywhere, including from
//! another process, and [`is_mounted`] reports whether a mountpoint is
//! live.
//!
//! # Mounting block devices
//!
//! The [`device`] layer provides cross-platform block-device access:
//! enumeration and raw opening of physical drives ([`HostDrives`] on
//! Windows/Linux/macOS), GPT/MBR partition-table parsing, physical-to-logical
//! volume resolution, multi-member raw sources, and boot-sector filesystem
//! detection. Platform openers use the [`proxy`] helper automatically when
//! direct block-device access is denied. Device mounts select a unique
//! operating-system logical view by default; raw access is always explicit.
//!
//! The [`drivers`] layer supplies the parser adapters: NTFS, FAT12/16/32,
//! `exFAT`, ext2/3/4, APFS, Btrfs, and `BitLocker` (which unlocks to NTFS).
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
//!
//! Raw, Expert Witness Format, VHD, and VHDX images can be opened through
//! [`open_image()`] or [`open_image_with_options`]. Segment sets, sparse blocks,
//! and VHD/VHDX differencing chains are decoded into the same seekable
//! [`ImageContainer`] media view consumed by the filesystem drivers.
//!
//! # Finding the filesystem, on an image or a drive
//!
//! A whole-disk image does not start with a filesystem, and neither does a
//! drive. Every way of saying *where* one is applies to both:
//!
//! | to say                              | image                             | drive                                    |
//! |-------------------------------------|-----------------------------------|------------------------------------------|
//! | what is on it                       | [`image_layout`]                  | [`drive_layout`]                         |
//! | what is *really* on it              | [`scan_image`]                    | [`scan_drive`]                           |
//! | open the N-th table entry           | [`ImageOpenOptions::with_partition`] | [`open_device_partition`]             |
//! | open the N-th filesystem a scan finds | [`ImageOpenOptions::with_scan`] | [`PartitionOpenOptions::with_scan`]      |
//! | open at a byte offset               | [`ImageOpenOptions::with_offset`] | [`open_device_at_offset`]                |
//! | read the table in 4 KiB sectors     | [`ImageOpenOptions::with_sector_size`] | [`PartitionOpenOptions::with_sector_size`] |
//!
//! [`image_layout`] and [`drive_layout`] share their enumeration, so an
//! image acquired from a drive and the drive itself number their partitions
//! identically:
//!
//! ```rust,no_run
//! use fsmnt::{ImageOpenOptions, drivers, image_layout, open_image_with_options};
//!
//! for partition in image_layout("disk.bin")?.partitions {
//!     println!("{:?} {:?}", partition.ordinal, partition.detected);
//! }
//! let options = ImageOpenOptions::new().with_partition(3);
//! let opened = open_image_with_options("disk.bin", &drivers::default_registry(), options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Whichever way a volume was located, the result records it — as
//! [`OpenedImage::layout_origin`] or [`OpenedPartition::layout_origin`] —
//! because a table read from the media, a table recovered from its backup
//! copy, a table invented by a scan, and a raw byte offset are four
//! different claims about the same bytes.
//!
//! # Damaged and partial images
//!
//! When the table and the media disagree, [`scan_image`] reads the decoded
//! media once and reports every offset that starts a filesystem, folding ext
//! backup superblocks into the filesystem they corroborate; each
//! [`LayoutPartition`] carries the [`missing_bytes`](LayoutPartition::missing_bytes)
//! the image is short of its declared extent; and a filesystem that opens
//! from a window smaller than it claims reports the shortfall as
//! [`OpenedImage::truncated_by`]. Partition tables written in 4 KiB sectors
//! are read as such, either on request
//! ([`ImageOpenOptions::with_sector_size`]) or by detection
//! ([`ImageLayout::sector_size_auto_detected`]).

pub use fsmnt_core::{
    DirFilesystem, FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, Fstab, FstabEntry,
    FstabParseError, FstabSource, MountNamespace, TargetFilesystem, filter_entries, normalize_path,
};

pub use fsmnt_device as device;
pub use fsmnt_device::{ImageContainer, ImageFormat, ImageOpenError, ImageReader};
pub use fsmnt_drivers as drivers;
pub use fsmnt_proxy as proxy;

mod backend;
mod ext_backup;
mod fstab_mount;
mod layout;
mod open_device;
mod open_image;
mod scan;
mod truncation;

pub use backend::{is_mounted, mount, unmount};
pub use fstab_mount::{open_device_partition_with_fstab, open_image_with_fstab};
pub use layout::{
    DriveLayout, DriveLayoutError, DriveLayoutOptions, ImageLayout, ImageLayoutOptions, LayoutKind,
    LayoutOrigin, LayoutPartition, drive_layout, image_layout, image_layout_with_options,
    image_layout_with_sector_size,
};
pub use open_device::{
    OpenedPartition, PartitionOpenOptions, open_device_at_offset, open_device_partition,
    open_device_partition_with_options, open_device_partition_with_selection,
};
pub use open_image::{
    ImageOpenOptions, OpenImageError, OpenedImage, open_image, open_image_with_options,
};
pub use scan::{
    DEFAULT_STRIDE, ExtBackupSuperblock, MediaScanError, ScanError, ScanHit, ScanHitKind,
    ScanOptions, mountable_hits, scan_drive, scan_image, scan_image_with_options, scan_media,
};
pub use truncation::missing_filesystem_bytes;

#[cfg(target_os = "linux")]
pub use fsmnt_device_linux::LinuxHostDrives as HostDrives;
#[cfg(target_os = "macos")]
pub use fsmnt_device_macos::MacOsHostDrives as HostDrives;
#[cfg(windows)]
pub use fsmnt_device_windows::WindowsHostDrives as HostDrives;
