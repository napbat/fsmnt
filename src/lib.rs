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
//! [`open_image`] or [`open_image_with_options`]. Segment sets, sparse blocks,
//! and VHD/VHDX differencing chains are decoded into the same seekable
//! [`ImageContainer`] media view consumed by the filesystem drivers.
//!
//! A whole-disk image does not start with a filesystem. [`image_layout`]
//! enumerates its partition table — ordinal, offset, size, type, label, and
//! detected filesystem per partition — and
//! [`ImageOpenOptions::with_partition`] mounts one of those ordinals without
//! any offset arithmetic:
//!
//! ```rust,no_run
//! use fsmnt::{ImageOpenOptions, drivers, image_layout, open_image_with_options};
//!
//! for partition in image_layout("disk.bin")?.partitions {
//!     println!("{} {:?}", partition.ordinal, partition.detected);
//! }
//! let options = ImageOpenOptions::new().with_partition(3);
//! let opened = open_image_with_options("disk.bin", &drivers::default_registry(), options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! [`ImageOpenOptions::with_offset`] remains for media whose filesystem sits
//! at a byte offset no partition table describes.
//!
//! # Damaged and partial images
//!
//! When the table and the media disagree, [`scan_image`] reads the decoded
//! media once and reports every offset that starts a filesystem, folding ext
//! backup superblocks into the filesystem they corroborate; each
//! [`ImagePartition`] carries the [`missing_bytes`](ImagePartition::missing_bytes)
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
mod fstab_mount;
mod image_layout;
mod open_image;
mod scan;
mod truncation;

pub use backend::{is_mounted, mount, unmount};
pub use fstab_mount::open_device_partition_with_fstab;
pub use image_layout::{
    ImageLayout, ImageLayoutKind, ImageLayoutOptions, ImagePartition, image_layout,
    image_layout_with_options, image_layout_with_sector_size,
};
pub use open_image::{
    ImageOpenOptions, OpenImageError, OpenedImage, open_image, open_image_with_options,
};
pub use scan::{
    DEFAULT_STRIDE, ExtBackupSuperblock, ScanError, ScanHit, ScanHitKind, ScanOptions, scan_image,
    scan_image_with_options,
};
pub use truncation::missing_filesystem_bytes;

#[cfg(target_os = "linux")]
pub use fsmnt_device_linux::LinuxHostDrives as HostDrives;
#[cfg(target_os = "macos")]
pub use fsmnt_device_macos::MacOsHostDrives as HostDrives;
#[cfg(windows)]
pub use fsmnt_device_windows::WindowsHostDrives as HostDrives;

use fsmnt_device::{
    DetectedBootSector, DeviceMember, DeviceSet, Disk, DiskLayout, DriverRegistry,
    FilesystemMemberId, FilesystemOpenOptions, FilesystemRoot, HostDriveEnumerator, HostDriveId,
    HostVolumeResolver, LogicalVolumeId, PartitionAddress, PartitionReader, PhysicalExtent,
    ResolvedMemberDiscovery, SectorReader, SourceMemberId, SourceOrigin, SourceSelection,
    select_logical_volume,
};

/// A partition opened from a block device, ready to mount.
pub struct OpenedPartition {
    /// The filesystem opened by a registered driver.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// The detected boot-sector type of the partition.
    pub detected: DetectedBootSector,
    /// Size of the partition in bytes (0 if unknown).
    pub size_bytes: u64,
    /// Bytes the opened filesystem claims for itself that the partition does
    /// not provide, or `None` when it fits or the partition size is unknown
    /// (see [`missing_filesystem_bytes`]).
    pub truncated_by: Option<u64>,
    /// Physical or operating-system logical source actually opened.
    pub source: SourceOrigin,
}

/// Independent source-layer and filesystem-root choices for opening a
/// partition.
#[derive(Clone, Debug)]
pub struct PartitionOpenOptions {
    source: SourceSelection,
    filesystem: FilesystemOpenOptions,
}

impl PartitionOpenOptions {
    /// Use automatic logical-volume selection and the filesystem's default
    /// root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            source: SourceSelection::Auto,
            filesystem: FilesystemOpenOptions::new(),
        }
    }

    /// Choose the logical or physical block source.
    #[must_use]
    pub fn with_source(mut self, source: SourceSelection) -> Self {
        self.source = source;
        self
    }

    /// Choose the filesystem-owned tree or container volume to expose.
    #[must_use]
    pub fn with_filesystem_root(mut self, root: FilesystemRoot) -> Self {
        self.filesystem = self.filesystem.with_root(root);
        self
    }

    /// Allow (default) or decline journal and orphan replay into an
    /// in-memory overlay; see
    /// [`FilesystemOpenOptions::with_journal_replay`]. The source is never
    /// written either way.
    #[must_use]
    pub fn with_journal_replay(mut self, replay: bool) -> Self {
        self.filesystem = self.filesystem.with_journal_replay(replay);
        self
    }

    /// Replace every filesystem-level option (root selector, journal replay)
    /// with `filesystem` at once.
    #[must_use]
    pub fn with_filesystem_options(mut self, filesystem: FilesystemOpenOptions) -> Self {
        self.filesystem = filesystem;
        self
    }

    /// Requested block-source selection.
    #[must_use]
    pub const fn source(&self) -> &SourceSelection {
        &self.source
    }

    /// Requested filesystem-open options.
    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemOpenOptions {
        &self.filesystem
    }
}

impl Default for PartitionOpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Open partition `partition` (0-based, counting non-empty entries) on
/// `drive` using the filesystem drivers in `drivers`.
///
/// Works with GPT and MBR partition tables; for a bare (unpartitioned)
/// filesystem, pass `partition = 0` to open the whole disk. The physical
/// drive is opened to read the partition table and reopened if the raw
/// partition becomes the filesystem source.
///
/// A unique operating-system logical volume is required by default. On
/// Windows, this means an OS-unlocked encrypted volume can be read without
/// supplying its key again. Use [`open_device_partition_with_selection`]
/// with [`SourceSelection::Raw`] to bypass the logical view.
///
/// The enumerator type parameter selects the platform: on Windows, Linux,
/// and macOS, use [`HostDrives`].
///
/// # Errors
///
/// Returns an error if the drive cannot be opened, the partition does not
/// exist, the disk layout is unrecognized, or no registered driver can open
/// the detected filesystem (see
/// [`DriverRegistry::open_devices`](fsmnt_device::DriverRegistry::open_devices)).
pub fn open_device_partition<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    open_device_partition_with_options::<E>(drive, partition, drivers, PartitionOpenOptions::new())
}

/// Open a device partition using the requested source selection.
///
/// [`SourceSelection::Auto`] requires a unique operating-system logical
/// volume and never falls back to raw access. [`SourceSelection::Logical`]
/// chooses one logical volume explicitly. [`SourceSelection::Raw`] bypasses
/// logical-volume lookup, discovers filesystem-referenced physical members
/// across host drives, and accepts explicit additional members for devices
/// outside platform enumeration.
///
/// # Errors
///
/// Returns an error if the drive cannot be opened, the partition does not
/// exist, logical-volume selection is impossible or ambiguous, the disk
/// layout is unrecognized, or no registered driver can open the detected
/// filesystem.
pub fn open_device_partition_with_selection<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
    selection: SourceSelection,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    open_device_partition_with_options::<E>(
        drive,
        partition,
        drivers,
        PartitionOpenOptions::new().with_source(selection),
    )
}

/// Open a device partition with independent block-source and filesystem-root
/// selections.
///
/// # Errors
///
/// Returns an error if the selected block view cannot be opened, the
/// filesystem driver rejects the requested root, or parsing fails.
pub fn open_device_partition_with_options<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let located = locate_partition::<E>(drive, partition)?;

    match options.source {
        SourceSelection::Auto => {
            open_logical_partition::<E>(&located, None, drivers, &options.filesystem)
        }
        SourceSelection::Logical(id) => {
            open_logical_partition::<E>(&located, Some(&id), drivers, &options.filesystem)
        }
        SourceSelection::Raw {
            additional_partitions,
        } => open_raw_partitions::<E>(
            &located,
            &additional_partitions,
            drivers,
            &options.filesystem,
        ),
    }
}

#[derive(Clone)]
struct LocatedPartition {
    extent: PhysicalExtent,
    sector_size: u32,
}

fn locate_partition<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    partition: usize,
) -> Result<LocatedPartition, Box<dyn std::error::Error>> {
    locate_partitions::<E>(drive)?
        .get(partition)
        .cloned()
        .ok_or_else(|| format!("partition {partition} not found on drive {drive}").into())
}

fn locate_partitions<E: HostDriveEnumerator>(
    drive: &HostDriveId,
) -> Result<Vec<LocatedPartition>, Box<dyn std::error::Error>> {
    let info = E::get_drive_info(drive).ok();
    let sector_size = info.as_ref().and_then(|i| i.sector_size).unwrap_or(512);

    let reader = E::open_drive(drive)?;
    let mut disk = Disk::with_sector_size(reader, sector_size)?;

    let extents = match disk.layout().clone() {
        DiskLayout::Gpt { .. } => {
            let count = disk.partition_count();
            let mut extents = Vec::new();
            for i in 0..count {
                let entry = disk.gpt_partition(i)?;
                if entry.is_empty() {
                    continue;
                }
                extents.push((
                    entry.start_offset(disk.sector_size()),
                    entry.size_bytes(disk.sector_size()),
                ));
            }
            extents
        }
        DiskLayout::Mbr { .. } => {
            let sector_size = disk.sector_size();
            disk.mbr_partitions()
                .map(|e| (e.start_offset(sector_size), e.size_bytes(sector_size)))
                .collect()
        }
        DiskLayout::Bare(_) => {
            let size = info.as_ref().and_then(|i| i.size_bytes).unwrap_or(0);
            vec![(0, if size == 0 { u64::MAX } else { size })]
        }
        DiskLayout::Unknown => {
            let size = info.as_ref().and_then(|i| i.size_bytes).unwrap_or(0);
            vec![(0, if size == 0 { u64::MAX } else { size })]
        }
    };
    Ok(extents
        .into_iter()
        .map(|(offset, size)| LocatedPartition {
            extent: PhysicalExtent::new(drive.clone(), offset, size),
            sector_size,
        })
        .collect())
}

fn open_logical_partition<E: HostVolumeResolver>(
    located: &LocatedPartition,
    requested: Option<&LogicalVolumeId>,
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let candidates = E::logical_volumes(&located.extent)?;
    let volume = select_logical_volume(&located.extent, &candidates, requested)?;
    let length = volume.length().unwrap_or_else(|| located.extent.length());
    let sector_size = volume.sector_size().unwrap_or(located.sector_size);
    let identity = volume.id().clone();
    let reader = E::open_logical_volume(&volume)?;
    let zone_reporter = E::logical_zone_reporter(&volume)?;
    let reader = SectorReader::new(reader, length, sector_size)?;
    let mut member = DeviceMember::new(
        SourceMemberId::Logical(identity),
        Box::new(reader),
        length,
        sector_size,
    )?;
    if let Some(zone_reporter) = zone_reporter {
        member = member.with_zone_reporter(zone_reporter);
    }
    open_devices(
        DeviceSet::new(member),
        SourceOrigin::Logical(volume),
        length,
        drivers,
        filesystem,
    )
}

fn open_raw_partitions<E: HostVolumeResolver>(
    primary: &LocatedPartition,
    additional: &[PartitionAddress],
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let mut extents = Vec::with_capacity(additional.len().saturating_add(1));
    extents.push(primary.extent.clone());
    let mut primary_member = open_raw_member::<E>(primary)?;
    let primary_discovery = discover_member(drivers, &mut primary_member)?;
    let mut discovered_ids = primary_discovery
        .as_ref()
        .map(|resolved| vec![resolved.discovery().member().clone()])
        .unwrap_or_default();
    let mut devices = DeviceSet::new(primary_member);

    for address in additional {
        let located = locate_partition::<E>(address.drive(), address.partition())?;
        let mut member = open_raw_member::<E>(&located)?;
        if let (Some(primary), Some(candidate)) = (
            primary_discovery.as_ref(),
            discover_member(drivers, &mut member)?,
        ) && member_matches(primary, &candidate, &discovered_ids)
        {
            discovered_ids.push(candidate.discovery().member().clone());
        }
        extents.push(located.extent.clone());
        devices.push(member)?;
    }

    if let Some(discovery) = primary_discovery.as_ref() {
        discover_raw_partitions::<E>(
            primary.extent.drive(),
            discovery,
            &mut discovered_ids,
            &mut devices,
            &mut extents,
            drivers,
        );
    }

    let size = if extents.len() == 1 {
        primary.extent.length()
    } else {
        0
    };
    open_devices(
        devices,
        SourceOrigin::Raw(extents),
        size,
        drivers,
        filesystem,
    )
}

fn discover_member(
    drivers: &DriverRegistry,
    member: &mut DeviceMember,
) -> Result<Option<ResolvedMemberDiscovery>, Box<dyn std::error::Error>> {
    let detected = fsmnt_device::detect_boot_sector_at(member.reader_mut(), 0);
    let restored = std::io::Seek::seek(member.reader_mut(), std::io::SeekFrom::Start(0));
    let detected = match (detected, restored) {
        (Ok(detected), Ok(_)) => detected,
        (Err(error), _) | (Ok(_), Err(error)) => return Err(error.into()),
    };
    Ok(drivers.discover_members(member, detected)?)
}

fn member_matches(
    primary: &ResolvedMemberDiscovery,
    candidate: &ResolvedMemberDiscovery,
    discovered_ids: &[FilesystemMemberId],
) -> bool {
    let candidate_id = candidate.discovery().member();
    primary.driver_name() == candidate.driver_name()
        && primary.discovery().detected() == candidate.discovery().detected()
        && primary.discovery().requires(candidate_id)
        && !discovered_ids.contains(candidate_id)
}

fn discovery_complete(
    primary: &ResolvedMemberDiscovery,
    discovered_ids: &[FilesystemMemberId],
) -> bool {
    primary
        .discovery()
        .required_members()
        .iter()
        .all(|required| discovered_ids.contains(required))
}

fn discover_raw_partitions<E: HostVolumeResolver>(
    primary_drive: &HostDriveId,
    primary: &ResolvedMemberDiscovery,
    discovered_ids: &mut Vec<FilesystemMemberId>,
    devices: &mut DeviceSet,
    extents: &mut Vec<PhysicalExtent>,
    drivers: &DriverRegistry,
) {
    if discovery_complete(primary, discovered_ids) {
        return;
    }

    let mut host_ids = vec![primary_drive.clone()];
    if let Ok(host_drives) = E::enumerate_drives() {
        for info in host_drives {
            if !host_ids.contains(&info.id) {
                host_ids.push(info.id);
            }
        }
    }

    for drive in host_ids {
        let Ok(partitions) = locate_partitions::<E>(&drive) else {
            continue;
        };
        for located in partitions {
            if extents.contains(&located.extent) {
                continue;
            }
            let Ok(mut member) = open_raw_member::<E>(&located) else {
                continue;
            };
            let Ok(Some(candidate)) = discover_member(drivers, &mut member) else {
                continue;
            };
            if !member_matches(primary, &candidate, discovered_ids) {
                continue;
            }
            if devices.push(member).is_err() {
                continue;
            }
            discovered_ids.push(candidate.discovery().member().clone());
            extents.push(located.extent);
            if discovery_complete(primary, discovered_ids) {
                return;
            }
        }
    }
}

fn open_raw_member<E: HostVolumeResolver>(
    located: &LocatedPartition,
) -> Result<DeviceMember, Box<dyn std::error::Error>> {
    let reader = E::open_drive(located.extent.drive())?;
    let zone_reporter = E::physical_zone_reporter(&located.extent)?;
    let partition = PartitionReader::new(reader, located.extent.offset(), located.extent.length());
    let reader = SectorReader::new(partition, located.extent.length(), located.sector_size)?;
    let mut member = DeviceMember::new(
        SourceMemberId::Physical(located.extent.clone()),
        Box::new(reader),
        located.extent.length(),
        located.sector_size,
    )?;
    if let Some(zone_reporter) = zone_reporter {
        member = member.with_zone_reporter(zone_reporter);
    }
    Ok(member)
}

fn open_devices(
    mut devices: DeviceSet,
    source: SourceOrigin,
    size: u64,
    drivers: &DriverRegistry,
    filesystem: &FilesystemOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let detected = fsmnt_device::detect_boot_sector_at(devices.primary_mut().reader_mut(), 0)?;
    std::io::Seek::seek(
        devices.primary_mut().reader_mut(),
        std::io::SeekFrom::Start(0),
    )?;
    let opened = drivers.open_devices_with_options_resolved(devices, detected, filesystem)?;

    let size_bytes = if size == u64::MAX { 0 } else { size };
    // A partition whose size is unknown (0) cannot contradict anything the
    // filesystem claims, so it never reports a shortfall.
    let truncated_by = (size_bytes > 0)
        .then(|| truncation::missing_filesystem_bytes(opened.filesystem.total_size(), size_bytes))
        .flatten();
    Ok(OpenedPartition {
        filesystem: opened.filesystem,
        detected: opened.detected,
        size_bytes,
        truncated_by,
        source,
    })
}

#[cfg(test)]
mod tests;
