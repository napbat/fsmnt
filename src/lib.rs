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

pub use fsmnt_core::{
    DirFilesystem, FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, Fstab, FstabEntry,
    FstabParseError, FstabSource, MountNamespace, TargetFilesystem, filter_entries, normalize_path,
};

pub use fsmnt_device as device;
pub use fsmnt_device::{ImageContainer, ImageFormat, ImageOpenError, ImageReader};
pub use fsmnt_drivers as drivers;
pub use fsmnt_proxy as proxy;

mod fstab_mount;
mod image_layout;

pub use fstab_mount::open_device_partition_with_fstab;
pub use image_layout::{ImageLayout, ImageLayoutKind, ImagePartition, image_layout};

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

/// A filesystem opened from a decoded disk-image container, ready to mount.
pub struct OpenedImage {
    /// The filesystem opened by a registered driver.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// The detected boot-sector type at the selected image offset.
    pub detected: DetectedBootSector,
    /// Byte offset the filesystem was opened at within the decoded media.
    /// For a selected partition this is the partition's start, not the
    /// offset originally requested.
    pub offset: u64,
    /// Size of the selected decoded media range in bytes.
    pub size_bytes: u64,
    /// Container format used to expose the decoded media.
    pub format: ImageFormat,
}

/// Failure to decode an image or open a filesystem within its virtual media.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OpenImageError {
    /// The image container could not be opened or decoded.
    #[error(transparent)]
    Container(#[from] ImageOpenError),
    /// The selected byte offset does not address decoded media.
    #[error("offset {offset} is at or past the end of {path:?} ({size_bytes} decoded bytes)")]
    OffsetOutOfRange {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Requested decoded-media offset.
        offset: u64,
        /// Total decoded-media size.
        size_bytes: u64,
    },
    /// The selected offset identifies another partition table.
    #[error(
        "{path:?} contains a partition table at offset {offset} ({detected:?}); select a partition with `--partition N` (see `fsmnt partitions {}`)",
        path.display()
    )]
    PartitionTable {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset that contains the partition table.
        offset: u64,
        /// Partition-table type detected at the offset.
        detected: DetectedBootSector,
    },
    /// The image layout could not be read to enumerate its partitions.
    #[error("failed to read the partition layout of {path:?}: {source}")]
    Layout {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// The requested partition ordinal is not present in the image.
    #[error(
        "partition {partition} not found in {path:?}: the image has {available} partition(s); list them with `fsmnt partitions {}`",
        path.display()
    )]
    PartitionNotFound {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Requested 0-based partition ordinal.
        partition: usize,
        /// Number of partitions the image actually exposes.
        available: usize,
    },
    /// The selected offset holds an ext *backup* superblock, not the start
    /// of a filesystem.
    ///
    /// Backup copies sit partway into an ext filesystem (with
    /// `sparse_super`, at block groups 1, 3, 5, 7, 9, 25, 27, …). Opening
    /// from one would locate every structure relative to the wrong place
    /// and present an empty volume, so it is refused with the group number
    /// as a hint that the real start is earlier.
    #[error(
        "offset {offset} in {path:?} holds an ext backup superblock (block group {group}), not the start of a filesystem; the primary lies earlier — list partitions with `fsmnt partitions {}`",
        path.display()
    )]
    ExtBackupSuperblock {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset that holds the backup copy.
        offset: u64,
        /// Block group the backup superblock belongs to.
        group: u16,
    },
    /// Reading or classifying the selected boot sector failed.
    #[error("failed to detect a filesystem at offset {offset} in {path:?}: {source}")]
    Detection {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset being inspected.
        offset: u64,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// A registered filesystem driver could not open the detected media.
    #[error("failed to open {detected:?} at offset {offset} in {path:?}: {source}")]
    Filesystem {
        /// Image path supplied by the caller.
        path: std::path::PathBuf,
        /// Decoded-media offset handed to the driver.
        offset: u64,
        /// Filesystem type detected at the offset.
        detected: DetectedBootSector,
        /// Driver or filesystem parser failure.
        #[source]
        source: FsError,
    },
}

/// Location and filesystem-root choices for opening a disk image.
#[derive(Clone, Debug)]
pub struct ImageOpenOptions {
    offset: u64,
    partition: Option<usize>,
    filesystem: FilesystemOpenOptions,
}

impl ImageOpenOptions {
    /// Use the beginning of the decoded image and the filesystem's default
    /// root.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            offset: 0,
            partition: None,
            filesystem: FilesystemOpenOptions::new(),
        }
    }

    /// Select the byte offset of the filesystem within decoded image media.
    ///
    /// Use this for media whose filesystem no partition table describes;
    /// prefer [`with_partition`](Self::with_partition) for a partitioned
    /// whole-disk image.
    #[must_use]
    pub const fn with_offset(mut self, offset: u64) -> Self {
        self.offset = offset;
        self
    }

    /// Select a partition of the image by its ordinal, counting non-empty
    /// partition-table entries from 0 — the same numbering
    /// [`image_layout`] prints and `mount-device --partition` uses.
    ///
    /// The partition's own start offset and length bound the filesystem, so
    /// this supersedes [`with_offset`](Self::with_offset): any offset set
    /// alongside a partition is ignored, and callers that select a partition
    /// should leave the offset at 0.
    #[must_use]
    pub const fn with_partition(mut self, partition: usize) -> Self {
        self.partition = Some(partition);
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

    /// Byte offset of the filesystem within decoded image media. Ignored
    /// when [`partition`](Self::partition) selects a partition.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Partition ordinal to open, if one was selected.
    #[must_use]
    pub const fn partition(&self) -> Option<usize> {
        self.partition
    }

    /// Requested filesystem-open options.
    #[must_use]
    pub const fn filesystem(&self) -> &FilesystemOpenOptions {
        &self.filesystem
    }
}

impl Default for ImageOpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Open a filesystem at the beginning of a supported disk image.
///
/// EWF container signatures are detected automatically and sibling segments
/// are discovered from the supplied segment path. Fixed, dynamic, and
/// differencing VHD/VHDX containers are decoded into virtual media; parent
/// locators resolve accessible `.avhd` and `.avhdx` chains. Use
/// [`open_image_with_options`] when the decoded image starts with a partition
/// table or when a non-default filesystem root is needed.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, its selected
/// range is empty, it starts with a partition table, filesystem detection
/// fails, or no registered driver can open it.
pub fn open_image(
    path: impl AsRef<std::path::Path>,
    drivers: &DriverRegistry,
) -> Result<OpenedImage, OpenImageError> {
    open_image_with_options(path, drivers, ImageOpenOptions::new())
}

/// Open a filesystem from a supported disk image with explicit options.
///
/// A partitioned whole-disk image is addressed by partition ordinal with
/// [`ImageOpenOptions::with_partition`], which bounds the filesystem to that
/// partition's extent; [`image_layout`] lists the ordinals. Without a
/// partition the offset is used as-is, addressing decoded logical media
/// rather than EWF segment bytes or VHD/VHDX container storage, and the
/// filesystem spans the rest of the image.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, the selected
/// partition does not exist, the resolved offset is at or past the end of
/// the decoded image, the selected range starts with a partition table,
/// filesystem detection fails, or no registered driver can open the detected
/// filesystem and requested root.
pub fn open_image_with_options(
    path: impl AsRef<std::path::Path>,
    drivers: &DriverRegistry,
    options: ImageOpenOptions,
) -> Result<OpenedImage, OpenImageError> {
    let path = path.as_ref();
    let ImageOpenOptions {
        offset,
        partition,
        filesystem,
    } = options;
    let (mut image, offset, size_bytes) = if let Some(partition) = partition {
        image_layout::locate_image_partition(path, partition)?
    } else {
        open_image_tail(path, offset)?
    };

    let detected = fsmnt_device::detect_boot_sector_at(&mut image, offset).map_err(|source| {
        OpenImageError::Detection {
            path: path.to_path_buf(),
            offset,
            source,
        }
    })?;
    if matches!(
        detected,
        DetectedBootSector::MbrPartitioned | DetectedBootSector::GptPartitioned
    ) {
        return Err(OpenImageError::PartitionTable {
            path: path.to_path_buf(),
            offset,
            detected,
        });
    }
    if detected == DetectedBootSector::Unknown {
        // Detection refuses ext backup superblocks; say so precisely rather
        // than "no filesystem driver for Unknown" — the offset came from a
        // magic-number scan more often than not, and the group number tells
        // the user how far back the real start is.
        let backup =
            fsmnt_device::ext_backup_superblock_at(&mut image, offset).map_err(|source| {
                OpenImageError::Detection {
                    path: path.to_path_buf(),
                    offset,
                    source,
                }
            })?;
        if let Some(group) = backup {
            return Err(OpenImageError::ExtBackupSuperblock {
                path: path.to_path_buf(),
                offset,
                group,
            });
        }
    }

    let format = image.format();
    let reader = PartitionReader::new(image, offset, size_bytes);
    let filesystem = drivers
        .open_with_options(Box::new(reader), detected, &filesystem)
        .map_err(|source| OpenImageError::Filesystem {
            path: path.to_path_buf(),
            offset,
            detected,
            source,
        })?;

    Ok(OpenedImage {
        filesystem,
        detected,
        offset,
        size_bytes,
        format,
    })
}

/// Open the decoded media and take everything from `offset` to its end.
///
/// This is the no-partition path: without a partition table entry to bound
/// the filesystem, the rest of the image is all the extent there is.
fn open_image_tail(
    path: &std::path::Path,
    offset: u64,
) -> Result<(ImageReader, u64, u64), OpenImageError> {
    let image = ImageReader::open(path)?;
    let image_size = image.len();
    if offset >= image_size {
        return Err(OpenImageError::OffsetOutOfRange {
            path: path.to_path_buf(),
            offset,
            size_bytes: image_size,
        });
    }
    Ok((image, offset, image_size - offset))
}

/// A partition opened from a block device, ready to mount.
pub struct OpenedPartition {
    /// The filesystem opened by a registered driver.
    pub filesystem: Box<dyn TargetFilesystem>,
    /// The detected boot-sector type of the partition.
    pub detected: DetectedBootSector,
    /// Size of the partition in bytes (0 if unknown).
    pub size_bytes: u64,
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

    Ok(OpenedPartition {
        filesystem: opened.filesystem,
        detected: opened.detected,
        size_bytes: if size == u64::MAX { 0 } else { size },
        source,
    })
}

#[cfg(test)]
mod tests;
