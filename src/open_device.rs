//! Opening a filesystem that lives on a physical drive.
//!
//! Three ways to say *where* on the drive, all landing in the same opener:
//! a partition ordinal from the drive's own table
//! ([`open_device_partition`]), the same ordinal counted over the
//! filesystems a scan finds ([`PartitionOpenOptions::with_scan`]), and a
//! bare byte offset ([`open_device_at_offset`]) for media whose table is
//! gone or lies. Every result records which of the three it was in
//! [`OpenedPartition::layout_origin`], because "partition 2 of the GPT",
//! "the third filesystem a scan turned up" and "whatever is at byte
//! 528384" are very different claims to make in a report.
//!
//! *Which view* of those bytes is a separate decision:
//! [`SourceSelection`] chooses between the operating system's logical volume
//! (which reads an OS-unlocked encrypted volume without its key) and raw
//! physical extents. A scanned offset and a byte offset have no logical
//! volume by construction, so both refuse [`SourceSelection::Logical`]
//! rather than quietly reading something else.

mod members;

use std::io::{Read, Seek};
use std::sync::Arc;

use fsmnt_core::TargetFilesystem;
use fsmnt_device::{
    DetectedBootSector, DriverRegistry, FilesystemOpenOptions, FilesystemRoot, HostDriveEnumerator,
    HostDriveId, HostDriveInfo, HostVolumeResolver, PartitionAddress, PartitionReader,
    PhysicalExtent, ReadSubstitutions, SectorReader, SourceOrigin, SourceSelection,
};

use crate::layout::{DEFAULT_SECTOR_SIZE, DriveLayoutOptions, LayoutOrigin};
use members::{ReadPolicy, open_logical_partition, open_raw_partitions};

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
    /// (see [`missing_filesystem_bytes`](crate::missing_filesystem_bytes)).
    pub truncated_by: Option<u64>,
    /// Physical or operating-system logical source actually opened.
    pub source: SourceOrigin,
    /// Running totals of bytes served as zeros in place of data the source
    /// could not provide — present only when opened with
    /// [`PartitionOpenOptions::with_best_effort_reads`]; shared with every
    /// member's reader so a caller can report them after the mount ends.
    pub substitutions: Option<Arc<ReadSubstitutions>>,
    /// How the opened extent was located: the drive's own partition table
    /// ([`LayoutOrigin::Table`]), its backup GPT
    /// ([`LayoutOrigin::BackupTable`]), an unpartitioned whole drive
    /// ([`LayoutOrigin::None`]), a **synthetic** table reconstructed from a
    /// scan ([`LayoutOrigin::Scan`]), or `None` when the caller named a byte
    /// offset and no table was consulted at all. Keep it alongside the mount
    /// if the record has to say how the volume was found.
    pub layout_origin: Option<LayoutOrigin>,
}

/// Independent source-layer, geometry and filesystem-root choices for
/// opening a partition.
#[derive(Clone, Debug)]
pub struct PartitionOpenOptions {
    source: SourceSelection,
    sector_size: Option<u32>,
    scan_stride: Option<u64>,
    best_effort_reads: bool,
    filesystem: FilesystemOpenOptions,
}

impl PartitionOpenOptions {
    /// Use automatic logical-volume selection, the drive's own geometry and
    /// partition table, and the filesystem's default root.
    #[must_use]
    pub fn new() -> Self {
        Self {
            source: SourceSelection::Auto,
            sector_size: None,
            scan_stride: None,
            best_effort_reads: false,
            filesystem: FilesystemOpenOptions::new(),
        }
    }

    /// Zero-fill what the device cannot provide instead of failing the read
    /// — a bad sector, or a partition extent that runs past the end of the
    /// media. Off by default; every substitution is counted in
    /// [`OpenedPartition::substitutions`].
    #[must_use]
    pub const fn with_best_effort_reads(mut self, best_effort: bool) -> Self {
        self.best_effort_reads = best_effort;
        self
    }

    /// Whether reads the device cannot satisfy are zero-filled rather than
    /// failed.
    #[must_use]
    pub const fn best_effort_reads(&self) -> bool {
        self.best_effort_reads
    }

    /// Read the drive's partition table in sectors of `sector_size` bytes
    /// instead of the size the operating system reports for it.
    ///
    /// Supply this for a 4Kn drive presented as 512e (or the reverse): the
    /// table's LBAs count the units it was written in, so a mismatch puts
    /// every partition a factor of eight from where it really is.
    #[must_use]
    pub const fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = Some(sector_size);
        self
    }

    /// The requested sector size, or `None` to use the drive's own.
    #[must_use]
    pub const fn sector_size(&self) -> Option<u32> {
        self.sector_size
    }

    /// Resolve the ordinal handed to
    /// [`open_device_partition_with_options`] against a **synthetic** table
    /// reconstructed by scanning the drive every `stride` bytes for
    /// filesystem starts, rather than against the partition table at the
    /// front of the drive (see [`LayoutOrigin::Scan`]).
    ///
    /// The ordinal then means "the N-th filesystem the scan finds", which
    /// holds only for this drive at this stride. The extent is opened raw
    /// and bounded to the size the filesystem claims for itself, or to the
    /// rest of the drive when the format states none — a scanned position
    /// is not a partition, so there is no table entry to bound it.
    #[must_use]
    pub const fn with_scan(mut self, stride: u64) -> Self {
        self.scan_stride = Some(stride);
        self
    }

    /// The stride of the drive scan a partition ordinal is resolved against,
    /// or `None` when the drive's own partition table is used.
    #[must_use]
    pub const fn scan_stride(&self) -> Option<u64> {
        self.scan_stride
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

    /// Replace every filesystem-level option (root selector, journal
    /// replay, backup-superblock group, salvage) with `filesystem` at once.
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

    /// The read policy these options imply.
    fn read_policy(&self) -> ReadPolicy {
        ReadPolicy::new(self.best_effort_reads)
    }
}

/// The extra raw members a selection names, if any.
///
/// [`SourceSelection::Auto`] reads raw wherever there is no logical volume
/// to select, and a caller in that position never named extra members.
fn raw_members(source: &SourceSelection) -> &[PartitionAddress] {
    match source {
        SourceSelection::Raw {
            additional_partitions,
        } => additional_partitions,
        SourceSelection::Auto | SourceSelection::Logical(_) => &[],
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
/// and macOS, use [`HostDrives`](crate::HostDrives).
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

/// Open a device partition with independent block-source, geometry and
/// filesystem-root selections.
///
/// `partition` counts non-empty partition-table entries from 0, unless
/// [`PartitionOpenOptions::with_scan`] is set, in which case it counts the
/// filesystems a scan of the drive finds.
///
/// # Errors
///
/// Returns an error if the selected block view cannot be opened, the
/// ordinal does not exist, a scan was requested and failed, a scanned
/// ordinal was combined with an explicit logical volume, the filesystem
/// driver rejects the requested root, or parsing fails.
pub fn open_device_partition_with_options<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    if let Some(stride) = options.scan_stride {
        return open_scanned_partition::<E>(drive, partition, stride, drivers, options);
    }
    let located = locate_partition::<E>(drive, partition, options.sector_size)?;
    open_located::<E>(&located, drivers, options)
}

/// Open the raw bytes of `drive` from `offset` to its end.
///
/// The counterpart to
/// [`ImageOpenOptions::with_offset`](crate::ImageOpenOptions::with_offset)
/// for a live drive: no partition table is consulted, so this is the way in
/// when the table is wiped, wrong, or describes a filesystem that has since
/// moved. The offset is physical — it counts from the first byte of the
/// drive, past any logical volume the operating system has laid over it —
/// so [`SourceSelection::Logical`] is refused and
/// [`SourceSelection::Auto`] reads raw.
///
/// # Errors
///
/// Returns an error if the drive cannot be opened, an explicit logical
/// volume was requested, the offset is at or past the end of the drive, the
/// offset holds a partition table rather than a filesystem, or no registered
/// driver can open what is there.
pub fn open_device_at_offset<E: HostVolumeResolver>(
    drive: &HostDriveId,
    offset: u64,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let policy = options.read_policy();
    let PartitionOpenOptions {
        source,
        sector_size: requested_sector_size,
        filesystem,
        ..
    } = options;
    if let SourceSelection::Logical(id) = &source {
        return Err(format!(
            "a byte offset has no logical volume; use --raw or a partition ordinal instead of \
             --volume {id}"
        )
        .into());
    }

    let info = E::get_drive_info(drive).ok();
    let sector_size = resolved_sector_size(requested_sector_size, info.as_ref());
    let mut reader = E::open_drive(drive)?;
    let size_bytes = crate::layout::drive_length(info.as_ref(), &mut reader);
    if let Some(size) = size_bytes
        && offset >= size
    {
        return Err(format!(
            "offset {offset} is at or past the end of drive {drive} ({size} bytes)"
        )
        .into());
    }
    let length = size_bytes.map_or(u64::MAX, |size| size - offset);

    let detected = detect_at_offset(reader, offset, length, sector_size)?;
    if matches!(
        detected,
        DetectedBootSector::MbrPartitioned | DetectedBootSector::GptPartitioned
    ) {
        return Err(format!(
            "drive {drive} contains a partition table at offset {offset} ({detected:?}); select a \
             partition with `--partition N` (see `fsmnt partitions {drive}`)"
        )
        .into());
    }

    let located = LocatedPartition {
        extent: PhysicalExtent::new(drive.clone(), offset, length),
        sector_size,
        // Nothing was read from a table, so there is no provenance to claim.
        origin: None,
    };
    open_raw_partitions::<E>(
        &located,
        raw_members(&source),
        requested_sector_size,
        drivers,
        &filesystem,
        &policy,
    )
}

/// Open an already-located partition through the requested source view.
fn open_located<E: HostVolumeResolver>(
    located: &LocatedPartition,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let policy = options.read_policy();
    let PartitionOpenOptions {
        source,
        sector_size,
        filesystem,
        ..
    } = options;
    match source {
        SourceSelection::Auto => {
            open_logical_partition::<E>(located, None, drivers, &filesystem, &policy)
        }
        SourceSelection::Logical(id) => {
            open_logical_partition::<E>(located, Some(&id), drivers, &filesystem, &policy)
        }
        SourceSelection::Raw {
            additional_partitions,
        } => open_raw_partitions::<E>(
            located,
            &additional_partitions,
            sector_size,
            drivers,
            &filesystem,
            &policy,
        ),
    }
}

/// Resolve `partition` against the filesystems a scan of the drive finds,
/// and open that extent raw.
fn open_scanned_partition<E: HostVolumeResolver>(
    drive: &HostDriveId,
    partition: usize,
    stride: u64,
    drivers: &DriverRegistry,
    options: PartitionOpenOptions,
) -> Result<OpenedPartition, Box<dyn std::error::Error>> {
    let policy = options.read_policy();
    let PartitionOpenOptions {
        source,
        sector_size: requested_sector_size,
        filesystem,
        ..
    } = options;
    if let SourceSelection::Logical(id) = &source {
        return Err(format!(
            "a scanned offset has no logical volume; the scan finds filesystems where they sit on \
             the drive, not the volumes the operating system publishes, so drop --volume {id} or \
             drop --scan"
        )
        .into());
    }

    let mut layout_options = DriveLayoutOptions::new()
        .with_scan(true)
        .with_scan_stride(stride);
    if let Some(sector_size) = requested_sector_size {
        layout_options = layout_options.with_sector_size(sector_size);
    }
    let layout = crate::drive_layout::<E>(drive, layout_options)?;
    let (offset, length) = crate::layout::scanned_extent(&layout, partition).ok_or_else(|| {
        format!(
            "partition {partition} not found on drive {drive}: the scan found {} \
                 filesystem(s); list them with `fsmnt partitions {drive} --scan{}`",
            layout.partitions.len(),
            stride_flag(stride),
        )
    })?;

    let located = LocatedPartition {
        extent: PhysicalExtent::new(drive.clone(), offset, length),
        sector_size: layout.sector_size,
        origin: Some(LayoutOrigin::Scan { stride }),
    };
    open_raw_partitions::<E>(
        &located,
        raw_members(&source),
        requested_sector_size,
        drivers,
        &filesystem,
        &policy,
    )
}

/// The `--stride` a hint has to repeat, or nothing when it is the default.
fn stride_flag(stride: u64) -> String {
    if stride == crate::DEFAULT_STRIDE {
        String::new()
    } else {
        format!(" --stride {stride}")
    }
}

/// Classify the boot sector at `offset` on an opened drive.
///
/// The probe goes through the same bounded, sector-aligned view the
/// filesystem will be opened in, because raw block-device handles reject
/// reads that are not whole sectors.
fn detect_at_offset<R: Read + Seek>(
    reader: R,
    offset: u64,
    length: u64,
    sector_size: u32,
) -> std::io::Result<DetectedBootSector> {
    let length = whole_sectors(length, sector_size);
    let window = PartitionReader::new(reader, offset, length);
    let mut window = SectorReader::new(window, length, sector_size)?;
    fsmnt_device::detect_boot_sector_at(&mut window, 0)
}

/// The sector size to read a drive in: the caller's override, else what the
/// operating system reports, else the 512 bytes almost everything uses.
fn resolved_sector_size(requested: Option<u32>, info: Option<&HostDriveInfo>) -> u32 {
    requested
        .or_else(|| info.and_then(|info| info.sector_size))
        .filter(|size| size.is_power_of_two())
        .unwrap_or(DEFAULT_SECTOR_SIZE)
}

/// Longest whole-sector prefix of `length`.
///
/// [`SectorReader`] reads complete sectors and refuses a length that is not
/// a multiple of one, so an extent ending mid-sector — or one of the
/// [`u64::MAX`] "to the end of an unmeasurable drive" lengths — is presented
/// as the sectors it fully covers.
pub(crate) fn whole_sectors(length: u64, sector_size: u32) -> u64 {
    let sector = u64::from(sector_size.max(1));
    length - length % sector
}

/// A partition extent resolved to the drive bytes that hold it.
#[derive(Clone)]
pub(crate) struct LocatedPartition {
    /// Where the partition sits on which drive.
    pub(crate) extent: PhysicalExtent,
    /// Sector size its reads are aligned to.
    pub(crate) sector_size: u32,
    /// Where the entry describing it was read from, or `None` for a
    /// caller-supplied byte offset.
    pub(crate) origin: Option<LayoutOrigin>,
}

/// Resolve one partition ordinal on `drive` to its extent.
pub(crate) fn locate_partition<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    partition: usize,
    sector_size: Option<u32>,
) -> Result<LocatedPartition, Box<dyn std::error::Error>> {
    locate_partitions::<E>(drive, sector_size)?
        .get(partition)
        .cloned()
        .ok_or_else(|| format!("partition {partition} not found on drive {drive}").into())
}

/// Enumerate every partition on `drive` as an openable extent.
///
/// The ordinals are [`drive_layout`](crate::drive_layout)'s, because both
/// read the same table through the same [`Disk`](fsmnt_device::Disk).
pub(crate) fn locate_partitions<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    sector_size: Option<u32>,
) -> Result<Vec<LocatedPartition>, Box<dyn std::error::Error>> {
    let mut options = DriveLayoutOptions::new();
    if let Some(sector_size) = sector_size {
        options = options.with_sector_size(sector_size);
    }
    let layout = crate::drive_layout::<E>(drive, options)?;
    Ok(layout
        .partitions
        .iter()
        .map(|partition| {
            // An unpartitioned drive whose size the operating system will
            // not state has no bound to give: u64::MAX is how the rest of
            // the device layer spells "to the end, however far that is".
            let length = if partition.size_bytes == 0 {
                u64::MAX
            } else {
                partition.size_bytes
            };
            LocatedPartition {
                extent: PhysicalExtent::new(drive.clone(), partition.offset, length),
                sector_size: layout.sector_size,
                origin: Some(layout.origin),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests;
