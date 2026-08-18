//! The `--json` wire format: what a program reads instead of the tables.
//!
//! Every command already gathers typed facts — offsets, byte counts,
//! provenance — and then spends them on a column layout. The types here are
//! that gathering, kept as numbers and enums, so a handler builds one report
//! and hands it either to the human printer or to [`print_document`]. There
//! is no second pass over the media for a machine reader, and no table to
//! scrape.
//!
//! The schema is the CLI's own, deliberately: the library types it converts
//! from are free to rename fields, split enums or grow variants without that
//! reaching a script. [`SCHEMA`] is bumped only when a field here changes
//! meaning or disappears — adding one is not a break, so a reader must
//! ignore what it does not know.
//!
//! Two rules hold everywhere. Numbers are JSON numbers, never formatted
//! strings: sizes are raw byte counts, and nothing is rounded to `1.5 GB`
//! for a program that wants to subtract it. Anything unknown, absent, or
//! inapplicable is `null` rather than a missing key or a placeholder, so a
//! reader can index a field it expects instead of testing for it — which is
//! also why an ordinal a person sees as `-` is `null` here.

use serde::{Serialize, Serializer};

use fsmnt::device::{DetectedBootSector, HostDriveBusType, HostDriveInfo, ReadSubstitutions};
use fsmnt::{
    DriveLayout, ImageFormat, ImageLayout, LayoutKind, LayoutOrigin, LayoutPartition, ScanHit,
};

use super::source::Source;

/// Version of every document and event below.
///
/// One integer for the whole surface rather than one per document: a reader
/// checks it once, and the CLI does not have to explain which of five
/// numbers applies to the thing it just parsed.
pub(crate) const SCHEMA: u32 = 1;

/// Who the command is speaking to.
///
/// Chosen once, from the global `--json`, and carried into every handler.
/// The two arms are exclusive by design: in JSON mode stdout carries JSON
/// and nothing else, so a reader can parse the whole stream without
/// skipping prose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Output {
    /// Aligned tables, hints, and the mount lifecycle lines.
    Human,
    /// One JSON document per command, or one event per line for `mount`.
    Json,
}

impl Output {
    /// What `--json` selects.
    pub(crate) const fn new(json: bool) -> Self {
        if json { Self::Json } else { Self::Human }
    }

    /// Whether stdout is reserved for JSON.
    pub(crate) const fn is_json(self) -> bool {
        matches!(self, Self::Json)
    }
}

/// Print one complete document on stdout, ending the line.
///
/// Pretty-printed: `drives`, `partitions`, `scan` and `unmount` each emit a
/// single document, so the whole of stdout is one value and the newlines
/// inside it cost a reader nothing.
pub(crate) fn print_document(document: &impl Serialize) {
    println!("{}", render(document, true));
}

/// Print one event of a stream as a single line (NDJSON).
///
/// A mount reports as it happens — opened, mounted, unmounted — and the
/// process may live for hours between them, so each event is one line a
/// reader can act on the moment it arrives.
pub(crate) fn print_event(event: &impl Serialize) {
    println!("{}", render(event, false));
}

/// Render a report as JSON text.
///
/// # Panics
///
/// Panics if serialization fails, which the types in this module make
/// impossible: they are plain data with string keys, finite numbers, and no
/// borrowed lifetimes that could outlive the value.
fn render(value: &impl Serialize, pretty: bool) -> String {
    let rendered = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    };
    rendered.expect("the report types are plain data and always serialize")
}

/// A length the medium may not know, as the wire spells it.
///
/// The layout types use 0 for "unknown, running to the end", which as a
/// number reads like an empty extent. `null` says the same thing without
/// asserting a size.
pub(crate) const fn media_size(bytes: u64) -> Option<u64> {
    if bytes == 0 { None } else { Some(bytes) }
}

/// One name per filesystem, used by every document here.
///
/// Deliberately not [`fs_label`](super::fs_label): that one also becomes the
/// `--fsname` an operating system displays, where `bitlocker+ntfs` and
/// `extfs` are what a person wants to read. A wire format wants one lowercase
/// token per format, and the same token wherever the format appears.
pub(crate) const fn json_fs_label(detected: DetectedBootSector) -> &'static str {
    use DetectedBootSector as D;
    match detected {
        D::Ntfs => "ntfs",
        D::BitLocker => "bitlocker",
        D::Fat12 => "fat12",
        D::Fat16 => "fat16",
        D::Fat32 => "fat32",
        D::ExFat => "exfat",
        D::Ext => "ext",
        D::Apfs => "apfs",
        D::Btrfs => "btrfs",
        D::MbrPartitioned => "mbr",
        D::GptPartitioned => "gpt",
        D::Unknown => "unknown",
    }
}

/// Serialize a detected filesystem as its wire name.
#[allow(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde hands a `serialize_with` helper the field by reference, whatever its size, \
              so the signature is prescribed rather than chosen"
)]
fn serialize_filesystem<S: Serializer>(
    detected: &Option<DetectedBootSector>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    detected.map(json_fs_label).serialize(serializer)
}

/// Serialize a container format as `raw`, `ewf`, `vhd` or `vhdx`.
#[allow(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde hands a `serialize_with` helper the field by reference, whatever its size, \
              so the signature is prescribed rather than chosen"
)]
fn serialize_format<S: Serializer>(
    format: &Option<ImageFormat>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    format
        .map(|format| format.to_string().to_lowercase())
        .serialize(serializer)
}

/// Serialize a bus type as its display name, lowercased.
#[allow(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde hands a `serialize_with` helper the field by reference, whatever its size, \
              so the signature is prescribed rather than chosen"
)]
fn serialize_bus<S: Serializer>(
    bus: &Option<HostDriveBusType>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    bus.map(|bus| bus.to_string().to_lowercase())
        .serialize(serializer)
}

/// Serialize the partition table, or the lack of one.
fn serialize_table<S: Serializer>(kind: &LayoutKind, serializer: S) -> Result<S::Ok, S::Error> {
    let name = match kind {
        LayoutKind::Gpt => "gpt",
        LayoutKind::Mbr => "mbr",
        LayoutKind::Bare(_) => "bare",
        LayoutKind::Unknown => "unknown",
        LayoutKind::Scanned => "scanned",
    };
    serializer.serialize_str(name)
}

/// The wire name for where a layout's entries came from.
const fn origin_name(origin: LayoutOrigin) -> &'static str {
    match origin {
        LayoutOrigin::Table => "table",
        LayoutOrigin::BackupTable => "backup_table",
        LayoutOrigin::Scan { .. } => "scan",
        LayoutOrigin::None => "none",
    }
}

/// Serialize the provenance of a layout.
fn serialize_origin<S: Serializer>(
    origin: &LayoutOrigin,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(origin_name(*origin))
}

/// Serialize the provenance of a mount, which may have consulted no table.
#[allow(
    clippy::ref_option,
    clippy::trivially_copy_pass_by_ref,
    reason = "serde hands a `serialize_with` helper the field by reference, whatever its size, \
              so the signature is prescribed rather than chosen"
)]
fn serialize_mount_origin<S: Serializer>(
    origin: &Option<LayoutOrigin>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    origin.map(origin_name).serialize(serializer)
}

/// The stride a scanned layout was built with, and nothing for a table that
/// was read rather than invented.
const fn scan_stride(origin: LayoutOrigin) -> Option<u64> {
    match origin {
        LayoutOrigin::Scan { stride } => Some(stride),
        LayoutOrigin::Table | LayoutOrigin::BackupTable | LayoutOrigin::None => None,
    }
}

/// The filesystem occupying a medium that carries no partition table.
const fn bare_filesystem(kind: &LayoutKind) -> Option<DetectedBootSector> {
    match kind {
        LayoutKind::Bare(detected) => Some(*detected),
        LayoutKind::Gpt | LayoutKind::Mbr | LayoutKind::Unknown | LayoutKind::Scanned => None,
    }
}

/// Which source a document is about, as the command line named it.
///
/// A driver that enumerated with `partitions` and then mounts has to be able
/// to pass the same word back, so the path is the text that was typed and
/// the drive is the ID `fsmnt drives` prints. The key that does not apply is
/// `null` rather than absent, so `source.path ?? source.id` needs no
/// membership test.
#[derive(Debug, Serialize)]
pub(crate) struct SourceRef {
    /// `image`, `drive`, or `directory`.
    kind: &'static str,
    /// Image or directory path, exactly as it was written.
    path: Option<String>,
    /// Drive ID, for a drive.
    id: Option<String>,
}

impl SourceRef {
    /// Name the resolved source.
    pub(crate) fn new(source: &Source) -> Self {
        match source {
            Source::Directory(path) => Self {
                kind: "directory",
                path: Some(path.display().to_string()),
                id: None,
            },
            Source::Image(path) => Self {
                kind: "image",
                path: Some(path.display().to_string()),
                id: None,
            },
            Source::Drive(drive) => Self {
                kind: "drive",
                path: None,
                id: Some(drive.to_string()),
            },
        }
    }
}

/// The physical drives on this machine.
#[derive(Debug, Serialize)]
pub(crate) struct DrivesDocument {
    /// Wire-format version.
    schema: u32,
    /// Document kind, so one field dispatches a reader.
    kind: &'static str,
    /// Every drive the platform enumerator returned, in its order.
    pub(crate) drives: Vec<DriveEntry>,
}

impl DrivesDocument {
    /// Report what the enumerator found.
    pub(crate) fn new(drives: &[HostDriveInfo]) -> Self {
        Self {
            schema: SCHEMA,
            kind: "drives",
            drives: drives.iter().map(DriveEntry::new).collect(),
        }
    }
}

/// One physical drive.
#[derive(Debug, Serialize)]
pub(crate) struct DriveEntry {
    /// The ID every other command takes as a `SOURCE`.
    pub(crate) id: String,
    /// Operating-system device path.
    pub(crate) path: String,
    /// Length in bytes, when the operating system reports one.
    pub(crate) size_bytes: Option<u64>,
    /// Logical sector size in bytes.
    pub(crate) sector_size: Option<u32>,
    /// Device model.
    pub(crate) model: Option<String>,
    /// Device serial number.
    pub(crate) serial_number: Option<String>,
    /// Bus the drive is attached to.
    #[serde(serialize_with = "serialize_bus")]
    pub(crate) bus: Option<HostDriveBusType>,
    /// Whether the media is removable.
    pub(crate) removable: Option<bool>,
    /// Whether this process can read the drive.
    pub(crate) accessible: bool,
    /// Why it cannot, when it cannot.
    pub(crate) access_error: Option<String>,
}

impl DriveEntry {
    /// Convert one enumerated drive.
    fn new(info: &HostDriveInfo) -> Self {
        Self {
            id: info.id.to_string(),
            path: info.path.display().to_string(),
            size_bytes: info.size_bytes,
            sector_size: info.sector_size,
            model: info.model.clone(),
            serial_number: info.serial_number.clone(),
            bus: info.bus_type,
            removable: info.removable,
            accessible: info.accessible,
            access_error: info.access_error.clone(),
        }
    }
}

/// What a medium contains, as `partitions` reports it.
///
/// The same document for an image and for a drive, because they describe the
/// same partitions: the fields only one of them can fill — the container
/// format, the drive model, the operating system's volumes — are `null` on
/// the other rather than absent.
#[derive(Debug, Serialize)]
pub(crate) struct PartitionsDocument {
    /// Wire-format version.
    schema: u32,
    /// Document kind.
    kind: &'static str,
    /// The medium these partitions are on.
    source: SourceRef,
    /// Container format, for an image.
    #[serde(serialize_with = "serialize_format")]
    pub(crate) format: Option<ImageFormat>,
    /// Drive model, for a drive.
    pub(crate) model: Option<String>,
    /// Length of the medium.
    pub(crate) size_bytes: Option<u64>,
    /// Logical sector size the table was read in.
    pub(crate) sector_size: u32,
    /// Whether that size was inferred rather than stated.
    pub(crate) sector_size_auto_detected: bool,
    /// The partition table, or the lack of one.
    #[serde(serialize_with = "serialize_table")]
    pub(crate) table: LayoutKind,
    /// Where the entries came from — read, recovered, or invented.
    #[serde(serialize_with = "serialize_origin")]
    pub(crate) origin: LayoutOrigin,
    /// Stride of the scan that built a synthetic table.
    pub(crate) scan_stride: Option<u64>,
    /// Filesystem occupying the whole medium, when it carries no table.
    #[serde(serialize_with = "serialize_filesystem")]
    pub(crate) bare_filesystem: Option<DetectedBootSector>,
    /// The entries, in listing order.
    pub(crate) partitions: Vec<PartitionEntry>,
}

impl PartitionsDocument {
    /// Report the layout of a disk image.
    pub(crate) fn from_image(source: &Source, layout: &ImageLayout) -> Self {
        Self {
            schema: SCHEMA,
            kind: "partitions",
            source: SourceRef::new(source),
            format: Some(layout.format),
            model: None,
            size_bytes: media_size(layout.size_bytes),
            sector_size: layout.sector_size,
            sector_size_auto_detected: layout.sector_size_auto_detected,
            table: layout.kind.clone(),
            origin: layout.origin,
            scan_stride: scan_stride(layout.origin),
            bare_filesystem: bare_filesystem(&layout.kind),
            partitions: layout
                .partitions
                .iter()
                .map(|partition| PartitionEntry::new(partition, None))
                .collect(),
        }
    }

    /// Report the layout of a physical drive.
    ///
    /// `volumes` answers, for one partition, which operating-system logical
    /// volumes are laid over it — `None` when that could not be established,
    /// which is a different fact from there being none.
    pub(crate) fn from_drive(
        source: &Source,
        model: Option<String>,
        layout: &DriveLayout,
        volumes: impl Fn(&LayoutPartition) -> Option<Vec<VolumeEntry>>,
    ) -> Self {
        Self {
            schema: SCHEMA,
            kind: "partitions",
            source: SourceRef::new(source),
            format: None,
            model,
            size_bytes: media_size(layout.size_bytes),
            sector_size: layout.sector_size,
            sector_size_auto_detected: layout.sector_size_auto_detected,
            table: layout.kind.clone(),
            origin: layout.origin,
            scan_stride: scan_stride(layout.origin),
            bare_filesystem: bare_filesystem(&layout.kind),
            partitions: layout
                .partitions
                .iter()
                .map(|partition| PartitionEntry::new(partition, volumes(partition)))
                .collect(),
        }
    }
}

/// One entry of a partition listing.
#[derive(Debug, Serialize)]
pub(crate) struct PartitionEntry {
    /// The number `--partition` takes, or `null` for an entry that exists to
    /// be seen rather than selected.
    pub(crate) ordinal: Option<usize>,
    /// GPT label, when the table stores one.
    pub(crate) name: Option<String>,
    /// Partition type as the table names it.
    #[serde(rename = "type")]
    pub(crate) type_name: Option<String>,
    /// Byte offset of the partition start within the medium.
    pub(crate) offset: u64,
    /// Length the table declares.
    pub(crate) size_bytes: Option<u64>,
    /// How much of that length the medium does not carry.
    pub(crate) missing_bytes: u64,
    /// How much of it the medium does carry.
    pub(crate) available_bytes: Option<u64>,
    /// Filesystem detected at the start, or `null` when those bytes could
    /// not be read.
    #[serde(serialize_with = "serialize_filesystem")]
    pub(crate) filesystem: Option<DetectedBootSector>,
    /// Whether the medium carries none of this partition at all.
    pub(crate) beyond_end: bool,
    /// Whether the medium carries some but not all of it.
    pub(crate) truncated: bool,
    /// Bytes of this filesystem that lie *before* the medium.
    pub(crate) head_absent: Option<u64>,
    /// Operating-system logical volumes over this extent; `null` for an
    /// image, and for a drive whose volumes could not be resolved.
    pub(crate) volumes: Option<Vec<VolumeEntry>>,
}

impl PartitionEntry {
    /// Convert one layout entry.
    fn new(partition: &LayoutPartition, volumes: Option<Vec<VolumeEntry>>) -> Self {
        let size_bytes = media_size(partition.size_bytes);
        Self {
            ordinal: partition.ordinal,
            name: partition.name.clone(),
            type_name: partition.type_name.clone(),
            offset: partition.offset,
            size_bytes,
            missing_bytes: partition.missing_bytes,
            // Nothing bounds an extent of unknown length, so nothing can be
            // said about how much of it is present either.
            available_bytes: size_bytes.map(|_| partition.available_bytes()),
            filesystem: partition.detected,
            beyond_end: size_bytes.is_some() && partition.is_beyond_end(),
            truncated: partition.is_truncated(),
            head_absent: partition.head_absent,
            volumes,
        }
    }
}

/// One operating-system logical volume over a partition.
#[derive(Debug, Serialize)]
pub(crate) struct VolumeEntry {
    /// The identifier `--volume` takes.
    pub(crate) id: String,
    /// Where the operating system has it mounted, if anywhere.
    pub(crate) mount_points: Vec<String>,
}

/// What a scan of a medium found.
#[derive(Debug, Serialize)]
pub(crate) struct ScanDocument {
    /// Wire-format version.
    schema: u32,
    /// Document kind.
    kind: &'static str,
    /// The medium that was searched.
    source: SourceRef,
    /// Distance in bytes between the positions that were tested.
    pub(crate) stride: u64,
    /// Sector size the offsets are also reported in.
    pub(crate) sector_size: u32,
    /// Length of the medium.
    pub(crate) size_bytes: Option<u64>,
    /// Container format, for an image.
    #[serde(serialize_with = "serialize_format")]
    pub(crate) format: Option<ImageFormat>,
    /// Every hit, in scan order.
    pub(crate) hits: Vec<ScanHitEntry>,
}

impl ScanDocument {
    /// Report a completed scan.
    ///
    /// The entries are built by the caller because the `note` on each one is
    /// the same sentence the table prints, and that wording belongs with the
    /// rest of the scan's prose rather than here.
    pub(crate) fn new(
        source: &Source,
        stride: u64,
        sector_size: u32,
        size_bytes: Option<u64>,
        format: Option<ImageFormat>,
        hits: Vec<ScanHitEntry>,
    ) -> Self {
        Self {
            schema: SCHEMA,
            kind: "scan",
            source: SourceRef::new(source),
            stride,
            sector_size,
            size_bytes,
            format,
            hits,
        }
    }
}

/// One thing a scan found at one offset.
///
/// The fields that only one kind of hit can fill — the block group of a
/// backup superblock, the extent of a run of superblock copies — are `null`
/// on the others, so `kind` is the only branch a reader needs.
#[derive(Debug, Serialize)]
pub(crate) struct ScanHitEntry {
    /// Byte offset in the medium.
    pub(crate) offset: u64,
    /// The same offset in sectors, when it is a whole number of them.
    pub(crate) sector: Option<u64>,
    /// `filesystem`, `partition_table`, `ext_backup_superblock`, or
    /// `ext_primary_copies`.
    pub(crate) kind: &'static str,
    /// The format the hit is evidence of.
    #[serde(serialize_with = "serialize_filesystem")]
    pub(crate) filesystem: Option<DetectedBootSector>,
    /// Size the structure claims for its filesystem.
    pub(crate) size_bytes: Option<u64>,
    /// The offset `--offset` would take, when the hit is mountable at one.
    pub(crate) mount_offset: Option<u64>,
    /// The synthetic `#` that `--scan --partition` takes, counting mountable
    /// hits in scan order.
    pub(crate) ordinal: Option<usize>,
    /// Backup superblocks that corroborate this hit.
    pub(crate) backup_superblocks: Vec<BackupSuperblockEntry>,
    /// Block group of a lone backup superblock.
    pub(crate) group: Option<u16>,
    /// Offset its filesystem would have started at.
    pub(crate) filesystem_start: Option<u64>,
    /// How far before this medium that start falls, when it does.
    pub(crate) start_before_medium: Option<u64>,
    /// How many superblock copies were folded into this hit.
    pub(crate) copies: Option<usize>,
    /// Offset of the last of them.
    pub(crate) last_offset: Option<u64>,
    /// What the hit is evidence of, in the words the table prints.
    pub(crate) note: String,
    /// The arguments to append to `fsmnt mount SOURCE MOUNTPOINT` to open
    /// this hit, or `null` when nothing here can be mounted. A list, not a
    /// command line, so a caller passes it on without quoting anything.
    pub(crate) mount_command: Option<Vec<String>>,
}

/// One ext superblock copy.
#[derive(Debug, Serialize)]
pub(crate) struct BackupSuperblockEntry {
    /// Byte offset of the copy.
    pub(crate) offset: u64,
    /// Block group it belongs to.
    pub(crate) group: u16,
}

impl BackupSuperblockEntry {
    /// The copies folded into one hit.
    pub(crate) fn all(hit: &ScanHit) -> Vec<Self> {
        hit.backup_superblocks
            .iter()
            .map(|backup| Self {
                offset: backup.offset,
                group: backup.group,
            })
            .collect()
    }
}

/// Everything a mount knows about itself once it is open.
///
/// One value for both audiences: [`block_on_mount`](super::block_on_mount)
/// hands its fields to the mount backend and, in JSON mode, prints them as
/// the `opened` event before the volume appears.
#[derive(Debug)]
pub(crate) struct MountReport {
    /// The source that was opened.
    pub(crate) source: SourceRef,
    /// Filesystem label: the detected type, or `directory`.
    pub(crate) filesystem: &'static str,
    /// Volume label the operating system shows.
    pub(crate) volname: String,
    /// Filesystem type label reported to the operating system.
    pub(crate) fsname: String,
    /// Byte offset the filesystem was opened at, where one applies.
    pub(crate) offset: Option<u64>,
    /// Partition ordinal that was selected, when one was.
    pub(crate) partition: Option<usize>,
    /// Length of the opened volume.
    pub(crate) size_bytes: Option<u64>,
    /// How the extent was located.
    pub(crate) layout_origin: Option<LayoutOrigin>,
    /// Bytes the filesystem claims that the medium does not carry.
    pub(crate) truncated_by: Option<u64>,
    /// Bytes of the filesystem in front of the medium.
    pub(crate) head_absent: Option<u64>,
}

/// The volume is open and about to be presented.
#[derive(Debug, Serialize)]
pub(crate) struct OpenedEvent<'a> {
    /// Wire-format version.
    schema: u32,
    /// Event name.
    event: &'static str,
    /// The source that was opened.
    source: &'a SourceRef,
    /// Detected filesystem, or `directory` for a host directory.
    filesystem: &'a str,
    /// Volume label the operating system shows.
    volname: &'a str,
    /// Filesystem type label reported to the operating system.
    fsname: &'a str,
    /// Byte offset the filesystem was opened at.
    offset: Option<u64>,
    /// Partition ordinal that was selected.
    partition: Option<usize>,
    /// Length of the opened volume.
    size_bytes: Option<u64>,
    /// Whether the extent came from a table, its backup, or a scan.
    #[serde(serialize_with = "serialize_mount_origin")]
    layout_origin: Option<LayoutOrigin>,
    /// Bytes the filesystem claims that the medium does not carry.
    truncated_by: Option<u64>,
    /// Bytes of the filesystem in front of the medium.
    head_absent: Option<u64>,
    /// Everything the driver did that departs from a plain open.
    ///
    /// Also on stderr as warnings; they are repeated here because a program
    /// deciding whether to trust this mount should not have to correlate two
    /// streams to learn that a backup superblock stood in for the primary.
    notices: Vec<String>,
}

impl<'a> OpenedEvent<'a> {
    /// Announce an opened volume and what the driver had to do to open it.
    pub(crate) fn new(report: &'a MountReport, notices: Vec<String>) -> Self {
        Self {
            schema: SCHEMA,
            event: "opened",
            source: &report.source,
            filesystem: report.filesystem,
            volname: &report.volname,
            fsname: &report.fsname,
            offset: report.offset,
            partition: report.partition,
            size_bytes: report.size_bytes,
            layout_origin: report.layout_origin,
            truncated_by: report.truncated_by,
            head_absent: report.head_absent,
            notices,
        }
    }
}

/// The volume is live.
#[derive(Debug, Serialize)]
pub(crate) struct MountedEvent<'a> {
    /// Wire-format version.
    schema: u32,
    /// Event name.
    event: &'static str,
    /// Where the volume appeared.
    mountpoint: &'a str,
    /// Process holding the mount — this one, or the background process
    /// `--detach` started, which is what `fsmnt unmount` releases.
    pid: u32,
}

impl<'a> MountedEvent<'a> {
    /// Announce a volume a program can now read.
    pub(crate) const fn new(mountpoint: &'a str, pid: u32) -> Self {
        Self {
            schema: SCHEMA,
            event: "mounted",
            mountpoint,
            pid,
        }
    }
}

/// The volume is gone.
#[derive(Debug, Serialize)]
pub(crate) struct UnmountedEvent<'a> {
    /// Wire-format version.
    schema: u32,
    /// Event name.
    event: &'static str,
    /// Where the volume was.
    mountpoint: &'a str,
    /// What best-effort reads had to substitute, or `null` when they were
    /// off and every byte served was real.
    best_effort: Option<BestEffort>,
}

impl<'a> UnmountedEvent<'a> {
    /// Close the mount, with the accounting the read tolerance kept.
    pub(crate) const fn new(mountpoint: &'a str, best_effort: Option<BestEffort>) -> Self {
        Self {
            schema: SCHEMA,
            event: "unmounted",
            mountpoint,
            best_effort,
        }
    }
}

/// How much of what was read was not there.
///
/// Distinct bytes, each counted once however often it was re-read, split by
/// what happened to them: a source that stopped short, an acquisition that
/// began too late, and sectors that failed are three different findings.
#[derive(Debug, Serialize)]
pub(crate) struct BestEffort {
    /// Bytes past the end of the source, served as zeros.
    pub(crate) missing_bytes: u64,
    /// Bytes in front of the medium, served as zeros.
    pub(crate) absent_bytes: u64,
    /// Bytes in sectors that failed to read, served as zeros.
    pub(crate) errored_bytes: u64,
    /// How many read errors were absorbed.
    pub(crate) read_errors: u64,
}

impl BestEffort {
    /// Read the counters a tolerant reader accumulated.
    pub(crate) fn new(stats: &ReadSubstitutions) -> Self {
        Self {
            missing_bytes: stats.missing_bytes(),
            absent_bytes: stats.absent_bytes(),
            errored_bytes: stats.errored_bytes(),
            read_errors: stats.read_errors(),
        }
    }
}

/// A volume was released.
#[derive(Debug, Serialize)]
pub(crate) struct UnmountDocument<'a> {
    /// Wire-format version.
    schema: u32,
    /// Document kind.
    kind: &'static str,
    /// The mountpoint that was released.
    mountpoint: &'a str,
    /// Always true. An unmount that did not happen is an error and a
    /// non-zero exit, not a document reporting `false`; the field is here so
    /// a reader can assert on it rather than on the absence of one.
    unmounted: bool,
}

impl<'a> UnmountDocument<'a> {
    /// Report a released mountpoint.
    pub(crate) const fn new(mountpoint: &'a str) -> Self {
        Self {
            schema: SCHEMA,
            kind: "unmount",
            mountpoint,
            unmounted: true,
        }
    }
}

#[cfg(test)]
mod tests;
