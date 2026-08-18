//! Read-only enumeration of what a decoded disk image contains.
//!
//! [`image_layout`] answers "what is inside this file?" without opening a
//! filesystem: the container format, the partition table (if any), and every
//! addressable partition with its ordinal, byte offset, size, type, label,
//! detected filesystem, and how much of it the image is missing.
//!
//! The ordinals it reports are the ones
//! [`ImageOpenOptions::with_partition`](crate::ImageOpenOptions::with_partition)
//! consumes — both come from the same enumeration, so a partition listed here
//! can be mounted by its number.
//!
//! Partition tables are written in the drive's logical sectors, so a dump of
//! a 4Kn drive puts its GPT header at byte 4096 and means every LBA in the
//! entry array counts 4096-byte units. [`ImageLayoutOptions::with_sector_size`]
//! states the sector size; without one, enumeration falls back to 4 KiB
//! sectors when 512-byte sectors find no table (see
//! [`ImageLayout::sector_size_auto_detected`]).

use std::path::Path;

use fsmnt_device::{DetectedBootSector, Disk, DiskLayout, ImageFormat, ImageReader};

use crate::OpenImageError;

/// Logical sector size assumed for a decoded image with no better
/// information: the 512-byte sector every 512n and 512e drive reports.
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Logical sector size tried when 512-byte sectors find no partition table.
///
/// 4Kn drives are the only common media whose dump needs a different unit,
/// and a raw dump of one carries no geometry metadata to read it from.
const NATIVE_4K_SECTOR_SIZE: u32 = 4096;

/// Partition table (or lack of one) found at the start of a decoded image.
///
/// Mirrors [`DiskLayout`] one variant for one variant, so matching on it is
/// exhaustive for as long as that type's is.
#[derive(Clone, Debug)]
pub enum ImageLayoutKind {
    /// A GUID partition table; partitions come from its entry array.
    Gpt,
    /// A master boot record; partitions come from its primary entries.
    Mbr,
    /// No partition table — the whole image is one filesystem of this type.
    Bare(DetectedBootSector),
    /// Neither a partition table nor a recognized filesystem at offset 0.
    Unknown,
    /// **Synthetic**: no table was read; the entries were reconstructed by
    /// scanning the media for filesystem starts (see
    /// [`LayoutOrigin::Scan`]).
    Scanned,
}

/// Where an [`ImageLayout`]'s entries came from — the provenance a listing
/// or a mount must state, because a table read from the media, a table
/// recovered from its backup copy, and a table *made up* from a scan are
/// three different levels of evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutOrigin {
    /// Read from the partition table at the front of the media: the GPT
    /// header at LBA 1 or the MBR at LBA 0.
    Table,
    /// Read from the GPT backup header in the last sector of the media
    /// because the primary at LBA 1 was wiped or invalid. The entries are
    /// the disk's own; the front of the media is what is damaged.
    BackupTable,
    /// Reconstructed by scanning the media for filesystem starts with the
    /// given stride, ignoring any partition table. Synthetic: the ordinals
    /// hold only for the same image scanned with the same stride, sizes are
    /// what each filesystem claims for itself, and there are no partition
    /// names or type GUIDs.
    Scan {
        /// Distance between the candidate positions the scan tested.
        stride: u64,
    },
    /// The image holds no table; its single entry is the whole image.
    None,
}

/// Sector-size and other choices for enumerating an image's layout.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageLayoutOptions {
    sector_size: Option<u32>,
    scan: bool,
    scan_stride: u64,
}

impl ImageLayoutOptions {
    /// Enumerate with automatic sector-size selection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sector_size: None,
            scan: false,
            scan_stride: crate::scan::DEFAULT_STRIDE,
        }
    }

    /// Ignore any partition table and reconstruct the layout by scanning
    /// the media for filesystem starts (the same search as `fsmnt scan`).
    ///
    /// The result is marked [`LayoutOrigin::Scan`] and
    /// [`ImageLayoutKind::Scanned`] so nothing downstream mistakes it for a
    /// table the media carried.
    #[must_use]
    pub const fn with_scan(mut self, scan: bool) -> Self {
        self.scan = scan;
        self
    }

    /// Distance between candidate positions when scanning; see
    /// [`ScanOptions::with_stride`](crate::ScanOptions::with_stride).
    #[must_use]
    pub const fn with_scan_stride(mut self, stride: u64) -> Self {
        self.scan_stride = stride;
        self
    }

    /// Whether the layout is to be reconstructed by scanning.
    #[must_use]
    pub const fn scan(&self) -> bool {
        self.scan
    }

    /// The scan stride in bytes.
    #[must_use]
    pub const fn scan_stride(&self) -> u64 {
        self.scan_stride
    }

    /// Read the partition table in sectors of `sector_size` bytes.
    ///
    /// Supply this for a dump of a 4Kn drive, whose GPT header sits at byte
    /// 4096 and whose entry LBAs count 4096-byte units. Setting it also
    /// disables the automatic fallback, so a wrong value is reported as "no
    /// partition table" rather than silently corrected.
    #[must_use]
    pub const fn with_sector_size(mut self, sector_size: u32) -> Self {
        self.sector_size = Some(sector_size);
        self
    }

    /// The requested sector size, or `None` when it is to be detected.
    #[must_use]
    pub const fn sector_size(&self) -> Option<u32> {
        self.sector_size
    }
}

/// One mountable extent within a decoded disk image.
#[derive(Clone, Debug)]
pub struct ImagePartition {
    /// Position in the listing, counting non-empty entries from 0. This is
    /// the number `--partition` and
    /// [`ImageOpenOptions::with_partition`](crate::ImageOpenOptions::with_partition)
    /// take.
    pub ordinal: usize,
    /// Byte offset of the partition start within the decoded media.
    pub offset: u64,
    /// Length of the partition in bytes, as declared by the partition table.
    pub size_bytes: u64,
    /// How many of those bytes lie past the end of the decoded image.
    ///
    /// 0 when the partition is fully present. Equal to
    /// [`size_bytes`](Self::size_bytes) when the partition starts past the
    /// end of the image — a partition-table-only dump, or an acquisition
    /// that stopped early, describes extents the media does not carry.
    pub missing_bytes: u64,
    /// Human-readable partition type: the GPT type name, or the MBR type
    /// name falling back to its `0xNN` code. `None` for a GPT type GUID
    /// with no known name and for images without a partition table.
    pub type_name: Option<String>,
    /// GPT partition label. Always `None` for MBR, which stores no labels.
    pub name: Option<String>,
    /// Filesystem detected at the partition start, or `None` when those
    /// bytes could not be read (a truncated or partition-table-only image).
    pub detected: Option<DetectedBootSector>,
}

impl ImagePartition {
    /// Bytes of this partition the decoded image actually carries.
    #[must_use]
    pub const fn available_bytes(&self) -> u64 {
        self.size_bytes.saturating_sub(self.missing_bytes)
    }

    /// Whether the image carries none of this partition at all.
    #[must_use]
    pub const fn is_beyond_end(&self) -> bool {
        self.available_bytes() == 0
    }

    /// Whether the image carries some but not all of this partition.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.missing_bytes > 0 && !self.is_beyond_end()
    }
}

/// What a decoded disk image contains.
///
/// Returned by [`image_layout`]; see [`ImageLayout::partitions`] for the
/// ordinals that select a partition when opening the image.
#[derive(Clone, Debug)]
pub struct ImageLayout {
    /// Container format the image was decoded from.
    pub format: ImageFormat,
    /// Logical sector size used to convert partition-table LBAs to byte
    /// offsets.
    pub sector_size: u32,
    /// Whether [`sector_size`](Self::sector_size) was inferred rather than
    /// supplied: 512-byte sectors found no partition table and 4096-byte
    /// sectors found a GPT.
    pub sector_size_auto_detected: bool,
    /// Where the entries came from: the media's own table, its backup copy,
    /// or a synthetic reconstruction from a scan.
    pub origin: LayoutOrigin,
    /// Length of the decoded media in bytes.
    pub size_bytes: u64,
    /// Partition table found at the start of the decoded media.
    pub kind: ImageLayoutKind,
    /// Mountable extents in ordinal order. An image without a partition
    /// table reports a single whole-image entry, so `--partition 0` always
    /// names something mountable when the image holds a filesystem.
    pub partitions: Vec<ImagePartition>,
}

/// A decoded image reader together with the layout read from it.
///
/// Opening a partition reuses the reader that enumeration already opened
/// instead of decoding the container a second time.
pub(crate) struct ImageLayoutView {
    /// Reader for the decoded media, positioned arbitrarily.
    pub(crate) image: ImageReader,
    /// Layout enumerated from that reader.
    pub(crate) layout: ImageLayout,
}

/// A partition resolved to the window a filesystem will be opened in.
pub(crate) struct LocatedImagePartition {
    /// Reader for the decoded media.
    pub(crate) image: ImageReader,
    /// Byte offset of the partition within the decoded media.
    pub(crate) offset: u64,
    /// Length the partition table declares for the partition.
    pub(crate) declared_bytes: u64,
    /// Bytes of that extent the decoded media actually carries.
    pub(crate) available_bytes: u64,
    /// Where the table this partition came from was read from, or `None`
    /// for a caller-supplied byte offset.
    pub(crate) origin: Option<LayoutOrigin>,
}

/// List the partitions inside a raw, EWF, VHD, or VHDX disk image.
///
/// The image is decoded and its partition table parsed, but no filesystem is
/// opened: each partition only carries the boot-sector type detected at its
/// start. Images with no partition table report one whole-image partition.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, or if its
/// leading sectors cannot be read to classify the layout.
pub fn image_layout(path: impl AsRef<Path>) -> Result<ImageLayout, OpenImageError> {
    image_layout_with_options(path, ImageLayoutOptions::new())
}

/// List an image's partitions, reading its partition table in sectors of
/// `sector_size` bytes.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, or if its
/// leading sectors cannot be read to classify the layout.
pub fn image_layout_with_sector_size(
    path: impl AsRef<Path>,
    sector_size: u32,
) -> Result<ImageLayout, OpenImageError> {
    image_layout_with_options(
        path,
        ImageLayoutOptions::new().with_sector_size(sector_size),
    )
}

/// List an image's partitions with explicit enumeration options.
///
/// # Errors
///
/// Returns an error if the image cannot be opened or decoded, or if its
/// leading sectors cannot be read to classify the layout.
pub fn image_layout_with_options(
    path: impl AsRef<Path>,
    options: ImageLayoutOptions,
) -> Result<ImageLayout, OpenImageError> {
    read_image_layout(path.as_ref(), options).map(|view| view.layout)
}

/// Enumerate an image's partitions and hand back the reader used to do it.
///
/// With no sector size requested this is where the 4Kn fallback lives: a
/// 512-byte read of a 4Kn dump finds a protective MBR at byte 0 and then no
/// GPT header at byte 512, so the first attempt either fails or reports
/// nothing mountable. Retrying at 4096 either produces a GPT — in which case
/// it is the truth about the media — or is discarded, leaving the original
/// answer intact.
pub(crate) fn read_image_layout(
    path: &Path,
    options: ImageLayoutOptions,
) -> Result<ImageLayoutView, OpenImageError> {
    if options.scan {
        return layout_from_scan(path, options);
    }
    if let Some(sector_size) = options.sector_size {
        return layout_at_sector_size(path, sector_size, false);
    }

    let first = layout_at_sector_size(path, DEFAULT_SECTOR_SIZE, false);
    if first.as_ref().is_ok_and(describes_the_media) {
        return first;
    }
    match layout_at_sector_size(path, NATIVE_4K_SECTOR_SIZE, true) {
        Ok(view) if matches!(view.layout.kind, ImageLayoutKind::Gpt) => Ok(view),
        _ => first,
    }
}

/// Whether a layout is an answer, as opposed to "nothing recognized here".
///
/// An MBR with no usable entries is as inconclusive as no table at all: a
/// 4Kn GPT dump's protective MBR parses as an MBR whose single entry is
/// filtered out for being GPT-protective.
fn describes_the_media(view: &ImageLayoutView) -> bool {
    match view.layout.kind {
        ImageLayoutKind::Gpt | ImageLayoutKind::Bare(_) | ImageLayoutKind::Scanned => true,
        ImageLayoutKind::Mbr => !view.layout.partitions.is_empty(),
        ImageLayoutKind::Unknown => false,
    }
}

/// Enumerate the image reading its partition table at one sector size.
fn layout_at_sector_size(
    path: &Path,
    sector_size: u32,
    auto_detected: bool,
) -> Result<ImageLayoutView, OpenImageError> {
    let image = ImageReader::open(path)?;
    let format = image.format();
    let size_bytes = image.len();
    let mut disk =
        Disk::with_sector_size(image, sector_size).map_err(|source| OpenImageError::Layout {
            path: path.to_path_buf(),
            source,
        })?;
    let sector_size = disk.sector_size();

    let origin = match disk.layout() {
        DiskLayout::Gpt {
            from_backup: true, ..
        } => LayoutOrigin::BackupTable,
        DiskLayout::Gpt { .. } | DiskLayout::Mbr { .. } => LayoutOrigin::Table,
        DiskLayout::Bare(_) | DiskLayout::Unknown => LayoutOrigin::None,
    };
    let (kind, entries) = match disk.layout().clone() {
        DiskLayout::Gpt { .. } => (ImageLayoutKind::Gpt, gpt_entries(&mut disk)),
        DiskLayout::Mbr { .. } => (ImageLayoutKind::Mbr, mbr_entries(&disk)),
        DiskLayout::Bare(detected) => (
            ImageLayoutKind::Bare(detected),
            vec![whole_image_entry(size_bytes)],
        ),
        DiskLayout::Unknown => (
            ImageLayoutKind::Unknown,
            vec![whole_image_entry(size_bytes)],
        ),
    };

    let partitions = entries
        .into_iter()
        .enumerate()
        .map(|(ordinal, entry)| ImagePartition {
            ordinal,
            offset: entry.offset,
            size_bytes: entry.size_bytes,
            missing_bytes: missing_bytes(entry.offset, entry.size_bytes, size_bytes),
            type_name: entry.type_name,
            name: entry.name,
            detected: detect_at(&mut disk, entry.offset, size_bytes),
        })
        .collect();

    Ok(ImageLayoutView {
        image: disk.into_inner(),
        layout: ImageLayout {
            format,
            sector_size,
            sector_size_auto_detected: auto_detected,
            origin,
            size_bytes,
            kind,
            partitions,
        },
    })
}

/// How much of the extent `offset..offset + size_bytes` the image lacks.
fn missing_bytes(offset: u64, size_bytes: u64, image_size: u64) -> u64 {
    offset
        .saturating_add(size_bytes)
        .saturating_sub(image_size)
        .min(size_bytes)
}

/// Reconstruct a layout by scanning the media for filesystem starts.
///
/// Every mountable scan hit (see [`crate::mountable_hits`]) becomes one
/// entry, in scan order: its offset is the filesystem start, its size is
/// what the filesystem claims for itself (or the rest of the image when the
/// format does not say), its type is the detected filesystem, and it has no
/// name. An ext filesystem found only through a backup superblock is listed
/// too — at the start the copy implies — so `--partition` on it produces
/// the "primary damaged, retry with `--backup-superblock`" guidance rather
/// than nothing.
fn layout_from_scan(
    path: &Path,
    options: ImageLayoutOptions,
) -> Result<ImageLayoutView, OpenImageError> {
    let stride = options.scan_stride;
    let hits =
        crate::scan::scan_image_with_options(path, crate::ScanOptions::new().with_stride(stride))
            .map_err(|source| OpenImageError::Scan {
            path: path.to_path_buf(),
            source,
        })?;
    let image = ImageReader::open(path)?;
    let format = image.format();
    let size_bytes = image.len();
    let sector_size = options.sector_size.unwrap_or(DEFAULT_SECTOR_SIZE);

    let partitions = crate::mountable_hits(&hits)
        .into_iter()
        .enumerate()
        .map(|(ordinal, hit)| {
            let offset = hit.mount_offset().unwrap_or(hit.offset);
            let rest = size_bytes.saturating_sub(offset);
            let claimed = hit.size_bytes.unwrap_or(rest);
            let (type_name, detected) = match hit.kind {
                crate::ScanHitKind::Filesystem(detected) => {
                    (Some(format!("{detected:?} (scan)")), Some(detected))
                }
                crate::ScanHitKind::ExtBackupSuperblock { group, .. } => (
                    Some(format!(
                        "Ext (scan; primary damaged, backup at group {group})"
                    )),
                    Some(DetectedBootSector::Unknown),
                ),
                crate::ScanHitKind::PartitionTable(_) => (None, None),
            };
            ImagePartition {
                ordinal,
                offset,
                size_bytes: claimed,
                missing_bytes: missing_bytes(offset, claimed, size_bytes),
                type_name,
                name: None,
                detected,
            }
        })
        .collect();

    Ok(ImageLayoutView {
        image,
        layout: ImageLayout {
            format,
            sector_size,
            sector_size_auto_detected: false,
            origin: LayoutOrigin::Scan { stride },
            size_bytes,
            kind: ImageLayoutKind::Scanned,
            partitions,
        },
    })
}

/// Resolve `partition` to its extent, reusing the enumeration ordinals.
///
/// Returns the decoded reader alongside the partition's byte offset, the
/// length the partition table declares, and the length actually present, so
/// the caller can bound a filesystem to what the image really carries.
pub(crate) fn locate_image_partition(
    path: &Path,
    partition: usize,
    options: ImageLayoutOptions,
) -> Result<LocatedImagePartition, OpenImageError> {
    let ImageLayoutView { image, layout } = read_image_layout(path, options)?;
    let selected =
        layout
            .partitions
            .get(partition)
            .ok_or_else(|| OpenImageError::PartitionNotFound {
                path: path.to_path_buf(),
                partition,
                available: layout.partitions.len(),
            })?;
    if selected.offset >= layout.size_bytes {
        return Err(OpenImageError::OffsetOutOfRange {
            path: path.to_path_buf(),
            offset: selected.offset,
            size_bytes: layout.size_bytes,
        });
    }
    Ok(LocatedImagePartition {
        image,
        offset: selected.offset,
        declared_bytes: selected.size_bytes,
        available_bytes: selected.available_bytes(),
        origin: Some(layout.origin),
    })
}

/// Classify the boot sector at `offset` within an image of `size_bytes`.
///
/// A partition table can describe partitions the image does not carry — a
/// partition-table-only dump, or a truncated acquisition. Reads past the end
/// of the decoded media come back empty and would classify as `Unknown`, so
/// those partitions report `None` ("not present") instead.
fn detect_at(
    disk: &mut Disk<ImageReader>,
    offset: u64,
    size_bytes: u64,
) -> Option<DetectedBootSector> {
    if offset >= size_bytes {
        return None;
    }
    disk.detect_boot_sector_at(offset).ok()
}

/// A partition extent before filesystem detection has been attempted.
struct RawEntry {
    /// Byte offset of the extent within the decoded media.
    offset: u64,
    /// Length of the extent in bytes.
    size_bytes: u64,
    /// Partition type as named by the partition table.
    type_name: Option<String>,
    /// Partition label, where the table stores one.
    name: Option<String>,
}

/// The single extent used for images with no partition table.
fn whole_image_entry(size_bytes: u64) -> RawEntry {
    RawEntry {
        offset: 0,
        size_bytes,
        type_name: None,
        name: None,
    }
}

/// Collect the non-empty GPT entries, skipping ones that cannot be read.
fn gpt_entries(disk: &mut Disk<ImageReader>) -> Vec<RawEntry> {
    let sector_size = disk.sector_size();
    let count = disk.partition_count();
    let mut entries = Vec::new();
    for index in 0..count {
        let Ok(entry) = disk.gpt_partition(index) else {
            continue;
        };
        if entry.is_empty() {
            continue;
        }
        let name = entry.name_string();
        entries.push(RawEntry {
            offset: entry.start_offset(sector_size),
            size_bytes: entry.size_bytes(sector_size),
            type_name: entry.type_name().map(str::to_string),
            name: (!name.is_empty()).then_some(name),
        });
    }
    entries
}

/// Collect the primary MBR entries in on-disk order.
fn mbr_entries(disk: &Disk<ImageReader>) -> Vec<RawEntry> {
    let sector_size = disk.sector_size();
    disk.mbr_partitions()
        .map(|entry| RawEntry {
            offset: entry.start_offset(sector_size),
            size_bytes: entry.size_bytes(sector_size),
            type_name: Some(
                entry
                    .type_name()
                    .map_or_else(|| format!("0x{:02X}", entry.partition_type), str::to_string),
            ),
            name: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{ImagePartition, missing_bytes};

    fn partition(offset: u64, size_bytes: u64, image_size: u64) -> ImagePartition {
        ImagePartition {
            ordinal: 0,
            offset,
            size_bytes,
            missing_bytes: missing_bytes(offset, size_bytes, image_size),
            type_name: None,
            name: None,
            detected: None,
        }
    }

    #[test]
    fn a_partition_inside_the_image_is_complete() {
        let partition = partition(1024, 4096, 65_536);
        assert_eq!(partition.missing_bytes, 0);
        assert_eq!(partition.available_bytes(), 4096);
        assert!(!partition.is_truncated());
        assert!(!partition.is_beyond_end());
    }

    #[test]
    fn a_partition_the_image_stops_inside_is_truncated() {
        let partition = partition(1024, 4096, 3072);
        assert_eq!(partition.missing_bytes, 2048);
        assert_eq!(partition.available_bytes(), 2048);
        assert!(partition.is_truncated());
        assert!(!partition.is_beyond_end());
    }

    #[test]
    fn a_partition_starting_past_the_end_is_missing_entirely() {
        let partition = partition(8192, 4096, 4096);
        assert_eq!(partition.missing_bytes, 4096);
        assert_eq!(partition.available_bytes(), 0);
        assert!(partition.is_beyond_end());
        assert!(!partition.is_truncated(), "nothing of it is present to cut");
    }

    #[test]
    fn a_partition_ending_exactly_at_the_end_is_complete() {
        let partition = partition(4096, 4096, 8192);
        assert_eq!(partition.missing_bytes, 0);
    }
}
