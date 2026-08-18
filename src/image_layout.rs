//! Read-only enumeration of what a decoded disk image contains.
//!
//! [`image_layout`] answers "what is inside this file?" without opening a
//! filesystem: the container format, the partition table (if any), and every
//! addressable partition with its ordinal, byte offset, size, type, label,
//! and detected filesystem.
//!
//! The ordinals it reports are the ones
//! [`ImageOpenOptions::with_partition`](crate::ImageOpenOptions::with_partition)
//! consumes — both come from the same enumeration, so a partition listed here
//! can be mounted by its number.

use std::path::Path;

use fsmnt_device::{DetectedBootSector, Disk, DiskLayout, ImageFormat, ImageReader};

use crate::OpenImageError;

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

/// What a decoded disk image contains.
///
/// Returned by [`image_layout`]; see [`ImageLayout::partitions`] for the
/// ordinals that select a partition when opening the image.
#[derive(Clone, Debug)]
pub struct ImageLayout {
    /// Container format the image was decoded from.
    pub format: ImageFormat,
    /// Logical sector size used to convert partition-table LBAs to byte
    /// offsets. Decoded image media is addressed in 512-byte sectors.
    pub sector_size: u32,
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
    read_image_layout(path.as_ref()).map(|view| view.layout)
}

/// Enumerate an image's partitions and hand back the reader used to do it.
pub(crate) fn read_image_layout(path: &Path) -> Result<ImageLayoutView, OpenImageError> {
    let image = ImageReader::open(path)?;
    let format = image.format();
    let size_bytes = image.len();
    let mut disk = Disk::new(image).map_err(|source| OpenImageError::Layout {
        path: path.to_path_buf(),
        source,
    })?;
    let sector_size = disk.sector_size();

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
            size_bytes,
            kind,
            partitions,
        },
    })
}

/// Resolve `partition` to its extent, reusing the enumeration ordinals.
///
/// Returns the decoded reader alongside the partition's byte offset and
/// length so the caller can open a filesystem bounded to it.
pub(crate) fn locate_image_partition(
    path: &Path,
    partition: usize,
) -> Result<(ImageReader, u64, u64), OpenImageError> {
    let ImageLayoutView { image, layout } = read_image_layout(path)?;
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
    Ok((image, selected.offset, selected.size_bytes))
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
