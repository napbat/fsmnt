//! Layout of a decoded disk image.

use std::path::Path;

use tracing::debug;

use fsmnt_device::{Disk, ImageFormat, ImageReader};

use super::media::{self, MediaEntries};
use super::{
    DEFAULT_SECTOR_SIZE, LayoutKind, LayoutOrigin, LayoutPartition, NATIVE_4K_SECTOR_SIZE,
};
use crate::OpenImageError;

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
    /// The result is marked [`LayoutOrigin::Scan`] and [`LayoutKind::Scanned`]
    /// so nothing downstream mistakes it for a table the media carried.
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
    pub kind: LayoutKind,
    /// Mountable extents in ordinal order. An image without a partition
    /// table reports a single whole-image entry, so `--partition 0` always
    /// names something mountable when the image holds a filesystem.
    pub partitions: Vec<LayoutPartition>,
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
        debug!(
            path = %path.display(),
            sector_size,
            "reading the image partition table in the sector size the caller stated"
        );
        return layout_at_sector_size(path, sector_size, false);
    }

    let first = layout_at_sector_size(path, DEFAULT_SECTOR_SIZE, false);
    if first.as_ref().is_ok_and(describes_the_media) {
        return first;
    }
    debug!(
        path = %path.display(),
        "512-byte sectors describe nothing here; retrying the table at 4096"
    );
    match layout_at_sector_size(path, NATIVE_4K_SECTOR_SIZE, true) {
        Ok(view) if matches!(view.layout.kind, LayoutKind::Gpt) => {
            debug!(
                path = %path.display(),
                sector_size = NATIVE_4K_SECTOR_SIZE,
                "the image is a dump of a 4Kn drive; its GPT reads in 4096-byte sectors"
            );
            Ok(view)
        }
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
        LayoutKind::Gpt | LayoutKind::Bare(_) | LayoutKind::Scanned => true,
        LayoutKind::Mbr => !view.layout.partitions.is_empty(),
        LayoutKind::Unknown => false,
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
    let MediaEntries {
        origin,
        kind,
        partitions,
    } = media::media_layout(&mut disk, Some(size_bytes));

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

/// Reconstruct a layout by scanning the media for filesystem starts.
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

    Ok(ImageLayoutView {
        image,
        layout: ImageLayout {
            format,
            sector_size,
            sector_size_auto_detected: false,
            origin: LayoutOrigin::Scan { stride },
            size_bytes,
            kind: LayoutKind::Scanned,
            partitions: media::layout_from_hits(&hits, Some(size_bytes)),
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
