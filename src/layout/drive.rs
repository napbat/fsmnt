//! Layout of a physical drive attached to this machine.
//!
//! The same enumeration images get, over a live drive: a drive with a wiped
//! partition table and an image of one are the same forensic situation, so
//! they get the same answers and the same provenance
//! ([`LayoutOrigin`]).

use std::io::{Seek, SeekFrom};

use fsmnt_device::{Disk, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo};

use super::media::{self, MediaEntries};
use super::{
    DEFAULT_SECTOR_SIZE, LayoutKind, LayoutOrigin, LayoutPartition, NATIVE_4K_SECTOR_SIZE,
};
use crate::ScanError;

/// Sector-size and other choices for enumerating a drive's layout.
#[derive(Clone, Copy, Debug, Default)]
pub struct DriveLayoutOptions {
    sector_size: Option<u32>,
    scan: bool,
    scan_stride: u64,
}

impl DriveLayoutOptions {
    /// Enumerate in the sectors the operating system reports for the drive.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sector_size: None,
            scan: false,
            scan_stride: crate::scan::DEFAULT_STRIDE,
        }
    }

    /// Ignore any partition table and reconstruct the layout by scanning
    /// the drive for filesystem starts (the same search as `fsmnt scan`).
    ///
    /// The result is marked [`LayoutOrigin::Scan`] and [`LayoutKind::Scanned`]
    /// so nothing downstream mistakes it for a table the drive carried.
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

    /// Read the partition table in sectors of `sector_size` bytes,
    /// overriding whatever the operating system says the drive uses.
    ///
    /// Supply this for a 4Kn drive presented as 512e (or the reverse), where
    /// the reported geometry and the geometry the table was written in
    /// disagree and every partition offset comes out a factor of eight off.
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
}

/// What a physical drive contains.
///
/// The same information [`ImageLayout`](super::ImageLayout) reports for a
/// decoded image, minus the container format a drive does not have.
#[derive(Clone, Debug)]
pub struct DriveLayout {
    /// Logical sector size used to convert partition-table LBAs to byte
    /// offsets: the caller's override, else the size the operating system
    /// reports for the drive, else a detected one.
    pub sector_size: u32,
    /// Whether [`sector_size`](Self::sector_size) was inferred by this crate
    /// rather than supplied or reported: neither the caller nor the
    /// operating system named one, 512-byte sectors found no partition
    /// table, and 4096-byte sectors found a GPT.
    pub sector_size_auto_detected: bool,
    /// Where the entries came from: the drive's own table, its backup copy,
    /// or a synthetic reconstruction from a scan.
    pub origin: LayoutOrigin,
    /// Length of the drive in bytes, or 0 when the operating system would
    /// not say. An unknown size is not fatal: the table is still read, no
    /// partition is reported as missing bytes, and an unpartitioned drive's
    /// single entry gets size 0 meaning "to the end of the drive".
    pub size_bytes: u64,
    /// Partition table found at the start of the drive.
    pub kind: LayoutKind,
    /// Mountable extents in ordinal order, numbered exactly as
    /// `--partition` counts them.
    pub partitions: Vec<LayoutPartition>,
}

/// Why a drive's layout could not be enumerated.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DriveLayoutError {
    /// The drive could not be opened for reading.
    #[error(transparent)]
    Drive(#[from] HostDriveError),
    /// The drive's leading sectors could not be read to classify it.
    #[error("failed to read the partition layout of drive {drive}: {source}")]
    Layout {
        /// Drive whose table was being read.
        drive: HostDriveId,
        /// Underlying seek or read failure.
        #[source]
        source: std::io::Error,
    },
    /// Reconstructing the layout by scanning the drive failed part-way.
    #[error("failed to scan drive {drive} for filesystems: {source}")]
    Scan {
        /// Drive that was being scanned.
        drive: HostDriveId,
        /// The scan failure.
        #[source]
        source: ScanError,
    },
}

/// List the partitions on a physical drive.
///
/// The partition table is parsed but no filesystem is opened: each partition
/// only carries the boot-sector type detected at its start. A drive with no
/// partition table reports one whole-drive partition, and
/// [`DriveLayoutOptions::with_scan`] ignores the table altogether and
/// reconstructs a **synthetic** one from the filesystems a scan finds.
///
/// The enumerator type parameter selects the platform: on Windows, Linux,
/// and macOS, use [`HostDrives`](crate::HostDrives).
///
/// # Errors
///
/// Returns an error if the drive cannot be opened, its leading sectors
/// cannot be read to classify the layout, or a requested scan fails.
pub fn drive_layout<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    options: DriveLayoutOptions,
) -> Result<DriveLayout, DriveLayoutError> {
    // A drive that cannot describe itself is still readable; the size and
    // sector size it would have supplied simply have to be found elsewhere.
    let info = E::get_drive_info(drive).ok();
    if options.scan {
        return scanned_drive_layout::<E>(drive, info.as_ref(), options);
    }

    let stated = options
        .sector_size
        .or_else(|| reported_sector_size(info.as_ref()));
    if let Some(sector_size) = stated {
        return layout_at_sector_size::<E>(drive, info.as_ref(), sector_size, false);
    }

    // Nothing knows the geometry: try the sector size almost every drive
    // uses, then the one whose table a 512-byte read cannot see.
    let first = layout_at_sector_size::<E>(drive, info.as_ref(), DEFAULT_SECTOR_SIZE, false);
    if first.as_ref().is_ok_and(describes_the_drive) {
        return first;
    }
    match layout_at_sector_size::<E>(drive, info.as_ref(), NATIVE_4K_SECTOR_SIZE, true) {
        Ok(layout) if matches!(layout.kind, LayoutKind::Gpt) => Ok(layout),
        _ => first,
    }
}

/// The sector size the operating system reports, if it reported a usable one.
fn reported_sector_size(info: Option<&HostDriveInfo>) -> Option<u32> {
    info.and_then(|info| info.sector_size)
        .filter(|size| size.is_power_of_two())
}

/// Whether a layout is an answer, as opposed to "nothing recognized here".
fn describes_the_drive(layout: &DriveLayout) -> bool {
    match layout.kind {
        LayoutKind::Gpt | LayoutKind::Bare(_) | LayoutKind::Scanned => true,
        LayoutKind::Mbr => !layout.partitions.is_empty(),
        LayoutKind::Unknown => false,
    }
}

/// Enumerate the drive reading its partition table at one sector size.
fn layout_at_sector_size<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    info: Option<&HostDriveInfo>,
    sector_size: u32,
    auto_detected: bool,
) -> Result<DriveLayout, DriveLayoutError> {
    let mut reader = E::open_drive(drive)?;
    let size_bytes = drive_length(info, &mut reader);
    let mut disk =
        Disk::with_sector_size(reader, sector_size).map_err(|source| DriveLayoutError::Layout {
            drive: drive.clone(),
            source,
        })?;
    let sector_size = disk.sector_size();
    let MediaEntries {
        origin,
        kind,
        partitions,
    } = media::media_layout(&mut disk, size_bytes);

    Ok(DriveLayout {
        sector_size,
        sector_size_auto_detected: auto_detected,
        origin,
        size_bytes: size_bytes.unwrap_or(0),
        kind,
        partitions,
    })
}

/// Reconstruct a drive's layout from the filesystems a scan finds.
fn scanned_drive_layout<E: HostDriveEnumerator>(
    drive: &HostDriveId,
    info: Option<&HostDriveInfo>,
    options: DriveLayoutOptions,
) -> Result<DriveLayout, DriveLayoutError> {
    let stride = options.scan_stride;
    // Measured the same way the scan bounds itself, so the entries it
    // produces and the drive they sit on agree about where the end is.
    let size_bytes = {
        let mut reader = E::open_drive(drive)?;
        drive_length(info, &mut reader)
    };
    let hits = crate::scan::scan_drive::<E>(drive, crate::ScanOptions::new().with_stride(stride))
        .map_err(|source| DriveLayoutError::Scan {
        drive: drive.clone(),
        source,
    })?;
    Ok(DriveLayout {
        sector_size: options
            .sector_size
            .or_else(|| reported_sector_size(info))
            .unwrap_or(DEFAULT_SECTOR_SIZE),
        sector_size_auto_detected: false,
        origin: LayoutOrigin::Scan { stride },
        size_bytes: size_bytes.unwrap_or(0),
        kind: LayoutKind::Scanned,
        partitions: media::layout_from_hits(&hits, size_bytes),
    })
}

/// How long the drive is: what it reported, else what seeking to its end
/// says, else unknown.
pub(crate) fn drive_length(info: Option<&HostDriveInfo>, reader: &mut impl Seek) -> Option<u64> {
    info.and_then(|info| info.size_bytes)
        .filter(|size| *size > 0)
        .or_else(|| reader.seek(SeekFrom::End(0)).ok().filter(|size| *size > 0))
}

/// Resolve the ordinal `partition` against a drive layout, returning the
/// extent to open raw.
///
/// The length is bounded to what the medium can supply: the extent the entry
/// declares, cut to the end of the drive, and [`u64::MAX`] when neither the
/// entry nor the drive states a length — the same "unknown" the rest of the
/// device layer uses for a whole drive it cannot measure.
pub(crate) fn scanned_extent(layout: &DriveLayout, partition: usize) -> Option<(u64, u64)> {
    let selected: &LayoutPartition = layout.partitions.get(partition)?;
    let available = selected.available_bytes();
    let length = if available > 0 {
        available
    } else if layout.size_bytes > selected.offset {
        layout.size_bytes - selected.offset
    } else {
        u64::MAX
    };
    Some((selected.offset, length))
}
