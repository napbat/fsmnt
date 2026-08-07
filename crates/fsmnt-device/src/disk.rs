//! Disk and partition abstraction.
//!
//! [`Disk`] is a thin wrapper over any `Read + Seek` source (a raw block
//! device opened via a platform crate, or a disk image file) that:
//!
//! - Detects the disk layout (bare filesystem vs GPT vs MBR)
//! - Caches minimal header info (GPT header or MBR)
//! - Provides on-demand partition access
//!
//! Partition entries are read on demand using the raw [`GptPartitionEntry`]
//! / [`MbrPartitionEntry`] types.  Filesystem detection is left to the
//! caller (see [`Disk::detect_boot_sector_at`]).

use std::io::{Read, Seek, SeekFrom};
use std::mem::size_of;

use crate::partition_reader::PartitionReader;
use crate::{
    BOOT_SECTOR_SIZE, DetectedBootSector, FS_DETECT_PROBE_SIZE, GptHeader, GptPartitionEntry, Mbr,
    MbrPartitionEntry, read_gpt_header,
};

/// The layout/structure of a disk.
#[derive(Debug, Clone)]
pub enum DiskLayout {
    /// Whole disk is a single filesystem (no partition table).
    Bare(DetectedBootSector),
    /// GPT partitioned disk — header cached for partition lookup.
    Gpt {
        /// The validated GPT header read from LBA 1.
        header: GptHeader,
    },
    /// MBR partitioned disk — MBR cached for partition lookup.
    Mbr {
        /// The parsed MBR sector.
        mbr: Box<Mbr>,
    },
    /// Unknown/unrecognized layout.
    Unknown,
}

/// Default sector size (standard for most disks).
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// A disk or image that may contain partitions or a direct filesystem.
///
/// This is a thin wrapper that detects disk layout and provides on-demand
/// access to partitions.  It does NOT eagerly enumerate all partitions or
/// detect filesystems — that's left to the caller.
pub struct Disk<R> {
    reader: R,
    layout: DiskLayout,
    /// Logical sector size in bytes (typically 512 or 4096).
    sector_size: u32,
}

impl<R: Read + Seek> Disk<R> {
    /// Open a disk and auto-detect its layout.
    ///
    /// Reads the start of the disk to determine whether it contains a
    /// direct filesystem (FAT, NTFS, …), an MBR partition table, or a GPT
    /// partition table.
    ///
    /// Uses the default sector size of 512 bytes.  For 4Kn drives or when
    /// the sector size is known, use [`with_sector_size`](Self::with_sector_size).
    ///
    /// # Errors
    ///
    /// Returns an error if the disk cannot be read or is smaller than the
    /// detection probe.
    pub fn new(reader: R) -> std::io::Result<Self> {
        Self::with_sector_size(reader, DEFAULT_SECTOR_SIZE)
    }

    /// Open a disk with a specific sector size.
    ///
    /// Use this when the sector size is known from OS enumeration (e.g.
    /// `IOCTL_DISK_GET_DRIVE_GEOMETRY` on Windows or sysfs on Linux).
    ///
    /// # Errors
    ///
    /// Returns an error if the disk cannot be read or is smaller than the
    /// detection probe.
    pub fn with_sector_size(mut reader: R, sector_size: u32) -> std::io::Result<Self> {
        let layout = Self::detect_layout(&mut reader, sector_size)?;
        Ok(Self {
            reader,
            layout,
            sector_size,
        })
    }

    /// The sector size in bytes.
    #[must_use]
    pub fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// The detected disk layout.
    #[must_use]
    pub fn layout(&self) -> &DiskLayout {
        &self.layout
    }

    /// Whether this disk has a partition table.
    #[must_use]
    pub fn is_partitioned(&self) -> bool {
        matches!(self.layout, DiskLayout::Gpt { .. } | DiskLayout::Mbr { .. })
    }

    /// The number of partition entries.
    ///
    /// For GPT this is the size of the partition entry array (including
    /// empty entries); for MBR the number of valid primary partitions.
    #[must_use]
    pub fn partition_count(&self) -> usize {
        match &self.layout {
            DiskLayout::Gpt { header } => header.num_partition_entries.get() as usize,
            DiskLayout::Mbr { mbr } => mbr.valid_partitions().count(),
            _ => 0,
        }
    }

    /// Read a GPT partition entry by index (on demand).
    ///
    /// Only valid when [`layout`](Self::layout) is [`DiskLayout::Gpt`].
    ///
    /// # Errors
    ///
    /// Returns an error if the disk is not GPT, the index is out of range,
    /// or the entry cannot be read.
    ///
    /// # Panics
    ///
    /// Panics if an offset within a sector does not fit in `usize` (not
    /// possible on supported platforms).
    pub fn gpt_partition(&mut self, index: usize) -> std::io::Result<GptPartitionEntry> {
        let DiskLayout::Gpt { header } = &self.layout else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Not a GPT disk",
            ));
        };

        if index >= header.num_partition_entries.get() as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Partition index {index} out of range"),
            ));
        }

        let sector_size = u64::from(self.sector_size);
        let entry_size = u64::from(header.partition_entry_size.get());
        let entry_lba = header.partition_entry_lba.get();

        let gpt_entry_bytes = size_of::<GptPartitionEntry>();
        if entry_size < gpt_entry_bytes as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GPT entry size {entry_size} is smaller than minimum {gpt_entry_bytes}"),
            ));
        }

        // Calculate the absolute byte offset of the entry.
        let entry_offset = entry_lba * sector_size + index as u64 * entry_size;

        // Raw disk I/O on Windows requires sector-aligned reads: find the
        // sector containing this entry and read whole sectors.
        let sector_offset = (entry_offset / sector_size) * sector_size;
        let offset_within_sector =
            usize::try_from(entry_offset % sector_size).expect("sector size fits in usize");

        self.reader.seek(SeekFrom::Start(sector_offset))?;
        let mut sector_buf = vec![0u8; self.sector_size as usize];
        self.reader.read_exact(&mut sector_buf)?;

        // Extract the entry from within the sector, using the header's
        // entry size for stride but reading only GptPartitionEntry bytes.
        let entry_end = offset_within_sector + gpt_entry_bytes;
        if entry_end > self.sector_size as usize {
            // Entry spans a sector boundary — read the next sector too.
            let mut buf = vec![0u8; gpt_entry_bytes];
            let first_part = self.sector_size as usize - offset_within_sector;
            buf[..first_part].copy_from_slice(&sector_buf[offset_within_sector..]);

            let mut sector_buf2 = vec![0u8; self.sector_size as usize];
            self.reader.read_exact(&mut sector_buf2)?;
            buf[first_part..].copy_from_slice(&sector_buf2[..(gpt_entry_bytes - first_part)]);

            GptPartitionEntry::from_bytes(&buf).copied().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid GPT entry")
            })
        } else {
            GptPartitionEntry::from_bytes(&sector_buf[offset_within_sector..entry_end])
                .copied()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid GPT entry")
                })
        }
    }

    /// Get an MBR partition entry by index (from the cached MBR).
    ///
    /// Only valid when [`layout`](Self::layout) is [`DiskLayout::Mbr`].
    #[must_use]
    pub fn mbr_partition(&self, index: usize) -> Option<&MbrPartitionEntry> {
        match &self.layout {
            DiskLayout::Mbr { mbr } => mbr.partitions.get(index),
            _ => None,
        }
    }

    /// Iterate over MBR partitions (from the cached MBR).
    ///
    /// Only valid when [`layout`](Self::layout) is [`DiskLayout::Mbr`].
    /// Yields only non-empty, non-GPT-protective partitions.
    pub fn mbr_partitions(&self) -> Box<dyn Iterator<Item = &MbrPartitionEntry> + '_> {
        match &self.layout {
            DiskLayout::Mbr { mbr } => Box::new(
                mbr.partitions
                    .iter()
                    .filter(|e| !e.is_empty() && !e.is_gpt_protective()),
            ),
            _ => Box::new(std::iter::empty()),
        }
    }

    /// Borrow the underlying reader.
    pub fn reader(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Consume and return the underlying reader.
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Create a [`PartitionReader`] for a GPT partition by index.
    ///
    /// # Errors
    ///
    /// Returns an error if the disk is not GPT, the index is out of range,
    /// or the partition entry is empty.
    pub fn gpt_partition_reader(
        &mut self,
        index: usize,
    ) -> std::io::Result<PartitionReader<&mut R>> {
        let entry = self.gpt_partition(index)?;

        if entry.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Partition is empty",
            ));
        }

        let offset = entry.start_offset(self.sector_size);
        let size = entry.size_bytes(self.sector_size);
        Ok(PartitionReader::new(&mut self.reader, offset, size))
    }

    /// Create a [`PartitionReader`] for an MBR partition by index.
    ///
    /// # Errors
    ///
    /// Returns an error if the disk is not MBR or the index has no
    /// partition entry.
    pub fn mbr_partition_reader(
        &mut self,
        index: usize,
    ) -> std::io::Result<PartitionReader<&mut R>> {
        let (offset, size) = {
            let entry = self.mbr_partition(index).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "Partition not found")
            })?;
            (
                entry.start_offset(self.sector_size),
                entry.size_bytes(self.sector_size),
            )
        };
        Ok(PartitionReader::new(&mut self.reader, offset, size))
    }

    /// Create a [`PartitionReader`] for the whole disk (offset 0).
    pub fn disk_reader(&mut self) -> PartitionReader<&mut R> {
        PartitionReader::new(&mut self.reader, 0, u64::MAX)
    }

    /// Detect the boot sector type on a partition (reads the probe at
    /// `offset`).
    ///
    /// # Errors
    ///
    /// Returns an error if the probe cannot be read.
    pub fn detect_boot_sector_at(&mut self, offset: u64) -> std::io::Result<DetectedBootSector> {
        self.reader.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; FS_DETECT_PROBE_SIZE];
        self.reader.read_exact(&mut buf)?;
        Ok(DetectedBootSector::from_bytes(&buf))
    }

    /// Detect the disk layout by classifying the first sectors.
    fn detect_layout(reader: &mut R, sector_size: u32) -> std::io::Result<DiskLayout> {
        // Read FS_DETECT_PROBE_SIZE bytes so filesystem-type detection
        // (including ext) works for bare-filesystem disks.
        reader.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; FS_DETECT_PROBE_SIZE];
        reader.read_exact(&mut buf)?;

        let detected = DetectedBootSector::from_bytes(&buf);

        match detected {
            DetectedBootSector::Ntfs
            | DetectedBootSector::Fat12
            | DetectedBootSector::Fat16
            | DetectedBootSector::Fat32
            | DetectedBootSector::ExFat
            | DetectedBootSector::BitLocker
            | DetectedBootSector::Ext
            | DetectedBootSector::Apfs => Ok(DiskLayout::Bare(detected)),

            DetectedBootSector::GptPartitioned => {
                let header = read_gpt_header(reader, u64::from(sector_size))?;
                Ok(DiskLayout::Gpt { header })
            }

            DetectedBootSector::MbrPartitioned => {
                // MBR parsing only looks at the first 512 bytes of buf.
                let mbr = Mbr::from_bytes(&buf[..BOOT_SECTOR_SIZE]).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid MBR")
                })?;
                Ok(DiskLayout::Mbr {
                    mbr: Box::new(*mbr),
                })
            }

            DetectedBootSector::Unknown => Ok(DiskLayout::Unknown),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn empty_image(size: usize) -> Cursor<Vec<u8>> {
        Cursor::new(vec![0u8; size])
    }

    #[test]
    fn unknown_layout_for_zeroed_image() {
        let disk = Disk::new(empty_image(4096)).expect("open");
        assert!(matches!(disk.layout(), DiskLayout::Unknown));
        assert!(!disk.is_partitioned());
        assert_eq!(disk.partition_count(), 0);
    }

    #[test]
    fn default_sector_size_is_512() {
        let disk = Disk::new(empty_image(4096)).expect("open");
        assert_eq!(disk.sector_size(), 512);
    }

    #[test]
    fn custom_sector_size() {
        let disk = Disk::with_sector_size(empty_image(4096), 4096).expect("open");
        assert_eq!(disk.sector_size(), 4096);
    }

    #[test]
    fn detect_boot_sector_at_reads_from_offset() {
        let mut disk = Disk::new(empty_image(4096)).expect("open");
        let bs = disk.detect_boot_sector_at(0).expect("detect");
        assert!(
            matches!(bs, DetectedBootSector::Unknown),
            "zeroed data should be Unknown: {bs:?}",
        );
    }

    #[test]
    fn gpt_partition_on_non_gpt_errors() {
        let mut disk = Disk::new(empty_image(4096)).expect("open");
        let result = disk.gpt_partition(0);
        let err = result.expect_err("not a GPT disk");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn mbr_partition_on_non_mbr_returns_none() {
        let disk = Disk::new(empty_image(4096)).expect("open");
        assert!(disk.mbr_partition(0).is_none());
    }

    #[test]
    fn mbr_partitions_empty_on_non_mbr() {
        let disk = Disk::new(empty_image(4096)).expect("open");
        assert_eq!(disk.mbr_partitions().count(), 0);
    }

    #[test]
    fn into_inner_returns_reader() {
        let disk = Disk::new(empty_image(4096)).expect("open");
        let cursor = disk.into_inner();
        assert_eq!(cursor.into_inner().len(), 4096);
    }

    #[test]
    fn disk_reader_starts_at_zero() {
        let mut disk = Disk::new(empty_image(4096)).expect("open");
        let mut reader = disk.disk_reader();
        let pos = reader.stream_position().expect("pos");
        assert_eq!(pos, 0);
    }

    #[test]
    fn too_small_image_errors() {
        let result = Disk::new(Cursor::new(vec![0u8; 100]));
        assert!(result.is_err());
    }
}
