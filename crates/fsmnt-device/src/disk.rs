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

use std::mem::size_of;

use nostdio::{Read, Seek, SeekFrom};

use crate::partition_reader::PartitionReader;
use crate::{
    BOOT_SECTOR_SIZE, DetectedBootSector, GptHeader, GptPartitionEntry, Mbr, MbrPartitionEntry,
    read_gpt_header,
};

/// The layout/structure of a disk.
#[derive(Debug, Clone)]
pub enum DiskLayout {
    /// Whole disk is a single filesystem (no partition table).
    Bare(DetectedBootSector),
    /// GPT partitioned disk — header cached for partition lookup.
    Gpt {
        /// The validated GPT header: read from LBA 1, or — when the primary
        /// is damaged — the backup copy in the disk's last sector, whose
        /// entry array sits just before it.
        header: GptHeader,
        /// Whether the header came from the backup at the end of the disk
        /// because the primary at LBA 1 was unreadable or invalid. The
        /// partitions it describes are the same; the front of the disk is
        /// what is damaged.
        from_backup: bool,
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
            DiskLayout::Gpt { header, .. } => {
                usize::try_from(header.num_partition_entries.get()).unwrap_or(usize::MAX)
            }
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
    pub fn gpt_partition(&mut self, index: usize) -> std::io::Result<GptPartitionEntry> {
        let DiskLayout::Gpt { header, .. } = &self.layout else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Not a GPT disk",
            ));
        };

        let entry_count = usize::try_from(header.num_partition_entries.get()).unwrap_or(usize::MAX);
        if index >= entry_count {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Partition index {index} out of range"),
            ));
        }

        let sector_size = u64::from(self.sector_size);
        let entry_size = u64::from(header.partition_entry_size.get());
        let entry_lba = header.partition_entry_lba.get();

        let gpt_entry_bytes = size_of::<GptPartitionEntry>();
        let gpt_entry_bytes_u64 = u64::try_from(gpt_entry_bytes).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "GPT entry type size exceeds u64",
            )
        })?;
        if entry_size < gpt_entry_bytes_u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("GPT entry size {entry_size} is smaller than minimum {gpt_entry_bytes}"),
            ));
        }

        // Calculate the absolute byte offset of the entry.
        let index = u64::try_from(index).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "GPT partition index exceeds u64",
            )
        })?;
        let entry_offset = entry_lba
            .checked_mul(sector_size)
            .and_then(|array_offset| {
                index
                    .checked_mul(entry_size)
                    .and_then(|offset| array_offset.checked_add(offset))
            })
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "GPT partition entry offset overflow",
                )
            })?;

        // Raw disk I/O on Windows requires sector-aligned reads: find the
        // sector containing this entry and read whole sectors.
        let sector_offset = (entry_offset / sector_size) * sector_size;
        let offset_within_sector = usize::try_from(entry_offset % sector_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "offset within logical sector exceeds usize",
            )
        })?;
        let sector_size_usize = usize::try_from(self.sector_size).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "logical sector size exceeds usize",
            )
        })?;

        self.reader.seek(SeekFrom::Start(sector_offset))?;
        let mut sector_buf = vec![0u8; sector_size_usize];
        self.reader.read_exact(&mut sector_buf)?;

        // Extract the entry from within the sector, using the header's
        // entry size for stride but reading only GptPartitionEntry bytes.
        let entry_end = offset_within_sector
            .checked_add(gpt_entry_bytes)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "GPT entry end overflow")
            })?;
        if entry_end > sector_size_usize {
            // Entry spans a sector boundary — read the next sector too.
            let mut buf = vec![0u8; gpt_entry_bytes];
            let first_part = sector_size_usize - offset_within_sector;
            buf[..first_part].copy_from_slice(&sector_buf[offset_within_sector..]);

            let mut sector_buf2 = vec![0u8; sector_size_usize];
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
    /// Returns an error if seeking or reading the probe fails. Reaching the
    /// end of a short source is not an error; detection uses the bytes read.
    pub fn detect_boot_sector_at(&mut self, offset: u64) -> std::io::Result<DetectedBootSector> {
        crate::detection::detect_boot_sector_at(&mut self.reader, offset)
    }

    /// Detect the disk layout by classifying the first sectors.
    fn detect_layout(reader: &mut R, sector_size: u32) -> std::io::Result<DiskLayout> {
        let probe = crate::detection::probe_at(reader, 0)?;
        if probe.prefix.len() < BOOT_SECTOR_SIZE {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        let detected = probe.detected;

        match detected {
            DetectedBootSector::Ntfs
            | DetectedBootSector::Fat12
            | DetectedBootSector::Fat16
            | DetectedBootSector::Fat32
            | DetectedBootSector::ExFat
            | DetectedBootSector::BitLocker
            | DetectedBootSector::Ext
            | DetectedBootSector::Apfs
            | DetectedBootSector::Btrfs => Ok(DiskLayout::Bare(detected)),

            DetectedBootSector::GptPartitioned => {
                match read_gpt_header(reader, u64::from(sector_size)) {
                    Ok(header) => Ok(DiskLayout::Gpt {
                        header,
                        from_backup: false,
                    }),
                    // The boot sector promised GPT but LBA 1 does not hold
                    // a valid header: the copy at the end may.
                    Err(error) => Self::backup_gpt_layout(reader, sector_size)?.ok_or(error),
                }
            }

            DetectedBootSector::MbrPartitioned => {
                let mbr = Mbr::from_bytes(&probe.prefix[..BOOT_SECTOR_SIZE]).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid MBR")
                })?;
                // A protective MBR whose GPT header at LBA 1 is gone is a
                // wiped-front GPT disk, not an MBR disk with one 0xEE
                // partition; the backup header at the end says which.
                if mbr.is_gpt_protective()
                    && let Some(layout) = Self::backup_gpt_layout(reader, sector_size)?
                {
                    return Ok(layout);
                }
                Ok(DiskLayout::Mbr {
                    mbr: Box::new(*mbr),
                })
            }

            DetectedBootSector::Unknown => {
                Ok(Self::backup_gpt_layout(reader, sector_size)?.unwrap_or(DiskLayout::Unknown))
            }
        }
    }

    /// The GPT layout described by the backup header in the last sector, if
    /// one is there and stands up.
    ///
    /// GPT writes a second copy of the header into the disk's last LBA and
    /// the entry array into the sectors before it, precisely so a damaged
    /// first track (`dd if=/dev/zero of=/dev/sdX count=64`, a bootloader
    /// gone wrong, a partial acquisition) does not lose the table. The copy
    /// is trusted only when its signature, its own header CRC-32, and its
    /// self-address (`current_lba` naming the last sector) all agree; the
    /// entry array it points at is read on demand like the primary's.
    ///
    /// # Errors
    ///
    /// Returns an error when the source's length cannot be determined or
    /// the last sector cannot be read.
    fn backup_gpt_layout(reader: &mut R, sector_size: u32) -> std::io::Result<Option<DiskLayout>> {
        let sector = u64::from(sector_size);
        let length = reader.seek(SeekFrom::End(0))?;
        if length < sector * 2 {
            return Ok(None);
        }
        let last_lba = length / sector - 1;
        reader.seek(SeekFrom::Start(last_lba * sector))?;
        let mut buffer = [0u8; 512];
        reader.read_exact(&mut buffer[..92])?;
        let Some(header) = GptHeader::from_bytes(&buffer[..92]) else {
            return Ok(None);
        };
        if !header.is_valid() || header.current_lba.get() != last_lba {
            return Ok(None);
        }
        // Header CRC covers `header_size` bytes with the CRC field zeroed;
        // GPT headers are 92 bytes in every implementation that matters, and
        // a claimed size outside a sector is corruption, not a longer header.
        let header_size = header.header_size.get() as usize;
        if !(92..=512).contains(&header_size) {
            return Ok(None);
        }
        let mut covered = [0u8; 512];
        reader.seek(SeekFrom::Start(last_lba * sector))?;
        reader.read_exact(&mut covered[..header_size])?;
        covered[16..20].fill(0);
        if crc32fast::hash(&covered[..header_size]) != header.header_crc32.get() {
            return Ok(None);
        }
        // The entry array must precede the backup header, on the disk.
        if header.partition_entry_lba.get() >= last_lba {
            return Ok(None);
        }
        Ok(Some(DiskLayout::Gpt {
            header: *header,
            from_backup: true,
        }))
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

#[cfg(test)]
mod backup_gpt_tests {
    use super::*;
    use std::io::Cursor;

    const SECTOR: usize = 512;
    /// 128 sectors: protective MBR, primary header, 32-sector entry array,
    /// data, 32-sector backup entry array, backup header in the last sector.
    const SECTORS: usize = 128;

    /// A GPT header for `current`/`backup` LBAs whose entry array (4 entries
    /// of 128 bytes) starts at `entries_lba`, with a correct header CRC.
    fn gpt_header(current: u64, backup: u64, entries_lba: u64) -> [u8; 92] {
        let mut h = [0u8; 92];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        h[12..16].copy_from_slice(&92_u32.to_le_bytes());
        h[24..32].copy_from_slice(&current.to_le_bytes());
        h[32..40].copy_from_slice(&backup.to_le_bytes());
        h[40..48].copy_from_slice(&34_u64.to_le_bytes()); // first usable
        h[48..56].copy_from_slice(&30_u64.to_le_bytes()); // last usable
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&4_u32.to_le_bytes());
        h[84..88].copy_from_slice(&128_u32.to_le_bytes());
        let crc = crc32fast::hash(&h);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }

    /// One partition entry: Linux filesystem type, LBAs 8..=15.
    fn entry() -> [u8; 128] {
        let mut e = [0u8; 128];
        e[0..16].copy_from_slice(&GptPartitionEntry::LINUX_FILESYSTEM_GUID);
        e[16..32].copy_from_slice(&[0x22; 16]);
        e[32..40].copy_from_slice(&8_u64.to_le_bytes());
        e[40..48].copy_from_slice(&15_u64.to_le_bytes());
        e
    }

    /// A complete GPT disk with primary and backup structures.
    fn gpt_disk() -> Vec<u8> {
        let mut disk = vec![0u8; SECTOR * SECTORS];
        let last = (SECTORS - 1) as u64;
        // Protective MBR.
        disk[446] = 0x00;
        disk[446 + 4] = 0xEE;
        disk[446 + 8..446 + 12].copy_from_slice(&1_u32.to_le_bytes());
        disk[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
        disk[510] = 0x55;
        disk[511] = 0xAA;
        // Primary header at LBA 1, entries at LBA 2.
        disk[SECTOR..SECTOR + 92].copy_from_slice(&gpt_header(1, last, 2));
        disk[SECTOR * 2..SECTOR * 2 + 128].copy_from_slice(&entry());
        // Backup entries at last-32, backup header in the last sector.
        let backup_entries = SECTOR * (SECTORS - 33);
        disk[backup_entries..backup_entries + 128].copy_from_slice(&entry());
        let backup_header = SECTOR * (SECTORS - 1);
        disk[backup_header..backup_header + 92].copy_from_slice(&gpt_header(
            last,
            1,
            (SECTORS - 33) as u64,
        ));
        disk
    }

    fn first_partition_extent(disk: &mut Disk<Cursor<Vec<u8>>>) -> (u64, u64) {
        let e = disk.gpt_partition(0).expect("entry 0");
        (e.start_offset(512), e.size_bytes(512))
    }

    #[test]
    fn intact_disk_uses_the_primary_header() {
        let mut disk = Disk::new(Cursor::new(gpt_disk())).expect("open");
        assert!(matches!(
            disk.layout(),
            DiskLayout::Gpt {
                from_backup: false,
                ..
            }
        ));
        assert_eq!(first_partition_extent(&mut disk), (8 * 512, 8 * 512));
    }

    #[test]
    fn wiped_front_falls_back_to_the_backup_header() {
        // Zero the whole first track: MBR, primary header, primary entries.
        let mut image = gpt_disk();
        image[..SECTOR * 34].fill(0);
        let mut disk = Disk::new(Cursor::new(image)).expect("open");
        assert!(
            matches!(
                disk.layout(),
                DiskLayout::Gpt {
                    from_backup: true,
                    ..
                }
            ),
            "backup header must be found: {:?}",
            disk.layout()
        );
        assert_eq!(disk.partition_count(), 4);
        assert_eq!(first_partition_extent(&mut disk), (8 * 512, 8 * 512));
    }

    #[test]
    fn protective_mbr_with_dead_primary_header_uses_the_backup() {
        // Only LBA 1..=33 wiped; the protective MBR survives, which used to
        // classify as an MBR disk with a single 0xEE partition.
        let mut image = gpt_disk();
        image[SECTOR..SECTOR * 34].fill(0);
        let disk = Disk::new(Cursor::new(image)).expect("open");
        assert!(matches!(
            disk.layout(),
            DiskLayout::Gpt {
                from_backup: true,
                ..
            }
        ));
    }

    #[test]
    fn a_corrupt_backup_header_is_not_trusted() {
        let mut image = gpt_disk();
        image[..SECTOR * 34].fill(0);
        // Flip a byte inside the backup header's covered region: the CRC no
        // longer matches, so it must be rejected rather than half-trusted.
        let backup_header = SECTOR * (SECTORS - 1);
        image[backup_header + 40] ^= 0x01;
        let disk = Disk::new(Cursor::new(image)).expect("open");
        assert!(matches!(disk.layout(), DiskLayout::Unknown));
    }
}
