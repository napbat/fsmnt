use crate::attribute::NtfsAttributeType;
use crate::boot_sector::{BootSector, BootSectorExt};
use crate::cluster_bitmap::NtfsClusterBitmap;
use crate::error::{NtfsError, Result};
use crate::file::{KnownNtfsFileRecordNumber, NtfsFile};
use crate::io::{Read, Seek, SeekFrom};
use crate::metafiles::NtfsAttrDef;
use crate::metafiles::NtfsBadClusters;
use crate::mft::NtfsMftEntries;
use crate::structured_values::{NtfsVolumeInformation, NtfsVolumeName};
use crate::types::NtfsPosition;
use crate::upcase_table::UpcaseTable;
use fs_common::boot_sector::BOOT_SECTOR_SIZE;
use fs_common::io::FsReadSeek;
use zerocopy::FromBytes;

/// Root structure describing an NTFS filesystem.
#[derive(Debug)]
pub struct Ntfs {
    /// The size of a single cluster, in bytes. This is usually 4096.
    cluster_size: u32,
    /// The size of a single sector, in bytes. This is usually 512.
    sector_size: u16,
    /// Size of the filesystem, in bytes.
    size: u64,
    /// Absolute position of the Master File Table (MFT), in bytes.
    mft_position: NtfsPosition,
    /// Absolute position of the MFT Mirror ($`MFTMirr`), in bytes.
    mft_mirror_position: NtfsPosition,
    /// Size of a single File Record, in bytes.
    file_record_size: u32,
    /// Serial number of the NTFS volume.
    serial_number: u64,
    /// Table of Unicode uppercase characters (only required for case-insensitive comparisons).
    upcase_table: Option<UpcaseTable>,
}

impl Ntfs {
    /// Creates a new [`Ntfs`] object from a reader and validates its boot sector information.
    ///
    /// The reader must cover the entire NTFS partition, not more and not less.
    /// It will be rewinded to the beginning before reading anything.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn new<T>(fs: &mut T) -> Result<Self>
    where
        T: Read + Seek,
    {
        // Read and validate the boot sector.
        fs.rewind()?;
        let mut boot_sector_bytes = [0u8; BOOT_SECTOR_SIZE];
        fs.read_exact(&mut boot_sector_bytes)?;
        let boot_sector = BootSector::ref_from_bytes(&boot_sector_bytes).map_err(|_| {
            NtfsError::BufferTooSmall {
                expected: BOOT_SECTOR_SIZE,
                actual: boot_sector_bytes.len(),
            }
        })?;
        boot_sector.validate()?;

        let cluster_size = boot_sector.cluster_size()?;
        let sector_size = boot_sector.sector_size()?;
        let total_sectors = boot_sector.total_sectors();
        let size = total_sectors
            .checked_mul(u64::from(sector_size))
            .ok_or(NtfsError::TotalSectorsTooBig { total_sectors })?;
        let mft_position = NtfsPosition::none();
        let mft_mirror_position = NtfsPosition::none();
        let file_record_size = boot_sector.file_record_size()?;
        let serial_number = boot_sector.serial_number();
        let upcase_table = None;

        let mut ntfs = Self {
            cluster_size,
            sector_size,
            size,
            mft_position,
            mft_mirror_position,
            file_record_size,
            serial_number,
            upcase_table,
        };
        ntfs.mft_position = boot_sector.mft_lcn()?.position(&ntfs)?;
        ntfs.mft_mirror_position = boot_sector.mft_mirr_lcn()?.position(&ntfs)?;

        Ok(ntfs)
    }

    /// Returns the size of a single cluster, in bytes.
    #[must_use]
    pub fn cluster_size(&self) -> u32 {
        self.cluster_size
    }

    /// Returns the [`NtfsFile`] for the given NTFS File Record Number.
    ///
    /// The first few NTFS files have fixed indexes and contain filesystem
    /// management information (see the [`KnownNtfsFileRecordNumber`] enum).
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn file<'n, T>(&'n self, fs: &mut T, file_record_number: u64) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        let offset = file_record_number
            .checked_mul(u64::from(self.file_record_size))
            .ok_or(NtfsError::InvalidFileRecordNumber { file_record_number })?;

        // The MFT may be split into multiple data runs, referenced by its $DATA attribute.
        // We therefore read it just like any other non-resident attribute value.
        // However, this code assumes that the MFT does not have an Attribute List!
        //
        let mft_position = self.mft_position.value().ok_or(NtfsError::InvalidMftLcn)?;
        let mft = NtfsFile::new(self, fs, mft_position, 0)?;
        let mft_data_attribute =
            mft.find_resident_attribute(NtfsAttributeType::Data, None, None)?;
        let mut mft_data_value = mft_data_attribute.value(fs)?;

        mft_data_value.seek(fs, SeekFrom::Start(offset))?;
        let position = mft_data_value
            .data_position()
            .value()
            .ok_or(NtfsError::InvalidFileRecordNumber { file_record_number })?;

        NtfsFile::new(self, fs, position, file_record_number)
    }

    /// Returns the size of a File Record of this NTFS filesystem, in bytes.
    #[must_use]
    pub fn file_record_size(&self) -> u32 {
        self.file_record_size
    }

    /// Returns a sequential iterator over all MFT file records.
    ///
    /// This is much more efficient than calling [`Ntfs::file`] in a loop,
    /// because it opens the MFT `$DATA` attribute only once and caches its
    /// physical layout.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn mft_entries<T>(&self, fs: &mut T) -> Result<NtfsMftEntries>
    where
        T: Read + Seek,
    {
        NtfsMftEntries::new(self, fs)
    }

    /// Loads the attribute definition table (`$AttrDef`, MFT entry 4).
    ///
    /// Returns an [`NtfsAttrDef`] that can be queried for attribute type
    /// metadata such as human-readable names, flags, and size constraints.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn attr_def<T: Read + Seek>(&self, fs: &mut T) -> Result<NtfsAttrDef> {
        NtfsAttrDef::load(self, fs)
    }

    /// Loads the bad cluster list (`$BadClus`, MFT entry 8).
    ///
    /// Returns an [`NtfsBadClusters`] that can report whether the volume
    /// has any bad clusters and enumerate their locations.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn bad_clusters<T: Read + Seek>(&self, fs: &mut T) -> Result<NtfsBadClusters> {
        NtfsBadClusters::load(self, fs)
    }

    /// Create a scanner for deleted (not-in-use) MFT records.
    ///
    /// Loads the cluster bitmap and MFT entry iterator, then yields
    /// deleted files one at a time via [`NtfsDeletedFileScanner::next`].
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    #[cfg(feature = "std")]
    pub fn deleted_files<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<crate::deleted_files::NtfsDeletedFileScanner> {
        crate::deleted_files::NtfsDeletedFileScanner::new(self, fs)
    }

    /// Loads and parses the `$LogFile` (MFT entry 2).
    ///
    /// Returns an [`NtfsLogFile`] containing all parsed log records,
    /// restart information, and the open attribute table.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    #[cfg(feature = "std")]
    pub fn logfile<T: Read + Seek>(&self, fs: &mut T) -> Result<crate::logfile::NtfsLogFile> {
        crate::logfile::NtfsLogFile::load(self, fs)
    }

    /// Loads the cluster allocation bitmap (`$Bitmap`, MFT entry 6).
    ///
    /// Returns an [`NtfsClusterBitmap`] that can be used to query whether
    /// individual clusters are allocated or free.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn cluster_bitmap<T: Read + Seek>(&self, fs: &mut T) -> Result<NtfsClusterBitmap> {
        NtfsClusterBitmap::load(self, fs)
    }

    /// Creates a signature-based carver for unallocated clusters.
    ///
    /// Returns an [`NtfsClusterCarver`] that scans clusters the `$Bitmap`
    /// reports as free for known file signatures, recovering content
    /// even when the originating MFT records have been reused.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn carve_unallocated<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<crate::cluster_carving::NtfsClusterCarver> {
        crate::cluster_carving::NtfsClusterCarver::new(self, fs)
    }

    /// Builds an [`NtfsParentMap`] by scanning the entire MFT.
    ///
    /// This is a convenience wrapper around [`NtfsParentMap::build`].
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    #[cfg(feature = "std")]
    pub fn build_parent_map<T: Read + Seek>(
        &self,
        fs: &mut T,
    ) -> Result<crate::parent_map::NtfsParentMap> {
        crate::parent_map::NtfsParentMap::build(self, fs)
    }

    /// Returns the absolute byte position of the Master File Table (MFT).
    ///
    /// This [`NtfsPosition`] is guaranteed to be nonzero.
    #[must_use]
    pub fn mft_position(&self) -> NtfsPosition {
        self.mft_position
    }

    /// Returns the absolute byte position of the MFT Mirror ($`MFTMirr`).
    ///
    /// This [`NtfsPosition`] is guaranteed to be nonzero.
    #[must_use]
    pub fn mft_mirror_position(&self) -> NtfsPosition {
        self.mft_mirror_position
    }

    /// Validates the MFT Mirror ($`MFTMirr`) against the primary MFT.
    ///
    /// Compares records 0-3 byte-for-byte (post-fixup) and returns
    /// per-record match/mismatch status.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn mft_mirr_validation<T>(
        &self,
        fs: &mut T,
    ) -> Result<crate::analysis::NtfsMftMirrValidation>
    where
        T: Read + Seek,
    {
        crate::analysis::validate_mft_mirror(self, fs)
    }

    /// Reads the $`UpCase` file from the filesystem and stores it in this [`Ntfs`] object.
    ///
    /// This function only needs to be called if case-insensitive comparisons are later performed
    /// (i.e. finding files).
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn read_upcase_table<T>(&mut self, fs: &mut T) -> Result<()>
    where
        T: Read + Seek,
    {
        let upcase_table = UpcaseTable::read(self, fs)?;
        self.upcase_table = Some(upcase_table);
        Ok(())
    }

    /// Returns the root directory of this NTFS volume as an [`NtfsFile`].
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn root_directory<'n, T>(&'n self, fs: &mut T) -> Result<NtfsFile<'n>>
    where
        T: Read + Seek,
    {
        self.file(fs, KnownNtfsFileRecordNumber::RootDirectory.as_u64())
    }

    /// Returns the size of a single sector in bytes.
    #[must_use]
    pub fn sector_size(&self) -> u16 {
        self.sector_size
    }

    /// Returns the 64-bit serial number of this NTFS volume.
    #[must_use]
    pub fn serial_number(&self) -> u64 {
        self.serial_number
    }

    /// Returns the partition size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the stored [`UpcaseTable`].
    ///
    /// # Panics
    ///
    /// Panics if [`read_upcase_table`][Ntfs::read_upcase_table] had not been called.
    pub(crate) fn upcase_table(&self) -> &UpcaseTable {
        self.upcase_table
            .as_ref()
            .expect("You need to call read_upcase_table first")
    }

    /// Builds an [`Ntfs`] with a caller-supplied [`UpcaseTable`] and
    /// otherwise default 512-byte cluster geometry, for unit tests that
    /// need case-insensitive comparison without a real `$UpCase` file.
    #[cfg(test)]
    pub(crate) fn with_upcase_table_for_test(upcase_table: UpcaseTable) -> Self {
        Self {
            cluster_size: 512,
            sector_size: 512,
            size: 0,
            mft_position: NtfsPosition::none(),
            mft_mirror_position: NtfsPosition::none(),
            file_record_size: 1024,
            serial_number: 0,
            upcase_table: Some(upcase_table),
        }
    }

    /// Returns an [`NtfsVolumeInformation`] containing general information about
    /// the volume, like the NTFS version.
    ///
    /// # Errors
    ///
    /// Returns an error if required NTFS metadata is malformed or cannot be read from the underlying stream.
    pub fn volume_info<T>(&self, fs: &mut T) -> Result<NtfsVolumeInformation>
    where
        T: Read + Seek,
    {
        let volume_file = self.file(fs, KnownNtfsFileRecordNumber::Volume.as_u64())?;
        volume_file.find_resident_attribute_structured_value::<NtfsVolumeInformation>(None)
    }

    /// Returns an [`NtfsVolumeName`] to read the volume name (also called volume label)
    /// of this NTFS volume.
    ///
    /// Note that a volume may also have no label, which is why the return value is further
    /// encapsulated in an `Option`.
    pub fn volume_name<T>(&self, fs: &mut T) -> Option<Result<NtfsVolumeName>>
    where
        T: Read + Seek,
    {
        let volume_file = iter_try!(self.file(fs, KnownNtfsFileRecordNumber::Volume.as_u64()));

        match volume_file.find_resident_attribute_structured_value::<NtfsVolumeName>(None) {
            Ok(volume_name) => Some(Ok(volume_name)),
            Err(NtfsError::AttributeNotFound { .. }) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basics() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        assert_eq!(ntfs.cluster_size(), 512);
        assert_eq!(ntfs.sector_size(), 512);
        // 8MB filesystem: 8388608 bytes total, 8388096 bytes usable (minus boot sector backup)
        assert_eq!(ntfs.size(), 8_388_096);
    }

    #[test]
    fn test_volume_info() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let volume_info = ntfs.volume_info(&mut testfs1).unwrap();
        assert_eq!(volume_info.major_version(), 3);
        assert_eq!(volume_info.minor_version(), 1);
    }

    #[test]
    fn test_volume_name() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let volume_name = ntfs.volume_name(&mut testfs1).unwrap().unwrap();
        assert_eq!(volume_name.name_length(), 14);
        assert_eq!(volume_name.name(), "mylabel");
    }

    /// Builds a minimal but valid 512-byte NTFS boot sector with explicit,
    /// distinct geometry so each accessor returns an unmistakable value.
    ///
    /// Byte offsets (BPB/EBPB per fs-common::boot_sector):
    ///   0x00 jump, 0x03 "NTFS    " OEM ID
    ///   0x0B `bytes_per_sector` (u16), 0x0D `sectors_per_cluster` (u8)
    ///   0x28 `total_sectors` (u64), 0x30 `mft_lcn` (u64), 0x38 `mft_mirror_lcn` (u64)
    ///   0x40 `clusters_per_mft_record` (i8), 0x48 `volume_serial_number` (u64)
    ///   0x1FE boot signature (0xAA55)
    fn build_ntfs_fs() -> std::io::Cursor<std::vec::Vec<u8>> {
        let mut buf = std::vec![0u8; 512];
        buf[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // sector_size 512
        buf[0x0D] = 2; // sectors_per_cluster -> cluster_size 1024
        buf[0x28..0x30].copy_from_slice(&2048u64.to_le_bytes()); // total_sectors
        buf[0x30..0x38].copy_from_slice(&4u64.to_le_bytes()); // mft_lcn
        buf[0x38..0x40].copy_from_slice(&8u64.to_le_bytes()); // mft_mirror_lcn
        buf[0x40] = (-10i8).cast_unsigned(); // clusters_per_mft_record -> 1024-byte records
        buf[0x48..0x50].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes()); // serial
        buf[510] = 0x55;
        buf[511] = 0xAA;
        std::io::Cursor::new(buf)
    }

    #[test]
    fn synthetic_boot_sector_geometry() {
        let mut fs = build_ntfs_fs();
        let ntfs = Ntfs::new(&mut fs).unwrap();

        // cluster_size = sector_size * sectors_per_cluster = 512 * 2.
        assert_eq!(ntfs.cluster_size(), 1024);
        // sector_size from the BPB.
        assert_eq!(ntfs.sector_size(), 512);
        // file_record_size = 2^10 from clusters_per_mft_record = -10.
        assert_eq!(ntfs.file_record_size(), 1024);
        // size = total_sectors * sector_size = 2048 * 512.
        assert_eq!(ntfs.size(), 1_048_576);
        // serial number verbatim from offset 0x48.
        assert_eq!(ntfs.serial_number(), 0x0123_4567_89AB_CDEF);
        // MFT position = mft_lcn * cluster_size = 4 * 1024.
        assert_eq!(ntfs.mft_position().value().unwrap().get(), 4 * 1024);
    }
}
