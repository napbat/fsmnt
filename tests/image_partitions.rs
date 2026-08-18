//! Public-API coverage for enumerating and mounting image partitions.
//!
//! Builds a small MBR-partitioned raw image (one Linux-typed partition of
//! zeroes, one NTFS partition) and drives [`fsmnt::image_layout`] and
//! [`fsmnt::ImageOpenOptions::with_partition`] over it, so the listing
//! ordinals and the mount selector are checked against the same media.

use std::io::Read;

use fsmnt::device::{DetectedBootSector, DeviceReader, FilesystemDriver, ImageFormat};
use fsmnt::{
    FsEntry, FsError, FsMetadata, FsResult, ImageLayoutKind, ImageOpenOptions, OpenImageError,
    TargetFilesystem, image_layout, open_image, open_image_with_options,
};

const SECTOR_SIZE: usize = 512;
const MEDIA_SIZE: usize = 32_768;
const MARKER_OFFSET: usize = 100;
const MARKER: u8 = 0xc7;
/// LBA and sector count of the leading data partition (no filesystem).
const DATA_START_LBA: u32 = 8;
/// Sector count of the leading data partition.
const DATA_SECTORS: u32 = 8;
/// LBA of the NTFS partition, chosen so it is not the first entry.
const NTFS_START_LBA: u32 = 16;
/// Sector count of the NTFS partition; it runs to the end of the media.
const NTFS_SECTORS: u32 = 48;

/// A filesystem that answers "not found" to everything.
struct EmptyFilesystem;

impl TargetFilesystem for EmptyFilesystem {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        Err(FsError::NotFound(path.to_string()))
    }

    fn try_exists(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn try_is_dir(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn try_is_file(&mut self, _path: &str) -> FsResult<bool> {
        Ok(false)
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        Err(FsError::NotFound(path.to_string()))
    }

    fn read_dir(&mut self, _path: &str) -> FsResult<Vec<FsEntry>> {
        Ok(Vec::new())
    }
}

/// A driver that only succeeds when handed the NTFS partition's own bytes.
struct InspectingNtfsDriver;

impl FilesystemDriver for InspectingNtfsDriver {
    fn name(&self) -> &'static str {
        "inspecting-ntfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ntfs
    }

    fn open(
        &self,
        mut reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let mut sector = [0_u8; SECTOR_SIZE];
        reader
            .read_exact(&mut sector)
            .map_err(|error| FsError::Filesystem(error.to_string()))?;
        if sector[3..11] != *b"NTFS    " || sector[MARKER_OFFSET] != MARKER {
            return Err(FsError::Filesystem(
                "driver was not positioned at the selected partition".to_string(),
            ));
        }
        Ok(Box::new(EmptyFilesystem))
    }
}

/// A registry holding only the inspecting NTFS driver.
fn registry() -> fsmnt::device::DriverRegistry {
    let mut registry = fsmnt::device::DriverRegistry::new();
    registry.register(Box::new(InspectingNtfsDriver));
    registry
}

/// Write an NTFS boot sector, marked so the driver can prove its position.
fn write_ntfs_boot_sector(media: &mut [u8], offset: usize) {
    let sector = &mut media[offset..offset + SECTOR_SIZE];
    sector[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[MARKER_OFFSET] = MARKER;
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

/// Fill one 16-byte MBR partition-table slot.
fn write_mbr_entry(entry: &mut [u8], partition_type: u8, start_lba: u32, sectors: u32) {
    entry[4] = partition_type;
    entry[8..12].copy_from_slice(&start_lba.to_le_bytes());
    entry[12..16].copy_from_slice(&sectors.to_le_bytes());
}

/// Raw media with an MBR whose second partition holds an NTFS volume.
fn mbr_partitioned_media() -> Vec<u8> {
    let mut media = vec![0_u8; MEDIA_SIZE];
    write_ntfs_boot_sector(&mut media, ntfs_offset());
    write_mbr_entry(&mut media[446..462], 0x83, DATA_START_LBA, DATA_SECTORS);
    write_mbr_entry(&mut media[462..478], 0x07, NTFS_START_LBA, NTFS_SECTORS);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

/// Byte offset of the NTFS partition within the media.
fn ntfs_offset() -> usize {
    NTFS_START_LBA as usize * SECTOR_SIZE
}

/// Write `media` into a temporary directory and hand back both.
fn image_file(media: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("disk.bin");
    std::fs::write(&path, media).expect("write raw image");
    (directory, path)
}

#[test]
fn mbr_images_are_enumerated_with_types_sizes_and_detected_filesystems() {
    let (_directory, path) = image_file(&mbr_partitioned_media());

    let layout = image_layout(&path).expect("enumerate image layout");

    assert_eq!(layout.format, ImageFormat::Raw);
    assert_eq!(layout.sector_size, 512);
    assert_eq!(layout.size_bytes, MEDIA_SIZE as u64);
    assert!(matches!(layout.kind, ImageLayoutKind::Mbr));
    assert_eq!(layout.partitions.len(), 2);

    let data = &layout.partitions[0];
    assert_eq!(data.ordinal, 0);
    assert_eq!(data.offset, u64::from(DATA_START_LBA) * 512);
    assert_eq!(data.size_bytes, u64::from(DATA_SECTORS) * 512);
    assert_eq!(data.type_name.as_deref(), Some("Linux"));
    assert_eq!(data.name, None, "MBR entries carry no label");
    assert_eq!(data.detected, Some(DetectedBootSector::Unknown));

    let ntfs = &layout.partitions[1];
    assert_eq!(ntfs.ordinal, 1);
    assert_eq!(ntfs.offset, ntfs_offset() as u64);
    assert_eq!(ntfs.size_bytes, u64::from(NTFS_SECTORS) * 512);
    assert_eq!(ntfs.type_name.as_deref(), Some("NTFS/HPFS/exFAT"));
    assert_eq!(ntfs.detected, Some(DetectedBootSector::Ntfs));
}

#[test]
fn selecting_a_partition_opens_it_bounded_to_its_own_extent() {
    let (_directory, path) = image_file(&mbr_partitioned_media());
    let options = ImageOpenOptions::new().with_partition(1);

    let opened =
        open_image_with_options(&path, &registry(), options).expect("open the NTFS partition");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.offset, ntfs_offset() as u64);
    assert_eq!(
        opened.size_bytes,
        u64::from(NTFS_SECTORS) * 512,
        "the filesystem is bounded by the partition, not the image tail"
    );
    assert_eq!(opened.format, ImageFormat::Raw);
}

#[test]
fn an_unselected_whole_disk_image_points_at_the_partition_options() {
    let (_directory, path) = image_file(&mbr_partitioned_media());

    let error = open_image(&path, &registry())
        .err()
        .expect("a partition table is not a filesystem");

    assert!(matches!(
        error,
        OpenImageError::PartitionTable {
            offset: 0,
            detected: DetectedBootSector::MbrPartitioned,
            ..
        }
    ));
    let message = error.to_string();
    assert!(message.contains("--partition"), "{message}");
    assert!(message.contains("fsmnt partitions"), "{message}");
}

#[test]
fn an_out_of_range_partition_reports_what_the_image_holds() {
    let (_directory, path) = image_file(&mbr_partitioned_media());
    let options = ImageOpenOptions::new().with_partition(9);

    let error = open_image_with_options(&path, &registry(), options)
        .err()
        .expect("partition 9 does not exist");

    assert!(matches!(
        error,
        OpenImageError::PartitionNotFound {
            partition: 9,
            available: 2,
            ..
        }
    ));
}

#[test]
fn an_unpartitioned_image_is_one_whole_image_partition() {
    let mut media = vec![0_u8; MEDIA_SIZE];
    write_ntfs_boot_sector(&mut media, 0);
    let (_directory, path) = image_file(&media);

    let layout = image_layout(&path).expect("enumerate bare image");
    assert!(matches!(
        layout.kind,
        ImageLayoutKind::Bare(DetectedBootSector::Ntfs)
    ));
    assert_eq!(layout.partitions.len(), 1);
    assert_eq!(layout.partitions[0].offset, 0);
    assert_eq!(layout.partitions[0].size_bytes, MEDIA_SIZE as u64);

    let options = ImageOpenOptions::new().with_partition(0);
    let opened =
        open_image_with_options(&path, &registry(), options).expect("mount the whole image");
    assert_eq!(opened.offset, 0);
    assert_eq!(opened.size_bytes, MEDIA_SIZE as u64);
}
