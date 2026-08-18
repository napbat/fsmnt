//! Public-API coverage for enumerating and mounting image partitions.
//!
//! Builds a small MBR-partitioned raw image (one Linux-typed partition of
//! zeroes, one NTFS partition) and drives [`fsmnt::image_layout`] and
//! [`fsmnt::ImageOpenOptions::with_partition`] over it, so the listing
//! ordinals and the mount selector are checked against the same media.
//!
//! Two variations on that media cover what a partition table can say about
//! bytes a file does not have: a GPT written in 4096-byte sectors, whose
//! offsets are eight times wrong when it is read as 512-byte ones, and an
//! image cut short of the partitions its table describes.

use std::io::Read;

use fsmnt::device::{
    DetectedBootSector, DeviceReader, FilesystemDriver, GptPartitionEntry, ImageFormat,
};
use fsmnt::{
    FsEntry, FsError, FsMetadata, FsResult, ImageLayoutKind, ImageOpenOptions, OpenImageError,
    TargetFilesystem, image_layout, image_layout_with_sector_size, open_image,
    open_image_with_options,
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

/// A filesystem that answers "not found" to everything, and claims to be
/// exactly as large as the NTFS partition it is opened from.
///
/// The claim is what makes a truncated image detectable: the driver opens
/// happily from a boot sector the image does carry, and only the size it
/// reports reveals that the rest is not there.
struct EmptyFilesystem;

impl EmptyFilesystem {
    /// The size this filesystem claims, matching the NTFS partition entry.
    fn claimed_size() -> u64 {
        u64::from(NTFS_SECTORS) * 512
    }
}

impl TargetFilesystem for EmptyFilesystem {
    fn total_size(&self) -> Option<u64> {
        Some(Self::claimed_size())
    }

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

/// Logical sector size of a 4Kn drive: the GPT header lands at byte 4096 and
/// every LBA in the entry array counts 4096-byte units.
const NATIVE_4K: usize = 4096;
/// First LBA of the single partition in the 4Kn image.
const NATIVE_4K_FIRST_LBA: u64 = 4;
/// Last LBA of that partition, inclusive as GPT records it.
const NATIVE_4K_LAST_LBA: u64 = 7;

/// Raw media laid out as a 4Kn drive's GPT: protective MBR in LBA 0, header
/// in LBA 1, entry array in LBA 2, one NTFS partition from LBA 4.
fn native_4k_gpt_media() -> Vec<u8> {
    let mut media = vec![0_u8; NATIVE_4K * 8];

    // The protective MBR lives in the first 512 bytes of LBA 0 whatever the
    // sector size — which is what makes a 512-byte read of a 4Kn dump look
    // like a GPT whose header has gone missing.
    write_mbr_entry(&mut media[446..462], 0xee, 1, 0xffff_ffff);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);

    let header = &mut media[NATIVE_4K..NATIVE_4K + 92];
    header[0..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes()); // revision 1.0
    header[12..16].copy_from_slice(&92_u32.to_le_bytes()); // header_size
    header[24..32].copy_from_slice(&1_u64.to_le_bytes()); // current_lba
    header[72..80].copy_from_slice(&2_u64.to_le_bytes()); // partition_entry_lba
    header[80..84].copy_from_slice(&4_u32.to_le_bytes()); // num_partition_entries
    header[84..88].copy_from_slice(&128_u32.to_le_bytes()); // partition_entry_size

    let entry = &mut media[NATIVE_4K * 2..NATIVE_4K * 2 + 128];
    entry[0..16].copy_from_slice(&GptPartitionEntry::LINUX_FILESYSTEM_GUID);
    entry[16..32].copy_from_slice(&[0x11_u8; 16]); // unique partition GUID
    entry[32..40].copy_from_slice(&NATIVE_4K_FIRST_LBA.to_le_bytes());
    entry[40..48].copy_from_slice(&NATIVE_4K_LAST_LBA.to_le_bytes());

    let partition_offset = usize::try_from(NATIVE_4K_FIRST_LBA).expect("lba fits") * NATIVE_4K;
    write_ntfs_boot_sector(&mut media, partition_offset);
    media
}

/// Byte offset and length of the 4Kn image's single partition.
fn native_4k_extent() -> (u64, u64) {
    let sector = u64::try_from(NATIVE_4K).expect("sector size fits");
    (
        NATIVE_4K_FIRST_LBA * sector,
        (NATIVE_4K_LAST_LBA - NATIVE_4K_FIRST_LBA + 1) * sector,
    )
}

#[test]
fn a_4kn_gpt_is_detected_when_no_sector_size_is_given() {
    let (_directory, path) = image_file(&native_4k_gpt_media());
    let (offset, size) = native_4k_extent();

    let layout = image_layout(&path).expect("enumerate the 4Kn image");

    assert!(matches!(layout.kind, ImageLayoutKind::Gpt));
    assert_eq!(layout.sector_size, 4096);
    assert!(
        layout.sector_size_auto_detected,
        "512-byte sectors find no GPT header here, so 4096 was inferred"
    );
    assert_eq!(layout.partitions.len(), 1);
    assert_eq!(layout.partitions[0].offset, offset);
    assert_eq!(layout.partitions[0].size_bytes, size);
    assert_eq!(layout.partitions[0].missing_bytes, 0);
    assert_eq!(
        layout.partitions[0].detected,
        Some(DetectedBootSector::Ntfs),
        "the partition offset has to be right for its boot sector to be found"
    );
}

#[test]
fn an_explicit_sector_size_is_taken_at_its_word() {
    let (_directory, path) = image_file(&native_4k_gpt_media());
    let (offset, _) = native_4k_extent();

    let layout = image_layout_with_sector_size(&path, 4096).expect("enumerate at 4096");
    assert_eq!(layout.sector_size, 4096);
    assert!(
        !layout.sector_size_auto_detected,
        "nothing was inferred; the caller said so"
    );
    assert_eq!(layout.partitions[0].offset, offset);

    let error =
        image_layout_with_sector_size(&path, 512).expect_err("there is no GPT header at byte 512");
    assert!(matches!(error, OpenImageError::Layout { .. }));
}

#[test]
fn a_4kn_partition_can_be_mounted_by_ordinal() {
    let (_directory, path) = image_file(&native_4k_gpt_media());
    let (offset, size) = native_4k_extent();

    let options = ImageOpenOptions::new()
        .with_partition(0)
        .with_sector_size(4096);
    let opened = open_image_with_options(&path, &registry(), options).expect("mount at 4096");
    assert_eq!(opened.offset, offset);
    assert_eq!(opened.size_bytes, size);
}

/// How much of the NTFS partition the truncated image still carries.
const PRESENT_NTFS_BYTES: usize = 8 * SECTOR_SIZE;

/// The MBR media, cut off part-way through the NTFS partition.
fn truncated_media() -> Vec<u8> {
    let mut media = mbr_partitioned_media();
    media.truncate(ntfs_offset() + PRESENT_NTFS_BYTES);
    media
}

#[test]
fn a_partition_the_image_stops_inside_reports_what_is_missing() {
    let (_directory, path) = image_file(&truncated_media());

    let layout = image_layout(&path).expect("enumerate the truncated image");

    let data = &layout.partitions[0];
    assert_eq!(data.missing_bytes, 0, "the leading partition is complete");
    assert!(!data.is_truncated());

    let ntfs = &layout.partitions[1];
    let declared = u64::from(NTFS_SECTORS) * 512;
    let present = u64::try_from(PRESENT_NTFS_BYTES).expect("byte count fits");
    assert_eq!(ntfs.size_bytes, declared);
    assert_eq!(ntfs.missing_bytes, declared - present);
    assert_eq!(ntfs.available_bytes(), present);
    assert!(ntfs.is_truncated());
    assert!(!ntfs.is_beyond_end());
    assert_eq!(
        ntfs.detected,
        Some(DetectedBootSector::Ntfs),
        "the boot sector is present even though the volume is not"
    );
}

#[test]
fn a_partition_beyond_the_end_of_the_image_is_reported_as_such() {
    let mut media = mbr_partitioned_media();
    media.truncate(ntfs_offset() - SECTOR_SIZE);
    let (_directory, path) = image_file(&media);

    let layout = image_layout(&path).expect("enumerate the short image");
    let ntfs = &layout.partitions[1];
    assert!(ntfs.is_beyond_end());
    assert!(!ntfs.is_truncated(), "none of it is present to be cut");
    assert_eq!(ntfs.available_bytes(), 0);
    assert_eq!(ntfs.detected, None, "nothing there to classify");
}

#[test]
fn mounting_a_truncated_partition_reports_the_shortfall() {
    let (_directory, path) = image_file(&truncated_media());
    let options = ImageOpenOptions::new().with_partition(1);

    let opened = open_image_with_options(&path, &registry(), options)
        .expect("the boot sector is present, so the driver opens");

    let present = u64::try_from(PRESENT_NTFS_BYTES).expect("byte count fits");
    assert_eq!(
        opened.size_bytes, present,
        "the window is bounded by the image, not by the partition table"
    );
    assert_eq!(opened.declared_size_bytes, u64::from(NTFS_SECTORS) * 512);
    assert_eq!(
        opened.truncated_by,
        Some(EmptyFilesystem::claimed_size() - present)
    );
}

#[test]
fn mounting_a_complete_partition_reports_no_shortfall() {
    let (_directory, path) = image_file(&mbr_partitioned_media());
    let options = ImageOpenOptions::new().with_partition(1);

    let opened = open_image_with_options(&path, &registry(), options).expect("open the partition");

    assert_eq!(opened.truncated_by, None);
    assert_eq!(opened.size_bytes, opened.declared_size_bytes);
}

/// A 512-byte-sector GPT disk of `sectors` sectors with primary *and* backup
/// structures, holding one Linux partition at LBAs 80..=87 that carries an
/// NTFS boot sector (so detection has something to find).
fn gpt_disk_with_backup(sectors: usize) -> Vec<u8> {
    fn header(current: u64, backup: u64, entries_lba: u64) -> [u8; 92] {
        let mut h = [0u8; 92];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000_u32.to_le_bytes());
        h[12..16].copy_from_slice(&92_u32.to_le_bytes());
        h[24..32].copy_from_slice(&current.to_le_bytes());
        h[32..40].copy_from_slice(&backup.to_le_bytes());
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&4_u32.to_le_bytes());
        h[84..88].copy_from_slice(&128_u32.to_le_bytes());
        let crc = crc32fast::hash(&h);
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    }
    let mut media = vec![0_u8; 512 * sectors];
    let last = (sectors - 1) as u64;
    write_mbr_entry(&mut media[446..462], 0xee, 1, 0xffff_ffff);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media[512..604].copy_from_slice(&header(1, last, 2));
    let mut entry = [0u8; 128];
    entry[0..16].copy_from_slice(&GptPartitionEntry::LINUX_FILESYSTEM_GUID);
    entry[16..32].copy_from_slice(&[0x33; 16]);
    entry[32..40].copy_from_slice(&80_u64.to_le_bytes());
    entry[40..48].copy_from_slice(&87_u64.to_le_bytes());
    media[1024..1152].copy_from_slice(&entry);
    let backup_entries = 512 * (sectors - 33);
    media[backup_entries..backup_entries + 128].copy_from_slice(&entry);
    let backup_header = 512 * (sectors - 1);
    media[backup_header..backup_header + 92].copy_from_slice(&header(
        last,
        1,
        (sectors - 33) as u64,
    ));
    write_ntfs_boot_sector(&mut media, 80 * 512);
    media
}

#[test]
fn a_wiped_front_gpt_is_read_from_its_backup_header() {
    let mut media = gpt_disk_with_backup(256);
    // dd if=/dev/zero of=disk count=64: MBR, primary header and entry array
    // all gone; the backup header and array at the end survive.
    media[..512 * 64].fill(0);
    let (_directory, path) = image_file(&media);

    let layout = image_layout(&path).expect("enumerate the wiped-front image");
    assert!(matches!(layout.kind, ImageLayoutKind::Gpt));
    assert!(
        layout.gpt_from_backup,
        "the table must come from the backup"
    );
    assert!(!layout.sector_size_auto_detected);
    assert_eq!(layout.partitions.len(), 1);
    assert_eq!(layout.partitions[0].offset, 80 * 512);
    assert_eq!(layout.partitions[0].size_bytes, 8 * 512);
    assert_eq!(
        layout.partitions[0].detected,
        Some(DetectedBootSector::Ntfs)
    );

    // And it is mountable by ordinal exactly like an intact table.
    let intact = gpt_disk_with_backup(256);
    let (_directory, intact_path) = image_file(&intact);
    let intact_layout = image_layout(&intact_path).expect("enumerate the intact image");
    assert!(!intact_layout.gpt_from_backup);
    assert_eq!(
        intact_layout.partitions[0].offset,
        layout.partitions[0].offset
    );
}
