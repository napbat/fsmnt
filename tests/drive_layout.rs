//! Public-API coverage for enumerating, scanning and opening a *drive*.
//!
//! A drive with a wiped partition table and an image of one are the same
//! forensic situation, so `fsmnt` answers both with the same enumeration.
//! These tests hold that promise to the letter: the same bytes are served to
//! an in-memory [`HostDriveEnumerator`] and written to a temporary file, and
//! [`fsmnt::drive_layout`] / [`fsmnt::scan_drive`] must agree with
//! [`fsmnt::image_layout`] / [`fsmnt::scan_image`] entry for entry.
//!
//! Around that sit the three ways of naming a place on a drive that used to
//! exist only for images: a table ordinal, an ordinal counted over what a
//! scan finds, and a bare byte offset.

use std::io::{Cursor, Read};
use std::path::PathBuf;

use fsmnt::device::{
    DetectedBootSector, DeviceReader, DriverRegistry, FilesystemDriver, HostDriveEnumerator,
    HostDriveError, HostDriveId, HostDriveInfo, HostDriveResult, HostVolumeResolver, LogicalVolume,
    LogicalVolumeId, PhysicalExtent, SourceSelection,
};
use fsmnt::{
    DriveLayoutOptions, FsEntry, FsError, FsMetadata, FsResult, LayoutKind, LayoutOrigin,
    PartitionOpenOptions, ScanOptions, TargetFilesystem, drive_layout, image_layout,
    open_device_at_offset, open_device_partition_with_options, scan_drive, scan_image,
};

/// Sector size the 512-byte fixture drive reports, and the unit its MBR is
/// written in.
const SECTOR_SIZE: usize = 512;
/// Length of the 512-byte fixture drive.
const MEDIA_SIZE: usize = 32_768;
/// Offset inside a boot sector holding the marker a driver checks.
const MARKER_OFFSET: usize = 100;
/// Value written there, proving the driver was handed the right window.
const MARKER: u8 = 0xc7;
/// LBA of the leading data partition (no filesystem in it).
const DATA_START_LBA: u32 = 8;
/// Sector count of the leading data partition.
const DATA_SECTORS: u32 = 8;
/// LBA of the NTFS partition, chosen so it is not the first entry.
const NTFS_START_LBA: u32 = 16;
/// Sector count of the NTFS partition; it runs to the end of the media.
const NTFS_SECTORS: u32 = 48;

/// Sector size the 4Kn fixture drive's table is written in, while it reports
/// itself as 512e.
const NATIVE_4K: usize = 4096;
/// Length of the 4Kn fixture drive: 64 native sectors.
const MEDIA_4K_SIZE: usize = NATIVE_4K * 64;
/// LBA of the 4Kn drive's only partition, in *its* 4096-byte units.
const NATIVE_4K_START_LBA: u32 = 4;
/// Sector count of that partition, in 4096-byte units.
const NATIVE_4K_SECTORS: u32 = 8;

/// Byte offset of the NTFS partition on the 512-byte fixture drive.
fn ntfs_offset() -> u64 {
    u64::from(NTFS_START_LBA) * SECTOR_SIZE as u64
}

/// Byte offset of the NTFS volume on the 4Kn fixture drive, read correctly.
fn native_4k_offset() -> u64 {
    u64::from(NATIVE_4K_START_LBA) * NATIVE_4K as u64
}

// ---------------------------------------------------------------- fixtures

/// An in-memory host exposing two drives: one ordinary 512-byte MBR disk,
/// and one whose MBR is written in 4096-byte sectors while the operating
/// system insists the drive is 512e.
struct FixtureHost;

impl HostDriveEnumerator for FixtureHost {
    type Reader = Cursor<Vec<u8>>;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        Ok(vec![drive_info("mbr")?, drive_info("4kn")?])
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        drive_info(id.as_str())
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        Ok(Cursor::new(drive_media(id.as_str())?))
    }
}

impl HostVolumeResolver for FixtureHost {
    type VolumeReader = Cursor<Vec<u8>>;

    fn logical_volumes(_extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        // No operating-system volume is layered over these fixtures, which
        // is what makes `Auto` fall through to raw access.
        Ok(Vec::new())
    }

    fn open_logical_volume(_volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        unreachable!("the fixture host publishes no logical volumes")
    }
}

fn drive_info(id: &str) -> HostDriveResult<HostDriveInfo> {
    let size = u64::try_from(drive_media(id)?.len()).expect("fixture length fits u64");
    Ok(HostDriveInfo::new(HostDriveId::new(id), PathBuf::from(id))
        .with_access(size)
        // Both drives report 512-byte sectors; only one of them is telling
        // the truth about the units its partition table was written in.
        .with_sector_size(512))
}

fn drive_media(id: &str) -> HostDriveResult<Vec<u8>> {
    match id {
        "mbr" => Ok(mbr_media()),
        "4kn" => Ok(native_4k_media()),
        other => Err(HostDriveError::NotFound(other.to_string())),
    }
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

/// A 512-byte-sector disk whose second partition holds an NTFS volume.
fn mbr_media() -> Vec<u8> {
    let mut media = vec![0_u8; MEDIA_SIZE];
    write_ntfs_boot_sector(&mut media, NTFS_START_LBA as usize * SECTOR_SIZE);
    write_mbr_entry(&mut media[446..462], 0x83, DATA_START_LBA, DATA_SECTORS);
    write_mbr_entry(&mut media[462..478], 0x07, NTFS_START_LBA, NTFS_SECTORS);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

/// A disk whose MBR counts 4096-byte sectors, holding one NTFS partition.
///
/// Read as 512-byte sectors the same entry points at byte 2048, where there
/// is nothing — which is exactly the failure `--sector-size` exists for.
fn native_4k_media() -> Vec<u8> {
    let mut media = vec![0_u8; MEDIA_4K_SIZE];
    write_ntfs_boot_sector(&mut media, NATIVE_4K_START_LBA as usize * NATIVE_4K);
    write_mbr_entry(
        &mut media[446..462],
        0x07,
        NATIVE_4K_START_LBA,
        NATIVE_4K_SECTORS,
    );
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

/// Write `media` into a temporary directory and hand back both.
fn image_file(media: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("disk.bin");
    std::fs::write(&path, media).expect("write raw image");
    (directory, path)
}

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

/// A driver that only succeeds when handed the marked NTFS boot sector, so
/// an open that lands one sector away fails loudly instead of quietly.
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
                "driver was not positioned at the selected filesystem".to_string(),
            ));
        }
        Ok(Box::new(EmptyFilesystem))
    }
}

fn registry() -> DriverRegistry {
    let mut registry = DriverRegistry::new();
    registry.register(Box::new(InspectingNtfsDriver));
    registry
}

fn raw() -> PartitionOpenOptions {
    PartitionOpenOptions::new().with_source(SourceSelection::Raw {
        additional_partitions: Vec::new(),
    })
}

// ------------------------------------------------------------------- tests

#[test]
fn a_drive_and_an_image_of_it_are_enumerated_identically() {
    let media = mbr_media();
    let (_directory, path) = image_file(&media);

    let from_drive =
        drive_layout::<FixtureHost>(&HostDriveId::new("mbr"), DriveLayoutOptions::new())
            .expect("enumerate the fixture drive");
    let from_image = image_layout(&path).expect("enumerate the same bytes as an image");

    assert!(matches!(from_drive.kind, LayoutKind::Mbr));
    assert_eq!(from_drive.origin, LayoutOrigin::Table);
    assert_eq!(from_drive.origin, from_image.origin);
    assert_eq!(from_drive.sector_size, from_image.sector_size);
    assert!(!from_drive.sector_size_auto_detected);
    assert_eq!(from_drive.size_bytes, from_image.size_bytes);
    assert_eq!(from_drive.partitions.len(), 2);

    for (drive, image) in from_drive.partitions.iter().zip(&from_image.partitions) {
        assert_eq!(drive.ordinal, image.ordinal);
        assert_eq!(drive.offset, image.offset);
        assert_eq!(drive.size_bytes, image.size_bytes);
        assert_eq!(drive.missing_bytes, image.missing_bytes);
        assert_eq!(drive.type_name, image.type_name);
        assert_eq!(drive.name, image.name);
        assert_eq!(drive.detected, image.detected);
    }

    // And the values themselves, so an agreement on nonsense cannot pass.
    let ntfs = &from_drive.partitions[1];
    assert_eq!(ntfs.offset, ntfs_offset());
    assert_eq!(ntfs.size_bytes, u64::from(NTFS_SECTORS) * 512);
    assert_eq!(ntfs.missing_bytes, 0);
    assert_eq!(ntfs.type_name.as_deref(), Some("NTFS/HPFS/exFAT"));
    assert_eq!(ntfs.detected, Some(DetectedBootSector::Ntfs));
}

#[test]
fn a_drive_scan_finds_what_an_image_scan_of_the_same_bytes_finds() {
    let media = mbr_media();
    let (_directory, path) = image_file(&media);

    let from_drive = scan_drive::<FixtureHost>(&HostDriveId::new("mbr"), ScanOptions::new())
        .expect("scan the fixture drive");
    let from_image = scan_image(&path).expect("scan the same bytes as an image");

    assert_eq!(from_drive, from_image);
    assert!(
        from_drive.iter().any(|hit| hit.offset == ntfs_offset()
            && hit.kind == fsmnt::ScanHitKind::Filesystem(DetectedBootSector::Ntfs)),
        "the NTFS volume must be found without consulting the table: {from_drive:#?}"
    );
}

#[test]
fn a_drive_layout_from_a_scan_declares_itself_synthetic() {
    let layout = drive_layout::<FixtureHost>(
        &HostDriveId::new("mbr"),
        DriveLayoutOptions::new().with_scan(true),
    )
    .expect("reconstruct the fixture drive's layout by scanning");

    assert!(matches!(layout.kind, LayoutKind::Scanned));
    assert_eq!(
        layout.origin,
        LayoutOrigin::Scan {
            stride: fsmnt::DEFAULT_STRIDE
        },
        "a scan-built table must declare its provenance"
    );
    assert_eq!(layout.size_bytes, MEDIA_SIZE as u64);

    // The MBR itself is a hit, but it is not mountable, so ordinal 0 is the
    // first *filesystem* the scan found.
    let first = &layout.partitions[0];
    assert_eq!(first.ordinal, 0);
    assert_eq!(first.offset, ntfs_offset());
    assert_eq!(first.detected, Some(DetectedBootSector::Ntfs));
    assert!(first.name.is_none(), "a scan has no partition names");
    assert!(
        first.type_name.as_deref().unwrap_or("").contains("scan"),
        "the type column says where it came from: {:?}",
        first.type_name
    );
}

#[test]
fn a_table_ordinal_records_that_it_came_from_the_table() {
    let opened = open_device_partition_with_options::<FixtureHost>(
        &HostDriveId::new("mbr"),
        1,
        &registry(),
        raw(),
    )
    .expect("open the NTFS partition by its table ordinal");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, u64::from(NTFS_SECTORS) * 512);
    assert_eq!(opened.layout_origin, Some(LayoutOrigin::Table));
}

#[test]
fn a_scanned_ordinal_opens_the_filesystem_the_scan_found_and_says_so() {
    let opened = open_device_partition_with_options::<FixtureHost>(
        &HostDriveId::new("mbr"),
        0,
        &registry(),
        raw().with_scan(fsmnt::DEFAULT_STRIDE),
    )
    .expect("open the first scanned filesystem");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(
        opened.layout_origin,
        Some(LayoutOrigin::Scan {
            stride: fsmnt::DEFAULT_STRIDE
        }),
        "a synthetic ordinal must never be reported as a table entry"
    );
    // Nothing in this NTFS boot sector states a volume length, so the extent
    // runs to the end of the drive rather than to a size it never claimed.
    assert_eq!(opened.size_bytes, MEDIA_SIZE as u64 - ntfs_offset());
}

#[test]
fn a_scanned_ordinal_past_the_end_says_how_many_the_scan_found() {
    let error = open_device_partition_with_options::<FixtureHost>(
        &HostDriveId::new("mbr"),
        7,
        &registry(),
        raw().with_scan(fsmnt::DEFAULT_STRIDE),
    )
    .err()
    .expect("there is no eighth scanned filesystem");
    let message = error.to_string();

    assert!(message.contains("the scan found 1 filesystem"), "{message}");
    assert!(
        message.contains("fsmnt partitions mbr --scan"),
        "the error must name the command that lists them: {message}"
    );
}

#[test]
fn a_scanned_ordinal_refuses_an_explicit_logical_volume() {
    let error = open_device_partition_with_options::<FixtureHost>(
        &HostDriveId::new("mbr"),
        0,
        &registry(),
        PartitionOpenOptions::new()
            .with_source(SourceSelection::Logical(LogicalVolumeId::new("C")))
            .with_scan(fsmnt::DEFAULT_STRIDE),
    )
    .err()
    .expect("a scanned offset is not a logical volume");

    assert!(
        error.to_string().contains("no logical volume"),
        "{error}, which does not explain why the combination is impossible"
    );
}

#[test]
fn a_byte_offset_opens_raw_media_and_claims_no_provenance() {
    let opened = open_device_at_offset::<FixtureHost>(
        &HostDriveId::new("mbr"),
        ntfs_offset(),
        &registry(),
        // Auto, not Raw: without a logical volume to select, a byte offset
        // is physical by construction.
        PartitionOpenOptions::new(),
    )
    .expect("open the NTFS volume at its byte offset");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, MEDIA_SIZE as u64 - ntfs_offset());
    assert_eq!(
        opened.layout_origin, None,
        "no table was consulted, so there is no provenance to claim"
    );
}

#[test]
fn a_byte_offset_on_a_partition_table_points_at_the_partition_list() {
    let error = open_device_at_offset::<FixtureHost>(
        &HostDriveId::new("mbr"),
        0,
        &registry(),
        PartitionOpenOptions::new(),
    )
    .err()
    .expect("offset 0 is the MBR, not a filesystem");
    let message = error.to_string();

    assert!(message.contains("partition table"), "{message}");
    assert!(message.contains("MbrPartitioned"), "{message}");
    assert!(
        message.contains("--partition") && message.contains("fsmnt partitions mbr"),
        "the error must name the way forward: {message}"
    );
}

#[test]
fn a_byte_offset_past_the_end_says_how_large_the_drive_is() {
    let error = open_device_at_offset::<FixtureHost>(
        &HostDriveId::new("mbr"),
        MEDIA_SIZE as u64,
        &registry(),
        PartitionOpenOptions::new(),
    )
    .err()
    .expect("the drive ends there");
    let message = error.to_string();

    assert!(message.contains("at or past the end"), "{message}");
    assert!(
        message.contains(&MEDIA_SIZE.to_string()),
        "the error must state the size it is comparing against: {message}"
    );
}

#[test]
fn a_byte_offset_refuses_an_explicit_logical_volume() {
    let error = open_device_at_offset::<FixtureHost>(
        &HostDriveId::new("mbr"),
        ntfs_offset(),
        &registry(),
        PartitionOpenOptions::new()
            .with_source(SourceSelection::Logical(LogicalVolumeId::new("C"))),
    )
    .err()
    .expect("a byte offset is not a logical volume");

    assert!(
        error.to_string().contains("no logical volume"),
        "{error}, which does not explain why the combination is impossible"
    );
}

#[test]
fn an_explicit_sector_size_overrides_what_the_drive_reports() {
    let drive = HostDriveId::new("4kn");

    // As reported: 512-byte sectors put the partition where nothing is.
    let reported = drive_layout::<FixtureHost>(&drive, DriveLayoutOptions::new())
        .expect("enumerate in the reported geometry");
    assert_eq!(reported.sector_size, 512);
    assert_eq!(reported.partitions.len(), 1);
    assert_eq!(
        reported.partitions[0].offset,
        u64::from(NATIVE_4K_START_LBA) * 512
    );
    assert_eq!(
        reported.partitions[0].detected,
        Some(DetectedBootSector::Unknown),
        "there is no filesystem where 512-byte sectors say the partition is"
    );

    // Told the truth: the same entry lands on the NTFS volume.
    let overridden =
        drive_layout::<FixtureHost>(&drive, DriveLayoutOptions::new().with_sector_size(4096))
            .expect("enumerate in the geometry the table was written in");
    assert_eq!(overridden.sector_size, 4096);
    assert_eq!(overridden.partitions[0].offset, native_4k_offset());
    assert_eq!(
        overridden.partitions[0].size_bytes,
        u64::from(NATIVE_4K_SECTORS) * NATIVE_4K as u64
    );
    assert_eq!(
        overridden.partitions[0].detected,
        Some(DetectedBootSector::Ntfs)
    );

    // And opening honours it too, all the way down to the reader the driver
    // is handed.
    let opened = open_device_partition_with_options::<FixtureHost>(
        &drive,
        0,
        &registry(),
        raw().with_sector_size(4096),
    )
    .expect("open the partition in the geometry its table was written in");
    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(
        opened.size_bytes,
        u64::from(NATIVE_4K_SECTORS) * NATIVE_4K as u64
    );
    assert_eq!(opened.layout_origin, Some(LayoutOrigin::Table));

    assert!(
        open_device_partition_with_options::<FixtureHost>(&drive, 0, &registry(), raw()).is_err(),
        "without the override the same ordinal opens 2 KiB of zeroes"
    );
}
