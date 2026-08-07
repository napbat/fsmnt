use std::io::Cursor;
use std::path::PathBuf;

use fsmnt_core::{FsEntry, FsMetadata};
use fsmnt_device::{DeviceReader, FilesystemDriver, HostDriveInfo, HostDriveResult};

use super::*;

const SECTOR_SIZE: u32 = 512;
const PARTITION_START_LBA: u32 = 4;
const PARTITION_SECTORS: u32 = 64;

fn partition_offset() -> u64 {
    u64::from(PARTITION_START_LBA) * u64::from(SECTOR_SIZE)
}

fn partition_size() -> u64 {
    u64::from(PARTITION_SECTORS) * u64::from(SECTOR_SIZE)
}

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

struct StubDriver(DetectedBootSector);

impl FilesystemDriver for StubDriver {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == self.0
    }

    fn open(
        &self,
        _reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Ok(Box::new(EmptyFilesystem))
    }
}

struct MountedVolumeEnumerator;

impl HostDriveEnumerator for MountedVolumeEnumerator {
    type Reader = Cursor<Vec<u8>>;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        Ok(vec![drive_info()])
    }

    fn get_drive_info(_id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        Ok(drive_info())
    }

    fn open_drive(_id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        Ok(Cursor::new(bitlocker_disk()))
    }

    fn open_volume_at(
        _drive_id: &HostDriveId,
        offset: u64,
    ) -> HostDriveResult<Option<Self::Reader>> {
        Ok((offset == partition_offset()).then(|| Cursor::new(ntfs_volume())))
    }
}

fn drive_info() -> HostDriveInfo {
    HostDriveInfo::new(HostDriveId::new("0"), PathBuf::from("mock"))
        .with_access(partition_offset() + partition_size())
        .with_sector_size(SECTOR_SIZE)
}

fn bitlocker_disk() -> Vec<u8> {
    let disk_size =
        usize::try_from(partition_offset() + partition_size()).expect("test disk size fits usize");
    let mut disk = vec![0_u8; disk_size];

    let entry = &mut disk[446..462];
    entry[4] = 0x07;
    entry[8..12].copy_from_slice(&PARTITION_START_LBA.to_le_bytes());
    entry[12..16].copy_from_slice(&PARTITION_SECTORS.to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xaa;

    let offset = usize::try_from(partition_offset()).expect("partition offset fits usize");
    let sector_size = usize::try_from(SECTOR_SIZE).expect("sector size fits usize");
    let boot_sector = &mut disk[offset..offset + sector_size];
    synthesize_ntfs_style_boot_sector(boot_sector, *b"-FVE-FS-");
    disk
}

fn ntfs_volume() -> Vec<u8> {
    let mut volume = vec![0_u8; 2048];
    synthesize_ntfs_style_boot_sector(&mut volume[..512], *b"NTFS    ");
    volume
}

fn synthesize_ntfs_style_boot_sector(boot_sector: &mut [u8], oem_id: [u8; 8]) {
    boot_sector[0] = 0xeb;
    boot_sector[1] = 0x52;
    boot_sector[2] = 0x90;
    boot_sector[3..11].copy_from_slice(&oem_id);
    boot_sector[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
    boot_sector[0x0d] = 8;
    boot_sector[510] = 0x55;
    boot_sector[511] = 0xaa;
}

#[test]
fn default_mode_prefers_mounted_filesystem_over_raw_filesystem() {
    let mut drivers = DriverRegistry::new();
    drivers.register(Box::new(StubDriver(DetectedBootSector::Ntfs)));

    let opened =
        open_device_partition::<MountedVolumeEnumerator>(&HostDriveId::new("0"), 0, &drivers)
            .expect("open OS-decrypted mounted volume");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(opened.size_bytes, partition_size());
}

#[test]
fn raw_mode_bypasses_available_mounted_filesystem() {
    let mut drivers = DriverRegistry::new();
    drivers.register(Box::new(StubDriver(DetectedBootSector::BitLocker)));

    let opened = open_device_partition_with_mode::<MountedVolumeEnumerator>(
        &HostDriveId::new("0"),
        0,
        &drivers,
        PartitionOpenMode::Raw,
    )
    .expect("open raw BitLocker partition");

    assert_eq!(opened.detected, DetectedBootSector::BitLocker);
    assert_eq!(opened.size_bytes, partition_size());
}
