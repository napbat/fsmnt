//! Cross-crate storage-source graph integration tests.

use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use fsmnt::device::{
    DetectedBootSector, DeviceReader, DeviceSet, FilesystemDriver, HostDriveEnumerator,
    HostDriveId, HostDriveInfo, HostDriveResult, HostVolumeResolver, LogicalVolume,
    PartitionAddress, PhysicalExtent, SourceOrigin, SourceSelection,
};
use fsmnt::{FsEntry, FsError, FsMetadata, FsResult, TargetFilesystem};

const SECTOR_SIZE: u32 = 512;
const START_LBA: u32 = 4;
static OPENED_MEMBER_COUNT: AtomicUsize = AtomicUsize::new(0);

struct TwoDriveHost;

impl HostDriveEnumerator for TwoDriveHost {
    type Reader = Cursor<Vec<u8>>;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        Ok(["primary", "second"].into_iter().map(drive_info).collect())
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        Ok(drive_info(id.as_str()))
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        let marker = match id.as_str() {
            "primary" => 0x11,
            "second" => 0x22,
            other => return Err(fsmnt::device::HostDriveError::NotFound(other.to_string())),
        };
        Ok(Cursor::new(test_disk(marker)))
    }
}

impl HostVolumeResolver for TwoDriveHost {
    type VolumeReader = Cursor<Vec<u8>>;

    fn logical_volumes(_extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        Ok(Vec::new())
    }

    fn open_logical_volume(_volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        unreachable!("raw integration test never opens a logical volume")
    }
}

fn drive_info(id: &str) -> HostDriveInfo {
    let size = u64::try_from(test_disk(0).len()).expect("test disk length fits u64");
    HostDriveInfo::new(HostDriveId::new(id), PathBuf::from(id))
        .with_access(size)
        .with_sector_size(SECTOR_SIZE)
}

fn test_disk(marker: u8) -> Vec<u8> {
    let mut partition = vec![0_u8; 4096];
    synthesize_ntfs_boot_sector(&mut partition[..512]);
    partition[1024] = marker;
    fsmnt_testkit::single_partition_mbr(&partition, 0x07, START_LBA, SECTOR_SIZE)
        .expect("synthetic MBR")
}

fn synthesize_ntfs_boot_sector(sector: &mut [u8]) {
    sector[0] = 0xeb;
    sector[1] = 0x52;
    sector[2] = 0x90;
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[510] = 0x55;
    sector[511] = 0xaa;
}

struct MultiDeviceDriver;

impl FilesystemDriver for MultiDeviceDriver {
    fn name(&self) -> &'static str {
        "multi-test"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ntfs
    }

    fn open(
        &self,
        _reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        Err(FsError::Filesystem(
            "integration driver requires a device set".to_string(),
        ))
    }

    fn open_devices(
        &self,
        devices: DeviceSet,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        OPENED_MEMBER_COUNT.store(devices.len(), Ordering::SeqCst);
        let mut markers = Vec::new();
        for mut member in devices.into_members() {
            let mut prefix = [0_u8; 1025];
            member.reader_mut().read_exact(&mut prefix)?;
            markers.push(prefix[1024]);
        }
        if markers != [0x11, 0x22] {
            return Err(FsError::Filesystem(format!(
                "unexpected raw member order: {markers:?}"
            )));
        }
        Ok(Box::new(EmptyFilesystem))
    }
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

#[test]
fn raw_selection_delivers_every_partition_to_multi_device_driver() {
    OPENED_MEMBER_COUNT.store(0, Ordering::SeqCst);
    let mut drivers = fsmnt::device::DriverRegistry::new();
    drivers.register(Box::new(MultiDeviceDriver));

    let opened = fsmnt::open_device_partition_with_selection::<TwoDriveHost>(
        &HostDriveId::new("primary"),
        0,
        &drivers,
        SourceSelection::Raw {
            additional_partitions: vec![PartitionAddress::new(HostDriveId::new("second"), 0)],
        },
    )
    .expect("open two-member raw filesystem");

    assert_eq!(opened.detected, DetectedBootSector::Ntfs);
    assert_eq!(
        opened.size_bytes, 0,
        "native multi-device capacity comes from the filesystem"
    );
    assert_eq!(OPENED_MEMBER_COUNT.load(Ordering::SeqCst), 2);
    let SourceOrigin::Raw(extents) = opened.source else {
        panic!("raw selection must report raw provenance");
    };
    assert_eq!(extents.len(), 2);
    assert_eq!(extents[0].drive().as_str(), "primary");
    assert_eq!(extents[1].drive().as_str(), "second");
}
