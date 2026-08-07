//! Cross-crate fstab source resolution and namespace-composition coverage.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use fsmnt::device::{
    DetectedBootSector, DeviceReader, DriverRegistry, FilesystemDriver, HostDriveEnumerator,
    HostDriveError, HostDriveId, HostDriveInfo, HostDriveResult, HostVolumeResolver, LogicalVolume,
    PhysicalExtent, SourceSelection,
};
use fsmnt::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, PartitionOpenOptions, TargetFilesystem,
};

const SECTOR_SIZE: u32 = 512;
const START_LBA: u32 = 4;

struct FixtureHost;

impl HostDriveEnumerator for FixtureHost {
    type Reader = Cursor<Vec<u8>>;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        Ok(["root", "child", "nested"]
            .into_iter()
            .map(drive_info)
            .collect())
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        drive_marker(id.as_str())?;
        Ok(drive_info(id.as_str()))
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        Ok(Cursor::new(test_disk(drive_marker(id.as_str())?)))
    }
}

impl HostVolumeResolver for FixtureHost {
    type VolumeReader = Cursor<Vec<u8>>;

    fn logical_volumes(_extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        Ok(Vec::new())
    }

    fn open_logical_volume(_volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        unreachable!("raw integration test never opens a logical volume")
    }
}

fn drive_marker(id: &str) -> HostDriveResult<u8> {
    match id {
        "root" => Ok(1),
        "child" => Ok(2),
        "nested" => Ok(3),
        other => Err(HostDriveError::NotFound(other.to_string())),
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
    sector[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

struct FixtureDriver;

impl FilesystemDriver for FixtureDriver {
    fn name(&self) -> &'static str {
        "fixture"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Ntfs
    }

    fn open(
        &self,
        mut reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let mut prefix = [0_u8; 1025];
        reader.read_exact(&mut prefix)?;
        Ok(Box::new(FixtureFilesystem::new(prefix[1024])?))
    }
}

struct FixtureFilesystem {
    uuid: &'static str,
    files: BTreeMap<&'static str, &'static [u8]>,
    directories: &'static [&'static str],
}

impl FixtureFilesystem {
    fn new(marker: u8) -> FsResult<Self> {
        match marker {
            1 => Ok(Self {
                uuid: "root-uuid",
                files: BTreeMap::from([
                    (
                        "etc/fstab",
                        concat!(
                            "UUID=root-uuid / fixture defaults 0 0\n",
                            "UUID=child-uuid /child fixture defaults 0 0\n",
                            "UUID=nested-uuid /child/nested fixture defaults 0 0\n",
                        )
                        .as_bytes(),
                    ),
                    ("root.txt", b"root".as_slice()),
                    ("child/covered.txt", b"covered by child".as_slice()),
                ]),
                directories: &["", "etc", "child", "child/nested"],
            }),
            2 => Ok(Self {
                uuid: "child-uuid",
                files: BTreeMap::from([
                    ("child.txt", b"child".as_slice()),
                    ("nested/covered.txt", b"covered by nested".as_slice()),
                ]),
                directories: &["", "nested"],
            }),
            3 => Ok(Self {
                uuid: "nested-uuid",
                files: BTreeMap::from([("nested.txt", b"nested".as_slice())]),
                directories: &[""],
            }),
            _ => Err(FsError::Filesystem(format!(
                "unknown fixture marker {marker}"
            ))),
        }
    }

    fn normalize(path: &str) -> &str {
        path.trim_matches('/')
    }

    fn is_directory(&self, path: &str) -> bool {
        self.directories.contains(&path)
    }
}

impl TargetFilesystem for FixtureFilesystem {
    fn read(&mut self, path: &str) -> FsResult<Vec<u8>> {
        let path = Self::normalize(path);
        self.files
            .get(path)
            .map(|contents| contents.to_vec())
            .ok_or_else(|| {
                if self.is_directory(path) {
                    FsError::NotAFile(path.to_string())
                } else {
                    FsError::NotFound(path.to_string())
                }
            })
    }

    fn try_exists(&mut self, path: &str) -> FsResult<bool> {
        let path = Self::normalize(path);
        Ok(self.is_directory(path) || self.files.contains_key(path))
    }

    fn try_is_dir(&mut self, path: &str) -> FsResult<bool> {
        Ok(self.is_directory(Self::normalize(path)))
    }

    fn try_is_file(&mut self, path: &str) -> FsResult<bool> {
        Ok(self.files.contains_key(Self::normalize(path)))
    }

    fn metadata(&mut self, path: &str) -> FsResult<FsMetadata> {
        let path = Self::normalize(path);
        if self.is_directory(path) {
            return Ok(FsMetadata {
                is_dir: true,
                ..FsMetadata::default()
            });
        }
        let contents = self
            .files
            .get(path)
            .ok_or_else(|| FsError::NotFound(path.to_string()))?;
        Ok(FsMetadata {
            size: u64::try_from(contents.len()).expect("fixture length fits u64"),
            ..FsMetadata::default()
        })
    }

    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let path = Self::normalize(path);
        if !self.is_directory(path) {
            return Err(FsError::NotADirectory(path.to_string()));
        }
        let prefix = (!path.is_empty()).then(|| format!("{path}/"));
        let mut names = BTreeMap::new();
        for directory in self.directories {
            insert_direct_child(&mut names, prefix.as_deref(), directory, true);
        }
        for (file, contents) in &self.files {
            insert_direct_child(&mut names, prefix.as_deref(), file, false);
            if direct_child(prefix.as_deref(), file).is_some() {
                let name = Path::new(file)
                    .file_name()
                    .expect("fixture filename")
                    .to_string_lossy()
                    .into_owned();
                if let Some(entry) = names.get_mut(&name) {
                    entry.metadata.size =
                        u64::try_from(contents.len()).expect("fixture length fits u64");
                }
            }
        }
        Ok(names.into_values().collect())
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(self.uuid.to_string())
    }
}

fn insert_direct_child(
    entries: &mut BTreeMap<String, FsEntry>,
    prefix: Option<&str>,
    candidate: &str,
    is_directory: bool,
) {
    let Some(name) = direct_child(prefix, candidate) else {
        return;
    };
    entries.entry(name.to_string()).or_insert_with(|| FsEntry {
        name: name.to_string(),
        path: PathBuf::from(candidate),
        flags: FsEntryFlags::empty(),
        file_id: None,
        metadata: FsMetadata {
            is_dir: is_directory,
            ..FsMetadata::default()
        },
    });
}

fn direct_child<'path>(prefix: Option<&str>, candidate: &'path str) -> Option<&'path str> {
    let remainder = match prefix {
        Some(prefix) => candidate.strip_prefix(prefix)?,
        None => candidate,
    };
    (!remainder.is_empty() && !remainder.contains('/')).then_some(remainder)
}

#[test]
fn fstab_resolves_cross_drive_uuids_and_routes_nested_mounts() {
    let mut drivers = DriverRegistry::new();
    drivers.register(Box::new(FixtureDriver));
    let opened = fsmnt::open_device_partition_with_fstab::<FixtureHost>(
        &HostDriveId::new("root"),
        0,
        &drivers,
        PartitionOpenOptions::new().with_source(SourceSelection::Raw {
            additional_partitions: Vec::new(),
        }),
        "/etc/fstab",
    )
    .expect("compose fixture namespace");
    let mut filesystem = opened.filesystem;

    assert_eq!(filesystem.read("/root.txt").expect("root"), b"root");
    assert_eq!(
        filesystem.read("/child/child.txt").expect("child"),
        b"child"
    );
    assert_eq!(
        filesystem.read("/child/nested/nested.txt").expect("nested"),
        b"nested"
    );
    assert!(!filesystem.exists("/child/covered.txt"));
    assert!(!filesystem.exists("/child/nested/covered.txt"));
}
