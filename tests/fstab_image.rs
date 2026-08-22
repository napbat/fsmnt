//! Composing a guest's fstab tree out of one disk image.
//!
//! A VM disk carries the whole machine: the root filesystem and every
//! volume its `/etc/fstab` names. This drives
//! [`fsmnt::open_image_with_fstab`] over a synthetic two-partition MBR image
//! whose fake driver gives each partition a distinct volume UUID, so the
//! sibling search, the root-UUID check, and the `nofail` policy are all
//! exercised against the same media.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fsmnt::device::{
    DetectedBootSector, DeviceReader, DriverRegistry, FilesystemDriver, ImageFormat,
};
use fsmnt::{
    FsEntry, FsEntryFlags, FsError, FsMetadata, FsResult, ImageOpenOptions, LayoutOrigin,
    TargetFilesystem, open_image_with_fstab,
};
use fsmnt_testkit::write_mbr_partition_entry as write_mbr_entry;

const SECTOR_SIZE: usize = 512;
const MEDIA_SIZE: usize = 32_768;
/// Byte in the boot sector that tells the fake driver which volume it holds.
const MARKER_OFFSET: usize = 100;
/// LBA and sector count of the root partition (ordinal 0).
const ROOT_START_LBA: u32 = 8;
/// Sector count of the root partition.
const ROOT_SECTORS: u32 = 24;
/// LBA of the child partition (ordinal 1).
const CHILD_START_LBA: u32 = 40;
/// Sector count of the child partition.
const CHILD_SECTORS: u32 = 24;

/// Marker of the child volume, mounted at `/boot`.
const CHILD: u8 = 2;
/// Marker of a root whose fstab names only volumes that exist.
const ROOT_PLAIN: u8 = 1;
/// Marker of a root whose fstab adds a `nofail` entry nothing carries.
const ROOT_NOFAIL_MISSING: u8 = 3;
/// Marker of a root whose fstab requires a volume nothing carries.
const ROOT_REQUIRED_MISSING: u8 = 4;
/// Marker of a root whose fstab describes a different machine's root.
const ROOT_FOREIGN: u8 = 5;

/// The fstab every variant starts from: this root, the child at `/boot`,
/// and a virtual filesystem that is no volume's business.
const BASE_FSTAB: &str = concat!(
    "UUID=root-uuid / ntfs defaults 0 1\n",
    "UUID=child-uuid /boot ntfs defaults 0 2\n",
    "proc /proc proc defaults 0 0\n",
);

/// Raw media with an MBR whose two partitions both hold an NTFS boot
/// sector, marked so the driver can tell them apart.
fn two_partition_media(root_marker: u8) -> Vec<u8> {
    let mut media = vec![0_u8; MEDIA_SIZE];
    write_ntfs_boot_sector(&mut media, offset_of(ROOT_START_LBA), root_marker);
    write_ntfs_boot_sector(&mut media, offset_of(CHILD_START_LBA), CHILD);
    write_mbr_entry(&mut media[446..462], 0x07, ROOT_START_LBA, ROOT_SECTORS);
    write_mbr_entry(&mut media[462..478], 0x07, CHILD_START_LBA, CHILD_SECTORS);
    media[510..512].copy_from_slice(&[0x55, 0xaa]);
    media
}

/// Byte offset of an LBA within the media.
fn offset_of(lba: u32) -> usize {
    lba as usize * SECTOR_SIZE
}

/// Write an NTFS boot sector carrying `marker`.
fn write_ntfs_boot_sector(media: &mut [u8], offset: usize, marker: u8) {
    let sector = &mut media[offset..offset + SECTOR_SIZE];
    sector[0..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
    sector[3..11].copy_from_slice(b"NTFS    ");
    sector[0x0b..0x0d].copy_from_slice(&512_u16.to_le_bytes());
    sector[0x0d] = 8;
    sector[MARKER_OFFSET] = marker;
    sector[510..512].copy_from_slice(&[0x55, 0xaa]);
}

/// Write `media` into a temporary directory and hand back both.
fn image_file(media: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("temporary image directory");
    let path = directory.path().join("guest.bin");
    std::fs::write(&path, media).expect("write raw image");
    (directory, path)
}

/// A registry holding only the marker-reading fake driver.
fn registry() -> DriverRegistry {
    let mut registry = DriverRegistry::new();
    registry.register(Box::new(MarkerDriver));
    registry
}

/// Opens whichever fixture volume the marker in the boot sector names.
struct MarkerDriver;

impl FilesystemDriver for MarkerDriver {
    fn name(&self) -> &'static str {
        "marker"
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
        Ok(Box::new(MarkerFilesystem::new(sector[MARKER_OFFSET])?))
    }
}

/// A volume that is a UUID, a set of files, and a set of directories.
struct MarkerFilesystem {
    uuid: &'static str,
    files: BTreeMap<&'static str, &'static [u8]>,
    directories: &'static [&'static str],
}

impl MarkerFilesystem {
    fn new(marker: u8) -> FsResult<Self> {
        match marker {
            ROOT_PLAIN => Ok(Self::root(BASE_FSTAB)),
            CHILD => Ok(Self {
                uuid: "child-uuid",
                files: BTreeMap::from([("boot.txt", b"boot".as_slice())]),
                directories: &[""],
            }),
            ROOT_NOFAIL_MISSING => Ok(Self::root(concat!(
                "UUID=root-uuid / ntfs defaults 0 1\n",
                "UUID=child-uuid /boot ntfs defaults 0 2\n",
                "UUID=absent-uuid /spare ntfs nofail 0 2\n",
            ))),
            ROOT_REQUIRED_MISSING => Ok(Self::root(concat!(
                "UUID=root-uuid / ntfs defaults 0 1\n",
                "UUID=absent-uuid /spare ntfs defaults 0 2\n",
            ))),
            ROOT_FOREIGN => Ok(Self::root(concat!(
                "UUID=another-machine / ntfs defaults 0 1\n",
                "UUID=child-uuid /boot ntfs defaults 0 2\n",
            ))),
            other => Err(FsError::Filesystem(format!("unknown marker {other}"))),
        }
    }

    /// The root volume, serving `fstab` at `/etc/fstab`.
    ///
    /// `boot/covered.txt` is what the root itself keeps under the mount
    /// point, so a composed namespace can be told from an uncomposed one.
    fn root(fstab: &'static str) -> Self {
        Self {
            uuid: "root-uuid",
            files: BTreeMap::from([
                ("etc/fstab", fstab.as_bytes()),
                ("root.txt", b"root".as_slice()),
                ("boot/covered.txt", b"covered by the child".as_slice()),
            ]),
            directories: &["", "etc", "boot", "spare"],
        }
    }

    fn normalize(path: &str) -> &str {
        path.trim_matches('/')
    }

    fn is_directory(&self, path: &str) -> bool {
        self.directories.contains(&path)
    }
}

impl TargetFilesystem for MarkerFilesystem {
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

    /// The files directly in `path`; the fixture's directories are listed
    /// by [`try_is_dir`](TargetFilesystem::try_is_dir), not by this.
    fn read_dir(&mut self, path: &str) -> FsResult<Vec<FsEntry>> {
        let path = Self::normalize(path);
        if !self.is_directory(path) {
            return Err(FsError::NotADirectory(path.to_string()));
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        Ok(self
            .files
            .keys()
            .filter_map(|file| file.strip_prefix(prefix.as_str()))
            .filter(|name| !name.contains('/'))
            .map(|name| FsEntry {
                name: name.to_string(),
                path: PathBuf::from(name),
                flags: FsEntryFlags::empty(),
                file_id: None,
                metadata: FsMetadata::default(),
            })
            .collect())
    }

    fn volume_uuid(&self) -> Option<String> {
        Some(self.uuid.to_string())
    }
}

#[test]
fn an_image_fstab_mounts_the_sibling_partition_it_names() {
    let (_directory, path) = image_file(&two_partition_media(ROOT_PLAIN));

    let opened = open_image_with_fstab(
        &path,
        &registry(),
        ImageOpenOptions::new().with_partition(0),
        "/etc/fstab",
    )
    .expect("compose the guest namespace");

    assert_eq!(
        opened.detected,
        DetectedBootSector::Ntfs,
        "the root's own detection survives composition"
    );
    assert_eq!(opened.format, ImageFormat::Raw);
    assert_eq!(opened.offset, offset_of(ROOT_START_LBA) as u64);
    assert_eq!(opened.size_bytes, u64::from(ROOT_SECTORS) * 512);
    assert_eq!(opened.declared_size_bytes, u64::from(ROOT_SECTORS) * 512);
    assert_eq!(opened.layout_origin, Some(LayoutOrigin::Table));

    let mut filesystem = opened.filesystem;
    assert_eq!(
        filesystem.read("/boot/boot.txt").expect("child volume"),
        b"boot",
        "the /boot entry is served by the second partition"
    );
    assert_eq!(
        filesystem.read("/root.txt").expect("root volume"),
        b"root",
        "the root's own files are still reachable"
    );
    assert!(
        !filesystem.exists("/boot/covered.txt"),
        "the child mount covers what the root keeps under /boot"
    );
    assert!(
        !filesystem.exists("/proc"),
        "a virtual filesystem is no volume to look for"
    );
}

#[test]
fn a_nofail_entry_no_partition_carries_is_skipped() {
    let (_directory, path) = image_file(&two_partition_media(ROOT_NOFAIL_MISSING));

    let opened = open_image_with_fstab(
        &path,
        &registry(),
        ImageOpenOptions::new().with_partition(0),
        "/etc/fstab",
    )
    .expect("compose despite the unresolvable nofail entry");

    let mut filesystem = opened.filesystem;
    assert_eq!(
        filesystem.read("/boot/boot.txt").expect("child volume"),
        b"boot",
        "the resolvable entries are mounted regardless"
    );
    assert!(
        !filesystem.exists("/spare/anything"),
        "nothing was attached where the missing volume would have gone"
    );
}

#[test]
fn a_required_entry_no_partition_carries_is_an_error() {
    let (_directory, path) = image_file(&two_partition_media(ROOT_REQUIRED_MISSING));

    let Err(error) = open_image_with_fstab(
        &path,
        &registry(),
        ImageOpenOptions::new().with_partition(0),
        "/etc/fstab",
    ) else {
        panic!("no partition of the image carries that UUID");
    };
    let error = error.to_string();

    assert!(
        error.contains("/spare") && error.contains("absent-uuid"),
        "the error names the mount point and the UUID it could not find: {error}"
    );
}

#[test]
fn an_fstab_describing_another_root_is_refused() {
    let (_directory, path) = image_file(&two_partition_media(ROOT_FOREIGN));

    let Err(error) = open_image_with_fstab(
        &path,
        &registry(),
        ImageOpenOptions::new().with_partition(0),
        "/etc/fstab",
    ) else {
        panic!("an fstab describing another machine's root must not compose");
    };
    let error = error.to_string();

    assert!(
        error.contains("another-machine") && error.contains("root-uuid"),
        "the error contrasts the UUID fstab expects with the one opened: {error}"
    );
}
