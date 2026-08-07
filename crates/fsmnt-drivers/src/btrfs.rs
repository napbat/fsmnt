//! Detection-only adapter over the `fs-btrfs` superblock parser.
//!
//! [`BtrfsDriver`] validates the volume and reports its identity through the
//! normal driver registry. It returns an explicit error from `open` until the
//! format crate grows B-tree traversal support.

use fs_btrfs::{Btrfs, BtrfsError};
use fsmnt_core::{FsError, FsResult, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceReader, DeviceSet, FilesystemDriver};

fn map_btrfs_error(error: BtrfsError) -> FsError {
    match error {
        BtrfsError::Io(error) => FsError::Io(error),
        other => FsError::Filesystem(format!("invalid Btrfs primary superblock: {other}")),
    }
}

fn traversal_stub(superblock: &fs_btrfs::BtrfsSuperblock) -> FsResult<Box<dyn TargetFilesystem>> {
    let label = superblock
        .label()
        .filter(|label| !label.is_empty())
        .map_or_else(|| "<unlabeled>".to_string(), |label| format!("{label:?}"));

    Err(FsError::Filesystem(format!(
        "Btrfs volume {label} (generation {}, {} bytes, {} device(s)) is recognized, \
         but filesystem-tree traversal is not implemented",
        superblock.generation(),
        superblock.total_bytes(),
        superblock.num_devices(),
    )))
}

/// Driver that recognizes Btrfs volumes while traversal remains unimplemented.
#[derive(Clone, Copy, Debug, Default)]
pub struct BtrfsDriver;

impl FilesystemDriver for BtrfsDriver {
    fn name(&self) -> &'static str {
        "btrfs"
    }

    fn supports(&self, detected: DetectedBootSector) -> bool {
        detected == DetectedBootSector::Btrfs
    }

    fn open(
        &self,
        reader: Box<dyn DeviceReader>,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let volume = Btrfs::new(reader).map_err(map_btrfs_error)?;
        traversal_stub(volume.superblock())
    }

    fn open_devices(
        &self,
        devices: DeviceSet,
        _detected: DetectedBootSector,
    ) -> FsResult<Box<dyn TargetFilesystem>> {
        let supplied = u64::try_from(devices.len()).map_err(|_| {
            FsError::Filesystem("Btrfs device-member count exceeds u64".to_string())
        })?;
        let mut superblocks = Vec::with_capacity(devices.len());
        for member in devices.into_members() {
            let volume = Btrfs::new(member.into_reader()).map_err(map_btrfs_error)?;
            superblocks.push(volume.superblock().clone());
        }
        let Some(primary) = superblocks.first() else {
            return Err(FsError::Filesystem(
                "Btrfs device set unexpectedly contained no members".to_string(),
            ));
        };

        if supplied != primary.num_devices() {
            return Err(FsError::Filesystem(format!(
                "Btrfs declares {} device(s), but {supplied} member(s) were supplied; \
                 use --raw with one --member DRIVE:PARTITION for each additional device",
                primary.num_devices(),
            )));
        }
        if superblocks
            .iter()
            .skip(1)
            .any(|candidate| candidate.fsid() != primary.fsid())
        {
            return Err(FsError::Filesystem(
                "supplied Btrfs members have different filesystem UUIDs".to_string(),
            ));
        }
        if superblocks
            .iter()
            .skip(1)
            .any(|candidate| candidate.num_devices() != primary.num_devices())
        {
            return Err(FsError::Filesystem(
                "supplied Btrfs members disagree about the device count".to_string(),
            ));
        }
        for (index, member) in superblocks.iter().enumerate() {
            if superblocks.iter().skip(index + 1).any(|candidate| {
                candidate.device_id() == member.device_id()
                    || candidate.device_uuid() == member.device_uuid()
            }) {
                return Err(FsError::Filesystem(
                    "the same Btrfs device ID or UUID was supplied more than once".to_string(),
                ));
            }
        }

        traversal_stub(primary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_btrfs::{PRIMARY_SUPERBLOCK_OFFSET, SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE};
    use std::io::Cursor;

    fn valid_image() -> Vec<u8> {
        valid_image_for([0_u8; 16], 1, 1, [1_u8; 16])
    }

    fn valid_image_for(
        fsid: [u8; 16],
        device_count: u64,
        device_id: u64,
        device_uuid: [u8; 16],
    ) -> Vec<u8> {
        let offset =
            usize::try_from(PRIMARY_SUPERBLOCK_OFFSET).expect("superblock offset fits usize");
        let mut image = vec![0_u8; offset + SUPERBLOCK_SIZE];
        let superblock = &mut image[offset..];
        superblock[0x20..0x30].copy_from_slice(&fsid);
        superblock[0x30..0x38].copy_from_slice(&PRIMARY_SUPERBLOCK_OFFSET.to_le_bytes());
        superblock[0x40..0x48].copy_from_slice(&SUPERBLOCK_MAGIC);
        superblock[0x48..0x50].copy_from_slice(&101_479u64.to_le_bytes());
        superblock[0x70..0x78].copy_from_slice(&3_998_008_475_648u64.to_le_bytes());
        superblock[0x78..0x80].copy_from_slice(&1_684_313_673_728u64.to_le_bytes());
        superblock[0x80..0x88].copy_from_slice(&6u64.to_le_bytes());
        superblock[0x88..0x90].copy_from_slice(&device_count.to_le_bytes());
        superblock[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
        superblock[0x94..0x98].copy_from_slice(&16_384u32.to_le_bytes());
        superblock[0xc9..0xd1].copy_from_slice(&device_id.to_le_bytes());
        superblock[0x10b..0x11b].copy_from_slice(&device_uuid);
        superblock[0x12b..0x137].copy_from_slice(b"fedora-test\0");
        image
    }

    #[test]
    fn driver_supports_only_btrfs() {
        assert!(BtrfsDriver.supports(DetectedBootSector::Btrfs));
        for other in [
            DetectedBootSector::Ntfs,
            DetectedBootSector::Fat32,
            DetectedBootSector::ExFat,
            DetectedBootSector::Ext,
            DetectedBootSector::Apfs,
            DetectedBootSector::BitLocker,
            DetectedBootSector::GptPartitioned,
            DetectedBootSector::Unknown,
        ] {
            assert!(
                !BtrfsDriver.supports(other),
                "driver must not claim {other:?}"
            );
        }
    }

    #[test]
    fn driver_name_is_stable() {
        assert_eq!(BtrfsDriver.name(), "btrfs");
    }

    #[test]
    fn invalid_superblock_is_reported_before_stub_error() {
        let reader = Box::new(Cursor::new(vec![0_u8; 0x1_1000]));
        let Err(error) = BtrfsDriver.open(reader, DetectedBootSector::Btrfs) else {
            panic!("zeroed superblock must fail");
        };

        assert!(error.to_string().contains("invalid Btrfs"), "{error}");
    }

    #[test]
    fn valid_volume_reports_unimplemented_traversal() {
        let reader = Box::new(Cursor::new(valid_image()));
        let Err(error) = BtrfsDriver.open(reader, DetectedBootSector::Btrfs) else {
            panic!("stub driver must not return a fake filesystem");
        };
        let message = error.to_string();

        assert!(message.contains("fedora-test"), "{message}");
        assert!(message.contains("generation 101479"), "{message}");
        assert!(
            message.contains("traversal is not implemented"),
            "{message}"
        );
    }

    fn member(id: &str, image: Vec<u8>) -> fsmnt_device::DeviceMember {
        let length = u64::try_from(image.len()).expect("test image length fits u64");
        fsmnt_device::DeviceMember::new(
            fsmnt_device::SourceMemberId::Synthetic(id.to_string()),
            Box::new(Cursor::new(image)),
            length,
            512,
        )
        .expect("test member")
    }

    #[test]
    fn multi_device_open_validates_complete_matching_set() {
        let fsid = [0x5a; 16];
        let mut devices = DeviceSet::new(member("one", valid_image_for(fsid, 2, 1, [1; 16])));
        devices
            .push(member("two", valid_image_for(fsid, 2, 2, [2; 16])))
            .expect("second member");

        let Err(error) = BtrfsDriver.open_devices(devices, DetectedBootSector::Btrfs) else {
            panic!("traversal remains a stub");
        };
        assert!(error.to_string().contains("2 device(s)"), "{error}");
        assert!(
            error.to_string().contains("traversal is not implemented"),
            "{error}"
        );
    }

    #[test]
    fn multi_device_open_rejects_missing_member() {
        let devices = DeviceSet::new(member("one", valid_image_for([0x5a; 16], 2, 1, [1; 16])));

        let Err(error) = BtrfsDriver.open_devices(devices, DetectedBootSector::Btrfs) else {
            panic!("missing member must fail");
        };
        assert!(
            error.to_string().contains("but 1 member(s) were supplied"),
            "{error}"
        );
    }

    #[test]
    fn multi_device_open_rejects_foreign_member() {
        let mut devices = DeviceSet::new(member("one", valid_image_for([0x5a; 16], 2, 1, [1; 16])));
        devices
            .push(member(
                "foreign",
                valid_image_for([0xa5; 16], 2, 2, [2; 16]),
            ))
            .expect("foreign identity is distinct");

        let Err(error) = BtrfsDriver.open_devices(devices, DetectedBootSector::Btrfs) else {
            panic!("foreign member must fail");
        };
        assert!(
            error.to_string().contains("different filesystem UUIDs"),
            "{error}"
        );
    }

    #[test]
    fn multi_device_open_rejects_duplicate_device() {
        let fsid = [0x5a; 16];
        let image = valid_image_for(fsid, 2, 1, [1; 16]);
        let mut devices = DeviceSet::new(member("one", image.clone()));
        devices
            .push(member("duplicate", image))
            .expect("synthetic source identities are distinct");

        let Err(error) = BtrfsDriver.open_devices(devices, DetectedBootSector::Btrfs) else {
            panic!("duplicate member must fail");
        };
        assert!(
            error
                .to_string()
                .contains("device ID or UUID was supplied more than once"),
            "{error}"
        );
    }
}
