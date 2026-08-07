//! Detection-only adapter over the `fs-btrfs` superblock parser.
//!
//! [`BtrfsDriver`] validates the volume and reports its identity through the
//! normal driver registry. It returns an explicit error from `open` until the
//! format crate grows B-tree traversal support.

use fs_btrfs::{Btrfs, BtrfsError};
use fsmnt_core::{FsError, FsResult, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceReader, FilesystemDriver};

fn map_btrfs_error(error: BtrfsError) -> FsError {
    match error {
        BtrfsError::Io(error) => FsError::Io(error),
        other => FsError::Filesystem(format!("invalid Btrfs primary superblock: {other}")),
    }
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
        let superblock = volume.superblock();
        let label = superblock
            .label()
            .filter(|label| !label.is_empty())
            .map_or_else(|| "<unlabeled>".to_string(), |label| format!("{label:?}"));

        Err(FsError::Filesystem(format!(
            "Btrfs volume {label} (generation {}, {} bytes) is recognized, \
             but filesystem-tree traversal is not implemented",
            superblock.generation(),
            superblock.total_bytes(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_btrfs::{PRIMARY_SUPERBLOCK_OFFSET, SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE};
    use std::io::Cursor;

    fn valid_image() -> Vec<u8> {
        let offset =
            usize::try_from(PRIMARY_SUPERBLOCK_OFFSET).expect("superblock offset fits usize");
        let mut image = vec![0_u8; offset + SUPERBLOCK_SIZE];
        let superblock = &mut image[offset..];
        superblock[0x30..0x38].copy_from_slice(&PRIMARY_SUPERBLOCK_OFFSET.to_le_bytes());
        superblock[0x40..0x48].copy_from_slice(&SUPERBLOCK_MAGIC);
        superblock[0x48..0x50].copy_from_slice(&101_479u64.to_le_bytes());
        superblock[0x70..0x78].copy_from_slice(&3_998_008_475_648u64.to_le_bytes());
        superblock[0x78..0x80].copy_from_slice(&1_684_313_673_728u64.to_le_bytes());
        superblock[0x80..0x88].copy_from_slice(&6u64.to_le_bytes());
        superblock[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
        superblock[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
        superblock[0x94..0x98].copy_from_slice(&16_384u32.to_le_bytes());
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
}
