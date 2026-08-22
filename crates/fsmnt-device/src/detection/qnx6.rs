//! End-relative QNX6 snapshot detection.

use fsmnt_parser_core::boot_sector::qnx6::{
    SUPERBLOCK_AREA_SIZE, SUPERBLOCK_SIZE, superblock_volume_size,
};
use nostdio::{Read, Seek};

use crate::{DetectedBootSector, Mbr};

/// Try the trailing snapshot when the primary result permits an override.
///
/// A damaged primary leaves the QNX boot-loader sector, which can carry an
/// MBR signature. Only an implausible table may be superseded; a credible
/// partition table remains authoritative.
pub(super) fn detect_backup_over_primary(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: u64,
    primary: DetectedBootSector,
    prefix: &[u8],
) -> std::io::Result<Option<DetectedBootSector>> {
    let may_override = primary == DetectedBootSector::Unknown
        || primary == DetectedBootSector::MbrPartitioned
            && Mbr::from_bytes(prefix).is_some_and(|mbr| !mbr.is_plausible_table());
    if !may_override {
        return Ok(None);
    }
    detect_backup(reader, offset, length)
}

/// Classify the trailing superblock snapshot of a bounded QNX6 volume.
pub(super) fn detect_backup(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: u64,
) -> std::io::Result<Option<DetectedBootSector>> {
    let Some(relative) = length.checked_sub(SUPERBLOCK_AREA_SIZE) else {
        return Ok(None);
    };
    let Some(absolute) = offset.checked_add(relative) else {
        return Ok(None);
    };
    let superblock = super::read_at(reader, absolute, SUPERBLOCK_SIZE)?;
    Ok((superblock_volume_size(&superblock) == Some(length)).then_some(DetectedBootSector::Qnx6))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use fsmnt_parser_core::boot_sector::qnx6::SUPERBLOCK_MAGIC;

    use super::super::detect_boot_sector_within;
    use super::*;

    const IMAGE_SIZE: usize = 0x6000;

    fn write_superblock(superblock: &mut [u8]) {
        superblock[..4].copy_from_slice(&SUPERBLOCK_MAGIC.to_le_bytes());
        superblock[0x30..0x34].copy_from_slice(&1024_u32.to_le_bytes());
        superblock[0x34..0x38].copy_from_slice(&100_u32.to_le_bytes());
        superblock[0x38..0x3c].copy_from_slice(&40_u32.to_le_bytes());
        superblock[0x3c..0x40].copy_from_slice(&8_u32.to_le_bytes());
        superblock[0x40..0x44].copy_from_slice(&1_u32.to_le_bytes());
    }

    fn image_with_backup() -> Vec<u8> {
        let mut image = vec![0_u8; IMAGE_SIZE];
        let backup = image.len()
            - usize::try_from(SUPERBLOCK_AREA_SIZE).expect("superblock area fits usize");
        write_superblock(&mut image[backup..backup + SUPERBLOCK_SIZE]);
        image
    }

    fn write_mbr_entry(image: &mut [u8], boot_indicator: u8) {
        let entry = 0x1BE;
        image[entry] = boot_indicator;
        image[entry + 4] = 0xB1;
        image[entry + 8..entry + 12].copy_from_slice(&1_u32.to_le_bytes());
        image[entry + 12..entry + 16].copy_from_slice(&8_u32.to_le_bytes());
        image[510] = 0x55;
        image[511] = 0xAA;
    }

    #[test]
    fn bounded_probe_uses_the_copy_when_the_primary_is_damaged() {
        let image = image_with_backup();
        let length = u64::try_from(image.len()).expect("length fits u64");
        let mut reader = Cursor::new(image);

        assert_eq!(
            detect_boot_sector_within(&mut reader, 0, length).expect("detect backup"),
            DetectedBootSector::Qnx6
        );
    }

    #[test]
    fn backup_overrides_an_implausible_boot_loader_mbr() {
        let mut image = image_with_backup();
        write_mbr_entry(&mut image, 0x7F);
        let length = u64::try_from(image.len()).expect("length fits u64");
        let mut reader = Cursor::new(image);

        assert_eq!(
            detect_boot_sector_within(&mut reader, 0, length).expect("detect backup"),
            DetectedBootSector::Qnx6
        );
    }

    #[test]
    fn backup_does_not_override_a_plausible_partition_table() {
        let mut image = image_with_backup();
        write_mbr_entry(&mut image, 0);
        let length = u64::try_from(image.len()).expect("length fits u64");
        let mut reader = Cursor::new(image);

        assert_eq!(
            detect_boot_sector_within(&mut reader, 0, length).expect("detect MBR"),
            DetectedBootSector::MbrPartitioned
        );
    }
}
