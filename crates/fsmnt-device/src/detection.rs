//! Staged filesystem detection over a seekable byte source.

use std::io::{Read, Seek, SeekFrom};

use crate::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_PROBE_SIZE, DetectedBootSector,
    FS_DETECT_PROBE_SIZE, is_btrfs_primary_superblock,
};

pub(crate) struct DetectionProbe {
    pub(crate) detected: DetectedBootSector,
    pub(crate) prefix: Vec<u8>,
}

/// Detect a filesystem or partition table at `offset`.
///
/// Common formats are classified from a short prefix. If that prefix is
/// unknown, the reader seeks directly to Btrfs's primary superblock rather
/// than reading the intervening bytes.
///
/// # Errors
///
/// Returns an error when a required seek or read operation fails, or when
/// adding the Btrfs superblock offset would overflow.
pub fn detect_boot_sector_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
) -> std::io::Result<DetectedBootSector> {
    Ok(probe_at(reader, offset)?.detected)
}

pub(crate) fn probe_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
) -> std::io::Result<DetectionProbe> {
    let prefix = read_at(reader, offset, FS_DETECT_PROBE_SIZE)?;
    let mut detected = DetectedBootSector::from_bytes(&prefix);

    if detected == DetectedBootSector::Unknown {
        let superblock_offset = offset
            .checked_add(BTRFS_PRIMARY_SUPERBLOCK_OFFSET)
            .ok_or(std::io::ErrorKind::InvalidInput)?;
        let superblock = read_at(reader, superblock_offset, BTRFS_SUPERBLOCK_PROBE_SIZE)?;
        if is_btrfs_primary_superblock(&superblock) {
            detected = DetectedBootSector::Btrfs;
        }
    }

    Ok(DetectionProbe { detected, prefix })
}

fn read_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: usize,
) -> std::io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0_u8; length];
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BTRFS_SUPERBLOCK_MAGIC;
    use std::io::Cursor;

    fn btrfs_image() -> Vec<u8> {
        let offset = usize::try_from(BTRFS_PRIMARY_SUPERBLOCK_OFFSET).expect("offset fits usize");
        let mut image = vec![0_u8; offset + BTRFS_SUPERBLOCK_PROBE_SIZE];
        let superblock = &mut image[offset..];
        superblock[0x30..0x38].copy_from_slice(&BTRFS_PRIMARY_SUPERBLOCK_OFFSET.to_le_bytes());
        superblock[0x40..0x48].copy_from_slice(&BTRFS_SUPERBLOCK_MAGIC);
        superblock[0x70..0x78].copy_from_slice(&1_073_741_824u64.to_le_bytes());
        superblock[0x78..0x80].copy_from_slice(&16_777_216u64.to_le_bytes());
        superblock[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
        superblock[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
        superblock[0x94..0x98].copy_from_slice(&16_384u32.to_le_bytes());
        image
    }

    #[test]
    fn staged_probe_detects_btrfs() {
        let mut reader = Cursor::new(btrfs_image());

        assert_eq!(
            detect_boot_sector_at(&mut reader, 0).expect("detect"),
            DetectedBootSector::Btrfs
        );
    }

    #[test]
    fn known_prefix_does_not_require_btrfs_region() {
        let mut fat = vec![0_u8; 512];
        fat[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
        fat[0x0d] = 1;
        fat[0x0e..0x10].copy_from_slice(&1u16.to_le_bytes());
        fat[0x10] = 2;
        fat[0x11..0x13].copy_from_slice(&224u16.to_le_bytes());
        fat[0x13..0x15].copy_from_slice(&2880u16.to_le_bytes());
        fat[0x16..0x18].copy_from_slice(&9u16.to_le_bytes());
        fat[510] = 0x55;
        fat[511] = 0xaa;
        let mut reader = Cursor::new(fat);

        assert_eq!(
            detect_boot_sector_at(&mut reader, 0).expect("detect"),
            DetectedBootSector::Fat12
        );
    }
}
