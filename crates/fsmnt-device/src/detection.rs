//! Staged filesystem detection over a seekable byte source.

use nostdio::{Read, Seek, SeekFrom};

use crate::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_PROBE_SIZE, DetectedBootSector,
    ExtBackupSuperblock, FS_DETECT_PROBE_SIZE, is_btrfs_primary_superblock,
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
    let detected = probe_at(reader, offset)?.detected;
    if detected != DetectedBootSector::Unknown {
        return Ok(detected);
    }
    Ok(detect_backup_boot_sector_at(reader, offset, None)?.unwrap_or(DetectedBootSector::Unknown))
}

/// Like [`detect_boot_sector_at`], for a volume known to span exactly
/// `length` bytes from `offset` (a partition, a bounded image window).
///
/// The bound enables one more fallback: NTFS keeps a copy of its boot
/// sector in the volume's *last* sector, which can only be found when the
/// end is known.
///
/// # Errors
///
/// Returns an error when a required seek or read operation fails.
pub fn detect_boot_sector_within(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: u64,
) -> std::io::Result<DetectedBootSector> {
    let detected = probe_at(reader, offset)?.detected;
    if detected != DetectedBootSector::Unknown {
        return Ok(detected);
    }
    Ok(detect_backup_boot_sector_at(reader, offset, Some(length))?
        .unwrap_or(DetectedBootSector::Unknown))
}

/// Sector sizes at which backup boot regions are looked for.
const BACKUP_SECTOR_SIZES: [u64; 2] = [512, 4096];

/// Classify a volume whose sector 0 is unreadable by its backup boot
/// region: FAT32 mirrors sectors 0–2 at sector 6, exFAT mirrors its 12-sector
/// boot region at sector 12, and NTFS keeps its boot sector in the last
/// sector of the volume (probed only when `length` is known).
///
/// A backup that reports a different sector size than the one it was found
/// at is a coincidence and is ignored. Returns `Ok(None)` when no backup
/// stands up. Drivers perform the same lookup and open the volume through
/// the copy, so a positive result here dispatches to a driver that can
/// actually read the volume.
///
/// # Errors
///
/// Returns an error when a required seek or read operation fails.
pub fn detect_backup_boot_sector_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: Option<u64>,
) -> std::io::Result<Option<DetectedBootSector>> {
    for sector_size in BACKUP_SECTOR_SIZES {
        // FAT32: `BPB_BkBootSec` is 6 in every formatter's output.
        let fat = read_at(reader, offset + 6 * sector_size, FS_DETECT_PROBE_SIZE)?;
        if DetectedBootSector::from_bytes(&fat) == DetectedBootSector::Fat32
            && bpb_bytes_per_sector(&fat) == sector_size
        {
            return Ok(Some(DetectedBootSector::Fat32));
        }
        // exFAT: backup boot region at sector 12; `BytesPerSectorShift` at 0x6C.
        let exfat = read_at(reader, offset + 12 * sector_size, FS_DETECT_PROBE_SIZE)?;
        if DetectedBootSector::from_bytes(&exfat) == DetectedBootSector::ExFat
            && exfat.len() > 0x6C
            && (1u64 << exfat[0x6C]) == sector_size
        {
            return Ok(Some(DetectedBootSector::ExFat));
        }
        // NTFS: last sector of the volume.
        if let Some(last) = length.and_then(|length| length.checked_sub(sector_size)) {
            let ntfs = read_at(reader, offset + last, FS_DETECT_PROBE_SIZE)?;
            if DetectedBootSector::from_bytes(&ntfs) == DetectedBootSector::Ntfs
                && bpb_bytes_per_sector(&ntfs) == sector_size
            {
                return Ok(Some(DetectedBootSector::Ntfs));
            }
        }
    }
    Ok(None)
}

/// `BPB_BytsPerSec` of a FAT/NTFS boot sector (`u16` at 0x0B); 0 for a
/// buffer too short to hold it.
fn bpb_bytes_per_sector(sector: &[u8]) -> u64 {
    if sector.len() < 0x0D {
        return 0;
    }
    u64::from(u16::from_le_bytes([sector[0x0B], sector[0x0C]]))
}

/// If `offset` holds an ext **backup** superblock, return the block group
/// it belongs to.
///
/// [`detect_boot_sector_at`] deliberately reports such offsets as
/// [`DetectedBootSector::Unknown`] — a backup copy is not the start of a
/// filesystem, and opening from one yields a volume with no readable files.
/// This companion probe lets a caller explain *why* an offset was rejected
/// ("backup superblock of group N; the filesystem starts earlier") instead
/// of a bare "no filesystem". Returns `None` for a primary superblock and
/// for non-ext data.
///
/// # Errors
///
/// Returns an error when the seek or read at `offset` fails.
pub fn ext_backup_superblock_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
) -> std::io::Result<Option<u16>> {
    Ok(ext_backup_superblock_info_at(reader, offset)?.map(|info| info.group))
}

/// Like [`ext_backup_superblock_at`], but also reports the geometry the
/// copy records, so the caller can compute where the filesystem starts
/// with [`ExtBackupSuperblock::filesystem_start`].
///
/// # Errors
///
/// Returns an error when the seek or read at `offset` fails.
pub fn ext_backup_superblock_info_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
) -> std::io::Result<Option<ExtBackupSuperblock>> {
    let prefix = read_at(reader, offset, FS_DETECT_PROBE_SIZE)?;
    Ok(fsmnt_parser_core::ext_backup_superblock_info(&prefix))
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
