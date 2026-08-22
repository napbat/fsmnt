//! Recovery detection for formats with redundant DOS-style boot regions.

use nostdio::{Read, Seek};
use tracing::debug;

use crate::{DetectedBootSector, FS_DETECT_PROBE_SIZE};

/// Sector sizes at which redundant boot regions are looked for.
const SECTOR_SIZES: [u64; 2] = [512, 4096];

/// Classify FAT32, exFAT, or NTFS from a redundant boot region.
pub(super) fn detect_backup(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
    length: Option<u64>,
) -> std::io::Result<Option<DetectedBootSector>> {
    for sector_size in SECTOR_SIZES {
        // FAT32: `BPB_BkBootSec` is 6 in every formatter's output.
        let fat_offset = absolute_offset(offset, 6 * sector_size)?;
        let fat = super::read_at(reader, fat_offset, FS_DETECT_PROBE_SIZE)?;
        if DetectedBootSector::from_bytes(&fat) == DetectedBootSector::Fat32
            && bpb_bytes_per_sector(&fat) == sector_size
        {
            debug!(
                offset,
                sector_size, "classified the volume from the FAT32 backup boot sector at sector 6"
            );
            return Ok(Some(DetectedBootSector::Fat32));
        }

        // exFAT: backup boot region at sector 12; `BytesPerSectorShift` at 0x6C.
        let exfat_offset = absolute_offset(offset, 12 * sector_size)?;
        let exfat = super::read_at(reader, exfat_offset, FS_DETECT_PROBE_SIZE)?;
        if DetectedBootSector::from_bytes(&exfat) == DetectedBootSector::ExFat
            && exfat.len() > 0x6C
            && 1_u64.checked_shl(u32::from(exfat[0x6C])) == Some(sector_size)
        {
            debug!(
                offset,
                sector_size, "classified the volume from the exFAT backup boot region at sector 12"
            );
            return Ok(Some(DetectedBootSector::ExFat));
        }

        // NTFS: boot-sector copy in the final sector of a bounded volume.
        if let Some(last) = length.and_then(|length| length.checked_sub(sector_size)) {
            let ntfs_offset = absolute_offset(offset, last)?;
            let ntfs = super::read_at(reader, ntfs_offset, FS_DETECT_PROBE_SIZE)?;
            if DetectedBootSector::from_bytes(&ntfs) == DetectedBootSector::Ntfs
                && bpb_bytes_per_sector(&ntfs) == sector_size
            {
                debug!(
                    offset,
                    sector_size,
                    "classified the volume from the NTFS boot-sector copy in its last sector"
                );
                return Ok(Some(DetectedBootSector::Ntfs));
            }
        }
    }
    Ok(None)
}

fn absolute_offset(base: u64, relative: u64) -> std::io::Result<u64> {
    base.checked_add(relative)
        .ok_or(std::io::ErrorKind::InvalidInput.into())
}

/// `BPB_BytsPerSec` (`u16` at 0x0B), or zero for a short buffer.
fn bpb_bytes_per_sector(sector: &[u8]) -> u64 {
    if sector.len() < 0x0D {
        return 0;
    }
    u64::from(u16::from_le_bytes([sector[0x0B], sector[0x0C]]))
}
