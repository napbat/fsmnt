//! Backup boot sectors: opening FAT32, exFAT and NTFS volumes whose
//! primary boot sector is damaged.
//!
//! Each of these formats keeps a copy of the boot region that a parser
//! insists on reading from sector 0:
//!
//! | Format | Backup location                                   | Copied region        |
//! |--------|---------------------------------------------------|----------------------|
//! | FAT32  | sector 6 (`BPB_BkBootSec`, fixed by every formatter) | 3 sectors: boot, `FSInfo`, sector 2 |
//! | exFAT  | sector 12 (backup boot region)                     | 12 sectors           |
//! | NTFS   | the last sector of the volume                      | 1 sector             |
//!
//! When sector 0 no longer classifies as the driver's format but the copy
//! does, the driver opens the volume through a [`PatchedReader`] that
//! presents the copy at sector 0 — the source is never modified — and
//! records a notice so the CLI can say which copy stood in. FAT12/16 have
//! no backup; a damaged FAT12/16 boot sector stays unrecoverable here.

use std::io::{self, Read, Seek, SeekFrom};

use fsmnt_device::DetectedBootSector;
use fsmnt_parser_core::FS_DETECT_PROBE_SIZE;
use tracing::debug;

use crate::patched::PatchedReader;

/// Sector sizes at which the backup regions are looked for: the classic
/// 512-byte layout and 4 KiB-sector media.
const SECTOR_SIZES: [u64; 2] = [512, 4096];

/// A backup boot region found on the volume, ready to stand in for sector 0.
pub(crate) struct BootBackup {
    /// Byte offset the copy was read from.
    pub(crate) source_offset: u64,
    /// The bytes to present starting at byte 0.
    pub(crate) bytes: Vec<u8>,
    /// Which format's backup this is, for the notice.
    pub(crate) what: &'static str,
}

impl BootBackup {
    /// Human-readable explanation of the fallback for
    /// [`fsmnt_core::TargetFilesystem::notices`].
    pub(crate) fn notice(&self) -> String {
        format!(
            "primary boot sector is not a valid {}; opened through the backup copy at byte {} \
             ({} bytes) — the view reflects that copy",
            self.what,
            self.source_offset,
            self.bytes.len()
        )
    }

    /// Wrap `reader` so that the copy is presented at byte 0.
    pub(crate) fn apply<R: Read + Seek>(&self, reader: R) -> PatchedReader<R> {
        PatchedReader::new(reader).with_patch(0, self.bytes.clone())
    }
}

/// The boot-sector families that keep a backup copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    /// FAT12/16/32 (only FAT32 has a backup, but any FAT type counts as an
    /// intact primary).
    Fat,
    /// exFAT.
    ExFat,
    /// NTFS.
    Ntfs,
}

impl Family {
    /// Whether `detected` is a healthy primary boot sector for this family.
    fn accepts(self, detected: DetectedBootSector) -> bool {
        match self {
            Self::Fat => matches!(
                detected,
                DetectedBootSector::Fat12 | DetectedBootSector::Fat16 | DetectedBootSector::Fat32
            ),
            Self::ExFat => detected == DetectedBootSector::ExFat,
            Self::Ntfs => detected == DetectedBootSector::Ntfs,
        }
    }
}

/// Read up to `len` bytes at `offset`; a short read (end of media) returns
/// the bytes that were there.
fn read_at(reader: &mut (impl Read + Seek + ?Sized), offset: u64, len: u64) -> io::Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; usize::try_from(len).map_err(|_| io::ErrorKind::InvalidInput)?];
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Classify the bytes at `offset` the way volume detection does.
fn classify_at(
    reader: &mut (impl Read + Seek + ?Sized),
    offset: u64,
) -> io::Result<DetectedBootSector> {
    let probe = read_at(reader, offset, FS_DETECT_PROBE_SIZE as u64)?;
    Ok(DetectedBootSector::from_bytes(&probe))
}

/// `BPB_BytsPerSec` of a FAT/NTFS boot sector (`u16` at 0x0B).
fn bpb_bytes_per_sector(sector: &[u8]) -> u64 {
    u64::from(u16::from_le_bytes([sector[0x0B], sector[0x0C]]))
}

/// If sector 0 is not a healthy `family` boot sector but a backup copy
/// exists, return that copy. `Ok(None)` means either "primary is fine, no
/// fallback needed" or "no usable backup either" — the caller opens the
/// volume normally in both cases and lets the parser report the damage.
///
/// The reader position is unspecified afterwards; callers rewind.
///
/// # Errors
///
/// Returns an error when the source cannot be read.
pub(crate) fn find_if_primary_damaged(
    reader: &mut (impl Read + Seek + ?Sized),
    family: Family,
) -> io::Result<Option<BootBackup>> {
    let primary = classify_at(reader, 0)?;
    if family.accepts(primary) {
        return Ok(None);
    }
    let backup = match family {
        Family::Fat => fat32_backup(reader),
        Family::ExFat => exfat_backup(reader),
        Family::Ntfs => ntfs_backup(reader),
    }?;
    if let Some(found) = &backup {
        debug!(
            family = ?family,
            primary = ?primary,
            offset = found.source_offset,
            size_bytes = found.bytes.len(),
            "sector 0 is not a usable boot sector; standing in the backup copy"
        );
    } else {
        debug!(
            family = ?family,
            primary = ?primary,
            "sector 0 is not a usable boot sector and no backup copy was found; \
             opening from sector 0 regardless"
        );
    }
    Ok(backup)
}

/// FAT32 keeps the boot sector, `FSInfo` and the third boot sector again at
/// sector 6 (`BPB_BkBootSec` is always 6 in practice).
fn fat32_backup(reader: &mut (impl Read + Seek + ?Sized)) -> io::Result<Option<BootBackup>> {
    for sector_size in SECTOR_SIZES {
        let offset = 6 * sector_size;
        if classify_at(reader, offset)? != DetectedBootSector::Fat32 {
            continue;
        }
        let region = read_at(reader, offset, 3 * sector_size)?;
        // The copy must agree that sectors are this big, or it is a
        // coincidence at the wrong scale.
        if region.len() < 512 || bpb_bytes_per_sector(&region) != sector_size {
            continue;
        }
        return Ok(Some(BootBackup {
            source_offset: offset,
            bytes: region,
            what: "FAT32 boot sector",
        }));
    }
    Ok(None)
}

/// exFAT mirrors its whole 12-sector main boot region at sector 12.
fn exfat_backup(reader: &mut (impl Read + Seek + ?Sized)) -> io::Result<Option<BootBackup>> {
    for sector_size in SECTOR_SIZES {
        let offset = 12 * sector_size;
        if classify_at(reader, offset)? != DetectedBootSector::ExFat {
            continue;
        }
        let region = read_at(reader, offset, 12 * sector_size)?;
        // `BytesPerSectorShift` at 0x6C: 9 for 512, 12 for 4096.
        if region.len() < 0x6D || (1u64 << region[0x6C]) != sector_size {
            continue;
        }
        return Ok(Some(BootBackup {
            source_offset: offset,
            bytes: region,
            what: "exFAT boot region",
        }));
    }
    Ok(None)
}

/// NTFS writes a copy of the boot sector into the last sector of the
/// volume — which is why an NTFS partition is one sector larger than the
/// filesystem it holds. This needs the reader to end where the volume ends
/// (a bounded partition reader does; a whole-disk image does not).
fn ntfs_backup(reader: &mut (impl Read + Seek + ?Sized)) -> io::Result<Option<BootBackup>> {
    let end = reader.seek(SeekFrom::End(0))?;
    for sector_size in SECTOR_SIZES {
        let Some(offset) = end.checked_sub(sector_size) else {
            continue;
        };
        if classify_at(reader, offset)? != DetectedBootSector::Ntfs {
            continue;
        }
        let sector = read_at(reader, offset, sector_size)?;
        if sector.len() < 512 || bpb_bytes_per_sector(&sector) != sector_size {
            continue;
        }
        return Ok(Some(BootBackup {
            source_offset: offset,
            bytes: sector,
            what: "NTFS boot sector",
        }));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A minimal FAT32 boot sector that `DetectedBootSector::from_bytes`
    /// classifies as FAT32.
    fn fat32_boot_sector() -> Vec<u8> {
        let mut s = vec![0u8; 512];
        s[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        s[3..11].copy_from_slice(b"MSWIN4.1");
        s[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes/sector
        s[0x0D] = 8; // sectors/cluster
        s[0x0E..0x10].copy_from_slice(&32u16.to_le_bytes()); // reserved sectors
        s[0x10] = 2; // FATs
        s[0x20..0x24].copy_from_slice(&1_048_576u32.to_le_bytes()); // total sectors 32
        s[0x24..0x28].copy_from_slice(&1024u32.to_le_bytes()); // FAT size 32
        s[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes()); // root cluster
        s[0x30..0x32].copy_from_slice(&1u16.to_le_bytes()); // FSInfo sector
        s[0x32..0x34].copy_from_slice(&6u16.to_le_bytes()); // backup boot sector
        s[0x40] = 0x80;
        s[0x42] = 0x29;
        s[0x47..0x52].copy_from_slice(b"NO NAME    ");
        s[0x52..0x5A].copy_from_slice(b"FAT32   ");
        s[510] = 0x55;
        s[511] = 0xAA;
        s
    }

    #[test]
    fn healthy_primary_needs_no_fallback() {
        let mut image = vec![0u8; 16 * 512];
        image[..512].copy_from_slice(&fat32_boot_sector());
        let mut reader = Cursor::new(image);
        assert!(
            find_if_primary_damaged(&mut reader, Family::Fat)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn damaged_fat32_primary_falls_back_to_sector_six() {
        let mut image = vec![0u8; 16 * 512];
        // Sector 0 zeroed (damaged); sectors 6..9 hold the backup region.
        image[6 * 512..7 * 512].copy_from_slice(&fat32_boot_sector());
        image[7 * 512..7 * 512 + 4].copy_from_slice(b"RRaA"); // FSInfo lead sig
        let mut reader = Cursor::new(image.clone());
        let backup = find_if_primary_damaged(&mut reader, Family::Fat)
            .unwrap()
            .expect("backup boot sector must be found");
        assert_eq!(backup.source_offset, 3072);
        assert_eq!(backup.bytes.len(), 1536);
        assert!(backup.notice().contains("byte 3072"));

        // Through the patch, sector 0 now reads as the FAT32 boot sector and
        // sector 1 as the FSInfo copy.
        let mut patched = backup.apply(Cursor::new(image));
        let mut head = vec![0u8; 1024];
        patched.read_exact(&mut head).unwrap();
        assert_eq!(&head[0x52..0x5A], b"FAT32   ");
        assert_eq!(&head[512..516], b"RRaA");
        assert_eq!(
            DetectedBootSector::from_bytes(&head[..512]),
            DetectedBootSector::Fat32
        );
    }

    #[test]
    fn no_backup_means_no_fallback() {
        let mut reader = Cursor::new(vec![0u8; 64 * 512]);
        assert!(
            find_if_primary_damaged(&mut reader, Family::Fat)
                .unwrap()
                .is_none()
        );
        assert!(
            find_if_primary_damaged(&mut reader, Family::ExFat)
                .unwrap()
                .is_none()
        );
        assert!(
            find_if_primary_damaged(&mut reader, Family::Ntfs)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ntfs_backup_is_the_last_sector() {
        // A boot sector shaped like NTFS's: OEM "NTFS    ", 512-byte sectors,
        // sensible geometry, boot signature.
        let mut boot = vec![0u8; 512];
        boot[0..3].copy_from_slice(&[0xEB, 0x52, 0x90]);
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        boot[0x0D] = 8;
        boot[0x15] = 0xF8;
        boot[0x18..0x1A].copy_from_slice(&63u16.to_le_bytes());
        boot[0x1A..0x1C].copy_from_slice(&255u16.to_le_bytes());
        boot[0x28..0x30].copy_from_slice(&2_097_151u64.to_le_bytes()); // total sectors
        boot[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes()); // $MFT cluster
        boot[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // $MFTMirr cluster
        boot[0x40] = 0xF6; // 1 KiB file records
        boot[0x44] = 1; // index buffer clusters
        boot[510] = 0x55;
        boot[511] = 0xAA;
        assert_eq!(
            DetectedBootSector::from_bytes(&boot),
            DetectedBootSector::Ntfs,
            "test boot sector must classify as NTFS"
        );

        let mut image = vec![0u8; 100 * 512];
        let last = image.len() - 512;
        image[last..].copy_from_slice(&boot);
        let mut reader = Cursor::new(image);
        let backup = find_if_primary_damaged(&mut reader, Family::Ntfs)
            .unwrap()
            .expect("NTFS backup at the end must be found");
        assert_eq!(backup.source_offset, last as u64);
        assert_eq!(backup.what, "NTFS boot sector");
    }
}
