use bitflags::bitflags;

use crate::error::{ExFatError, Result};
use crate::io::{Read, Seek};

use fs_common::boot_sector::{BOOT_SECTOR_SIZE, BOOT_SIGNATURE, ExFatBootSector};
use zerocopy::FromBytes;

bitflags! {
    /// exFAT volume flags from the boot sector.
    ///
    /// These flags indicate the state of the volume and which FAT is
    /// active.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VolumeFlags: u16 {
        /// Which FAT and allocation bitmap are active (0 = first,
        /// 1 = second). Only meaningful when NumberOfFats is 2.
        const ACTIVE_FAT = 0x0001;
        /// The volume is dirty and may have inconsistencies.
        const VOLUME_DIRTY = 0x0002;
        /// The volume has experienced a media failure.
        const MEDIA_FAILURE = 0x0004;
        /// Reserved; implementations shall clear this on mount.
        const CLEAR_TO_ZERO = 0x0008;
    }
}

/// Offset of the backup boot sector (sector 12, always at 12 * 512
/// because we do not yet know the true sector size).
const BACKUP_BOOT_SECTOR_OFFSET: u64 = 12 * BOOT_SECTOR_SIZE as u64;

/// Validates every field of an exFAT boot sector that can be checked
/// without I/O beyond the sector itself.
pub(crate) fn validate_boot_sector(bs: &ExFatBootSector) -> Result<()> {
    // 1. Filesystem name
    if &bs.filesystem_name != b"EXFAT   " {
        return Err(ExFatError::InvalidFileSystemName {
            actual: bs.filesystem_name,
        });
    }

    // 2. Boot signature
    if bs.boot_signature.get() != BOOT_SIGNATURE {
        return Err(ExFatError::InvalidBootSignature {
            actual: bs.boot_signature.get(),
        });
    }

    // 3. MustBeZero BPB area
    if !bs.must_be_zero.iter().all(|&b| b == 0) {
        return Err(ExFatError::MustBeZeroViolation);
    }

    // 4. BytesPerSectorShift in 9..=12
    if !(9..=12).contains(&bs.bytes_per_sector_shift) {
        return Err(ExFatError::InvalidBytesPerSectorShift {
            actual: bs.bytes_per_sector_shift,
        });
    }

    // 5. SectorsPerClusterShift in 0..=(25 - BytesPerSectorShift)
    let max_spc_shift = 25 - bs.bytes_per_sector_shift;
    if bs.sectors_per_cluster_shift > max_spc_shift {
        return Err(ExFatError::InvalidSectorsPerClusterShift {
            actual: bs.sectors_per_cluster_shift,
            max: max_spc_shift,
            bps_shift: bs.bytes_per_sector_shift,
        });
    }

    // 6. NumberOfFats must be 1 or 2
    if bs.number_of_fats != 1 && bs.number_of_fats != 2 {
        return Err(ExFatError::InvalidNumberOfFats {
            actual: bs.number_of_fats,
        });
    }

    // 7. VolumeLength must be > 0
    if bs.volume_length.get() == 0 {
        return Err(ExFatError::InvalidVolumeLength {
            actual: bs.volume_length.get(),
        });
    }

    // 8. PercentInUse must be 0-100 or 0xFF
    if bs.percent_in_use > 100 && bs.percent_in_use != 0xFF {
        return Err(ExFatError::InvalidPercentInUse {
            actual: bs.percent_in_use,
        });
    }

    // 9. FilesystemRevision major must be 0 or 1
    let rev_major = (bs.filesystem_revision.get() >> 8) as u8;
    let rev_minor = (bs.filesystem_revision.get() & 0xFF) as u8;
    if rev_major > 1 {
        return Err(ExFatError::UnsupportedRevision {
            major: rev_major,
            minor: rev_minor,
        });
    }

    // 10. RootDirectoryCluster must be >= 2
    if bs.root_directory_cluster.get() < 2 {
        return Err(ExFatError::InvalidCluster {
            cluster: bs.root_directory_cluster.get(),
        });
    }

    Ok(())
}

/// Reads and parses an exFAT boot sector from the current reader
/// position. If the primary boot sector (offset 0) fails validation,
/// the backup at sector 12 is attempted. Returns the parsed struct
/// together with the sector size in bytes.
pub(crate) fn read_and_validate_boot_sector<T>(fs: &mut T) -> Result<(ExFatBootSector, bool)>
where
    T: Read + Seek,
{
    // --- primary boot sector ---
    fs.rewind()?;
    let mut buf = [0u8; BOOT_SECTOR_SIZE];
    fs.read_exact(&mut buf)?;

    let primary_result = ExFatBootSector::ref_from_bytes(&buf)
        .map_err(|_| ExFatError::InvalidBootSignature { actual: 0 })
        .and_then(|bs| validate_boot_sector(bs).map(|()| *bs));

    match primary_result {
        Ok(bs) => Ok((bs, false)),
        Err(primary_err) => {
            // --- backup boot sector at sector 12 ---
            if fs
                .seek(crate::io::SeekFrom::Start(BACKUP_BOOT_SECTOR_OFFSET))
                .is_err()
            {
                return Err(primary_err);
            }
            let mut backup_buf = [0u8; BOOT_SECTOR_SIZE];
            if fs.read_exact(&mut backup_buf).is_err() {
                return Err(primary_err);
            }

            let backup_result = ExFatBootSector::ref_from_bytes(&backup_buf)
                .ok()
                .and_then(|bs| validate_boot_sector(bs).ok().map(|()| *bs));

            match backup_result {
                Some(bs) => Ok((bs, true)),
                None => Err(primary_err),
            }
        }
    }
}

/// Computes the VBR (Volume Boot Record) checksum over sectors 0
/// through 10, skipping byte indices 106, 107, and 112.
///
/// The checksum is a rotating right-shift with carry (bit 0 moves to
/// bit 31).
pub(crate) fn compute_boot_checksum(sectors: &[u8], bytes_per_sector: u32) -> u32 {
    let len = bytes_per_sector as usize * 11;
    let mut checksum: u32 = 0;

    for i in 0..len {
        // Skip VolumeFlags (bytes 106-107) and PercentInUse (112)
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        let byte = if i < sectors.len() {
            sectors[i] as u32
        } else {
            0
        };
        let bit0 = checksum & 1;
        let carry: u32 = if bit0 != 0 { 0x8000_0000 } else { 0 };
        checksum = carry.wrapping_add(checksum >> 1).wrapping_add(byte);
    }

    checksum
}

/// Reads sectors 0-11 from the reader, computes the checksum over
/// sectors 0-10, and compares it to the repeated checksum value
/// stored in sector 11.
///
/// Returns `Ok(true)` if the checksum matches, `Ok(false)` if it
/// does not. I/O errors are propagated.
pub(crate) fn verify_boot_checksum<T>(
    fs: &mut T,
    bytes_per_sector: u32,
    base_offset: u64,
) -> Result<bool>
where
    T: Read + Seek,
{
    let bps = bytes_per_sector as usize;
    let data_len = bps * 11;

    // Read sectors 0 through 10.
    fs.seek(crate::io::SeekFrom::Start(base_offset))?;
    let mut data = alloc::vec![0u8; data_len];
    fs.read_exact(&mut data)?;

    let expected = compute_boot_checksum(&data, bytes_per_sector);

    // Read sector 11 (the checksum sector).
    let mut checksum_sector = alloc::vec![0u8; bps];
    fs.read_exact(&mut checksum_sector)?;

    // The spec requires the entire sector to be filled with
    // the same u32 checksum value.
    for chunk in checksum_sector.chunks_exact(4) {
        let stored = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        if stored != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{U16, U32, U64};

    /// Creates a valid ExFatBootSector for testing.
    fn make_valid_boot_sector() -> ExFatBootSector {
        ExFatBootSector {
            jump_instruction: [0xEB, 0x76, 0x90],
            filesystem_name: *b"EXFAT   ",
            must_be_zero: [0; 53],
            partition_offset: U64::new(0),
            volume_length: U64::new(100_000),
            fat_offset: U32::new(1),
            fat_length: U32::new(1),
            cluster_heap_offset: U32::new(3),
            cluster_count: U32::new(100),
            root_directory_cluster: U32::new(2),
            volume_serial_number: U32::new(0xDEAD_BEEF),
            filesystem_revision: U16::new(0x0100),
            volume_flags: U16::new(0),
            bytes_per_sector_shift: 9,
            sectors_per_cluster_shift: 0,
            number_of_fats: 1,
            drive_select: 0x80,
            percent_in_use: 50,
            reserved: [0; 7],
            boot_code: [0; 390],
            boot_signature: U16::new(0xAA55),
        }
    }

    #[test]
    fn validate_accepts_valid_boot_sector() {
        let bs = make_valid_boot_sector();
        assert!(validate_boot_sector(&bs).is_ok());
    }

    #[test]
    fn validate_rejects_bad_filesystem_name() {
        let mut bs = make_valid_boot_sector();
        bs.filesystem_name = *b"FAT32   ";
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidFileSystemName { .. }));
    }

    #[test]
    fn validate_rejects_bad_boot_signature() {
        let mut bs = make_valid_boot_sector();
        bs.boot_signature = U16::new(0x0000);
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidBootSignature { .. }));
    }

    #[test]
    fn validate_rejects_nonzero_must_be_zero() {
        let mut bs = make_valid_boot_sector();
        bs.must_be_zero[10] = 0xFF;
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(err, ExFatError::MustBeZeroViolation));
    }

    #[test]
    fn validate_rejects_invalid_bytes_per_sector_shift() {
        for shift in [0, 8, 13, 255] {
            let mut bs = make_valid_boot_sector();
            bs.bytes_per_sector_shift = shift;
            let err = validate_boot_sector(&bs).unwrap_err();
            assert!(matches!(err, ExFatError::InvalidBytesPerSectorShift { .. }));
        }
    }

    #[test]
    fn validate_rejects_invalid_sectors_per_cluster_shift() {
        // With bps_shift=9, max spc_shift=16; 17 should fail.
        let mut bs = make_valid_boot_sector();
        bs.bytes_per_sector_shift = 9;
        bs.sectors_per_cluster_shift = 17;
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(
            err,
            ExFatError::InvalidSectorsPerClusterShift { .. }
        ));
    }

    #[test]
    fn validate_rejects_invalid_number_of_fats() {
        for n in [0, 3, 255] {
            let mut bs = make_valid_boot_sector();
            bs.number_of_fats = n;
            let err = validate_boot_sector(&bs).unwrap_err();
            assert!(matches!(err, ExFatError::InvalidNumberOfFats { .. }));
        }
    }

    #[test]
    fn validate_accepts_two_fats() {
        let mut bs = make_valid_boot_sector();
        bs.number_of_fats = 2;
        assert!(validate_boot_sector(&bs).is_ok());
    }

    #[test]
    fn validate_rejects_invalid_root_directory_cluster() {
        for c in [0u32, 1] {
            let mut bs = make_valid_boot_sector();
            bs.root_directory_cluster = U32::new(c);
            let err = validate_boot_sector(&bs).unwrap_err();
            assert!(matches!(err, ExFatError::InvalidCluster { .. }));
        }
    }

    #[test]
    fn checksum_consistent() {
        let data = [0x42u8; 512 * 11];
        let c1 = compute_boot_checksum(&data, 512);
        let c2 = compute_boot_checksum(&data, 512);
        assert_eq!(c1, c2);
        assert_ne!(c1, 0);
    }

    #[test]
    fn checksum_skips_volume_flags_and_percent_in_use() {
        let mut data = [0x42u8; 512 * 11];
        let c1 = compute_boot_checksum(&data, 512);

        // Modify bytes at offsets 106, 107, 112 -- checksum should
        // not change.
        data[106] = 0xFF;
        data[107] = 0xFF;
        data[112] = 0xFF;
        let c2 = compute_boot_checksum(&data, 512);

        assert_eq!(c1, c2);
    }

    #[test]
    fn checksum_changes_for_other_bytes() {
        let mut data = [0x42u8; 512 * 11];
        let c1 = compute_boot_checksum(&data, 512);

        data[0] = 0x00;
        let c2 = compute_boot_checksum(&data, 512);
        assert_ne!(c1, c2);
    }

    #[test]
    fn validate_rejects_zero_volume_length() {
        let mut bs = make_valid_boot_sector();
        bs.volume_length = U64::new(0);
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidVolumeLength { .. }));
    }

    #[test]
    fn validate_rejects_invalid_percent_in_use() {
        for piu in [101, 200, 0xFE] {
            let mut bs = make_valid_boot_sector();
            bs.percent_in_use = piu;
            let err = validate_boot_sector(&bs).unwrap_err();
            assert!(matches!(err, ExFatError::InvalidPercentInUse { .. }));
        }
    }

    #[test]
    fn validate_accepts_valid_percent_in_use() {
        for piu in [0, 50, 100, 0xFF] {
            let mut bs = make_valid_boot_sector();
            bs.percent_in_use = piu;
            assert!(validate_boot_sector(&bs).is_ok());
        }
    }

    #[test]
    fn validate_rejects_unsupported_revision() {
        let mut bs = make_valid_boot_sector();
        bs.filesystem_revision = U16::new(0x0200); // major=2
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(
            err,
            ExFatError::UnsupportedRevision { major: 2, .. }
        ));
    }

    #[test]
    fn validate_accepts_revision_1_0() {
        let mut bs = make_valid_boot_sector();
        bs.filesystem_revision = U16::new(0x0100);
        assert!(validate_boot_sector(&bs).is_ok());
    }

    #[test]
    fn validate_accepts_revision_0_0() {
        let mut bs = make_valid_boot_sector();
        bs.filesystem_revision = U16::new(0x0000);
        assert!(validate_boot_sector(&bs).is_ok());
    }

    /// Spec §3.1.5 caps `SectorsPerClusterShift` at `25 -
    /// BytesPerSectorShift`; the inclusive boundary must be accepted.
    /// Kills `> → >=` at the spec-bound check.
    #[test]
    fn validate_accepts_max_sectors_per_cluster_shift() {
        let mut bs = make_valid_boot_sector();
        bs.bytes_per_sector_shift = 9;
        bs.sectors_per_cluster_shift = 25 - 9; // exactly at the bound
        assert!(validate_boot_sector(&bs).is_ok());
    }

    /// The minor revision byte is extracted with `& 0xFF`; mutations
    /// that swap `&` for `|` or `^` would corrupt the low byte.
    /// Asserting the exact minor value carried in the error variant
    /// pins the correct bitwise operation.
    #[test]
    fn validate_rejects_unsupported_revision_carries_minor_byte() {
        let mut bs = make_valid_boot_sector();
        bs.filesystem_revision = U16::new(0x0205); // major=2, minor=5
        let err = validate_boot_sector(&bs).unwrap_err();
        assert!(matches!(
            err,
            ExFatError::UnsupportedRevision { major: 2, minor: 5 }
        ));
    }

    /// `compute_boot_checksum` zero-fills beyond `sectors.len()` via
    /// the `i < sectors.len()` guard; mutating to `<=` would index
    /// one past the end and panic. Calling with a short slice
    /// exercises that branch.
    #[test]
    fn checksum_zero_fills_short_sectors_without_panicking() {
        // sectors only 100 bytes long but checksum spans 11 sectors
        // (= 5632 bytes) — the rest must be treated as zero.
        let short = [0x42u8; 100];
        let cs = compute_boot_checksum(&short, 512);
        // Sanity: must not equal zero (some non-zero bytes feed in)
        // and must equal the checksum of the same data zero-padded
        // to 11 sectors.
        let mut padded = [0u8; 512 * 11];
        padded[..100].copy_from_slice(&short);
        let cs_padded = compute_boot_checksum(&padded, 512);
        assert_eq!(cs, cs_padded);
    }
}
