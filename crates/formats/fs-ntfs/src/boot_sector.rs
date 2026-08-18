use core::ops::RangeInclusive;

use core::mem::offset_of;

use crate::error::{NtfsError, Result};
use crate::types::{Lcn, NtfsPosition};

fn field_offset(offset: usize) -> u64 {
    u64::try_from(offset).expect("boot-sector field offsets fit in u64")
}

// Re-use the boot sector structure from fsmnt-parser-core
pub use fsmnt_parser_core::boot_sector::BOOT_SIGNATURE;
pub(crate) type BootSector = fsmnt_parser_core::boot_sector::NtfsBootSector;

/// Extension trait providing NTFS-specific validation and accessors for the boot sector.
pub(crate) trait BootSectorExt {
    /// Validates the boot sector signature.
    fn validate(&self) -> Result<()>;

    /// Returns the size of a single cluster, in bytes.
    fn cluster_size(&self) -> Result<u32>;

    /// Returns the size of a single sector, in bytes.
    fn sector_size(&self) -> Result<u16>;

    /// Returns the size of a single file record, in bytes.
    fn file_record_size(&self) -> Result<u32>;

    /// Returns the Logical Cluster Number (LCN) to the beginning of the Master File Table (MFT).
    fn mft_lcn(&self) -> Result<Lcn>;

    /// Returns the Logical Cluster Number (LCN) to the beginning of the MFT Mirror ($`MFTMirr`).
    fn mft_mirr_lcn(&self) -> Result<Lcn>;

    /// Returns the volume serial number.
    fn serial_number(&self) -> u64;

    /// Returns the total number of sectors on the volume.
    fn total_sectors(&self) -> u64;
}

/// Expected NTFS OEM ID at offset 3 in the boot sector.
const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";

/// `BitLocker` FVE OEM ID at offset 3 in the boot sector.
const BITLOCKER_OEM_ID: &[u8; 8] = b"-FVE-FS-";

impl BootSectorExt for BootSector {
    fn validate(&self) -> Result<()> {
        // Validate the infamous [0x55, 0xAA] signature at the end of the boot sector.
        let signature = self.boot_signature.get();
        if signature != BOOT_SIGNATURE {
            return Err(NtfsError::InvalidTwoByteSignature {
                position: NtfsPosition::new(field_offset(offset_of!(BootSector, boot_signature))),
                expected: &[0x55, 0xAA],
                actual: signature.to_le_bytes(),
            });
        }

        // Check for BitLocker-encrypted volume before the NTFS OEM ID check.
        // BitLocker replaces "NTFS    " with "-FVE-FS-" but preserves
        // the rest of the boot sector layout.
        if &self.header.oem_id == BITLOCKER_OEM_ID {
            return Err(NtfsError::BitLockerEncrypted {
                position: NtfsPosition::new(field_offset(offset_of!(BootSector, header)) + 3),
                oem_id: self.header.oem_id,
            });
        }

        // Validate the NTFS OEM ID ("NTFS    ") at offset 3.
        if &self.header.oem_id != NTFS_OEM_ID {
            return Err(NtfsError::InvalidOemId {
                position: NtfsPosition::new(field_offset(offset_of!(BootSector, header)) + 3),
                expected: NTFS_OEM_ID,
                actual: self.header.oem_id,
            });
        }

        Ok(())
    }

    fn cluster_size(&self) -> Result<u32> {
        /// The cluster size cannot go lower than a single sector.
        const MIN_CLUSTER_SIZE: u32 = 512;

        /// The maximum cluster size supported by Windows is 2 MiB.
        /// Source: <https://en.wikipedia.org/wiki/NTFS>
        const MAX_CLUSTER_SIZE: u32 = 2_097_152;

        const CLUSTER_SIZE_RANGE: RangeInclusive<u32> = MIN_CLUSTER_SIZE..=MAX_CLUSTER_SIZE;

        // `sectors_per_cluster` and `sector_size` both check for powers of two.
        // Don't need to do that a third time here.
        let cluster_size = u32::from(sectors_per_cluster(self)?) * u32::from(self.sector_size()?);
        if !CLUSTER_SIZE_RANGE.contains(&cluster_size) {
            return Err(NtfsError::UnsupportedClusterSize {
                min: MIN_CLUSTER_SIZE,
                max: MAX_CLUSTER_SIZE,
                actual: cluster_size,
            });
        }

        Ok(cluster_size)
    }

    fn sector_size(&self) -> Result<u16> {
        /// This is the minimum supported by Windows.
        /// NTFS-3G also supports 256-byte sectors, but I haven't seen them anywhere.
        const MIN_SECTOR_SIZE: u16 = 512;

        /// This is the maximum currently supported by Windows.
        /// Tested with Arsenal Image Mounter (<https://github.com/ColinFinck/ntfs/issues/14>).
        const MAX_SECTOR_SIZE: u16 = 4096;

        const SECTOR_SIZE_RANGE: RangeInclusive<u16> = MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE;

        let sector_size = self.bpb.bytes_per_sector.get();
        if !SECTOR_SIZE_RANGE.contains(&sector_size) || !sector_size.is_power_of_two() {
            return Err(NtfsError::UnsupportedSectorSize {
                min: MIN_SECTOR_SIZE,
                max: MAX_SECTOR_SIZE,
                actual: sector_size,
            });
        }

        Ok(sector_size)
    }

    fn file_record_size(&self) -> Result<u32> {
        record_size(self, self.ebpb.clusters_per_mft_record)
    }

    fn mft_lcn(&self) -> Result<Lcn> {
        let mft_lcn_value = self.ebpb.mft_lcn.get();
        if mft_lcn_value > 0 {
            Ok(Lcn::from(mft_lcn_value))
        } else {
            Err(NtfsError::InvalidMftLcn)
        }
    }

    fn mft_mirr_lcn(&self) -> Result<Lcn> {
        let lcn_value = self.ebpb.mft_mirror_lcn.get();
        if lcn_value > 0 {
            Ok(Lcn::from(lcn_value))
        } else {
            Err(NtfsError::InvalidMftMirrLcn)
        }
    }

    fn serial_number(&self) -> u64 {
        self.ebpb.volume_serial_number.get()
    }

    fn total_sectors(&self) -> u64 {
        self.ebpb.total_sectors.get()
    }
}

/// Helper function to decode sectors per cluster with NTFS-specific encoding.
fn sectors_per_cluster(boot_sector: &BootSector) -> Result<u16> {
    /// We can't go lower than a single sector per cluster.
    const MIN_SECTORS_PER_CLUSTER: u8 = 1;

    /// 2^12 = 4096 bytes. With 512 bytes sector size, this translates to 2 MiB cluster size,
    /// which is the maximum currently supported by Windows.
    const MAX_EXPONENT: i8 = 12;

    let sectors_per_cluster = boot_sector.bpb.sectors_per_cluster;

    // Cluster sizes from 512 to 64K are represented by taking `sectors_per_cluster`
    // as-is (with possible values 1, 2, 4, 8, 16, 32, 64, 128).
    // For larger cluster sizes, `sectors_per_cluster` is treated as a binary exponent
    // after negation.
    //
    // See https://dfir.ru/2019/04/23/ntfs-large-clusters/
    if sectors_per_cluster > 128 {
        let exponent = -sectors_per_cluster.cast_signed();

        if exponent > MAX_EXPONENT {
            return Err(NtfsError::InvalidSectorsPerCluster {
                sectors_per_cluster,
            });
        }

        let exponent = u16::try_from(exponent).expect("validated exponent is nonnegative");
        Ok(1 << exponent)
    } else {
        if sectors_per_cluster < MIN_SECTORS_PER_CLUSTER || !sectors_per_cluster.is_power_of_two() {
            return Err(NtfsError::InvalidSectorsPerCluster {
                sectors_per_cluster,
            });
        }

        Ok(u16::from(sectors_per_cluster))
    }
}

/// Helper function to decode record size with NTFS-specific encoding.
/// Source: <https://en.wikipedia.org/wiki/NTFS#Partition_Boot_Sector>_(VBR)
fn record_size(boot_sector: &BootSector, size_info: i8) -> Result<u32> {
    // The usual exponent of `clusters_per_mft_record` is 10 (2^10 = 1024 bytes).
    // For index records, it's usually 12 (2^12 = 4096 bytes).

    /// Exponents < 10 have never been seen and are denied to guarantee that every record header
    /// fits into a record.
    const MIN_EXPONENT: u32 = 10;

    /// Exponents > 12 have neither been seen and are denied to prevent allocating too large buffers.
    const MAX_EXPONENT: u32 = 12;

    const EXPONENT_RANGE: RangeInclusive<u32> = MIN_EXPONENT..=MAX_EXPONENT;

    let cluster_size = boot_sector.cluster_size()?;

    if size_info > 0 {
        // The size field denotes a cluster count.
        cluster_size
            .checked_mul(u32::try_from(size_info).expect("positive record size fits in u32"))
            .ok_or(NtfsError::InvalidRecordSizeInfo {
                size_info,
                cluster_size,
            })
    } else {
        // The size field denotes a binary exponent after negation.
        let exponent = u32::from(size_info.unsigned_abs());

        if !EXPONENT_RANGE.contains(&exponent) {
            return Err(NtfsError::InvalidRecordSizeInfo {
                size_info,
                cluster_size,
            });
        }

        Ok(1 << exponent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::FromBytes;

    /// Build a 512-byte buffer representing a `BitLocker` boot sector.
    /// Valid 0x55AA signature, `-FVE-FS-` OEM ID, NTFS-like BPB.
    fn make_bitlocker_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x52;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8;
        buf[0x28..0x30].copy_from_slice(&2_097_152_u64.to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn test_validate_bitlocker_returns_bitlocker_encrypted() {
        let buf = make_bitlocker_sector();
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        let err = bs.validate().unwrap_err();
        match err {
            NtfsError::BitLockerEncrypted { position, oem_id } => {
                assert_eq!(position.value().map(std::num::NonZero::get), Some(3));
                assert_eq!(&oem_id, b"-FVE-FS-");
            }
            other => panic!("Expected BitLockerEncrypted, got {other}"),
        }
    }

    #[test]
    fn test_validate_invalid_oem_id_unchanged() {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x52;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"GARBAGE!");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8;
        buf[510] = 0x55;
        buf[511] = 0xAA;

        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        let err = bs.validate().unwrap_err();
        let NtfsError::InvalidOemId {
            position,
            expected,
            actual,
        } = err
        else {
            panic!("Expected InvalidOemId, got {err}");
        };
        assert_eq!(expected, b"NTFS    ");
        assert_eq!(&actual, b"GARBAGE!");
        // OEM ID lives at offset 3 (header offset 0 + 3); pins the `+ 3`.
        assert_eq!(position.value().map(std::num::NonZero::get), Some(3));
    }

    /// Build a 512-byte buffer representing a valid NTFS boot sector.
    ///
    /// Field offsets (per `NtfsBootSector` layout): OEM ID @0x03,
    /// `bytes_per_sector` @0x0B, `sectors_per_cluster` @0x0D,
    /// `total_sectors` @0x28, `mft_lcn` @0x30, `mft_mirror_lcn` @0x38,
    /// `clusters_per_mft_record` @0x40, `volume_serial_number` @0x48.
    fn make_ntfs_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x52;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes()); // bytes_per_sector = 512
        buf[0x0D] = 8; // sectors_per_cluster = 8 -> cluster_size = 4096
        buf[0x28..0x30].copy_from_slice(&0x0010_0000u64.to_le_bytes()); // total_sectors
        buf[0x30..0x38].copy_from_slice(&4u64.to_le_bytes()); // mft_lcn
        buf[0x38..0x40].copy_from_slice(&2u64.to_le_bytes()); // mft_mirror_lcn
        buf[0x40] = (-10i8).cast_unsigned(); // clusters_per_mft_record = -10 -> 1024-byte records
        buf[0x48..0x50].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes()); // serial
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn test_valid_accessors_exact_values() {
        let buf = make_ntfs_sector();
        let bs = BootSector::ref_from_bytes(&buf).unwrap();

        bs.validate().expect("valid NTFS boot sector");
        // 512 bytes/sector * 8 sectors/cluster = 4096-byte clusters.
        assert_eq!(bs.cluster_size().unwrap(), 4096);
        assert_eq!(bs.sector_size().unwrap(), 512);
        // clusters_per_mft_record = -10 -> 2^10 = 1024-byte records.
        assert_eq!(bs.file_record_size().unwrap(), 1024);
        assert_eq!(bs.mft_lcn().unwrap().value(), 4);
        assert_eq!(bs.mft_mirr_lcn().unwrap().value(), 2);
        assert_eq!(bs.serial_number(), 0x1122_3344_5566_7788);
        assert_eq!(bs.total_sectors(), 0x0010_0000);
    }

    #[test]
    fn test_cluster_size_multiplies_not_adds() {
        // bytes_per_sector=1024, sectors_per_cluster=4 -> 4096 (multiply).
        // Addition (1024+4=1028) or division would give different values.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&1024u16.to_le_bytes());
        buf[0x0D] = 4;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.cluster_size().unwrap(), 4096);
        assert_eq!(bs.sector_size().unwrap(), 1024);
    }

    #[test]
    fn test_cluster_size_rejects_too_large() {
        // sector_size=4096, sectors_per_cluster=128 -> 524288 (valid, <=2 MiB)
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&4096u16.to_le_bytes());
        buf[0x0D] = 128;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.cluster_size().unwrap(), 524_288);
    }

    #[test]
    fn test_sector_size_boundaries() {
        // 256 is below MIN_SECTOR_SIZE (512) -> rejected.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&256u16.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(bs.sector_size().is_err());

        // 512 is exactly MIN -> accepted.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.sector_size().unwrap(), 512);

        // 4096 is exactly MAX -> accepted.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&4096u16.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.sector_size().unwrap(), 4096);

        // 8192 is above MAX (4096) -> rejected.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&8192u16.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(bs.sector_size().is_err());
    }

    #[test]
    fn test_sector_size_rejects_non_power_of_two() {
        // 1536 is within [512, 4096] but not a power of two -> rejected.
        let mut buf = make_ntfs_sector();
        buf[0x0B..0x0D].copy_from_slice(&1536u16.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(bs.sector_size().is_err());
    }

    #[test]
    fn test_mft_lcn_zero_is_error() {
        let mut buf = make_ntfs_sector();
        buf[0x30..0x38].copy_from_slice(&0u64.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(matches!(bs.mft_lcn(), Err(NtfsError::InvalidMftLcn)));

        // LCN = 1 (just above the zero boundary) is valid.
        let mut buf = make_ntfs_sector();
        buf[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.mft_lcn().unwrap().value(), 1);
    }

    #[test]
    fn test_mft_mirr_lcn_zero_is_error() {
        let mut buf = make_ntfs_sector();
        buf[0x38..0x40].copy_from_slice(&0u64.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(matches!(
            bs.mft_mirr_lcn(),
            Err(NtfsError::InvalidMftMirrLcn)
        ));

        // LCN = 1 (just above the zero boundary) is valid.
        let mut buf = make_ntfs_sector();
        buf[0x38..0x40].copy_from_slice(&1u64.to_le_bytes());
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.mft_mirr_lcn().unwrap().value(), 1);
    }

    #[test]
    fn test_sectors_per_cluster_boundaries() {
        // 0 sectors_per_cluster < MIN (1) -> error.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 0;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(sectors_per_cluster(bs).is_err());

        // 3 is not a power of two -> error.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 3;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(sectors_per_cluster(bs).is_err());

        // 1 is exactly MIN_SECTORS_PER_CLUSTER and a power of two -> Ok(1).
        // This is the boundary: `< 1` is false but `== 1`/`<= 1` would
        // wrongly treat it as below-minimum.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 1;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(sectors_per_cluster(bs).unwrap(), 1);

        // 128 is the largest direct value (power of two) -> 128.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 128;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(sectors_per_cluster(bs).unwrap(), 128);
    }

    #[test]
    fn test_sectors_per_cluster_large_exponent_encoding() {
        // sectors_per_cluster > 128 is treated as a negated exponent.
        // 0xF1 as i8 = -15; negate -> 15; 15 > MAX_EXPONENT(12) -> error.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 0xF1;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(sectors_per_cluster(bs).is_err());

        // 0xF4 as i8 = -12; negate -> 12 (== MAX_EXPONENT) -> 1 << 12 = 4096.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 0xF4;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(sectors_per_cluster(bs).unwrap(), 4096);

        // 0xF6 as i8 = -10; negate -> 10; 1 << 10 = 1024.
        let mut buf = make_ntfs_sector();
        buf[0x0D] = 0xF6;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(sectors_per_cluster(bs).unwrap(), 1024);
    }

    #[test]
    fn test_file_record_size_positive_cluster_count() {
        // clusters_per_mft_record = 2 (positive) -> 2 * cluster_size(4096) = 8192.
        let mut buf = make_ntfs_sector();
        buf[0x40] = 2;
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert_eq!(bs.file_record_size().unwrap(), 8192);
    }

    #[test]
    fn test_record_size_exponent_boundaries() {
        // clusters_per_mft_record = -9 -> exponent 9 < MIN(10) -> error.
        let mut buf = make_ntfs_sector();
        buf[0x40] = (-9i8).cast_unsigned();
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(record_size(bs, -9).is_err());

        // size_info == 0 is NOT a positive cluster count (`> 0` is false),
        // so it takes the exponent path where exponent 0 < MIN -> error.
        // `>= 0` would wrongly multiply, yielding Ok(0).
        let buf = make_ntfs_sector();
        let bs = BootSector::ref_from_bytes(&buf).unwrap();
        assert!(record_size(bs, 0).is_err());

        // size_info == 1 (positive) -> 1 * cluster_size(4096) = 4096.
        assert_eq!(record_size(bs, 1).unwrap(), 4096);

        // -10 -> exponent 10 (== MIN) -> 1024.
        assert_eq!(record_size(bs, -10).unwrap(), 1024);

        // -12 -> exponent 12 (== MAX) -> 4096.
        assert_eq!(record_size(bs, -12).unwrap(), 4096);

        // -13 -> exponent 13 > MAX(12) -> error.
        assert!(record_size(bs, -13).is_err());
    }
}
