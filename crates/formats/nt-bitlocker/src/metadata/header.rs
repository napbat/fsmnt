use zerocopy::FromBytes;

use super::layout::BitLockerVolumeHeader;
use crate::{BitLockerError, MetadataFailure, Result};

const BITLOCKER_OEM_ID: &[u8; 8] = b"-FVE-FS-";
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const VOLUME_HEADER_SIZE: usize = size_of::<BitLockerVolumeHeader>();

/// Parsed `BitLocker` volume header (boot sector).
///
/// Extracts BPB geometry fields and FVE metadata block offsets
/// needed to locate the three redundant FVE metadata copies.
#[derive(Debug)]
pub struct VolumeHeader {
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    total_sectors: u64,
    volume_serial_number: u64,
    fve_metadata_offsets: [u64; 3],
}

impl VolumeHeader {
    /// Parse a 512-byte volume header from raw bytes.
    ///
    /// Validates the OEM ID (`-FVE-FS-`) and boot signature (0x55AA).
    ///
    /// # Errors
    ///
    /// Returns `InvalidMetadata` if the buffer is too small, the OEM ID
    /// is not `-FVE-FS-`, or the boot signature is missing.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let raw = BitLockerVolumeHeader::read_from_bytes(buf.get(..VOLUME_HEADER_SIZE).ok_or(
            BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: VOLUME_HEADER_SIZE as u64,
                    available: buf.len() as u64,
                },
            },
        )?)
        .map_err(|_| BitLockerError::InvalidMetadata {
            block_index: 0,
            reason: MetadataFailure::SizeBoundsExceeded {
                declared: VOLUME_HEADER_SIZE as u64,
                available: buf.len() as u64,
            },
        })?;

        if &raw.oem_id != BITLOCKER_OEM_ID {
            return Err(BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::InvalidSignature,
            });
        }

        if raw.boot_signature != BOOT_SIGNATURE {
            return Err(BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::InvalidSignature,
            });
        }

        let bytes_per_sector = raw.bytes_per_sector.get();
        if !bytes_per_sector.is_multiple_of(512) || bytes_per_sector == 0 {
            return Err(BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::ParseFailed {
                    offset: 0x0B,
                    detail: "bytes_per_sector must be a non-zero multiple of 512",
                },
            });
        }

        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster: raw.sectors_per_cluster,
            total_sectors: raw.total_sectors.get(),
            volume_serial_number: raw.volume_serial.get(),
            fve_metadata_offsets: [
                raw.fve_metadata_offsets[0].get(),
                raw.fve_metadata_offsets[1].get(),
                raw.fve_metadata_offsets[2].get(),
            ],
        })
    }

    #[must_use]
    pub fn is_bitlocker(&self) -> bool {
        true // Validated in from_bytes
    }

    #[must_use]
    pub fn bytes_per_sector(&self) -> u16 {
        self.bytes_per_sector
    }

    #[must_use]
    pub fn sectors_per_cluster(&self) -> u8 {
        self.sectors_per_cluster
    }

    #[must_use]
    pub fn total_sectors(&self) -> u64 {
        self.total_sectors
    }

    #[must_use]
    pub fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    #[must_use]
    pub fn fve_metadata_offsets(&self) -> [u64; 3] {
        self.fve_metadata_offsets
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn make_volume_header() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x58;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"-FVE-FS-");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 8;
        buf[0x28..0x30].copy_from_slice(&2_097_152u64.to_le_bytes());
        buf[0x48..0x50].copy_from_slice(&0xDEAD_BEEF_CAFE_BABEu64.to_le_bytes());
        buf[0xB0..0xB8].copy_from_slice(&0x0001_0000u64.to_le_bytes());
        buf[0xB8..0xC0].copy_from_slice(&0x0010_0000u64.to_le_bytes());
        buf[0xC0..0xC8].copy_from_slice(&0x0020_0000u64.to_le_bytes());
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    #[test]
    fn parse_volume_header_oem_id() {
        let buf = make_volume_header();
        let header = VolumeHeader::from_bytes(&buf).unwrap();
        assert!(header.is_bitlocker());
        assert_eq!(header.bytes_per_sector(), 512);
        assert_eq!(header.sectors_per_cluster(), 8);
    }

    #[test]
    fn parse_fve_offsets() {
        let buf = make_volume_header();
        let header = VolumeHeader::from_bytes(&buf).unwrap();
        let offsets = header.fve_metadata_offsets();
        assert_eq!(offsets, [0x0001_0000, 0x0010_0000, 0x0020_0000]);
    }

    #[test]
    fn parse_total_sectors() {
        let buf = make_volume_header();
        let header = VolumeHeader::from_bytes(&buf).unwrap();
        assert_eq!(header.total_sectors(), 2_097_152);
    }

    #[test]
    fn reject_non_bitlocker_oem() {
        let mut buf = make_volume_header();
        buf[3..11].copy_from_slice(b"NTFS    ");
        let err = VolumeHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::InvalidSignature,
                ..
            }
        ));
    }

    #[test]
    fn reject_invalid_boot_signature() {
        let mut buf = make_volume_header();
        buf[510] = 0x00;
        let err = VolumeHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::InvalidSignature,
                ..
            }
        ));
    }

    #[test]
    fn reject_zero_bytes_per_sector() {
        let mut buf = make_volume_header();
        buf[0x0B..0x0D].copy_from_slice(&0u16.to_le_bytes());
        let err = VolumeHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::ParseFailed { .. },
                ..
            }
        ));
    }

    #[test]
    fn reject_non_512_multiple_sector_size() {
        let mut buf = make_volume_header();
        buf[0x0B..0x0D].copy_from_slice(&300u16.to_le_bytes());
        let err = VolumeHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::ParseFailed { .. },
                ..
            }
        ));
    }

    #[test]
    fn reject_too_short_buffer() {
        let buf = [0u8; 100];
        let err = VolumeHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }
}
