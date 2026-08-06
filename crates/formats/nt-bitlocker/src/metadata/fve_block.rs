use zerocopy::FromBytes;

use super::layout::{FveBlockHeader, FveDatasetHeader, FveValidation};
use crate::{BitLockerError, MetadataFailure, Result};

const FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";
const BLOCK_HEADER_SIZE: usize = size_of::<FveBlockHeader>();
const DATASET_HEADER_SIZE: usize = size_of::<FveDatasetHeader>();
const MIN_BLOCK_SIZE: usize = BLOCK_HEADER_SIZE + DATASET_HEADER_SIZE;
/// Version 2 (Windows 7+): the block header `size` field is shifted left
/// by 4 to obtain the total metadata block size in bytes.
const V_SEVEN: u16 = 2;

/// Parsed FVE metadata block (block header + dataset header + datum data).
///
/// Each `BitLocker` volume contains three redundant copies of this structure.
#[derive(Debug, Clone)]
pub struct FveBlock {
    block_version: u16,
    encryption_state_raw: u16,
    encrypted_volume_size: u64,
    nb_backup_sectors: u32,
    boot_sectors_backup: u64,
    metadata_version: u32,
    encryption_method_raw: u32,
    volume_guid: [u8; 16],
    creation_time: u64,
    datum_data: Vec<u8>,
}

impl FveBlock {
    /// Parse an FVE metadata block from raw bytes.
    ///
    /// `block_index` identifies which of the three copies this is (0, 1, or 2)
    /// for error reporting.
    ///
    /// # Errors
    ///
    /// Returns `InvalidMetadata` if the signature is wrong, the buffer is
    /// too small, or the CRC-32 check fails.
    pub fn from_bytes(buf: &[u8], block_index: u8) -> Result<Self> {
        if buf.len() < MIN_BLOCK_SIZE {
            return Err(BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(MIN_BLOCK_SIZE).unwrap_or(u64::MAX),
                    available: u64::try_from(buf.len()).unwrap_or(u64::MAX),
                },
            });
        }

        // Parse the block header (64 bytes at offset 0).
        let (block_hdr, rest) =
            FveBlockHeader::read_from_prefix(buf).map_err(|_| BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(BLOCK_HEADER_SIZE).unwrap_or(u64::MAX),
                    available: u64::try_from(buf.len()).unwrap_or(u64::MAX),
                },
            })?;

        if &block_hdr.signature != FVE_SIGNATURE {
            return Err(BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::InvalidSignature,
            });
        }

        let block_version = block_hdr.version.get();

        // Total metadata block size: for V2 (Windows 7+) the block header
        // `size` field is stored shifted right by 4 — multiply by 16.
        // For V1 (Vista) the field is the raw byte count.
        // Ref: dislocker metadata.c get_metadata()
        let total_block_size = if block_version >= V_SEVEN {
            usize::from(block_hdr.size.get()) << 4
        } else {
            usize::from(block_hdr.size.get())
        };

        // Parse the dataset header (48 bytes at offset 64).
        let dataset_hdr = FveDatasetHeader::read_from_prefix(rest)
            .map(|(hdr, _)| hdr)
            .map_err(|_| BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(DATASET_HEADER_SIZE).unwrap_or(u64::MAX),
                    available: u64::try_from(rest.len()).unwrap_or(u64::MAX),
                },
            })?;

        let dataset_size = usize::try_from(dataset_hdr.size.get()).unwrap_or(usize::MAX);
        if dataset_size < DATASET_HEADER_SIZE {
            return Err(BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(DATASET_HEADER_SIZE).unwrap_or(u64::MAX),
                    available: u64::try_from(dataset_size).unwrap_or(u64::MAX),
                },
            });
        }

        // Parse the validations structure (8 bytes immediately after the block).
        let validations_start = total_block_size;
        let validations_end = validations_start + size_of::<FveValidation>();
        if validations_end > buf.len() {
            return Err(BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: u64::try_from(validations_end).unwrap_or(u64::MAX),
                    available: u64::try_from(buf.len()).unwrap_or(u64::MAX),
                },
            });
        }

        let validation = FveValidation::read_from_bytes(&buf[validations_start..validations_end])
            .map_err(|_| BitLockerError::InvalidMetadata {
            block_index,
            reason: MetadataFailure::SizeBoundsExceeded {
                declared: u64::try_from(validations_end).unwrap_or(u64::MAX),
                available: u64::try_from(buf.len()).unwrap_or(u64::MAX),
            },
        })?;

        // CRC-32 validation: computed over the entire metadata block
        // (block header + dataset header + datums), then compared against
        // the crc32 field in the validations structure.
        // Ref: dislocker metadata.c get_metadata_lazy_checked()
        let computed_crc = crc32fast::hash(&buf[..total_block_size]);
        if computed_crc != validation.crc32.get() {
            return Err(BitLockerError::InvalidMetadata {
                block_index,
                reason: MetadataFailure::CrcMismatch,
            });
        }

        // Datum data follows the dataset header.
        let datum_start = BLOCK_HEADER_SIZE + DATASET_HEADER_SIZE;
        let datum_end = (BLOCK_HEADER_SIZE + dataset_size).min(total_block_size);
        let datum_data = if datum_start < datum_end {
            buf[datum_start..datum_end].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            block_version,
            encryption_state_raw: block_hdr.curr_state.get(),
            encrypted_volume_size: block_hdr.encrypted_volume_size.get(),
            nb_backup_sectors: block_hdr.nb_backup_sectors.get(),
            boot_sectors_backup: block_hdr.boot_sectors_backup.get(),
            metadata_version: dataset_hdr.version.get(),
            encryption_method_raw: u32::from(dataset_hdr.algorithm.get()),
            volume_guid: dataset_hdr.volume_guid,
            creation_time: dataset_hdr.timestamp.get(),
            datum_data,
        })
    }

    #[must_use]
    /// Returns the FVE metadata block format version.
    pub fn block_version(&self) -> u16 {
        self.block_version
    }

    #[must_use]
    /// Returns the raw on-disk encryption-state identifier.
    pub fn encryption_state_raw(&self) -> u16 {
        self.encryption_state_raw
    }

    #[must_use]
    /// Returns the number of volume bytes covered by encryption.
    pub fn encrypted_volume_size(&self) -> u64 {
        self.encrypted_volume_size
    }

    /// Number of sectors at the start of the volume that have been relocated
    /// to [`boot_sectors_backup_offset`](Self::boot_sectors_backup_offset).
    #[must_use]
    pub fn nb_backup_sectors(&self) -> u32 {
        self.nb_backup_sectors
    }

    /// Byte offset on disk where the original boot sectors are backed up.
    #[must_use]
    pub fn boot_sectors_backup_offset(&self) -> u64 {
        self.boot_sectors_backup
    }

    #[must_use]
    /// Returns the dataset metadata version used to select redundant copies.
    pub fn metadata_version(&self) -> u32 {
        self.metadata_version
    }

    #[must_use]
    /// Returns the raw on-disk encryption-method identifier.
    pub fn encryption_method_raw(&self) -> u32 {
        self.encryption_method_raw
    }

    #[must_use]
    /// Returns the volume identifier recorded in this metadata block.
    pub fn volume_guid(&self) -> &[u8; 16] {
        &self.volume_guid
    }

    #[must_use]
    /// Returns the metadata creation timestamp in its raw Windows form.
    pub fn creation_time(&self) -> u64 {
        self.creation_time
    }

    #[must_use]
    /// Returns the encoded datum sequence following the dataset header.
    pub fn datum_data(&self) -> &[u8] {
        &self.datum_data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALIDATION_SIZE: usize = size_of::<FveValidation>();

    fn make_fve_block(version: u16) -> Vec<u8> {
        let metadata_size: u32 = 128;
        // total_block_size = block_header (64) + metadata_size (128) = 192
        let total_block_size = BLOCK_HEADER_SIZE
            + usize::try_from(metadata_size)
                .expect("the test metadata size fits in the host address space");
        // Buffer must hold the block + the 8-byte validations structure
        let mut buf = vec![0u8; total_block_size + VALIDATION_SIZE];
        // Block header (64 bytes)
        buf[0..8].copy_from_slice(b"-FVE-FS-");
        // Size field at offset 8: for V2 this is total_block_size >> 4
        let size_field: u16 = if version >= V_SEVEN {
            u16::try_from(total_block_size >> 4)
                .expect("the test block's 16-byte unit count fits in u16")
        } else {
            u16::try_from(total_block_size).expect("the test block size fits in u16")
        };

        buf[0x08..0x0A].copy_from_slice(&size_field.to_le_bytes());
        buf[0x0A..0x0C].copy_from_slice(&version.to_le_bytes());
        buf[0x10..0x18].copy_from_slice(&1_048_576u64.to_le_bytes());

        // Metadata header (48 bytes, at offset 64)
        buf[64..68].copy_from_slice(&metadata_size.to_le_bytes());
        buf[68..72].copy_from_slice(&1u32.to_le_bytes()); // version
        buf[72..76].copy_from_slice(&48u32.to_le_bytes()); // header size
        buf[76..80].copy_from_slice(&metadata_size.to_le_bytes()); // size copy

        // encryption method at offset 64+0x24 = 100
        buf[100..104].copy_from_slice(&0x8004u32.to_le_bytes()); // AES-128-XTS

        // CRC-32 validation: CRC is computed over the entire block
        // (block header + metadata header + datums) and stored in the
        // validations structure that follows, at offset total_block_size+4.
        let crc = crc32fast::hash(&buf[..total_block_size]);
        let crc_offset = total_block_size + 4; // skip {u16 size, u16 version}
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn parse_fve_block_valid() {
        let buf = make_fve_block(2);
        let block = FveBlock::from_bytes(&buf, 0).unwrap();
        assert_eq!(block.block_version(), 2);
        assert_eq!(block.encryption_method_raw(), 0x8004);
        assert_eq!(block.encrypted_volume_size(), 1_048_576);
    }

    #[test]
    fn reject_bad_signature() {
        let mut buf = make_fve_block(2);
        buf[0..8].copy_from_slice(b"NOTFVEFS");
        let err = FveBlock::from_bytes(&buf, 0).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::InvalidSignature,
                ..
            }
        ));
    }

    #[test]
    fn reject_crc_mismatch() {
        let mut buf = make_fve_block(2);
        // Corrupt metadata content after CRC was computed
        buf[70] = 0xFF;
        let err = FveBlock::from_bytes(&buf, 0).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::CrcMismatch,
                ..
            }
        ));
    }

    #[test]
    fn reject_truncated_block() {
        let buf = vec![0u8; 4];
        let err = FveBlock::from_bytes(&buf, 0).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }

    #[test]
    fn reject_tiny_metadata_size() {
        let mut buf = make_fve_block(2);
        // Set metadata_size to 4 (less than METADATA_HEADER_SIZE=48)
        buf[64..68].copy_from_slice(&4u32.to_le_bytes());
        let err = FveBlock::from_bytes(&buf, 0).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }

    #[test]
    fn datum_data_extracted() {
        let buf = make_fve_block(2);
        let block = FveBlock::from_bytes(&buf, 0).unwrap();
        // metadata_size=128, header=48, so datum_data = 128-48 = 80 bytes
        assert_eq!(block.datum_data().len(), 80);
    }
}
