use zerocopy::FromBytes;

use crate::metadata::entry::{DatumIter, VALUE_TYPE_EXTERNAL_KEY};
use crate::metadata::layout::FveDatasetHeader;
use crate::{BitLockerError, Result};

/// BEK dataset header size (48 bytes) — same as `FveDatasetHeader`.
const BEK_HEADER_SIZE: usize = size_of::<FveDatasetHeader>();

/// Parsed BEK (`BitLocker` Startup Key) file.
///
/// Layout: 48-byte `bitlocker_dataset_t` header followed by FVE datum entries.
/// The datum entries use the same format as on-disk FVE metadata.
#[derive(Debug)]
pub struct BekFile<'a> {
    guid: [u8; 16],
    key_data: &'a [u8],
}

impl<'a> BekFile<'a> {
    /// Parse a BEK file from raw bytes.
    ///
    /// Validates the header, then searches datum entries for the external key
    /// containing the unprotected key material.
    ///
    /// # Errors
    ///
    /// Returns `InvalidCredentialFormat` if the header is malformed or no
    /// external key datum is found.
    pub fn from_bytes(buf: &'a [u8]) -> Result<Self> {
        let (hdr, _) = FveDatasetHeader::read_from_prefix(buf).map_err(|_| {
            BitLockerError::InvalidCredentialFormat {
                detail: "BEK file too short for header (need 48 bytes)",
            }
        })?;

        let size = usize::try_from(hdr.size.get()).map_err(|_| {
            BitLockerError::InvalidCredentialFormat {
                detail: "BEK size exceeds the host address space",
            }
        })?;
        let header_size = usize::try_from(hdr.header_size.get()).map_err(|_| {
            BitLockerError::InvalidCredentialFormat {
                detail: "BEK header size exceeds the host address space",
            }
        })?;
        let copy_size = usize::try_from(hdr.size_copy.get()).map_err(|_| {
            BitLockerError::InvalidCredentialFormat {
                detail: "BEK copy size exceeds the host address space",
            }
        })?;

        if header_size != BEK_HEADER_SIZE {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "BEK header_size field is not 0x30",
            });
        }

        if size != copy_size {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "BEK size and copy_size fields do not match",
            });
        }

        if size < BEK_HEADER_SIZE || size > buf.len() {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "BEK declared size is invalid",
            });
        }

        let guid = hdr.volume_guid;

        // Datum entries start after the 48-byte header
        let datum_data = &buf[BEK_HEADER_SIZE..size];

        // Find the external key datum (value_type 9)
        let ext_key_datum = DatumIter::new(datum_data)
            .find(|d| d.value_type() == VALUE_TYPE_EXTERNAL_KEY)
            .ok_or(BitLockerError::InvalidCredentialFormat {
                detail: "BEK file contains no external key datum",
            })?;

        // External key payload: GUID(16) + timestamp(8) + nested data
        let payload = ext_key_datum.payload();
        if payload.len() < 28 {
            return Err(BitLockerError::InvalidCredentialFormat {
                detail: "BEK external key datum payload too short",
            });
        }

        // Nested data after GUID(16) + timestamp(8) contains a key datum
        // with its own datum header. Extract raw key bytes from it.
        let nested = &payload[24..];
        let key_data = extract_key_bytes(nested)?;

        Ok(Self { guid, key_data })
    }

    /// Volume identifier GUID from the BEK header.
    #[must_use]
    pub fn guid(&self) -> &[u8; 16] {
        &self.guid
    }

    /// Raw key bytes extracted from the external key datum.
    #[must_use]
    pub fn key_data(&self) -> &[u8] {
        self.key_data
    }
}

/// Extract raw key bytes from nested datum data inside the external key.
///
/// The nested data may contain a key datum (`value_type` 1) whose payload
/// holds an algorithm ID (4 bytes) followed by the key material.
/// If no nested datum is found, the raw bytes are returned as-is.
fn extract_key_bytes(nested: &[u8]) -> Result<&[u8]> {
    // Try to parse as a datum — if it has a valid header, extract key
    // from the key datum payload (skip 4-byte algorithm field)
    for datum in DatumIter::new(nested) {
        // value_type 1 = DATUMS_VALUE_KEY
        if datum.value_type() == 0x0001 {
            let payload = datum.payload();
            if payload.len() >= 4 {
                return Ok(&payload[4..]);
            }
        }
    }

    // Fallback: use nested bytes directly if no key datum wrapper
    if nested.is_empty() {
        return Err(BitLockerError::InvalidCredentialFormat {
            detail: "BEK external key contains no key data",
        });
    }
    Ok(nested)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal BEK file with a known key.
    fn make_bek_file(guid: &[u8; 16], key: &[u8]) -> Vec<u8> {
        // Key datum (value_type 1): header(8) + algorithm(4) + key
        let key_datum_size = 12
            + u16::try_from(key.len()).expect("the test key length fits in the 16-bit datum size");
        let mut key_datum = vec![0u8; usize::from(key_datum_size)];
        key_datum[0..2].copy_from_slice(&key_datum_size.to_le_bytes());
        key_datum[2..4].copy_from_slice(&0u16.to_le_bytes()); // entry_type: 0
        key_datum[4..6].copy_from_slice(&1u16.to_le_bytes()); // value_type: KEY
        // algorithm ID at payload[0..4] = 0
        key_datum[12..12 + key.len()].copy_from_slice(key);

        // External key datum (value_type 9):
        //   header(8) + ext_guid(16) + timestamp(8) + key_datum
        let ext_datum_size: u16 = 8 + 16 + 8 + key_datum_size;
        let mut ext_datum = vec![0u8; usize::from(ext_datum_size)];
        ext_datum[0..2].copy_from_slice(&ext_datum_size.to_le_bytes());
        ext_datum[2..4].copy_from_slice(&0u16.to_le_bytes()); // entry_type
        ext_datum[4..6].copy_from_slice(&VALUE_TYPE_EXTERNAL_KEY.to_le_bytes());
        // ext_guid at payload[0..16]
        ext_datum[8..24].copy_from_slice(guid);
        // timestamp at payload[16..24] = 0
        // nested key datum after 8+16+8=32
        ext_datum[32..].copy_from_slice(&key_datum);

        // BEK header (48 bytes) + ext_datum
        let total_size = u32::try_from(BEK_HEADER_SIZE)
            .expect("the fixed BEK header size fits in u32")
            + u32::from(ext_datum_size);
        let mut bek = vec![
            0u8;
            usize::try_from(total_size)
                .expect("the test BEK size fits in the host address space")
        ];
        bek[0..4].copy_from_slice(&total_size.to_le_bytes()); // size
        bek[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
        bek[8..12].copy_from_slice(&0x30u32.to_le_bytes()); // header_size
        bek[12..16].copy_from_slice(&total_size.to_le_bytes()); // copy_size
        bek[0x10..0x20].copy_from_slice(guid); // GUID
        // remaining header fields (counter, algorithm, timestamp) = 0
        bek[BEK_HEADER_SIZE..].copy_from_slice(&ext_datum);
        bek
    }

    #[test]
    fn parse_bek_extracts_guid() {
        let guid = [0xAA; 16];
        let key = [0x42u8; 32];
        let bek = make_bek_file(&guid, &key);
        let parsed = BekFile::from_bytes(&bek).unwrap();
        assert_eq!(parsed.guid(), &guid);
    }

    #[test]
    fn parse_bek_extracts_key() {
        let guid = [0xBB; 16];
        let key = [0x42u8; 32];
        let bek = make_bek_file(&guid, &key);
        let parsed = BekFile::from_bytes(&bek).unwrap();
        assert_eq!(parsed.key_data(), &key);
    }

    #[test]
    fn reject_truncated_bek() {
        let buf = [0u8; 16];
        let err = BekFile::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_wrong_header_size() {
        let guid = [0; 16];
        let mut bek = make_bek_file(&guid, &[0; 32]);
        // Corrupt header_size field
        bek[8..12].copy_from_slice(&64u32.to_le_bytes());
        let err = BekFile::from_bytes(&bek).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_size_mismatch() {
        let guid = [0; 16];
        let mut bek = make_bek_file(&guid, &[0; 32]);
        // Set copy_size to something different from size
        bek[12..16].copy_from_slice(&999u32.to_le_bytes());
        let err = BekFile::from_bytes(&bek).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_size_smaller_than_header() {
        let mut bek = vec![0u8; 64];
        bek[0..4].copy_from_slice(&32u32.to_le_bytes()); // size < 48
        bek[8..12].copy_from_slice(&0x30u32.to_le_bytes()); // header_size
        bek[12..16].copy_from_slice(&32u32.to_le_bytes()); // copy_size
        let err = BekFile::from_bytes(&bek).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn reject_declared_size_exceeds_file() {
        let guid = [0; 16];
        let mut bek = make_bek_file(&guid, &[0; 32]);
        let huge = (u32::try_from(bek.len()).expect("the test BEK length fits in u32") + 100)
            .to_le_bytes();
        bek[0..4].copy_from_slice(&huge);
        bek[12..16].copy_from_slice(&huge);
        let err = BekFile::from_bytes(&bek).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidCredentialFormat { .. }
        ));
    }

    #[test]
    fn parse_bek_with_256_bit_key() {
        let guid = [0xCC; 16];
        let key = [0x99u8; 32]; // 256-bit key
        let bek = make_bek_file(&guid, &key);
        let parsed = BekFile::from_bytes(&bek).unwrap();
        assert_eq!(parsed.key_data().len(), 32);
        assert_eq!(parsed.key_data(), &key);
    }
}
