use zerocopy::FromBytes;

use super::layout::DatumHeaderRaw;
use crate::{BitLockerError, MetadataFailure, Result};

/// Minimum size of a datum header (8 bytes).
pub const DATUM_HEADER_SIZE: usize = size_of::<DatumHeaderRaw>();

/// Entry type constants.
pub const ENTRY_TYPE_VMK: u16 = 0x0002;
pub const ENTRY_TYPE_FVEK: u16 = 0x0003;

/// Value type constants.
pub const VALUE_TYPE_STRETCH_KEY: u16 = 0x0003;
pub const VALUE_TYPE_AES_CCM: u16 = 0x0005;
pub const VALUE_TYPE_VMK: u16 = 0x0008;
pub const VALUE_TYPE_EXTERNAL_KEY: u16 = 0x0009;

/// Parsed datum entry: a typed header backed by the full datum byte slice.
#[derive(Debug, Clone, Copy)]
pub struct DatumHeader<'a> {
    header: DatumHeaderRaw,
    data: &'a [u8],
}

impl<'a> DatumHeader<'a> {
    /// Parse a datum header from at least 8 bytes.
    ///
    /// The returned header borrows the entire datum (header + payload) based
    /// on the `datum_size` field.
    ///
    /// # Errors
    ///
    /// Returns `InvalidMetadata` if the buffer is shorter than 8 bytes
    /// or the declared size exceeds available data.
    pub fn from_bytes(buf: &'a [u8]) -> Result<Self> {
        let (header, _) =
            DatumHeaderRaw::read_from_prefix(buf).map_err(|_| BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: DATUM_HEADER_SIZE as u64,
                    available: buf.len() as u64,
                },
            })?;

        let size = header.size.get() as usize;
        if size < DATUM_HEADER_SIZE || size > buf.len() {
            return Err(BitLockerError::InvalidMetadata {
                block_index: 0,
                reason: MetadataFailure::SizeBoundsExceeded {
                    declared: size as u64,
                    available: buf.len() as u64,
                },
            });
        }

        Ok(Self {
            header,
            data: &buf[..size],
        })
    }

    #[must_use]
    pub fn size(&self) -> u16 {
        self.header.size.get()
    }

    #[must_use]
    pub fn entry_type(&self) -> u16 {
        self.header.entry_type.get()
    }

    #[must_use]
    pub fn value_type(&self) -> u16 {
        self.header.value_type.get()
    }

    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[DATUM_HEADER_SIZE..]
    }

    #[must_use]
    pub fn raw_data(&self) -> &'a [u8] {
        self.data
    }
}

/// Iterator over consecutive datum entries in a byte slice.
pub struct DatumIter<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> DatumIter<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for DatumIter<'a> {
    type Item = DatumHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let remaining = &self.data[self.offset..];
        let (raw, _) = DatumHeaderRaw::read_from_prefix(remaining).ok()?;
        let size = raw.size.get() as usize;
        if size < DATUM_HEADER_SIZE || size > remaining.len() {
            return None;
        }

        let header = DatumHeader {
            header: raw,
            data: &remaining[..size],
        };
        self.offset += size;
        Some(header)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests")]
mod tests {
    use super::*;

    fn make_datum(entry_type: u16, value_type: u16, size: u16) -> Vec<u8> {
        let mut buf = vec![0u8; size as usize];
        buf[0..2].copy_from_slice(&size.to_le_bytes());
        buf[2..4].copy_from_slice(&entry_type.to_le_bytes());
        buf[4..6].copy_from_slice(&value_type.to_le_bytes());
        buf
    }

    #[test]
    fn parse_datum_header() {
        let buf = make_datum(0x0002, 0x0008, 64);
        let entry = DatumHeader::from_bytes(&buf).unwrap();
        assert_eq!(entry.entry_type(), 0x0002);
        assert_eq!(entry.value_type(), 0x0008);
        assert_eq!(entry.size(), 64);
        assert_eq!(entry.payload().len(), 56);
    }

    #[test]
    fn iterate_datum_entries() {
        let mut buf = vec![0u8; 64];
        // Entry 1: 32 bytes, type=VMK
        buf[0..2].copy_from_slice(&32u16.to_le_bytes());
        buf[2..4].copy_from_slice(&0x0002u16.to_le_bytes());
        // Entry 2: 32 bytes, type=FVEK
        buf[32..34].copy_from_slice(&32u16.to_le_bytes());
        buf[34..36].copy_from_slice(&0x0003u16.to_le_bytes());

        let entries: Vec<_> = DatumIter::new(&buf).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].entry_type(), 0x0002);
        assert_eq!(entries[1].entry_type(), 0x0003);
    }

    #[test]
    fn reject_truncated_datum() {
        let buf = vec![0u8; 4];
        let err = DatumHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }

    #[test]
    fn reject_datum_size_too_large() {
        let mut buf = vec![0u8; 16];
        buf[0..2].copy_from_slice(&64u16.to_le_bytes()); // claims 64 bytes but only 16 available
        let err = DatumHeader::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            BitLockerError::InvalidMetadata {
                reason: MetadataFailure::SizeBoundsExceeded { .. },
                ..
            }
        ));
    }

    #[test]
    fn iterator_stops_at_end() {
        let buf = make_datum(0x0002, 0x0008, 16);
        let entries: Vec<_> = DatumIter::new(&buf).collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn iterator_stops_on_zero_size() {
        let buf = vec![0u8; 16]; // size field = 0
        let entries: Vec<_> = DatumIter::new(&buf).collect();
        assert_eq!(entries.len(), 0);
    }
}
