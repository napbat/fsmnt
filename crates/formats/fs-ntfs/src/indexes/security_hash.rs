use core::fmt;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, U64, Unaligned};

use crate::error::{NtfsError, Result};
use crate::indexes::{NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryType};
use crate::types::NtfsPosition;

use super::NtfsIndexEntryKey;

/// On-disk layout for a $SDH key (8 bytes).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct SdhKeyLayout {
    hash: U32<LittleEndian>,
    security_id: U32<LittleEndian>,
}

/// On-disk layout for $SDH data (20 bytes).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct SdhDataLayout {
    hash: U32<LittleEndian>,
    security_id: U32<LittleEndian>,
    sds_offset: U64<LittleEndian>,
    sds_size: U32<LittleEndian>,
}

/// Defines the [`NtfsIndexEntryType`] for $SDH (Security Descriptor Hash)
/// entries in the `$Secure` system file.
#[derive(Clone, Copy, Debug)]
pub struct NtfsSecurityHashIndex;

impl NtfsIndexEntryType for NtfsSecurityHashIndex {
    type KeyType = NtfsSecurityHashKey;
}

impl NtfsIndexEntryHasData for NtfsSecurityHashIndex {
    type DataType = NtfsSecurityHashData;
}

/// The key type for $SDH index entries: a composite (hash, `security_id`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsSecurityHashKey {
    hash: u32,
    security_id: u32,
}

impl NtfsSecurityHashKey {
    /// Returns the security descriptor hash.
    #[must_use]
    pub fn hash(&self) -> u32 {
        self.hash
    }

    /// Returns the security ID.
    #[must_use]
    pub fn security_id(&self) -> u32 {
        self.security_id
    }
}

impl NtfsIndexEntryKey for NtfsSecurityHashKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let raw = SdhKeyLayout::read_from_prefix(slice)
            .map_err(|_| NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "$SDH key too short (expected 8 bytes)",
            })?
            .0;
        Ok(Self {
            hash: raw.hash.get(),
            security_id: raw.security_id.get(),
        })
    }
}

impl fmt::Display for NtfsSecurityHashKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SDH(hash={:#x}, id={})", self.hash, self.security_id)
    }
}

/// The data type for $SDH index entries: hash, `security_id`, SDS offset, and
/// SDS size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsSecurityHashData {
    hash: u32,
    security_id: u32,
    sds_offset: u64,
    sds_size: u32,
}

impl NtfsSecurityHashData {
    /// Returns the hash of the security descriptor.
    #[must_use]
    pub fn hash(&self) -> u32 {
        self.hash
    }

    /// Returns the security ID.
    #[must_use]
    pub fn security_id(&self) -> u32 {
        self.security_id
    }

    /// Returns the byte offset into the $SDS stream.
    #[must_use]
    pub fn sds_offset(&self) -> u64 {
        self.sds_offset
    }

    /// Returns the size of the entry in the $SDS stream (header + descriptor).
    #[must_use]
    pub fn sds_size(&self) -> u32 {
        self.sds_size
    }
}

impl NtfsIndexEntryData for NtfsSecurityHashData {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let raw = SdhDataLayout::read_from_prefix(slice)
            .map_err(|_| NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "$SDH data too short (expected 20 bytes)",
            })?
            .0;
        Ok(Self {
            hash: raw.hash.get(),
            security_id: raw.security_id.get(),
            sds_offset: raw.sds_offset.get(),
            sds_size: raw.sds_size.get(),
        })
    }
}

impl fmt::Display for NtfsSecurityHashData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SDH(hash={:#x}, id={}, offset={}, size={})",
            self.hash, self.security_id, self.sds_offset, self.sds_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_valid() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
        ];
        let key = NtfsSecurityHashKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.hash(), 0x1234_5678);
        assert_eq!(key.security_id(), 5);
    }

    #[test]
    fn test_key_endianness() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, // hash = 0x04030201 (LE)
            0x0A, 0x0B, 0x0C, 0x0D, // security_id = 0x0D0C0B0A (LE)
        ];
        let key = NtfsSecurityHashKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.hash(), 0x0403_0201);
        assert_eq!(key.security_id(), 0x0D0C_0B0A);
    }

    #[test]
    fn test_key_truncated() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let result = NtfsSecurityHashKey::key_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_key_extra_bytes() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash
            0x05, 0x00, 0x00, 0x00, // security_id
            0xFF, 0xFF, // extra
        ];
        let key = NtfsSecurityHashKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.hash(), 0x1234_5678);
        assert_eq!(key.security_id(), 5);
    }

    #[test]
    fn test_key_display() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
        ];
        let key = NtfsSecurityHashKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(format!("{key}"), "SDH(hash=0x12345678, id=5)");
    }

    #[test]
    fn test_data_valid() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sds_offset = 0x1000
            0x80, 0x00, 0x00, 0x00, // sds_size = 128
        ];
        let data = NtfsSecurityHashData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(data.hash(), 0x1234_5678);
        assert_eq!(data.security_id(), 5);
        assert_eq!(data.sds_offset(), 0x1000);
        assert_eq!(data.sds_size(), 128);
    }

    #[test]
    fn test_data_endianness() {
        let bytes = [
            0x01, 0x02, 0x03, 0x04, // hash = 0x04030201
            0x0A, 0x0B, 0x0C, 0x0D, // security_id = 0x0D0C0B0A
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, // sds_offset
            0xAA, 0xBB, 0xCC, 0xDD, // sds_size
        ];
        let data = NtfsSecurityHashData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(data.hash(), 0x0403_0201);
        assert_eq!(data.security_id(), 0x0D0C_0B0A);
        assert_eq!(data.sds_offset(), 0x8070_6050_4030_2010);
        assert_eq!(data.sds_size(), 0xDDCC_BBAA);
    }

    #[test]
    fn test_data_truncated() {
        let bytes = [0u8; 19];
        let result = NtfsSecurityHashData::data_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_data_extra_bytes() {
        let mut bytes = [0u8; 24];
        bytes[16] = 0x80; // sds_size = 128
        bytes[22] = 0xFF; // extra
        let data = NtfsSecurityHashData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(data.sds_size(), 128);
    }

    #[test]
    fn test_data_display() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sds_offset = 0x1000
            0x80, 0x00, 0x00, 0x00, // sds_size = 128
        ];
        let data = NtfsSecurityHashData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(
            format!("{data}"),
            "SDH(hash=0x12345678, id=5, offset=4096, size=128)"
        );
    }
}
