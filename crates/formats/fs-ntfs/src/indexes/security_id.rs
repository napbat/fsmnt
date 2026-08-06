use core::fmt;

use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, U64, Unaligned};

use crate::error::{NtfsError, Result};
use crate::indexes::{NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryType};
use crate::types::NtfsPosition;

use super::NtfsIndexEntryKey;

/// On-disk layout for a $SII key (4 bytes).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct SiiKeyLayout {
    security_id: U32<LittleEndian>,
}

/// On-disk layout for $SII data (20 bytes).
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct SiiDataLayout {
    hash: U32<LittleEndian>,
    security_id: U32<LittleEndian>,
    sds_offset: U64<LittleEndian>,
    sds_size: U32<LittleEndian>,
}

/// Defines the [`NtfsIndexEntryType`] for $SII (Security ID Index) entries
/// in the `$Secure` system file.
#[derive(Clone, Copy, Debug)]
pub struct NtfsSecurityIdIndex;

impl NtfsIndexEntryType for NtfsSecurityIdIndex {
    type KeyType = NtfsSecurityIdKey;
}

impl NtfsIndexEntryHasData for NtfsSecurityIdIndex {
    type DataType = NtfsSecurityIdData;
}

/// The key type for $SII index entries: a u32 security ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsSecurityIdKey {
    security_id: u32,
}

impl NtfsSecurityIdKey {
    /// Returns the security ID.
    pub fn security_id(&self) -> u32 {
        self.security_id
    }
}

impl NtfsIndexEntryKey for NtfsSecurityIdKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let raw = SiiKeyLayout::read_from_prefix(slice)
            .map_err(|_| NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "$SII key too short (expected 4 bytes)",
            })?
            .0;
        Ok(Self {
            security_id: raw.security_id.get(),
        })
    }
}

impl fmt::Display for NtfsSecurityIdKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityId({})", self.security_id)
    }
}

/// The data type for $SII index entries: hash, security_id, SDS offset, and SDS size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsSecurityIdData {
    hash: u32,
    security_id: u32,
    sds_offset: u64,
    sds_size: u32,
}

impl NtfsSecurityIdData {
    /// Returns the hash of the security descriptor.
    pub fn hash(&self) -> u32 {
        self.hash
    }

    /// Returns the security ID (matches the key).
    pub fn security_id(&self) -> u32 {
        self.security_id
    }

    /// Returns the byte offset into the $SDS stream.
    pub fn sds_offset(&self) -> u64 {
        self.sds_offset
    }

    /// Returns the size of the entry in the $SDS stream (header + descriptor).
    pub fn sds_size(&self) -> u32 {
        self.sds_size
    }
}

impl NtfsIndexEntryData for NtfsSecurityIdData {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        let raw = SiiDataLayout::read_from_prefix(slice)
            .map_err(|_| NtfsError::InvalidSecurityDescriptor {
                position,
                reason: "$SII data too short (expected 20 bytes)",
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

impl fmt::Display for NtfsSecurityIdData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SII(hash={:#x}, id={}, offset={}, size={})",
            self.hash, self.security_id, self.sds_offset, self.sds_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn test_key_valid() {
        // $SII key layout: security_id (u32 LE).
        let bytes = [0x05, 0x00, 0x00, 0x00];
        let key = NtfsSecurityIdKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.security_id(), 5);
    }

    #[test]
    fn test_key_endianness() {
        // security_id at offset 0 (u32 LE) = 0x0D0C0B0A.
        let bytes = [0x0A, 0x0B, 0x0C, 0x0D];
        let key = NtfsSecurityIdKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(key.security_id(), 0x0D0C_0B0A);
    }

    #[test]
    fn test_key_truncated() {
        let bytes = [0x01, 0x02, 0x03];
        let result = NtfsSecurityIdKey::key_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_key_display() {
        let bytes = [0x07, 0x00, 0x00, 0x00];
        let key = NtfsSecurityIdKey::key_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(format!("{key}"), "SecurityId(7)");
    }

    #[test]
    fn test_data_valid() {
        // $SII data layout: hash (u32), security_id (u32), sds_offset (u64), sds_size (u32).
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sds_offset = 0x1000
            0x80, 0x00, 0x00, 0x00, // sds_size = 128
        ];
        let data = NtfsSecurityIdData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
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
        let data = NtfsSecurityIdData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(data.hash(), 0x0403_0201);
        assert_eq!(data.security_id(), 0x0D0C_0B0A);
        assert_eq!(data.sds_offset(), 0x8070_6050_4030_2010);
        assert_eq!(data.sds_size(), 0xDDCC_BBAA);
    }

    #[test]
    fn test_data_truncated() {
        let bytes = [0u8; 19];
        let result = NtfsSecurityIdData::data_from_slice(&bytes, NtfsPosition::none());
        assert!(result.is_err());
    }

    #[test]
    fn test_data_display() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, // hash = 0x12345678
            0x05, 0x00, 0x00, 0x00, // security_id = 5
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // sds_offset = 0x1000
            0x80, 0x00, 0x00, 0x00, // sds_size = 128
        ];
        let data = NtfsSecurityIdData::data_from_slice(&bytes, NtfsPosition::none()).unwrap();
        assert_eq!(
            format!("{data}"),
            "SII(hash=0x12345678, id=5, offset=4096, size=128)"
        );
    }
}
