//! EFS (Encrypting File System) metadata parsing.
//!
//! EFS attaches per-file encryption metadata to an encrypted object as a
//! `$LOGGED_UTILITY_STREAM` (0x100) attribute named `$EFS`. The metadata
//! holds the file's File Encryption Key (FEK), individually wrapped for
//! each authorized user (the Data Decryption Field, DDF) and each Data
//! Recovery Agent (the Data Recovery Field, DRF).
//!
//! Two on-disk formats exist:
//! - **Version 1** (EFS versions 1-3, Windows 2000/XP/2003) — a flat
//!   layout of key lists; see [`EfsMetadataV1`].
//! - **Version 2** (EFS versions 4-5, Windows Vista and later) — a tree
//!   of tagged EFSX datum structures; see [`EfsMetadataV2`].
//!
//! The wrapped FEK blobs are RSA/AES ciphertext. This module exposes them
//! verbatim for offline key-recovery tooling but does not decrypt them —
//! decryption requires a private key or DRA key recovered out of band.
//!
//! Reference: MS-EFSR §2.2.2 (`docs/ms-efsr/01-metadata-v1.md`,
//! `docs/ms-efsr/02-metadata-v2.md`).

mod v1;
mod v2;

pub use v1::*;
pub use v2::*;

use zerocopy::FromBytes;

use crate::error::{NtfsError, Result};
use crate::guid::NtfsGuid;
use crate::types::NtfsPosition;

/// Maximum EFSRPC metadata size (256 KiB).
///
/// MS-EFSR product behavior caps EFSRPC metadata at 262144 bytes.
const MAX_EFS_METADATA_SIZE: usize = 262_144;

/// Offset of the `EFS_Version` field, identical in the V1 and V2 headers.
const EFS_VERSION_OFFSET: usize = 0x08;

/// Highest `EFS_Version` value that still uses the flat V1 metadata layout.
///
/// MS-EFSR §2.2.2.1: versions 1-3 use Version 1 metadata; version 4 (and
/// the version-5 DPAPI-NG variant) use Version 2 metadata (§2.2.2.2).
const MAX_V1_EFS_VERSION: u32 = 3;

/// Symmetric algorithm used to encrypt file content with the FEK.
///
/// Values are Windows `ALG_ID` constants (MS-EFSR §2.2.13).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EfsAlgorithm {
    /// `CALG_DES` (0x6601).
    Des,
    /// `CALG_3DES` (0x6603).
    TripleDes,
    /// `CALG_DESX` (0x6604).
    Desx,
    /// `CALG_AES_256` (0x6610).
    Aes256,
    /// An `ALG_ID` not recognized by this parser.
    Unknown(u32),
}

impl EfsAlgorithm {
    /// Maps a raw 32-bit `ALG_ID` to a known algorithm.
    #[must_use]
    pub fn from_alg_id(alg_id: u32) -> Self {
        match alg_id {
            0x6601 => Self::Des,
            0x6603 => Self::TripleDes,
            0x6604 => Self::Desx,
            0x6610 => Self::Aes256,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed `$EFS` metadata — either a Version 1 or a Version 2 structure.
#[derive(Clone, Debug)]
pub enum NtfsEfsMetadata {
    /// Flat Version 1 metadata (EFS versions 1-3).
    V1(EfsMetadataV1),
    /// EFSX-datum Version 2 metadata (EFS versions 4-5).
    V2(EfsMetadataV2),
}

impl NtfsEfsMetadata {
    /// Parses `$EFS` metadata from the raw bytes of a `$LOGGED_UTILITY_STREAM`.
    ///
    /// Dispatches on the `EFS_Version` field at offset 0x08, which occupies
    /// the same position in both header formats (MS-EFSR §2.2.2.1/§2.2.2.2).
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata exceeds the EFSRPC size limit, is
    /// truncated, declares an unsupported version, or contains invalid offsets.
    pub fn parse(data: &[u8], position: NtfsPosition) -> Result<Self> {
        if data.len() > MAX_EFS_METADATA_SIZE {
            return Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "metadata exceeds the 256 KiB EFSRPC limit",
            });
        }

        let efs_version = read_u32(data, EFS_VERSION_OFFSET, position)?;
        match efs_version {
            0 => Err(NtfsError::InvalidEfsMetadata {
                position,
                reason: "EFS_Version is zero",
            }),
            1..=MAX_V1_EFS_VERSION => {
                Ok(Self::V1(EfsMetadataV1::parse(data, position, efs_version)?))
            }
            _ => Ok(Self::V2(EfsMetadataV2::parse(data, position, efs_version)?)),
        }
    }

    /// Returns the `EFS_Version` recorded in the metadata header.
    #[must_use]
    pub fn efs_version(&self) -> u32 {
        match self {
            Self::V1(m) => m.efs_version(),
            Self::V2(m) => m.efs_version(),
        }
    }

    /// Returns the `EFS_ID` GUID of the machine that created the metadata.
    #[must_use]
    pub fn efs_id(&self) -> &NtfsGuid {
        match self {
            Self::V1(m) => m.efs_id(),
            Self::V2(m) => m.efs_id(),
        }
    }
}

/// Reads a little-endian `u32` at `offset`, failing if it runs past `data`.
fn read_u32(data: &[u8], offset: usize, position: NtfsPosition) -> Result<u32> {
    let bytes = read_slice(data, offset, 4, position)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Reads a little-endian `u16` at `offset`, failing if it runs past `data`.
fn read_u16(data: &[u8], offset: usize, position: NtfsPosition) -> Result<u16> {
    let bytes = read_slice(data, offset, 2, position)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Borrows `len` bytes at `offset`, failing if the range runs past `data`.
fn read_slice(data: &[u8], offset: usize, len: usize, position: NtfsPosition) -> Result<&[u8]> {
    let end = offset
        .checked_add(len)
        .ok_or(NtfsError::InvalidEfsMetadata {
            position,
            reason: "field offset arithmetic overflowed",
        })?;
    data.get(offset..end).ok_or(NtfsError::InvalidEfsMetadata {
        position,
        reason: "field extends past the metadata buffer",
    })
}

/// Reads a 16-byte GUID at `offset`.
fn read_guid(data: &[u8], offset: usize, position: NtfsPosition) -> Result<NtfsGuid> {
    let bytes = read_slice(data, offset, 16, position)?;
    NtfsGuid::read_from_bytes(bytes).map_err(|_| NtfsError::InvalidEfsMetadata {
        position,
        reason: "GUID field could not be read",
    })
}

/// Decodes a NUL-terminated UTF-16LE string from the start of `data`.
///
/// Used for the certificate container/provider/display name hints
/// (MS-EFSR §2.2.2.1.4).
fn decode_utf16le(data: &[u8]) -> alloc::string::String {
    let mut units = alloc::vec::Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let unit = u16::from_le_bytes([data[i], data[i + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
    }
    alloc::string::String::from_utf16_lossy(&units)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal 84-byte V1 header with no key list entries.
    fn v1_header(efs_version: u32) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec![0u8; 0x54 + 4];
        buf[0x08..0x0C].copy_from_slice(&efs_version.to_le_bytes());
        // DDF key list at 0x54 with a zero entry count.
        buf[0x40..0x44].copy_from_slice(&0x54u32.to_le_bytes());
        buf
    }

    #[test]
    fn algorithm_id_mapping() {
        assert_eq!(EfsAlgorithm::from_alg_id(0x6601), EfsAlgorithm::Des);
        assert_eq!(EfsAlgorithm::from_alg_id(0x6603), EfsAlgorithm::TripleDes);
        assert_eq!(EfsAlgorithm::from_alg_id(0x6604), EfsAlgorithm::Desx);
        assert_eq!(EfsAlgorithm::from_alg_id(0x6610), EfsAlgorithm::Aes256);
        assert_eq!(
            EfsAlgorithm::from_alg_id(0x1234),
            EfsAlgorithm::Unknown(0x1234),
        );
    }

    #[test]
    fn dispatches_v1_for_versions_1_to_3() {
        for version in 1u32..=3 {
            let buf = v1_header(version);
            let meta =
                NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).expect("V1 header should parse");
            assert!(matches!(meta, NtfsEfsMetadata::V1(_)));
            assert_eq!(meta.efs_version(), version);
        }
    }

    #[test]
    fn rejects_zero_version() {
        let buf = v1_header(0);
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn rejects_buffer_too_short_for_version_field() {
        let buf = [0u8; 4];
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn rejects_oversized_metadata() {
        let buf = alloc::vec![0u8; MAX_EFS_METADATA_SIZE + 1];
        assert!(NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).is_err());
    }

    #[test]
    fn read_helpers_bounds_check() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(
            read_u32(&data, 0, NtfsPosition::none()).unwrap(),
            0x0403_0201
        );
        assert!(read_u32(&data, 1, NtfsPosition::none()).is_err());
        assert_eq!(read_u16(&data, 2, NtfsPosition::none()).unwrap(), 0x0403);
        assert!(read_u16(&data, 3, NtfsPosition::none()).is_err());
    }

    #[test]
    fn decode_utf16le_stops_at_nul() {
        // "Hi" followed by a NUL terminator and trailing garbage.
        let data = [b'H', 0, b'i', 0, 0, 0, b'X', 0];
        assert_eq!(decode_utf16le(&data), "Hi");
    }

    #[test]
    fn decode_utf16le_handles_unterminated() {
        let data = [b'A', 0, b'B', 0];
        assert_eq!(decode_utf16le(&data), "AB");
    }

    #[test]
    fn decode_utf16le_stops_one_short_of_odd_tail() {
        // Three full code units followed by a single trailing byte. The
        // `i + 1 < data.len()` guard must read exactly three units and stop
        // before the lone trailing byte. An `i + 1` -> `i * 1` change or a
        // `<` -> `<=` change would either drop the third unit or read past
        // the end.
        let data = [b'A', 0, b'B', 0, b'C', 0, 0x7A];
        assert_eq!(decode_utf16le(&data), "ABC");
    }

    #[test]
    fn parses_v1_at_exactly_max_size() {
        // A buffer of exactly MAX_EFS_METADATA_SIZE must be accepted; this
        // anchors the `>` boundary at line 93 (a `>=` or `==` flip rejects).
        let mut buf = v1_header(1);
        buf.resize(MAX_EFS_METADATA_SIZE, 0);
        let meta = NtfsEfsMetadata::parse(&buf, NtfsPosition::none())
            .expect("buffer of exactly the max size should parse");
        assert_eq!(meta.efs_version(), 1);
    }

    #[test]
    fn zero_version_arm_rejected() {
        // The match arm `0 => Err(...)` at line 102; deleting it would fall
        // through to a different arm. A header that is otherwise valid but
        // has EFS_Version 0 must be rejected with InvalidEfsMetadata.
        let buf = v1_header(0);
        let err = NtfsEfsMetadata::parse(&buf, NtfsPosition::none()).unwrap_err();
        let NtfsError::InvalidEfsMetadata { reason, .. } = err else {
            panic!("expected InvalidEfsMetadata for version 0, got {err:?}");
        };
        assert_eq!(reason, "EFS_Version is zero");
    }
}
