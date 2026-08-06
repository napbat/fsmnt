//! Projected File System (`ProjFS`) reparse point parsing.
//!
//! `ProjFS` lets a user-mode provider populate a directory tree on demand.
//! A projected file that has not been fully hydrated carries a reparse
//! point; deleting a projected file leaves a tombstone reparse point.
//! Providers include VFS for Git / Scalar (large monorepos) and the
//! Windows Package Manager.
//!
//! Two tags are recognized:
//! - `IO_REPARSE_TAG_PROJFS` (0x9000001C) — an active projected placeholder.
//! - `IO_REPARSE_TAG_PROJFS_TOMBSTONE` (0xA0000022) — a deleted projected file.
//!
//! The reparse data buffer begins with a 16-byte `ProviderId` GUID
//! identifying the virtualization provider, followed by provider-specific
//! data whose format is private to that provider:
//! ```text
//! Offset  Size  Field
//! 0x00    16    ProviderId (GUID)
//! 0x10    var   Provider-specific data
//! ```
//!
//! Forensically, the materialized-vs-virtual state of projected files
//! reveals which files a user actually accessed, and tombstones record
//! deletions of virtual files.

use alloc::vec::Vec;

use super::reparse_point::{NtfsReparsePoint, reparse_tags};
use crate::error::{NtfsError, Result};
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::types::NtfsPosition;

use zerocopy::FromBytes;

/// Identifies which `ProjFS` tag a reparse point uses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProjFsTag {
    /// `IO_REPARSE_TAG_PROJFS` (0x9000001C) — an active projected placeholder.
    Placeholder,
    /// `IO_REPARSE_TAG_PROJFS_TOMBSTONE` (0xA0000022) — a deleted projected file.
    Tombstone,
}

impl ProjFsTag {
    /// Maps a raw reparse tag constant to a [`ProjFsTag`] variant, or
    /// `None` for any non-ProjFS tag.
    #[must_use]
    pub fn from_raw(raw_tag: u32) -> Option<Self> {
        match raw_tag {
            reparse_tags::PROJFS => Some(Self::Placeholder),
            reparse_tags::PROJFS_TOMBSTONE => Some(Self::Tombstone),
            _ => None,
        }
    }

    /// Returns the raw reparse tag value for this variant.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Placeholder => reparse_tags::PROJFS,
            Self::Tombstone => reparse_tags::PROJFS_TOMBSTONE,
        }
    }
}

/// A parsed Projected File System reparse point.
///
/// Obtain via [`NtfsReparsePoint::as_projfs`].
#[derive(Clone, Debug)]
pub struct NtfsProjFsReparsePoint {
    tag: ProjFsTag,
    provider_id: NtfsGuid,
    provider_data: Vec<u8>,
}

impl NtfsProjFsReparsePoint {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        let tag =
            ProjFsTag::from_raw(reparse_point.tag()).ok_or(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::PROJFS,
                actual: reparse_point.tag(),
            })?;

        let data = reparse_point.data();
        if data.len() < GUID_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "ProjFS reparse data too small for the provider GUID",
            });
        }

        let provider_id = NtfsGuid::read_from_bytes(&data[..GUID_SIZE]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to parse ProjFS provider GUID",
            }
        })?;

        Ok(Self {
            tag,
            provider_id,
            provider_data: data[GUID_SIZE..].to_vec(),
        })
    }

    /// Returns which `ProjFS` tag this reparse point uses.
    #[must_use]
    pub fn tag(&self) -> ProjFsTag {
        self.tag
    }

    /// Returns `true` if this is a `ProjFS` tombstone (a deleted projected file).
    #[must_use]
    pub fn is_tombstone(&self) -> bool {
        self.tag == ProjFsTag::Tombstone
    }

    /// Returns the GUID identifying the virtualization provider.
    #[must_use]
    pub fn provider_id(&self) -> &NtfsGuid {
        &self.provider_id
    }

    /// Returns the provider-specific data following the GUID.
    ///
    /// The format is private to each provider; the bytes are exposed
    /// verbatim for forensic inspection.
    #[must_use]
    pub fn provider_data(&self) -> &[u8] {
        &self.provider_data
    }
}

impl NtfsReparsePoint {
    /// Attempts to parse this reparse point as a `ProjFS` reparse point.
    ///
    /// Succeeds for both `IO_REPARSE_TAG_PROJFS` and
    /// `IO_REPARSE_TAG_PROJFS_TOMBSTONE`; returns an error for any other
    /// tag, or if the data is too small to hold the provider GUID.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-ProjFS tag or a payload too short to contain
    /// the provider identifier.
    pub fn as_projfs(&self) -> Result<NtfsProjFsReparsePoint> {
        NtfsProjFsReparsePoint::from_reparse_point(self)
    }

    /// Returns `true` if this is any ProjFS-family reparse point
    /// (placeholder or tombstone).
    #[must_use]
    pub fn is_projfs(&self) -> bool {
        matches!(
            self.tag(),
            reparse_tags::PROJFS | reparse_tags::PROJFS_TOMBSTONE
        )
    }

    /// Returns `true` if this is a `ProjFS` tombstone reparse point.
    #[must_use]
    pub fn is_projfs_tombstone(&self) -> bool {
        self.tag() == reparse_tags::PROJFS_TOMBSTONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds raw reparse point bytes (8-byte header + data) for `tag`.
    fn make_reparse_bytes(tag: u32, reparse_data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tag.to_le_bytes());
        buf.extend_from_slice(
            &u16::try_from(reparse_data.len())
                .expect("test value fits u16")
                .to_le_bytes(),
        );
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(reparse_data);
        buf
    }

    /// A 16-byte provider GUID followed by `extra` provider data.
    fn projfs_payload(extra: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            0x0B, 0x77, 0xC8, 0x67, // data1 (LE)
            0xF1, 0x44, // data2 (LE)
            0x0A, 0x41, // data3 (LE)
            0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE, // data4
        ]);
        buf.extend_from_slice(extra);
        buf
    }

    #[test]
    fn projfs_tag_from_raw_round_trips() {
        for tag in [ProjFsTag::Placeholder, ProjFsTag::Tombstone] {
            assert_eq!(ProjFsTag::from_raw(tag.as_u32()), Some(tag));
        }
        assert!(ProjFsTag::from_raw(reparse_tags::SYMLINK).is_none());
    }

    #[test]
    fn parses_placeholder_with_provider_data() {
        let raw = make_reparse_bytes(reparse_tags::PROJFS, &projfs_payload(&[0xDE, 0xAD]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");

        let projfs = rp.as_projfs().expect("valid ProjFS parse");
        assert_eq!(projfs.tag(), ProjFsTag::Placeholder);
        assert!(!projfs.is_tombstone());
        assert_eq!(projfs.provider_id().data1(), 0x67C8_770B);
        assert_eq!(projfs.provider_data(), &[0xDE, 0xAD]);
        assert!(rp.is_projfs());
        assert!(!rp.is_projfs_tombstone());
    }

    #[test]
    fn parses_tombstone() {
        let raw = make_reparse_bytes(reparse_tags::PROJFS_TOMBSTONE, &projfs_payload(&[]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");

        let projfs = rp.as_projfs().expect("valid ProjFS parse");
        assert_eq!(projfs.tag(), ProjFsTag::Tombstone);
        assert!(projfs.is_tombstone());
        assert!(projfs.provider_data().is_empty());
        assert!(rp.is_projfs());
        assert!(rp.is_projfs_tombstone());
    }

    #[test]
    fn rejects_non_projfs_tag() {
        let raw = make_reparse_bytes(reparse_tags::SYMLINK, &projfs_payload(&[]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.as_projfs().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { .. }),
            "expected ReparseTagMismatch, got {err:?}",
        );
        assert!(!rp.is_projfs());
    }

    #[test]
    fn rejects_data_too_small_for_guid() {
        let raw = make_reparse_bytes(reparse_tags::PROJFS, &[0u8; 8]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_projfs().is_err());
    }

    #[test]
    fn placeholder_with_exactly_guid_and_no_provider_data() {
        let raw = make_reparse_bytes(reparse_tags::PROJFS, &projfs_payload(&[]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let projfs = rp.as_projfs().expect("valid ProjFS parse");
        assert!(projfs.provider_data().is_empty());
    }
}
