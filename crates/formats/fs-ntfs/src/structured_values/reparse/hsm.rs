//! Hierarchical Storage Management (HSM) reparse point parsing.
//!
//! HSM reparse points mark files whose content has been migrated from
//! local NTFS to remote or archival storage (tape, cloud, tiered
//! storage). The file remains visible in the directory tree, but its
//! data must be recalled from the remote store before it can be read —
//! so an HSM-migrated file cannot be recovered from a disk image alone.
//!
//! Two tags are recognized:
//! - `IO_REPARSE_TAG_HSM` (0xC0000004) — HSM v1 (Windows 2000 Remote Storage).
//! - `IO_REPARSE_TAG_HSM2` (0x80000006) — HSM v2 (third-party HSM providers).
//!
//! HSM v1 reparse data has a documented 32-byte header (Windows 2000
//! Resource Kit):
//! ```text
//! Offset  Size  Field
//! 0x00    4     Version
//! 0x04    4     Reserved
//! 0x08    16    DataStreamId (GUID)
//! 0x18    8     DataStreamOffset
//! 0x20    var   Provider-specific data
//! ```
//! HSM v2 data is provider-dependent and is exposed verbatim.
//!
//! A file's migration state is also reflected in its file-attribute
//! flags ([`NtfsFileAttributeFlags`]): `OFFLINE`, `RECALL_ON_OPEN`, and
//! `RECALL_ON_DATA_ACCESS`. [`HsmMigrationState::from_attributes`]
//! summarises those flags.

use alloc::vec::Vec;

use super::reparse_point::{NtfsReparsePoint, reparse_tags};
use crate::error::{NtfsError, Result};
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::structured_values::NtfsFileAttributeFlags;
use crate::types::NtfsPosition;

use zerocopy::FromBytes;

/// Size of the documented HSM v1 reparse data header.
const HSM_V1_HEADER_SIZE: usize = 0x20;
/// Offset of the `DataStreamOffset` field within the HSM v1 header.
const DATA_STREAM_OFFSET_FIELD: usize = 0x18;

/// Identifies which HSM tag a reparse point uses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HsmTag {
    /// `IO_REPARSE_TAG_HSM` (0xC0000004) — HSM v1, Windows 2000 Remote Storage.
    V1,
    /// `IO_REPARSE_TAG_HSM2` (0x80000006) — HSM v2, third-party providers.
    V2,
}

impl HsmTag {
    /// Maps a raw reparse tag constant to an [`HsmTag`] variant, or
    /// `None` for any non-HSM tag.
    #[must_use]
    pub fn from_raw(raw_tag: u32) -> Option<Self> {
        match raw_tag {
            reparse_tags::HSM => Some(Self::V1),
            reparse_tags::HSM2 => Some(Self::V2),
            _ => None,
        }
    }

    /// Returns the raw reparse tag value for this variant.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self {
            Self::V1 => reparse_tags::HSM,
            Self::V2 => reparse_tags::HSM2,
        }
    }
}

/// The documented HSM v1 reparse data header (Windows 2000 Remote Storage).
#[derive(Clone, Debug)]
pub struct HsmV1Header {
    version: u32,
    reserved: u32,
    data_stream_id: NtfsGuid,
    data_stream_offset: u64,
}

impl HsmV1Header {
    /// The HSM v1 format version.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The reserved header field.
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// The GUID identifying the migrated data stream in the remote store.
    #[must_use]
    pub fn data_stream_id(&self) -> &NtfsGuid {
        &self.data_stream_id
    }

    /// The offset of the migrated content within the remote data stream.
    #[must_use]
    pub fn data_stream_offset(&self) -> u64 {
        self.data_stream_offset
    }
}

/// A parsed Hierarchical Storage Management reparse point.
///
/// Obtain via [`NtfsReparsePoint::as_hsm`].
#[derive(Clone, Debug)]
pub struct NtfsHsmReparsePoint {
    tag: HsmTag,
    v1_header: Option<HsmV1Header>,
    provider_data: Vec<u8>,
}

impl NtfsHsmReparsePoint {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        let tag = HsmTag::from_raw(reparse_point.tag()).ok_or(NtfsError::ReparseTagMismatch {
            position: NtfsPosition::none(),
            expected: reparse_tags::HSM,
            actual: reparse_point.tag(),
        })?;

        let data = reparse_point.data();
        match tag {
            HsmTag::V1 => Self::parse_v1(data),
            // HSM v2 layout is provider-dependent — keep the bytes raw.
            HsmTag::V2 => Ok(Self {
                tag,
                v1_header: None,
                provider_data: data.to_vec(),
            }),
        }
    }

    /// Parses an HSM v1 reparse point from its reparse data buffer.
    fn parse_v1(data: &[u8]) -> Result<Self> {
        if data.len() < HSM_V1_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "HSM v1 reparse data too small for the 32-byte header",
            });
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let reserved = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let data_stream_id = NtfsGuid::read_from_bytes(&data[8..8 + GUID_SIZE]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to parse HSM data stream GUID",
            }
        })?;
        let offset_bytes: [u8; 8] = data[DATA_STREAM_OFFSET_FIELD..DATA_STREAM_OFFSET_FIELD + 8]
            .try_into()
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to read HSM data stream offset",
            })?;

        Ok(Self {
            tag: HsmTag::V1,
            v1_header: Some(HsmV1Header {
                version,
                reserved,
                data_stream_id,
                data_stream_offset: u64::from_le_bytes(offset_bytes),
            }),
            provider_data: data[HSM_V1_HEADER_SIZE..].to_vec(),
        })
    }

    /// Returns which HSM tag this reparse point uses.
    #[must_use]
    pub fn tag(&self) -> HsmTag {
        self.tag
    }

    /// Returns the documented HSM v1 header, or `None` for an HSM v2
    /// reparse point (which has no documented header).
    #[must_use]
    pub fn v1_header(&self) -> Option<&HsmV1Header> {
        self.v1_header.as_ref()
    }

    /// Returns the provider-specific data.
    ///
    /// For HSM v1 this is the bytes after the 32-byte header; for HSM v2
    /// it is the entire reparse data buffer.
    #[must_use]
    pub fn provider_data(&self) -> &[u8] {
        &self.provider_data
    }
}

/// Summarises a file's HSM migration state from its file-attribute flags.
///
/// An HSM-migrated file is identified by an HSM reparse point combined
/// with these flags; the flags alone describe how the content is
/// recalled. See [`NtfsReparsePoint::is_hsm`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HsmMigrationState {
    /// No offline/recall flags — the content is present locally.
    Online,
    /// `OFFLINE` is set, but no recall-trigger flag — content has been
    /// migrated and is not present locally.
    Offline,
    /// `RECALL_ON_OPEN` is set — opening the file recalls its content.
    RecallOnOpen,
    /// `RECALL_ON_DATA_ACCESS` is set — content is recalled lazily when
    /// data is actually read.
    RecallOnDataAccess,
}

impl HsmMigrationState {
    /// Derives the migration state from a file's attribute flags.
    ///
    /// `RECALL_ON_DATA_ACCESS` and `RECALL_ON_OPEN` take precedence over
    /// a bare `OFFLINE` flag, since they describe how the migrated
    /// content is brought back.
    #[must_use]
    pub fn from_attributes(flags: NtfsFileAttributeFlags) -> Self {
        if flags.contains(NtfsFileAttributeFlags::RECALL_ON_DATA_ACCESS) {
            Self::RecallOnDataAccess
        } else if flags.contains(NtfsFileAttributeFlags::RECALL_ON_OPEN) {
            Self::RecallOnOpen
        } else if flags.contains(NtfsFileAttributeFlags::OFFLINE) {
            Self::Offline
        } else {
            Self::Online
        }
    }

    /// Returns `true` if the file's content is not present locally.
    #[must_use]
    pub fn is_migrated(self) -> bool {
        !matches!(self, Self::Online)
    }
}

impl NtfsReparsePoint {
    /// Attempts to parse this reparse point as an HSM reparse point.
    ///
    /// Succeeds for both `IO_REPARSE_TAG_HSM` (v1) and
    /// `IO_REPARSE_TAG_HSM2` (v2); returns an error for any other tag,
    /// or if an HSM v1 buffer is too small for its header.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-HSM tag or a truncated HSM payload.
    pub fn as_hsm(&self) -> Result<NtfsHsmReparsePoint> {
        NtfsHsmReparsePoint::from_reparse_point(self)
    }

    /// Returns `true` if this is an HSM-family reparse point (v1 or v2).
    #[must_use]
    pub fn is_hsm(&self) -> bool {
        matches!(self.tag(), reparse_tags::HSM | reparse_tags::HSM2)
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

    /// A 32-byte HSM v1 header followed by `extra` provider data.
    fn hsm_v1_payload(version: u32, offset: u64, extra: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&version.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
        buf.extend_from_slice(&[
            0x0B, 0x77, 0xC8, 0x67, 0xF1, 0x44, 0x0A, 0x41, // GUID
            0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE,
        ]);
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(extra);
        buf
    }

    #[test]
    fn hsm_tag_from_raw_round_trips() {
        for tag in [HsmTag::V1, HsmTag::V2] {
            assert_eq!(HsmTag::from_raw(tag.as_u32()), Some(tag));
        }
        assert!(HsmTag::from_raw(reparse_tags::SYMLINK).is_none());
    }

    #[test]
    fn parses_hsm_v1_header() {
        let raw = make_reparse_bytes(reparse_tags::HSM, &hsm_v1_payload(3, 0x1_0000, &[0xAA]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");

        let hsm = rp.as_hsm().expect("valid HSM parse");
        assert_eq!(hsm.tag(), HsmTag::V1);
        let header = hsm.v1_header().expect("v1 header present");
        assert_eq!(header.version(), 3);
        assert_eq!(header.reserved(), 0);
        assert_eq!(header.data_stream_id().data1(), 0x67C8_770B);
        assert_eq!(header.data_stream_offset(), 0x1_0000);
        assert_eq!(hsm.provider_data(), &[0xAA]);
        assert!(rp.is_hsm());
    }

    #[test]
    fn parses_hsm_v2_as_raw() {
        let raw = make_reparse_bytes(reparse_tags::HSM2, &[0x01, 0x02, 0x03, 0x04]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");

        let hsm = rp.as_hsm().expect("valid HSM parse");
        assert_eq!(hsm.tag(), HsmTag::V2);
        assert!(hsm.v1_header().is_none());
        assert_eq!(hsm.provider_data(), &[0x01, 0x02, 0x03, 0x04]);
        assert!(rp.is_hsm());
    }

    #[test]
    fn rejects_non_hsm_tag() {
        let raw = make_reparse_bytes(reparse_tags::SYMLINK, &hsm_v1_payload(1, 0, &[]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.as_hsm().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { .. }),
            "expected ReparseTagMismatch, got {err:?}",
        );
        assert!(!rp.is_hsm());
    }

    #[test]
    fn rejects_truncated_hsm_v1() {
        let raw = make_reparse_bytes(reparse_tags::HSM, &[0u8; 16]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_hsm().is_err());
    }

    #[test]
    fn hsm_v1_reserved_field_is_parsed() {
        // A nonzero reserved field at offset 0x04 must be returned verbatim,
        // so a `reserved -> 0` replacement is observable.
        let mut payload = hsm_v1_payload(1, 0, &[]);
        payload[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let raw = make_reparse_bytes(reparse_tags::HSM, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let hsm = rp.as_hsm().expect("valid HSM parse");
        assert_eq!(hsm.v1_header().unwrap().reserved(), 0xDEAD_BEEF);
    }

    #[test]
    fn hsm_v1_with_no_provider_data() {
        let raw = make_reparse_bytes(reparse_tags::HSM, &hsm_v1_payload(1, 0, &[]));
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let hsm = rp.as_hsm().expect("valid HSM parse");
        assert!(hsm.provider_data().is_empty());
    }

    #[test]
    fn migration_state_from_attributes() {
        assert_eq!(
            HsmMigrationState::from_attributes(NtfsFileAttributeFlags::empty()),
            HsmMigrationState::Online,
        );
        assert_eq!(
            HsmMigrationState::from_attributes(NtfsFileAttributeFlags::OFFLINE),
            HsmMigrationState::Offline,
        );
        assert_eq!(
            HsmMigrationState::from_attributes(NtfsFileAttributeFlags::RECALL_ON_OPEN),
            HsmMigrationState::RecallOnOpen,
        );
        assert_eq!(
            HsmMigrationState::from_attributes(NtfsFileAttributeFlags::RECALL_ON_DATA_ACCESS),
            HsmMigrationState::RecallOnDataAccess,
        );
    }

    #[test]
    fn recall_flag_takes_precedence_over_offline() {
        // A migrated file commonly has OFFLINE set alongside a recall flag.
        let flags = NtfsFileAttributeFlags::OFFLINE | NtfsFileAttributeFlags::RECALL_ON_OPEN;
        assert_eq!(
            HsmMigrationState::from_attributes(flags),
            HsmMigrationState::RecallOnOpen,
        );
    }

    #[test]
    fn is_migrated_predicate() {
        assert!(!HsmMigrationState::Online.is_migrated());
        assert!(HsmMigrationState::Offline.is_migrated());
        assert!(HsmMigrationState::RecallOnDataAccess.is_migrated());
    }
}
