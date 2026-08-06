//! Windows Container Isolation (WCI) reparse point parsing.
//!
//! WCI reparse points are used by Docker on Windows, Windows Sandbox, and
//! MSIX to implement filesystem layering. Four tags (WCI, `WCI_1`, `WCI_LINK`,
//! `WCI_LINK_1`) share a common payload layout; `WCI_TOMBSTONE` has no
//! documented payload format.
//!
//! The payload layout (de-facto standard from multiple independent sources):
//! ```text
//! Offset  Size  Field
//! 0x00    4     Version (observed: 1)
//! 0x04    4     Reserved
//! 0x08    16    LookupGuid (Windows GUID wire format)
//! 0x18    2     PathStringLength (bytes)
//! 0x1A    var   PathString (UTF-16LE, not null-terminated)
//! ```
//!
//! Reference: `crates/fs-ntfs/docs/ms-fscc/WCI Data Buffer Structures.md`

use arrayvec::ArrayVec;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, Unaligned};

use super::reparse_point::{MAX_PATH_BUFFER_SIZE, NtfsReparsePoint, decode_utf16le, reparse_tags};
use crate::error::{NtfsError, Result};
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::types::NtfsPosition;

/// Size of the WCI reparse data header (version + reserved = 8 bytes).
const WCI_REPARSE_DATA_HEADER_SIZE: usize = 8;

/// Minimum payload size: header (8) + GUID (16) + path length field (2).
const WCI_MIN_PAYLOAD_SIZE: usize = WCI_REPARSE_DATA_HEADER_SIZE + GUID_SIZE + 2;

/// On-disk header for WCI reparse data (8 bytes).
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct WciReparseDataHeader {
    version: U32<LittleEndian>,
    reserved: U32<LittleEndian>,
}

/// Identifies which WCI tag variant a reparse point uses.
///
/// Four tags share a common payload layout. [`WciTag`] covers those four;
/// `WCI_TOMBSTONE` is excluded because it has no documented payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum WciTag {
    /// `IO_REPARSE_TAG_WCI` (`0x8000_0018`).
    Wci,
    /// `IO_REPARSE_TAG_WCI_1` (`0x9000_1018`).
    Wci1,
    /// `IO_REPARSE_TAG_WCI_LINK` (`0xA000_0027`).
    WciLink,
    /// `IO_REPARSE_TAG_WCI_LINK_1` (`0xA000_1027`).
    WciLink1,
}

impl WciTag {
    /// Maps a raw reparse tag constant to a [`WciTag`] variant.
    ///
    /// Returns `None` for `WCI_TOMBSTONE` (no parseable payload) and
    /// any non-WCI tag.
    #[must_use]
    pub fn from_raw(raw_tag: u32) -> Option<Self> {
        match raw_tag {
            reparse_tags::WCI => Some(Self::Wci),
            reparse_tags::WCI_1 => Some(Self::Wci1),
            reparse_tags::WCI_LINK => Some(Self::WciLink),
            reparse_tags::WCI_LINK_1 => Some(Self::WciLink1),
            _ => None,
        }
    }

    /// Returns the raw reparse tag value for this variant.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self {
            Self::Wci => reparse_tags::WCI,
            Self::Wci1 => reparse_tags::WCI_1,
            Self::WciLink => reparse_tags::WCI_LINK,
            Self::WciLink1 => reparse_tags::WCI_LINK_1,
        }
    }
}

/// Parsed Windows Container Isolation reparse point.
///
/// Contains the version, GUID, and layer path extracted from the
/// reparse data buffer. Obtain via [`NtfsReparsePoint::as_wci`].
#[derive(Clone, Debug)]
pub struct NtfsWciReparsePoint {
    tag: WciTag,
    version: u32,
    reserved: u32,
    lookup_guid: NtfsGuid,
    path: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsWciReparsePoint {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        let tag = WciTag::from_raw(reparse_point.tag()).ok_or(NtfsError::ReparseTagMismatch {
            position: NtfsPosition::none(),
            expected: reparse_tags::WCI,
            actual: reparse_point.tag(),
        })?;

        let data = reparse_point.data();
        if data.len() < WCI_MIN_PAYLOAD_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WCI reparse data too small for header",
            });
        }

        let header = WciReparseDataHeader::read_from_bytes(&data[..WCI_REPARSE_DATA_HEADER_SIZE])
            .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse WCI reparse data header",
        })?;

        let guid_start = WCI_REPARSE_DATA_HEADER_SIZE;
        let guid_end = guid_start + GUID_SIZE;
        let lookup_guid = NtfsGuid::read_from_bytes(&data[guid_start..guid_end]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "failed to parse WCI lookup GUID",
            }
        })?;

        let path_len_offset = guid_end;
        let path_len = usize::from(u16::from_le_bytes([
            data[path_len_offset],
            data[path_len_offset + 1],
        ]));

        if !path_len.is_multiple_of(2) {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WCI path length is odd (must be even for UTF-16LE)",
            });
        }

        let path_start = path_len_offset + 2;
        if path_len > data.len() - path_start {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WCI path length exceeds available data",
            });
        }

        let mut path = ArrayVec::new();
        path.try_extend_from_slice(&data[path_start..path_start + path_len])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WCI path too large for buffer",
            })?;

        Ok(Self {
            tag,
            version: header.version.get(),
            reserved: header.reserved.get(),
            lookup_guid,
            path,
        })
    }

    /// Returns which WCI tag variant this reparse point uses.
    #[must_use]
    pub fn tag(&self) -> WciTag {
        self.tag
    }

    /// Returns the version field from the WCI header.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the reserved field from the WCI header.
    #[must_use]
    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    /// Returns the lookup GUID used for layer resolution.
    #[must_use]
    pub fn lookup_guid(&self) -> &NtfsGuid {
        &self.lookup_guid
    }

    /// Returns the raw UTF-16LE path bytes.
    #[must_use]
    pub fn path_bytes(&self) -> &[u8] {
        &self.path
    }

    /// Decodes the path as a UTF-16LE string.
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains malformed UTF-16.
    pub fn path(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.path)
    }
}

impl NtfsReparsePoint {
    /// Attempts to parse as a Windows Container Isolation reparse point.
    ///
    /// Returns an error if the reparse tag is not one of the four
    /// parseable WCI tags (WCI, `WCI_1`, `WCI_LINK`, `WCI_LINK_1`).
    /// Use [`is_wci_tombstone`](Self::is_wci_tombstone) to check for
    /// tombstone tags, which have no documented payload.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported WCI tag or malformed WCI payload.
    pub fn as_wci(&self) -> Result<NtfsWciReparsePoint> {
        NtfsWciReparsePoint::from_reparse_point(self)
    }

    /// Returns `true` if this is any WCI-family reparse point,
    /// including tombstone.
    #[must_use]
    pub fn is_wci(&self) -> bool {
        matches!(
            self.tag(),
            reparse_tags::WCI
                | reparse_tags::WCI_1
                | reparse_tags::WCI_TOMBSTONE
                | reparse_tags::WCI_LINK
                | reparse_tags::WCI_LINK_1
        )
    }

    /// Returns `true` if this is a WCI tombstone reparse point.
    #[must_use]
    pub fn is_wci_tombstone(&self) -> bool {
        self.tag() == reparse_tags::WCI_TOMBSTONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NtfsPosition;

    fn make_reparse_bytes(tag: u32, reparse_data: &[u8]) -> alloc::vec::Vec<u8> {
        let tag_bytes = tag.to_le_bytes();
        let data_len = u16::try_from(reparse_data.len())
            .expect("test value fits u16")
            .to_le_bytes();
        let reserved = [0u8; 2];
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&tag_bytes);
        buf.extend_from_slice(&data_len);
        buf.extend_from_slice(&reserved);
        buf.extend_from_slice(reparse_data);
        buf
    }

    /// Real `WCI_1` payload from Check Point Research:
    /// Windows\System32\kernel32.dll
    fn wci1_test_vector_payload() -> [u8; 84] {
        [
            0x01, 0x00, 0x00, 0x00, // Version = 1
            0x00, 0x00, 0x00, 0x00, // Reserved = 0
            0x77, 0xF6, 0x64, 0x82, 0xB0, 0x40, 0xA5, 0x4C, // GUID
            0xBF, 0x9A, 0x94, 0x4A, 0xC2, 0xDA, 0x80, 0x87, 0x3A,
            0x00, // PathStringLength = 58
            0x57, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x64, 0x00, 0x6F, 0x00, 0x77, 0x00, 0x73, 0x00,
            0x5C, 0x00, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00,
            0x33, 0x00, 0x32, 0x00, 0x5C, 0x00, 0x6B, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6E, 0x00,
            0x65, 0x00, 0x6C, 0x00, 0x33, 0x00, 0x32, 0x00, 0x2E, 0x00, 0x64, 0x00, 0x6C, 0x00,
            0x6C, 0x00,
        ]
    }

    // --- WciTag tests ---

    #[test]
    fn wci_tag_from_raw_wci() {
        let tag = WciTag::from_raw(reparse_tags::WCI);
        assert_eq!(tag, Some(WciTag::Wci));
    }

    #[test]
    fn wci_tag_from_raw_wci1() {
        let tag = WciTag::from_raw(reparse_tags::WCI_1);
        assert_eq!(tag, Some(WciTag::Wci1));
    }

    #[test]
    fn wci_tag_from_raw_wci_link() {
        let tag = WciTag::from_raw(reparse_tags::WCI_LINK);
        assert_eq!(tag, Some(WciTag::WciLink));
    }

    #[test]
    fn wci_tag_from_raw_wci_link1() {
        let tag = WciTag::from_raw(reparse_tags::WCI_LINK_1);
        assert_eq!(tag, Some(WciTag::WciLink1));
    }

    #[test]
    fn wci_tag_from_raw_tombstone_returns_none() {
        assert!(WciTag::from_raw(reparse_tags::WCI_TOMBSTONE).is_none());
    }

    #[test]
    fn wci_tag_from_raw_non_wci_returns_none() {
        assert!(WciTag::from_raw(reparse_tags::SYMLINK).is_none());
        assert!(WciTag::from_raw(reparse_tags::MOUNT_POINT).is_none());
        assert!(WciTag::from_raw(0xDEAD_BEEF).is_none());
    }

    #[test]
    fn wci_tag_as_u32_round_trips() {
        let tags = [WciTag::Wci, WciTag::Wci1, WciTag::WciLink, WciTag::WciLink1];
        for tag in tags {
            let raw = tag.as_u32();
            let back = WciTag::from_raw(raw);
            assert_eq!(back, Some(tag));
        }
    }

    // --- Parsing tests ---

    #[test]
    fn parse_wci1_test_vector() {
        let payload = wci1_test_vector_payload();
        let raw = make_reparse_bytes(reparse_tags::WCI_1, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");

        let wci = rp.as_wci().expect("valid WCI parse");
        assert_eq!(wci.tag(), WciTag::Wci1);
        assert_eq!(wci.version(), 1);
        assert_eq!(wci.reserved(), 0);
        assert_eq!(
            wci.path().expect("valid path"),
            r"Windows\System32\kernel32.dll"
        );
    }

    #[test]
    fn version_and_reserved_reflect_header_bytes() {
        // Build a payload with non-default version/reserved so a mutation
        // that hardcodes version()->1 or reserved()->0 is caught.
        let mut payload = [0u8; WCI_MIN_PAYLOAD_SIZE];
        // Version field at offset 0x00 = 7 (not 0, not 1).
        payload[0..4].copy_from_slice(&7u32.to_le_bytes());
        // Reserved field at offset 0x04 = 0x1234_5678 (not 0).
        payload[4..8].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let raw = make_reparse_bytes(reparse_tags::WCI, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let wci = rp.as_wci().expect("valid WCI parse");
        assert_eq!(wci.version(), 7);
        assert_eq!(wci.reserved(), 0x1234_5678);
    }

    #[test]
    fn parse_all_four_wci_tags() {
        let payload = wci1_test_vector_payload();
        let expected = [
            (reparse_tags::WCI, WciTag::Wci),
            (reparse_tags::WCI_1, WciTag::Wci1),
            (reparse_tags::WCI_LINK, WciTag::WciLink),
            (reparse_tags::WCI_LINK_1, WciTag::WciLink1),
        ];
        for (raw_tag, variant) in expected {
            let raw = make_reparse_bytes(raw_tag, &payload);
            let rp = NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none())
                .expect("valid reparse point");
            let wci = rp.as_wci().expect("valid WCI parse");
            assert_eq!(wci.tag(), variant);
        }
    }

    #[test]
    fn reject_non_wci_tag() {
        let payload = wci1_test_vector_payload();
        let raw = make_reparse_bytes(reparse_tags::SYMLINK, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_wci().is_err());
    }

    #[test]
    fn reject_tombstone_tag() {
        let payload = wci1_test_vector_payload();
        let raw = make_reparse_bytes(reparse_tags::WCI_TOMBSTONE, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let err = rp.as_wci().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { .. }),
            "expected ReparseTagMismatch, got {err:?}"
        );
    }

    #[test]
    fn reject_truncated_data() {
        let raw = make_reparse_bytes(reparse_tags::WCI, &[0u8; 25]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_wci().is_err());
    }

    #[test]
    fn reject_odd_path_length() {
        let mut payload = [0u8; WCI_MIN_PAYLOAD_SIZE];
        // Set PathStringLength to 1 (odd)
        payload[24] = 0x01;
        payload[25] = 0x00;
        let raw = make_reparse_bytes(reparse_tags::WCI, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_wci().is_err());
    }

    #[test]
    fn reject_path_length_exceeding_data() {
        // Minimal header (26 bytes) with PathStringLength=2 but no
        // path bytes after the length field.
        let mut payload = [0u8; WCI_MIN_PAYLOAD_SIZE];
        payload[24] = 0x02;
        payload[25] = 0x00;
        let raw = make_reparse_bytes(reparse_tags::WCI, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.as_wci().is_err());
    }

    #[test]
    fn parse_empty_path() {
        let payload = [0u8; WCI_MIN_PAYLOAD_SIZE];
        let raw = make_reparse_bytes(reparse_tags::WCI, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let wci = rp.as_wci().expect("valid WCI parse");
        assert!(wci.path_bytes().is_empty());
        assert_eq!(wci.path().expect("valid empty path"), "");
    }

    #[test]
    fn path_bytes_returns_raw_utf16le() {
        let payload = wci1_test_vector_payload();
        let raw = make_reparse_bytes(reparse_tags::WCI_1, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let wci = rp.as_wci().expect("valid WCI parse");
        let bytes = wci.path_bytes();
        assert_eq!(bytes.len(), 58);
        assert_eq!(bytes[0], 0x57); // 'W' low byte
        assert_eq!(bytes[1], 0x00); // 'W' high byte
    }

    #[test]
    fn lookup_guid_matches_test_vector() {
        let payload = wci1_test_vector_payload();
        let raw = make_reparse_bytes(reparse_tags::WCI_1, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let wci = rp.as_wci().expect("valid WCI parse");
        let guid = wci.lookup_guid();
        assert_eq!(guid.data1(), 0x8264_F677);
        assert_eq!(guid.data2(), 0x40B0);
        assert_eq!(guid.data3(), 0x4CA5);
        assert_eq!(
            guid.data4(),
            [0xBF, 0x9A, 0x94, 0x4A, 0xC2, 0xDA, 0x80, 0x87]
        );
    }

    // --- is_wci / is_wci_tombstone tests ---

    #[test]
    fn is_wci_returns_true_for_all_five_tags() {
        let tags = [
            reparse_tags::WCI,
            reparse_tags::WCI_1,
            reparse_tags::WCI_TOMBSTONE,
            reparse_tags::WCI_LINK,
            reparse_tags::WCI_LINK_1,
        ];
        for tag in tags {
            let raw = make_reparse_bytes(tag, &[]);
            let rp = NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none())
                .expect("valid reparse point");
            assert!(rp.is_wci(), "expected is_wci() for tag {tag:#010X}");
        }
    }

    #[test]
    fn is_wci_returns_false_for_non_wci() {
        let tags = [
            reparse_tags::SYMLINK,
            reparse_tags::MOUNT_POINT,
            reparse_tags::CLOUD,
            reparse_tags::NFS,
        ];
        for tag in tags {
            let raw = make_reparse_bytes(tag, &[]);
            let rp = NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none())
                .expect("valid reparse point");
            assert!(!rp.is_wci(), "expected !is_wci() for tag {tag:#010X}");
        }
    }

    #[test]
    fn is_wci_tombstone_only_for_tombstone() {
        let tombstone_raw = make_reparse_bytes(reparse_tags::WCI_TOMBSTONE, &[]);
        let tombstone_rp = NtfsReparsePoint::from_bytes(&tombstone_raw, NtfsPosition::none())
            .expect("valid reparse point");
        assert!(tombstone_rp.is_wci_tombstone());

        let wci_raw = make_reparse_bytes(reparse_tags::WCI, &[]);
        let wci_rp = NtfsReparsePoint::from_bytes(&wci_raw, NtfsPosition::none())
            .expect("valid reparse point");
        assert!(!wci_rp.is_wci_tombstone());
    }

    #[test]
    fn tombstone_raw_data_accessible() {
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let raw = make_reparse_bytes(reparse_tags::WCI_TOMBSTONE, &payload);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert_eq!(rp.data(), &payload);
    }
}
