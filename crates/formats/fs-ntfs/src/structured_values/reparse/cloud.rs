//! Cloud Files reparse point metadata.
//!
//! Cloud reparse points (tags `0x9000_001A` through `0x9000_F01A`) are used
//! by `OneDrive`, Azure File Sync, and other cloud storage providers on
//! Windows 10/11. The 16 tag variants encode a 4-bit sub-variant in
//! bits 12-15 of the reparse tag.
//!
//! # Support boundary
//!
//! This module deliberately stops at **tag-family recognition and the
//! 4-bit variant nibble**. The Cloud Files reparse *data buffer* is
//! **not parsed**, and that is an intentional, fixed boundary — not a
//! gap to be filled later:
//!
//! - The buffer format is private to `cldflt.sys`. Microsoft publishes
//!   no on-disk specification for it; MS-FSCC documents only the tag.
//! - The layout is not stable: it has changed across Windows 10/11
//!   feature updates, so any field offsets parsed today could silently
//!   misread on another build.
//!
//! Consequently this crate does **not** decode per-file hydration state
//! (hydrated / dehydrated / pinned / unpinned), the sync-provider
//! identity, or the placeholder identity blob from the reparse buffer.
//! Callers that need those bytes must read the raw buffer themselves via
//! [`NtfsReparsePoint::data`] and interpret it at their own risk.
//!
//! Note that the OS-level hydration *hints* are still observable through
//! [`NtfsFileAttributeFlags`] (`RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS`,
//! `PINNED`, `UNPINNED`, `OFFLINE`), which this crate does parse.
//!
//! Reference: MS-FSCC Section 2.1.2.1 (Reparse Tags).
//!
//! [`NtfsFileAttributeFlags`]: crate::structured_values::NtfsFileAttributeFlags

use super::reparse_point::{NtfsReparsePoint, reparse_tags};

/// Mask to isolate the Cloud tag family (bits 16-27 must be zero).
const CLOUD_FAMILY_MASK: u32 = 0xFFFF_0FFF;

/// Expected value after masking for Cloud tag family.
const CLOUD_FAMILY_EXPECTED: u32 = reparse_tags::CLOUD; // 0x9000_001A

/// Bit shift to extract the 4-bit cloud variant nibble (bits 12-15).
const CLOUD_VARIANT_SHIFT: u32 = 12;

/// Cloud tag sub-variant (0-15).
///
/// Extracted from bits 12-15 of Cloud Files reparse tags
/// (`0x9000_X01A` where `X` is the variant nibble).
///
/// The variant nibble encodes:
/// - Bit 0: name surrogate
/// - Bit 1: directory
/// - Bits 2-3: reserved
///
/// Reference: MS-FSCC Section 2.1.2.1.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CloudVariant {
    /// Variant 0 — base Cloud tag (`0x9000_001A`).
    V0 = 0,
    /// Variant 1 (`0x9000_101A`).
    V1 = 1,
    /// Variant 2 (`0x9000_201A`).
    V2 = 2,
    /// Variant 3 (`0x9000_301A`).
    V3 = 3,
    /// Variant 4 (`0x9000_401A`).
    V4 = 4,
    /// Variant 5 (`0x9000_501A`).
    V5 = 5,
    /// Variant 6 (`0x9000_601A`).
    V6 = 6,
    /// Variant 7 (`0x9000_701A`).
    V7 = 7,
    /// Variant 8 (`0x9000_801A`).
    V8 = 8,
    /// Variant 9 (`0x9000_901A`).
    V9 = 9,
    /// Variant 10 (`0x9000_A01A`).
    V10 = 10,
    /// Variant 11 (`0x9000_B01A`).
    V11 = 11,
    /// Variant 12 (`0x9000_C01A`).
    V12 = 12,
    /// Variant 13 (`0x9000_D01A`).
    V13 = 13,
    /// Variant 14 (`0x9000_E01A`).
    V14 = 14,
    /// Variant 15 (`0x9000_F01A`).
    V15 = 15,
}

impl CloudVariant {
    /// Creates a `CloudVariant` from a raw 4-bit nibble value (0-15).
    ///
    /// Returns `None` if the value is out of range (>15).
    #[must_use]
    pub fn from_nibble(nibble: u8) -> Option<Self> {
        match nibble {
            0 => Some(Self::V0),
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            5 => Some(Self::V5),
            6 => Some(Self::V6),
            7 => Some(Self::V7),
            8 => Some(Self::V8),
            9 => Some(Self::V9),
            10 => Some(Self::V10),
            11 => Some(Self::V11),
            12 => Some(Self::V12),
            13 => Some(Self::V13),
            14 => Some(Self::V14),
            15 => Some(Self::V15),
            _ => None,
        }
    }

    /// Returns the raw 4-bit nibble value (0-15).
    #[must_use]
    pub fn as_nibble(self) -> u8 {
        match self {
            Self::V0 => 0,
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8 => 8,
            Self::V9 => 9,
            Self::V10 => 10,
            Self::V11 => 11,
            Self::V12 => 12,
            Self::V13 => 13,
            Self::V14 => 14,
            Self::V15 => 15,
        }
    }
}

/// Parsed Cloud Files reparse point metadata.
///
/// Contains the cloud tag sub-variant and the raw reparse tag value.
/// Obtain via [`NtfsReparsePoint::cloud_info`].
///
/// This is the **complete** parsed view of a Cloud Files reparse point:
/// it is derived entirely from the reparse tag. The reparse *data
/// buffer* is intentionally not parsed — its format is private to
/// `cldflt.sys` and unstable across Windows builds — so `CloudInfo`
/// carries no hydration state (hydrated / dehydrated / pinned) and no
/// sync-provider identity. Use [`NtfsReparsePoint::data`] for raw buffer
/// access. See the [module documentation](self) for the rationale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct CloudInfo {
    /// The cloud tag sub-variant (0-15).
    pub variant: CloudVariant,
    /// The raw reparse tag value (preserves the full tag including variant).
    pub raw_tag: u32,
}

/// Returns `true` if the raw tag belongs to the Cloud Files family.
fn is_cloud_tag(raw_tag: u32) -> bool {
    (raw_tag & CLOUD_FAMILY_MASK) == CLOUD_FAMILY_EXPECTED
}

/// Extracts the 4-bit cloud variant nibble from a raw tag.
///
/// Caller must ensure `raw_tag` is a Cloud family tag.
fn extract_variant(raw_tag: u32) -> CloudVariant {
    let nibble = ((raw_tag >> CLOUD_VARIANT_SHIFT) & 0xF).to_le_bytes()[0];
    // Nibble is masked to 4 bits, so from_nibble always returns Some.
    match CloudVariant::from_nibble(nibble) {
        Some(v) => v,
        None => CloudVariant::V0, // unreachable: nibble is 0..=15
    }
}

impl NtfsReparsePoint {
    /// Parse Cloud Files reparse point metadata, if this is a Cloud tag.
    ///
    /// Returns `None` if the tag is not in the Cloud Files family
    /// (`0x9000_X01A` where `X` is 0-F).
    /// This method never fails — Cloud metadata is derived entirely
    /// from the tag value, not from the reparse data buffer.
    #[must_use]
    pub fn cloud_info(&self) -> Option<CloudInfo> {
        let raw_tag = self.tag();
        if !is_cloud_tag(raw_tag) {
            return None;
        }
        Some(CloudInfo {
            variant: extract_variant(raw_tag),
            raw_tag,
        })
    }

    /// Returns `true` if this is a Cloud Files reparse point.
    #[must_use]
    pub fn is_cloud(&self) -> bool {
        is_cloud_tag(self.tag())
    }

    /// Returns the cloud variant, if this is a Cloud Files reparse point.
    ///
    /// Convenience for `self.cloud_info().map(|c| c.variant)`.
    #[must_use]
    pub fn cloud_variant(&self) -> Option<CloudVariant> {
        if is_cloud_tag(self.tag()) {
            Some(extract_variant(self.tag()))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NtfsPosition;

    /// Build raw reparse point bytes (header + data) for a given tag.
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

    #[test]
    fn cloud_info_returns_none_for_non_cloud_tag() {
        let raw = make_reparse_bytes(reparse_tags::SYMLINK, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.cloud_info().is_none());
        assert!(!rp.is_cloud());
        assert!(rp.cloud_variant().is_none());
    }

    #[test]
    fn cloud_info_returns_none_for_near_miss_wrong_high_nibble() {
        // 0x8000_001A — Microsoft bit but not Cloud family (top nibble 8 not 9)
        let raw = make_reparse_bytes(0x8000_001A, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.cloud_info().is_none());
    }

    #[test]
    fn cloud_info_returns_none_for_near_miss_nonzero_bits_16_27() {
        // 0x9ABC_F01A — bits 16-27 are non-zero, not a valid Cloud tag
        let raw = make_reparse_bytes(0x9ABC_F01A, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.cloud_info().is_none());
    }

    #[test]
    fn cloud_info_returns_none_for_near_miss_wrong_low_bits() {
        // 0x9000_001B — low 12 bits differ
        let raw = make_reparse_bytes(0x9000_001B, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert!(rp.cloud_info().is_none());
    }

    #[test]
    fn cloud_variant_v0() {
        let raw = make_reparse_bytes(0x9000_001A, &[0xAB; 4]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.cloud_info().expect("is Cloud");
        assert_eq!(info.variant, CloudVariant::V0);
        assert_eq!(info.raw_tag, 0x9000_001A);
        assert!(rp.is_cloud());
        assert_eq!(rp.cloud_variant(), Some(CloudVariant::V0));
    }

    #[test]
    fn cloud_variant_v1() {
        let raw = make_reparse_bytes(0x9000_101A, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.cloud_info().expect("is Cloud");
        assert_eq!(info.variant, CloudVariant::V1);
        assert_eq!(info.raw_tag, 0x9000_101A);
    }

    #[test]
    fn cloud_variant_v15() {
        let raw = make_reparse_bytes(0x9000_F01A, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        let info = rp.cloud_info().expect("is Cloud");
        assert_eq!(info.variant, CloudVariant::V15);
        assert_eq!(info.raw_tag, 0x9000_F01A);
    }

    #[test]
    fn all_16_variants_parse_correctly() {
        for nibble in 0u8..=15 {
            let tag = 0x9000_001Au32 | (u32::from(nibble) << 12);
            let raw = make_reparse_bytes(tag, &[]);
            let rp = NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none())
                .expect("valid reparse point");
            let info = rp.cloud_info().expect("is Cloud");
            assert_eq!(info.variant.as_nibble(), nibble);
            assert_eq!(info.raw_tag, tag);
        }
    }

    #[test]
    fn is_cloud_matches_cloud_info() {
        let cloud_raw = make_reparse_bytes(0x9000_501A, &[]);
        let cloud_rp = NtfsReparsePoint::from_bytes(&cloud_raw, NtfsPosition::none())
            .expect("valid reparse point");
        assert_eq!(cloud_rp.is_cloud(), cloud_rp.cloud_info().is_some());

        let non_cloud_raw = make_reparse_bytes(reparse_tags::WOF, &[]);
        let non_cloud_rp = NtfsReparsePoint::from_bytes(&non_cloud_raw, NtfsPosition::none())
            .expect("valid reparse point");
        assert_eq!(non_cloud_rp.is_cloud(), non_cloud_rp.cloud_info().is_some());
    }

    #[test]
    fn cloud_variant_convenience_matches_cloud_info() {
        let raw = make_reparse_bytes(0x9000_A01A, &[]);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert_eq!(rp.cloud_variant(), rp.cloud_info().map(|c| c.variant),);
    }

    #[test]
    fn cloud_variant_from_nibble_all_valid() {
        for n in 0u8..=15 {
            let v = CloudVariant::from_nibble(n).expect("valid nibble");
            assert_eq!(v.as_nibble(), n);
        }
    }

    #[test]
    fn cloud_variant_from_nibble_out_of_range() {
        assert!(CloudVariant::from_nibble(16).is_none());
        assert!(CloudVariant::from_nibble(255).is_none());
    }

    #[test]
    fn cloud_info_preserves_raw_data() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        let raw = make_reparse_bytes(0x9000_301A, &data);
        let rp =
            NtfsReparsePoint::from_bytes(&raw, NtfsPosition::none()).expect("valid reparse point");
        assert_eq!(rp.data(), &data);
        assert!(rp.cloud_info().is_some());
    }
}
