use core::fmt;

use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::types::NtfsPosition;

use super::NtfsIndexEntryKey;
use super::{NtfsIndexEntryHasFileReference, NtfsIndexEntryType};

/// Size of the on-disk key: reparse_tag(4) + file_reference(8) = 12 bytes.
const REPARSE_POINT_INDEX_KEY_SIZE: usize = 12;

/// Defines the [`NtfsIndexEntryType`] for `$R` (Reparse Point) index entries
/// in the `$Extend\$Reparse` system file.
///
/// The `$R` index lists every reparse point on the volume, sorted by
/// reparse tag then by file reference. Entries carry a file reference
/// in the index entry header but no additional data payload.
#[derive(Clone, Copy, Debug)]
pub struct NtfsReparsePointIndex;

impl NtfsIndexEntryType for NtfsReparsePointIndex {
    type KeyType = NtfsReparsePointIndexKey;
}

impl NtfsIndexEntryHasFileReference for NtfsReparsePointIndex {}

/// The key type for `$R` index entries: a reparse tag followed by
/// the file reference of the file that owns the reparse point.
#[derive(Clone, Debug)]
pub struct NtfsReparsePointIndexKey {
    reparse_tag: u32,
    file_reference: NtfsFileReference,
}

impl NtfsReparsePointIndexKey {
    /// Returns the reparse tag identifying the type of reparse point
    /// (e.g. `IO_REPARSE_TAG_SYMLINK`, `IO_REPARSE_TAG_MOUNT_POINT`).
    pub fn reparse_tag(&self) -> u32 {
        self.reparse_tag
    }

    /// Returns the file reference of the file that owns this reparse point.
    pub fn file_reference(&self) -> NtfsFileReference {
        self.file_reference
    }
}

impl NtfsIndexEntryKey for NtfsReparsePointIndexKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < REPARSE_POINT_INDEX_KEY_SIZE {
            return Err(NtfsError::InvalidReparsePointIndexEntry {
                position,
                reason: "$R key too short (expected 12 bytes)",
            });
        }

        let reparse_tag = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        let file_reference = NtfsFileReference::new([
            slice[4], slice[5], slice[6], slice[7], slice[8], slice[9], slice[10], slice[11],
        ]);

        Ok(Self {
            reparse_tag,
            file_reference,
        })
    }
}

impl fmt::Display for NtfsReparsePointIndexKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ReparsePoint(tag={:#010x}, file={})",
            self.reparse_tag,
            self.file_reference.file_record_number(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 12-byte $R key by packing raw little-endian bytes directly,
    /// without round-tripping through `NtfsFileReference` accessors.
    fn build_key(tag: u32, record_number: u64, sequence_number: u16) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&tag.to_le_bytes());
        let packed: u64 =
            (record_number & 0x0000_ffff_ffff_ffff) | ((sequence_number as u64) << 48);
        buf[4..12].copy_from_slice(&packed.to_le_bytes());
        buf
    }

    #[test]
    fn key_parse_valid() {
        let buf = build_key(0x8000_0012, 1234, 3);
        let key = NtfsReparsePointIndexKey::key_from_slice(&buf, NtfsPosition::none())
            .expect("should parse valid $R key");
        assert_eq!(key.reparse_tag(), 0x8000_0012);
        assert_eq!(key.file_reference().file_record_number(), 1234);
        assert_eq!(key.file_reference().sequence_number(), 3);
    }

    #[test]
    fn key_endianness() {
        // Hardcoded byte literal to catch byte-order bugs independently
        // of NtfsFileReference encoding.
        // tag = 0xA1B2_C3D4 (LE: D4 C3 B2 A1)
        // record = 0xDEAD_BEEF (LE: EF BE AD DE 00 00), seq = 0x1234 (LE: 34 12)
        let raw: [u8; 12] = [
            0xD4, 0xC3, 0xB2, 0xA1, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x34, 0x12,
        ];
        let key = NtfsReparsePointIndexKey::key_from_slice(&raw, NtfsPosition::none())
            .expect("should parse non-symmetric tag");
        assert_eq!(key.reparse_tag(), 0xA1B2_C3D4);
        assert_eq!(key.file_reference().file_record_number(), 0xDEAD_BEEF);
        assert_eq!(key.file_reference().sequence_number(), 0x1234);
    }

    #[test]
    fn key_accepts_extra_bytes() {
        let mut buf = [0u8; 14];
        buf[0..12].copy_from_slice(&build_key(1, 2, 3));
        buf[12] = 0xFF;
        buf[13] = 0xFE;
        let key = NtfsReparsePointIndexKey::key_from_slice(&buf, NtfsPosition::none())
            .expect("should accept extra trailing bytes");
        assert_eq!(key.reparse_tag(), 1);
    }

    #[test]
    fn key_reject_truncated() {
        let buf = [0u8; 11];
        let result = NtfsReparsePointIndexKey::key_from_slice(&buf, NtfsPosition::new(0x500));
        assert!(result.is_err());
    }

    #[test]
    fn key_reject_empty() {
        let result = NtfsReparsePointIndexKey::key_from_slice(&[], NtfsPosition::new(0x100));
        assert!(result.is_err());
    }

    #[test]
    fn display_impl() {
        let buf = build_key(0xA000_000C, 42, 1);
        let key = NtfsReparsePointIndexKey::key_from_slice(&buf, NtfsPosition::none())
            .expect("should parse valid $R key for display test");
        let s = format!("{key}");
        assert!(s.contains("0xa000000c"));
        assert!(s.contains("42"));
    }
}
