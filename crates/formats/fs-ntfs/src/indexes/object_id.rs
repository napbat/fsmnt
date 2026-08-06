use core::fmt;

use zerocopy::FromBytes;

use crate::error::{NtfsError, Result};
use crate::file_reference::NtfsFileReference;
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::indexes::{NtfsIndexEntryData, NtfsIndexEntryHasData, NtfsIndexEntryType};
use crate::types::NtfsPosition;

use super::NtfsIndexEntryKey;

/// Size of the $O index data on disk:
/// file reference (8) + birth volume ID (16) + birth object ID (16) + domain ID (16) = 56 bytes.
const OBJECT_ID_DATA_SIZE: usize = 8 + 3 * GUID_SIZE;

/// Defines the [`NtfsIndexEntryType`] for `$O` (Object ID) index entries
/// in the `$Extend\$ObjId` system file.
///
/// The `$O` index maps object GUIDs to MFT file references, enabling
/// volume-wide GUID-to-file lookup without scanning the entire MFT.
/// Each entry also stores the birth volume ID, birth object ID, and
/// domain ID for distributed link tracking.
#[derive(Clone, Copy, Debug)]
pub struct NtfsObjectIdIndex;

impl NtfsIndexEntryType for NtfsObjectIdIndex {
    type KeyType = NtfsObjectIdIndexKey;
}

impl NtfsIndexEntryHasData for NtfsObjectIdIndex {
    type DataType = NtfsObjectIdIndexData;
}

/// The key type for `$O` index entries: a 16-byte object GUID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NtfsObjectIdIndexKey {
    object_id: NtfsGuid,
}

impl NtfsObjectIdIndexKey {
    /// Returns the object ID GUID.
    #[must_use]
    pub fn object_id(&self) -> &NtfsGuid {
        &self.object_id
    }
}

impl NtfsIndexEntryKey for NtfsObjectIdIndexKey {
    impl_fixed_size_key_ref!();

    fn key_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < GUID_SIZE {
            return Err(NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O key too short (expected 16 bytes)",
            });
        }

        let object_id = NtfsGuid::read_from_bytes(&slice[..GUID_SIZE])
            .map_err(|_| NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O key GUID parsing failed",
            })?
            .clone();

        Ok(Self { object_id })
    }
}

impl fmt::Display for NtfsObjectIdIndexKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.object_id)
    }
}

/// The data type for `$O` index entries: file reference, birth volume ID,
/// birth object ID, and domain ID.
///
/// On-disk layout (56 bytes):
/// - `0x00..0x08`: File reference (6-byte MFT record number + 2-byte sequence)
/// - `0x08..0x18`: Birth volume ID (GUID)
/// - `0x18..0x28`: Birth object ID (GUID)
/// - `0x28..0x38`: Domain ID (GUID)
#[derive(Clone, Debug)]
pub struct NtfsObjectIdIndexData {
    file_reference: NtfsFileReference,
    birth_volume_id: NtfsGuid,
    birth_object_id: NtfsGuid,
    domain_id: NtfsGuid,
}

impl NtfsObjectIdIndexData {
    /// Returns the file reference (MFT record number + sequence number)
    /// of the file that owns this object ID.
    #[must_use]
    pub fn file_reference(&self) -> NtfsFileReference {
        self.file_reference
    }

    /// Returns the object ID of the `$Volume` file on the partition
    /// where this file was originally created.
    #[must_use]
    pub fn birth_volume_id(&self) -> &NtfsGuid {
        &self.birth_volume_id
    }

    /// Returns the first object ID that was ever assigned to this file,
    /// persisting across moves and renames for distributed link tracking.
    #[must_use]
    pub fn birth_object_id(&self) -> &NtfsGuid {
        &self.birth_object_id
    }

    /// Returns the domain ID (reserved, typically zero).
    #[must_use]
    pub fn domain_id(&self) -> &NtfsGuid {
        &self.domain_id
    }
}

impl NtfsIndexEntryData for NtfsObjectIdIndexData {
    fn data_from_slice(slice: &[u8], position: NtfsPosition) -> Result<Self> {
        if slice.len() < OBJECT_ID_DATA_SIZE {
            return Err(NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O data too short (expected 56 bytes)",
            });
        }

        let file_reference = NtfsFileReference::new([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ]);

        let birth_volume_id = NtfsGuid::read_from_bytes(&slice[8..8 + GUID_SIZE])
            .map_err(|_| NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O data birth volume ID parsing failed",
            })?
            .clone();

        let birth_object_id = NtfsGuid::read_from_bytes(&slice[24..24 + GUID_SIZE])
            .map_err(|_| NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O data birth object ID parsing failed",
            })?
            .clone();

        let domain_id = NtfsGuid::read_from_bytes(&slice[40..40 + GUID_SIZE])
            .map_err(|_| NtfsError::InvalidObjectIdIndexEntry {
                position,
                reason: "$O data domain ID parsing failed",
            })?
            .clone();

        Ok(Self {
            file_reference,
            birth_volume_id,
            birth_object_id,
            domain_id,
        })
    }
}

impl fmt::Display for NtfsObjectIdIndexData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjId(file={}/{}, birth_vol={}, birth_obj={}, domain={})",
            self.file_reference.file_record_number(),
            self.file_reference.sequence_number(),
            self.birth_volume_id,
            self.birth_object_id,
            self.domain_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 16-byte GUID from raw little-endian components.
    fn build_guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&data1.to_le_bytes());
        buf[4..6].copy_from_slice(&data2.to_le_bytes());
        buf[6..8].copy_from_slice(&data3.to_le_bytes());
        buf[8..16].copy_from_slice(&data4);
        buf
    }

    /// Builds a packed 8-byte file reference from record number and sequence.
    fn build_file_ref(record_number: u64, sequence_number: u16) -> [u8; 8] {
        let packed = (record_number & 0x0000_ffff_ffff_ffff) | (u64::from(sequence_number) << 48);
        packed.to_le_bytes()
    }

    /// Builds a full 56-byte $O data entry.
    fn build_data(
        record_number: u64,
        sequence_number: u16,
        birth_volume: [u8; 16],
        birth_object: [u8; 16],
        domain: [u8; 16],
    ) -> [u8; 56] {
        let mut buf = [0u8; 56];
        buf[0..8].copy_from_slice(&build_file_ref(record_number, sequence_number));
        buf[8..24].copy_from_slice(&birth_volume);
        buf[24..40].copy_from_slice(&birth_object);
        buf[40..56].copy_from_slice(&domain);
        buf
    }

    // ── Key tests ──

    #[test]
    fn key_parse_valid() {
        let guid = build_guid(
            0x67C8_770B,
            0x44F1,
            0x410A,
            [0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE],
        );
        let key = NtfsObjectIdIndexKey::key_from_slice(&guid, NtfsPosition::none())
            .expect("should parse valid $O key");
        assert_eq!(key.object_id().data1(), 0x67C8_770B);
        assert_eq!(key.object_id().data2(), 0x44F1);
        assert_eq!(key.object_id().data3(), 0x410A);
        assert_eq!(
            key.object_id().data4(),
            [0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE]
        );
    }

    #[test]
    fn key_endianness() {
        // Hardcoded byte literal to catch byte-order bugs.
        let raw: [u8; 16] = [
            0x0B, 0x77, 0xC8, 0x67, // data1 LE = 0x67C8770B
            0xF1, 0x44, // data2 LE = 0x44F1
            0x0A, 0x41, // data3 LE = 0x410A
            0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE, // data4
        ];
        let key = NtfsObjectIdIndexKey::key_from_slice(&raw, NtfsPosition::none())
            .expect("should parse GUID from raw LE bytes");
        assert_eq!(key.object_id().data1(), 0x67C8_770B);
        assert_eq!(key.object_id().data2(), 0x44F1);
        assert_eq!(key.object_id().data3(), 0x410A);
    }

    #[test]
    fn key_accepts_extra_bytes() {
        let mut buf = [0u8; 20];
        let guid = build_guid(1, 2, 3, [4; 8]);
        buf[0..16].copy_from_slice(&guid);
        buf[16..20].copy_from_slice(&[0xFF; 4]);
        let key = NtfsObjectIdIndexKey::key_from_slice(&buf, NtfsPosition::none())
            .expect("should accept extra trailing bytes");
        assert_eq!(key.object_id().data1(), 1);
    }

    #[test]
    fn key_reject_truncated() {
        let buf = [0u8; 15];
        let result = NtfsObjectIdIndexKey::key_from_slice(&buf, NtfsPosition::new(0x500));
        assert!(result.is_err());
    }

    #[test]
    fn key_reject_empty() {
        let result = NtfsObjectIdIndexKey::key_from_slice(&[], NtfsPosition::new(0x100));
        assert!(result.is_err());
    }

    #[test]
    fn key_display() {
        let guid = build_guid(
            0x67C8_770B,
            0x44F1,
            0x410A,
            [0xAB, 0x9A, 0xF9, 0xB5, 0x44, 0x6F, 0x13, 0xEE],
        );
        let key = NtfsObjectIdIndexKey::key_from_slice(&guid, NtfsPosition::none())
            .expect("should parse key for display test");
        let s = format!("{key}");
        assert!(s.starts_with("ObjectId("), "expected ObjectId prefix: {s}");
        assert!(s.contains("67C8770B"), "expected data1 in display: {s}");
    }

    #[test]
    fn key_equality() {
        let guid1 = build_guid(0xAAAA_BBBB, 0x1111, 0x2222, [0x33; 8]);
        let guid2 = build_guid(0xAAAA_BBBB, 0x1111, 0x2222, [0x33; 8]);
        let guid3 = build_guid(0xCCCC_DDDD, 0x1111, 0x2222, [0x33; 8]);
        let key1 =
            NtfsObjectIdIndexKey::key_from_slice(&guid1, NtfsPosition::none()).expect("key1");
        let key2 =
            NtfsObjectIdIndexKey::key_from_slice(&guid2, NtfsPosition::none()).expect("key2");
        let key3 =
            NtfsObjectIdIndexKey::key_from_slice(&guid3, NtfsPosition::none()).expect("key3");
        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    // ── Data tests ──

    #[test]
    fn data_parse_valid() {
        let birth_vol = build_guid(0x1111_1111, 0x2222, 0x3333, [0x44; 8]);
        let birth_obj = build_guid(0x5555_5555, 0x6666, 0x7777, [0x88; 8]);
        let domain = build_guid(0, 0, 0, [0; 8]);
        let buf = build_data(1234, 3, birth_vol, birth_obj, domain);

        let data = NtfsObjectIdIndexData::data_from_slice(&buf, NtfsPosition::none())
            .expect("should parse valid $O data");

        assert_eq!(data.file_reference().file_record_number(), 1234);
        assert_eq!(data.file_reference().sequence_number(), 3);
        assert_eq!(data.birth_volume_id().data1(), 0x1111_1111);
        assert_eq!(data.birth_object_id().data1(), 0x5555_5555);
        assert_eq!(data.domain_id().data1(), 0);
    }

    #[test]
    fn data_endianness() {
        // Hardcoded byte literal for the file reference portion.
        // record = 0xDEAD_BEEF (LE: EF BE AD DE 00 00), seq = 0x1234 (LE: 34 12)
        let mut buf = [0u8; 56];
        buf[0..8].copy_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x34, 0x12]);
        // Fill GUIDs with recognizable patterns.
        let vol = build_guid(0xAABB_CCDD, 0x1122, 0x3344, [0x55; 8]);
        let obj = build_guid(0xEEFF_0011, 0x2233, 0x4455, [0x66; 8]);
        let dom = build_guid(0x7788_99AA, 0xBBCC, 0xDDEE, [0xFF; 8]);
        buf[8..24].copy_from_slice(&vol);
        buf[24..40].copy_from_slice(&obj);
        buf[40..56].copy_from_slice(&dom);

        let data = NtfsObjectIdIndexData::data_from_slice(&buf, NtfsPosition::none())
            .expect("should parse endianness test data");
        assert_eq!(data.file_reference().file_record_number(), 0xDEAD_BEEF);
        assert_eq!(data.file_reference().sequence_number(), 0x1234);
        assert_eq!(data.birth_volume_id().data1(), 0xAABB_CCDD);
        assert_eq!(data.birth_volume_id().data2(), 0x1122);
        assert_eq!(data.birth_object_id().data1(), 0xEEFF_0011);
        assert_eq!(data.domain_id().data1(), 0x7788_99AA);
        assert_eq!(data.domain_id().data4(), [0xFF; 8]);
    }

    #[test]
    fn data_accepts_extra_bytes() {
        let zeros = [0u8; 16];
        let mut buf = [0u8; 60];
        buf[0..56].copy_from_slice(&build_data(1, 1, zeros, zeros, zeros));
        buf[56..60].copy_from_slice(&[0xFF; 4]);
        let data = NtfsObjectIdIndexData::data_from_slice(&buf, NtfsPosition::none())
            .expect("should accept extra trailing bytes");
        assert_eq!(data.file_reference().file_record_number(), 1);
    }

    #[test]
    fn data_reject_truncated() {
        let buf = [0u8; 55];
        let result = NtfsObjectIdIndexData::data_from_slice(&buf, NtfsPosition::new(0x800));
        assert!(result.is_err());
    }

    #[test]
    fn data_reject_empty() {
        let result = NtfsObjectIdIndexData::data_from_slice(&[], NtfsPosition::new(0x100));
        assert!(result.is_err());
    }

    #[test]
    fn data_display() {
        let birth_vol = build_guid(0xAAAA_BBBB, 0, 0, [0; 8]);
        let birth_obj = build_guid(0xCCCC_DDDD, 0, 0, [0; 8]);
        let domain = build_guid(0xEEEE_FFFF, 0, 0, [0; 8]);
        let buf = build_data(42, 7, birth_vol, birth_obj, domain);

        let data = NtfsObjectIdIndexData::data_from_slice(&buf, NtfsPosition::none())
            .expect("should parse data for display test");
        let s = format!("{data}");
        assert!(s.contains("42"), "expected record number in display: {s}");
        assert!(s.contains('7'), "expected sequence number in display: {s}");
        assert!(s.contains("AAAABBBB"), "expected birth_vol in display: {s}");
        assert!(s.contains("CCCCDDDD"), "expected birth_obj in display: {s}");
        assert!(s.contains("EEEEFFFF"), "expected domain in display: {s}");
    }
}
