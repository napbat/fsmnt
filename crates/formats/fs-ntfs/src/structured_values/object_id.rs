use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Structure of an $`OBJECT_ID` attribute.
///
/// This optional attribute contains a globally unique identifier of the file.
///
/// An $`OBJECT_ID` attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/object_id.html>
///
/// Spec reference: MS-FSCC Section 2.1.3 (`FILE_OBJECTID_BUFFER`).
#[derive(Clone, Debug)]
pub struct NtfsObjectId {
    object: NtfsGuid,
    birth_volume: Option<NtfsGuid>,
    birth_object: Option<NtfsGuid>,
    domain: Option<NtfsGuid>,
}

impl NtfsObjectId {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        let guid_size = u64::try_from(GUID_SIZE).expect("the fixed 16-byte GUID size fits in u64");
        if value_length < guid_size {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::ObjectId,
                expected: guid_size,
                actual: value_length,
            });
        }

        let object = read_pod::<T, NtfsGuid, GUID_SIZE>(r)?;

        let mut birth_volume = None;
        if value_length >= 2 * guid_size {
            birth_volume = Some(read_pod::<T, NtfsGuid, GUID_SIZE>(r)?);
        }

        let mut birth_object = None;
        if value_length >= 3 * guid_size {
            birth_object = Some(read_pod::<T, NtfsGuid, GUID_SIZE>(r)?);
        }

        let mut domain = None;
        if value_length >= 4 * guid_size {
            domain = Some(read_pod::<T, NtfsGuid, GUID_SIZE>(r)?);
        }

        Ok(Self {
            object,
            birth_volume,
            birth_object,
            domain,
        })
    }

    /// Returns the (optional) first Object ID that has ever been assigned to this file.
    #[must_use]
    pub fn birth_object_id(&self) -> Option<&NtfsGuid> {
        self.birth_object.as_ref()
    }

    /// Returns the (optional) Object ID of the $Volume file of the partition where this file was created.
    #[must_use]
    pub fn birth_volume_id(&self) -> Option<&NtfsGuid> {
        self.birth_volume.as_ref()
    }

    /// Returns the (optional) Domain ID of this file.
    #[must_use]
    pub fn domain_id(&self) -> Option<&NtfsGuid> {
        self.domain.as_ref()
    }

    /// Returns the Object ID, a globally unique identifier of the file.
    #[must_use]
    pub fn object_id(&self) -> &NtfsGuid {
        &self.object
    }
}

impl_structured_value_via_new!(NtfsObjectId, NtfsAttributeType::ObjectId);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsObjectId {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsObjectId {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let object: NtfsGuid = u.arbitrary()?;
        // On-disk, optional fields form a prefix chain: birth_volume_id can only
        // exist if object_id is present, birth_object_id only if birth_volume_id
        // is present, and domain_id only if birth_object_id is present.
        let birth_volume: Option<NtfsGuid> = u.arbitrary()?;
        let birth_object = if birth_volume.is_some() {
            u.arbitrary()?
        } else {
            None
        };
        let domain = if birth_object.is_some() {
            u.arbitrary()?
        } else {
            None
        };
        Ok(Self {
            object,
            birth_volume,
            birth_object,
            domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::ReadOnlyCursor;

    #[test]
    fn test_object_id_minimum_16_bytes() {
        // 16 bytes: just an object_id GUID.
        let data: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, // data1
            0x05, 0x06, // data2
            0x07, 0x08, // data3
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, // data4
        ];

        let mut cursor = ReadOnlyCursor::new(&data);
        let obj_id = NtfsObjectId::new(&mut cursor, NtfsPosition::new(100), 16).unwrap();

        assert_eq!(obj_id.object_id().data1(), 0x0403_0201);
        assert!(obj_id.birth_volume_id().is_none());
        assert!(obj_id.birth_object_id().is_none());
        assert!(obj_id.domain_id().is_none());
    }

    #[test]
    fn test_object_id_32_bytes() {
        // 32 bytes: object_id + birth_volume_id.
        let data = [0xAAu8; 32];

        let mut cursor = ReadOnlyCursor::new(&data);
        let obj_id = NtfsObjectId::new(&mut cursor, NtfsPosition::new(100), 32).unwrap();

        assert!(obj_id.birth_volume_id().is_some());
        assert!(obj_id.birth_object_id().is_none());
        assert!(obj_id.domain_id().is_none());
    }

    #[test]
    fn test_object_id_48_bytes() {
        // 48 bytes: object_id + birth_volume_id + birth_object_id.
        let data = [0xBBu8; 48];

        let mut cursor = ReadOnlyCursor::new(&data);
        let obj_id = NtfsObjectId::new(&mut cursor, NtfsPosition::new(100), 48).unwrap();

        assert!(obj_id.birth_volume_id().is_some());
        assert!(obj_id.birth_object_id().is_some());
        assert!(obj_id.domain_id().is_none());
    }

    #[test]
    fn test_object_id_64_bytes_all_guids() {
        // 64 bytes: all four GUIDs present.
        let data = [0xCCu8; 64];

        let mut cursor = ReadOnlyCursor::new(&data);
        let obj_id = NtfsObjectId::new(&mut cursor, NtfsPosition::new(100), 64).unwrap();

        assert!(obj_id.birth_volume_id().is_some());
        assert!(obj_id.birth_object_id().is_some());
        assert!(obj_id.domain_id().is_some());
    }

    #[test]
    fn test_object_id_too_small() {
        // Less than 16 bytes should fail.
        let data = [0u8; 8];

        let mut cursor = ReadOnlyCursor::new(&data);
        let result = NtfsObjectId::new(&mut cursor, NtfsPosition::new(100), 8);
        assert!(result.is_err());
    }
}
