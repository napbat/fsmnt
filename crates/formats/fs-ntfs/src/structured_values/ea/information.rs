use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of the on-disk [`EaInformationData`] structure.
const EA_INFORMATION_SIZE: usize = 8;

/// On-disk layout of the `$EA_INFORMATION` attribute (type 0xD0).
///
/// Reference: [MS-FSCC] Section 2.4.13
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct EaInformationData {
    packed_ea_size: U16<LittleEndian>,
    need_ea_count: U16<LittleEndian>,
    unpacked_ea_size: U32<LittleEndian>,
}

/// Structure of a `$EA_INFORMATION` attribute (type 0xD0).
///
/// This attribute stores summary information about the extended
/// attributes associated with a file. It is always resident and
/// accompanies a `$EA` attribute when extended attributes are present.
///
/// Reference: [MS-FSCC] Section 2.4.13
#[derive(Clone, Debug)]
pub struct NtfsEaInformation {
    info: EaInformationData,
}

impl NtfsEaInformation {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        let required_size =
            u64::try_from(EA_INFORMATION_SIZE).expect("the fixed EA-information size fits u64");
        if value_length < required_size {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::EAInformation,
                expected: required_size,
                actual: value_length,
            });
        }

        let info = read_pod::<T, EaInformationData, EA_INFORMATION_SIZE>(r)?;

        Ok(Self { info })
    }

    /// Returns the combined packed size of all extended attributes,
    /// in bytes.
    #[must_use]
    pub fn packed_ea_size(&self) -> u16 {
        self.info.packed_ea_size.get()
    }

    /// Returns the number of extended attributes that have the
    /// `FILE_NEED_EA` flag set.
    #[must_use]
    pub fn need_ea_count(&self) -> u16 {
        self.info.need_ea_count.get()
    }

    /// Returns the combined unpacked size of all extended attributes,
    /// in bytes.
    #[must_use]
    pub fn unpacked_ea_size(&self) -> u32 {
        self.info.unpacked_ea_size.get()
    }
}

impl_structured_value_via_new!(NtfsEaInformation, NtfsAttributeType::EAInformation);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsEaInformation {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsEaInformation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; EA_INFORMATION_SIZE] = u.arbitrary()?;
        let info = EaInformationData::read_from_bytes(&bytes)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self { info })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ea_information_parse_valid() {
        // packed_ea_size = 0x0020 (32)
        // need_ea_count  = 0x0001 (1)
        // unpacked_ea_size = 0x00000040 (64)
        let data: [u8; 8] = [
            0x20, 0x00, // packed_ea_size
            0x01, 0x00, // need_ea_count
            0x40, 0x00, 0x00, 0x00, // unpacked_ea_size
        ];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea_info = NtfsEaInformation::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA-information length fits u64"),
        )
        .expect("should parse valid EA_INFORMATION");

        assert_eq!(ea_info.packed_ea_size(), 32);
        assert_eq!(ea_info.need_ea_count(), 1);
        assert_eq!(ea_info.unpacked_ea_size(), 64);
    }

    #[test]
    fn test_ea_information_size_validation() {
        let short_data = [0u8; 4];
        let mut cursor = ReadOnlyCursor::new(&short_data);
        let result = NtfsEaInformation::new(
            &mut cursor,
            NtfsPosition::new(0x100),
            u64::try_from(short_data.len()).expect("test EA-information length fits u64"),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_ea_information_accessor_values() {
        // packed_ea_size = 0xFF00 (65280)
        // need_ea_count  = 0x0003 (3)
        // unpacked_ea_size = 0x0001_0000 (65536)
        let data: [u8; 8] = [
            0x00, 0xFF, // packed_ea_size
            0x03, 0x00, // need_ea_count
            0x00, 0x00, 0x01, 0x00, // unpacked_ea_size
        ];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea_info = NtfsEaInformation::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA-information length fits u64"),
        )
        .expect("should parse valid EA_INFORMATION");

        assert_eq!(ea_info.packed_ea_size(), 0xFF00);
        assert_eq!(ea_info.need_ea_count(), 3);
        assert_eq!(ea_info.unpacked_ea_size(), 0x0001_0000);
    }

    #[test]
    fn test_ea_information_zero_values() {
        let data = [0u8; 8];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ea_info = NtfsEaInformation::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(data.len()).expect("test EA-information length fits u64"),
        )
        .expect("should parse zero-filled EA_INFORMATION");

        assert_eq!(ea_info.packed_ea_size(), 0);
        assert_eq!(ea_info.need_ea_count(), 0);
        assert_eq!(ea_info.unpacked_ea_size(), 0);
    }
}
