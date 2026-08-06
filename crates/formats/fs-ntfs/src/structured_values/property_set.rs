use arrayvec::ArrayVec;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::ReadOnlyCursor;
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Maximum size for property set data (4KB).
///
/// `$PROPERTY_SET` is marked `ALWAYS_RESIDENT` in `$AttrDef`, so it must fit
/// inside an MFT record (typically 1KB, at most 4KB). 4KB is therefore a safe
/// upper bound that accommodates the largest possible MFT record size.
const MAX_PROPERTY_SET_SIZE: usize = 4096;

/// Structure of a `$PROPERTY_SET` attribute (type 0xF0).
///
/// This is an obsolete NTFS attribute that was used in NTFS v1.2
/// (Windows NT 4.0) for storing OLE structured storage property sets
/// directly as file attributes. Modern NTFS volumes use named alternate
/// data streams (with the ♣ prefix) instead.
///
/// The raw data follows the OLE Property Set format (MS-OLEPS).
/// This parser stores the raw bytes for forensic access without
/// interpreting the OLE structure.
///
/// Reference: MS-FSCC Section 5.6 (marked "Obsolete")
#[derive(Clone, Debug)]
pub struct NtfsPropertySet {
    data: ArrayVec<u8, MAX_PROPERTY_SET_SIZE>,
}

impl NtfsPropertySet {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length > MAX_PROPERTY_SET_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::PropertySet,
                expected: MAX_PROPERTY_SET_SIZE as u64,
                actual: value_length,
            });
        }

        let value_length = value_length as usize;

        let mut data = ArrayVec::from([0u8; MAX_PROPERTY_SET_SIZE]);
        r.read_exact(&mut data[..value_length])?;
        data.truncate(value_length);

        Ok(Self { data })
    }

    /// Returns the raw property set data as a byte slice.
    ///
    /// The data follows the OLE Property Set format (MS-OLEPS).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the property set data in bytes.
    pub fn data_length(&self) -> usize {
        self.data.len()
    }
}

impl_structured_value_via_new!(NtfsPropertySet, NtfsAttributeType::PropertySet);

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsPropertySet {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsPropertySet {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.arbitrary::<u16>()? as usize % (MAX_PROPERTY_SET_SIZE + 1);
        let mut data = ArrayVec::new();
        for _ in 0..len {
            data.push(u.arbitrary()?);
        }
        Ok(Self { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_set_parse_valid() {
        // Minimal data — just some raw bytes
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ps = NtfsPropertySet::new(&mut cursor, NtfsPosition::none(), data.len() as u64)
            .expect("should parse valid property set");

        assert_eq!(ps.data(), &data);
        assert_eq!(ps.data_length(), 8);
    }

    #[test]
    fn test_property_set_empty() {
        let data: [u8; 0] = [];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ps = NtfsPropertySet::new(&mut cursor, NtfsPosition::none(), 0)
            .expect("should parse empty property set");

        assert!(ps.data().is_empty());
        assert_eq!(ps.data_length(), 0);
    }

    #[test]
    fn test_property_set_too_large() {
        let data = [0u8; 8];
        let mut cursor = ReadOnlyCursor::new(&data);
        let result = NtfsPropertySet::new(
            &mut cursor,
            NtfsPosition::new(0x200),
            (MAX_PROPERTY_SET_SIZE as u64) + 1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_property_set_max_size() {
        let data = [0xABu8; MAX_PROPERTY_SET_SIZE];
        let mut cursor = ReadOnlyCursor::new(&data);
        let ps = NtfsPropertySet::new(
            &mut cursor,
            NtfsPosition::none(),
            MAX_PROPERTY_SET_SIZE as u64,
        )
        .expect("should parse max-size property set");

        assert_eq!(ps.data_length(), MAX_PROPERTY_SET_SIZE);
        assert!(ps.data().iter().all(|&b| b == 0xAB));
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_property_set_arbitrary_length_bound() {
        // Deterministic Unstructured: all 0xFF. The first two bytes form the u16
        // value 0xFFFF = 65535. The arbitrary impl computes
        // len = 65535 % (MAX_PROPERTY_SET_SIZE + 1) = 65535 % 4097 = 4080.
        // The surviving mutations on line 88 produce different lengths:
        //   `% with /`  -> 65535 / 4097           = 15
        //   `+ with *`  -> 65535 % (4096 * 1)      = 4095
        //   `+ with -`  -> 65535 % (4096 - 1)      = 15
        // All differ from the genuine 4080, so this assertion kills every variant.
        let buf = [0xFFu8; 8192];
        let mut u = arbitrary::Unstructured::new(&buf);
        let ps = <NtfsPropertySet as arbitrary::Arbitrary>::arbitrary(&mut u)
            .expect("arbitrary property set");
        assert_eq!(ps.data_length(), 65535 % (MAX_PROPERTY_SET_SIZE + 1));
        assert_eq!(ps.data_length(), 4080);
    }

    #[test]
    fn test_property_set_preserves_bytes() {
        // Simulate an OLE property set header (first 28 bytes)
        let mut data = [0u8; 28];
        // Byte order mark (0xFFFE = little-endian)
        data[0] = 0xFE;
        data[1] = 0xFF;
        // Format version (0x0000)
        data[2] = 0x00;
        data[3] = 0x00;
        // OS version
        data[4] = 0x06;
        data[5] = 0x00;
        data[6] = 0x02;
        data[7] = 0x00;
        // CLSID (16 bytes of zeros)
        // Number of sections = 1
        data[24] = 0x01;
        data[25] = 0x00;
        data[26] = 0x00;
        data[27] = 0x00;

        let mut cursor = ReadOnlyCursor::new(&data);
        let ps = NtfsPropertySet::new(&mut cursor, NtfsPosition::none(), data.len() as u64)
            .expect("should parse OLE-like property set");

        assert_eq!(ps.data(), &data);
        assert_eq!(ps.data()[0..2], [0xFE, 0xFF]);
    }
}
