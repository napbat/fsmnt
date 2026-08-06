use core::mem;

use arrayvec::ArrayVec;
use nt_string::u16strle::U16StrLe;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::ReadOnlyCursor;
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// The largest `VolumeName` attribute has a name containing 128 UTF-16 code points (256 bytes).
const VOLUME_NAME_MAX_SIZE: usize = 128 * mem::size_of::<u16>();
const VOLUME_NAME_MAX_SIZE_U64: u64 = 128 * 2;

/// Structure of a $`VOLUME_NAME` attribute.
///
/// This attribute is only used by the top-level $Volume file and contains the user-defined name of this filesystem.
/// You can easily access it via [`Ntfs::volume_name`].
///
/// A $`VOLUME_NAME` attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/volume_name.html>
///
/// Spec reference: MS-FSCC Section 2.5.10 (`FileFsVolumeInformation`).
///
/// [`Ntfs::volume_name`]: crate::Ntfs::volume_name
#[derive(Clone, Debug)]
pub struct NtfsVolumeName {
    name: ArrayVec<u8, VOLUME_NAME_MAX_SIZE>,
}

impl NtfsVolumeName {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length > VOLUME_NAME_MAX_SIZE_U64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::VolumeName,
                expected: VOLUME_NAME_MAX_SIZE_U64,
                actual: value_length,
            });
        }

        let value_length =
            usize::try_from(value_length).expect("validated volume name size fits in usize");

        let mut name = ArrayVec::from([0u8; VOLUME_NAME_MAX_SIZE]);
        r.read_exact(&mut name[..value_length])?;
        name.truncate(value_length);

        Ok(Self { name })
    }

    /// Gets the volume name and returns it wrapped in a [`U16StrLe`].
    #[must_use]
    pub fn name(&self) -> U16StrLe<'_> {
        U16StrLe(&self.name)
    }

    /// Returns the volume name length, in bytes.
    ///
    /// A volume name has a maximum length of 128 UTF-16 code points (256 bytes).
    #[must_use]
    pub fn name_length(&self) -> usize {
        self.name.len()
    }
}

impl_structured_value_via_new!(NtfsVolumeName, NtfsAttributeType::VolumeName);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsVolumeName {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsVolumeName {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        // Generate an even-length name (UTF-16 requires pairs of bytes)
        let len_u16: u8 = u.arbitrary()?;
        let len = (usize::from(len_u16) % (VOLUME_NAME_MAX_SIZE / 2 + 1)) * 2;
        let mut name = ArrayVec::new();
        for _ in 0..len {
            name.push(u.arbitrary()?);
        }
        Ok(Self { name })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volume_name_max_size_is_256() {
        // 128 UTF-16 code points * 2 bytes = 256. Pins the `* size_of::<u16>()`
        // computation (128+2=130 or 128/2=64 would differ).
        assert_eq!(VOLUME_NAME_MAX_SIZE, 256);
    }

    #[test]
    fn test_volume_name_parses_and_reports_length() {
        // "AB" in UTF-16LE = 4 bytes.
        let data = [b'A', 0, b'B', 0];
        let mut cursor = ReadOnlyCursor::new(&data);
        let vn = NtfsVolumeName::new(
            &mut cursor,
            NtfsPosition::new(0x100),
            u64::try_from(data.len()).expect("test volume-name length fits u64"),
        )
        .expect("valid volume name");
        // name_length is the genuine byte count (4), distinct from 0/1.
        assert_eq!(vn.name_length(), 4);
        assert_eq!(vn.name().to_string().unwrap(), "AB");
    }

    #[test]
    fn test_volume_name_empty_has_zero_length() {
        let data: [u8; 0] = [];
        let mut cursor = ReadOnlyCursor::new(&data);
        let vn = NtfsVolumeName::new(&mut cursor, NtfsPosition::none(), 0)
            .expect("valid empty volume name");
        assert_eq!(vn.name_length(), 0);
    }

    #[test]
    fn test_volume_name_accepts_max_size() {
        // Exactly VOLUME_NAME_MAX_SIZE (256) bytes is accepted.
        let data = alloc::vec![0u8; VOLUME_NAME_MAX_SIZE];
        let mut cursor = ReadOnlyCursor::new(&data);
        let vn = NtfsVolumeName::new(
            &mut cursor,
            NtfsPosition::none(),
            u64::try_from(VOLUME_NAME_MAX_SIZE).expect("volume-name size limit fits u64"),
        )
        .expect("max-size volume name should parse");
        assert_eq!(vn.name_length(), VOLUME_NAME_MAX_SIZE);
    }

    #[test]
    fn test_volume_name_rejects_oversized() {
        // One byte over the 256-byte limit is rejected.
        let data = alloc::vec![0u8; VOLUME_NAME_MAX_SIZE + 1];
        let mut cursor = ReadOnlyCursor::new(&data);
        let result = NtfsVolumeName::new(
            &mut cursor,
            NtfsPosition::new(0x200),
            u64::try_from(VOLUME_NAME_MAX_SIZE).expect("volume-name size limit fits u64") + 1,
        );
        assert!(matches!(
            result,
            Err(NtfsError::InvalidStructuredValueSize { .. })
        ));
    }

    #[cfg(feature = "arbitrary")]
    #[test]
    fn test_volume_name_arbitrary_length_is_bounded_and_even() {
        use arbitrary::Arbitrary;

        // Drive the Arbitrary impl across all u8 length seeds and confirm the
        // generated name is always even-length and within bounds. This pins
        // the `% (MAX/2 + 1) * 2` arithmetic: any operator swap would either
        // overflow the ArrayVec capacity (panic) or produce an odd length.
        for seed in 0u8..=255 {
            // Generous buffer: the first byte seeds the length, the rest feed
            // the name bytes so generation never short-circuits.
            let mut bytes = alloc::vec![0u8; 512];
            bytes[0] = seed;
            let mut u = arbitrary::Unstructured::new(&bytes);
            let vn = NtfsVolumeName::arbitrary(&mut u).expect("arbitrary name");
            // `(seed % 129) * 2`: exact expected length pins every operator.
            let expected = (usize::from(seed) % (VOLUME_NAME_MAX_SIZE / 2 + 1)) * 2;
            assert_eq!(vn.name_length(), expected);
            assert!(vn.name_length() <= VOLUME_NAME_MAX_SIZE);
            assert_eq!(vn.name_length() % 2, 0, "name length must be even");
        }
    }
}
