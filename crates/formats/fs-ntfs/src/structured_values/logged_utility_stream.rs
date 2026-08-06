use alloc::vec;
use alloc::vec::Vec;

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::ReadOnlyCursor;
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Maximum size for logged utility stream data (256KB).
///
/// `$LOGGED_UTILITY_STREAM` can be non-resident and may hold substantial
/// EFS metadata (DDF/DRF entries with multiple recovery certificates).
/// 256KB is a generous upper bound that rejects obviously corrupt values.
const MAX_LOGGED_UTILITY_STREAM_SIZE: u64 = 256 * 1024;

/// Structure of a `$LOGGED_UTILITY_STREAM` attribute (type 0x100).
///
/// This attribute is a generic container used by multiple NTFS subsystems:
/// - **EFS** stores encryption metadata (DDF/DRF headers, certificate hashes)
///   in a stream named `$EFS`.
/// - **`TxF`** stores transaction log data in `$Extend\$RmMetadata` and
///   related system files.
///
/// This parser stores the raw bytes for forensic access without
/// interpreting EFS or `TxF` internal formats.
///
/// Reference: MS-FSCC Section 5 (NTFS Attribute Types)
#[derive(Clone, Debug)]
pub struct NtfsLoggedUtilityStream {
    data: Vec<u8>,
    position: NtfsPosition,
}

impl NtfsLoggedUtilityStream {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length > MAX_LOGGED_UTILITY_STREAM_SIZE {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::LoggedUtilityStream,
                expected: MAX_LOGGED_UTILITY_STREAM_SIZE,
                actual: value_length,
            });
        }

        let len = usize::try_from(value_length)
            .expect("validated logged utility stream size fits in usize");
        let mut data = vec![0u8; len];
        r.read_exact(&mut data)?;

        Ok(Self { data, position })
    }

    /// Returns the absolute byte position of this attribute in the NTFS
    /// image, or `NtfsPosition::none()` if the position is unknown.
    #[must_use]
    pub fn position(&self) -> NtfsPosition {
        self.position
    }

    /// Returns the raw stream data as a byte slice.
    ///
    /// The internal format depends on the stream name: `$EFS` streams
    /// contain EFS encryption metadata, while `TxF` streams contain
    /// transaction log data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length of the stream data in bytes.
    #[must_use]
    pub fn data_length(&self) -> usize {
        self.data.len()
    }

    /// Interprets this stream as EFS (`$EFS`) metadata.
    ///
    /// This is only meaningful when the `$LOGGED_UTILITY_STREAM` attribute
    /// is named `$EFS`; callers should check the attribute name first.
    /// `TxF` (`$TXF_DATA`) and other named streams use unrelated formats.
    ///
    /// Reference: MS-EFSR Section 2.2.2.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is not valid EFS metadata.
    pub fn parse_efs(&self) -> Result<crate::structured_values::NtfsEfsMetadata> {
        crate::structured_values::NtfsEfsMetadata::parse(&self.data, self.position)
    }

    /// Interprets this stream as `TxF` (`$TXF_DATA`) per-file metadata.
    ///
    /// This is only meaningful when the `$LOGGED_UTILITY_STREAM`
    /// attribute is named `$TXF_DATA`; callers should check the
    /// attribute name first. EFS (`$EFS`) streams use an unrelated
    /// format.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is truncated or is not valid `$TXF_DATA`
    /// metadata.
    pub fn parse_txf(&self) -> Result<crate::structured_values::NtfsTxfData> {
        crate::structured_values::NtfsTxfData::parse(&self.data, self.position)
    }
}

impl_structured_value_via_new!(
    NtfsLoggedUtilityStream,
    NtfsAttributeType::LoggedUtilityStream
);

impl<'f> NtfsStructuredValueFromResidentAttributeValue<'_, 'f> for NtfsLoggedUtilityStream {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsLoggedUtilityStream {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let len = u.int_in_range(0..=1024_usize)?;
        let bytes = u.bytes(len)?;
        Ok(Self {
            data: bytes.to_vec(),
            position: NtfsPosition::none(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_data() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::new(0x400),
            u64::try_from(data.len()).expect("test stream length fits u64"),
        )
        .expect("should parse valid data");

        assert_eq!(lus.data(), &data);
        assert_eq!(lus.data_length(), 8);
        assert_eq!(lus.position(), NtfsPosition::new(0x400));
    }

    #[test]
    fn parse_empty() {
        let data: [u8; 0] = [];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(&mut cursor, NtfsPosition::none(), 0)
            .expect("should parse empty stream");

        assert!(lus.data().is_empty());
        assert_eq!(lus.data_length(), 0);
    }

    #[test]
    fn reject_oversized() {
        let data = [0u8; 8];
        let mut cursor = ReadOnlyCursor::new(&data);
        let result = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::new(0x200),
            MAX_LOGGED_UTILITY_STREAM_SIZE + 1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn accept_max_size() {
        let data = vec![
            0xCDu8;
            usize::try_from(MAX_LOGGED_UTILITY_STREAM_SIZE)
                .expect("test value fits usize")
        ];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::none(),
            MAX_LOGGED_UTILITY_STREAM_SIZE,
        )
        .expect("should parse max-size stream");

        assert_eq!(
            lus.data_length(),
            usize::try_from(MAX_LOGGED_UTILITY_STREAM_SIZE).expect("test value fits usize")
        );
    }

    #[test]
    fn max_size_is_256_kib() {
        // 256 * 1024 = 262144. Pins the `*` against `+` (256+1024=1280).
        assert_eq!(MAX_LOGGED_UTILITY_STREAM_SIZE, 262_144);
    }

    #[test]
    fn accept_size_above_mutated_limit() {
        // 2000 bytes is well within the real 256 KiB limit but ABOVE the
        // value the `* -> +` mutant would compute (256 + 1024 = 1280), so a
        // mutated limit would wrongly reject this otherwise-valid stream.
        let len = 2000u64;
        let data = vec![0x42u8; usize::try_from(len).expect("test value fits usize")];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(&mut cursor, NtfsPosition::none(), len)
            .expect("2000-byte stream is within the 256 KiB limit");
        assert_eq!(lus.data_length(), 2000);
    }

    #[test]
    fn parse_efs_interprets_v1_metadata() {
        // Minimal 84-byte V1 header: EFS_Version 2, DDF key list at 0x54
        // with a zero entry count and no DRF.
        let mut data = vec![0u8; 0x54 + 4];
        data[0x08..0x0C].copy_from_slice(&2u32.to_le_bytes());
        data[0x40..0x44].copy_from_slice(&0x54u32.to_le_bytes());

        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::new(0x400),
            u64::try_from(data.len()).expect("test stream length fits u64"),
        )
        .expect("should parse logged utility stream");

        let efs = lus.parse_efs().expect("should interpret $EFS metadata");
        assert_eq!(efs.efs_version(), 2);
    }

    #[test]
    fn parse_efs_rejects_non_efs_bytes() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(&mut cursor, NtfsPosition::none(), 4)
            .expect("should parse logged utility stream");
        assert!(lus.parse_efs().is_err());
    }

    #[test]
    fn preserves_bytes() {
        // Simulate plausible EFS header bytes
        let data: Vec<u8> = (0..64).collect();
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::new(0x800),
            u64::try_from(data.len()).expect("test stream length fits u64"),
        )
        .expect("should preserve all bytes");

        assert_eq!(lus.data(), data.as_slice());
    }

    #[test]
    fn parse_txf_interprets_txf_data() {
        // 56-byte $TXF_DATA with TxID at offset 22.
        let mut data = vec![0u8; 56];
        data[22..30].copy_from_slice(&0x1234_5678u64.to_le_bytes());

        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(
            &mut cursor,
            NtfsPosition::new(0x600),
            u64::try_from(data.len()).expect("test stream length fits u64"),
        )
        .expect("should parse logged utility stream");

        let txf = lus.parse_txf().expect("should interpret $TXF_DATA");
        assert_eq!(txf.txf_id(), 0x1234_5678);
    }

    #[test]
    fn parse_txf_rejects_short_stream() {
        let data = [0u8; 16];
        let mut cursor = ReadOnlyCursor::new(&data);
        let lus = NtfsLoggedUtilityStream::new(&mut cursor, NtfsPosition::none(), 16)
            .expect("should parse logged utility stream");
        assert!(lus.parse_txf().is_err());
    }
}
