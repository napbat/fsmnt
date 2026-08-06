use core::fmt;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U64, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of all [`VolumeInformationData`] fields.
const VOLUME_INFORMATION_SIZE: usize = 12;

#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct VolumeInformationData {
    _reserved: U64<LittleEndian>,
    major_version: u8,
    minor_version: u8,
    flags: U16<LittleEndian>,
}

bitflags! {
    /// Flags returned by [`NtfsVolumeInformation::flags`].
    ///
    /// Spec reference: MS-FSCC Section 2.5.10 (FileFsVolumeInformation).
    #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct NtfsVolumeFlags: u16 {
        /// The volume needs to be checked by `chkdsk`.
        const IS_DIRTY = 0x0001;
        const RESIZE_LOG_FILE = 0x0002;
        const UPGRADE_ON_MOUNT = 0x0004;
        const MOUNTED_ON_NT4 = 0x0008;
        const DELETE_USN_UNDERWAY = 0x0010;
        const REPAIR_OBJECT_ID = 0x0020;
        const CHKDSK_UNDERWAY = 0x4000;
        const MODIFIED_BY_CHKDSK = 0x8000;
    }
}

impl fmt::Display for NtfsVolumeFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsVolumeFlags {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bits: u16 = u.arbitrary()?;
        Ok(Self::from_bits_truncate(bits))
    }
}

/// Structure of a $VOLUME_INFORMATION attribute.
///
/// This attribute is only used by the top-level $Volume file and contains general information about the filesystem.
/// You can easily access it via [`Ntfs::volume_info`].
///
/// A $VOLUME_INFORMATION attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/volume_information.html>
///
/// Spec reference: MS-FSCC Section 2.5.10 (FileFsVolumeInformation).
///
/// [`Ntfs::volume_info`]: crate::Ntfs::volume_info
#[derive(Clone, Debug)]
pub struct NtfsVolumeInformation {
    info: VolumeInformationData,
}

impl NtfsVolumeInformation {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length < VOLUME_INFORMATION_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::VolumeInformation,
                expected: VOLUME_INFORMATION_SIZE as u64,
                actual: value_length,
            });
        }

        let info = read_pod::<T, VolumeInformationData, VOLUME_INFORMATION_SIZE>(r)?;

        Ok(Self { info })
    }

    /// Returns flags set for this NTFS filesystem/volume as specified by [`NtfsVolumeFlags`].
    pub fn flags(&self) -> NtfsVolumeFlags {
        NtfsVolumeFlags::from_bits_truncate(self.info.flags.get())
    }

    /// Returns the major NTFS version of this filesystem (e.g. `3` for NTFS 3.1).
    pub fn major_version(&self) -> u8 {
        self.info.major_version
    }

    /// Returns the minor NTFS version of this filesystem (e.g. `1` for NTFS 3.1).
    pub fn minor_version(&self) -> u8 {
        self.info.minor_version
    }
}

impl_structured_value_via_new!(NtfsVolumeInformation, NtfsAttributeType::VolumeInformation);

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsVolumeInformation {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsVolumeInformation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; VOLUME_INFORMATION_SIZE] = u.arbitrary()?;
        let info = VolumeInformationData::read_from_bytes(&bytes)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;
        Ok(Self { info })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::ntfs::Ntfs;

    #[test]
    fn test_volume_information_accessors() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let vol_info = ntfs.volume_info(&mut testfs1).unwrap();

        // testfs1 is NTFS 3.1 (created by mkntfs 3.1)
        assert_eq!(vol_info.major_version(), 3);
        assert_eq!(vol_info.minor_version(), 1);
    }

    #[test]
    fn test_volume_flags() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let vol_info = ntfs.volume_info(&mut testfs1).unwrap();

        let flags = vol_info.flags();
        // A clean test image should not have destructive flags set.
        assert!(!flags.contains(NtfsVolumeFlags::CHKDSK_UNDERWAY));
        assert!(!flags.contains(NtfsVolumeFlags::UPGRADE_ON_MOUNT));
    }

    #[test]
    fn test_volume_information_from_attribute() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // Access $Volume directly (MFT entry 3) and find VolumeInformation attribute.
        let volume_file = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::Volume as u64)
            .unwrap();
        let mut attrs = volume_file.attributes_raw();

        // Find the VolumeInformation attribute.
        let vi_attr = loop {
            let attr = attrs.next().unwrap().unwrap();
            if attr.ty().unwrap() == NtfsAttributeType::VolumeInformation {
                break attr;
            }
        };

        assert!(vi_attr.is_resident());
        let vol_info = vi_attr
            .resident_structured_value::<NtfsVolumeInformation>()
            .unwrap();
        assert_eq!(vol_info.major_version(), 3);
        assert_eq!(vol_info.minor_version(), 1);
    }

    #[test]
    fn test_volume_information_size_validation() {
        // A buffer shorter than VOLUME_INFORMATION_SIZE should fail.
        let short_data = [0u8; 4];
        let mut cursor = crate::helpers::ReadOnlyCursor::new(&short_data);
        let result = NtfsVolumeInformation::new(
            &mut cursor,
            NtfsPosition::new(100),
            short_data.len() as u64,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_volume_flags_display() {
        let flags = NtfsVolumeFlags::IS_DIRTY | NtfsVolumeFlags::CHKDSK_UNDERWAY;
        let s = format!("{flags}");
        // Display is implemented via bitflags, just verify it doesn't panic.
        assert!(!s.is_empty());
    }

    /// Builds a 12-byte $VOLUME_INFORMATION value (MS-FSCC 2.5.10):
    /// 8-byte reserved, major_version (u8), minor_version (u8), flags (u16).
    fn build_volume_information(major: u8, minor: u8, flags: u16) -> [u8; VOLUME_INFORMATION_SIZE] {
        let mut buf = [0u8; VOLUME_INFORMATION_SIZE];
        buf[8] = major;
        buf[9] = minor;
        buf[10..12].copy_from_slice(&flags.to_le_bytes());
        buf
    }

    #[test]
    fn test_volume_information_versions_from_synthetic_bytes() {
        // major=3, minor=1 are distinct and neither 0 nor 1 collision-wise:
        // major 3 distinguishes the accessor from the 0/1 replacements,
        // minor 1 differs from major and from 0.
        let buf = build_volume_information(3, 1, 0x0001);
        let mut cursor = crate::helpers::ReadOnlyCursor::new(&buf);
        let vol_info =
            NtfsVolumeInformation::new(&mut cursor, NtfsPosition::new(0x200), buf.len() as u64)
                .unwrap();

        assert_eq!(vol_info.major_version(), 3);
        assert_eq!(vol_info.minor_version(), 1);
        assert!(vol_info.flags().contains(NtfsVolumeFlags::IS_DIRTY));
    }

    #[test]
    fn test_volume_information_distinct_versions() {
        // Use major=7, minor=2 so both accessors return values distinct from
        // each other and from 0/1, killing the "return 0" / "return 1" mutants
        // for both fields independently.
        let buf = build_volume_information(7, 2, 0);
        let mut cursor = crate::helpers::ReadOnlyCursor::new(&buf);
        let vol_info =
            NtfsVolumeInformation::new(&mut cursor, NtfsPosition::none(), buf.len() as u64)
                .unwrap();
        assert_eq!(vol_info.major_version(), 7);
        assert_eq!(vol_info.minor_version(), 2);
    }
}
