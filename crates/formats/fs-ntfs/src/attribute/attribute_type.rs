use strum_macros::Display;

/// All known NTFS Attribute types.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/index.html>
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[repr(u32)]
pub enum NtfsAttributeType {
    /// $`STANDARD_INFORMATION`, see [`NtfsStandardInformation`].
    ///
    /// [`NtfsStandardInformation`]: crate::structured_values::NtfsStandardInformation
    StandardInformation = 0x10,
    /// $`ATTRIBUTE_LIST`, see [`NtfsAttributeList`].
    ///
    /// [`NtfsAttributeList`]: crate::structured_values::NtfsAttributeList
    AttributeList = 0x20,
    /// $`FILE_NAME`, see [`NtfsFileName`].
    ///
    /// [`NtfsFileName`]: crate::structured_values::NtfsFileName
    FileName = 0x30,
    /// $`OBJECT_ID`, see [`NtfsObjectId`].
    ///
    /// [`NtfsObjectId`]: crate::structured_values::NtfsObjectId
    ObjectId = 0x40,
    /// $`SECURITY_DESCRIPTOR`
    SecurityDescriptor = 0x50,
    /// $`VOLUME_NAME`, see [`NtfsVolumeName`].
    ///
    /// [`NtfsVolumeName`]: crate::structured_values::NtfsVolumeName
    VolumeName = 0x60,
    /// $`VOLUME_INFORMATION`, see [`NtfsVolumeInformation`].
    ///
    /// [`NtfsVolumeInformation`]: crate::structured_values::NtfsVolumeInformation
    VolumeInformation = 0x70,
    /// $DATA, see [`NtfsFile::data`].
    ///
    /// [`NtfsFile::data`]: crate::file::NtfsFile::data
    Data = 0x80,
    /// $`INDEX_ROOT`, see [`NtfsIndexRoot`].
    ///
    /// [`NtfsIndexRoot`]: crate::structured_values::NtfsIndexRoot
    IndexRoot = 0x90,
    /// $`INDEX_ALLOCATION`, see [`NtfsIndexAllocation`].
    ///
    /// [`NtfsIndexAllocation`]: crate::structured_values::NtfsIndexAllocation
    IndexAllocation = 0xA0,
    /// $BITMAP
    Bitmap = 0xB0,
    /// $`REPARSE_POINT`
    ReparsePoint = 0xC0,
    /// $`EA_INFORMATION`
    EAInformation = 0xD0,
    /// $EA
    EA = 0xE0,
    /// $`PROPERTY_SET`, see [`NtfsPropertySet`].
    ///
    /// [`NtfsPropertySet`]: crate::structured_values::NtfsPropertySet
    PropertySet = 0xF0,
    /// $`LOGGED_UTILITY_STREAM`, see [`NtfsLoggedUtilityStream`].
    ///
    /// [`NtfsLoggedUtilityStream`]: crate::structured_values::NtfsLoggedUtilityStream
    LoggedUtilityStream = 0x100,
    /// Marks the end of the valid attributes.
    End = 0xFFFF_FFFF,
}

impl NtfsAttributeType {
    /// Returns the numeric type code stored in an NTFS attribute header.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::StandardInformation => 0x10,
            Self::AttributeList => 0x20,
            Self::FileName => 0x30,
            Self::ObjectId => 0x40,
            Self::SecurityDescriptor => 0x50,
            Self::VolumeName => 0x60,
            Self::VolumeInformation => 0x70,
            Self::Data => 0x80,
            Self::IndexRoot => 0x90,
            Self::IndexAllocation => 0xA0,
            Self::Bitmap => 0xB0,
            Self::ReparsePoint => 0xC0,
            Self::EAInformation => 0xD0,
            Self::EA => 0xE0,
            Self::PropertySet => 0xF0,
            Self::LoggedUtilityStream => 0x100,
            Self::End => 0xFFFF_FFFF,
        }
    }

    /// Converts an on-disk attribute type code into a known NTFS type.
    ///
    /// Returns `None` when the code is not assigned by the NTFS format.
    #[must_use]
    pub fn n(value: u32) -> Option<Self> {
        match value {
            0x10 => Some(Self::StandardInformation),
            0x20 => Some(Self::AttributeList),
            0x30 => Some(Self::FileName),
            0x40 => Some(Self::ObjectId),
            0x50 => Some(Self::SecurityDescriptor),
            0x60 => Some(Self::VolumeName),
            0x70 => Some(Self::VolumeInformation),
            0x80 => Some(Self::Data),
            0x90 => Some(Self::IndexRoot),
            0xA0 => Some(Self::IndexAllocation),
            0xB0 => Some(Self::Bitmap),
            0xC0 => Some(Self::ReparsePoint),
            0xD0 => Some(Self::EAInformation),
            0xE0 => Some(Self::EA),
            0xF0 => Some(Self::PropertySet),
            0x100 => Some(Self::LoggedUtilityStream),
            0xFFFF_FFFF => Some(Self::End),
            _ => None,
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsAttributeType {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let variants = [
            NtfsAttributeType::StandardInformation,
            NtfsAttributeType::AttributeList,
            NtfsAttributeType::FileName,
            NtfsAttributeType::ObjectId,
            NtfsAttributeType::SecurityDescriptor,
            NtfsAttributeType::VolumeName,
            NtfsAttributeType::VolumeInformation,
            NtfsAttributeType::Data,
            NtfsAttributeType::IndexRoot,
            NtfsAttributeType::IndexAllocation,
            NtfsAttributeType::Bitmap,
            NtfsAttributeType::ReparsePoint,
            NtfsAttributeType::EAInformation,
            NtfsAttributeType::EA,
            NtfsAttributeType::PropertySet,
            NtfsAttributeType::LoggedUtilityStream,
            NtfsAttributeType::End,
        ];
        let index: usize = u.arbitrary()?;
        Ok(variants[index % variants.len()])
    }
}
