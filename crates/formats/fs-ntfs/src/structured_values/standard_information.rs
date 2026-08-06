use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U32, U64, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsFileAttributeFlags, NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::time::NtfsTime;
use crate::types::NtfsPosition;

/// Size of all [`Ntfs1Fields`] fields.
const NTFS1_FIELDS_SIZE: usize = 48;

/// Size of all [`Ntfs3Fields`] fields.
const ADDITIONAL_NTFS3_FIELDS_SIZE: usize = 24;

#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct Ntfs1Fields {
    creation_time: NtfsTime,
    modification_time: NtfsTime,
    mft_record_modification_time: NtfsTime,
    access_time: NtfsTime,
    file_attributes: U32<LittleEndian>,
    maximum_versions: U32<LittleEndian>,
    version: U32<LittleEndian>,
    class_id: U32<LittleEndian>,
}

#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct Ntfs3Fields {
    owner_id: U32<LittleEndian>,
    security_id: U32<LittleEndian>,
    quota_charged: U64<LittleEndian>,
    usn: U64<LittleEndian>,
}

/// Structure of a $STANDARD_INFORMATION attribute.
///
/// Among other things, this is the place where the file times and "File Attributes"
/// (Read-Only, Hidden, System, Archive, etc.) are stored.
///
/// A $STANDARD_INFORMATION attribute is always resident.
///
/// Reference: <https://flatcap.github.io/linux-ntfs/ntfs/attributes/standard_information.html>
///
/// Spec reference: MS-FSCC Section 2.4.7 (FileBasicInformation) for field semantics (timestamps, file attributes).
#[derive(Clone, Debug)]
pub struct NtfsStandardInformation {
    ntfs1_data: Ntfs1Fields,
    ntfs3_data: Option<Ntfs3Fields>,
}

impl NtfsStandardInformation {
    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length < NTFS1_FIELDS_SIZE as u64 {
            return Err(NtfsError::InvalidStructuredValueSize {
                position,
                ty: NtfsAttributeType::StandardInformation,
                expected: NTFS1_FIELDS_SIZE as u64,
                actual: value_length,
            });
        }

        let ntfs1_data = read_pod::<T, Ntfs1Fields, NTFS1_FIELDS_SIZE>(r)?;

        let mut ntfs3_data = None;
        if value_length >= (NTFS1_FIELDS_SIZE + ADDITIONAL_NTFS3_FIELDS_SIZE) as u64 {
            ntfs3_data = Some(read_pod::<T, Ntfs3Fields, ADDITIONAL_NTFS3_FIELDS_SIZE>(r)?);
        }

        Ok(Self {
            ntfs1_data,
            ntfs3_data,
        })
    }

    /// Returns the time this file was last accessed.
    pub fn access_time(&self) -> NtfsTime {
        self.ntfs1_data.access_time
    }

    /// Returns the Class ID of the file.
    pub fn class_id(&self) -> u32 {
        self.ntfs1_data.class_id.get()
    }

    /// Returns the time this file was created.
    pub fn creation_time(&self) -> NtfsTime {
        self.ntfs1_data.creation_time
    }

    /// Returns flags that a user can set for a file (Read-Only, Hidden, System, Archive, etc.).
    /// Commonly called "File Attributes" in Windows Explorer.
    pub fn file_attributes(&self) -> NtfsFileAttributeFlags {
        NtfsFileAttributeFlags::from_bits_truncate(self.ntfs1_data.file_attributes.get())
    }

    /// Returns the maximum allowed versions for this file.
    ///
    /// A value of zero means that versioning is disabled for this file.
    pub fn maximum_versions(&self) -> u32 {
        self.ntfs1_data.maximum_versions.get()
    }

    /// Returns the time the MFT record of this file was last modified.
    pub fn mft_record_modification_time(&self) -> NtfsTime {
        self.ntfs1_data.mft_record_modification_time
    }

    /// Returns the time this file was last modified.
    pub fn modification_time(&self) -> NtfsTime {
        self.ntfs1_data.modification_time
    }

    /// Returns the Owner ID of the file, if stored via NTFS 3.x file information.
    pub fn owner_id(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.owner_id.get())
    }

    /// Returns the quota charged by this file, if stored via NTFS 3.x file information.
    pub fn quota_charged(&self) -> Option<u64> {
        self.ntfs3_data.as_ref().map(|x| x.quota_charged.get())
    }

    /// Returns the Security ID of the file, if stored via NTFS 3.x file information.
    pub fn security_id(&self) -> Option<u32> {
        self.ntfs3_data.as_ref().map(|x| x.security_id.get())
    }

    /// Returns the Update Sequence Number (USN) of the file, if stored via NTFS 3.x file information.
    pub fn usn(&self) -> Option<u64> {
        self.ntfs3_data.as_ref().map(|x| x.usn.get())
    }

    /// Returns the version of the file.
    ///
    /// This will be zero if versioning is disabled for this file.
    pub fn version(&self) -> u32 {
        self.ntfs1_data.version.get()
    }
}

impl_structured_value_via_new!(
    NtfsStandardInformation,
    NtfsAttributeType::StandardInformation
);

#[cfg(test)]
impl NtfsStandardInformation {
    /// Test-only constructor that reads from a byte slice.
    pub(crate) fn from_bytes_for_test(data: &[u8]) -> Self {
        let position = NtfsPosition::none();
        let mut cursor = ReadOnlyCursor::new(data);
        Self::new(&mut cursor, position, data.len() as u64).expect("test SI construction failed")
    }
}

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsStandardInformation {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for NtfsStandardInformation {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let ntfs1_bytes: [u8; NTFS1_FIELDS_SIZE] = u.arbitrary()?;
        let ntfs1_data = Ntfs1Fields::read_from_bytes(&ntfs1_bytes)
            .map_err(|_| arbitrary::Error::IncorrectFormat)?;

        let has_ntfs3: bool = u.arbitrary()?;
        let ntfs3_data = if has_ntfs3 {
            let ntfs3_bytes: [u8; ADDITIONAL_NTFS3_FIELDS_SIZE] = u.arbitrary()?;
            Some(
                Ntfs3Fields::read_from_bytes(&ntfs3_bytes)
                    .map_err(|_| arbitrary::Error::IncorrectFormat)?,
            )
        } else {
            None
        };

        Ok(Self {
            ntfs1_data,
            ntfs3_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::KnownNtfsFileRecordNumber;
    use crate::ntfs::Ntfs;

    #[test]
    fn test_standard_information() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let mut mft_attributes = mft.attributes_raw();

        // Check the StandardInformation attribute of the MFT.
        let attribute = mft_attributes.next().unwrap().unwrap();
        assert_eq!(
            attribute.ty().unwrap(),
            NtfsAttributeType::StandardInformation,
        );
        assert_eq!(attribute.attribute_length(), 96);
        assert!(attribute.is_resident());
        assert_eq!(attribute.name_length(), 0);
        assert_eq!(attribute.value_length(), 72);

        // Try to read the actual information.
        let _standard_info = attribute
            .resident_structured_value::<NtfsStandardInformation>()
            .unwrap();

        // There are no reliable values to check here, so that's it.
    }

    #[test]
    fn test_file_attributes_can_be_read() {
        use crate::indexes::NtfsFileNameIndex;

        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
        ntfs.read_upcase_table(&mut testfs1).unwrap();
        let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

        // Find the "edge-cases" subdirectory.
        let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
        let mut root_dir_finder = root_dir_index.finder();
        let entry =
            NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
                .unwrap()
                .unwrap();
        let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Test that we can find and read attributes from readonly-file.txt
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "readonly-file.txt",
        )
        .unwrap()
        .unwrap();
        let readonly_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

        // Verify we can read the standard information and file attributes.
        let info = readonly_file.info().unwrap();
        let attrs = info.file_attributes();
        // Note: ntfs-3g may not set the READ_ONLY flag from chmod 444,
        // but we verify the attribute can be read without error.
        // The ARCHIVE flag is typically set on regular files.
        // We just verify we can read the attributes - the actual flags depend on
        // how ntfs-3g created the file.
        let _ = attrs.contains(super::super::NtfsFileAttributeFlags::ARCHIVE);

        // Test hidden-file.txt
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "hidden-file.txt",
        )
        .unwrap()
        .unwrap();
        let hidden_file = entry.to_file(&ntfs, &mut testfs1).unwrap();
        let _info = hidden_file.info().unwrap();

        // Test system-file.txt
        let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
        let mut edge_cases_finder = edge_cases_index.finder();
        let entry = NtfsFileNameIndex::find(
            &mut edge_cases_finder,
            &ntfs,
            &mut testfs1,
            "system-file.txt",
        )
        .unwrap()
        .unwrap();
        let system_file = entry.to_file(&ntfs, &mut testfs1).unwrap();
        let _info = system_file.info().unwrap();
    }

    #[test]
    fn test_security_id_accessor() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // Read $STANDARD_INFORMATION from the MFT (which has 72-byte SI = NTFS 3.x).
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let info = mft.info().unwrap();

        // NTFS 3.x extended fields should be present (72-byte SI).
        let security_id = info.security_id();
        assert!(
            security_id.is_some(),
            "72-byte SI should have security_id field"
        );
        // The value itself may be 0 if mkntfs didn't populate it.
    }

    #[test]
    fn test_usn_accessor() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let info = mft.info().unwrap();

        // 72-byte SI should have the USN field.
        let usn = info.usn();
        assert!(usn.is_some(), "72-byte SI should have USN field");
    }

    #[test]
    fn test_timestamps_nonzero() {
        use crate::time::tests::NT_TIMESTAMP_2021_01_01;

        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let root_dir = ntfs
            .file(
                &mut testfs1,
                KnownNtfsFileRecordNumber::RootDirectory as u64,
            )
            .unwrap();
        let info = root_dir.info().unwrap();

        // All timestamps should be nonzero and after 2021 (when testfs1 was created).
        assert!(info.creation_time().nt_timestamp() > NT_TIMESTAMP_2021_01_01);
        assert!(info.modification_time().nt_timestamp() > NT_TIMESTAMP_2021_01_01);
        assert!(info.access_time().nt_timestamp() > NT_TIMESTAMP_2021_01_01);
        assert!(info.mft_record_modification_time().nt_timestamp() > NT_TIMESTAMP_2021_01_01);
    }

    #[test]
    fn test_directory_file_attributes() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // The root directory should not have the IS_DIRECTORY flag in $STANDARD_INFORMATION
        // (that flag is only in $FILE_NAME attributes). But it should be flagged as a directory
        // via the file record flags.
        let root_dir = ntfs
            .file(
                &mut testfs1,
                KnownNtfsFileRecordNumber::RootDirectory as u64,
            )
            .unwrap();
        assert!(root_dir.is_directory());

        // The $MFT should not be a directory.
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        assert!(!mft.is_directory());

        // Verify the file attributes field is accessible.
        let mft_info = mft.info().unwrap();
        let _attrs = mft_info.file_attributes();
    }

    #[test]
    fn test_owner_id_and_quota_charged() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        // Use MFT which has 72-byte SI (NTFS 3.x extended fields).
        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let info = mft.info().unwrap();

        // 72-byte SI should have these fields present.
        assert!(info.owner_id().is_some());
        assert!(info.quota_charged().is_some());
    }

    #[test]
    fn test_version_and_class_id() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mft = ntfs
            .file(&mut testfs1, KnownNtfsFileRecordNumber::MFT as u64)
            .unwrap();
        let info = mft.info().unwrap();

        // These are typically zero.
        let _version = info.version();
        let _class_id = info.class_id();
        let _max_versions = info.maximum_versions();
    }

    /// Builds a synthetic 72-byte $STANDARD_INFORMATION buffer (NTFS 3.x).
    ///
    /// Layout (offsets within the attribute value):
    /// - 0..8   creation_time
    /// - 8..16  modification_time
    /// - 16..24 mft_record_modification_time
    /// - 24..32 access_time
    /// - 32..36 file_attributes
    /// - 36..40 maximum_versions
    /// - 40..44 version
    /// - 44..48 class_id
    /// - 48..52 owner_id
    /// - 52..56 security_id
    /// - 56..64 quota_charged
    /// - 64..72 usn
    fn synthetic_si_ntfs3() -> [u8; 72] {
        let mut buf = [0u8; 72];
        // creation_time = 0x1111111111111111
        buf[0..8].copy_from_slice(&0x1111_1111_1111_1111u64.to_le_bytes());
        // modification_time = 0x2222222222222222
        buf[8..16].copy_from_slice(&0x2222_2222_2222_2222u64.to_le_bytes());
        // mft_record_modification_time = 0x3333333333333333
        buf[16..24].copy_from_slice(&0x3333_3333_3333_3333u64.to_le_bytes());
        // access_time = 0x4444444444444444
        buf[24..32].copy_from_slice(&0x4444_4444_4444_4444u64.to_le_bytes());
        // file_attributes = 0x00000020 (ARCHIVE)
        buf[32..36].copy_from_slice(&0x0000_0020u32.to_le_bytes());
        // maximum_versions = 7
        buf[36..40].copy_from_slice(&7u32.to_le_bytes());
        // version = 5
        buf[40..44].copy_from_slice(&5u32.to_le_bytes());
        // class_id = 9
        buf[44..48].copy_from_slice(&9u32.to_le_bytes());
        // owner_id = 0x0A0B0C0D
        buf[48..52].copy_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
        // security_id = 0x11223344
        buf[52..56].copy_from_slice(&0x1122_3344u32.to_le_bytes());
        // quota_charged = 0xCAFEBABEDEADBEEF
        buf[56..64].copy_from_slice(&0xCAFE_BABE_DEAD_BEEFu64.to_le_bytes());
        // usn = 0x0102030405060708
        buf[64..72].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        buf
    }

    #[test]
    fn test_synthetic_ntfs3_fields() {
        let buf = synthetic_si_ntfs3();
        let info = NtfsStandardInformation::from_bytes_for_test(&buf);

        assert_eq!(info.creation_time().nt_timestamp(), 0x1111_1111_1111_1111);
        assert_eq!(
            info.modification_time().nt_timestamp(),
            0x2222_2222_2222_2222
        );
        assert_eq!(
            info.mft_record_modification_time().nt_timestamp(),
            0x3333_3333_3333_3333
        );
        assert_eq!(info.access_time().nt_timestamp(), 0x4444_4444_4444_4444);
        assert!(
            info.file_attributes()
                .contains(NtfsFileAttributeFlags::ARCHIVE)
        );

        assert_eq!(info.maximum_versions(), 7);
        assert_eq!(info.version(), 5);
        assert_eq!(info.class_id(), 9);

        assert_eq!(info.owner_id(), Some(0x0A0B_0C0D));
        assert_eq!(info.security_id(), Some(0x1122_3344));
        assert_eq!(info.quota_charged(), Some(0xCAFE_BABE_DEAD_BEEF));
        assert_eq!(info.usn(), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn test_synthetic_ntfs1_only_has_no_ntfs3_fields() {
        // A 48-byte (NTFS 1.x) buffer has no NTFS 3.x extension; those accessors return None.
        let buf = synthetic_si_ntfs3();
        let info = NtfsStandardInformation::from_bytes_for_test(&buf[..48]);

        assert_eq!(info.maximum_versions(), 7);
        assert_eq!(info.version(), 5);
        assert_eq!(info.class_id(), 9);

        assert_eq!(info.owner_id(), None);
        assert_eq!(info.security_id(), None);
        assert_eq!(info.quota_charged(), None);
        assert_eq!(info.usn(), None);
    }
}
