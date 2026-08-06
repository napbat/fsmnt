use super::*;
use crate::ntfs::Ntfs;
use crate::time::tests::NT_TIMESTAMP_2021_01_01;
use fs_common::iter::FsTryIterator;

const MFT_RECORD_NUMBER: u64 = 0;
const ROOT_DIRECTORY_RECORD_NUMBER: u64 = 5;

#[test]
fn test_file_name() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let mft = ntfs.file(&mut testfs1, MFT_RECORD_NUMBER).unwrap();
    let mut mft_attributes = mft.attributes_raw();

    // Check the FileName attribute of the MFT.
    let attribute = mft_attributes.nth(1).unwrap().unwrap();
    assert_eq!(attribute.ty().unwrap(), NtfsAttributeType::FileName);
    assert_eq!(attribute.attribute_length(), 104);
    assert!(attribute.is_resident());
    assert_eq!(attribute.name_length(), 0);
    assert_eq!(attribute.value_length(), 74);

    // Check the actual "file name" of the MFT.
    let file_name = attribute
        .structured_value::<_, NtfsFileName>(&mut testfs1)
        .unwrap();

    let creation_time = file_name.creation_time();
    assert!(creation_time.nt_timestamp() > NT_TIMESTAMP_2021_01_01);
    assert_eq!(creation_time, file_name.modification_time());
    assert_eq!(creation_time, file_name.mft_record_modification_time());
    assert_eq!(creation_time, file_name.access_time());

    let allocated_size = file_name.allocated_size();
    assert!(allocated_size > 0);
    assert_eq!(allocated_size, file_name.data_size());

    assert_eq!(file_name.name_length(), 8);

    // Test various ways to compare the same string.
    assert_eq!(file_name.name(), "$MFT");
    assert_eq!(file_name.name().to_string_lossy(), String::from("$MFT"));
    assert_eq!(
        file_name.name(),
        U16StrLe(&[b'$', 0, b'M', 0, b'F', 0, b'T', 0])
    );
}

#[test]
fn test_parent_directory_reference() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // $MFT's parent directory reference should point to the root directory (record 5).
    let mft = ntfs.file(&mut testfs1, MFT_RECORD_NUMBER).unwrap();
    let mut mft_attributes = mft.attributes_raw();
    let attribute = mft_attributes.nth(1).unwrap().unwrap();
    let file_name = attribute
        .structured_value::<_, NtfsFileName>(&mut testfs1)
        .unwrap();

    let parent_ref = file_name.parent_directory_reference();
    assert_eq!(
        parent_ref.file_record_number(),
        ROOT_DIRECTORY_RECORD_NUMBER
    );
}

#[test]
fn test_file_name_namespace_of_system_files() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // System files like $MFT typically use Win32AndDos namespace.
    let mft = ntfs.file(&mut testfs1, MFT_RECORD_NUMBER).unwrap();
    let mut mft_attributes = mft.attributes_raw();
    let attribute = mft_attributes.nth(1).unwrap().unwrap();
    let file_name = attribute
        .structured_value::<_, NtfsFileName>(&mut testfs1)
        .unwrap();

    let ns = file_name.namespace();
    // $MFT's name fits in 8.3 format, so it's typically Win32AndDos.
    assert!(
        ns == NtfsFileNamespace::Win32AndDos || ns == NtfsFileNamespace::Win32,
        "unexpected namespace: {ns:?}"
    );
}

#[test]
fn test_file_name_directory_flag() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut entries = root_dir_index.entries();

    // Iterate entries and check that directories have the IS_DIRECTORY flag
    // in their $FILE_NAME attributes.
    while let Some(entry) = entries.try_next(&mut testfs1).unwrap() {
        if let Some(Ok(file_name)) = entry.key() {
            let is_dir = file_name.is_directory();
            let attrs = file_name.file_attributes();
            assert_eq!(is_dir, attrs.contains(NtfsFileAttributeFlags::IS_DIRECTORY),);
        }
    }
}

#[test]
fn test_file_name_reparse_point_tag() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();

    // Regular files should have reparse_point_tag == 0.
    let mft = ntfs.file(&mut testfs1, MFT_RECORD_NUMBER).unwrap();
    let mut mft_attributes = mft.attributes_raw();
    let attribute = mft_attributes.nth(1).unwrap().unwrap();
    let file_name = attribute
        .structured_value::<_, NtfsFileName>(&mut testfs1)
        .unwrap();

    assert_eq!(file_name.reparse_point_tag(), 0);
}
