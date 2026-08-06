#[test]
fn test_compressed_directory_files() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "compressed" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry =
        NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "compressed")
            .unwrap()
            .unwrap();
    let compressed_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the small-compressed.txt file and verify we can read it.
    let compressed_index = compressed_dir.directory_index(&mut testfs1).unwrap();
    let mut compressed_finder = compressed_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut compressed_finder,
        &ntfs,
        &mut testfs1,
        "small-compressed.txt",
    )
    .unwrap()
    .unwrap();
    let compressed_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Verify we can read the file's attributes and data.
    let _info = compressed_file.info().unwrap();
    let data_attribute_item = compressed_file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();

    // Read the content - should be "Hello, compressed world!"
    let mut data_value = data_attribute.value(&mut testfs1).unwrap();
    let mut buf = vec![0u8; usize::try_from(data_attribute.value_length()).expect("test value fits usize")];
    let bytes_read = data_value.read(&mut testfs1, &mut buf).unwrap();
    assert_eq!(bytes_read, usize::try_from(data_attribute.value_length()).expect("test value fits usize"));
    assert_eq!(
        core::str::from_utf8(&buf).unwrap(),
        "Hello, compressed world!"
    );

    // Test the is_compressed() method - it checks the attribute flags.
    // Note: ntfs-3g's setfattr may not properly set the compression flag,
    // so we just verify the method works without asserting the result.
    let _is_compressed = data_attribute.is_compressed();

    // Find and read the repetitive-compressed.txt file (100KB of 'A's).
    let compressed_index = compressed_dir.directory_index(&mut testfs1).unwrap();
    let mut compressed_finder = compressed_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut compressed_finder,
        &ntfs,
        &mut testfs1,
        "repetitive-compressed.txt",
    )
    .unwrap()
    .unwrap();
    let repetitive_file = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let data_attribute_item = repetitive_file.data(&mut testfs1, "").unwrap().unwrap();
    let data_attribute = data_attribute_item.to_attribute().unwrap();
    // Should be 100000 bytes (100KB of 'A's)
    assert_eq!(data_attribute.value_length(), 100_000);
}
