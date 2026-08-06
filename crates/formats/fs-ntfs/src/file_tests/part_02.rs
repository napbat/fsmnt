#[test]
fn reparse_point_index_opens_or_skips() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // $Extend is MFT entry 11.
    let extend_dir = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::Extend.as_u64())
        .unwrap();

    let extend_index = extend_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = extend_index.finder();

    // Try to find $Reparse in $Extend.
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "$Reparse");
    let Some(entry) = entry else {
        // mkntfs may not create $Reparse — skip.
        return;
    };
    let reparse_file = entry.unwrap().to_file(&ntfs, &mut testfs1).unwrap();

    // Open the $R index via the convenience method.
    match reparse_file.reparse_point_index(&mut testfs1) {
        Ok(index) => {
            // Iterate to verify no panics. Empty index is fine.
            let mut iter = index.entries();
            while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                if let Some(key) = entry.key() {
                    let key = key.unwrap();
                    // Sanity: at least one field should be non-zero.
                    assert!(
                        key.reparse_tag() != 0 || key.file_reference().file_record_number() > 0
                    );
                }
            }
        }
        Err(NtfsError::AttributeNotFound { .. }) => {
            // $Reparse file exists but has no $R index — skip.
        }
        Err(e) => panic!("unexpected error opening $R index: {e}"),
    }
}

#[test]
fn quota_indexes_open_or_skip() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let extend_dir = ntfs
        .file(&mut testfs1, KnownNtfsFileRecordNumber::Extend.as_u64())
        .unwrap();

    let extend_index = extend_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = extend_index.finder();

    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "$Quota");
    let Some(entry) = entry else {
        return;
    };
    let quota_file = entry.unwrap().to_file(&ntfs, &mut testfs1).unwrap();

    // $Q index
    match quota_file.quota_q_index(&mut testfs1) {
        Ok(q_index) => {
            let mut iter = q_index.entries();
            while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                if let Some(key) = entry.key() {
                    let _key = key.unwrap();
                }
            }
        }
        Err(NtfsError::AttributeNotFound { .. }) => {}
        Err(e) => panic!("unexpected error opening $Q index: {e}"),
    }

    // $O index — same file, different named index.
    match quota_file.quota_o_index(&mut testfs1) {
        Ok(o_index) => {
            let mut iter = o_index.entries();
            while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
                if let Some(key) = entry.key() {
                    let _key = key.unwrap();
                }
            }
        }
        Err(NtfsError::AttributeNotFound { .. }) => {}
        Err(e) => panic!("unexpected error opening $O index: {e}"),
    }
}
