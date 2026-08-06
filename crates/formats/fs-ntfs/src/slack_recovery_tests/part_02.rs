#[test]
fn test_recovered_entry_accessors() {
    use crate::attribute::NtfsAttributeType;
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;
    use crate::structured_values::{NtfsIndexAllocation, NtfsIndexRoot};

    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Use "many_subdirs" which has a large B-tree with more potential slack
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "many_subdirs")
        .unwrap()
        .unwrap();
    let many_subdirs = entry.to_file(&ntfs, &mut testfs1).unwrap();
    let many_subdirs_record = many_subdirs.file_record_number();

    let config = SlackRecoveryConfig {
        require_parent_match: false,
        ..SlackRecoveryConfig::default()
    };

    // Get attributes
    let mut attrs = many_subdirs.attributes();
    let mut index_root_item = None;
    let mut index_alloc_item = None;
    while let Some(item) = attrs.try_next(&mut testfs1).unwrap() {
        let attr = item.to_attribute().unwrap();
        let ty = attr.ty().unwrap();
        if ty == NtfsAttributeType::IndexRoot {
            index_root_item = Some(item);
        } else if ty == NtfsAttributeType::IndexAllocation {
            index_alloc_item = Some(item);
        }
    }

    let index_root_item = index_root_item.unwrap();
    let index_root_attr = index_root_item.to_attribute().unwrap();
    let index_root = index_root_attr
        .resident_structured_value::<NtfsIndexRoot>()
        .unwrap();

    let mut all_entries = Vec::new();

    let scanner = NtfsSlackEntryScanner::new(
        index_root.slack_data(),
        index_root.slack_position(),
        config,
        many_subdirs_record,
    );
    all_entries.extend(scanner);

    if let Some(alloc_item) = index_alloc_item {
        let alloc_attr = alloc_item.to_attribute().unwrap();
        let index_alloc = alloc_attr
            .structured_value::<_, NtfsIndexAllocation>(&mut testfs1)
            .unwrap();
        let index_record_size = index_root.index_record_size();
        let mut record_iter = index_alloc.records(index_record_size);
        while let Some(record) = record_iter.try_next(&mut testfs1).unwrap() {
            let scanner = NtfsSlackEntryScanner::new(
                record.slack_data(),
                record.slack_position(),
                config,
                many_subdirs_record,
            );
            all_entries.extend(scanner);
        }
    }

    // If any entries were recovered, verify all accessors work
    for entry in &all_entries {
        let _file_ref = entry.file_reference();
        let _file_name = entry.file_name();
        let _validation = entry.validation();
        let _position = entry.position();

        // Validate score is in range
        assert!(entry.validation().score() <= 6);
    }
}

#[test]
fn test_directory_entry_enum() {
    use crate::indexes::NtfsFileNameIndex;
    use crate::ntfs::Ntfs;

    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut entries = index.entries();

    // Get the first active entry.
    let first_entry = entries.try_next(&mut testfs1).unwrap().unwrap();
    let active: NtfsDirectoryEntry<'_, NtfsFileNameIndex> =
        NtfsDirectoryEntry::Active(first_entry);
    assert!(active.is_active());
    assert!(!active.is_recovered());

    // Verify we can get a file_name from the active variant.
    let file_name = active.file_name();
    assert!(file_name.is_some());
    assert!(file_name.unwrap().is_ok());

    // Construct a Recovered variant from the root directory's slack.
    let config = SlackRecoveryConfig {
        require_parent_match: false,
        ..SlackRecoveryConfig::default()
    };
    let recovered_entries = root_dir
        .recover_directory_slack(&mut testfs1, config)
        .unwrap();

    for re in recovered_entries {
        let recovered: NtfsDirectoryEntry<'_, NtfsFileNameIndex> =
            NtfsDirectoryEntry::Recovered(Box::new(re));
        assert!(!recovered.is_active());
        assert!(recovered.is_recovered());

        let file_name = recovered.file_name();
        assert!(file_name.is_some());
        assert!(file_name.unwrap().is_ok());
    }
}

#[test]
fn test_round_up_4() {
    assert_eq!(round_up_4(0), 0);
    assert_eq!(round_up_4(1), 4);
    assert_eq!(round_up_4(2), 4);
    assert_eq!(round_up_4(3), 4);
    assert_eq!(round_up_4(4), 4);
    assert_eq!(round_up_4(5), 8);
    assert_eq!(round_up_4(84), 84);
    assert_eq!(round_up_4(85), 88);
}
