use super::*;
use crate::file::KnownNtfsFileRecordNumber;
use crate::indexes::NtfsFileNameIndex;
use crate::ntfs::Ntfs;
use fsmnt_parser_core::iter::FsTryIterator;

#[test]
fn test_index_find() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "many_subdirs" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
        .unwrap()
        .unwrap();
    let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Prove that we can find all 512 indexed subdirectories.
    let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
    let mut subdir_finder = subdir_index.finder();

    for i in 1..=512 {
        let dir_name = format!("{i}");
        let entry = NtfsFileNameIndex::find(&mut subdir_finder, &ntfs, &mut testfs1, &dir_name)
            .unwrap()
            .unwrap();
        let entry_name = entry.key().unwrap().unwrap();
        assert_eq!(entry_name.name(), dir_name.as_str());
    }
}

#[test]
fn test_index_iter() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "many_subdirs" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "many_subdirs")
        .unwrap()
        .unwrap();
    let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Prove that we can iterate through all 512 indexed subdirectories in order.
    // Keep in mind that subdirectories are ordered like "1", "10", "100", "101", ...
    // We can create the same order by adding them to a vector and sorting that vector.
    let mut dir_names = Vec::with_capacity(512);
    for i in 1..=512 {
        dir_names.push(format!("{i}"));
    }

    dir_names.sort_unstable();

    let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
    let mut subdir_iter = subdir_index.entries();

    for dir_name in dir_names {
        let entry = subdir_iter.try_next(&mut testfs1).unwrap().unwrap();
        let entry_name = entry.key().unwrap().unwrap();
        assert_eq!(entry_name.name(), dir_name.as_str());
    }

    assert!(subdir_iter.try_next(&mut testfs1).unwrap().is_none());
}

#[test]
fn test_unicode_filename() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "edge-cases" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the unicode filename.
    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut edge_cases_finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut edge_cases_finder,
        &ntfs,
        &mut testfs1,
        "unicode-名前-имя-🎉.txt",
    )
    .unwrap()
    .unwrap();
    let entry_name = entry.key().unwrap().unwrap();
    assert_eq!(entry_name.name(), "unicode-名前-имя-🎉.txt");
}

#[test]
fn test_long_filename() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "edge-cases" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the long filename (200 'a' characters + .txt).
    let long_name = "a".repeat(200) + ".txt";
    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut edge_cases_finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(&mut edge_cases_finder, &ntfs, &mut testfs1, &long_name)
        .unwrap()
        .unwrap();
    let entry_name = entry.key().unwrap().unwrap();
    // Verify the name matches (200 'a's + ".txt")
    assert_eq!(entry_name.name(), long_name.as_str());
}

#[test]
fn test_empty_directory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Find the "edge-cases" subdirectory.
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut root_dir_finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut root_dir_finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Find the empty directory.
    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut edge_cases_finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(
        &mut edge_cases_finder,
        &ntfs,
        &mut testfs1,
        "empty-directory",
    )
    .unwrap()
    .unwrap();
    let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Verify it's a directory and is empty.
    assert!(empty_dir.is_directory());
    let empty_dir_index = empty_dir.directory_index(&mut testfs1).unwrap();
    let mut empty_dir_iter = empty_dir_index.entries();
    assert!(empty_dir_iter.try_next(&mut testfs1).unwrap().is_none());
}

#[test]
fn test_deep_nesting() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    // Navigate through edge-cases/level1/level2/.../level10/deep-file.txt
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let mut current_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    // Navigate through 10 levels of nesting.
    for level in 1..=10 {
        let dir_name = format!("level{level}");
        let dir_index = current_dir.directory_index(&mut testfs1).unwrap();
        let mut dir_finder = dir_index.finder();
        let entry = NtfsFileNameIndex::find(&mut dir_finder, &ntfs, &mut testfs1, &dir_name)
            .unwrap()
            .unwrap();
        current_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();
    }

    // Find the deep file at level 10.
    let dir_index = current_dir.directory_index(&mut testfs1).unwrap();
    let mut dir_finder = dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut dir_finder, &ntfs, &mut testfs1, "deep-file.txt")
        .unwrap()
        .unwrap();
    let entry_name = entry.key().unwrap().unwrap();
    assert_eq!(entry_name.name(), "deep-file.txt");
}

#[test]
fn test_entries_with_dots_root_directory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let ntfs = Ntfs::new(&mut testfs1).unwrap();
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();

    let dir_ref =
        NtfsFileReference::from_parts(root_dir.file_record_number(), root_dir.sequence_number());
    // Root directory's parent is itself.
    let parent_ref = root_dir.parent_reference(&mut testfs1).unwrap();

    let index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut iter = index.entries_with_dots(dir_ref, parent_ref);

    // First entry should be "." pointing to the root directory.
    let entry = iter.try_next(&mut testfs1).unwrap().unwrap();
    match entry {
        NtfsDirEntry::CurrentDirectory(r) => {
            assert_eq!(
                r.file_record_number(),
                KnownNtfsFileRecordNumber::RootDirectory.as_u64()
            );
        }
        _ => panic!("expected CurrentDirectory"),
    }

    // Second entry should be ".." also pointing to root (for root dir).
    let entry = iter.try_next(&mut testfs1).unwrap().unwrap();
    match entry {
        NtfsDirEntry::ParentDirectory(r) => {
            assert_eq!(
                r.file_record_number(),
                KnownNtfsFileRecordNumber::RootDirectory.as_u64()
            );
        }
        _ => panic!("expected ParentDirectory"),
    }

    // Remaining entries should be real index entries.
    let mut real_count = 0;
    while let Some(entry) = iter.try_next(&mut testfs1).unwrap() {
        assert!(matches!(entry, NtfsDirEntry::IndexEntry(_)));
        real_count += 1;
    }
    assert!(real_count > 0, "root directory should have children");
}

#[test]
fn test_entries_with_dots_subdirectory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Navigate to "edge-cases" subdirectory.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let subdir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let dir_ref =
        NtfsFileReference::from_parts(subdir.file_record_number(), subdir.sequence_number());
    let parent_ref = subdir.parent_reference(&mut testfs1).unwrap();

    let subdir_index = subdir.directory_index(&mut testfs1).unwrap();
    let mut iter = subdir_index.entries_with_dots(dir_ref, parent_ref);

    // "." should point to the subdirectory itself.
    let dot = iter.try_next(&mut testfs1).unwrap().unwrap();
    assert_eq!(
        dot.file_reference().file_record_number(),
        subdir.file_record_number()
    );

    // ".." should point to root (MFT 5).
    let dotdot = iter.try_next(&mut testfs1).unwrap().unwrap();
    assert_eq!(
        dotdot.file_reference().file_record_number(),
        KnownNtfsFileRecordNumber::RootDirectory.as_u64()
    );

    // Count real entries match entries() count.
    let mut dots_real_count = 0;
    while let Some(_entry) = iter.try_next(&mut testfs1).unwrap() {
        dots_real_count += 1;
    }

    let mut plain_iter = subdir_index.entries();
    let mut plain_count = 0;
    while let Some(_entry) = plain_iter.try_next(&mut testfs1).unwrap() {
        plain_count += 1;
    }

    assert_eq!(dots_real_count, plain_count);
}

#[test]
fn test_entries_with_dots_empty_directory() {
    let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
        return;
    };
    let mut ntfs = Ntfs::new(&mut testfs1).unwrap();
    ntfs.read_upcase_table(&mut testfs1).unwrap();

    // Navigate to edge-cases/empty-directory.
    let root_dir = ntfs.root_directory(&mut testfs1).unwrap();
    let root_dir_index = root_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = root_dir_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "edge-cases")
        .unwrap()
        .unwrap();
    let edge_cases_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let edge_cases_index = edge_cases_dir.directory_index(&mut testfs1).unwrap();
    let mut finder = edge_cases_index.finder();
    let entry = NtfsFileNameIndex::find(&mut finder, &ntfs, &mut testfs1, "empty-directory")
        .unwrap()
        .unwrap();
    let empty_dir = entry.to_file(&ntfs, &mut testfs1).unwrap();

    let dir_ref =
        NtfsFileReference::from_parts(empty_dir.file_record_number(), empty_dir.sequence_number());
    let parent_ref = empty_dir.parent_reference(&mut testfs1).unwrap();

    let empty_index = empty_dir.directory_index(&mut testfs1).unwrap();
    let mut iter = empty_index.entries_with_dots(dir_ref, parent_ref);

    // Should still get "." and ".." even for an empty directory.
    let dot = iter.try_next(&mut testfs1).unwrap().unwrap();
    assert!(matches!(dot, NtfsDirEntry::CurrentDirectory(_)));

    let dotdot = iter.try_next(&mut testfs1).unwrap().unwrap();
    assert!(matches!(dotdot, NtfsDirEntry::ParentDirectory(_)));

    // No more entries.
    assert!(iter.try_next(&mut testfs1).unwrap().is_none());
}
