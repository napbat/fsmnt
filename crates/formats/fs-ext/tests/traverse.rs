//! Integration tests for recursive ext directory traversal.

mod support;

use std::collections::BTreeSet;

use fs_common::iter::FsTryIterator;
use fs_common::traverse::{EntryKind, FsDirectory, FsId, walk_dir};
use fs_ext::ExtRawDirectoryIter;

#[test]
fn list_root_directory_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    let mut names = Vec::new();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    }
    assert!(names.contains(&"hello.txt".to_string()));
    assert!(names.contains(&"subdir".to_string()));
    assert!(names.contains(&"lost+found".to_string()));
    assert!(!names.contains(&".".to_string()));
    assert!(!names.contains(&"..".to_string()));
}

#[test]
fn list_root_directory_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    let mut names = Vec::new();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    }
    assert!(
        names.contains(&"hello.txt".to_string()),
        "expected hello.txt in root, got {names:?}"
    );
    assert!(!names.contains(&".".to_string()));
    assert!(!names.contains(&"..".to_string()));
}

#[test]
fn list_root_directory_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    let mut names = Vec::new();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    }
    assert!(
        names.contains(&"hello.txt".to_string()),
        "expected hello.txt in root, got {names:?}"
    );
    assert!(
        names.contains(&"subdir".to_string()),
        "expected subdir in root, got {names:?}"
    );
}

#[test]
fn walk_dir_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut seen = BTreeSet::<FsId>::new();
    let mut file_count = 0u32;
    let mut dir_count = 0u32;
    walk_dir(
        &mut fs,
        &mut root,
        &mut seen,
        &mut |entry| match entry.kind() {
            EntryKind::File => file_count += 1,
            EntryKind::Directory => dir_count += 1,
            _ => {}
        },
    )
    .unwrap();
    assert!(file_count > 0, "expected at least one file");
    assert!(dir_count > 0, "expected at least one directory");
}

#[test]
fn walk_dir_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let mut root = ext.root_directory();
    let mut seen = BTreeSet::<FsId>::new();
    let mut count = 0u32;
    walk_dir(&mut fs, &mut root, &mut seen, &mut |_entry| {
        count += 1;
    })
    .unwrap();
    assert!(count > 0, "expected at least one entry");
}

#[test]
fn walk_dir_ext3() {
    let (ext, mut fs) = support::open_ext("ext3.img");
    let mut root = ext.root_directory();
    let mut seen = BTreeSet::<FsId>::new();
    let mut count = 0u32;
    walk_dir(&mut fs, &mut root, &mut seen, &mut |_entry| {
        count += 1;
    })
    .unwrap();
    assert!(count > 0, "expected at least one entry");
}

#[test]
fn entry_kind_file_vs_directory_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    let mut found_file = false;
    let mut found_dir = false;
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        let name = String::from_utf8_lossy(entry.name_bytes()).into_owned();
        if name == "hello.txt" {
            assert_eq!(entry.kind(), EntryKind::File);
            found_file = true;
        }
        if name == "subdir" {
            assert_eq!(entry.kind(), EntryKind::Directory);
            found_dir = true;
        }
    }
    assert!(found_file, "hello.txt not found");
    assert!(found_dir, "subdir not found");
}

#[test]
fn entry_kind_file_vs_directory_ext2() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    let mut found_file = false;
    let mut found_dir = false;
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        let name = String::from_utf8_lossy(entry.name_bytes()).into_owned();
        if name == "hello.txt" {
            assert_eq!(entry.kind(), EntryKind::File);
            found_file = true;
        }
        if name == "subdir" {
            assert_eq!(entry.kind(), EntryKind::Directory);
            found_dir = true;
        }
    }
    assert!(found_file, "hello.txt not found in ext2");
    assert!(found_dir, "subdir not found in ext2");
}

#[test]
fn walk_dir_finds_nested_files() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut seen = BTreeSet::<FsId>::new();
    let mut names = Vec::new();
    walk_dir(&mut fs, &mut root, &mut seen, &mut |entry| {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    })
    .unwrap();
    assert!(
        names.contains(&"nested.txt".to_string()),
        "expected nested.txt in walk, got {names:?}"
    );
    assert!(
        names.contains(&"deep_file.txt".to_string()),
        "expected deep_file.txt in walk, got {names:?}"
    );
}

#[test]
fn entry_id_is_nonzero_for_real_entries() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        let id = entry.id();
        assert!(id.is_some(), "all ext entries should have an id");
        assert!(id.unwrap().0 > 0, "entry id should be nonzero");
    }
}

#[test]
fn open_dir_returns_none_for_file() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        let name = String::from_utf8_lossy(entry.name_bytes()).into_owned();
        if name == "hello.txt" {
            let dir = entry.open_dir().unwrap();
            assert!(dir.is_none(), "open_dir on a file should return None");
            return;
        }
    }
    panic!("hello.txt not found");
}

#[test]
fn open_dir_returns_some_for_directory() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let mut root = ext.root_directory();
    let mut iter = root.entries(&mut fs).unwrap();
    while let Some(entry) = iter.try_next(&mut fs).unwrap() {
        let name = String::from_utf8_lossy(entry.name_bytes()).into_owned();
        if name == "subdir" {
            let dir = entry.open_dir().unwrap();
            assert!(dir.is_some(), "open_dir on a directory should return Some");
            return;
        }
    }
    panic!("subdir not found");
}

#[test]
fn root_directory_id_is_inode_2() {
    let ext = {
        let mut fs = support::load_image("ext4.img");
        fs_ext::Ext::new(&mut fs).unwrap()
    };
    let root = ext.root_directory();
    let id = <fs_ext::ExtDirectory<'_> as FsDirectory<fsmnt_testkit::Cursor<Vec<u8>>>>::id(&root);
    assert_eq!(id, Some(FsId(2)));
}

#[test]
fn walk_dir_ext2_finds_nested() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let mut root = ext.root_directory();
    let mut seen = BTreeSet::<FsId>::new();
    let mut names = Vec::new();
    walk_dir(&mut fs, &mut root, &mut seen, &mut |entry| {
        names.push(String::from_utf8_lossy(entry.name_bytes()).into_owned());
    })
    .unwrap();
    assert!(
        names.contains(&"nested.txt".to_string()),
        "expected nested.txt in ext2 walk, got {names:?}"
    );
    assert!(
        names.contains(&"deep_file.txt".to_string()),
        "expected deep_file.txt in ext2 walk, got {names:?}"
    );
}

#[test]
fn raw_entries_yields_same_structural_info_as_entries_on_ext4() {
    let (ext, mut fs) = support::open_ext("ext4.img");

    // Collect from entries() (kind-resolved).
    let mut kind_entries: Vec<(Vec<u8>, u32)> = Vec::new();
    {
        let mut dir = ext.root_directory();
        let mut iter = dir.entries(&mut fs).unwrap();
        while let Some(e) = iter.try_next(&mut fs).unwrap() {
            kind_entries.push((e.name_bytes().to_vec(), e.inode_number()));
        }
    }

    // Collect from raw_entries() (structural only).
    let mut raw_entries: Vec<(Vec<u8>, u32, u8)> = Vec::new();
    {
        let mut dir = ext.root_directory();
        let mut iter: ExtRawDirectoryIter<'_> = dir.raw_entries(&mut fs).unwrap();
        while let Some(e) = iter.try_next(&mut fs).unwrap() {
            raw_entries.push((e.name_bytes().to_vec(), e.inode_number(), e.file_type()));
        }
    }

    assert_eq!(
        kind_entries.len(),
        raw_entries.len(),
        "entry count must match between entries() and raw_entries()"
    );
    for (k, r) in kind_entries.iter().zip(raw_entries.iter()) {
        assert_eq!(k.0, r.0, "name mismatch");
        assert_eq!(k.1, r.1, "inode_number mismatch");
    }

    // Ext4 has FILETYPE — at least one entry must carry a non-zero file_type byte.
    assert!(
        raw_entries.iter().any(|(_, _, ft)| *ft != 0),
        "ext4 has FILETYPE; at least one entry should have a non-zero file_type"
    );
}
