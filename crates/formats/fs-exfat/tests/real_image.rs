//! Integration tests against a real exFAT image created by mkfs.exfat.
//!
//! The test image (`testdata/testfs1`) is created by running:
//!   `sudo bash testdata/create-testfs1.sh`
//!
//! These tests verify that the parser works on a real filesystem
//! created by real tools, not just hand-crafted byte arrays.

use std::collections::BTreeSet;
use std::io::{Cursor, Read as _};

use fs_common::FsReadSeek;
use fs_common::traverse::{EntryKind, walk_dir};
use fs_exfat::{ExFat, ExFatDirectory, ExFatTraversalEntry};

fn load_test_image() -> Option<Cursor<Vec<u8>>> {
    let path = "testdata/testfs1";
    if !std::path::Path::new(path).exists() {
        eprintln!(
            "SKIPPED: {path} not found — run: \
             sudo bash testdata/create-testfs1.sh"
        );
        return None;
    }
    let mut buffer = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .read_to_end(&mut buffer)
        .unwrap();
    Some(Cursor::new(buffer))
}

/// Helper macro to skip tests when the test image is missing.
macro_rules! require_test_image {
    () => {
        match load_test_image() {
            Some(cursor) => cursor,
            None => return,
        }
    };
}

// ---------------------------------------------------------------
// Boot sector and volume metadata
// ---------------------------------------------------------------

#[test]
fn parse_real_image() {
    let mut cursor = require_test_image!();
    let exfat = ExFat::new(&mut cursor).unwrap();

    assert_eq!(exfat.cluster_size(), 4096);
    assert_eq!(exfat.filesystem_revision_major(), 1);
    assert_eq!(exfat.filesystem_revision_minor(), 0);
    assert!(exfat.boot_checksum_valid());
    assert!(exfat.cluster_count() > 0);
    assert_eq!(exfat.number_of_fats(), 1);
}

#[test]
fn load_metadata_real_image() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    // Bitmap and upcase table should be loaded
    assert!(exfat.bitmap().is_some());
    assert!(exfat.upcase_table().is_some());

    // Some clusters should be allocated (we wrote files)
    let bitmap = exfat.bitmap().unwrap();
    assert!(bitmap.allocated_count() > 0);
}

// ---------------------------------------------------------------
// Root directory listing
// ---------------------------------------------------------------

#[test]
fn list_root_directory() {
    let mut cursor = require_test_image!();
    let exfat = ExFat::new(&mut cursor).unwrap();

    let mut names: Vec<String> = Vec::new();
    let mut iter = exfat.root_dir_entries();
    while let Some(item) = iter.next(&mut cursor) {
        match item.unwrap() {
            fs_exfat::ExFatDirItem::FileEntry(es) => {
                names.push(es.name_string());
            }
            fs_exfat::ExFatDirItem::VolumeLabel(label) => {
                assert_eq!(label, "TESTEXFAT");
            }
            fs_exfat::ExFatDirItem::BenignEntry { .. }
            | fs_exfat::ExFatDirItem::DeletedEntry { .. } => {}
        }
    }

    // Verify expected entries exist in root
    assert!(
        names.iter().any(|n| n == "hello.txt"),
        "missing hello.txt in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "empty-file"),
        "missing empty-file in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "docs"),
        "missing docs/ in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "edge-cases"),
        "missing edge-cases/ in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n == "many-files"),
        "missing many-files/ in root: {names:?}"
    );
}

// ---------------------------------------------------------------
// Path navigation with open()
// ---------------------------------------------------------------

#[test]
fn open_file_in_root() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat.open(&mut cursor, "hello.txt").unwrap();
    assert_eq!(es.name_string(), "hello.txt");
    assert_eq!(es.data_length(), 13); // "Hello, exFAT!"
    assert!(!es.is_directory());
}

#[test]
fn open_nested_path() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat.open(&mut cursor, "docs/README.TXT").unwrap();
    assert_eq!(es.name_string(), "README.TXT");
    assert!(!es.is_directory());
}

#[test]
fn open_deeply_nested_path() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat
        .open(&mut cursor, "projects/rust/src/main.rs")
        .unwrap();
    assert_eq!(es.name_string(), "main.rs");
}

#[test]
fn open_case_insensitive() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    // exFAT is case-insensitive — these should all find the same file
    let es1 = exfat.open(&mut cursor, "HELLO.TXT").unwrap();
    let es2 = exfat.open(&mut cursor, "Hello.Txt").unwrap();
    assert_eq!(es1.first_cluster(), es2.first_cluster());
}

#[test]
fn open_not_found() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let result = exfat.open(&mut cursor, "nonexistent.xyz");
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// File data reading
// ---------------------------------------------------------------

#[test]
fn read_small_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "hello.txt").unwrap();
    assert_eq!(file.len(), 13);

    let mut buf = vec![0u8; 64];
    let n = file.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(&buf[..13], b"Hello, exFAT!");
}

#[test]
fn read_pattern_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "pattern-file.dat").unwrap();
    assert_eq!(file.len(), 1000);

    let mut buf = vec![0u8; 1000];
    let n = file.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 1000);

    // Should be "12345" repeated 200 times
    for i in 0..200 {
        assert_eq!(
            &buf[i * 5..(i + 1) * 5],
            b"12345",
            "mismatch at repetition {i}"
        );
    }
}

#[test]
fn read_empty_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "empty-file").unwrap();
    assert_eq!(file.len(), 0);
    assert!(file.is_empty());

    let mut buf = [0u8; 10];
    let n = file.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn read_multi_cluster_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "multi-cluster.bin").unwrap();
    assert_eq!(file.len(), 64 * 1024);

    // Read the whole thing
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0;
    while total < buf.len() {
        let n = file.read(&mut cursor, &mut buf[total..]).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, 64 * 1024);
}

#[test]
fn read_nested_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "docs/README.TXT").unwrap();

    let mut buf = vec![0u8; 256];
    let n = file.read(&mut cursor, &mut buf).unwrap();
    let content = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(content, "This is a readme.\n");
}

#[test]
fn seek_and_read_file() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let mut file = exfat.open_file(&mut cursor, "hello.txt").unwrap();

    // Seek to offset 7 ("exFAT!")
    file.seek(&mut cursor, std::io::SeekFrom::Start(7)).unwrap();

    let mut buf = [0u8; 6];
    let n = file.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"exFAT!");
}

// ---------------------------------------------------------------
// walk_dir traversal
// ---------------------------------------------------------------

#[test]
fn walk_dir_real_image() {
    let mut cursor = require_test_image!();
    let exfat = ExFat::new(&mut cursor).unwrap();

    let mut root = ExFatDirectory::root(&exfat);
    let mut seen = BTreeSet::new();
    let mut entries: Vec<(String, EntryKind)> = Vec::new();

    walk_dir(
        &mut cursor,
        &mut root,
        &mut seen,
        &mut |entry: ExFatTraversalEntry<'_>| {
            let name = entry.inner().name_string();
            let kind = if entry.inner().is_directory() {
                EntryKind::Directory
            } else {
                EntryKind::File
            };
            entries.push((name, kind));
        },
    )
    .unwrap();

    // Should find files at multiple levels
    assert!(
        entries.iter().any(|(n, _)| n == "hello.txt"),
        "walk_dir should find hello.txt"
    );
    assert!(
        entries
            .iter()
            .any(|(n, k)| n == "docs" && *k == EntryKind::Directory),
        "walk_dir should find docs/"
    );
    assert!(
        entries.iter().any(|(n, _)| n == "README.TXT"),
        "walk_dir should find docs/README.TXT"
    );
    assert!(
        entries.iter().any(|(n, _)| n == "main.rs"),
        "walk_dir should find projects/rust/src/main.rs"
    );

    // Should find all 50 files in many-files/
    let many_count = entries
        .iter()
        .filter(|(n, _)| n.starts_with("file-"))
        .count();
    assert_eq!(many_count, 50, "should find all 50 files in many-files/");

    // Total should be substantial (files + dirs)
    assert!(
        entries.len() > 60,
        "expected 60+ entries, got {}",
        entries.len()
    );
}

// ---------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------

#[test]
fn unicode_filename() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat
        .open(&mut cursor, "edge-cases/café-naïve.txt")
        .unwrap();
    assert_eq!(es.data_length(), 16); // "unicode content\n"
}

#[test]
fn filename_with_spaces() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    let es = exfat
        .open(&mut cursor, "edge-cases/file with spaces.txt")
        .unwrap();
    assert!(!es.is_directory());
}

#[test]
fn mixed_case_filename() {
    let mut cursor = require_test_image!();
    let mut exfat = ExFat::new(&mut cursor).unwrap();
    exfat.load_metadata(&mut cursor).unwrap();

    // Should find regardless of case used in query
    let es = exfat
        .open(&mut cursor, "edge-cases/mixed-case.txt")
        .unwrap();
    assert_eq!(es.name_string(), "MiXeD-CaSe.TxT");
}

#[test]
fn empty_directory() {
    let mut cursor = require_test_image!();
    let exfat = ExFat::new(&mut cursor).unwrap();

    let mut root = ExFatDirectory::root(&exfat);
    let mut seen = BTreeSet::new();
    let mut found_empty_dir = false;

    walk_dir(
        &mut cursor,
        &mut root,
        &mut seen,
        &mut |entry: ExFatTraversalEntry<'_>| {
            if entry.inner().name_string() == "empty-dir" && entry.inner().is_directory() {
                found_empty_dir = true;
            }
        },
    )
    .unwrap();

    assert!(found_empty_dir, "should find empty-dir/");
}
