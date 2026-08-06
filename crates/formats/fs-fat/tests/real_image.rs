//! Integration tests against a real FAT32 image created by mkfs.fat.
//!
//! The test image (`testdata/testfs1`) is created by running:
//!   `sudo bash testdata/create-testfs1.sh`
//!
//! These tests verify that the parser works on a real filesystem
//! created by real tools, not just hand-crafted byte arrays.

use fsmnt_testkit::Cursor;
use std::collections::BTreeSet;

use fs_common::FsReadSeek;
use fs_common::traverse::walk_dir;
use fs_fat::{Fat, FatDirectory, FatDirectoryEntry, FatType};

fn load_test_image() -> Option<Cursor<Vec<u8>>> {
    let path = "testdata/testfs1";
    let Some(buffer) = fsmnt_testkit::read_optional_fixture(env!("CARGO_MANIFEST_DIR"), path)
    else {
        eprintln!(
            "SKIPPED: {path} not found — run: \
             sudo bash testdata/create-testfs1.sh"
        );
        return None;
    };
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
    let fat = Fat::new(&mut cursor).unwrap();

    assert_eq!(fat.fat_type(), FatType::Fat32);
    assert!(fat.cluster_size() > 0);
    assert!(fat.total_clusters() > 0);
    assert!(fat.size() > 0);
}

#[test]
fn volume_label() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    // Check volume label from root directory entries.
    // FAT stores the label in 8.3 format: "TESTFAT32" becomes
    // "TESTFAT3" + "2  " which short_name_string() formats as
    // "TESTFAT3.2". Check the raw 11-byte short name instead.
    let mut entries = fat.root_dir_entries();
    let mut found_label = false;
    while let Some(result) = entries.next(&mut cursor) {
        let entry = result.unwrap();
        if entry.is_volume_id() {
            found_label = true;
            let raw = entry.short_name();
            // "TESTFAT32  " padded to 11 bytes
            assert_eq!(&raw[..9], b"TESTFAT32", "unexpected label: {raw:?}");
            break;
        }
    }
    assert!(found_label, "volume label entry not found in root dir");
}

// ---------------------------------------------------------------
// Root directory listing
// ---------------------------------------------------------------

#[test]
fn list_root_directory() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let mut names: Vec<String> = Vec::new();
    let mut entries = fat.root_dir_entries();
    while let Some(result) = entries.next(&mut cursor) {
        let entry = result.unwrap();
        if entry.is_volume_id() || entry.is_dot_or_dotdot() {
            continue;
        }
        names.push(entry.name());
    }

    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("hello.txt")),
        "missing hello.txt in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("empty-file")),
        "missing empty-file in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("docs")),
        "missing docs/ in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("edge-cases")),
        "missing edge-cases/ in root: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("many-files")),
        "missing many-files/ in root: {names:?}"
    );
}

// ---------------------------------------------------------------
// Path navigation with open()
// ---------------------------------------------------------------

#[test]
fn open_file_in_root() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "hello.txt").unwrap();
    assert!(!file.is_directory());
    assert_eq!(file.file_size(), 13); // "Hello, FAT32!"
}

#[test]
fn open_nested_path() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "docs/README.TXT").unwrap();
    assert!(!file.is_directory());
}

#[test]
fn open_deeply_nested_path() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "projects/rust/src/main.rs").unwrap();
    assert!(!file.is_directory());
}

#[test]
fn open_case_insensitive() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let f1 = fat.open(&mut cursor, "hello.txt").unwrap();
    let f2 = fat.open(&mut cursor, "HELLO.TXT").unwrap();
    let f3 = fat.open(&mut cursor, "Hello.Txt").unwrap();
    assert_eq!(f1.first_cluster(), f2.first_cluster());
    assert_eq!(f2.first_cluster(), f3.first_cluster());
}

#[test]
fn open_not_found() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let result = fat.open(&mut cursor, "nonexistent.xyz");
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// File data reading
// ---------------------------------------------------------------

#[test]
fn read_exact_cluster_boundary_file() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "sector-size.bin").unwrap();
    assert_eq!(file.file_size(), 512); // exactly one cluster

    let mut value = file.data().unwrap();
    let mut buf = vec![0u8; 1024];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 512);

    // Second read should return 0 (EOF, no next cluster)
    let n2 = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n2, 0);
}

#[test]
fn read_small_file() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "hello.txt").unwrap();
    let mut value = file.data().unwrap();

    let mut buf = vec![0u8; 64];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 13);
    assert_eq!(&buf[..13], b"Hello, FAT32!");
}

#[test]
fn read_pattern_file() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "pattern-file.dat").unwrap();
    assert_eq!(file.file_size(), 1000);

    let mut value = file.data().unwrap();
    let mut buf = vec![0u8; 1000];
    let mut total = 0;
    while total < buf.len() {
        let n = value.read(&mut cursor, &mut buf[total..]).unwrap();
        if n == 0 {
            break;
        }
        total += n;
    }
    assert_eq!(total, 1000);

    // Verify "12345" repeated 200 times
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
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "empty-file").unwrap();
    assert_eq!(file.file_size(), 0);

    let mut value = file.data().unwrap();
    let mut buf = [0u8; 10];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn read_multi_cluster_file() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "multi-cluster.bin").unwrap();
    assert_eq!(
        usize::try_from(file.file_size()).expect("the fixture file size fits usize"),
        64 * 1024
    );

    let mut value = file.data().unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0;
    while total < buf.len() {
        let n = value.read(&mut cursor, &mut buf[total..]).unwrap();
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
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "docs/README.TXT").unwrap();
    let mut value = file.data().unwrap();

    let mut buf = vec![0u8; 256];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    let content = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(content, "This is a readme.\n");
}

#[test]
fn seek_and_read_file() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "hello.txt").unwrap();
    let mut value = file.data().unwrap();

    // Seek to offset 7 ("FAT32!")
    value
        .seek(&mut cursor, fs_common::io::SeekFrom::Start(7))
        .unwrap();

    let mut buf = [0u8; 6];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"FAT32!");
}

#[test]
fn seek_from_end() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "hello.txt").unwrap();
    let mut value = file.data().unwrap();

    // "Hello, FAT32!" — last 6 bytes = "FAT32!"
    value
        .seek(&mut cursor, fs_common::io::SeekFrom::End(-6))
        .unwrap();

    let mut buf = [0u8; 6];
    let n = value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"FAT32!");
}

#[test]
fn seek_backward_and_reread() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat.open(&mut cursor, "hello.txt").unwrap();
    let mut value = file.data().unwrap();

    // Read first 7 bytes: "Hello, "
    let mut buf = [0u8; 7];
    value.read(&mut cursor, &mut buf).unwrap();
    assert_eq!(&buf, b"Hello, ");

    // Seek back to start with SeekFrom::Current
    value
        .seek(&mut cursor, fs_common::io::SeekFrom::Current(-7))
        .unwrap();

    // Re-read — should get same data
    let mut buf2 = [0u8; 7];
    value.read(&mut cursor, &mut buf2).unwrap();
    assert_eq!(&buf2, b"Hello, ");
}

// ---------------------------------------------------------------
// walk_dir traversal
// ---------------------------------------------------------------

#[test]
fn walk_dir_real_image() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let root_file = fat.root_directory();
    let mut root = FatDirectory::new(root_file).unwrap();
    let mut seen = BTreeSet::new();
    let mut names: Vec<String> = Vec::new();

    walk_dir(
        &mut cursor,
        &mut root,
        &mut seen,
        &mut |entry: FatDirectoryEntry<'_>| {
            names.push(entry.inner().name());
        },
    )
    .unwrap();

    // Should find files at multiple levels
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("hello.txt")),
        "walk_dir should find hello.txt: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("docs")),
        "walk_dir should find docs/"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("README.TXT")),
        "walk_dir should find docs/README.TXT"
    );
    assert!(
        names.iter().any(|n| n.eq_ignore_ascii_case("main.rs")),
        "walk_dir should find projects/rust/src/main.rs"
    );

    // Should find all 50 files in many-files/
    let many_count = names
        .iter()
        .filter(|n| n.starts_with("file-") || n.starts_with("FILE-"))
        .count();
    assert_eq!(many_count, 50, "should find all 50 files in many-files/");

    // Total should be substantial
    assert!(
        names.len() > 60,
        "expected 60+ entries, got {}",
        names.len()
    );
}

// ---------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------

#[test]
fn long_filename() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat
        .open(
            &mut cursor,
            "edge-cases/this-is-a-very-long-filename-that-requires-lfn-entries.txt",
        )
        .unwrap();
    assert!(!file.is_directory());
}

#[test]
fn filename_with_spaces() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let file = fat
        .open(&mut cursor, "edge-cases/file with spaces.txt")
        .unwrap();
    assert!(!file.is_directory());
}

#[test]
fn empty_directory() {
    let mut cursor = require_test_image!();
    let fat = Fat::new(&mut cursor).unwrap();

    let dir = fat.open(&mut cursor, "empty-dir").unwrap();
    assert!(dir.is_directory());

    // Should have only . and .. entries
    let mut entries = dir.dir_entries().unwrap();
    let mut count = 0;
    while let Some(result) = entries.next(&mut cursor) {
        let entry = result.unwrap();
        if !entry.is_dot_or_dotdot() {
            count += 1;
        }
    }
    assert_eq!(count, 0, "empty-dir should have no real entries");
}
