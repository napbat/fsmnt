use std::io::Cursor;

use super::*;

#[test]
fn driver_supports_only_ext() {
    crate::test_support::assert_supports_exactly(&ExtDriver, &[DetectedBootSector::Ext]);
}

#[test]
fn driver_name_is_stable() {
    assert_eq!(ExtDriver.name(), "ext");
}

#[test]
fn opening_a_non_ext_image_fails() {
    let reader = Box::new(Cursor::new(vec![0u8; 8192]));
    assert!(
        ExtDriver.open(reader, DetectedBootSector::Ext).is_err(),
        "an all-zero image must not parse as ext"
    );
}

#[test]
fn canonicalise_handles_root_and_empty_paths() {
    assert!(canonicalise_ext_path("").is_empty());
    assert!(canonicalise_ext_path("/").is_empty());
}

#[test]
fn canonicalise_collapses_separators() {
    assert_eq!(canonicalise_ext_path("/foo/bar"), ["foo", "bar"]);
    assert_eq!(canonicalise_ext_path("foo/bar"), ["foo", "bar"]);
    assert_eq!(canonicalise_ext_path("//foo///bar//"), ["foo", "bar"]);
}

#[test]
fn canonicalise_preserves_backslash_and_colon() {
    // Both are legal filename bytes on ext; the Windows-oriented
    // normalisation must not be applied here.
    assert_eq!(canonicalise_ext_path("/a\\b"), ["a\\b"]);
    assert_eq!(canonicalise_ext_path("/C:literal"), ["C:literal"]);
    assert_eq!(canonicalise_ext_path("/foo/a:b:c"), ["foo", "a:b:c"]);
}

#[test]
fn canonicalise_resolves_dot_and_dotdot() {
    assert_eq!(canonicalise_ext_path("/./foo"), ["foo"]);
    assert_eq!(canonicalise_ext_path("/foo/./bar"), ["foo", "bar"]);
    assert_eq!(canonicalise_ext_path("/foo/../bar"), ["bar"]);
    assert_eq!(canonicalise_ext_path("/foo/bar/.."), ["foo"]);
    // `..` beyond the root is clamped rather than escaping it.
    assert_eq!(canonicalise_ext_path("/../../foo"), ["foo"]);
}

#[test]
fn timestamp_zero_is_the_unix_epoch_not_unset() {
    let dt = ts_to_utc(ExtTimestamp {
        seconds: 0,
        nanoseconds: 0,
    })
    .expect("epoch is a valid ext timestamp");
    assert_eq!(dt.timestamp(), 0);
}

#[test]
fn timestamp_out_of_range_maps_to_none() {
    assert!(
        ts_to_utc(ExtTimestamp {
            seconds: 0,
            nanoseconds: 2_000_000_000,
        })
        .is_none()
    );
}

#[test]
fn error_mapping_preserves_semantic_variants() {
    assert!(matches!(
        map_ext_error(ExtError::NotFound, "/foo"),
        FsError::NotFound(p) if p == "/foo"
    ));
    assert!(matches!(
        map_ext_error(ExtError::NotADirectory { inode: 42 }, "/foo"),
        FsError::NotADirectory(_)
    ));
    assert!(matches!(
        map_ext_error(ExtError::IsADirectory { inode: 7 }, "/foo"),
        FsError::NotAFile(_)
    ));
    assert!(matches!(
        map_ext_error(ExtError::EncryptedInode { inode: 123 }, "/foo"),
        FsError::Filesystem(msg) if msg.contains("123") && msg.contains("encrypted")
    ));
    assert!(matches!(
        map_ext_error(ExtError::JournalExpectedButAbsent, "<open>"),
        FsError::Filesystem(msg) if msg.contains("no journal is available")
    ));
}
