//! Public-API coverage for opening ext images whose primary metadata is
//! damaged: the diagnosis [`fsmnt::open_image_with_options`] produces, and
//! the backup-superblock and salvage options that then open the volume.
//!
//! Driven through real fixture images, so the test skips itself when the
//! gitignored fixtures have not been generated.

use std::io::Write;
use std::path::PathBuf;

use fsmnt::device::FilesystemOpenOptions;
use fsmnt::{ImageOpenOptions, OpenImageError, drivers, open_image_with_options};

/// Bytes the primary metadata of `ext4-multigroup.img` occupies: 1 KiB
/// blocks, so the superblock is block 1 and its descriptor table block 2.
const PRIMARY_METADATA: usize = 8192;

/// Byte offset of group 1 in `ext4-multigroup.img` (`-b 1024 -g 1024`, so
/// group 1 begins at block 1025) — where its backup superblock lives.
const GROUP_ONE_OFFSET: u64 = 1025 * 1024;

/// Load an `fs-ext` fixture, or `None` when it has not been generated.
fn fixture(file: &str) -> Option<Vec<u8>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "crates",
        "formats",
        "fs-ext",
        "testdata",
        file,
    ]
    .iter()
    .collect();
    std::fs::read(path).ok()
}

/// Write `image` to a temporary file so the image-opening API, which takes
/// a path, can be driven over it.
fn image_file(image: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create a scratch image");
    file.write_all(image).expect("write the scratch image");
    file.flush().expect("flush the scratch image");
    file
}

#[test]
fn a_wiped_primary_is_diagnosed_from_the_group_one_backup() {
    let Some(mut image) = fixture("ext4-multigroup.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-multigroup.img not generated");
        return;
    };
    image[..PRIMARY_METADATA].fill(0);
    let file = image_file(&image);

    let Err(error) = open_image_with_options(
        file.path(),
        &drivers::default_registry(),
        ImageOpenOptions::new(),
    ) else {
        panic!("an image with no readable primary metadata must not open");
    };
    let OpenImageError::ExtPrimaryDamaged {
        offset,
        group,
        backup_offset,
        ..
    } = &error
    else {
        panic!("the failure should identify the surviving backup: {error}");
    };
    assert_eq!((*offset, *group, *backup_offset), (0, 1, GROUP_ONE_OFFSET));
    let message = error.to_string();
    assert!(
        message.contains("--backup-superblock 1"),
        "the message should name the flag that opens it: {message}",
    );
}

#[test]
fn the_backup_superblock_option_opens_a_wiped_primary() {
    let Some(mut image) = fixture("ext4-multigroup.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-multigroup.img not generated");
        return;
    };
    image[..PRIMARY_METADATA].fill(0);
    let file = image_file(&image);

    let options = ImageOpenOptions::new()
        .with_filesystem_options(FilesystemOpenOptions::new().with_ext_backup_superblock(Some(1)));
    let mut opened = open_image_with_options(file.path(), &drivers::default_registry(), options)
        .expect("the group 1 backup should open the volume");
    let entries = opened
        .filesystem
        .read_dir("/")
        .expect("the recovered root should list");
    assert!(
        entries.iter().any(|entry| entry.name == "hello.txt"),
        "the recovered tree should be the fixture's: {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>(),
    );
}

#[test]
fn a_backup_superblock_offset_reports_where_the_filesystem_starts() {
    let Some(image) = fixture("ext4-multigroup.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-multigroup.img not generated");
        return;
    };
    let file = image_file(&image);

    // A magic-number scan lands on the copy 1024 bytes into group 1,
    // because that is where a filesystem start keeps its superblock.
    let probe_offset = GROUP_ONE_OFFSET - 1024;
    let Err(error) = open_image_with_options(
        file.path(),
        &drivers::default_registry(),
        ImageOpenOptions::new().with_offset(probe_offset),
    ) else {
        panic!("a backup superblock is not the start of a filesystem");
    };
    let OpenImageError::ExtBackupSuperblock {
        group,
        filesystem_start,
        ..
    } = &error
    else {
        panic!("the failure should identify the backup copy: {error}");
    };
    assert_eq!((*group, *filesystem_start), (1, Some(0)));
    let message = error.to_string();
    assert!(
        message.contains("the filesystem starts at offset 0"),
        "the message should point at the primary: {message}",
    );
}
