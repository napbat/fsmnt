//! End-to-end checks that drive real filesystem images through the full
//! stack: boot-sector detection, driver dispatch via [`DriverRegistry`],
//! then reads through the [`TargetFilesystem`] interface.
//!
//! The images are generated fixtures (gitignored), so every test skips
//! itself when its image is absent.

use std::io::Cursor;
use std::path::PathBuf;

use fsmnt_core::TargetFilesystem;
use fsmnt_device::{DetectedBootSector, FS_DETECT_PROBE_SIZE};
use fsmnt_drivers::default_registry;

/// Load a fixture image from a sibling vendored crate, or `None` if the
/// fixture has not been generated.
fn fixture(crate_name: &str, file: &str) -> Option<Vec<u8>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "formats",
        crate_name,
        "testdata",
        file,
    ]
    .iter()
    .collect();
    std::fs::read(path).ok()
}

/// Detect the filesystem type at the start of `image`.
fn detect(image: &[u8]) -> DetectedBootSector {
    let probe_len = image.len().min(FS_DETECT_PROBE_SIZE);
    DetectedBootSector::from_bytes(&image[..probe_len])
}

/// Open `image` through the registry exactly as the mount path does.
fn open(image: Vec<u8>) -> (DetectedBootSector, Box<dyn TargetFilesystem>) {
    let detected = detect(&image);
    let fs = default_registry()
        .open(Box::new(Cursor::new(image)), detected)
        .expect("registry should open the image");
    (detected, fs)
}

#[test]
fn exfat_image_detects_and_reads_through_registry() {
    let Some(image) = fixture("fs-exfat", "testfs1") else {
        eprintln!("skipping: fs-exfat/testdata/testfs1 not generated");
        return;
    };

    let (detected, mut fs) = open(image);
    assert_eq!(detected, DetectedBootSector::ExFat);

    // The root must list and every entry must be statable by path.
    let entries = fs.read_dir("/").expect("read_dir on root");
    assert!(!entries.is_empty(), "root listing should not be empty");

    for entry in &entries {
        let meta = fs
            .metadata(&entry.name)
            .unwrap_or_else(|e| panic!("metadata for {:?}: {e}", entry.name));
        assert_eq!(
            meta.is_dir, entry.metadata.is_dir,
            "cached and canonical metadata disagree for {:?}",
            entry.name,
        );
    }

    // Reading a regular file must return exactly the advertised size.
    let file = entries
        .iter()
        .find(|e| !e.metadata.is_dir && e.metadata.size > 0)
        .expect("fixture should contain a non-empty file");
    let data = fs
        .read(&file.name)
        .unwrap_or_else(|e| panic!("read {:?}: {e}", file.name));
    assert_eq!(
        data.len() as u64,
        file.metadata.size,
        "short read for {:?}",
        file.name,
    );
}

#[test]
fn ext_image_detects_and_reads_through_registry() {
    let Some(image) = fixture("fs-ext", "ext4-fscrypt.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-fscrypt.img not generated");
        return;
    };

    let (detected, mut fs) = open(image);
    assert_eq!(detected, DetectedBootSector::Ext);

    assert!(fs.try_is_dir("/").expect("root should stat"));
    let entries = fs.read_dir("/").expect("read_dir on root");
    assert!(!entries.is_empty(), "root listing should not be empty");
}

#[test]
fn registry_rejects_type_with_no_driver() {
    // A zeroed image classifies as Unknown, which no driver claims.
    let image = vec![0u8; FS_DETECT_PROBE_SIZE];
    let detected = detect(&image);
    assert_eq!(detected, DetectedBootSector::Unknown);

    let Err(err) = default_registry().open(Box::new(Cursor::new(image)), detected) else {
        panic!("Unknown must not resolve to a driver");
    };
    assert!(
        err.to_string().contains("no filesystem driver"),
        "unexpected error: {err}",
    );
}
