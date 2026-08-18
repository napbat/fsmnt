//! End-to-end checks that drive real filesystem images through the full
//! stack: boot-sector detection, driver dispatch via [`DriverRegistry`],
//! then reads through the [`TargetFilesystem`] interface.
//!
//! The images are generated fixtures (gitignored), so every test skips
//! itself when its image is absent.

use std::io::Cursor;
use std::path::PathBuf;

use fsmnt_core::TargetFilesystem;
use fsmnt_device::{
    DetectedBootSector, FS_DETECT_PROBE_SIZE, FilesystemOpenOptions, PartitionReader,
    detect_boot_sector_at, ext_backup_superblock_at,
};
use fsmnt_drivers::{ExtFilesystem, default_registry};

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
    detect_boot_sector_at(&mut Cursor::new(image), 0).expect("detect image")
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
        u64::try_from(data.len()).expect("buffer length fits u64"),
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

/// Byte offset of inode 2 (the root directory) in `ext4-fscrypt.img`:
/// group 0's inode table starts at block 34 (4 KiB blocks), and inode
/// numbers are 1-based with 256-byte inodes, so inode 2 is the second slot.
const FSCRYPT_ROOT_INODE_OFFSET: usize = 34 * 4096 + 256;

#[test]
fn ext_open_fails_when_root_directory_is_unusable() {
    let Some(mut image) = fixture("fs-ext", "ext4-fscrypt.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-fscrypt.img not generated");
        return;
    };

    // Wipe the root inode. The superblock and group descriptors are intact,
    // so the parser still opens the volume — exactly the shape of a mount
    // from a misplaced superblock, where everything located relative to it
    // is garbage. The driver must refuse instead of exposing an empty tree.
    image[FSCRYPT_ROOT_INODE_OFFSET..FSCRYPT_ROOT_INODE_OFFSET + 256].fill(0);
    let detected = detect(&image);
    assert_eq!(detected, DetectedBootSector::Ext);

    let Err(err) = default_registry().open(Box::new(Cursor::new(image)), detected) else {
        panic!("a volume whose root directory is unusable must not open");
    };
    let message = err.to_string();
    assert!(
        message.contains("root") && message.contains("usable filesystem"),
        "error should point at the root directory check: {message}",
    );
}

/// Group 1 of `ext4-meta-bg.img` (1 KiB blocks, 1024 blocks per group,
/// `sparse_super`) starts at block 1025 and holds a backup superblock. An
/// offset 1 KiB before it therefore has that backup exactly where a
/// filesystem start keeps its primary.
const META_BG_BACKUP_SUPERBLOCK_OFFSET: u64 = 1024 * 1024;

#[test]
fn ext_backup_superblock_is_not_a_filesystem_start() {
    let Some(image) = fixture("fs-ext", "ext4-meta-bg.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-meta-bg.img not generated");
        return;
    };
    let mut cursor = Cursor::new(image);

    // The primary is a filesystem start; the backup is not, and the probe
    // can say which group the copy belongs to.
    assert_eq!(
        detect_boot_sector_at(&mut cursor, 0).expect("detect primary"),
        DetectedBootSector::Ext
    );
    assert_eq!(
        detect_boot_sector_at(&mut cursor, META_BG_BACKUP_SUPERBLOCK_OFFSET)
            .expect("detect backup"),
        DetectedBootSector::Unknown,
        "an ext backup superblock must not classify as a filesystem start",
    );
    assert_eq!(
        ext_backup_superblock_at(&mut cursor, 0).expect("probe primary"),
        None
    );
    assert_eq!(
        ext_backup_superblock_at(&mut cursor, META_BG_BACKUP_SUPERBLOCK_OFFSET)
            .expect("probe backup"),
        Some(1)
    );

    // Even when a caller forces the ext driver onto that offset, the open
    // must fail rather than mount a volume with no readable files.
    let image = cursor.into_inner();
    let length = u64::try_from(image.len()).expect("fixture length fits u64")
        - META_BG_BACKUP_SUPERBLOCK_OFFSET;
    let reader = PartitionReader::new(Cursor::new(image), META_BG_BACKUP_SUPERBLOCK_OFFSET, length);
    assert!(
        default_registry()
            .open(Box::new(reader), DetectedBootSector::Ext)
            .is_err(),
        "opening from a backup superblock must fail",
    );
}

#[test]
fn ext_open_without_replay_presents_on_disk_state() {
    let Some(image) = fixture("fs-ext", "ext4-dirty-orphan.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-dirty-orphan.img not generated");
        return;
    };

    // The default open recovers the dirty volume through an overlay …
    let recovered = ExtFilesystem::new(Cursor::new(image.clone())).expect("recovered open");
    assert_ne!(
        recovered.overlay_kind(),
        "clean",
        "fixture should require recovery"
    );

    // … while declining replay still opens, serves the root, and says so.
    let mut raw =
        ExtFilesystem::new_without_replay(Cursor::new(image.clone())).expect("open without replay");
    assert_eq!(raw.overlay_kind(), "unreplayed");
    assert!(raw.try_is_dir("/").expect("root should stat"));

    // The same choice reaches the driver through the registry's options.
    let options = FilesystemOpenOptions::new().with_journal_replay(false);
    let mut through_registry = default_registry()
        .open_with_options(
            Box::new(Cursor::new(image)),
            DetectedBootSector::Ext,
            &options,
        )
        .expect("registry honours journal_replay = false");
    assert!(through_registry.try_is_dir("/").expect("root should stat"));
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
