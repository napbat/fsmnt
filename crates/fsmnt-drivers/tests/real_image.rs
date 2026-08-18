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

/// Bytes the primary metadata of `ext4-multigroup.img` occupies: 1 KiB
/// blocks put the superblock in block 1 and its group-descriptor table in
/// block 2, so wiping the first 8 KiB destroys both (and the bitmaps that
/// follow) while leaving every backup copy intact.
const MULTIGROUP_PRIMARY_METADATA: usize = 8192;

#[test]
fn ext_opens_from_a_backup_superblock_when_the_primary_is_wiped() {
    let Some(image) = fixture("fs-ext", "ext4-multigroup.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-multigroup.img not generated");
        return;
    };

    let mut damaged = image;
    damaged[..MULTIGROUP_PRIMARY_METADATA].fill(0);
    assert_eq!(
        detect(&damaged),
        DetectedBootSector::Unknown,
        "a wiped primary superblock must not detect as a filesystem",
    );
    assert!(
        default_registry()
            .open(
                Box::new(Cursor::new(damaged.clone())),
                DetectedBootSector::Ext
            )
            .is_err(),
        "the ordinary open reads the primary and must fail",
    );

    // Group 1 keeps a copy of both the superblock and the descriptor
    // table, which is enough to locate every inode again.
    let options = FilesystemOpenOptions::new().with_ext_backup_superblock(Some(1));
    let mut fs = default_registry()
        .open_with_options(
            Box::new(Cursor::new(damaged.clone())),
            DetectedBootSector::Ext,
            &options,
        )
        .expect("group 1's backup metadata should open the volume");
    let entries = fs.read_dir("/").expect("root should list from the backup");
    assert!(
        entries.iter().any(|entry| entry.name == "hello.txt"),
        "the recovered root should hold the fixture tree: {:?}",
        entries.iter().map(|e| &e.name).collect::<Vec<_>>(),
    );
    assert_eq!(
        fs.read("/hello.txt").expect("read through the backup open"),
        b"Hello from ext4-multigroup!\n",
    );

    // sparse_super keeps copies in groups 1, 3, 5 and 7 only.
    let options = FilesystemOpenOptions::new().with_ext_backup_superblock(Some(2));
    let Err(error) = default_registry().open_with_options(
        Box::new(Cursor::new(damaged)),
        DetectedBootSector::Ext,
        &options,
    ) else {
        panic!("group 2 holds no backup superblock, so the open must fail");
    };
    assert!(
        error.to_string().contains("no ext backup superblock"),
        "the failure should name the missing copy: {error}",
    );
}

#[test]
fn ext_meta_bg_opens_from_its_backup_superblock() {
    let Some(image) = fixture("fs-ext", "ext4-meta-bg.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-meta-bg.img not generated");
        return;
    };

    // META_BG scatters the descriptor blocks, so only the superblock copy
    // is patched in; the descriptors are read from where they already are.
    let options = FilesystemOpenOptions::new().with_ext_backup_superblock(Some(1));
    let mut fs = default_registry()
        .open_with_options(
            Box::new(Cursor::new(image)),
            DetectedBootSector::Ext,
            &options,
        )
        .expect("group 1's backup superblock should open a META_BG volume");
    let entries = fs.read_dir("/").expect("root should list");
    assert!(
        entries.iter().any(|entry| entry.name == "hello.txt"),
        "the volume opened through the backup should expose the same tree",
    );
}

/// Byte range of the root directory's single data block in `ext4.img`:
/// 4 KiB blocks, and inode 2's extent points at block 4.
const EXT4_ROOT_DIRECTORY_BLOCK: std::ops::Range<usize> = 4 * 4096..5 * 4096;

/// Contents of `/hello.txt` in `ext4.img`, used to recognise the file
/// again once its name is gone.
const EXT4_HELLO_CONTENT: &[u8] = b"Hello from ext4!\n";

#[test]
fn ext_salvage_recovers_files_when_the_root_directory_is_gone() {
    let Some(image) = fixture("fs-ext", "ext4.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4.img not generated");
        return;
    };

    // Destroy the names, keep the data: the shape of a truncated Android
    // image, whose directories live at the end of the volume.
    let mut damaged = image;
    damaged[EXT4_ROOT_DIRECTORY_BLOCK].fill(0);

    let Err(error) = default_registry().open(
        Box::new(Cursor::new(damaged.clone())),
        DetectedBootSector::Ext,
    ) else {
        panic!("a volume whose root cannot be listed must not open by default");
    };
    assert!(
        error
            .to_string()
            .contains("root directory cannot be listed"),
        "unexpected error: {error}",
    );

    let options = FilesystemOpenOptions::new().with_salvage(true);
    let mut fs = default_registry()
        .open_with_options(
            Box::new(Cursor::new(damaged)),
            DetectedBootSector::Ext,
            &options,
        )
        .expect("salvage mode should open a volume with an unusable root");

    let root = fs.read_dir("/").expect("the root lists in salvage mode");
    assert!(
        root.iter().any(|entry| entry.name == ".fsmnt-salvage"),
        "salvage mode must advertise its directory: {:?}",
        root.iter().map(|e| &e.name).collect::<Vec<_>>(),
    );

    let salvaged = fs
        .read_dir("/.fsmnt-salvage")
        .expect("the salvage directory lists");
    assert!(
        salvaged.len() > 1,
        "the sweep should find the fixture's inodes, found {}",
        salvaged.len(),
    );

    // hello.txt is unreachable by name, but its bytes come back through
    // the ordinary inode path under its recovered number.
    let recovered = salvaged
        .iter()
        .filter(|entry| !entry.metadata.is_dir)
        .find_map(|entry| {
            let path = format!("/.fsmnt-salvage/{}", entry.name);
            fs.read(&path)
                .ok()
                .filter(|bytes| bytes == EXT4_HELLO_CONTENT)
        });
    assert!(
        recovered.is_some(),
        "hello.txt's content should be recoverable from the inode sweep",
    );

    // Directories are recovered too, which restores the real names of
    // everything below any surviving one.
    let directory = salvaged
        .iter()
        .find(|entry| entry.metadata.is_dir)
        .expect("the fixture has subdirectories");
    let listed = fs
        .read_dir(&format!("/.fsmnt-salvage/{}", directory.name))
        .expect("a recovered directory should list");
    assert!(
        listed.iter().all(|entry| entry.name != "."),
        "`.` and `..` stay filtered inside salvage listings",
    );
}

/// Byte range of the jbd2 superblock in the `ext4.img` family: the journal
/// (inode 8) begins at physical block 9, with 4 KiB blocks.
const EXT4_JOURNAL_SUPERBLOCK: std::ops::Range<usize> = 9 * 4096..10 * 4096;

#[test]
fn ext_replay_failure_points_at_the_no_replay_view() {
    let Some(image) = fixture("fs-ext", "ext4-dirty-orphan.img") else {
        eprintln!("skipping: fs-ext/testdata/ext4-dirty-orphan.img not generated");
        return;
    };

    // The fixture is dirty, so opening it attempts replay. Destroy the
    // jbd2 superblock and replay has nothing to work from — while the
    // on-disk view remains perfectly readable.
    let mut damaged = image;
    damaged[EXT4_JOURNAL_SUPERBLOCK].fill(0xFF);

    let Err(error) = ExtFilesystem::new(Cursor::new(damaged.clone())) else {
        panic!("replay cannot succeed without a journal");
    };
    let message = error.to_string();
    assert!(
        message.contains("--no-journal-replay"),
        "a replay failure should name the view that still works: {message}",
    );

    let mut raw = ExtFilesystem::new_without_replay(Cursor::new(damaged))
        .expect("the on-disk view is unaffected by the broken journal");
    assert!(raw.try_is_dir("/").expect("root should stat"));
}
