//! Public-API coverage for an image that begins *inside* its filesystem.
//!
//! The forensic case: a slice cut out of a larger volume — one eMMC
//! partition of an ext4 that spans more of the chip, an acquisition that
//! started late — where the filesystem's own first bytes were never
//! captured. `ImageOpenOptions::with_head_absent` declares that head so the
//! parser addresses its structures at the offsets its geometry names, and
//! the surviving backup superblock supplies the metadata the head held.
//!
//! Driven through a real fixture, so the test skips itself when the
//! gitignored images have not been generated.

use std::io::Write;
use std::path::PathBuf;

use fsmnt::device::FilesystemOpenOptions;
use fsmnt::{ImageOpenOptions, OpenImageError, drivers, open_image_with_options};

/// The fixture this test cuts up: 40 MB of ext4 in 1 KiB blocks with 1024
/// blocks per group, so it has 40 block groups and therefore backup
/// superblocks (groups 1, 3, 5, …) to open through. A single-group image
/// would have none, and there would be no case to test.
const FIXTURE: &str = "ext4-meta-bg.img";

/// Full length of that fixture, which is what the opened filesystem must
/// still claim for itself once the head is declared absent.
const VOLUME_BYTES: u64 = 41_943_040;

/// Bytes cut off the front, chosen to be exactly the metadata at the start
/// of block group 0: the 1 KiB boot area, the primary superblock in block
/// 1, and the group descriptor table in block 2. Everything a mount needs
/// from those blocks is duplicated in group 1, and everything after them —
/// the inode tables and the file data — is still on the medium.
const HEAD_ABSENT: u64 = 3072;

/// An inode the salvage sweep finds whose content lies past the cut, so
/// reading it proves the bytes the medium *does* carry are addressed
/// correctly rather than 3072 bytes out.
const SALVAGED_FILE: &str = "/.fsmnt-salvage/inode-40";

/// What that file holds in the fixture.
const SALVAGED_CONTENT: &str = "Hello from ext4-meta-bg!\n";

/// Load an `fs-ext` fixture, or `None` when it has not been generated.
fn fixture() -> Option<Vec<u8>> {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "crates",
        "formats",
        "fs-ext",
        "testdata",
        FIXTURE,
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

/// The fixture with its first [`HEAD_ABSENT`] bytes never acquired: only
/// the bytes from the cut onwards are written, so the file really is a
/// slice of the volume rather than a padded copy of it.
fn tail_of_the_fixture() -> Option<tempfile::NamedTempFile> {
    let image = fixture()?;
    let cut = usize::try_from(HEAD_ABSENT).expect("the cut fits a usize");
    Some(image_file(&image[cut..]))
}

/// The options that open such a slice: the absent head, the group-1 backup
/// to read the metadata from, the sweep that finds the inodes the lost
/// directory tree pointed at, and zeros for what is not there.
fn salvage_options(best_effort: bool) -> ImageOpenOptions {
    ImageOpenOptions::new()
        .with_head_absent(HEAD_ABSENT)
        .with_best_effort_reads(best_effort)
        .with_filesystem_options(
            FilesystemOpenOptions::new()
                .with_ext_backup_superblock(Some(1))
                .with_salvage(true),
        )
}

#[test]
fn a_slice_that_begins_inside_a_filesystem_opens_as_the_whole_volume() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };

    let mut opened = open_image_with_options(
        tail.path(),
        &drivers::default_registry(),
        salvage_options(true),
    )
    .expect("the group 1 backup should open the volume the slice belongs to");

    assert_eq!(
        opened.offset, 0,
        "the filesystem starts at byte 0 of the volume, which is before the medium"
    );
    assert_eq!(
        opened.size_bytes, VOLUME_BYTES,
        "the window is the whole volume, absent head included"
    );
    assert_eq!(
        opened.filesystem.total_size(),
        Some(VOLUME_BYTES),
        "the filesystem still claims every byte it was made with"
    );
    assert_eq!(
        opened.truncated_by, None,
        "nothing is missing off the end — what is missing is off the front"
    );

    // The bytes the medium does carry are addressed by their volume
    // offsets, so a file that survived reads as itself and not as whatever
    // sits HEAD_ABSENT bytes away from it.
    let recovered = opened
        .filesystem
        .read_to_string(SALVAGED_FILE)
        .expect("a salvaged file whose data lies past the cut should read");
    assert_eq!(recovered, SALVAGED_CONTENT);
}

#[test]
fn the_absent_head_is_served_as_zeros_and_counted_separately() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };

    let opened = open_image_with_options(
        tail.path(),
        &drivers::default_registry(),
        salvage_options(true),
    )
    .expect("the volume should open");
    let substitutions = opened
        .substitutions
        .as_ref()
        .expect("best-effort reads share their counter");

    // Opening reads the front of the volume — boot sector detection, then
    // the driver's own look at the primary superblock — and every one of
    // those bytes is absent rather than damaged.
    assert_eq!(
        substitutions.absent_bytes(),
        HEAD_ABSENT,
        "the whole head was asked for and served as zeros"
    );
    assert_eq!(
        substitutions.missing_bytes(),
        0,
        "nothing lies past the end of the source"
    );
    assert_eq!(
        substitutions.errored_bytes(),
        0,
        "an absent head is not a bad sector"
    );
    assert_eq!(substitutions.read_errors(), 0, "and it is not an I/O error");
    assert!(substitutions.any());
}

#[test]
fn without_best_effort_reads_the_absent_head_says_what_it_is() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };

    // The ext driver reads the primary superblock at byte 1024 even when it
    // has been told to take its metadata from a backup, and byte 1024 is
    // one of the bytes this medium never carried. Without zeros standing in
    // for the head that read fails — which is the honest outcome, and the
    // message has to name the head rather than read like corruption.
    let error = open_image_with_options(
        tail.path(),
        &drivers::default_registry(),
        salvage_options(false),
    )
    .err()
    .expect("a read into the absent head cannot be satisfied");
    let message = error.to_string();
    assert!(
        message.contains("the medium begins 3072 bytes into this volume; bytes 0..3072 are absent"),
        "the failure should name the absent head: {message}"
    );
}

#[test]
fn an_absent_head_and_a_location_inside_the_image_cannot_both_be_true() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };
    let registry = drivers::default_registry();

    for (what, options) in [
        ("--partition", salvage_options(true).with_partition(0)),
        ("--scan", salvage_options(true).with_scan(4096)),
        ("--offset", salvage_options(true).with_offset(1_048_576)),
    ] {
        let error = open_image_with_options(tail.path(), &registry, options)
            .err()
            .unwrap_or_else(|| panic!("{what} alongside an absent head should be refused"));
        let OpenImageError::HeadAbsentConflictsWithLocation { head_absent, .. } = &error else {
            panic!("{what} should be refused as a conflict, not as {error}");
        };
        assert_eq!(*head_absent, HEAD_ABSENT);
        assert!(
            error
                .to_string()
                .contains("cannot both be where the filesystem is"),
            "{what}: {error}"
        );
    }
}

#[test]
fn an_absent_head_without_a_backup_superblock_names_the_flag_it_needs() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };

    // Nothing at offset 0 can be classified — the boot sector and the
    // primary superblock are both in the head — so the open has to say
    // which option supplies the metadata instead of reporting "no driver
    // for Unknown".
    let error = open_image_with_options(
        tail.path(),
        &drivers::default_registry(),
        ImageOpenOptions::new()
            .with_head_absent(HEAD_ABSENT)
            .with_best_effort_reads(true),
    )
    .err()
    .expect("an absent head with no way in must not open");
    let OpenImageError::HeadAbsentPrimaryUnreadable { head_absent, .. } = &error else {
        panic!("the failure should be about the unreadable primary: {error}");
    };
    assert_eq!(*head_absent, HEAD_ABSENT);
    assert!(
        error.to_string().contains("--backup-superblock GROUP"),
        "the message should name the flag that opens it: {error}"
    );
}

#[test]
fn a_scan_of_the_slice_reports_the_head_it_begins_after() {
    let Some(tail) = tail_of_the_fixture() else {
        eprintln!("skipping: fs-ext/testdata/{FIXTURE} not generated");
        return;
    };

    // This is where the number for `--offset -N` comes from: the backup
    // superblocks left on the medium record their own block groups, and a
    // group's distance from the start of its filesystem is arithmetic.
    //
    // A finer stride than the default is needed here for the ordinary
    // reason: cutting the front off a volume moves everything in it off the
    // 4 KiB grid the scan steps along by default.
    let hits =
        fsmnt::scan_image_with_options(tail.path(), fsmnt::ScanOptions::new().with_stride(512))
            .expect("scan the slice");
    let found = hits
        .iter()
        .find(|hit| hit.head_absent() == Some(HEAD_ABSENT))
        .unwrap_or_else(|| {
            panic!(
                "no hit placed the filesystem start before the medium: {:?}",
                hits.iter()
                    .map(|hit| (hit.offset, hit.kind))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        found.mount_offset(),
        None,
        "there is no offset on this medium that is the start of that filesystem"
    );
    assert_eq!(
        found.backup_superblock_group(),
        Some(1),
        "the first surviving copy is what --backup-superblock takes"
    );
}
