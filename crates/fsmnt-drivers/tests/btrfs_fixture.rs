//! Cross-crate Btrfs parser-to-`TargetFilesystem` integration coverage.

use std::fs::File;
use std::path::Path;

use fsmnt_core::{FsEntryFlags, TargetFilesystem};
use fsmnt_device::{DetectedBootSector, DeviceMember, DeviceSet, FilesystemDriver, SourceMemberId};
use fsmnt_drivers::{BtrfsDriver, BtrfsFilesystem};
use fsmnt_testkit::{Cursor, fixture_path, read_optional_fixture};

const FIXTURE: &str = "../formats/fs-btrfs/testdata/btrfs-basic.img";

fn filesystem() -> Option<BtrfsFilesystem<Cursor<Vec<u8>>>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), FIXTURE)?;
    Some(BtrfsFilesystem::new(Cursor::new(bytes)).expect("open fixture filesystem"))
}

fn device_member(id: &str, path: &Path) -> DeviceMember {
    let file = File::open(path).expect("fixture member");
    let length = file.metadata().expect("fixture metadata").len();
    DeviceMember::new(
        SourceMemberId::Synthetic(id.to_owned()),
        Box::new(file),
        length,
        4096,
    )
    .expect("valid member geometry")
}

#[test]
fn adapter_reads_and_stats_real_files() {
    let Some(mut filesystem) = filesystem() else {
        return;
    };

    assert!(filesystem.try_is_dir("").expect("root kind"));
    assert!(filesystem.try_is_dir("nested/deeper").expect("nested kind"));
    assert!(filesystem.try_is_file("hello.txt").expect("file kind"));
    assert!(!filesystem.try_exists("missing").expect("missing lookup"));
    assert_eq!(
        filesystem.read("hello.txt").expect("hello contents"),
        b"hello from fsmnt btrfs\n"
    );

    let metadata = filesystem.metadata("hello.txt").expect("hello metadata");
    assert!(!metadata.is_dir);
    assert_eq!(metadata.size, 23);
    assert!(metadata.modified.is_some());
    assert_eq!(filesystem.total_size(), Some(268_435_456));
    assert!(filesystem.free_space().is_some());
}

#[test]
fn adapter_lists_nested_entries_and_marks_symlinks() {
    let Some(mut filesystem) = filesystem() else {
        return;
    };
    let entries = filesystem.read_dir("").expect("root listing");
    let link = entries
        .iter()
        .find(|entry| entry.name == "note-link")
        .expect("symlink entry");
    assert!(link.flags.contains(FsEntryFlags::REPARSE_POINT));

    let nested = filesystem
        .read_dir("nested/deeper")
        .expect("nested listing");
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].name, "note.txt");
    assert_eq!(
        filesystem.read("note-link").expect("symlink bytes"),
        b"nested/deeper/note.txt"
    );
}

#[test]
fn driver_opens_real_multi_device_set_and_reads_raid0_data() {
    let first = fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        "../formats/fs-btrfs/testdata/btrfs-multi-1.img",
    );
    let second = fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        "../formats/fs-btrfs/testdata/btrfs-multi-2.img",
    );
    if !first.exists() || !second.exists() {
        return;
    }
    let mut devices = DeviceSet::new(device_member("second", &second));
    devices
        .push(device_member("first", &first))
        .expect("distinct member identities");
    let mut filesystem = BtrfsDriver
        .open_devices(devices, DetectedBootSector::Btrfs)
        .expect("open Btrfs device set");

    let actual = filesystem.read("striped.txt").expect("read RAID0 file");
    let mut expected = Vec::new();
    for number in 1..=32_768 {
        expected.extend_from_slice(format!("multi-device-line-{number:05}\n").as_bytes());
    }
    assert_eq!(actual, expected);
}
