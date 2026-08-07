//! Cross-crate Btrfs parser-to-`TargetFilesystem` integration coverage.

use std::fs::File;
use std::io::SeekFrom;
use std::path::Path;

use fsmnt_core::{FsEntryFlags, TargetFilesystem};
use fsmnt_device::{
    DetectedBootSector, DeviceMember, DeviceSet, FilesystemDriver, FilesystemOpenOptions,
    FilesystemRoot, SourceMemberId,
};
use fsmnt_drivers::{BtrfsDriver, BtrfsFilesystem};
use fsmnt_testkit::{Cursor, fixture_path, read_optional_fixture};

const FIXTURE: &str = "../formats/fs-btrfs/testdata/btrfs-basic.img";
const SUBVOLUME_FIXTURE: &str = "../formats/fs-btrfs/testdata/btrfs-subvolumes.img";

fn filesystem() -> Option<BtrfsFilesystem<Cursor<Vec<u8>>>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), FIXTURE)?;
    Some(BtrfsFilesystem::new(Cursor::new(bytes)).expect("open fixture filesystem"))
}

fn selected_filesystem(root: FilesystemRoot) -> Option<Box<dyn TargetFilesystem>> {
    let bytes = read_optional_fixture(env!("CARGO_MANIFEST_DIR"), SUBVOLUME_FIXTURE)?;
    let options = FilesystemOpenOptions::new().with_root(root);
    Some(
        BtrfsDriver
            .open_with_options(
                Box::new(Cursor::new(bytes)),
                DetectedBootSector::Btrfs,
                &options,
            )
            .expect("open selected Btrfs root"),
    )
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
    let mut range = [0_u8; 8];
    assert_eq!(
        filesystem
            .read_at("hello.txt", 6, &mut range)
            .expect("hello range"),
        range.len()
    );
    assert_eq!(&range, b"from fsm");

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
fn generic_root_options_select_default_top_level_and_nested_views() {
    let Some(mut default) = selected_filesystem(FilesystemRoot::Default) else {
        return;
    };
    assert_eq!(
        default
            .read("etc/root-marker.txt")
            .expect("default root marker"),
        b"selected default root\n"
    );

    let mut top_level =
        selected_filesystem(FilesystemRoot::TopLevel).expect("fixture remains available");
    let names: Vec<String> = top_level
        .read_dir("")
        .expect("top-level listing")
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert!(names.contains(&"root".to_string()));
    assert!(names.contains(&"home".to_string()));
    assert!(names.contains(&"root-snapshot".to_string()));

    let mut home = selected_filesystem(FilesystemRoot::Path("home".to_string()))
        .expect("fixture remains available");
    assert_eq!(
        home.read("home-marker.txt").expect("home marker"),
        b"selected home subvolume\n"
    );

    let mut nested = selected_filesystem(FilesystemRoot::Path("root/var/lib/nested".to_string()))
        .expect("fixture remains available");
    assert_eq!(
        nested
            .read("nested-marker.txt")
            .expect("nested root marker"),
        b"selected nested subvolume\n"
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

#[test]
fn driver_discovers_real_multi_device_identities_and_restores_position() {
    let first = fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        "../formats/fs-btrfs/testdata/btrfs-multi-1.img",
    );
    if !first.exists() {
        return;
    }
    let mut member = device_member("first", &first);
    member
        .reader_mut()
        .seek(SeekFrom::Start(123))
        .expect("position member");
    let discovery = BtrfsDriver
        .discover_members(&mut member, DetectedBootSector::Btrfs)
        .expect("inspect Btrfs member")
        .expect("Btrfs has filesystem-owned member metadata");

    assert_eq!(discovery.required_members().len(), 2);
    assert!(discovery.requires(discovery.member()));
    assert_eq!(
        member
            .reader_mut()
            .stream_position()
            .expect("member position"),
        123
    );
}
