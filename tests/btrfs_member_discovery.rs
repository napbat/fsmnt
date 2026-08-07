//! Automatic raw-member discovery against real multi-device Btrfs fixtures.

use std::fs::File;
use std::path::PathBuf;

use fsmnt::device::{
    HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo, HostDriveResult,
    HostVolumeResolver, LogicalVolume, PhysicalExtent, SourceOrigin, SourceSelection,
};
use fsmnt::drivers;
use fsmnt_testkit::fixture_path;

const SECTOR_SIZE: u32 = 4096;

struct FixtureHost;

impl HostDriveEnumerator for FixtureHost {
    type Reader = File;

    fn enumerate_drives() -> HostDriveResult<Vec<HostDriveInfo>> {
        [
            "unrelated",
            "seed-middle",
            "second",
            "seed-base",
            "first",
            "seed-top",
        ]
        .into_iter()
        .map(|id| Self::get_drive_info(&HostDriveId::new(id)))
        .collect()
    }

    fn get_drive_info(id: &HostDriveId) -> HostDriveResult<HostDriveInfo> {
        let path = member_path(id)?;
        let length = path.metadata()?.len();
        Ok(HostDriveInfo::new(id.clone(), path)
            .with_access(length)
            .with_sector_size(SECTOR_SIZE))
    }

    fn open_drive(id: &HostDriveId) -> HostDriveResult<Self::Reader> {
        Ok(File::open(member_path(id)?)?)
    }
}

impl HostVolumeResolver for FixtureHost {
    type VolumeReader = File;

    fn logical_volumes(_extent: &PhysicalExtent) -> HostDriveResult<Vec<LogicalVolume>> {
        Ok(Vec::new())
    }

    fn open_logical_volume(_volume: &LogicalVolume) -> HostDriveResult<Self::VolumeReader> {
        unreachable!("raw discovery tests never open logical volumes")
    }
}

fn member_path(id: &HostDriveId) -> HostDriveResult<PathBuf> {
    let filename = match id.as_str() {
        "first" => "btrfs-multi-1.img",
        "second" => "btrfs-multi-2.img",
        "unrelated" => "btrfs-basic.img",
        "seed-base" => "btrfs-seed-base.img",
        "seed-middle" => "btrfs-seed-middle.img",
        "seed-top" => "btrfs-seed-top.img",
        other => return Err(HostDriveError::NotFound(other.to_string())),
    };
    Ok(fixture_path(
        env!("CARGO_MANIFEST_DIR"),
        format!("crates/formats/fs-btrfs/testdata/{filename}"),
    ))
}

fn fixtures_exist(ids: &[&str]) -> bool {
    ids.iter()
        .all(|id| member_path(&HostDriveId::new(*id)).is_ok_and(|path| path.exists()))
}

fn numbered_lines(prefix: &str, count: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    for number in 1..=count {
        bytes.extend_from_slice(format!("{prefix}-{number:05}\n").as_bytes());
    }
    bytes
}

#[test]
fn raw_open_discovers_an_ordinary_multi_device_filesystem() {
    if !fixtures_exist(&["first", "second", "unrelated"]) {
        return;
    }
    let mut opened = fsmnt::open_device_partition_with_selection::<FixtureHost>(
        &HostDriveId::new("first"),
        0,
        &drivers::default_registry(),
        SourceSelection::Raw {
            additional_partitions: Vec::new(),
        },
    )
    .expect("discover and open both Btrfs members");

    assert_eq!(
        opened.filesystem.read("striped.txt").expect("RAID0 file"),
        numbered_lines("multi-device-line", 32_768)
    );
    let SourceOrigin::Raw(extents) = opened.source else {
        panic!("raw open must retain physical provenance");
    };
    assert_eq!(extents.len(), 2);
    assert_eq!(extents[0].drive().as_str(), "first");
    assert_eq!(extents[1].drive().as_str(), "second");
}

#[test]
fn raw_open_discovers_a_seed_chain_with_distinct_fsids() {
    if !fixtures_exist(&["seed-base", "seed-middle", "seed-top", "unrelated"]) {
        return;
    }
    let mut opened = fsmnt::open_device_partition_with_selection::<FixtureHost>(
        &HostDriveId::new("seed-top"),
        0,
        &drivers::default_registry(),
        SourceSelection::Raw {
            additional_partitions: Vec::new(),
        },
    )
    .expect("discover and open the complete Btrfs seed chain");

    assert_eq!(
        opened.filesystem.read("base-only.txt").expect("base seed"),
        numbered_lines("seed-base-line", 32_768)
    );
    assert_eq!(
        opened
            .filesystem
            .read("middle-only.txt")
            .expect("middle seed"),
        numbered_lines("seed-middle-line", 32_768)
    );
    let SourceOrigin::Raw(extents) = opened.source else {
        panic!("raw open must retain physical provenance");
    };
    assert_eq!(extents.len(), 3);
    assert_eq!(
        extents
            .iter()
            .map(|extent| extent.drive().as_str())
            .collect::<Vec<_>>(),
        ["seed-top", "seed-middle", "seed-base"]
    );
}
