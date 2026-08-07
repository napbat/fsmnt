//! Opt-in live-device integration coverage for automatic Btrfs member discovery.

#![cfg(target_os = "linux")]

use fsmnt::device::{DetectedBootSector, HostDriveId, SourceOrigin, SourceSelection};
use fsmnt::{HostDrives, PartitionOpenOptions, open_device_partition_with_options};

const DEVICE_VARIABLE: &str = "FSMNT_TEST_BTRFS_MULTI_DEVICE";

#[test]
fn discovers_and_reads_a_real_multi_device_btrfs_filesystem() {
    let Some(device) = fsmnt_testkit::live_device_id(DEVICE_VARIABLE) else {
        eprintln!("skipping live multi-device Btrfs test; {DEVICE_VARIABLE} is unset");
        return;
    };
    let drivers = fsmnt_drivers::default_registry();
    let options = PartitionOpenOptions::new().with_source(SourceSelection::Raw {
        additional_partitions: Vec::new(),
    });
    let mut opened = open_device_partition_with_options::<HostDrives>(
        &HostDriveId::new(device),
        0,
        &drivers,
        options,
    )
    .expect("discover and open live Btrfs members");

    assert_eq!(opened.detected, DetectedBootSector::Btrfs);
    let SourceOrigin::Raw(extents) = &opened.source else {
        panic!("live raw test must retain physical provenance");
    };
    assert_eq!(extents.len(), 2, "the second member must be discovered");
    assert_eq!(
        opened
            .filesystem
            .read("/multi-marker.txt")
            .expect("read marker through Btrfs parser"),
        b"fsmnt real multi-device btrfs\n"
    );
}
