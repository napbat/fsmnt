//! Opt-in live-device integration coverage for zoned Btrfs.

#![cfg(target_os = "linux")]

use fsmnt::device::{DetectedBootSector, HostDriveId, SourceSelection};
use fsmnt::{HostDrives, PartitionOpenOptions, open_device_partition_with_options};

const DEVICE_VARIABLE: &str = "FSMNT_TEST_ZONED_DEVICE";

#[test]
fn reads_a_real_zoned_btrfs_device() {
    let Some(device) = fsmnt_testkit::live_device_id(DEVICE_VARIABLE) else {
        eprintln!("skipping live zoned Btrfs test; {DEVICE_VARIABLE} is unset");
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
    .expect("open live zoned Btrfs device");

    assert_eq!(opened.detected, DetectedBootSector::Btrfs);
    assert_eq!(
        opened
            .filesystem
            .read("/zoned-marker.txt")
            .expect("read marker through Btrfs parser"),
        b"fsmnt real zoned btrfs\n"
    );
}
