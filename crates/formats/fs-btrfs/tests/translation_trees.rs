//! End-to-end checks for experimental Btrfs address-translation trees.

#![cfg(feature = "std")]

use std::fs::File;

use fs_btrfs::Btrfs;
use fsmnt_testkit::fixture_path;

const RAID_STRIPE_TREE_FIXTURE: &str = "testdata/btrfs-raid-stripe-tree.img";
const REMAP_TREE_FIXTURE: &str = "testdata/btrfs-remap-tree.img";
const RAID_STRIPE_PATTERN: &[u8] = b"fsmnt raid-stripe-tree data 0123456789abcdef\n";
const REMAP_PATTERN: &[u8] = b"fsmnt remap-tree data 0123456789abcdef\n";

fn expected_pattern(pattern: &[u8], offset: usize, length: usize) -> Vec<u8> {
    (offset..offset.saturating_add(length))
        .map(|index| pattern[index % pattern.len()])
        .collect()
}

#[test]
fn real_raid_stripe_tree_translates_data_stripes() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), RAID_STRIPE_TREE_FIXTURE);
    if !path.exists() {
        return;
    }

    let mut volume =
        Btrfs::new(File::open(path).expect("RAID stripe-tree fixture")).expect("superblock");
    assert!(volume.superblock().has_raid_stripe_tree());
    volume
        .initialize()
        .expect("load the real populated RAID stripe tree");

    let marker = volume
        .resolve_path([b"marker.txt".as_slice()])
        .expect("marker inode");
    assert_eq!(
        volume.read_file(marker).expect("marker contents"),
        b"raid stripe tree kernel fixture\n"
    );

    let data = volume
        .resolve_path([b"data.bin".as_slice()])
        .expect("pattern inode");
    for offset in [0_usize, 4_194_304 - 4093, 4_194_304 + 7, 62 * 1024 * 1024] {
        let mut actual = vec![0_u8; 8192];
        let count = volume
            .read_file_range(
                data,
                u64::try_from(offset).expect("fixture offset fits u64"),
                &mut actual,
            )
            .expect("read RAID stripe-tree fixture range");
        assert_eq!(count, actual.len());
        assert_eq!(
            actual,
            expected_pattern(RAID_STRIPE_PATTERN, offset, actual.len())
        );
    }
}

#[test]
fn real_forward_remap_reads_target_after_source_is_poisoned() {
    let path = fixture_path(env!("CARGO_MANIFEST_DIR"), REMAP_TREE_FIXTURE);
    if !path.exists() {
        return;
    }

    let mut volume = Btrfs::new(File::open(path).expect("remap-tree fixture")).expect("superblock");
    assert!(volume.superblock().has_remap_tree());
    assert!(volume.superblock().remap_root().is_some());
    volume
        .initialize()
        .expect("load the real forward remap and v2 block groups");

    let marker = volume
        .resolve_path([b"marker.txt".as_slice()])
        .expect("marker inode");
    assert_eq!(
        volume.read_file(marker).expect("marker contents"),
        b"remap tree converted fixture\n"
    );

    let data = volume
        .resolve_path([b"nested".as_slice(), b"data.bin".as_slice()])
        .expect("pattern inode");
    for offset in [0_usize, 4093, 1_048_579, 8_388_608 - 8192] {
        let mut actual = vec![0_u8; 8192];
        let count = volume
            .read_file_range(
                data,
                u64::try_from(offset).expect("fixture offset fits u64"),
                &mut actual,
            )
            .expect("read remap-tree fixture range");
        assert_eq!(count, actual.len());
        assert_eq!(
            actual,
            expected_pattern(REMAP_PATTERN, offset, actual.len())
        );
    }
}
