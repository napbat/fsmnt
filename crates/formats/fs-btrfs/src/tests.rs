use fsmnt_testkit::Cursor;
use zerocopy::{FromBytes, U16, U32, U64};

use super::*;
use crate::key::{DISK_KEY_SIZE, RawDiskKey};
use crate::superblock::RawSuperblock;

fn valid_superblock() -> [u8; SUPERBLOCK_SIZE] {
    let mut data = [0_u8; SUPERBLOCK_SIZE];
    let device_uuid = [0xcd; 16];
    let system_chunk = crate::chunk::canonical_system_chunk(0x10_0000, 4096, 7, device_uuid);
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.fsid.fill(0xab);
    raw.physical_address = U64::new(PRIMARY_SUPERBLOCK_OFFSET);
    raw.magic = SUPERBLOCK_MAGIC;
    raw.generation = U64::new(42);
    raw.root = U64::new(0x10_0000);
    raw.chunk_root = U64::new(0x20_0000);
    raw.total_bytes = U64::new(1_073_741_824);
    raw.bytes_used = U64::new(16_777_216);
    raw.root_dir_object_id = U64::new(6);
    raw.num_devices = U64::new(1);
    raw.sector_size = U32::new(4096);
    raw.node_size = U32::new(16_384);
    raw.leaf_size = raw.node_size;
    raw.stripe_size = raw.sector_size;
    raw.compat_flags = U64::new(0x1122_3344_5566_7788);
    raw.compat_ro_flags = U64::new(0x8877_6655_4433_2211);
    raw.incompat_flags = U64::new(1_u64 << 9);
    raw.device.device_id = U64::new(7);
    raw.device.total_bytes = raw.total_bytes;
    raw.device.bytes_used = raw.bytes_used;
    raw.device.sector_size = raw.sector_size;
    raw.device.uuid = device_uuid;
    raw.device.fsid = raw.fsid;
    raw.system_chunk_array[..system_chunk.len()].copy_from_slice(&system_chunk);
    raw.system_chunk_array_size =
        U32::new(u32::try_from(system_chunk.len()).expect("system chunk size fits u32"));
    raw.label[..11].copy_from_slice(b"fedora-test");
    finalize_checksum(&mut data);
    data
}

fn valid_superblock_at(physical_address: u64, generation: u64) -> [u8; SUPERBLOCK_SIZE] {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.physical_address = U64::new(physical_address);
    raw.generation = U64::new(generation);
    finalize_checksum(&mut data);
    data
}

fn valid_zoned_superblock(generation: u64) -> [u8; SUPERBLOCK_SIZE] {
    let mut data = valid_superblock_at(PRIMARY_SUPERBLOCK_OFFSET, generation);
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.incompat_flags = U64::new(raw.incompat_flags.get() | (1_u64 << 12));
    finalize_checksum(&mut data);
    data
}

fn finalize_checksum(data: &mut [u8; SUPERBLOCK_SIZE]) {
    finalize_checksum_as(data, crate::checksum::ChecksumType::Crc32c, 0);
}

fn finalize_checksum_as(
    data: &mut [u8; SUPERBLOCK_SIZE],
    checksum_type: crate::checksum::ChecksumType,
    raw_type: u16,
) {
    let raw = RawSuperblock::mut_from_bytes(data).expect("superblock layout");
    raw.checksum_type = U16::new(raw_type);
    raw.checksum.fill(0);
    let checksum = checksum_type.compute(&data[32..]);
    RawSuperblock::mut_from_bytes(data)
        .expect("superblock layout")
        .checksum = checksum;
}

fn valid_image() -> Vec<u8> {
    let offset = usize::try_from(PRIMARY_SUPERBLOCK_OFFSET).expect("offset fits usize");
    let mut image = vec![0_u8; offset + SUPERBLOCK_SIZE];
    image[offset..].copy_from_slice(&valid_superblock());
    image
}

#[test]
fn parses_primary_superblock_metadata() {
    let superblock =
        BtrfsSuperblock::from_primary_bytes(&valid_superblock()).expect("valid superblock");

    assert_eq!(superblock.fsid(), &[0xab; 16]);
    assert_eq!(superblock.physical_address(), PRIMARY_SUPERBLOCK_OFFSET);
    assert_eq!(superblock.generation(), 42);
    assert_eq!(superblock.total_bytes(), 1_073_741_824);
    assert_eq!(superblock.bytes_used(), 16_777_216);
    assert_eq!(superblock.root_dir_object_id(), 6);
    assert_eq!(superblock.num_devices(), 1);
    assert_eq!(superblock.sector_size(), 4096);
    assert_eq!(superblock.node_size(), 16_384);
    assert_eq!(superblock.compat_flags(), 0x1122_3344_5566_7788);
    assert_eq!(superblock.compat_ro_flags(), 0x8877_6655_4433_2211);
    assert_eq!(superblock.incompat_flags(), 1_u64 << 9);
    assert_eq!(superblock.log_root(), None);
    assert_eq!(superblock.log_root_transid(), 0);
    assert_eq!(superblock.log_root_level(), 0);
    assert_eq!(superblock.global_root_count(), 0);
    assert!(!superblock.has_raid_stripe_tree());
    assert!(!superblock.has_remap_tree());
    assert_eq!(superblock.remap_root(), None);
    assert_eq!(superblock.remap_root_generation(), None);
    assert_eq!(superblock.remap_root_level(), None);
    assert_eq!(superblock.device_id(), 7);
    assert_eq!(superblock.device_uuid(), &[0xcd; 16]);
    assert_eq!(superblock.label_bytes(), b"fedora-test");
    assert_eq!(superblock.label(), Some("fedora-test"));
}

#[test]
fn parses_pending_tree_log_metadata() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.log_root = U64::new(0x30_0000);
    raw.log_root_transid = U64::new(17);
    raw.log_root_level = 2;
    finalize_checksum(&mut data);

    let superblock =
        BtrfsSuperblock::from_primary_bytes(&data).expect("superblock with pending tree log");
    assert_eq!(superblock.log_root(), Some(0x30_0000));
    assert_eq!(superblock.log_root_transid(), 17);
    assert_eq!(superblock.log_root_level(), 2);
}

#[test]
fn opens_volume_at_primary_superblock_offset() {
    let volume = Btrfs::new(Cursor::new(valid_image())).expect("open Btrfs volume");

    assert_eq!(volume.superblock().generation(), 42);
    assert_eq!(volume.reader().position(), PRIMARY_SUPERBLOCK_OFFSET + 4096);
    assert_eq!(
        volume.into_inner().into_inner().len(),
        usize::try_from(PRIMARY_SUPERBLOCK_OFFSET).expect("offset fits usize") + SUPERBLOCK_SIZE
    );
}

#[test]
fn recovers_from_backup_and_selects_the_newest_valid_mirror() {
    let backup_address = SUPERBLOCK_MIRROR_OFFSETS[1];
    let backup_offset = usize::try_from(backup_address).expect("backup offset fits usize");
    let mut image = vec![0_u8; backup_offset + SUPERBLOCK_SIZE];
    let primary_offset =
        usize::try_from(PRIMARY_SUPERBLOCK_OFFSET).expect("primary offset fits usize");
    let mut corrupt_primary = valid_superblock_at(PRIMARY_SUPERBLOCK_OFFSET, 44);
    corrupt_primary[SUPERBLOCK_SIZE - 1] ^= 1;
    image[primary_offset..primary_offset + SUPERBLOCK_SIZE].copy_from_slice(&corrupt_primary);
    image[backup_offset..].copy_from_slice(&valid_superblock_at(backup_address, 43));

    let recovered = Btrfs::new(Cursor::new(image)).expect("recover from backup mirror");
    assert_eq!(recovered.superblock().physical_address(), backup_address);
    assert_eq!(recovered.superblock().generation(), 43);
    assert_eq!(
        recovered.reader().position(),
        backup_address + u64::try_from(SUPERBLOCK_SIZE).expect("superblock size fits u64")
    );

    let mut image = recovered.into_inner().into_inner();
    image[primary_offset..primary_offset + SUPERBLOCK_SIZE]
        .copy_from_slice(&valid_superblock_at(PRIMARY_SUPERBLOCK_OFFSET, 44));
    let newest = Btrfs::new(Cursor::new(image)).expect("select newest primary mirror");
    assert_eq!(
        newest.superblock().physical_address(),
        PRIMARY_SUPERBLOCK_OFFSET
    );
    assert_eq!(newest.superblock().generation(), 44);
}

#[test]
fn validates_each_documented_superblock_mirror_address() {
    for physical_address in SUPERBLOCK_MIRROR_OFFSETS {
        let data = valid_superblock_at(physical_address, 42);
        let superblock =
            BtrfsSuperblock::from_bytes_at(&data, physical_address).expect("valid mirror");
        assert_eq!(superblock.physical_address(), physical_address);
    }
}

#[test]
fn zoned_superblock_uses_log_position_and_conventional_mirror_identity() {
    let zone_size = MIN_ZONE_SIZE;
    let record = 4096;
    let mut image =
        vec![0_u8; usize::try_from(2 * zone_size).expect("test image length fits usize")];
    let record_start = usize::try_from(record).expect("record offset fits usize");
    image[record_start..record_start + SUPERBLOCK_SIZE]
        .copy_from_slice(&valid_zoned_superblock(51));
    let zone_report = vec![
        BtrfsZone::new(
            0,
            zone_size,
            zone_size,
            record + u64::try_from(SUPERBLOCK_SIZE).expect("superblock size fits u64"),
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Closed,
        ),
        BtrfsZone::new(
            zone_size,
            zone_size,
            zone_size,
            zone_size,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Empty,
        ),
    ];
    let zoned_device = BtrfsZonedDevice::new(zone_size, zone_report).expect("valid zone report");
    let source = BtrfsDeviceSource::new(Cursor::new(image)).with_zoned_device(zoned_device);

    let volume = Btrfs::from_device_sources(vec![source]).expect("open zoned Btrfs member");
    assert_eq!(volume.superblock().generation(), 51);
    assert_eq!(
        volume.superblock().physical_address(),
        PRIMARY_SUPERBLOCK_OFFSET
    );
    assert_eq!(
        volume.reader().position(),
        record + u64::try_from(SUPERBLOCK_SIZE).expect("superblock size fits u64")
    );
}

#[test]
fn zoned_both_full_pair_selects_newest_valid_generation() {
    let zone_size = MIN_ZONE_SIZE;
    let first_record = zone_size - u64::try_from(SUPERBLOCK_SIZE).expect("size fits u64");
    let second_record = 2 * zone_size - u64::try_from(SUPERBLOCK_SIZE).expect("size fits u64");
    let mut image =
        vec![0_u8; usize::try_from(2 * zone_size).expect("test image length fits usize")];
    let first = usize::try_from(first_record).expect("record offset fits usize");
    let second = usize::try_from(second_record).expect("record offset fits usize");
    image[first..first + SUPERBLOCK_SIZE].copy_from_slice(&valid_zoned_superblock(70));
    image[second..second + SUPERBLOCK_SIZE].copy_from_slice(&valid_zoned_superblock(71));
    let zone_report = vec![
        BtrfsZone::new(
            0,
            zone_size,
            zone_size,
            zone_size,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Full,
        ),
        BtrfsZone::new(
            zone_size,
            zone_size,
            zone_size,
            2 * zone_size,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Full,
        ),
    ];
    let zoned_device = BtrfsZonedDevice::new(zone_size, zone_report).expect("valid full zone pair");
    let source = BtrfsDeviceSource::new(Cursor::new(image)).with_zoned_device(zoned_device);

    let volume = Btrfs::from_device_sources(vec![source]).expect("open newest zoned record");
    assert_eq!(volume.superblock().generation(), 71);
    assert_eq!(
        volume.reader().position(),
        second_record + u64::try_from(SUPERBLOCK_SIZE).expect("size fits u64")
    );
}

#[test]
fn empty_zoned_log_pair_reports_no_superblock() {
    let zone_size = MIN_ZONE_SIZE;
    let zone_report = vec![
        BtrfsZone::new(
            0,
            zone_size,
            zone_size,
            0,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Empty,
        ),
        BtrfsZone::new(
            zone_size,
            zone_size,
            zone_size,
            zone_size,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Empty,
        ),
    ];
    let zoned_device =
        BtrfsZonedDevice::new(zone_size, zone_report).expect("valid empty zone pair");
    let source = BtrfsDeviceSource::new(Cursor::new(Vec::new())).with_zoned_device(zoned_device);
    assert!(matches!(
        Btrfs::from_device_sources(vec![source]),
        Err(BtrfsError::ZonedSuperblockNotFound)
    ));
}

#[test]
fn zoned_probe_restores_reader_position() {
    let zone_size = MIN_ZONE_SIZE;
    let record = 4096;
    let mut image =
        vec![0_u8; usize::try_from(2 * zone_size).expect("test image length fits usize")];
    let record_start = usize::try_from(record).expect("record offset fits usize");
    image[record_start..record_start + SUPERBLOCK_SIZE]
        .copy_from_slice(&valid_zoned_superblock(80));
    let zone_report = vec![
        BtrfsZone::new(
            0,
            zone_size,
            zone_size,
            record + u64::try_from(SUPERBLOCK_SIZE).expect("size fits u64"),
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Closed,
        ),
        BtrfsZone::new(
            zone_size,
            zone_size,
            zone_size,
            zone_size,
            BtrfsZoneType::SequentialWriteRequired,
            BtrfsZoneCondition::Empty,
        ),
    ];
    let zoned_device = BtrfsZonedDevice::new(zone_size, zone_report).expect("valid zone report");
    let mut reader = Cursor::new(image);
    reader.set_position(123);
    assert!(probe_zoned_superblock(&mut reader, &zoned_device).expect("probe zoned superblock"));
    assert_eq!(reader.position(), 123);
}

#[test]
fn multi_device_constructor_requires_at_least_one_reader() {
    let readers: Vec<Cursor<Vec<u8>>> = Vec::new();
    assert!(matches!(
        Btrfs::from_devices(readers),
        Err(BtrfsError::NoDevices)
    ));
}

#[test]
fn rejects_short_superblock() {
    let error =
        BtrfsSuperblock::from_primary_bytes(&[0_u8; 128]).expect_err("short input must fail");
    assert!(matches!(
        error,
        BtrfsError::BufferTooSmall {
            expected: SUPERBLOCK_SIZE,
            actual: 128
        }
    ));
}

#[test]
fn rejects_empty_system_chunk_array() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .system_chunk_array_size = U32::new(0);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidSystemChunkArraySize { actual: 0 })
    ));
}

#[test]
fn rejects_structurally_invalid_system_chunk_array() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    RawDiskKey::mut_from_bytes(&mut raw.system_chunk_array[..DISK_KEY_SIZE])
        .expect("system chunk key")
        .object_id = U64::new(0);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::MalformedItem { object_id: 0, .. })
    ));
}

#[test]
fn rejects_unknown_superblock_state_flags() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .flags = U64::new(1_u64 << 63);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::UnsupportedSuperblockFlags {
            flags: 0x8000_0000_0000_0000
        })
    ));
}

#[test]
fn rejects_magic_only_superblock() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .physical_address = U64::new(0);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidPhysicalAddress {
            expected: PRIMARY_SUPERBLOCK_OFFSET,
            actual: 0
        })
    ));
}

#[test]
fn rejects_used_space_beyond_volume_size() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .bytes_used = U64::new(2_147_483_648);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidBytesUsed { .. })
    ));
}

#[test]
fn rejects_node_size_smaller_than_sector_size() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.sector_size = U32::new(16_384);
    raw.node_size = U32::new(4096);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidNodeSize { .. })
    ));
}

#[test]
fn preserves_non_utf8_label_bytes() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.label.fill(0);
    raw.label[..2].copy_from_slice(&[0xff, 0xfe]);
    finalize_checksum(&mut data);
    let superblock = BtrfsSuperblock::from_primary_bytes(&data).expect("valid superblock");

    assert_eq!(superblock.label_bytes(), &[0xff, 0xfe]);
    assert_eq!(superblock.label(), None);
}

#[test]
fn rejects_corrupt_primary_superblock_checksum() {
    let mut data = valid_superblock();
    data[SUPERBLOCK_SIZE - 1] ^= 1;

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidChecksum {
            structure: "primary superblock",
            ..
        })
    ));
}

#[test]
fn parses_every_supported_superblock_checksum() {
    for (raw, checksum_type) in [
        (0, ChecksumType::Crc32c),
        (1, ChecksumType::XxHash64),
        (2, ChecksumType::Sha256),
        (3, ChecksumType::Blake2b256),
    ] {
        let mut data = valid_superblock();
        finalize_checksum_as(&mut data, checksum_type, raw);
        let parsed = BtrfsSuperblock::from_primary_bytes(&data).expect("supported checksum");
        assert_eq!(parsed.checksum_type(), checksum_type);
    }
}

#[test]
fn metadata_uuid_feature_selects_the_tree_block_uuid() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.incompat_flags = U64::new(1_u64 << 10);
    raw.metadata_uuid.fill(0x5a);
    raw.device.fsid = raw.metadata_uuid;
    finalize_checksum(&mut data);

    let parsed = BtrfsSuperblock::from_primary_bytes(&data).expect("metadata UUID feature");
    assert_eq!(parsed.tree_uuid(), &[0x5a; 16]);
}

#[test]
fn rejects_incompatible_metadata_layouts() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .incompat_flags = U64::new(1_u64 << 15);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::UnsupportedIncompatFeatures { flags: 0x8000 })
    ));
}

#[test]
fn parses_raid_stripe_and_remap_tree_features() {
    let mut raid_stripe = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut raid_stripe)
        .expect("superblock layout")
        .incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 14));
    finalize_checksum(&mut raid_stripe);
    let parsed =
        BtrfsSuperblock::from_primary_bytes(&raid_stripe).expect("RAID stripe-tree superblock");
    assert!(parsed.has_raid_stripe_tree());

    let mut remap = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut remap).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 17));
    raw.compat_ro_flags = U64::new((1_u64 << 0) | (1_u64 << 1) | (1_u64 << 3));
    raw.remap_root = U64::new(0x30_0000);
    raw.remap_root_generation = U64::new(41);
    raw.remap_root_level = 2;
    finalize_checksum(&mut remap);
    let parsed = BtrfsSuperblock::from_primary_bytes(&remap).expect("remap-tree superblock");
    assert!(parsed.has_remap_tree());
    assert_eq!(parsed.remap_root(), Some(0x30_0000));
    assert_eq!(parsed.remap_root_generation(), Some(41));
    assert_eq!(parsed.remap_root_level(), Some(2));
}

#[test]
fn rejects_invalid_remap_tree_feature_dependencies_and_root() {
    let mut missing_compat = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut missing_compat).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 17));
    raw.compat_ro_flags = U64::new(0);
    raw.remap_root = U64::new(0x30_0000);
    raw.remap_root_generation = U64::new(42);
    finalize_checksum(&mut missing_compat);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&missing_compat),
        Err(BtrfsError::InvalidSuperblockField {
            field: "remap_tree_missing_compat_ro",
            ..
        })
    ));

    let mut incompatible = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut incompatible).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 2) | (1_u64 << 9) | (1_u64 << 17));
    raw.compat_ro_flags = U64::new((1_u64 << 0) | (1_u64 << 1) | (1_u64 << 3));
    raw.remap_root = U64::new(0x30_0000);
    raw.remap_root_generation = U64::new(42);
    finalize_checksum(&mut incompatible);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&incompatible),
        Err(BtrfsError::InvalidSuperblockField {
            field: "remap_tree_incompatible_features",
            ..
        })
    ));

    let mut stale_fields = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut stale_fields)
        .expect("superblock layout")
        .remap_root = U64::new(0x30_0000);
    finalize_checksum(&mut stale_fields);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&stale_fields),
        Err(BtrfsError::InvalidSuperblockField {
            field: "remap_root_without_feature",
            ..
        })
    ));
}

#[test]
fn parses_extent_tree_v2_feature_dependencies_and_root_count() {
    let mut data = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut data).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 13));
    raw.compat_ro_flags = U64::new((1_u64 << 0) | (1_u64 << 1) | (1_u64 << 3));
    raw.global_root_count = U64::new(4);
    finalize_checksum(&mut data);

    let parsed = BtrfsSuperblock::from_primary_bytes(&data).expect("extent-tree-v2 superblock");
    assert_eq!(parsed.global_root_count(), 4);
}

#[test]
fn rejects_extent_tree_v2_without_mandatory_features() {
    let mut missing_compat = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut missing_compat).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 13));
    raw.compat_ro_flags = U64::new(0);
    raw.global_root_count = U64::new(4);
    finalize_checksum(&mut missing_compat);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&missing_compat),
        Err(BtrfsError::InvalidSuperblockField {
            field: "extent_tree_v2_missing_compat_ro",
            ..
        })
    ));

    let mut missing_no_holes = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut missing_no_holes).expect("superblock layout");
    raw.incompat_flags = U64::new(1_u64 << 13);
    raw.compat_ro_flags = U64::new((1_u64 << 0) | (1_u64 << 1) | (1_u64 << 3));
    raw.global_root_count = U64::new(4);
    finalize_checksum(&mut missing_no_holes);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&missing_no_holes),
        Err(BtrfsError::InvalidSuperblockField {
            field: "extent_tree_v2_no_holes",
            ..
        })
    ));

    let mut zero_roots = valid_superblock();
    let raw = RawSuperblock::mut_from_bytes(&mut zero_roots).expect("superblock layout");
    raw.incompat_flags = U64::new((1_u64 << 9) | (1_u64 << 13));
    raw.compat_ro_flags = U64::new((1_u64 << 0) | (1_u64 << 1) | (1_u64 << 3));
    raw.global_root_count = U64::new(0);
    finalize_checksum(&mut zero_roots);
    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&zero_roots),
        Err(BtrfsError::InvalidSuperblockField {
            field: "global_root_count",
            value: 0
        })
    ));
}

#[test]
fn rejects_global_root_count_without_extent_tree_v2() {
    let mut data = valid_superblock();
    RawSuperblock::mut_from_bytes(&mut data)
        .expect("superblock layout")
        .global_root_count = U64::new(1);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidSuperblockField {
            field: "global_root_count_without_extent_tree_v2",
            value: 1
        })
    ));
}
