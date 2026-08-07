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
    assert_eq!(superblock.device_id(), 7);
    assert_eq!(superblock.device_uuid(), &[0xcd; 16]);
    assert_eq!(superblock.label_bytes(), b"fedora-test");
    assert_eq!(superblock.label(), Some("fedora-test"));
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
        Err(BtrfsError::InvalidPhysicalAddress { actual: 0 })
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
        .incompat_flags = U64::new(1_u64 << 13);
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::UnsupportedIncompatFeatures { flags: 0x2000 })
    ));
}
