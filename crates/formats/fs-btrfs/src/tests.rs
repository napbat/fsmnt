use fsmnt_testkit::Cursor;

use super::*;

fn valid_superblock() -> [u8; SUPERBLOCK_SIZE] {
    let mut data = [0_u8; SUPERBLOCK_SIZE];
    data[0x20..0x30].fill(0xab);
    data[0x30..0x38].copy_from_slice(&PRIMARY_SUPERBLOCK_OFFSET.to_le_bytes());
    data[0x40..0x48].copy_from_slice(&SUPERBLOCK_MAGIC);
    data[0x48..0x50].copy_from_slice(&42u64.to_le_bytes());
    data[0x50..0x58].copy_from_slice(&0x10_0000_u64.to_le_bytes());
    data[0x58..0x60].copy_from_slice(&0x20_0000_u64.to_le_bytes());
    data[0x70..0x78].copy_from_slice(&1_073_741_824u64.to_le_bytes());
    data[0x78..0x80].copy_from_slice(&16_777_216u64.to_le_bytes());
    data[0x80..0x88].copy_from_slice(&6u64.to_le_bytes());
    data[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
    data[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
    data[0x94..0x98].copy_from_slice(&16_384u32.to_le_bytes());
    data[0xac..0xb4].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
    data[0xb4..0xbc].copy_from_slice(&0x8877_6655_4433_2211_u64.to_le_bytes());
    data[0xbc..0xc4].copy_from_slice(&(1_u64 << 9).to_le_bytes());
    data[0xc9..0xd1].copy_from_slice(&7_u64.to_le_bytes());
    data[0x10b..0x11b].fill(0xcd);
    data[0x12b..0x137].copy_from_slice(b"fedora-test\0");
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
    data[0xc4..0xc6].copy_from_slice(&raw_type.to_le_bytes());
    data[..32].fill(0);
    let checksum = checksum_type.compute(&data[32..]);
    data[..32].copy_from_slice(&checksum);
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
fn rejects_magic_only_superblock() {
    let mut data = valid_superblock();
    data[0x30..0x38].fill(0);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidPhysicalAddress { actual: 0 })
    ));
}

#[test]
fn rejects_used_space_beyond_volume_size() {
    let mut data = valid_superblock();
    data[0x78..0x80].copy_from_slice(&2_147_483_648u64.to_le_bytes());
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidBytesUsed { .. })
    ));
}

#[test]
fn rejects_node_size_smaller_than_sector_size() {
    let mut data = valid_superblock();
    data[0x90..0x94].copy_from_slice(&16_384u32.to_le_bytes());
    data[0x94..0x98].copy_from_slice(&4096u32.to_le_bytes());
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidNodeSize { .. })
    ));
}

#[test]
fn preserves_non_utf8_label_bytes() {
    let mut data = valid_superblock();
    data[0x12b..0x12e].copy_from_slice(&[0xff, 0xfe, 0]);
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
    data[0xbc..0xc4].copy_from_slice(&(1_u64 << 10).to_le_bytes());
    data[0x23b..0x24b].fill(0x5a);
    finalize_checksum(&mut data);

    let parsed = BtrfsSuperblock::from_primary_bytes(&data).expect("metadata UUID feature");
    assert_eq!(parsed.tree_uuid(), &[0x5a; 16]);
}

#[test]
fn rejects_incompatible_metadata_layouts() {
    let mut data = valid_superblock();
    data[0xbc..0xc4].copy_from_slice(&(1_u64 << 13).to_le_bytes());
    finalize_checksum(&mut data);

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::UnsupportedIncompatFeatures { flags: 0x2000 })
    ));
}
