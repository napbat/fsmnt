use fsmnt_testkit::Cursor;

use super::*;

fn valid_superblock() -> [u8; SUPERBLOCK_SIZE] {
    let mut data = [0_u8; SUPERBLOCK_SIZE];
    data[0x20..0x30].fill(0xab);
    data[0x30..0x38].copy_from_slice(&PRIMARY_SUPERBLOCK_OFFSET.to_le_bytes());
    data[0x40..0x48].copy_from_slice(&SUPERBLOCK_MAGIC);
    data[0x48..0x50].copy_from_slice(&42u64.to_le_bytes());
    data[0x70..0x78].copy_from_slice(&1_073_741_824u64.to_le_bytes());
    data[0x78..0x80].copy_from_slice(&16_777_216u64.to_le_bytes());
    data[0x80..0x88].copy_from_slice(&6u64.to_le_bytes());
    data[0x88..0x90].copy_from_slice(&1u64.to_le_bytes());
    data[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
    data[0x94..0x98].copy_from_slice(&16_384u32.to_le_bytes());
    data[0x12b..0x137].copy_from_slice(b"fedora-test\0");
    data
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

    assert!(matches!(
        BtrfsSuperblock::from_primary_bytes(&data),
        Err(BtrfsError::InvalidNodeSize { .. })
    ));
}

#[test]
fn preserves_non_utf8_label_bytes() {
    let mut data = valid_superblock();
    data[0x12b..0x12e].copy_from_slice(&[0xff, 0xfe, 0]);
    let superblock = BtrfsSuperblock::from_primary_bytes(&data).expect("valid superblock");

    assert_eq!(superblock.label_bytes(), &[0xff, 0xfe]);
    assert_eq!(superblock.label(), None);
}
