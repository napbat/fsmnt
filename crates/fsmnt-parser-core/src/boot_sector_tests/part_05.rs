#[derive(Clone, Copy)]
enum TestByteOrder {
    Little,
    Big,
}

fn write_qnx6_u32(target: &mut [u8], offset: usize, value: u32, order: TestByteOrder) {
    let bytes = match order {
        TestByteOrder::Little => value.to_le_bytes(),
        TestByteOrder::Big => value.to_be_bytes(),
    };
    target[offset..offset + bytes.len()].copy_from_slice(&bytes);
}

fn qnx6_detection_probe(order: TestByteOrder) -> std::vec::Vec<u8> {
    let mut probe = std::vec![0_u8; FS_DETECT_PROBE_SIZE];
    let superblock_offset =
        usize::try_from(qnx6::BOOT_AREA_SIZE).expect("QNX6 offset fits usize");
    let superblock = &mut probe[superblock_offset..];
    write_qnx6_u32(superblock, 0, qnx6::SUPERBLOCK_MAGIC, order);
    write_qnx6_u32(superblock, 0x30, 1024, order);
    write_qnx6_u32(superblock, 0x34, 100, order);
    write_qnx6_u32(superblock, 0x38, 40, order);
    write_qnx6_u32(superblock, 0x3c, 1000, order);
    write_qnx6_u32(superblock, 0x40, 250, order);
    probe
}

#[test]
fn qnx6_detection_accepts_both_disk_byte_orders() {
    for order in [TestByteOrder::Little, TestByteOrder::Big] {
        let probe = qnx6_detection_probe(order);
        let detected = DetectedBootSector::from_bytes(&probe);
        assert_eq!(detected, DetectedBootSector::Qnx6);
        assert!(detected.is_filesystem());
        assert!(!detected.is_partition_table());
    }
}

#[test]
fn qnx6_detection_requires_complete_plausible_geometry() {
    let valid = qnx6_detection_probe(TestByteOrder::Little);
    let offset = usize::try_from(qnx6::BOOT_AREA_SIZE).expect("offset fits usize");
    let superblock = &valid[offset..offset + qnx6::SUPERBLOCK_PROBE_SIZE];
    assert!(qnx6::is_superblock(superblock));
    assert!(!qnx6::is_superblock(&superblock[..superblock.len() - 1]));

    let mut bad_block_size = valid.clone();
    bad_block_size[offset + 0x30..offset + 0x34].copy_from_slice(&768_u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&bad_block_size),
        DetectedBootSector::Unknown
    );

    let mut too_many_free_blocks = valid;
    too_many_free_blocks[offset + 0x40..offset + 0x44]
        .copy_from_slice(&1001_u32.to_le_bytes());
    assert_eq!(
        DetectedBootSector::from_bytes(&too_many_free_blocks),
        DetectedBootSector::Unknown
    );
}

#[test]
fn qnx6_declared_volume_size_includes_both_superblock_areas() {
    let probe = qnx6_detection_probe(TestByteOrder::Little);
    let offset = usize::try_from(qnx6::BOOT_AREA_SIZE).expect("offset fits usize");
    let expected =
        1000_u64 * 1024 + qnx6::DATA_AREA_OFFSET + qnx6::SUPERBLOCK_AREA_SIZE;
    assert_eq!(
        DetectedBootSector::Qnx6.declared_volume_size(&probe),
        Some(expected)
    );
    assert_eq!(
        qnx6::superblock_volume_size(&probe[offset..]),
        Some(expected)
    );
}

#[test]
fn qnx6_superblock_wins_over_its_implausible_mbr_shaped_boot_loader() {
    let mut probe = qnx6_detection_probe(TestByteOrder::Little);
    let partition_entry = 0x1BE;
    probe[partition_entry] = 0x56;
    probe[partition_entry + 4] = 0xB1;
    probe[partition_entry + 8..partition_entry + 12].copy_from_slice(&1_u32.to_le_bytes());
    probe[partition_entry + 12..partition_entry + 16].copy_from_slice(&100_u32.to_le_bytes());
    probe[510] = 0x55;
    probe[511] = 0xAA;

    assert!(matches!(
        parse_boot_sector(&probe),
        Ok(ParsedBootSector::Mbr { .. })
    ));
    assert_eq!(
        DetectedBootSector::from_bytes(&probe),
        DetectedBootSector::Qnx6
    );
}

#[test]
fn a_plausible_mbr_wins_over_qnx_shaped_bytes_later_in_the_disk() {
    let mut probe = qnx6_detection_probe(TestByteOrder::Little);
    let partition_entry = 0x1BE;
    probe[partition_entry + 4] = 0xB1;
    probe[partition_entry + 8..partition_entry + 12].copy_from_slice(&1_u32.to_le_bytes());
    probe[partition_entry + 12..partition_entry + 16].copy_from_slice(&100_u32.to_le_bytes());
    probe[510] = 0x55;
    probe[511] = 0xAA;

    assert_eq!(
        DetectedBootSector::from_bytes(&probe),
        DetectedBootSector::MbrPartitioned
    );
}

#[test]
fn a_valid_filesystem_boot_sector_wins_over_qnx_shaped_later_bytes() {
    let mut probe = qnx6_detection_probe(TestByteOrder::Little);
    let ntfs = build_dos_boot_sector(*b"NTFS    ", 512, 8, 0, 0, 0, 0, 0, 0);
    probe[..ntfs.len()].copy_from_slice(&ntfs);

    assert_eq!(
        DetectedBootSector::from_bytes(&probe),
        DetectedBootSector::Ntfs
    );
}
