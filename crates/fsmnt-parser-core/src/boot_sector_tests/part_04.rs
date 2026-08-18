/// Geometry of the hand-built filesystem the start-check tests use: 4 KiB
/// blocks, so the group descriptor table begins one block in, at 4096.
const START_CHECK_BLOCK_SIZE: usize = 4096;
const START_CHECK_BLOCKS_COUNT: u32 = 8192;
const START_CHECK_BLOCKS_PER_GROUP: u32 = 8192;
const START_CHECK_INODES_PER_GROUP: u32 = 2048;
const START_CHECK_INODE_SIZE: u16 = 256;
const START_CHECK_UUID: [u8; 16] = [0x11; 16];

/// A filesystem start: superblock at 1024, group-0 descriptor at 4096, with
/// the `GDT_CSUM` CRC-16 the superblock's features promise.
///
/// Every value is one a real e2fsprogs run could have written, because the
/// point of the check is that only such a layout passes it.
fn build_ext_start() -> std::vec::Vec<u8> {
    let mut buf = std::vec![0_u8; 2 * START_CHECK_BLOCK_SIZE];
    let sb = 1024;
    buf[sb + 0x04..sb + 0x08].copy_from_slice(&START_CHECK_BLOCKS_COUNT.to_le_bytes());
    buf[sb + 0x14..sb + 0x18].copy_from_slice(&0_u32.to_le_bytes()); // s_first_data_block
    buf[sb + 0x18..sb + 0x1C].copy_from_slice(&2_u32.to_le_bytes()); // s_log_block_size
    buf[sb + 0x20..sb + 0x24].copy_from_slice(&START_CHECK_BLOCKS_PER_GROUP.to_le_bytes());
    buf[sb + 0x28..sb + 0x2C].copy_from_slice(&START_CHECK_INODES_PER_GROUP.to_le_bytes());
    buf[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53_u16.to_le_bytes());
    buf[sb + 0x4C..sb + 0x50].copy_from_slice(&1_u32.to_le_bytes()); // s_rev_level
    buf[sb + 0x58..sb + 0x5A].copy_from_slice(&START_CHECK_INODE_SIZE.to_le_bytes());
    buf[sb + 0x5A..sb + 0x5C].copy_from_slice(&0_u16.to_le_bytes()); // s_block_group_nr
    buf[sb + 0x64..sb + 0x68].copy_from_slice(&0x10_u32.to_le_bytes()); // GDT_CSUM
    buf[sb + 0x68..sb + 0x78].copy_from_slice(&START_CHECK_UUID);

    let desc = START_CHECK_BLOCK_SIZE;
    buf[desc..desc + 4].copy_from_slice(&100_u32.to_le_bytes()); // bg_block_bitmap_lo
    buf[desc + 0x04..desc + 0x08].copy_from_slice(&101_u32.to_le_bytes()); // bg_inode_bitmap_lo
    buf[desc + 0x08..desc + 0x0C].copy_from_slice(&102_u32.to_le_bytes()); // bg_inode_table_lo
    buf[desc + 0x0C..desc + 0x0E].copy_from_slice(&1000_u16.to_le_bytes()); // bg_free_blocks
    buf[desc + 0x0E..desc + 0x10].copy_from_slice(&500_u16.to_le_bytes()); // bg_free_inodes
    buf[desc + 0x10..desc + 0x12].copy_from_slice(&2_u16.to_le_bytes()); // bg_used_dirs
    buf[desc + 0x12..desc + 0x14].copy_from_slice(&0x0001_u16.to_le_bytes()); // bg_flags
    buf[desc + 0x1C..desc + 0x1E].copy_from_slice(&10_u16.to_le_bytes()); // bg_itable_unused

    let checksum = start_check_descriptor_crc16(&buf[desc..desc + 32]);
    buf[desc + 0x1E..desc + 0x20].copy_from_slice(&checksum.to_le_bytes());
    buf
}

/// The `GDT_CSUM` CRC-16 over group 0's descriptor, computed the way the
/// kernel does: UUID, then the group number, then the descriptor with its
/// own checksum field stepped over rather than zeroed.
fn start_check_descriptor_crc16(desc: &[u8]) -> u16 {
    let mut crc = ext4_crc16(0xFFFF, &START_CHECK_UUID);
    crc = ext4_crc16(crc, &0_u32.to_le_bytes());
    crc = ext4_crc16(crc, &desc[..0x1E]);
    ext4_crc16(crc, &desc[0x20..])
}

#[test]
fn the_crc16_path_checksums_a_real_gdt_csum_descriptor() {
    // Group 0 of an Android /data volume with `GDT_CSUM` and no
    // `METADATA_CSUM`, lifted from a real image. The two ext4 checksum paths
    // treat `bg_checksum` differently — zeroed stand-in for CRC-32C, skipped
    // for CRC-16 — and only the skipping form reproduces what mke2fs wrote.
    let uuid: [u8; 16] = [
        0x57, 0xf8, 0xf4, 0xbc, 0xab, 0xf4, 0x65, 0x5f, 0xbf, 0x67, 0x94, 0x6f, 0xc0, 0xf9, 0xf2,
        0x5b,
    ];
    let desc: [u8; 32] = [
        0x01, 0x01, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x7e, 0x16, 0x74,
        0x1d, 0x2b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xde, 0x58,
    ];
    let mut crc = ext4_crc16(0xFFFF, &uuid);
    crc = ext4_crc16(crc, &0_u32.to_le_bytes());
    crc = ext4_crc16(crc, &desc[..0x1E]);
    assert_eq!(crc, u16::from_le_bytes([desc[0x1E], desc[0x1F]]));
}

#[test]
fn checksum_helpers_match_the_published_vectors() {
    // The same vector fs-ext's checksum tests pin: the kernel's raw
    // accumulation of "123456789" is the standard CRC-32C inverted.
    assert_eq!(ext4_crc32c(!0, b"123456789"), 0x1CF9_6D7C);
    // ext4.img's stored s_checksum_seed for a UUID of all 0x33 bytes.
    assert_eq!(ext4_crc32c(!0, &[0x33; 16]), 0x36F1_3DED);
    // CRC-16/ARC and CRC-16/MODBUS differ only in their initial value, and
    // both are published check values for this polynomial.
    assert_eq!(ext4_crc16(0x0000, b"123456789"), 0xBB3D);
    assert_eq!(ext4_crc16(0xFFFF, b"123456789"), 0x4B37);
}

#[test]
fn a_superblock_followed_by_its_descriptor_table_is_a_filesystem_start() {
    assert_eq!(ext_start_check(&build_ext_start()), ExtStartCheck::Confirmed);
}

#[test]
fn a_descriptor_whose_bitmap_lies_outside_the_filesystem_is_not_a_start() {
    let mut buf = build_ext_start();
    let desc = START_CHECK_BLOCK_SIZE;
    // 0xFFFFFFFF is what an all-ones block-allocation bitmap looks like when
    // it is read as a descriptor: far past s_blocks_count.
    buf[desc..desc + 4].copy_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    assert_eq!(ext_start_check(&buf), ExtStartCheck::Unconfirmed);
}

#[test]
fn a_superblock_followed_by_an_inode_table_is_not_a_start() {
    // What actually follows a journalled copy of block 0: the next block of
    // whatever the journal was recording. Directory inode, one block long,
    // with a plausible 2011 access time.
    let mut buf = build_ext_start();
    let desc = START_CHECK_BLOCK_SIZE;
    buf[desc..desc + 2].copy_from_slice(&0x41C0_u16.to_le_bytes()); // i_mode
    buf[desc + 0x02..desc + 0x04].copy_from_slice(&0_u16.to_le_bytes()); // i_uid
    buf[desc + 0x04..desc + 0x08].copy_from_slice(&0x0000_1000_u32.to_le_bytes()); // i_size
    buf[desc + 0x08..desc + 0x0C].copy_from_slice(&0x4EBD_02D2_u32.to_le_bytes()); // i_atime
    assert_eq!(ext_start_check(&buf), ExtStartCheck::Unconfirmed);
}

#[test]
fn a_buffer_that_stops_before_the_descriptor_decides_nothing() {
    let buf = build_ext_start();
    assert_eq!(
        ext_start_check(&buf[..2048]),
        ExtStartCheck::Inconclusive,
        "a short read is not evidence either way",
    );
}

#[test]
fn a_structurally_sound_descriptor_with_a_wrong_checksum_is_not_a_start() {
    let mut buf = build_ext_start();
    let checksum = START_CHECK_BLOCK_SIZE + 0x1E;
    buf[checksum] ^= 0xFF;
    assert_eq!(ext_start_check(&buf), ExtStartCheck::Unconfirmed);
}

/// Block the hand-built descriptor points its inode table at, and the byte
/// offset of inode 2 that follows from it: one inode into that block.
const START_CHECK_INODE_TABLE_BLOCK: u64 = 102;
const START_CHECK_ROOT_INODE_OFFSET: u64 =
    START_CHECK_INODE_TABLE_BLOCK * START_CHECK_BLOCK_SIZE as u64 + START_CHECK_INODE_SIZE as u64;

/// A root inode as mke2fs writes it: `drwxr-xr-x`, three links (`.`, `..`
/// from itself, and the parent's entry), one block of directory data, alive.
fn build_root_inode() -> std::vec::Vec<u8> {
    let mut inode = std::vec![0_u8; usize::from(START_CHECK_INODE_SIZE)];
    inode[0x00..0x02].copy_from_slice(&0x41ED_u16.to_le_bytes()); // i_mode
    inode[0x04..0x08].copy_from_slice(&4096_u32.to_le_bytes()); // i_size_lo
    inode[0x1A..0x1C].copy_from_slice(&3_u16.to_le_bytes()); // i_links_count
    inode
}

#[test]
fn a_root_inode_reads_as_the_directory_it_is() {
    assert!(ext_root_inode_plausible(&build_root_inode()));
}

#[test]
fn the_root_inode_check_needs_a_whole_base_inode() {
    let inode = build_root_inode();
    assert!(
        !ext_root_inode_plausible(&inode[..127]),
        "under 128 bytes there is no inode to judge",
    );
    assert!(ext_root_inode_plausible(&inode[..128]));
}

#[test]
fn garbage_where_the_root_inode_should_be_is_not_a_root_inode() {
    // The three things actually found at a wrong inode-table address: an
    // all-ones bitmap block, an unwritten one, and a regular file — which is
    // what a *right* address in the wrong filesystem tends to hold.
    let mut regular = build_root_inode();
    regular[0x00..0x02].copy_from_slice(&0x81A4_u16.to_le_bytes()); // -rw-r--r--
    for (name, inode) in [
        ("0xFF fill", std::vec![0xFF_u8; 256]),
        ("all zero", std::vec![0_u8; 256]),
        ("a regular file", regular),
    ] {
        assert!(
            !ext_root_inode_plausible(&inode),
            "{name} is not the root directory",
        );
    }
}

#[test]
fn a_deleted_or_unlinked_root_inode_is_not_one() {
    let mut deleted = build_root_inode();
    deleted[0x14..0x18].copy_from_slice(&0x4EBD_02D2_u32.to_le_bytes()); // i_dtime
    assert!(!ext_root_inode_plausible(&deleted), "a live root never has a deletion time");

    let mut unlinked = build_root_inode();
    unlinked[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes()); // i_links_count
    assert!(!ext_root_inode_plausible(&unlinked), "the root always has at least `.` and `..`");

    let mut empty = build_root_inode();
    empty[0x04..0x08].copy_from_slice(&0_u32.to_le_bytes()); // i_size_lo
    assert!(!ext_root_inode_plausible(&empty), "a directory occupies at least one block");
}

#[test]
fn the_root_inode_location_follows_the_descriptor_to_the_inode_table() {
    let location = ext_root_inode_location(&build_ext_start()).expect("a confirmed start");
    assert_eq!(location.offset, START_CHECK_ROOT_INODE_OFFSET);
    assert_eq!(location.len, u32::from(START_CHECK_INODE_SIZE));
}

#[test]
fn only_a_confirmed_start_has_a_root_inode_to_locate() {
    let mut buf = build_ext_start();
    let checksum = START_CHECK_BLOCK_SIZE + 0x1E;
    buf[checksum] ^= 0xFF;
    assert_eq!(ext_start_check(&buf), ExtStartCheck::Unconfirmed);
    assert!(
        ext_root_inode_location(&buf).is_none(),
        "an unconfirmed table's inode-table pointer is not worth following",
    );
    assert!(ext_root_inode_location(&buf[..2048]).is_none());
}

#[test]
fn every_ext_fixture_has_a_readable_root_inode_where_it_says() {
    // The false-negative guard for the root-inode check: it may reject
    // whatever it likes, but never a filesystem mkfs actually wrote, because
    // rejecting one hides the only mountable thing in an image.
    for (path, image) in ext_fixtures() {
        // 68 KiB reaches the first descriptor of even a 64 KiB-block
        // filesystem, which is the largest ext supports.
        let prefix = &image[..image.len().min(68 * 1024)];
        let location = ext_root_inode_location(prefix)
            .unwrap_or_else(|| std::panic!("{} is a real ext filesystem", path.display()));
        let start = usize::try_from(location.offset).expect("offset fits");
        let end = start + usize::try_from(location.len).expect("length fits");
        assert!(
            end <= image.len(),
            "{} is {} bytes and puts its root inode at {start}",
            path.display(),
            image.len(),
        );
        assert!(
            ext_root_inode_plausible(&image[start..end]),
            "{} has its root directory at {start} and the check must see it",
            path.display(),
        );
    }
}

#[test]
fn the_check_confirms_the_start_of_every_ext_fixture() {
    // The false-negative guard: whatever the check rejects, it must never
    // reject a filesystem that mkfs actually wrote.
    for (path, image) in ext_fixtures() {
        // 68 KiB reaches the first descriptor of even a 64 KiB-block
        // filesystem, which is the largest ext supports.
        let prefix = &image[..image.len().min(68 * 1024)];
        assert_eq!(
            ext_start_check(prefix),
            ExtStartCheck::Confirmed,
            "{} is a real ext filesystem and must be recognised as one",
            path.display(),
        );
    }
}

/// Every generated ext fixture, read whole.
///
/// The images are produced by `testdata/gen-fixtures.sh` and gitignored, so
/// a clean checkout simply has nothing here and the tests that iterate this
/// pass vacuously; the count goes to stderr so a skip is visible rather than
/// silent.
fn ext_fixtures() -> std::vec::Vec<(std::path::PathBuf, std::vec::Vec<u8>)> {
    let testdata =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../formats/fs-ext/testdata");
    let Ok(entries) = std::fs::read_dir(&testdata) else {
        std::eprintln!("no ext fixtures in {}", testdata.display());
        return std::vec::Vec::new();
    };
    let mut fixtures = std::vec::Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("img") {
            continue;
        }
        if let Ok(image) = std::fs::read(&path) {
            fixtures.push((path, image));
        }
    }
    std::eprintln!("read {} ext fixture(s)", fixtures.len());
    fixtures
}
