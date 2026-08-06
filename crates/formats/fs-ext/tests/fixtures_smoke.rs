//! Smoke tests for the generated ext2, ext3, and ext4 fixture images.

mod support;

#[test]
fn fixtures_exist_and_load() {
    for name in ["ext2.img", "ext2-no-filetype.img", "ext3.img", "ext4.img"] {
        let fs = support::load_image(name);
        assert!(fs.get_ref().len() > 2048, "{name} too small");
    }
}

#[test]
fn ext2_has_correct_magic() {
    let fs = support::load_image("ext2.img");
    let buf = fs.get_ref();
    let magic = u16::from_le_bytes([buf[1024 + 0x38], buf[1024 + 0x39]]);
    assert_eq!(magic, 0xEF53);
}

#[test]
fn ext2_no_filetype_has_correct_magic() {
    let fs = support::load_image("ext2-no-filetype.img");
    let buf = fs.get_ref();
    let magic = u16::from_le_bytes([buf[1024 + 0x38], buf[1024 + 0x39]]);
    assert_eq!(magic, 0xEF53);
}

#[test]
fn ext3_has_correct_magic() {
    let fs = support::load_image("ext3.img");
    let buf = fs.get_ref();
    let magic = u16::from_le_bytes([buf[1024 + 0x38], buf[1024 + 0x39]]);
    assert_eq!(magic, 0xEF53);
}

#[test]
fn ext4_has_correct_magic() {
    let fs = support::load_image("ext4.img");
    let buf = fs.get_ref();
    let magic = u16::from_le_bytes([buf[1024 + 0x38], buf[1024 + 0x39]]);
    assert_eq!(magic, 0xEF53);
}

#[test]
fn ext4_has_64bit_flag() {
    let fs = support::load_image("ext4.img");
    let buf = fs.get_ref();
    let incompat = u32::from_le_bytes(buf[1024 + 0x60..1024 + 0x64].try_into().unwrap());
    assert_ne!(incompat & 0x0080, 0, "64BIT flag should be set");
}

#[test]
fn ext2_is_rev0() {
    let fs = support::load_image("ext2.img");
    let buf = fs.get_ref();
    let rev = u32::from_le_bytes(buf[1024 + 0x4C..1024 + 0x50].try_into().unwrap());
    assert_eq!(rev, 0, "ext2.img should be revision 0");
}

#[test]
fn ext3_has_journal_flag() {
    let fs = support::load_image("ext3.img");
    let buf = fs.get_ref();
    // COMPAT_HAS_JOURNAL = 0x0004, at offset 0x5C
    let compat = u32::from_le_bytes(buf[1024 + 0x5C..1024 + 0x60].try_into().unwrap());
    assert_ne!(compat & 0x0004, 0, "HAS_JOURNAL compat flag should be set");
}

#[test]
fn ext4_has_metadata_csum() {
    let fs = support::load_image("ext4.img");
    let buf = fs.get_ref();
    // RO_COMPAT_METADATA_CSUM = 0x0400, at offset 0x64
    let ro_compat = u32::from_le_bytes(buf[1024 + 0x64..1024 + 0x68].try_into().unwrap());
    assert_ne!(
        ro_compat & 0x0400,
        0,
        "METADATA_CSUM ro_compat flag should be set"
    );
}

#[test]
fn images_have_correct_uuids() {
    // UUID is at superblock offset 0x68, 16 bytes
    let expected = [
        (
            "ext2.img",
            [
                0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                0x11, 0x11,
            ],
        ),
        (
            "ext2-no-filetype.img",
            [
                0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12,
                0x12, 0x12,
            ],
        ),
        (
            "ext3.img",
            [
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22,
            ],
        ),
        (
            "ext4.img",
            [
                0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                0x33, 0x33,
            ],
        ),
    ];

    for (name, uuid) in expected {
        let fs = support::load_image(name);
        let buf = fs.get_ref();
        let actual = &buf[1024 + 0x68..1024 + 0x78];
        assert_eq!(actual, uuid, "{name} UUID mismatch");
    }
}

#[test]
fn ext2_no_filetype_clears_incompat_filetype() {
    let fs = support::load_image("ext2-no-filetype.img");
    let buf = fs.get_ref();
    let incompat = u32::from_le_bytes(buf[1024 + 0x60..1024 + 0x64].try_into().unwrap());
    assert_eq!(
        incompat & 0x0002,
        0,
        "INCOMPAT_FILETYPE should be disabled in ext2-no-filetype.img"
    );
}

#[test]
fn ext4_forensics_has_plausible_mkfs_time_and_no_errors() {
    let (ext, _fs) = support::open_ext("ext4.img");
    let f = ext.superblock_forensics();
    assert!(
        f.mkfs_time_seconds > 0,
        "mkfs_time should be populated on the test image"
    );
    assert_eq!(f.error_count, 0, "test image should be clean (no errors)");
    assert!(
        f.first_error.is_none(),
        "clean image should have no first_error record"
    );
    assert!(
        f.last_error.is_none(),
        "clean image should have no last_error record"
    );
    // first_inode is 11 for ext4 (the standard EXT4_GOOD_OLD_FIRST_INO).
    assert_eq!(ext.first_inode(), 11);
}

#[test]
fn ext4_fixture_does_not_have_strict_encoding() {
    let (ext, _fs) = support::open_ext("ext4.img");
    // The bundled fixtures are not built with `casefold` + strict mode,
    // so `has_strict_encoding` must be false on them.
    assert!(
        !ext.has_strict_encoding(),
        "ext4.img should not have strict encoding"
    );
    assert_eq!(ext.encoding_flags() & 0x0001, 0);
}

#[test]
fn ext4_fixture_has_no_mmp_returns_none() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    assert!(
        !ext.has_mmp(),
        "test fixtures are not built with INCOMPAT_MMP",
    );
    let mmp = ext.read_mmp_block(&mut fs).unwrap();
    assert!(
        mmp.is_none(),
        "MMP-disabled filesystem must return None from read_mmp_block",
    );
}

#[test]
fn ext4_superblock_checksum_valid() {
    let (ext, _fs) = support::open_ext("ext4.img");
    assert_eq!(
        ext.superblock_checksum(),
        fs_ext::ChecksumState::Valid,
        "ext4 superblock checksum should validate"
    );
}

#[test]
fn ext4_fixture_exposes_first_inode_as_eleven() {
    let (ext, _fs) = support::open_ext("ext4.img");
    // EXT4_GOOD_OLD_FIRST_INO = 11. Inodes below this are reserved
    // for root, journal, resize, and quota internals.
    assert_eq!(ext.first_inode(), 11);
}

#[test]
fn ext2_rev0_fixture_first_inode_falls_back_to_eleven() {
    // ext2.img is revision 0; `s_first_ino` is not a dynamic field on
    // rev0 superblocks and may read as zero. The Ext open path must
    // substitute EXT2_GOOD_OLD_FIRST_INO = 11.
    let (ext, _fs) = support::open_ext("ext2.img");
    assert_eq!(ext.first_inode(), 11);
}

#[test]
fn ext2_superblock_checksum_unknown() {
    let (ext, _fs) = support::open_ext("ext2.img");
    assert_eq!(
        ext.superblock_checksum(),
        fs_ext::ChecksumState::Unknown,
        "ext2 has no METADATA_CSUM"
    );
}

#[test]
fn ext4_group_descriptor_checksums_valid() {
    let (ext, _fs) = support::open_ext("ext4.img");
    let valid_count = ext
        .group_checksums()
        .filter(|state| *state == fs_ext::ChecksumState::Valid)
        .count();
    assert_eq!(
        valid_count,
        usize::try_from(ext.group_count()).expect("fixture group count fits usize"),
        "every ext4 group descriptor checksum should validate"
    );
    for (i, state) in ext.group_checksums().enumerate() {
        assert_eq!(
            state,
            fs_ext::ChecksumState::Valid,
            "ext4 group {i} checksum should validate"
        );
    }
}

#[test]
fn ext4_inode_checksum_valid() {
    let (ext, mut fs) = support::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert_eq!(
        root.checksum_state(),
        fs_ext::ChecksumState::Valid,
        "ext4 root inode checksum should validate"
    );
}

#[test]
fn ext2_inode_checksum_unknown() {
    let (ext, mut fs) = support::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert_eq!(
        root.checksum_state(),
        fs_ext::ChecksumState::Unknown,
        "ext2 has no METADATA_CSUM"
    );
}
