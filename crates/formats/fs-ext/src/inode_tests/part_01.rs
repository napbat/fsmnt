use super::*;

#[test]
fn raw_inode_is_128_bytes() {
    assert_eq!(core::mem::size_of::<RawInode>(), 128);
}

#[test]
fn ea_inode_size_match_accepts_equal_sizes() {
    let size = validate_ea_inode_size(77, 4096, 4096).unwrap();
    assert_eq!(size, 4096);
}

#[test]
fn ea_inode_size_match_rejects_oversized_inode() {
    let err = validate_ea_inode_size(77, 8192, 4096).unwrap_err();
    assert!(matches!(err, ExtError::InvalidInode { inode: 77, .. }));
}

#[test]
fn ea_inode_size_match_rejects_undersized_inode() {
    let err = validate_ea_inode_size(77, 1024, 4096).unwrap_err();
    assert!(matches!(err, ExtError::InvalidInode { inode: 77, .. }));
}

#[test]
fn inode_flags_known_bits() {
    let flags = InodeFlags::EXTENTS_FL | InodeFlags::HUGE_FILE_FL;
    assert!(flags.contains(InodeFlags::EXTENTS_FL));
    assert!(!flags.contains(InodeFlags::ENCRYPT_FL));
}

#[test]
fn inode_flags_low_priority_catalog_bits() {
    // Catalog inventory bits added for forensic completeness.
    assert_eq!(InodeFlags::EOFBLOCKS_FL.bits(), 0x0040_0000);
    assert_eq!(InodeFlags::SNAPFILE_FL.bits(), 0x0100_0000);
    assert_eq!(InodeFlags::DAX_FL.bits(), 0x0200_0000);
    assert_eq!(InodeFlags::SNAPFILE_DELETED_FL.bits(), 0x0400_0000);
    assert_eq!(InodeFlags::SNAPFILE_SHRUNK_FL.bits(), 0x0800_0000);

    // Round-trip an inode with all five new bits set.
    let raw = 0x0040_0000 | 0x0100_0000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000;
    let flags = InodeFlags::from_bits_retain(raw);
    assert!(flags.contains(InodeFlags::EOFBLOCKS_FL));
    assert!(flags.contains(InodeFlags::SNAPFILE_FL));
    assert!(flags.contains(InodeFlags::DAX_FL));
    assert!(flags.contains(InodeFlags::SNAPFILE_DELETED_FL));
    assert!(flags.contains(InodeFlags::SNAPFILE_SHRUNK_FL));
}

#[test]
fn inode_flags_unknown_bit_preserved_by_from_bits_retain() {
    // Forensic invariant: unknown future bits round-trip through
    // `from_bits_retain` without being silently dropped.
    let raw = 0x8000_0000u32; // unassigned today
    let flags = InodeFlags::from_bits_retain(raw);
    assert_eq!(flags.bits(), raw);
}

#[test]
fn file_type_constants() {
    assert_eq!(S_IFIFO, 0x1000);
    assert_eq!(S_IFCHR, 0x2000);
    assert_eq!(S_IFDIR, 0x4000);
    assert_eq!(S_IFBLK, 0x6000);
    assert_eq!(S_IFREG, 0x8000);
    assert_eq!(S_IFLNK, 0xA000);
    assert_eq!(S_IFSOCK, 0xC000);
}

fn raw_with_mode(mode: u16) -> RawInode {
    RawInode {
        i_mode: U16::new(mode),
        i_uid: U16::new(0),
        i_size_lo: U32::new(0),
        i_atime: U32::new(0),
        i_ctime: U32::new(0),
        i_mtime: U32::new(0),
        i_dtime: U32::new(0),
        i_gid: U16::new(0),
        i_links_count: U16::new(1),
        i_blocks_lo: U32::new(0),
        i_flags: U32::new(0),
        osd1: U32::new(0),
        i_block: [0u8; 60],
        i_generation: U32::new(0),
        i_file_acl_lo: U32::new(0),
        i_size_high: U32::new(0),
        i_obso_faddr: U32::new(0),
        osd2: [0u8; 12],
    }
}

fn raw_device(mode: u16, i_block: [u8; 60]) -> RawInode {
    let mut raw = raw_with_mode(mode);
    raw.i_block = i_block;
    raw
}

#[test]
fn ext_inode_kind_dispatches_each_s_if() {
    for (mode, expected) in [
        (S_IFIFO, ExtFileKind::Fifo),
        (S_IFCHR, ExtFileKind::CharacterDevice),
        (S_IFDIR, ExtFileKind::Directory),
        (S_IFBLK, ExtFileKind::BlockDevice),
        (S_IFREG, ExtFileKind::RegularFile),
        (S_IFLNK, ExtFileKind::Symlink),
        (S_IFSOCK, ExtFileKind::Socket),
    ] {
        let inode = ExtInode::from_raw_for_test(raw_with_mode(mode | 0o644), 100);
        assert_eq!(inode.kind(), expected, "mode 0x{mode:04X}");
    }
}

#[test]
fn ext_inode_kind_unknown_for_zero_mode_bits() {
    let inode = ExtInode::from_raw_for_test(raw_with_mode(0), 101);
    assert_eq!(inode.kind(), ExtFileKind::Unknown);
}

#[test]
fn ext_inode_is_helpers_match_kind_for_special_types() {
    let fifo = ExtInode::from_raw_for_test(raw_with_mode(S_IFIFO | 0o600), 1);
    assert!(fifo.is_fifo());
    assert!(!fifo.is_character_device() && !fifo.is_block_device() && !fifo.is_socket());

    let chr = ExtInode::from_raw_for_test(raw_with_mode(S_IFCHR | 0o600), 2);
    assert!(chr.is_character_device());
    assert!(!chr.is_fifo() && !chr.is_block_device() && !chr.is_socket());

    let blk = ExtInode::from_raw_for_test(raw_with_mode(S_IFBLK | 0o600), 3);
    assert!(blk.is_block_device());
    assert!(!blk.is_fifo() && !blk.is_character_device() && !blk.is_socket());

    let sock = ExtInode::from_raw_for_test(raw_with_mode(S_IFSOCK | 0o600), 4);
    assert!(sock.is_socket());
    assert!(!sock.is_fifo() && !sock.is_character_device() && !sock.is_block_device());
}

#[test]
fn device_id_none_for_non_device_inode() {
    for mode in [S_IFIFO, S_IFDIR, S_IFREG, S_IFLNK, S_IFSOCK] {
        let inode = ExtInode::from_raw_for_test(raw_with_mode(mode | 0o644), 10);
        assert!(inode.device_id().is_none(), "mode 0x{mode:04X}");
    }
}

#[test]
fn device_id_old_encoding_low_16_bits() {
    // include/linux/kdev_t.h: old_decode_dev(u16 val) =
    //     MKDEV((val >> 8) & 255, val & 255)
    // raw value 0x0301 => major=3, minor=1 (e.g. /dev/ttyS0 territory)
    let mut blocks = [0u8; 60];
    blocks[0..4].copy_from_slice(&0x0000_0301u32.to_le_bytes());
    let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 11);
    assert_eq!(inode.device_id(), Some(ExtDeviceId { major: 3, minor: 1 }));
}

#[test]
fn device_id_old_encoding_ignores_high_word_and_i_block_1() {
    // fs/ext4/inode.c:5508-5510 — when i_block[0] != 0, only the
    // u16 value of i_block[0] (after C-side truncation) is used;
    // i_block[1] is ignored.
    let mut blocks = [0u8; 60];
    blocks[0..4].copy_from_slice(&0xFFFF_FF55u32.to_le_bytes());
    blocks[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 12);
    assert_eq!(
        inode.device_id(),
        Some(ExtDeviceId {
            major: 0xff,
            minor: 0x55,
        })
    );
}

#[test]
fn device_id_new_encoding_when_i_block0_zero() {
    // include/linux/kdev_t.h: new_encode_dev(dev_t dev) =
    //   (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12)
    // For major=0x103, minor=0x301:
    //   (0x01) | (0x103 << 8) | ((0x300) << 12) = 0x01 | 0x10300 | 0x300000
    //   = 0x310301
    let mut blocks = [0u8; 60];
    blocks[0..4].copy_from_slice(&0u32.to_le_bytes());
    blocks[4..8].copy_from_slice(&0x0031_0301u32.to_le_bytes());
    let inode = ExtInode::from_raw_for_test(raw_device(S_IFBLK | 0o660, blocks), 13);
    assert_eq!(
        inode.device_id(),
        Some(ExtDeviceId {
            major: 0x103,
            minor: 0x301,
        })
    );
}

#[test]
fn device_id_new_encoding_full_range() {
    // Max 12-bit major (0xfff) + max 20-bit minor (0xfffff).
    //   (0xff) | (0xfff << 8) | ((0xfff00) << 12)
    //   = 0xff | 0xfff00 | 0xfff00000 = 0xffff_ffff
    let mut blocks = [0u8; 60];
    blocks[0..4].copy_from_slice(&0u32.to_le_bytes());
    blocks[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o660, blocks), 14);
    assert_eq!(
        inode.device_id(),
        Some(ExtDeviceId {
            major: 0xfff,
            minor: 0xfffff,
        })
    );
}

#[test]
fn device_id_new_encoding_zero_both_words_decodes_to_zero() {
    // Both words zero is the "new encoding" branch with rdev=0.
    // Valid byte-level encoding (no malformed case).
    let inode = ExtInode::from_raw_for_test(raw_device(S_IFCHR | 0o600, [0u8; 60]), 15);
    assert_eq!(inode.device_id(), Some(ExtDeviceId { major: 0, minor: 0 }));
}

fn raw_inode_with_flags(flags_bits: u32, mode: u16) -> RawInode {
    RawInode {
        i_mode: U16::new(mode),
        i_uid: U16::new(0),
        i_size_lo: U32::new(0),
        i_atime: U32::new(0),
        i_ctime: U32::new(0),
        i_mtime: U32::new(0),
        i_dtime: U32::new(0),
        i_gid: U16::new(0),
        i_links_count: U16::new(1),
        i_blocks_lo: U32::new(0),
        i_flags: U32::new(flags_bits),
        osd1: U32::new(0),
        i_block: [0u8; 60],
        i_generation: U32::new(0),
        i_file_acl_lo: U32::new(0),
        i_size_high: U32::new(0),
        i_obso_faddr: U32::new(0),
        osd2: [0u8; 12],
    }
}

#[test]
fn is_casefolded_reads_inode_flag() {
    // EXT4_CASEFOLD_FL = 0x4000_0000 (inode.rs:93).
    let dir =
        ExtInode::from_raw_for_test(raw_inode_with_flags(0x4000_0000, S_IFDIR | 0o755), 2);
    assert!(dir.is_casefolded());

    let plain_dir = ExtInode::from_raw_for_test(raw_inode_with_flags(0, S_IFDIR | 0o755), 3);
    assert!(!plain_dir.is_casefolded());
}

#[test]
fn is_encrypted_reads_inode_flag() {
    // EXT4_ENCRYPT_FL = 0x0000_0800 (inode.rs:80).
    let enc =
        ExtInode::from_raw_for_test(raw_inode_with_flags(0x0000_0800, S_IFREG | 0o644), 42);
    assert!(enc.is_encrypted());

    let plain = ExtInode::from_raw_for_test(raw_inode_with_flags(0, S_IFREG | 0o644), 43);
    assert!(!plain.is_encrypted());
}

/// Build a synthetic inode buffer with given `extra_isize` and
/// known timestamp extra values at the correct offsets.
fn make_inode_buf(size: usize, extra_isize: u16) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    if size >= 130 {
        buf[0x80] = (extra_isize & 0xFF) as u8;
        buf[0x81] = (extra_isize >> 8) as u8;
    }
    // Plant known values at extended timestamp offsets
    if size >= 0x8C {
        // ctime_extra = 0x11
        buf[0x84..0x88].copy_from_slice(&0x11u32.to_le_bytes());
        // mtime_extra = 0x22
        buf[0x88..0x8C].copy_from_slice(&0x22u32.to_le_bytes());
    }
    if size >= 0x90 {
        // atime_extra = 0x33
        buf[0x8C..0x90].copy_from_slice(&0x33u32.to_le_bytes());
    }
    if size >= 0x98 {
        // crtime_base = 0x44, crtime_extra = 0x55
        buf[0x90..0x94].copy_from_slice(&0x44u32.to_le_bytes());
        buf[0x94..0x98].copy_from_slice(&0x55u32.to_le_bytes());
    }
    buf
}

#[test]
fn parse_ts_extras_inode_size_128() {
    let buf = make_inode_buf(128, 0);
    let extras = parse_timestamp_extras(&buf, 128);
    assert_eq!(extras.present, 0);
}

#[test]
fn parse_ts_extras_extra_isize_zero() {
    let buf = make_inode_buf(256, 0);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, 0);
}

#[test]
fn parse_ts_extras_extra_isize_7_no_fields() {
    // i_extra_isize=7: ctime_extra needs >=8, so nothing available
    let buf = make_inode_buf(256, 7);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, 0);
}

#[test]
fn parse_ts_extras_extra_isize_8_ctime_only() {
    // i_extra_isize=8: ctime_extra at 0x84..0x88 fits (8>=8),
    // mtime_extra at 0x88..0x8C needs >=12
    let buf = make_inode_buf(256, 8);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, TS_CTIME_EXTRA);
    assert_eq!(extras.ctime_extra, 0x11);
}

#[test]
fn parse_ts_extras_extra_isize_12_ctime_mtime() {
    // i_extra_isize=12: mtime_extra at 0x88..0x8C fits (12>=12)
    let buf = make_inode_buf(256, 12);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, TS_CTIME_EXTRA | TS_MTIME_EXTRA);
    assert_eq!(extras.ctime_extra, 0x11);
    assert_eq!(extras.mtime_extra, 0x22);
}

#[test]
fn parse_ts_extras_extra_isize_15_no_atime() {
    // i_extra_isize=15: atime_extra at 0x8C..0x90 needs >=16
    let buf = make_inode_buf(256, 15);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, TS_CTIME_EXTRA | TS_MTIME_EXTRA);
}

#[test]
fn parse_ts_extras_extra_isize_16_atime() {
    // i_extra_isize=16: atime_extra at 0x8C..0x90 fits (16>=16)
    let buf = make_inode_buf(256, 16);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(
        extras.present,
        TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA
    );
    assert_eq!(extras.atime_extra, 0x33);
}

#[test]
fn parse_ts_extras_extra_isize_19_no_crtime() {
    // i_extra_isize=19: i_crtime at 0x90..0x94 needs >=20
    let buf = make_inode_buf(256, 19);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(
        extras.present,
        TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA
    );
}

#[test]
fn parse_ts_extras_extra_isize_20_crtime_base_only() {
    // i_extra_isize=20: i_crtime at 0x90..0x94 fits (20>=20),
    // i_crtime_extra at 0x94..0x98 needs >=24
    let buf = make_inode_buf(256, 20);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(
        extras.present,
        TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE
    );
    assert_eq!(extras.crtime_base, 0x44);
}

#[test]
fn parse_ts_extras_extra_isize_23_no_crtime_extra() {
    // i_extra_isize=23: i_crtime_extra at 0x94..0x98 needs >=24
    let buf = make_inode_buf(256, 23);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(
        extras.present,
        TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE
    );
}

#[test]
fn parse_ts_extras_extra_isize_24_crtime_full() {
    let buf = make_inode_buf(256, 24);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(
        extras.present,
        TS_CTIME_EXTRA | TS_MTIME_EXTRA | TS_ATIME_EXTRA | TS_CRTIME_BASE | TS_CRTIME_EXTRA
    );
    assert_eq!(extras.crtime_base, 0x44);
    assert_eq!(extras.crtime_extra, 0x55);
}

#[test]
fn parse_ts_extras_buf_too_short_for_claimed_extra() {
    // extra_isize=32 but buffer is only 140 bytes
    let buf = make_inode_buf(140, 32);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, 0);
}

#[test]
fn parse_ts_extras_buf_short_for_claimed_extra_rejects_all() {
    // extra_isize=24 but buffer only 0x90 bytes (128+24=152 > 144).
    // The entire extended region is inconsistent, so no fields parsed.
    let buf = make_inode_buf(0x90, 24);
    let extras = parse_timestamp_extras(&buf, 256);
    assert_eq!(extras.present, 0);
}

#[test]
fn inode_extra_isize_reads_present_value() {
    let buf = make_inode_buf(256, 32);
    assert_eq!(inode_extra_isize(&buf, 256), 32);
}

#[test]
fn inode_extra_isize_returns_zero_for_small_inode() {
    let buf = make_inode_buf(128, 32);
    assert_eq!(inode_extra_isize(&buf, 128), 0);
}

#[test]
fn raw_i_dtime_returns_le_u32_unchanged() {
    let mut raw_bytes = [0u8; 128];
    // i_dtime at offset 0x14 = 0x1234_5678
    raw_bytes[0x14..0x18].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    let raw: &RawInode = zerocopy::FromBytes::ref_from_bytes(&raw_bytes).unwrap();
    assert_eq!(raw.i_dtime.get(), 0x1234_5678);
}

#[test]
fn ea_inode_refcount_reads_i_ctime_high_u32_and_osd1_low_u32() {
    // i_ctime at 0x0C..0x10 = 0x1234_5678 (high 32 bits of refcount).
    // osd1 at 0x24..0x28 = 0xABCD_EF01 (low 32 bits, l_i_version).
    // Expected refcount = 0x1234_5678_ABCD_EF01.
    let mut bytes = [0u8; 128];
    bytes[0x0C..0x10].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes[0x24..0x28].copy_from_slice(&0xABCD_EF01u32.to_le_bytes());
    let raw: RawInode = *zerocopy::FromBytes::ref_from_bytes(&bytes).unwrap();
    let inode = ExtInode::from_raw_for_test(raw, 0);
    assert_eq!(inode.ea_inode_refcount(), 0x1234_5678_ABCD_EF01u64);
}

#[test]
fn set_ea_inode_refcount_bytes_writes_i_ctime_high_and_osd1_low() {
    let mut bytes = [0u8; 256];
    set_ea_inode_refcount_bytes(&mut bytes, 0x0000_0001_DEAD_BEEFu64);
    // i_ctime at 0x0C..0x10: high 32 bits = 0x0000_0001
    assert_eq!(&bytes[0x0C..0x10], &0x0000_0001u32.to_le_bytes());
    // osd1 at 0x24..0x28: low 32 bits = 0xDEAD_BEEF
    assert_eq!(&bytes[0x24..0x28], &0xDEAD_BEEFu32.to_le_bytes());
}

#[test]
fn set_ea_inode_refcount_bytes_round_trips_through_reader() {
    let mut bytes = [0u8; 256];
    set_ea_inode_refcount_bytes(&mut bytes, 0xCAFE_BABE_1234_5678_u64);
    let raw: RawInode = *zerocopy::FromBytes::ref_from_bytes(&bytes[..128]).unwrap();
    let inode = ExtInode::from_raw_for_test(raw, 0);
    assert_eq!(inode.ea_inode_refcount(), 0xCAFE_BABE_1234_5678_u64);
}

/// EA inode 536 in ext4.img is the backing store for `ea_inode_file`'s
/// `user.big_value` xattr (`e_value_inum` = 536). It is referenced exactly once,
/// so its on-disk refcount — packed as (`i_ctime` << 32) | osd1 — must be 1.
///
/// This test pins the `i_ctime` + osd1 field choice against future regressions;
/// the synthetic byte tests above cannot catch a wrong-offset bug because they
/// exercise both encode and decode through the same offsets.
///
/// Note: inode 536 (not 535) because multiblock.bin (added for truncate
/// fixtures) was inserted before `sparse_file` in the ext4.img tree, shifting
/// all inodes allocated after that point by one.
#[test]
fn ea_inode_refcount_reads_1_for_fixture_ea_inode_536() {
    let bytes = crate::test_support::load_clean_ext4_image();
    let mut cursor = std::io::Cursor::new(bytes);
    let ext = crate::ext::Ext::new(&mut cursor).expect("open ext4.img");
    // Inode 536 is the EA inode backing ea_inode_file's big_value xattr.
    // It has EA_INODE_FL and is referenced once, so refcount must be 1.
    let ea_inode = ext.inode(&mut cursor, 536).expect("read EA inode 536");
    assert_eq!(
        ea_inode.ea_inode_refcount(),
        1,
        "EA inode 536 refcount must be 1 (referenced once by ea_inode_file)"
    );
}
