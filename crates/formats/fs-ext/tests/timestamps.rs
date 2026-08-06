mod common;

// ── ext2: 128-byte inodes, no extended timestamps ───────────────────

#[test]
fn ext2_root_has_no_crtime() {
    let (ext, mut fs) = common::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert!(
        root.crtime().is_none(),
        "ext2 rev0 inodes (128 bytes) have no creation time"
    );
}

#[test]
fn ext2_timestamps_have_zero_nanoseconds() {
    let (ext, mut fs) = common::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    assert_eq!(root.atime().nanoseconds, 0);
    assert_eq!(root.ctime().nanoseconds, 0);
    assert_eq!(root.mtime().nanoseconds, 0);
    assert_eq!(root.dtime().nanoseconds, 0);
}

#[test]
fn ext2_base_timestamps_are_correct() {
    let (ext, mut fs) = common::open_ext("ext2.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    // Fixture created with E2FSPROGS_FAKE_TIME=1700000000
    assert_eq!(root.ctime().seconds, 1_700_000_000);
    assert_eq!(root.mtime().seconds, 1_700_000_000);
    assert_eq!(root.atime().seconds, 1_700_000_000);
}

// ── ext4: 256-byte inodes with i_extra_isize=32 ────────────────────

#[test]
fn ext4_root_has_crtime() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    let crtime = root
        .crtime()
        .expect("ext4 inode with i_extra_isize=32 should have crtime");
    // Fixture created with E2FSPROGS_FAKE_TIME=1700000000
    assert_eq!(crtime.seconds, 1_700_000_000);
}

#[test]
fn ext4_extended_timestamps_use_extra_fields() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    // With extended fields present, the decode path runs through
    // decode_extended_timestamp(). The fixture has extra=0 for all
    // fields (epoch 0, 0 nanoseconds), so the result matches the
    // base value.
    assert_eq!(root.ctime().seconds, 1_700_000_000);
    assert_eq!(root.mtime().seconds, 1_700_000_000);
    assert_eq!(root.atime().seconds, 1_700_000_000);
    assert_eq!(root.ctime().nanoseconds, 0);
    assert_eq!(root.mtime().nanoseconds, 0);
    assert_eq!(root.atime().nanoseconds, 0);
}

#[test]
fn ext4_dtime_remains_base_only() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    // dtime has no extended field, always base-only
    let dtime = root.dtime();
    assert_eq!(dtime.seconds, 0, "root dir should not be deleted");
    assert_eq!(dtime.nanoseconds, 0);
}

#[test]
fn ext4_crtime_equals_ctime_for_fixture() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    let crtime = root.crtime().unwrap();
    // In a freshly-created fixture, creation time equals change time
    assert_eq!(crtime.seconds, root.ctime().seconds);
}

// ── ext3: 256-byte inodes with extended fields ──────────────────────

#[test]
fn ext3_has_crtime() {
    let (ext, mut fs) = common::open_ext("ext3.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    // ext3 fixture has inode_size=256, i_extra_isize=32 which covers
    // all extended timestamp fields including crtime
    let crtime = root
        .crtime()
        .expect("ext3 inode with i_extra_isize=32 should have crtime");
    assert_eq!(crtime.seconds, 1_700_000_000);
}

#[test]
fn ext3_extended_timestamps_present() {
    let (ext, mut fs) = common::open_ext("ext3.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    // ext3 has extended inodes, so the decode path uses extras
    assert_eq!(root.ctime().seconds, 1_700_000_000);
    assert_eq!(root.mtime().seconds, 1_700_000_000);
    assert_eq!(root.atime().seconds, 1_700_000_000);
}

// ── monotonic sanity across filesystem types ────────────────────────

#[test]
fn timestamps_monotonic_sanity_ext4() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    let root = ext.inode(&mut fs, 2).unwrap();
    let crtime = root.crtime().unwrap();
    // Creation time should be <= change time (ctime is updated on
    // metadata changes, crtime never changes)
    assert!(
        crtime.seconds <= root.ctime().seconds,
        "crtime ({}) should be <= ctime ({})",
        crtime.seconds,
        root.ctime().seconds
    );
}

#[test]
fn file_inode_has_crtime_ext4() {
    let (ext, mut fs) = common::open_ext("ext4.img");
    // Inode 12 is the first file-like inode in ext4 fixture
    let inode = ext.inode(&mut fs, 12).unwrap();
    let crtime = inode.crtime().expect("ext4 file inode should have crtime");
    assert!(crtime.seconds > 0, "crtime should be a valid timestamp");
}
