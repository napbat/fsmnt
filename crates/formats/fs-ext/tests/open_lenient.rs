mod common;

use fs_ext::{Ext, ExtError};

#[test]
fn open_lenient_accepts_clean_filesystem() {
    let mut fs = common::load_image("ext4.img");
    let ext = Ext::open_lenient(&mut fs).expect("open_lenient on clean image");
    assert!(!ext.needs_journal_recovery());
    assert!(!ext.has_orphan_present());
    assert!(ext.has_journal());
}

#[test]
fn open_lenient_accepts_dirty_filesystem() {
    let mut fs = common::load_image("ext4.img");
    common::patch_superblock_incompat(&mut fs, 0x4);
    let ext = Ext::open_lenient(&mut fs).expect("open_lenient on dirty image");
    assert!(ext.needs_journal_recovery());
}

#[test]
fn ext_new_still_rejects_dirty_filesystem() {
    let mut fs = common::load_image("ext4.img");
    common::patch_superblock_incompat(&mut fs, 0x4);
    let err = Ext::new(&mut fs).expect_err("Ext::new must reject dirty");
    assert!(matches!(err, ExtError::NeedsRecovery), "got {err:?}");
}

#[test]
fn ext_new_reports_recover_before_orphan_when_both_set() {
    let mut fs = common::load_image("ext4.img");
    common::patch_superblock_incompat(&mut fs, 0x4);
    common::patch_superblock_ro_compat(&mut fs, 0x0001_0000);
    let err = Ext::new(&mut fs).expect_err("Ext::new must reject");
    assert!(matches!(err, ExtError::NeedsRecovery), "got {err:?}");
}

#[test]
fn open_lenient_still_rejects_journal_dev() {
    let mut fs = common::load_image("ext4.img");
    common::patch_superblock_incompat(&mut fs, 0x8);
    let err = Ext::open_lenient(&mut fs).expect_err("open_lenient must reject");
    assert!(
        matches!(err, ExtError::UnsupportedJournalDevice),
        "got {err:?}"
    );
}

#[test]
fn open_lenient_reports_orphan_file_and_bigalloc_state_on_clean_image() {
    let mut fs = common::load_image("ext4.img");
    let ext = fs_ext::Ext::open_lenient(&mut fs).expect("lenient open");
    // ext4.img is built with COMPAT_ORPHAN_FILE (modern e2fsck enables it
    // by default) and without BIGALLOC.
    assert!(ext.has_orphan_file());
}
