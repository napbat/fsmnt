//! Integration tests for ext3/ext4 journal discovery and recovery behavior.

mod support;

use fs_common::iter::FsTryIterator;
use fs_common::traverse::FsDirectory;
use fs_ext::journal::StopReason;
use fs_ext::{Ext, ExtError, JournalReplay, OverlayReader};

#[test]
fn clean_image_reports_journal_via_public_accessors() {
    let (ext, _fs) = support::open_ext("ext4.img");
    assert!(ext.has_journal());
    assert!(!ext.needs_journal_recovery());
}

#[test]
fn dirty_image_with_no_journal_would_fail_later() {
    let mut fs = support::load_image("ext4.img");
    {
        let buf = fs.get_mut();
        let current = u32::from_le_bytes(buf[1024 + 0x5C..1024 + 0x60].try_into().unwrap());
        let new = current & !0x4;
        buf[1024 + 0x5C..1024 + 0x60].copy_from_slice(&new.to_le_bytes());
    }
    support::patch_superblock_incompat(&mut fs, 0x4);
    let ext = Ext::open_lenient(&mut fs).expect("lenient open");
    assert!(!ext.has_journal());
    assert!(ext.needs_journal_recovery());
    let _ = ExtError::JournalExpectedButAbsent;
}

#[test]
fn build_fails_when_journal_absent() {
    let mut fs = support::load_image("ext4.img");
    {
        let buf = fs.get_mut();
        let current = u32::from_le_bytes(buf[1024 + 0x5C..1024 + 0x60].try_into().unwrap());
        let new = current & !0x4;
        buf[1024 + 0x5C..1024 + 0x60].copy_from_slice(&new.to_le_bytes());
    }
    support::patch_superblock_incompat(&mut fs, 0x4);

    let ext = fs_ext::Ext::open_lenient(&mut fs).expect("lenient");
    let err = JournalReplay::build(&ext, &mut fs).unwrap_err();
    assert!(
        matches!(err, ExtError::JournalExpectedButAbsent),
        "got {err:?}"
    );
}

#[test]
fn canonical_flow_on_clean_image_round_trips_root_directory() {
    let mut fs = support::load_image("ext4.img");
    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    let replay = JournalReplay::build(&pre_replay, &mut fs).expect("build");

    assert!(replay.plan().committed.is_empty());
    assert!(replay.plan().stop.is_none());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    let post_replay = Ext::new(&mut overlay).expect("strict open through overlay");

    let mut root = post_replay.root_directory();
    let mut iter = root.entries(&mut overlay).expect("entries via overlay");
    let mut saw_any = false;
    while let Some(_entry) = iter.try_next(&mut overlay).expect("try_next via overlay") {
        saw_any = true;
    }
    assert!(saw_any, "root directory yielded no entries through overlay");
}

fn fixture_available(name: &str) -> bool {
    fsmnt_testkit::fixture_path(env!("CARGO_MANIFEST_DIR"), format!("testdata/{name}")).exists()
}

#[test]
fn dirty_empty_journal_recovers_to_clean_view() {
    if !fixture_available("ext4-dirty-empty.img") {
        eprintln!("skipping: ext4-dirty-empty.img not generated in this environment");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-empty.img");
    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    assert!(pre_replay.needs_journal_recovery());
    let replay = JournalReplay::build(&pre_replay, &mut fs).expect("build");
    assert!(replay.plan().committed.is_empty());
    assert!(replay.plan().stop.is_none());

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    Ext::new(&mut overlay).expect("strict open through overlay");
}

#[test]
fn dirty_orphan_fails_strict_reopen_with_orphan_error() {
    if !fixture_available("ext4-dirty-orphan.img") {
        eprintln!("skipping: ext4-dirty-orphan.img not generated in this environment");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-orphan.img");
    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    let replay = JournalReplay::build(&pre_replay, &mut fs).expect("build");
    let mut overlay = OverlayReader::new(&mut fs, &replay);
    let err = Ext::new(&mut overlay).expect_err("strict open must fail");
    assert!(
        matches!(err, ExtError::OrphanRecoveryRequired),
        "got {err:?}",
    );
}

#[test]
fn dirty_v3_image_recovers_and_reports_committed_transactions() {
    if !fixture_available("ext4-dirty-v3.img") {
        eprintln!("skipping: ext4-dirty-v3.img not generated in this environment");
        return;
    }
    let mut fs = support::load_image("ext4-dirty-v3.img");
    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    assert!(pre_replay.needs_journal_recovery());

    let replay = JournalReplay::build(&pre_replay, &mut fs).expect("build");
    assert!(
        !replay.plan().committed.is_empty(),
        "expected at least one committed tx",
    );
    if let Some(stop) = &replay.plan().stop {
        eprintln!(
            "journal walk stopped: {:?} at {:?}",
            stop.reason, stop.position,
        );
    }

    let mut overlay = OverlayReader::new(&mut fs, &replay);
    let post_replay = Ext::new(&mut overlay).expect("strict open through overlay");
    let mut root = post_replay.root_directory();
    let mut iter = root.entries(&mut overlay).expect("entries via overlay");
    while let Some(_entry) = iter.try_next(&mut overlay).expect("try_next via overlay") {}
}

#[test]
fn journal_uses_superblock_backup_when_journal_inode_mapping_is_corrupt() {
    let mut fs = support::load_image("ext4.img");
    corrupt_journal_inode_extent_header(&mut fs);

    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    let replay = JournalReplay::build(&pre_replay, &mut fs).expect("build");

    assert!(
        replay.plan().used_superblock_journal_backup,
        "expected fallback to s_jnl_blocks when journal inode mapping is corrupt",
    );
}

#[test]
fn superblock_backup_truncated_journal_stops_replay_without_setup_error() {
    let mut fs = support::load_image("ext4.img");
    corrupt_journal_inode_extent_header(&mut fs);

    let block_size = ext_block_size(&fs);
    let journal_block_zero = backup_journal_physical_block(&fs, 0);
    let sb_start =
        usize::try_from(journal_block_zero).expect("fixture journal block fits usize") * block_size;
    fs.get_mut()[sb_start + 0x1C..sb_start + 0x20].copy_from_slice(&1u32.to_be_bytes());

    let journal_block_one = backup_journal_physical_block(&fs, 1);
    fs.get_mut().truncate(
        usize::try_from(journal_block_one).expect("fixture journal block fits usize") * block_size
            + block_size / 2,
    );

    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    let replay = JournalReplay::build(&pre_replay, &mut fs)
        .expect("truncated fallback journal should produce replay plan");

    assert!(
        replay.plan().used_superblock_journal_backup,
        "expected fallback to s_jnl_blocks when journal inode mapping is corrupt",
    );
    let stop = replay.plan().stop.as_ref().expect("truncated stop");
    assert_eq!(stop.reason, StopReason::Truncated);
}

#[test]
fn journal_fails_when_inode_mapping_and_superblock_backup_are_both_corrupt() {
    let mut fs = support::load_image("ext4.img");
    corrupt_journal_inode_extent_header(&mut fs);
    zero_superblock_journal_backup(&mut fs);

    let pre_replay = Ext::open_lenient(&mut fs).expect("lenient");
    let err = JournalReplay::build(&pre_replay, &mut fs).expect_err("build should fail");
    assert!(
        matches!(
            err,
            ExtError::InvalidExtentHeader { .. }
                | ExtError::InvalidInode { .. }
                | ExtError::BlockOutOfRange { .. }
        ),
        "unexpected error when both journal paths are damaged: {err:?}",
    );
}

fn corrupt_journal_inode_extent_header(fs: &mut std::io::Cursor<Vec<u8>>) {
    let (block_size, inodes_per_group, inode_size, journal_inum) = {
        let sb = &fs.get_ref()[1024..1024 + 1024];
        (
            1024u32 << u32::from_le_bytes(sb[0x18..0x1C].try_into().unwrap()),
            u32::from_le_bytes(sb[0x28..0x2C].try_into().unwrap()),
            u16::from_le_bytes(sb[0x58..0x5A].try_into().unwrap()),
            u32::from_le_bytes(sb[0xE0..0xE4].try_into().unwrap()),
        )
    };
    assert!(journal_inum > 0, "fixture must contain an internal journal");

    let group = (journal_inum - 1) / inodes_per_group;
    let index = (journal_inum - 1) % inodes_per_group;
    let gdt_off = if block_size == 1024 {
        2048usize
    } else {
        usize::try_from(block_size).expect("fixture block size fits usize")
    };
    let desc_size = 64usize;
    let desc_off = gdt_off + usize::try_from(group).expect("fixture group fits usize") * desc_size;
    let inode_table_block = u32::from_le_bytes(
        fs.get_ref()[desc_off + 8..desc_off + 12]
            .try_into()
            .unwrap(),
    );
    let inode_off = usize::try_from(inode_table_block)
        .expect("fixture inode-table block fits usize")
        * usize::try_from(block_size).expect("fixture block size fits usize")
        + usize::try_from(index).expect("fixture inode index fits usize") * usize::from(inode_size);
    let i_block_off = inode_off + 40;
    fs.get_mut()[i_block_off..i_block_off + 2].copy_from_slice(&0u16.to_le_bytes());
}

fn zero_superblock_journal_backup(fs: &mut std::io::Cursor<Vec<u8>>) {
    let off = 1024 + 0x10C;
    fs.get_mut()[off..off + (17 * 4)].fill(0);
}

fn ext_block_size(fs: &std::io::Cursor<Vec<u8>>) -> usize {
    let sb = &fs.get_ref()[1024..1024 + 1024];
    1024usize << u32::from_le_bytes(sb[0x18..0x1C].try_into().unwrap())
}

fn backup_journal_physical_block(fs: &std::io::Cursor<Vec<u8>>, logical: u32) -> u64 {
    const EXTENT_MAGIC: u16 = 0xF30A;
    let off = 1024 + 0x10C;
    let i_block = &fs.get_ref()[off..off + 60];
    let magic = u16::from_le_bytes(i_block[0..2].try_into().unwrap());
    if magic == EXTENT_MAGIC {
        let entries = usize::from(u16::from_le_bytes(i_block[2..4].try_into().unwrap()));
        let depth = u16::from_le_bytes(i_block[6..8].try_into().unwrap());
        assert_eq!(depth, 0, "fixture journal backup should use inline extents");
        for idx in 0..entries {
            let extent_off = 12 + idx * 12;
            let ee_block =
                u32::from_le_bytes(i_block[extent_off..extent_off + 4].try_into().unwrap());
            let ee_len =
                u16::from_le_bytes(i_block[extent_off + 4..extent_off + 6].try_into().unwrap());
            let ee_start_hi =
                u16::from_le_bytes(i_block[extent_off + 6..extent_off + 8].try_into().unwrap());
            let ee_start_lo =
                u32::from_le_bytes(i_block[extent_off + 8..extent_off + 12].try_into().unwrap());
            let len = u32::from(ee_len & 0x7FFF);
            if logical >= ee_block && logical < ee_block + len {
                let start = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);
                return start + u64::from(logical - ee_block);
            }
        }
        panic!("logical journal block {logical} missing from backup extents");
    }

    assert!(logical < 12, "fixture direct backup block expected");
    let logical = usize::try_from(logical).expect("fixture logical block fits usize");
    u64::from(u32::from_le_bytes(
        i_block[logical * 4..logical * 4 + 4].try_into().unwrap(),
    ))
}
