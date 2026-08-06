//! Integration tests for ext4 fast-commit and classic-journal replay composition.

use std::io::Cursor;

use fs_ext::io::{Read, Seek, SeekFrom};
use fs_ext::{Ext, JournalReplay, OverlayReader};

const SUPERBLOCK_OFFSET: usize = 1024;
const JBD_MAGIC: u32 = 0xC03B_3998;
const JBD_BT_DESCRIPTOR: u32 = 1;
const JBD_BT_COMMIT: u32 = 2;
const JBD_TAG_FLAG_SAME_UUID: u16 = 0x2;
const JBD_TAG_FLAG_LAST: u16 = 0x8;
const JBD_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;
const JBD_SB_CHECKSUM_OFFSET: usize = 0xFC;
const FC_TAG_INODE: u16 = 0x0006;
const FC_TAG_TAIL: u16 = 0x0008;
const FC_TAG_HEAD: u16 = 0x0009;
const FC_TID: u32 = 100;
const FC_BLOCKS: u32 = 4;
const ROOT_INO: u32 = 2;
const CLASSIC_START: u32 = 1;
const CLASSIC_FIRST_SEQ: u32 = 100;

fn fixture_available(name: &str) -> bool {
    fsmnt_testkit::fixture_path(env!("CARGO_MANIFEST_DIR"), format!("testdata/{name}")).exists()
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    fsmnt_testkit::read_required_fixture(
        env!("CARGO_MANIFEST_DIR"),
        format!("testdata/{name}"),
        "regenerate fixtures with `sudo bash crates/formats/fs-ext/testdata/gen-fixtures.sh`",
    )
}

#[test]
fn vm_generated_fc_fixture_replays_to_consistent_state() -> Result<(), Box<dyn std::error::Error>> {
    if !fixture_available("ext4-dirty-fast-commit.img") {
        eprintln!("skipping: ext4-dirty-fast-commit.img not generated");
        return Ok(());
    }

    let bytes = fixture_bytes("ext4-dirty-fast-commit.img");
    let mut cursor = Cursor::new(bytes);
    let jr = JournalReplay::build(&Ext::open_lenient(&mut cursor)?, &mut cursor)?;
    let fc_plan = jr.fast_commit_plan();
    assert!(fc_plan.is_some(), "FC plan present");
    let fc_plan = fc_plan.expect("FC plan present");

    // Crash-truncated final transactions may stop; forward progress is enough.
    assert!(
        fc_plan.transactions_replayed > 0,
        "fixture replayed 0 transactions; crash induction may have failed"
    );

    Ok(())
}

#[test]
fn clean_state_with_fast_commit_replays_inode_overlay() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fixture_bytes("ext4.img");
    let layout = FixtureLayout::read(&bytes)?;

    let journal_block_count = layout.journal_block_count(&bytes)?;
    assert!(
        journal_block_count > FC_BLOCKS + 1,
        "fixture journal must leave room for a 4-block FC tail"
    );

    patch_journal_superblock_for_clean_fast_commit(&mut bytes, &layout, journal_block_count)?;

    let inode_offset = layout.inode_offset(&bytes, ROOT_INO)?;
    let inode_size = usize::from(layout.inode_size);
    let mut raw_inode = bytes[inode_offset..inode_offset + inode_size].to_vec();
    let old_mode = u16::from_le_bytes(raw_inode[0x00..0x02].try_into()?);
    let new_mode = old_mode ^ 0o001;
    raw_inode[0x00..0x02].copy_from_slice(&new_mode.to_le_bytes());

    let tx = FcTxBuilder::new(FC_TID)
        .head(0)
        .inode(ROOT_INO, &raw_inode)
        .build();
    let fc_blocks = fc_region(vec![tx], FC_BLOCKS, layout.block_size);
    write_fc_region_blocks(&mut bytes, &layout, journal_block_count, &fc_blocks)?;

    let mut cursor = Cursor::new(bytes);
    let jr = JournalReplay::build(&Ext::open_lenient(&mut cursor)?, &mut cursor)?;
    let plan = jr.fast_commit_plan().expect("FC plan should exist");
    assert_eq!(plan.transactions_replayed, 1);
    assert_eq!(plan.last_committed_tid, Some(FC_TID));
    assert!(plan.stop.is_none());
    assert_eq!(plan.inodes_modified, 1);

    // Per-tag count assertions for the single-INODE transaction.
    // The transaction contains HEAD + INODE + TAIL; only HEAD and
    // INODE end up in the `FastCommitTagCounts` (the TAIL contributes
    // to per-tx CRC validation, not the tag-count summary).
    // Kills `delete field head from struct FastCommitTagCounts` on
    // apply.rs:101 and the `+= *=` mutant on `tag_counts.inode` at
    // apply.rs:164.
    assert_eq!(
        plan.tag_counts.head, 1,
        "single-tx FC region must record head=1 in tag counts"
    );
    assert_eq!(
        plan.tag_counts.inode, 1,
        "single-INODE tx must record inode=1 in tag counts"
    );
    assert_eq!(
        plan.tag_counts.pad, 0,
        "single-INODE tx must not record any PAD tags"
    );
    assert_eq!(
        plan.tag_counts.add_range, 0,
        "single-INODE tx must not record any ADD_RANGE tags"
    );

    let ext = Ext::open_lenient(&mut cursor)?;
    let mut overlay = OverlayReader::new(&mut cursor, &jr);
    let overlaid_inode = ext.inode(&mut overlay, ROOT_INO)?;
    assert_eq!(overlaid_inode.mode(), new_mode);

    Ok(())
}

#[test]
fn dirty_classic_plus_dirty_fc_composes_full_state() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fixture_bytes("ext4.img");
    let layout = FixtureLayout::read(&bytes)?;

    let journal_block_count = layout.journal_block_count(&bytes)?;
    let classic_txs = 2;
    let classic_blocks = classic_txs * 3;
    let stop_block = CLASSIC_START + classic_blocks;
    let fc_first = (journal_block_count - 1) - FC_BLOCKS + 1;
    assert!(
        fc_first > stop_block + classic_txs,
        "fixture journal must have room for classic txs before the FC tail"
    );

    patch_journal_superblock_for_dirty_classic_and_fast_commit(
        &mut bytes,
        &layout,
        journal_block_count,
        CLASSIC_FIRST_SEQ,
        CLASSIC_START,
    )?;
    let classic_replay =
        inject_classic_transactions(&mut bytes, &layout, classic_txs, CLASSIC_FIRST_SEQ)?;
    let expected_fc_tid = classic_replay.last_sequence.wrapping_add(1);

    let inode_offset = layout.inode_offset(&bytes, ROOT_INO)?;
    let inode_size = usize::from(layout.inode_size);
    let raw_inode = bytes[inode_offset..inode_offset + inode_size].to_vec();
    let old_mode = u16::from_le_bytes(raw_inode[0x00..0x02].try_into()?);
    let mut mode = old_mode;
    let mut transactions = Vec::new();
    for bit in [0o001, 0o002, 0o004] {
        mode ^= bit;
        let mut tx_inode = raw_inode.clone();
        tx_inode[0x00..0x02].copy_from_slice(&mode.to_le_bytes());
        transactions.push(
            FcTxBuilder::new(expected_fc_tid)
                .head(0)
                .inode(ROOT_INO, &tx_inode)
                .build(),
        );
    }

    let fc_blocks = fc_region(transactions, FC_BLOCKS, layout.block_size);
    write_fc_region_blocks(&mut bytes, &layout, journal_block_count, &fc_blocks)?;

    let mut cursor = Cursor::new(bytes);
    let jr = JournalReplay::build(&Ext::open_lenient(&mut cursor)?, &mut cursor)?;
    assert_eq!(jr.plan().committed.len(), 2);
    assert_eq!(
        jr.plan().committed.last().map(|tx| tx.sequence),
        Some(classic_replay.last_sequence)
    );

    let fc_plan = jr.fast_commit_plan().expect("FC plan should exist");
    assert_eq!(fc_plan.transactions_replayed, 3);
    assert_eq!(fc_plan.last_committed_tid, Some(expected_fc_tid));
    assert!(fc_plan.stop.is_none());

    let ext = Ext::open_lenient(&mut cursor)?;
    let mut overlay = OverlayReader::new(&mut cursor, &jr);
    for expected in &classic_replay.writes {
        let mut block = vec![0u8; usize::try_from(layout.block_size)?];
        overlay.seek(SeekFrom::Start(
            expected.fs_block * u64::from(layout.block_size),
        ))?;
        overlay.read_exact(&mut block)?;
        assert!(
            block.iter().all(|&byte| byte == expected.fill_byte),
            "classic write to fs block {} should survive FC overlay composition",
            expected.fs_block
        );
    }
    let overlaid_inode = ext.inode(&mut overlay, ROOT_INO)?;
    assert_eq!(overlaid_inode.mode(), mode);

    // Strict reopen through the composed overlay forces the
    // end-of-FC `finalize` block to actually have run: without it,
    // the post-replay sb tallies are inconsistent and Ext::new's
    // strict validation would reject the image. This kills the
    // `delete !` mutant on fast_commit/mod.rs:95 (`if
    // !modified_inodes.is_empty() { finalize }` becomes `if
    // modified_inodes.is_empty()`, skipping finalize whenever an
    // inode IS modified — exactly this fixture's case).
    let mut overlay = OverlayReader::new(&mut cursor, &jr);
    Ext::new(&mut overlay).expect(
        "strict reopen must succeed through the composed overlay — \
         kills `!modified_inodes.is_empty()` finalize-block skip mutant",
    );

    Ok(())
}

#[test]
fn bad_tail_mid_fc_stops_after_two_valid_transactions() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = fixture_bytes("ext4.img");
    let layout = FixtureLayout::read(&bytes)?;

    let journal_block_count = layout.journal_block_count(&bytes)?;
    assert!(
        journal_block_count > FC_BLOCKS + 1,
        "fixture journal must leave room for a 4-block FC tail"
    );

    patch_journal_superblock_for_clean_fast_commit(&mut bytes, &layout, journal_block_count)?;

    let inode_offset = layout.inode_offset(&bytes, ROOT_INO)?;
    let inode_size = usize::from(layout.inode_size);
    let raw_inode = bytes[inode_offset..inode_offset + inode_size].to_vec();
    let old_mode = u16::from_le_bytes(raw_inode[0x00..0x02].try_into()?);
    let first_mode = old_mode ^ 0o001;
    let second_mode = first_mode ^ 0o002;
    let bad_mode = second_mode ^ 0o004;

    let mut first_inode = raw_inode.clone();
    first_inode[0x00..0x02].copy_from_slice(&first_mode.to_le_bytes());
    let mut second_inode = raw_inode.clone();
    second_inode[0x00..0x02].copy_from_slice(&second_mode.to_le_bytes());
    let mut bad_inode = raw_inode.clone();
    bad_inode[0x00..0x02].copy_from_slice(&bad_mode.to_le_bytes());

    let tx1 = FcTxBuilder::new(FC_TID)
        .head(0)
        .inode(ROOT_INO, &first_inode)
        .build();
    let tx2 = FcTxBuilder::new(FC_TID)
        .head(0)
        .inode(ROOT_INO, &second_inode)
        .build();
    let tx3 = FcTxBuilder::new(FC_TID)
        .head(0)
        .inode(ROOT_INO, &bad_inode)
        .build_with_bad_crc();
    let fc_blocks = fc_region(vec![tx1, tx2, tx3], FC_BLOCKS, layout.block_size);
    write_fc_region_blocks(&mut bytes, &layout, journal_block_count, &fc_blocks)?;

    let mut cursor = Cursor::new(bytes);
    let jr = JournalReplay::build(&Ext::open_lenient(&mut cursor)?, &mut cursor)?;
    let fc_plan = jr.fast_commit_plan().expect("FC plan should exist");
    assert_eq!(fc_plan.transactions_replayed, 2);
    assert!(matches!(
        fc_plan.stop.as_ref().map(|s| &s.reason),
        Some(fs_ext::journal::FastCommitStopReason::TailChecksumInvalid { .. }),
    ));
    assert_eq!(fc_plan.last_committed_tid, Some(FC_TID));

    let ext = Ext::open_lenient(&mut cursor)?;
    let mut overlay = OverlayReader::new(&mut cursor, &jr);
    let overlaid_inode = ext.inode(&mut overlay, ROOT_INO)?;
    assert_eq!(overlaid_inode.mode(), second_mode);
    assert_ne!(overlaid_inode.mode(), bad_mode);

    Ok(())
}

struct FixtureLayout {
    block_size: u32,
    inode_size: u16,
    inodes_per_group: u32,
    journal_inum: u32,
    group_desc_table_offset: usize,
    group_desc_size: usize,
}

struct ClassicReplayFixture {
    last_sequence: u32,
    writes: Vec<ClassicWriteExpectation>,
}

struct ClassicWriteExpectation {
    fs_block: u64,
    fill_byte: u8,
}

impl FixtureLayout {
    fn read(bytes: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let sb = &bytes[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + 1024];
        let block_size = 1024u32 << le_u32(sb, 0x18);
        let inode_size = le_u16(sb, 0x58);
        let inodes_per_group = le_u32(sb, 0x28);
        let journal_inum = le_u32(sb, 0xE0);
        let incompat = le_u32(sb, 0x60);
        let group_desc_size = if incompat & 0x80 != 0 {
            usize::from(le_u16(sb, 0xFE))
        } else {
            32
        };
        let block_size_usize = usize::try_from(block_size)?;
        let group_desc_table_offset = if block_size == 1024 {
            2 * block_size_usize
        } else {
            block_size_usize
        };

        assert_eq!(block_size, 4096, "fixture layout assumption changed");
        assert_eq!(inode_size, 256, "fixture inode size assumption changed");
        assert!(journal_inum != 0, "fixture must have an internal journal");
        assert!(
            group_desc_size >= 32,
            "fixture group descriptors must include inode table fields"
        );

        Ok(Self {
            block_size,
            inode_size,
            inodes_per_group,
            journal_inum,
            group_desc_table_offset,
            group_desc_size,
        })
    }

    fn inode_offset(&self, bytes: &[u8], inum: u32) -> Result<usize, Box<dyn std::error::Error>> {
        let group = (inum - 1) / self.inodes_per_group;
        let index = (inum - 1) % self.inodes_per_group;
        let gd = self.group_desc(bytes, group)?;
        let table_block_lo = le_u32(gd, 0x08);
        let table_block_hi = if self.group_desc_size >= 64 {
            u64::from(le_u32(gd, 0x28))
        } else {
            0
        };
        let table_block = (table_block_hi << 32) | u64::from(table_block_lo);
        let offset = table_block
            .checked_mul(u64::from(self.block_size))
            .and_then(|v| v.checked_add(u64::from(index) * u64::from(self.inode_size)))
            .ok_or("inode offset overflow")?;
        Ok(usize::try_from(offset)?)
    }

    fn journal_block_count(&self, bytes: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
        let inode = self.inode(bytes, self.journal_inum)?;
        let size = inode_size_bytes(inode);
        assert_eq!(
            size % u64::from(self.block_size),
            0,
            "fixture journal file size must be block-aligned"
        );
        Ok(u32::try_from(size / u64::from(self.block_size))?)
    }

    fn journal_block_offset(
        &self,
        bytes: &[u8],
        journal_block: u32,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let inode = self.inode(bytes, self.journal_inum)?;
        let physical_block = extent_physical_block(bytes, self.block_size, inode, journal_block)?;
        let offset = physical_block
            .checked_mul(u64::from(self.block_size))
            .ok_or("journal block offset overflow")?;
        Ok(usize::try_from(offset)?)
    }

    fn inode<'a>(
        &self,
        bytes: &'a [u8],
        inum: u32,
    ) -> Result<&'a [u8], Box<dyn std::error::Error>> {
        let offset = self.inode_offset(bytes, inum)?;
        let len = usize::from(self.inode_size);
        Ok(&bytes[offset..offset + len])
    }

    fn group_desc<'a>(
        &self,
        bytes: &'a [u8],
        group: u32,
    ) -> Result<&'a [u8], Box<dyn std::error::Error>> {
        let start = self
            .group_desc_table_offset
            .checked_add(usize::try_from(group)? * self.group_desc_size)
            .ok_or("group descriptor offset overflow")?;
        Ok(&bytes[start..start + self.group_desc_size])
    }
}

// `fs-ext` intentionally keeps journal inode details and logical-to-physical
// mapping private. This integration test patches the owned fixture bytes by
// reading only the ext4 on-disk fields needed to locate the internal journal.
fn patch_journal_superblock_for_clean_fast_commit(
    bytes: &mut [u8],
    layout: &FixtureLayout,
    journal_block_count: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let sb_off = layout.journal_block_offset(bytes, 0)?;
    let sb = &mut bytes[sb_off..sb_off + 1024];
    let patched_maxlen = journal_block_count - 1;

    sb[0x10..0x14].copy_from_slice(&patched_maxlen.to_be_bytes());
    sb[0x18..0x1C].copy_from_slice(&FC_TID.to_be_bytes());
    sb[0x1C..0x20].copy_from_slice(&0u32.to_be_bytes());
    sb[0x24..0x28].copy_from_slice(&0u32.to_be_bytes());
    // Clear checksum modes while enabling FAST_COMMIT, so no jbd2
    // superblock checksum is expected for the synthetic journal state.
    sb[0x28..0x2C].copy_from_slice(&JBD_FEATURE_INCOMPAT_FAST_COMMIT.to_be_bytes());
    sb[0x2C..0x30].copy_from_slice(&0u32.to_be_bytes());
    sb[0x50] = 0;
    sb[0x54..0x58].copy_from_slice(&FC_BLOCKS.to_be_bytes());
    sb[0x58..0x5C].copy_from_slice(&0u32.to_be_bytes());
    sb[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);

    Ok(())
}

fn patch_journal_superblock_for_dirty_classic_and_fast_commit(
    bytes: &mut [u8],
    layout: &FixtureLayout,
    journal_block_count: u32,
    first_classic_tid: u32,
    classic_start: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let sb_off = layout.journal_block_offset(bytes, 0)?;
    let sb = &mut bytes[sb_off..sb_off + 1024];
    let patched_maxlen = journal_block_count - 1;

    sb[0x10..0x14].copy_from_slice(&patched_maxlen.to_be_bytes());
    sb[0x14..0x18].copy_from_slice(&1u32.to_be_bytes());
    sb[0x18..0x1C].copy_from_slice(&first_classic_tid.to_be_bytes());
    sb[0x1C..0x20].copy_from_slice(&classic_start.to_be_bytes());
    sb[0x24..0x28].copy_from_slice(&0u32.to_be_bytes());
    sb[0x28..0x2C].copy_from_slice(&JBD_FEATURE_INCOMPAT_FAST_COMMIT.to_be_bytes());
    sb[0x2C..0x30].copy_from_slice(&0u32.to_be_bytes());
    sb[0x50] = 0;
    sb[0x54..0x58].copy_from_slice(&FC_BLOCKS.to_be_bytes());
    sb[0x58..0x5C].copy_from_slice(&0u32.to_be_bytes());
    sb[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);

    Ok(())
}

fn inject_classic_transactions(
    bytes: &mut [u8],
    layout: &FixtureLayout,
    count: u32,
    first_sequence: u32,
) -> Result<ClassicReplayFixture, Box<dyn std::error::Error>> {
    assert!(count > 0);
    let block_size = usize::try_from(layout.block_size)?;
    let stop_block = CLASSIC_START + count * 3;
    let mut writes = Vec::new();

    for tx_idx in 0..count {
        let sequence = first_sequence.wrapping_add(tx_idx);
        let tx_start = CLASSIC_START + tx_idx * 3;
        let target_journal_block = stop_block + 1 + tx_idx;
        let target_fs_block = journal_block_host_fs_block(bytes, layout, target_journal_block)?;
        let fill_byte = 0xA0u8 | u8::try_from(tx_idx & 0x0F)?;

        let mut descriptor = vec![0u8; block_size];
        descriptor[..12].copy_from_slice(&jbd_header(JBD_BT_DESCRIPTOR, sequence));
        descriptor[12..16].copy_from_slice(
            &u32::try_from(target_fs_block)
                .expect("fixture journal host block fits u32")
                .to_be_bytes(),
        );
        descriptor[16..18].copy_from_slice(&0u16.to_be_bytes());
        descriptor[18..20]
            .copy_from_slice(&(JBD_TAG_FLAG_SAME_UUID | JBD_TAG_FLAG_LAST).to_be_bytes());

        let data = vec![fill_byte; block_size];
        let mut commit = vec![0u8; block_size];
        commit[..12].copy_from_slice(&jbd_header(JBD_BT_COMMIT, sequence));

        write_journal_block(bytes, layout, tx_start, &descriptor)?;
        write_journal_block(bytes, layout, tx_start + 1, &data)?;
        write_journal_block(bytes, layout, tx_start + 2, &commit)?;
        writes.push(ClassicWriteExpectation {
            fs_block: target_fs_block,
            fill_byte,
        });
    }

    let zero = vec![0u8; block_size];
    write_journal_block(bytes, layout, stop_block, &zero)?;

    Ok(ClassicReplayFixture {
        last_sequence: first_sequence.wrapping_add(count - 1),
        writes,
    })
}

fn jbd_header(block_type: u32, sequence: u32) -> [u8; 12] {
    let mut hdr = [0u8; 12];
    hdr[0..4].copy_from_slice(&JBD_MAGIC.to_be_bytes());
    hdr[4..8].copy_from_slice(&block_type.to_be_bytes());
    hdr[8..12].copy_from_slice(&sequence.to_be_bytes());
    hdr
}

fn journal_block_host_fs_block(
    bytes: &[u8],
    layout: &FixtureLayout,
    journal_block: u32,
) -> Result<u64, Box<dyn std::error::Error>> {
    let offset = layout.journal_block_offset(bytes, journal_block)?;
    let block_size = usize::try_from(layout.block_size)?;
    assert_eq!(
        offset % block_size,
        0,
        "journal block host offset must be block aligned"
    );
    Ok(u64::try_from(offset / block_size)?)
}

fn write_journal_block(
    bytes: &mut [u8],
    layout: &FixtureLayout,
    journal_block: u32,
    block: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(block.len(), usize::try_from(layout.block_size)?);
    let off = layout.journal_block_offset(bytes, journal_block)?;
    bytes[off..off + block.len()].copy_from_slice(block);
    Ok(())
}

fn write_fc_region_blocks(
    bytes: &mut [u8],
    layout: &FixtureLayout,
    journal_block_count: u32,
    blocks: &[Vec<u8>],
) -> Result<(), Box<dyn std::error::Error>> {
    let maxlen = journal_block_count - 1;
    let fc_first = maxlen - FC_BLOCKS + 1;
    assert_eq!(
        blocks.len(),
        usize::try_from(FC_BLOCKS)?,
        "test must write the full FC region to avoid stale fixture bytes"
    );
    for (i, block) in blocks.iter().enumerate() {
        assert_eq!(block.len(), usize::try_from(layout.block_size)?);
        let off = layout.journal_block_offset(bytes, fc_first + u32::try_from(i)?)?;
        bytes[off..off + block.len()].copy_from_slice(block);
    }
    Ok(())
}

fn extent_physical_block(
    bytes: &[u8],
    block_size: u32,
    inode: &[u8],
    logical: u32,
) -> Result<u64, Box<dyn std::error::Error>> {
    let i_block = &inode[0x28..0x64];
    let depth = le_u16(i_block, 0x06);
    match depth {
        0 => extent_leaf_lookup(i_block, logical),
        1 => {
            let entries = le_u16(i_block, 0x02);
            let mut leaf = None;
            for idx in 0..usize::from(entries) {
                let off = 12 + idx * 12;
                let ei_block = le_u32(i_block, off);
                if ei_block <= logical {
                    let lo = le_u32(i_block, off + 4);
                    let hi = le_u16(i_block, off + 8);
                    leaf = Some((u64::from(hi) << 32) | u64::from(lo));
                }
            }
            let leaf = leaf.ok_or("logical journal block precedes first extent index")?;
            let leaf_off = usize::try_from(leaf * u64::from(block_size))?;
            let block_size = usize::try_from(block_size)?;
            extent_leaf_lookup(&bytes[leaf_off..leaf_off + block_size], logical)
        }
        _ => Err("fixture journal extent tree depth > 1 is unsupported by this test".into()),
    }
}

fn extent_leaf_lookup(leaf: &[u8], logical: u32) -> Result<u64, Box<dyn std::error::Error>> {
    assert_eq!(
        le_u16(leaf, 0x00),
        0xF30A,
        "fixture journal inode must use extents"
    );
    let entries = le_u16(leaf, 0x02);
    for idx in 0..usize::from(entries) {
        let off = 12 + idx * 12;
        let ee_block = le_u32(leaf, off);
        let ee_len = u32::from(le_u16(leaf, off + 4) & 0x7FFF);
        let ee_start_hi = le_u16(leaf, off + 6);
        let ee_start_lo = le_u32(leaf, off + 8);
        if logical >= ee_block && logical < ee_block + ee_len {
            let start = (u64::from(ee_start_hi) << 32) | u64::from(ee_start_lo);
            return Ok(start + u64::from(logical - ee_block));
        }
    }
    Err("journal logical block not mapped by fixture extents".into())
}

fn inode_size_bytes(inode: &[u8]) -> u64 {
    u64::from(le_u32(inode, 0x04)) | (u64::from(le_u32(inode, 0x6C)) << 32)
}

struct FcTxBuilder {
    tid: u32,
    bytes: Vec<u8>,
    running_crc: u32,
}

impl FcTxBuilder {
    fn new(tid: u32) -> Self {
        Self {
            tid,
            bytes: Vec::new(),
            running_crc: 0,
        }
    }

    fn head(mut self, features: u32) -> Self {
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&features.to_le_bytes());
        payload[4..8].copy_from_slice(&self.tid.to_le_bytes());
        self.push_crc_tlv(&fc_tlv(FC_TAG_HEAD, &payload));
        self
    }

    fn inode(mut self, inum: u32, raw_inode: &[u8]) -> Self {
        assert!(raw_inode.len() >= 128);
        let mut payload = Vec::with_capacity(4 + raw_inode.len());
        payload.extend_from_slice(&inum.to_le_bytes());
        payload.extend_from_slice(raw_inode);
        self.push_crc_tlv(&fc_tlv(FC_TAG_INODE, &payload));
        self
    }

    fn build(mut self) -> Vec<u8> {
        let fc_len = 8u16;
        let mut tail_crc_input = Vec::with_capacity(8);
        tail_crc_input.extend_from_slice(&FC_TAG_TAIL.to_le_bytes());
        tail_crc_input.extend_from_slice(&fc_len.to_le_bytes());
        // TAIL CRC covers the TL header plus fc_tid, but not the stored crc.
        tail_crc_input.extend_from_slice(&self.tid.to_le_bytes());
        self.running_crc = ext4_crc32c(self.running_crc, &tail_crc_input);

        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&self.tid.to_le_bytes());
        payload[4..8].copy_from_slice(&self.running_crc.to_le_bytes());
        self.bytes.extend_from_slice(&fc_tlv(FC_TAG_TAIL, &payload));
        self.bytes
    }

    fn build_with_bad_crc(self) -> Vec<u8> {
        let mut bytes = self.build();
        let stored_crc = bytes.len() - 4;
        bytes[stored_crc] ^= 0xFF;
        bytes
    }

    fn push_crc_tlv(&mut self, tlv: &[u8]) {
        self.running_crc = ext4_crc32c(self.running_crc, tlv);
        self.bytes.extend_from_slice(tlv);
    }
}

fn fc_tlv(tag: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(
        &u16::try_from(payload.len())
            .expect("FC TLV payload must fit u16")
            .to_le_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

fn fc_region(transactions: Vec<Vec<u8>>, num_blocks: u32, block_size: u32) -> Vec<Vec<u8>> {
    let block_size = usize::try_from(block_size).expect("fixture block size fits usize");
    let num_blocks = usize::try_from(num_blocks).expect("fixture block count fits usize");
    let mut blocks = vec![vec![0u8; block_size]; num_blocks];
    let mut block_idx = 0usize;
    let mut block_off = 0usize;
    for tx in transactions {
        assert!(tx.len() <= block_size);
        if block_off + tx.len() > block_size {
            block_idx += 1;
            block_off = 0;
        }
        assert!(block_idx < blocks.len());
        blocks[block_idx][block_off..block_off + tx.len()].copy_from_slice(&tx);
        block_off += tx.len();
    }
    blocks
}

fn ext4_crc32c(seed: u32, data: &[u8]) -> u32 {
    !crc32c::crc32c_append(!seed, data)
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed slice"))
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed slice"))
}
