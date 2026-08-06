use super::*;
use crate::journal::OverlaySource;
use crate::journal::fast_commit::test_support::{FcTxBuilder, fc_region};
use crate::journal::superblock::{JBD_MAGIC, JbdHeader};
use zerocopy::FromBytes;

const TEST_CLASSIC_SEQ: u32 = 100;
const TEST_CLASSIC_START: u32 = 1;

struct TestBorrowedReader<'a, 'e, T> {
    file: &'a mut crate::journal::source::JournalFile<'e>,
    fs: &'a mut T,
}

impl<T: Read + Seek> JournalBlockReader for TestBorrowedReader<'_, '_, T> {
    fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()> {
        self.file.read_block(self.fs, u64::from(journal_block), buf)
    }
}

#[test]
fn plan_default_is_empty() {
    let plan = ReplayPlan::default();
    assert!(plan.committed.is_empty());
    assert!(!plan.used_superblock_journal_backup);
    assert!(plan.stop.is_none());
    assert_eq!(plan.revocation_summary, RevocationSummary::default());
}

/// `<impl OverlaySource for BlockOverlay>::sb_host_block` and
/// `::sb_host_block_content` are trivial getters; without direct
/// assertions, the `-> 0` / `-> 1` / `-> Vec::leak(...)` body
/// mutants survive because every fixture happens to have
/// `sb_host_block = 0` and the higher-level tests never inspect
/// the slice contents through the trait.
#[test]
fn block_overlay_overlay_source_accessors_return_stored_fields() {
    let canary_bytes: alloc::vec::Vec<u8> = (10u8..18).collect();
    let overlay = BlockOverlay {
        block_size: 1024,
        blocks: BTreeMap::new(),
        // Pick 2 specifically (not 0, not 1) so `-> 0` and `-> 1`
        // body mutants both produce a wrong value.
        sb_host_block: 2,
        sb_host_block_content: canary_bytes.clone().into_boxed_slice(),
    };

    // Through the OverlaySource trait so the mutant bodies fire
    // exactly the trait impl, not the inherent forwarding above.
    let via_trait_block = OverlaySource::sb_host_block(&overlay);
    assert_eq!(
        via_trait_block, 2,
        "OverlaySource::sb_host_block must return the stored field — \
         kills `-> 0` and `-> 1` body mutants"
    );

    let via_trait_content = OverlaySource::sb_host_block_content(&overlay);
    assert_eq!(
        via_trait_content,
        canary_bytes.as_slice(),
        "OverlaySource::sb_host_block_content must return the stored buffer — \
         kills `-> Vec::leak(Vec::new())`, `-> Vec::leak(vec![0])`, \
         `-> Vec::leak(vec![1])` body mutants"
    );
}

/// `compute_sb_host_block` picks block 0 with a 1 KiB offset for
/// `block_size` > 1024 and block 1 with no offset for `block_size` ==
/// 1024. The `> -> >=` mutant on line 489 only diverges at
/// `block_size` == 1024 (mutant returns `(0, 1024)` instead of
/// `(1, 0)`); without a 1 KiB-block test, the mutant survives.
#[test]
fn compute_sb_host_block_at_one_kib_returns_block_one_offset_zero() {
    // block_size > 1024 (the common case the existing tests
    // already cover): block 0, offset 1024.
    assert_eq!(compute_sb_host_block(4096), (0, 1024));
    assert_eq!(compute_sb_host_block(2048), (0, 1024));

    // block_size == 1024 (the > vs >= boundary): block 1, offset 0.
    assert_eq!(
        compute_sb_host_block(1024),
        (1, 0),
        "1 KiB block_size must yield (sb_host_block=1, sb_offset_in_host=0) — \
         kills `> -> >=` (mutant would return (0, 1024))"
    );
}

#[test]
fn fast_commit_plan_returns_none_when_not_constructed() {
    let overlay = BlockOverlay {
        block_size: 4096,
        blocks: BTreeMap::new(),
        sb_host_block: 0,
        sb_host_block_content: alloc::vec![0u8; 1024].into_boxed_slice(),
    };
    let jr = JournalReplay::for_test(overlay);
    assert!(jr.fast_commit_plan().is_none());
}

#[test]
fn journal_replay_build_runs_fc_phase_when_feature_set() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let mut bytes = std::fs::read(path).expect("read ext4 fixture");
    let source = patch_journal_sb_for_fast_commit(&mut bytes, 4);
    write_fc_region_blocks(
        &mut bytes,
        &source,
        &alloc::vec![alloc::vec![0u8; source.block_size as usize]; 4],
    );
    write_minimal_classic_tx(&mut bytes, &source);

    let expected_tid = {
        let mut cursor = std::io::Cursor::new(bytes.clone());
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open patched ext4 fixture");
        let last_classic_seq = classic_last_sequence(&ext, &mut cursor, &source);
        assert_eq!(last_classic_seq, Some(TEST_CLASSIC_SEQ));
        source.expected_fc_tid(last_classic_seq)
    };
    assert_ne!(expected_tid, source.sequence);

    let inum = 2;
    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let ext = crate::Ext::open_lenient(&mut cursor).expect("open patched ext4 fixture");
    let mut raw_inode = raw_inode_bytes(&ext, &mut cursor, inum);
    let new_mode =
        u16::from_le_bytes(raw_inode[0x00..0x02].try_into().expect("fixed slice")) ^ 0o001;
    raw_inode[0x00..0x02].copy_from_slice(&new_mode.to_le_bytes());

    let tx = FcTxBuilder::new(expected_tid)
        .head(0)
        .inode(inum, &raw_inode)
        .build();
    let blocks = fc_region(alloc::vec![tx], 4, source.block_size);
    write_fc_region_blocks(&mut bytes, &source, &blocks);

    let mut cursor = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
    let jr = JournalReplay::build(&ext, &mut cursor).expect("journal replay");

    assert_eq!(
        jr.fast_commit_plan()
            .expect("FC plan should exist")
            .transactions_replayed,
        1
    );
    assert_eq!(
        jr.fast_commit_plan()
            .expect("FC plan should exist")
            .inodes_modified,
        1
    );

    let mut overlay_reader = crate::OverlayReader::new(&mut cursor, &jr);
    let overlaid_inode = ext
        .inode(&mut overlay_reader, inum)
        .expect("read FC-overlaid inode");
    assert_eq!(overlaid_inode.mode(), new_mode);
}

fn classic_last_sequence<T: Read + Seek>(
    ext: &crate::Ext,
    fs: &mut T,
    source: &JournalSource,
) -> Option<u32> {
    let mut journal_file = crate::journal::source::open_journal_file(
        ext,
        fs,
        source,
        &crate::journal::source::JournalLocator::Inode,
    )
    .expect("open journal file");

    let mut reader = TestBorrowedReader {
        file: &mut journal_file,
        fs,
    };
    let mut plan = ReplayPlan::default();
    let _st = walk(source, &mut reader, &mut plan).expect("classic journal walk");
    plan.committed.last().map(|tx| tx.sequence)
}

fn raw_inode_bytes<T: Read + Seek>(ext: &crate::Ext, fs: &mut T, inum: u32) -> Vec<u8> {
    let group = (inum - 1) / ext.inodes_per_group;
    let index = (inum - 1) % ext.inodes_per_group;
    let table_block = ext.group_descs[group as usize].inode_table;
    let offset =
        table_block * u64::from(ext.block_size()) + u64::from(index) * u64::from(ext.inode_size());
    fs.seek(SeekFrom::Start(offset)).expect("seek raw inode");
    let mut bytes = alloc::vec![0u8; usize::from(ext.inode_size())];
    fs.read_exact(&mut bytes).expect("read raw inode");
    bytes
}

fn patch_journal_sb_for_fast_commit(bytes: &mut Vec<u8>, num_fc_blocks: u32) -> JournalSource {
    let (sb_off, checksum_mode_uses_sb_checksum, patched_maxlen) = {
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
        let source = crate::journal::source::open_journal_source(&ext, &mut cursor)
            .expect("open journal source")
            .expect("journal source");
        let journal_inode = ext
            .inode(&mut cursor, ext.journal_inum())
            .expect("read journal inode");
        let journal_blocks = u32::try_from(journal_inode.size() / u64::from(ext.block_size()))
            .expect("journal block count fits u32");
        let sb_off = journal_block_host_offset(&ext, &mut cursor, 0);
        let uses_checksum = matches!(
            source.source.checksum_mode,
            JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c
        );
        (
            sb_off,
            uses_checksum,
            source.source.maxlen.min(journal_blocks - 1),
        )
    };

    let sb_range = sb_off..sb_off + 1024;
    let sb = &mut bytes[sb_range];
    sb[0x10..0x14].copy_from_slice(&patched_maxlen.to_be_bytes());
    sb[0x18..0x1C].copy_from_slice(&TEST_CLASSIC_SEQ.to_be_bytes());
    sb[0x1C..0x20].copy_from_slice(&TEST_CLASSIC_START.to_be_bytes());
    sb[0x24..0x28].copy_from_slice(&0u32.to_be_bytes());
    sb[0x28..0x2C].copy_from_slice(&JournalIncompatFeatures::FAST_COMMIT.bits().to_be_bytes());
    sb[0x50] = 0;
    sb[0x54..0x58].copy_from_slice(&num_fc_blocks.to_be_bytes());
    if checksum_mode_uses_sb_checksum {
        let checksum_off = crate::journal::superblock::JBD_SB_CHECKSUM_OFFSET;
        sb[checksum_off..checksum_off + 4].fill(0);
        let checksum = crate::checksum::ext4_crc32c(!0, sb);
        sb[checksum_off..checksum_off + 4].copy_from_slice(&checksum.to_be_bytes());
    }

    let mut cursor = std::io::Cursor::new(bytes.as_slice());
    let ext = crate::Ext::open_lenient(&mut cursor).expect("open patched ext4 fixture");
    crate::journal::source::open_journal_source(&ext, &mut cursor)
        .expect("open patched journal source")
        .expect("patched journal source")
        .source
}

fn write_minimal_classic_tx(bytes: &mut Vec<u8>, source: &JournalSource) {
    let block_size = usize::try_from(source.block_size).expect("block size fits usize");
    let fs_target = {
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
        journal_block_host_fs_block(&ext, &mut cursor, 10)
    };

    let mut descriptor = alloc::vec![0u8; block_size];
    descriptor[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, TEST_CLASSIC_SEQ));
    descriptor[12..16].copy_from_slice(
        &u32::try_from(fs_target)
            .expect("fixture journal host block fits u32")
            .to_be_bytes(),
    );
    descriptor[16..18].copy_from_slice(&0u16.to_be_bytes());
    descriptor[18..20].copy_from_slice(
        &(u16::try_from(
            crate::journal::tags::TAG_FLAG_LAST | crate::journal::tags::TAG_FLAG_SAME_UUID,
        )
        .expect("the test fixture value fits in u16"))
        .to_be_bytes(),
    );

    let data = alloc::vec![0xA5u8; block_size];
    let mut commit = alloc::vec![0u8; block_size];
    commit[..12].copy_from_slice(&hdr(BT_COMMIT, TEST_CLASSIC_SEQ));
    let stop = alloc::vec![0u8; block_size];

    write_journal_block(bytes, source, TEST_CLASSIC_START, &descriptor);
    write_journal_block(bytes, source, TEST_CLASSIC_START + 1, &data);
    write_journal_block(bytes, source, TEST_CLASSIC_START + 2, &commit);
    write_journal_block(bytes, source, TEST_CLASSIC_START + 3, &stop);
}

fn write_journal_block(bytes: &mut Vec<u8>, source: &JournalSource, block: u32, data: &[u8]) {
    let host_off = {
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
        journal_block_host_offset(&ext, &mut cursor, block)
    };
    let end = host_off + data.len();
    bytes[host_off..end].copy_from_slice(data);
    assert_eq!(data.len(), source.block_size as usize);
}

fn write_fc_region_blocks(bytes: &mut Vec<u8>, source: &JournalSource, blocks: &[Vec<u8>]) {
    let fc_first = source
        .maxlen
        .checked_sub(source.effective_num_fc_blocks())
        .expect("FC blocks fit in journal")
        + 1;
    for (i, block) in blocks.iter().enumerate() {
        let host_off = {
            let mut cursor = std::io::Cursor::new(bytes.as_slice());
            let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
            journal_block_host_offset(
                &ext,
                &mut cursor,
                fc_first + u32::try_from(i).expect("the test fixture value fits in u32"),
            )
        };
        let end = host_off + block.len();
        bytes[host_off..end].copy_from_slice(block);
    }
}

fn journal_block_host_offset<T: Read + Seek>(
    ext: &crate::Ext,
    fs: &mut T,
    journal_block: u32,
) -> usize {
    let inode = ext
        .inode(fs, ext.journal_inum())
        .expect("read journal inode");
    let file = inode.open_file().expect("open journal file");
    let physical = file
        .logical_to_physical_block(fs, journal_block)
        .expect("resolve journal block");
    usize::try_from(physical * u64::from(ext.block_size())).expect("host offset fits usize")
}

fn journal_block_host_fs_block<T: Read + Seek>(
    ext: &crate::Ext,
    fs: &mut T,
    journal_block: u32,
) -> u64 {
    let inode = ext
        .inode(fs, ext.journal_inum())
        .expect("read journal inode");
    let file = inode.open_file().expect("open journal file");
    file.logical_to_physical_block(fs, journal_block)
        .expect("resolve journal block")
}

#[test]
fn stop_reason_is_non_exhaustive_compatible() {
    let reason = StopReason::BadMagic;
    #[allow(
        unreachable_patterns,
        reason = "non_exhaustive catch-all is required by contract"
    )]
    let _ = match reason {
        StopReason::BadMagic => 0,
        StopReason::SequenceMismatch { .. } => 1,
        StopReason::DescriptorTailChecksumInvalid => 2,
        StopReason::CommitChecksumInvalid => 3,
        StopReason::RevocationTailChecksumInvalid => 4,
        StopReason::DataBlockChecksumInvalid { .. } => 5,
        StopReason::Truncated => 6,
        _ => 7,
    };
}

fn hdr(blocktype: u32, sequence: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&JBD_MAGIC.to_be_bytes());
    b[4..8].copy_from_slice(&blocktype.to_be_bytes());
    b[8..12].copy_from_slice(&sequence.to_be_bytes());
    b
}

#[test]
fn header_dispatch_detects_descriptor() {
    let block_size = 4096usize;
    let mut desc = alloc::vec![0u8; block_size];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    let parsed = JbdHeader::ref_from_bytes(&desc[..12]).expect("parse");
    assert_eq!(parsed.h_blocktype.get(), BT_DESCRIPTOR);
}

#[test]
fn header_dispatch_detects_commit_and_revocation() {
    assert_eq!(u32::from_be_bytes([0, 0, 0, 2]), BT_COMMIT);
    assert_eq!(u32::from_be_bytes([0, 0, 0, 5]), BT_REVOCATION);
}

use crate::journal::features::{
    JournalChecksumMode, JournalIncompatFeatures, JournalSuperblockVersion,
};
use crate::journal::superblock::JournalSource;

struct InMemJournal {
    blocks: Vec<Vec<u8>>,
    block_size: u32,
}

impl JournalBlockReader for InMemJournal {
    fn read_block(&mut self, b: u32, buf: &mut [u8]) -> Result<()> {
        let idx = b as usize;
        if idx >= self.blocks.len() {
            return Err(crate::error::ExtError::UnexpectedEof {
                context: "in-mem journal",
                offset: u64::from(b) * u64::from(self.block_size),
            });
        }
        buf.copy_from_slice(&self.blocks[idx]);
        Ok(())
    }
}

fn dummy_source(block_size: u32, mode: JournalChecksumMode) -> JournalSource {
    JournalSource {
        block_size,
        maxlen: 32,
        first: 1,
        sequence: 1,
        start: 1,
        version: JournalSuperblockVersion::V2,
        features: JournalIncompatFeatures::empty(),
        checksum_mode: mode,
        uuid: [0u8; 16],
        num_fc_blocks: 0,
        fc_head: 0,
    }
}

#[test]
fn process_descriptor_accumulates_writes() {
    let bs = 4096usize;
    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&42u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc[24..28].copy_from_slice(&0u32.to_be_bytes());
    let mut data = alloc::vec![0u8; bs];
    data[0..8].copy_from_slice(b"HELLOJRN");
    let mut mem = InMemJournal {
        blocks: alloc::vec![alloc::vec![0u8; bs], desc, data, alloc::vec![0u8; bs]],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };
    // Use None mode so checksum verification is skipped; this test covers
    // write accumulation only.
    let mut st = WalkState::new(&dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::None,
    ));
    mem.read_block(1, &mut st.scratch).expect("read descriptor");
    process_descriptor(&mut mem, &mut st).expect("process");
    assert_eq!(st.pending.writes.len(), 1);
    assert_eq!(st.pending.writes[0].fs_block, 42);
    assert_eq!(&st.pending.writes[0].content[0..8], b"HELLOJRN");
    assert_eq!(st.cur, 3);
}

#[test]
fn revocation_parses_32bit_entries() {
    let bs = 4096usize;
    let mut blk = alloc::vec![0u8; bs];
    blk[..12].copy_from_slice(&hdr(BT_REVOCATION, 1));
    let entries: [u32; 3] = [100, 200, 300];
    blk[12..16].copy_from_slice(&(16u32 + 12).to_be_bytes());
    for (i, e) in entries.iter().enumerate() {
        let off = 16 + i * 4;
        blk[off..off + 4].copy_from_slice(&e.to_be_bytes());
    }
    let mut st = WalkState::new(&dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::None,
    ));
    st.scratch.copy_from_slice(&blk);
    let r = process_revocation(&mut st);
    assert!(r.is_none());
    assert_eq!(st.pending.revocations, alloc::vec![100u64, 200, 300]);
}

fn compute_commit_block_bytes(bs: usize, seed: u32, sequence: u32) -> Vec<u8> {
    let mut blk = alloc::vec![0u8; bs];
    blk[..12].copy_from_slice(&hdr(BT_COMMIT, sequence));
    blk[0xC] = 4;
    blk[0xD] = 4;
    let csum =
        crate::journal::checksum::block_tail_checksum_split(seed, &blk[..0x10], &blk[0x14..]);
    blk[0x10..0x14].copy_from_slice(&csum.to_be_bytes());
    blk
}

#[test]
fn commit_closes_transaction_v3() {
    let bs = 4096usize;
    let mut st = WalkState::new(&dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::V3Crc32c,
    ));
    st.pending.writes.push(PendingWrite {
        fs_block: 7,
        content: alloc::vec![0u8; bs].into_boxed_slice(),
        escape: false,
    });
    st.pending.descriptor_count = 1;

    let blk = compute_commit_block_bytes(bs, st.seed, st.expected_seq);
    st.scratch.copy_from_slice(&blk);
    let stop = process_commit(&mut st);
    assert!(stop.is_none());
    assert_eq!(st.plan_committed.len(), 1);
    assert_eq!(st.plan_committed[0].sequence, 1);
    assert_eq!(st.committed_meta.len(), 1);
    assert_eq!(st.latest.len(), 1);
    assert_eq!(st.expected_seq, 2);
}

#[test]
fn walk_processes_one_tx_and_stops_at_bad_magic() {
    let bs = 4096usize;
    let mode = JournalChecksumMode::None;
    let source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        mode,
    );

    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&42u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc[24..28].copy_from_slice(&0u32.to_be_bytes());

    let data = alloc::vec![0u8; bs];
    let commit = {
        let mut b = alloc::vec![0u8; bs];
        b[..12].copy_from_slice(&hdr(BT_COMMIT, 1));
        b
    };
    let junk = alloc::vec![0u8; bs];

    let mut mem = InMemJournal {
        blocks: alloc::vec![alloc::vec![0u8; bs], desc, data, commit, junk],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };
    let mut plan = ReplayPlan::default();
    walk(&source, &mut mem, &mut plan).expect("walk");
    assert_eq!(plan.committed.len(), 1);
    assert!(matches!(
        plan.stop.as_ref().map(|s| s.reason),
        Some(StopReason::BadMagic),
    ));
}

#[test]
fn classic_walk_reads_last_block_at_s_maxlen_index() {
    // jbd2 1-indexed convention: for s_maxlen=N, valid data block
    // indices are 1..=N inclusive. The off-by-one fix targets reading
    // the block at index s_maxlen itself.
    let bs = 4096usize;
    let mode = JournalChecksumMode::None;
    let mut source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        mode,
    );
    source.maxlen = 5;
    source.first = 1;
    source.start = 1;

    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&77u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc[24..28].copy_from_slice(&0u32.to_be_bytes());

    let data = alloc::vec![0u8; bs];
    let commit = {
        let mut b = alloc::vec![0u8; bs];
        b[..12].copy_from_slice(&hdr(BT_COMMIT, 1));
        b
    };
    let revocation = {
        let mut b = alloc::vec![0u8; bs];
        b[..12].copy_from_slice(&hdr(BT_REVOCATION, 2));
        b[12..16].copy_from_slice(&16u32.to_be_bytes());
        b
    };
    let mut mem = InMemJournal {
        blocks: alloc::vec![
            alloc::vec![0u8; bs],
            desc,
            data,
            commit,
            revocation,
            alloc::vec![0u8; bs],
        ],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };

    let mut plan = ReplayPlan::default();
    walk(&source, &mut mem, &mut plan).expect("walk");
    assert_eq!(
        plan.committed.len(),
        1,
        "the descriptor at block 1 must commit"
    );
    let stop = plan.stop.as_ref().expect("stop fires on block 5");
    assert!(matches!(stop.reason, StopReason::BadMagic));
    assert_eq!(
        stop.position.journal_block, 5,
        "stop must register at block index 5 = s_maxlen"
    );
}

#[test]
fn classic_walk_wraps_from_past_maxlen_back_to_first() {
    // Start at s_maxlen itself. After reading that slot, descriptor data
    // should wrap to s_first, then the walk should continue normally.
    let bs = 4096usize;
    let mode = JournalChecksumMode::None;
    let mut source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        mode,
    );
    source.maxlen = 4;
    source.first = 1;
    source.start = 4;

    let mut desc_at_4 = alloc::vec![0u8; bs];
    desc_at_4[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc_at_4[12..16].copy_from_slice(&55u32.to_be_bytes());
    desc_at_4[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc_at_4[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc_at_4[24..28].copy_from_slice(&0u32.to_be_bytes());

    let data_at_1 = {
        let mut d = alloc::vec![0u8; bs];
        d[0..4].copy_from_slice(b"WRAP");
        d
    };
    let commit_at_2 = {
        let mut b = alloc::vec![0u8; bs];
        b[..12].copy_from_slice(&hdr(BT_COMMIT, 1));
        b
    };

    let mut mem = InMemJournal {
        blocks: alloc::vec![
            alloc::vec![0u8; bs],
            data_at_1,
            commit_at_2,
            alloc::vec![0u8; bs],
            desc_at_4,
        ],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };

    let mut plan = ReplayPlan::default();
    walk(&source, &mut mem, &mut plan).expect("walk");
    assert_eq!(plan.committed.len(), 1);
}

#[test]
fn apply_restores_escape_and_suppresses_revoked() {
    let bs = 4096usize;
    let mode = JournalChecksumMode::None;
    let source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        mode,
    );
    let mut st = WalkState::new(&source);

    st.plan_committed.push(CommittedTx {
        sequence: 1,
        commit_time: None,
        data_blocks_applied: 0,
        data_blocks_revoked: 0,
        data_blocks_escaped: 0,
        revocation_entries: 0,
        descriptor_blocks: 1,
    });
    st.committed_meta.push((10, 1, 0, true));
    st.committed_meta.push((20, 1, 0, false));
    let mut escaped_content = alloc::vec![0u8; bs];
    escaped_content[0..4].copy_from_slice(&0u32.to_be_bytes());
    st.latest
        .insert(10, (1, 0, escaped_content.into_boxed_slice(), true));
    st.latest
        .insert(20, (1, 0, alloc::vec![0u8; bs].into_boxed_slice(), false));
    st.revocations.insert(20, 2);

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(&path).expect("ext4.img fixture");
    let mut cursor = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut cursor).expect("lenient open");

    let mut plan = ReplayPlan {
        committed: core::mem::take(&mut st.plan_committed),
        ..ReplayPlan::default()
    };
    let overlay = apply_pass(&ext, &mut cursor, &mut st, &mut plan).expect("apply");

    assert!(overlay.blocks.contains_key(&10));
    assert!(!overlay.blocks.contains_key(&20));
    let restored = overlay.blocks.get(&10).expect("block 10");
    assert_eq!(&restored[0..4], &0xC03B_3998u32.to_be_bytes());
    assert_eq!(plan.committed[0].data_blocks_applied, 1);
    assert_eq!(plan.committed[0].data_blocks_revoked, 1);
    assert_eq!(plan.committed[0].data_blocks_escaped, 1);
}

#[test]
fn apply_drops_out_of_range_blocks() {
    let bs = 4096usize;
    let source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::None,
    );
    let mut st = WalkState::new(&source);

    st.plan_committed.push(CommittedTx {
        sequence: 1,
        commit_time: None,
        data_blocks_applied: 0,
        data_blocks_revoked: 0,
        data_blocks_escaped: 0,
        revocation_entries: 0,
        descriptor_blocks: 1,
    });
    // One in-range write and one impossibly-large write. The ext4.img
    // fixture has blocks_count = 4096, so 10 is valid and u64::MAX - 1
    // is not.
    st.committed_meta.push((10, 1, 0, false));
    st.committed_meta.push((u64::MAX - 1, 1, 0, false));
    st.latest
        .insert(10, (1, 0, alloc::vec![0u8; bs].into_boxed_slice(), false));
    st.latest.insert(
        u64::MAX - 1,
        (1, 0, alloc::vec![0u8; bs].into_boxed_slice(), false),
    );

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
    let bytes = std::fs::read(&path).expect("ext4.img fixture");
    let mut cursor = std::io::Cursor::new(bytes);
    let ext = crate::Ext::open_lenient(&mut cursor).expect("lenient open");

    let mut plan = ReplayPlan {
        committed: core::mem::take(&mut st.plan_committed),
        ..ReplayPlan::default()
    };
    let overlay = apply_pass(&ext, &mut cursor, &mut st, &mut plan).expect("apply");

    assert!(overlay.blocks.contains_key(&10));
    assert!(!overlay.blocks.contains_key(&(u64::MAX - 1)));
    // Only the in-range write counts as applied.
    assert_eq!(plan.committed[0].data_blocks_applied, 1);
    assert_eq!(plan.committed[0].data_blocks_revoked, 0);
}

#[test]
fn descriptor_with_truncated_body_stops_instead_of_erroring() {
    // A descriptor whose body is too short for even one tag is
    // structurally bogus. The iterator must yield an error on the first
    // call; process_descriptor maps that to DescriptorBodyInvalid instead
    // of propagating as Err. A 16-byte "block" leaves only 4 bytes of
    // body (less than one legacy tag's 8 bytes).
    let bs = 16usize;
    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    let mut mem = InMemJournal {
        blocks: alloc::vec![alloc::vec![0u8; bs], desc],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };
    let mut st = WalkState::new(&dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::None,
    ));
    mem.read_block(1, &mut st.scratch).expect("read descriptor");
    let reason = process_descriptor(&mut mem, &mut st).expect("stop, not error");
    assert_eq!(reason, Some(StopReason::DescriptorBodyInvalid));
}

#[test]
fn walk_propagates_real_io_errors() {
    struct IoErrorReader;
    impl JournalBlockReader for IoErrorReader {
        fn read_block(&mut self, _b: u32, _buf: &mut [u8]) -> Result<()> {
            Err(crate::io::Error::new(crate::io::ErrorKind::PermissionDenied, "injected").into())
        }
    }

    let source = dummy_source(4096, JournalChecksumMode::None);
    let mut reader = IoErrorReader;
    let mut plan = ReplayPlan::default();
    let err = walk(&source, &mut reader, &mut plan).expect_err("io error must propagate");
    assert!(matches!(err, ExtError::Io(_)), "got {err:?}");
    assert!(
        plan.stop.is_none(),
        "no Truncated stop for a real I/O error"
    );
}

#[test]
fn descriptor_rejects_bad_tail_checksum_v3() {
    let bs = 4096usize;
    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&42u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc[24..28].copy_from_slice(&0u32.to_be_bytes());
    // Write a nonsense tail checksum; the real checksum over the block
    // with the tail zeroed would not match this value.
    let tail_off = bs - 4;
    desc[tail_off..tail_off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

    let mut mem = InMemJournal {
        blocks: alloc::vec![
            alloc::vec![0u8; bs],
            desc,
            alloc::vec![0u8; bs],
            alloc::vec![0u8; bs]
        ],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };
    let mut st = WalkState::new(&dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        JournalChecksumMode::V3Crc32c,
    ));
    mem.read_block(1, &mut st.scratch).expect("read descriptor");
    let reason = process_descriptor(&mut mem, &mut st).expect("process");
    assert!(matches!(
        reason,
        Some(StopReason::DescriptorTailChecksumInvalid)
    ));
}

#[test]
fn descriptor_wraps_data_block_reads_at_ring_boundary() {
    // Place the descriptor at the last block in the ring. Its one data
    // block should be read from `source.first`, immediately after
    // `maxlen`.
    let bs = 4096usize;
    let mode = JournalChecksumMode::None;
    let first = 1u32;
    let maxlen = 4u32; // block 0 is jbd2 superblock, ring = 1..=4
    let mut source = dummy_source(
        u32::try_from(bs).expect("the test fixture value fits in u32"),
        mode,
    );
    source.first = first;
    source.maxlen = maxlen;
    source.start = maxlen; // last ring slot: descriptor lands here

    let mut desc = alloc::vec![0u8; bs];
    desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
    desc[12..16].copy_from_slice(&77u32.to_be_bytes());
    desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
    desc[20..24].copy_from_slice(&0u32.to_be_bytes());
    desc[24..28].copy_from_slice(&0u32.to_be_bytes());

    // Populate: block 0 = sb, block 1 = the wrapped data block, blocks 2
    // & 3 unused, and block 4 holds the descriptor.
    let mut data = alloc::vec![0u8; bs];
    data[0..4].copy_from_slice(b"WRAP");
    let mut mem = InMemJournal {
        blocks: alloc::vec![
            alloc::vec![0u8; bs],
            data,
            alloc::vec![0u8; bs],
            alloc::vec![0u8; bs],
            desc,
        ],
        block_size: u32::try_from(bs).expect("the test fixture value fits in u32"),
    };

    let mut st = WalkState::new(&source);
    assert_eq!(st.cur, maxlen);
    mem.read_block(maxlen, &mut st.scratch)
        .expect("read descriptor");
    let reason = process_descriptor(&mut mem, &mut st).expect("process");
    assert!(reason.is_none());
    assert_eq!(st.pending.writes.len(), 1);
    assert_eq!(st.pending.writes[0].fs_block, 77);
    assert_eq!(&st.pending.writes[0].content[0..4], b"WRAP");
    // After wrapping, cur should point to the slot after the data block.
    assert_eq!(st.cur, 2);
}
