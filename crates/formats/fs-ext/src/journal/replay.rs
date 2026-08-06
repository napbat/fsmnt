//! Journal replay engine: walk, apply, and produce the overlay artifact.
//!
//! See `docs/superpowers/specs/2026-04-22-fs-ext-journal-recovery-design.md`.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::features::{JournalChecksumMode, JournalIncompatFeatures};
use super::superblock::{JBD_MAGIC, JbdHeader, JournalSource};
use crate::checksum::ext4_crc32c;
use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{Read, Seek, SeekFrom};
use zerocopy::FromBytes;

/// Block type codes used by jbd2.
const BT_DESCRIPTOR: u32 = 1;
const BT_COMMIT: u32 = 2;
const BT_REVOCATION: u32 = 5;

#[derive(Debug, Default)]
pub(crate) struct PendingTx {
    pub writes: Vec<PendingWrite>,
    pub revocations: Vec<u64>,
    pub descriptor_count: u32,
}

#[derive(Debug)]
pub(crate) struct PendingWrite {
    pub fs_block: u64,
    pub content: Box<[u8]>,
    pub escape: bool,
}

/// Shape of a read source supplying journal blocks. In production this is
/// backed by a persistent `JournalFile` wrapped by a small adapter;
/// unit tests pass an in-memory implementation.
pub(crate) trait JournalBlockReader {
    fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()>;
}

struct BorrowedJournalReader<'a, 'e, T> {
    file: &'a mut super::source::JournalFile<'e>,
    fs: &'a mut T,
}

impl<T: Read + Seek> JournalBlockReader for BorrowedJournalReader<'_, '_, T> {
    fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()> {
        self.file.read_block(self.fs, u64::from(journal_block), buf)
    }
}

/// Forensic record of a journal replay walk.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct ReplayPlan {
    /// Transactions that committed in the journal, in sequence order.
    pub committed: Vec<CommittedTx>,
    /// True when journal data was read through superblock `s_jnl_blocks`
    /// fallback because journal inode lookup/open failed.
    pub used_superblock_journal_backup: bool,
    /// If the walk terminated before the log end, why and where.
    pub stop: Option<ReplayStop>,
    /// Aggregate revocation records and writes suppressed by them.
    pub revocation_summary: RevocationSummary,
}

/// Summary of one journal transaction accepted as committed.
#[derive(Debug)]
#[non_exhaustive]
pub struct CommittedTx {
    /// JBD2 transaction sequence number.
    pub sequence: u32,
    /// Commit timestamp recorded in the commit block, when present.
    pub commit_time: Option<JbdCommitTime>,
    /// Data blocks written into the replay overlay.
    pub data_blocks_applied: u32,
    /// Candidate data writes suppressed by revocation records.
    pub data_blocks_revoked: u32,
    /// Journal data blocks whose escaped magic word was restored.
    pub data_blocks_escaped: u32,
    /// Revocation entries carried by the transaction.
    pub revocation_entries: u32,
    /// Descriptor blocks consumed by the transaction.
    pub descriptor_blocks: u32,
}

/// Location and reason at which classic JBD2 replay stopped.
#[derive(Debug)]
#[non_exhaustive]
pub struct ReplayStop {
    /// Last transaction sequence that committed successfully.
    pub last_good_sequence: u32,
    /// Journal and filesystem location of the failing block.
    pub position: JournalPosition,
    /// Condition that made further replay unsafe.
    pub reason: StopReason,
}

/// Fatal conditions encountered while walking the classic JBD2 log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StopReason {
    /// A journal block did not begin with the JBD2 magic value.
    BadMagic,
    /// A journal block belongs to an unexpected transaction sequence.
    SequenceMismatch {
        /// Sequence expected by the replay walk.
        expected: u32,
        /// Sequence encoded in the journal block.
        seen: u32,
    },
    /// A descriptor block contains malformed tags or payload structure.
    DescriptorBodyInvalid,
    /// A descriptor block's trailing checksum is invalid.
    DescriptorTailChecksumInvalid,
    /// A commit block's transaction checksum is invalid.
    CommitChecksumInvalid,
    /// A revocation block's trailing checksum is invalid.
    RevocationTailChecksumInvalid,
    /// A descriptor tag's checksum does not authenticate its data block.
    DataBlockChecksumInvalid {
        /// Filesystem block targeted by the invalid journal data.
        fs_block: u64,
    },
    /// The journal ended before the current structure was complete.
    Truncated,
}

/// Aggregate revocation activity observed during replay.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RevocationSummary {
    /// Number of revocation entries decoded across all transactions.
    pub total_records: u32,
    /// Number of unique filesystem blocks present in the final revocation map.
    pub distinct_blocks_revoked: u32,
    /// Number of candidate writes omitted because a later revocation won.
    pub suppressed_writes: u32,
}

/// Timestamp encoded by a JBD2 commit block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JbdCommitTime {
    /// Whole seconds since the Unix epoch.
    pub secs: u64,
    /// Nanosecond fraction within the second.
    pub nsecs: u32,
}

/// Correlated journal-block and filesystem-byte position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalPosition {
    /// Journal-relative block number.
    pub journal_block: u32,
    /// Absolute byte offset of that journal block in its source.
    pub fs_byte_offset: u64,
}

/// Block-level overlay produced by replay. Consumed by `OverlayReader`.
#[derive(Debug)]
pub(crate) struct BlockOverlay {
    pub(crate) block_size: u32,
    pub(crate) blocks: BTreeMap<u64, Box<[u8]>>,
    pub(crate) sb_host_block: u64,
    pub(crate) sb_host_block_content: Box<[u8]>,
}

#[derive(Debug)]
struct WalkState {
    expected_seq: u32,
    cur: u32,
    first: u32,
    maxlen: u32,
    block_size: u32,
    is_64bit: bool,
    mode: JournalChecksumMode,
    seed: u32,
    scratch: Box<[u8]>,
    pending: PendingTx,
    committed_meta: Vec<(u64, u32, usize, bool)>,
    #[allow(
        clippy::type_complexity,
        reason = "per-block latest-write record: (sequence, tx_index, content, escape)"
    )]
    latest: BTreeMap<u64, (u32, usize, Box<[u8]>, bool)>,
    revocations: BTreeMap<u64, u32>,
    plan_committed: Vec<CommittedTx>,
}

impl WalkState {
    fn new(source: &JournalSource) -> Self {
        let seed = if matches!(
            source.version,
            super::features::JournalSuperblockVersion::V2
        ) && matches!(
            source.checksum_mode,
            JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c
        ) {
            super::checksum::journal_csum_seed(&source.uuid)
        } else {
            0
        };
        Self {
            expected_seq: source.sequence,
            cur: source.start,
            first: source.first,
            maxlen: source.maxlen,
            block_size: source.block_size,
            is_64bit: source.features.contains(JournalIncompatFeatures::_64BIT),
            mode: source.checksum_mode,
            seed,
            scratch: alloc::vec![0u8; source.block_size as usize].into_boxed_slice(),
            pending: PendingTx::default(),
            committed_meta: Vec::new(),
            latest: BTreeMap::new(),
            revocations: BTreeMap::new(),
            plan_committed: Vec::new(),
        }
    }

    /// Advance a journal block index by one, wrapping from `maxlen` back
    /// to `first` so the ring-buffer layout is honored.
    ///
    /// Kernel jbd2 uses 1-indexed data blocks: block 0 is the journal
    /// superblock, and data blocks live at indices `first..=maxlen`
    /// inclusive. The wrap point is the slot after `maxlen`, not `maxlen`.
    fn next_block(&self, block: u32) -> u32 {
        let next = block.wrapping_add(1);
        if next > self.maxlen { self.first } else { next }
    }
}

/// Walker step for descriptor blocks.
///
/// Parses tags from `st.scratch[12..body_end]` (post-header, pre-tail where
/// applicable), reads each following data block, verifies per-tag checksums
/// under `CSUM_V2/V3`, and accumulates `PendingWrite` entries into `st.pending`.
fn process_descriptor<R: JournalBlockReader>(
    reader: &mut R,
    st: &mut WalkState,
) -> Result<Option<StopReason>> {
    use super::checksum::{block_tail_checksum_split, tag_block_checksum};
    use super::tags::parse_descriptor_tags;

    // Under CSUM_V2/V3, the last 4 bytes of the descriptor block are the
    // tail checksum over the block with the tail field zeroed. Verify that
    // before trusting any of the tag bytes.
    let body_end = match st.mode {
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c => {
            let off = st.scratch.len() - 4;
            let stored =
                u32::from_be_bytes(st.scratch[off..off + 4].try_into().expect("fixed slice"));
            let computed = block_tail_checksum_split(st.seed, &st.scratch[..off], &[]);
            if computed != stored {
                return Ok(Some(StopReason::DescriptorTailChecksumInvalid));
            }
            off
        }
        _ => st.scratch.len(),
    };
    st.pending.descriptor_count += 1;

    // Borrow the body slice up-front so the iterator holds only `&st.scratch`.
    // The loop body mutates `st.pending` via the disjoint-field borrow rule.
    let mode = st.mode;
    let is_64bit = st.is_64bit;
    let seed = st.seed;
    let expected_seq = st.expected_seq;
    let block_size = st.block_size;
    let mut block = st.next_block(st.cur);

    let tags = parse_descriptor_tags(&st.scratch[12..body_end], mode, is_64bit);
    for result in tags {
        // Structural problems with the descriptor body (missing LAST_TAG,
        // truncated UUID, truncated 64BIT high half) surface as a stop
        // rather than an error — `build()` is contracted to return `Err`
        // only for setup failures, not mid-walk corruption.
        let tag = match result {
            Ok(t) => t,
            Err(ExtError::InvalidJournalSuperblock { .. }) => {
                return Ok(Some(StopReason::DescriptorBodyInvalid));
            }
            Err(e) => return Err(e),
        };

        let mut data = alloc::vec![0u8; block_size as usize];
        // An `UnexpectedEof` here means the journal ran out mid-transaction;
        // treat it the same as truncation at the walk top-level rather than
        // bubbling it as a setup error.
        match reader.read_block(block, &mut data) {
            Ok(()) => {}
            Err(ExtError::UnexpectedEof { .. }) => {
                return Ok(Some(StopReason::Truncated));
            }
            Err(e) => return Err(e),
        }

        match mode {
            JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c => {
                let computed = tag_block_checksum(mode, seed, expected_seq, &data);
                if computed != tag.checksum {
                    return Ok(Some(StopReason::DataBlockChecksumInvalid {
                        fs_block: tag.fs_block,
                    }));
                }
            }
            _ => {}
        }

        st.pending.writes.push(PendingWrite {
            fs_block: tag.fs_block,
            content: data.into_boxed_slice(),
            escape: tag.escape,
        });
        block = st.next_block(block);
    }
    st.cur = block;
    Ok(None)
}

fn process_revocation(st: &mut WalkState) -> Option<StopReason> {
    let r_count = u32::from_be_bytes(st.scratch[12..16].try_into().expect("fixed slice")) as usize;
    if r_count < 16 || r_count > st.scratch.len() {
        return Some(StopReason::RevocationTailChecksumInvalid);
    }

    let data_end = match st.mode {
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c => {
            let off = st.scratch.len() - 4;
            let computed =
                super::checksum::block_tail_checksum_split(st.seed, &st.scratch[..off], &[]);
            let stored =
                u32::from_be_bytes(st.scratch[off..off + 4].try_into().expect("fixed slice"));
            if computed != stored {
                return Some(StopReason::RevocationTailChecksumInvalid);
            }
            r_count.min(st.scratch.len() - 4)
        }
        _ => r_count,
    };

    let mut offset = 16usize;
    let entry_width = if st.is_64bit { 8 } else { 4 };
    while offset + entry_width <= data_end {
        let block = if st.is_64bit {
            u64::from_be_bytes(
                st.scratch[offset..offset + 8]
                    .try_into()
                    .expect("fixed slice"),
            )
        } else {
            u64::from(u32::from_be_bytes(
                st.scratch[offset..offset + 4]
                    .try_into()
                    .expect("fixed slice"),
            ))
        };
        st.pending.revocations.push(block);
        offset += entry_width;
    }
    st.cur = st.next_block(st.cur);
    None
}

fn process_commit(st: &mut WalkState) -> Option<StopReason> {
    match st.mode {
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c => {
            const CSUM_OFF: usize = 0x10;
            let computed = super::checksum::block_tail_checksum_split(
                st.seed,
                &st.scratch[..CSUM_OFF],
                &st.scratch[CSUM_OFF + 4..],
            );
            let stored = u32::from_be_bytes(
                st.scratch[CSUM_OFF..CSUM_OFF + 4]
                    .try_into()
                    .expect("fixed slice"),
            );
            if computed != stored {
                return Some(StopReason::CommitChecksumInvalid);
            }
        }
        JournalChecksumMode::CompatCrc32 => {
            let mut hasher = super::checksum::CompatCrc32::new();
            for w in &st.pending.writes {
                hasher.update(&w.content);
            }
            let computed = hasher.finalize();
            let stored =
                u32::from_be_bytes(st.scratch[0x10..0x14].try_into().expect("fixed slice"));
            if computed != stored {
                return Some(StopReason::CommitChecksumInvalid);
            }
        }
        JournalChecksumMode::None => {}
    }

    let tx_index = st.plan_committed.len();
    let sequence = st.expected_seq;

    for &blk in &st.pending.revocations {
        let entry = st.revocations.entry(blk).or_insert(0);
        if sequence > *entry {
            *entry = sequence;
        }
    }

    let writes = core::mem::take(&mut st.pending.writes);
    for pw in writes {
        st.committed_meta
            .push((pw.fs_block, sequence, tx_index, pw.escape));
        st.latest
            .insert(pw.fs_block, (sequence, tx_index, pw.content, pw.escape));
    }

    let commit_time = {
        let secs = u64::from_be_bytes(st.scratch[0x30..0x38].try_into().expect("fixed slice"));
        let nsecs = u32::from_be_bytes(st.scratch[0x38..0x3C].try_into().expect("fixed slice"));
        if secs == 0 && nsecs == 0 {
            None
        } else {
            Some(JbdCommitTime { secs, nsecs })
        }
    };

    let descriptor_count = st.pending.descriptor_count;
    let revocation_count = u32::try_from(st.pending.revocations.len()).unwrap_or(u32::MAX);

    st.plan_committed.push(CommittedTx {
        sequence,
        commit_time,
        data_blocks_applied: 0,
        data_blocks_revoked: 0,
        data_blocks_escaped: 0,
        revocation_entries: revocation_count,
        descriptor_blocks: descriptor_count,
    });

    st.pending = PendingTx::default();
    st.expected_seq = st.expected_seq.wrapping_add(1);
    st.cur = st.next_block(st.cur);
    None
}

fn stop_here(st: &WalkState, reason: StopReason) -> ReplayStop {
    let last_good_sequence = st
        .plan_committed
        .last()
        .map_or(st.expected_seq.wrapping_sub(1), |t| t.sequence);
    ReplayStop {
        last_good_sequence,
        position: JournalPosition {
            journal_block: st.cur,
            fs_byte_offset: u64::from(st.cur) * u64::from(st.block_size),
        },
        reason,
    }
}

fn walk<R: JournalBlockReader>(
    source: &JournalSource,
    reader: &mut R,
    plan: &mut ReplayPlan,
) -> Result<WalkState> {
    let mut st = WalkState::new(source);
    if st.cur == 0 {
        return Ok(st);
    }

    let start_cur = st.cur;
    let mut iterations: u32 = 0;
    loop {
        // Only `UnexpectedEof` (journal file ran out under us) is a normal
        // end-of-log condition. Underlying I/O failures must surface as
        // errors so callers can distinguish a dirty tail from a broken
        // reader.
        match reader.read_block(st.cur, &mut st.scratch) {
            Ok(()) => {}
            Err(ExtError::UnexpectedEof { .. }) => {
                plan.stop = Some(stop_here(&st, StopReason::Truncated));
                break;
            }
            Err(e) => return Err(e),
        }
        let hdr = JbdHeader::ref_from_bytes(&st.scratch[..12]).expect("scratch is block-sized");
        if hdr.h_magic.get() != JBD_MAGIC {
            plan.stop = Some(stop_here(&st, StopReason::BadMagic));
            break;
        }
        if hdr.h_sequence.get() != st.expected_seq {
            plan.stop = Some(stop_here(
                &st,
                StopReason::SequenceMismatch {
                    expected: st.expected_seq,
                    seen: hdr.h_sequence.get(),
                },
            ));
            break;
        }

        let outcome = match hdr.h_blocktype.get() {
            BT_DESCRIPTOR => process_descriptor(reader, &mut st)?,
            BT_REVOCATION => process_revocation(&mut st),
            BT_COMMIT => process_commit(&mut st),
            _ => {
                plan.stop = Some(stop_here(&st, StopReason::BadMagic));
                break;
            }
        };
        if let Some(reason) = outcome {
            plan.stop = Some(stop_here(&st, reason));
            break;
        }

        iterations += 1;
        if st.cur > source.maxlen {
            st.cur = source.first;
        }
        if st.cur == start_cur && iterations > 0 {
            break;
        }
    }

    plan.committed = core::mem::take(&mut st.plan_committed);
    plan.revocation_summary.total_records =
        plan.committed.iter().map(|t| t.revocation_entries).sum();

    Ok(st)
}

const INCOMPAT_RECOVER_BIT: u32 = 0x0000_0004;
const S_FEATURE_INCOMPAT_OFFSET: usize = 0x60;
const S_CHECKSUM_OFFSET: usize = 0x3FC;
const SUPERBLOCK_LEN: usize = 1024;

fn compute_sb_host_block(block_size: u32) -> (u64, usize) {
    if block_size > 1024 { (0, 1024) } else { (1, 0) }
}

fn apply_pass<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    st: &mut WalkState,
    plan: &mut ReplayPlan,
) -> Result<BlockOverlay> {
    let (sb_host_block, sb_offset_in_host) = compute_sb_host_block(st.block_size);

    let blocks_count = ext.blocks_count;
    for &(fs_block, sequence, tx_index, escape) in &st.committed_meta {
        // Drop writes that reference out-of-range blocks; they cannot
        // appear in the overlay (BlockOverlay invariant) and are not
        // counted as applied.
        if fs_block >= blocks_count {
            continue;
        }
        let suppressed = st.revocations.get(&fs_block).copied().unwrap_or(0) > sequence;
        let tx = &mut plan.committed[tx_index];
        if suppressed {
            tx.data_blocks_revoked += 1;
            plan.revocation_summary.suppressed_writes += 1;
        } else {
            tx.data_blocks_applied += 1;
            if escape {
                tx.data_blocks_escaped += 1;
            }
        }
    }
    plan.revocation_summary.distinct_blocks_revoked =
        u32::try_from(st.revocations.len()).unwrap_or(u32::MAX);

    let mut blocks: BTreeMap<u64, Box<[u8]>> = BTreeMap::new();
    let mut sb_host_stash: Option<Box<[u8]>> = None;
    let latest = core::mem::take(&mut st.latest);
    for (fs_block, (sequence, _tx_index, mut content, escape)) in latest {
        if fs_block >= blocks_count {
            // Enforces BlockOverlay::blocks invariant from the design spec.
            continue;
        }
        if st.revocations.get(&fs_block).copied().unwrap_or(0) > sequence {
            continue;
        }
        if escape {
            content[0..4].copy_from_slice(&JBD_MAGIC.to_be_bytes());
        }
        if fs_block == sb_host_block {
            sb_host_stash = Some(content);
        } else {
            blocks.insert(fs_block, content);
        }
    }

    let mut host = if let Some(buf) = sb_host_stash {
        buf
    } else {
        let mut buf = alloc::vec![0u8; st.block_size as usize].into_boxed_slice();
        fs.seek(SeekFrom::Start(sb_host_block * u64::from(st.block_size)))?;
        fs.read_exact(&mut buf[..])?;
        buf
    };
    {
        let sb_region = &mut host[sb_offset_in_host..sb_offset_in_host + SUPERBLOCK_LEN];
        let current = u32::from_le_bytes(
            sb_region[S_FEATURE_INCOMPAT_OFFSET..S_FEATURE_INCOMPAT_OFFSET + 4]
                .try_into()
                .expect("fixed slice"),
        );
        let patched = current & !INCOMPAT_RECOVER_BIT;
        sb_region[S_FEATURE_INCOMPAT_OFFSET..S_FEATURE_INCOMPAT_OFFSET + 4]
            .copy_from_slice(&patched.to_le_bytes());

        if ext.has_metadata_csum() {
            let computed = ext4_crc32c(!0, &sb_region[..S_CHECKSUM_OFFSET]);
            sb_region[S_CHECKSUM_OFFSET..S_CHECKSUM_OFFSET + 4]
                .copy_from_slice(&computed.to_le_bytes());
        }
    }

    Ok(BlockOverlay {
        block_size: st.block_size,
        blocks,
        sb_host_block,
        sb_host_block_content: host,
    })
}

/// Journal replay artifact. Opaque to external callers; mediates access to
/// the overlay via `OverlayReader`.
#[derive(Debug)]
pub struct JournalReplay {
    plan: ReplayPlan,
    fast_commit_plan: Option<crate::journal::FastCommitPlan>,
    overlay: BlockOverlay,
}

impl JournalReplay {
    /// Walk the journal, verify checksums, build the overlay.
    ///
    /// Returns `Ok` even when the journal log terminates partially; inspect
    /// [`ReplayPlan::stop`] to distinguish. Returns `Err` only for setup
    /// failures (no journal, bad journal superblock, bad inode table).
    ///
    /// # Errors
    ///
    /// Returns an I/O, journal setup, inode, or overlay-construction error
    /// when replay cannot begin or its recovered blocks cannot be materialized.
    pub fn build<T: Read + Seek>(ext: &Ext, fs: &mut T) -> Result<Self> {
        let Some(opened) = super::source::open_journal_source(ext, fs)? else {
            return Err(crate::error::ExtError::JournalExpectedButAbsent);
        };
        let source = opened.source;

        let (mut st, mut plan) = {
            let mut journal_file =
                super::source::open_journal_file(ext, fs, &source, &opened.locator)?;

            let mut reader = BorrowedJournalReader {
                file: &mut journal_file,
                fs,
            };
            let mut plan = ReplayPlan {
                used_superblock_journal_backup: opened.used_superblock_backup,
                ..ReplayPlan::default()
            };
            let st = walk(&source, &mut reader, &mut plan)?;
            (st, plan)
        };

        let overlay = apply_pass(ext, fs, &mut st, &mut plan)?;
        let last_classic_seq = plan.committed.last().map(|t| t.sequence);
        let (overlay, fast_commit_plan) = if source.effective_num_fc_blocks() > 0 {
            let expected_tid = source.expected_fc_tid(last_classic_seq);
            let (composed, fc_plan) = crate::journal::fast_commit::FastCommitReplay::build(
                ext,
                fs,
                &source,
                &opened.locator,
                overlay,
                expected_tid,
            )?;
            (composed, Some(fc_plan))
        } else {
            (overlay, None)
        };
        Ok(Self {
            plan,
            fast_commit_plan,
            overlay,
        })
    }

    /// Walk and replay the journal of a filesystem whose journal lives
    /// on an external device (`INCOMPAT_JOURNAL_DEV`).
    ///
    /// `fs` is the filesystem reader; `journal` is the external journal
    /// device. Journal blocks are read from `journal` (block `N` at byte
    /// offset `N * block_size`); filesystem blocks — read while
    /// materialising the overlay — stay on `fs`.
    ///
    /// External journals carrying fast-commit blocks are rejected with
    /// [`ExtError::ExternalJournalFastCommitUnsupported`]; classic
    /// journal replay is fully supported.
    ///
    /// # Errors
    ///
    /// Returns an I/O or journal-format error, a UUID mismatch, or
    /// [`ExtError::ExternalJournalFastCommitUnsupported`] when the external
    /// journal cannot be replayed.
    pub fn build_with_external_journal<T: Read + Seek, J: Read + Seek>(
        ext: &Ext,
        fs: &mut T,
        journal: &mut J,
    ) -> Result<Self> {
        let source = super::source::open_external_journal_source(ext, journal)?;
        if source.effective_num_fc_blocks() > 0 {
            return Err(crate::error::ExtError::ExternalJournalFastCommitUnsupported);
        }

        let (mut st, mut plan) = {
            /// Reads journal blocks off the external device. jbd2 block
            /// `N` lives at device block `base_block + N` — `base_block`
            /// skips the journal device's own ext4 superblock region
            /// (see `external_journal_base_block`).
            struct ExternalJournalReader<'a, J> {
                journal: &'a mut J,
                block_size: u32,
                base_block: u64,
            }
            impl<J: Read + Seek> JournalBlockReader for ExternalJournalReader<'_, J> {
                fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()> {
                    let device_block = self.base_block + u64::from(journal_block);
                    let offset = device_block * u64::from(self.block_size);
                    self.journal.seek(SeekFrom::Start(offset))?;
                    self.journal.read_exact(buf)?;
                    Ok(())
                }
            }

            let mut reader = ExternalJournalReader {
                journal,
                block_size: source.block_size,
                base_block: super::source::external_journal_base_block(source.block_size),
            };
            let mut plan = ReplayPlan::default();
            let st = walk(&source, &mut reader, &mut plan)?;
            (st, plan)
        };

        // The classic walk materialised every journal block into `st`;
        // apply_pass only reads the filesystem to fetch the sb-host base
        // block, so it stays on `fs`.
        let overlay = apply_pass(ext, fs, &mut st, &mut plan)?;
        Ok(Self {
            plan,
            fast_commit_plan: None,
            overlay,
        })
    }

    #[must_use]
    /// Returns the forensic plan produced by this replay.
    pub fn plan(&self) -> &ReplayPlan {
        &self.plan
    }

    #[must_use]
    /// Consumes the replay artifact and returns its forensic plan.
    pub fn into_plan(self) -> ReplayPlan {
        self.plan
    }

    /// The fast-commit replay plan, when the journal had
    /// `INCOMPAT_FAST_COMMIT` and a non-empty FC region.
    ///
    /// Returns `Some(plan)` even when no transactions replayed — that's
    /// the legitimate "FC region present but never used" case. Returns
    /// `None` only when the journal had no FC region.
    #[must_use]
    pub fn fast_commit_plan(&self) -> Option<&crate::journal::FastCommitPlan> {
        self.fast_commit_plan.as_ref()
    }

    /// Construct a minimal `JournalReplay` for unit tests. Not available in
    /// production builds.
    #[cfg(test)]
    pub(crate) fn for_test(overlay: BlockOverlay) -> Self {
        Self {
            plan: ReplayPlan::default(),
            fast_commit_plan: None,
            overlay,
        }
    }

    /// Construct a `JournalReplay` with a caller-supplied plan, for tests
    /// that need a non-default plan (e.g. to exercise `OrphanReplay`
    /// accessors that forward `journal_plan()` / `into_plans()`).
    /// Not available in production builds.
    #[cfg(test)]
    pub(crate) fn for_test_with_plan(overlay: BlockOverlay, plan: ReplayPlan) -> Self {
        Self {
            plan,
            fast_commit_plan: None,
            overlay,
        }
    }
}

impl super::overlay::OverlaySource for JournalReplay {
    fn block_size(&self) -> u32 {
        self.overlay.block_size
    }

    fn sb_host_block(&self) -> u64 {
        self.overlay.sb_host_block
    }

    fn sb_host_block_content(&self) -> &[u8] {
        &self.overlay.sb_host_block_content
    }

    fn overlay_block(&self, fs_block: u64) -> Option<&[u8]> {
        self.overlay
            .blocks
            .get(&fs_block)
            .map(core::convert::AsRef::as_ref)
    }
}

impl super::overlay::OverlaySource for BlockOverlay {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn sb_host_block(&self) -> u64 {
        self.sb_host_block
    }

    fn sb_host_block_content(&self) -> &[u8] {
        &self.sb_host_block_content
    }

    fn overlay_block(&self, fs_block: u64) -> Option<&[u8]> {
        self.blocks.get(&fs_block).map(core::convert::AsRef::as_ref)
    }
}

#[cfg(test)]
#[path = "replay_tests/mod.rs"]
mod tests;
