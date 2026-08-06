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
    pub revocation_summary: RevocationSummary,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct CommittedTx {
    pub sequence: u32,
    pub commit_time: Option<JbdCommitTime>,
    pub data_blocks_applied: u32,
    pub data_blocks_revoked: u32,
    pub data_blocks_escaped: u32,
    pub revocation_entries: u32,
    pub descriptor_blocks: u32,
}

#[derive(Debug)]
#[non_exhaustive]
pub struct ReplayStop {
    pub last_good_sequence: u32,
    pub position: JournalPosition,
    pub reason: StopReason,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StopReason {
    BadMagic,
    SequenceMismatch { expected: u32, seen: u32 },
    DescriptorBodyInvalid,
    DescriptorTailChecksumInvalid,
    CommitChecksumInvalid,
    RevocationTailChecksumInvalid,
    DataBlockChecksumInvalid { fs_block: u64 },
    Truncated,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct RevocationSummary {
    pub total_records: u32,
    pub distinct_blocks_revoked: u32,
    pub suppressed_writes: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JbdCommitTime {
    pub secs: u64,
    pub nsecs: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JournalPosition {
    pub journal_block: u32,
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
/// under CSUM_V2/V3, and accumulates `PendingWrite` entries into `st.pending`.
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

fn process_revocation(st: &mut WalkState) -> Result<Option<StopReason>> {
    let r_count = u32::from_be_bytes(st.scratch[12..16].try_into().expect("fixed slice")) as usize;
    if r_count < 16 || r_count > st.scratch.len() {
        return Ok(Some(StopReason::RevocationTailChecksumInvalid));
    }

    let data_end = match st.mode {
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c => {
            let off = st.scratch.len() - 4;
            let computed =
                super::checksum::block_tail_checksum_split(st.seed, &st.scratch[..off], &[]);
            let stored =
                u32::from_be_bytes(st.scratch[off..off + 4].try_into().expect("fixed slice"));
            if computed != stored {
                return Ok(Some(StopReason::RevocationTailChecksumInvalid));
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
    Ok(None)
}

fn process_commit(st: &mut WalkState) -> Result<Option<StopReason>> {
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
                return Ok(Some(StopReason::CommitChecksumInvalid));
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
                return Ok(Some(StopReason::CommitChecksumInvalid));
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
    let revocation_count = st.pending.revocations.len() as u32;

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
    Ok(None)
}

fn stop_here(st: &WalkState, reason: StopReason) -> ReplayStop {
    let last_good_sequence = st
        .plan_committed
        .last()
        .map(|t| t.sequence)
        .unwrap_or(st.expected_seq.wrapping_sub(1));
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
            BT_REVOCATION => process_revocation(&mut st)?,
            BT_COMMIT => process_commit(&mut st)?,
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
    plan.revocation_summary.distinct_blocks_revoked = st.revocations.len() as u32;

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

    let mut host = match sb_host_stash {
        Some(buf) => buf,
        None => {
            let mut buf = alloc::vec![0u8; st.block_size as usize].into_boxed_slice();
            fs.seek(SeekFrom::Start(sb_host_block * u64::from(st.block_size)))?;
            fs.read_exact(&mut buf[..])?;
            buf
        }
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
    pub fn build<T: Read + Seek>(ext: &Ext, fs: &mut T) -> Result<Self> {
        let opened = match super::source::open_journal_source(ext, fs)? {
            Some(s) => s,
            None => {
                return Err(crate::error::ExtError::JournalExpectedButAbsent);
            }
        };
        let source = opened.source;

        let (mut st, mut plan) = {
            let mut journal_file =
                super::source::open_journal_file(ext, fs, &source, &opened.locator)?;

            struct BorrowedReader<'a, 'e, T> {
                file: &'a mut super::source::JournalFile<'e>,
                fs: &'a mut T,
            }
            impl<'a, 'e, T: Read + Seek> JournalBlockReader for BorrowedReader<'a, 'e, T> {
                fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()> {
                    self.file.read_block(self.fs, u64::from(journal_block), buf)
                }
            }

            let mut reader = BorrowedReader {
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

    pub fn plan(&self) -> &ReplayPlan {
        &self.plan
    }

    pub fn into_plan(self) -> ReplayPlan {
        self.plan
    }

    /// The fast-commit replay plan, when the journal had
    /// `INCOMPAT_FAST_COMMIT` and a non-empty FC region.
    ///
    /// Returns `Some(plan)` even when no transactions replayed — that's
    /// the legitimate "FC region present but never used" case. Returns
    /// `None` only when the journal had no FC region.
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
        self.overlay.blocks.get(&fs_block).map(|b| b.as_ref())
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
        self.blocks.get(&fs_block).map(|b| b.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::fast_commit::test_support::{FcTxBuilder, fc_region};
    use crate::journal::superblock::{JBD_MAGIC, JbdHeader};
    use zerocopy::FromBytes;

    const TEST_CLASSIC_SEQ: u32 = 100;
    const TEST_CLASSIC_START: u32 = 1;

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
        use crate::journal::OverlaySource;
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
    /// block_size > 1024 and block 1 with no offset for block_size ==
    /// 1024. The `> -> >=` mutant on line 489 only diverges at
    /// block_size == 1024 (mutant returns `(0, 1024)` instead of
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
            alloc::vec![alloc::vec![0u8; source.block_size as usize]; 4],
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
        write_fc_region_blocks(&mut bytes, &source, blocks);

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

        struct BorrowedReader<'a, 'e, T> {
            file: &'a mut crate::journal::source::JournalFile<'e>,
            fs: &'a mut T,
        }
        impl<'a, 'e, T: Read + Seek> JournalBlockReader for BorrowedReader<'a, 'e, T> {
            fn read_block(&mut self, journal_block: u32, buf: &mut [u8]) -> Result<()> {
                self.file.read_block(self.fs, u64::from(journal_block), buf)
            }
        }

        let mut reader = BorrowedReader {
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
        let offset = table_block * u64::from(ext.block_size())
            + u64::from(index) * u64::from(ext.inode_size());
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
            &((crate::journal::tags::TAG_FLAG_LAST | crate::journal::tags::TAG_FLAG_SAME_UUID)
                as u16)
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

    fn write_fc_region_blocks(bytes: &mut Vec<u8>, source: &JournalSource, blocks: Vec<Vec<u8>>) {
        let fc_first = source
            .maxlen
            .checked_sub(source.effective_num_fc_blocks())
            .expect("FC blocks fit in journal")
            + 1;
        for (i, block) in blocks.iter().enumerate() {
            let host_off = {
                let mut cursor = std::io::Cursor::new(bytes.as_slice());
                let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
                journal_block_host_offset(&ext, &mut cursor, fc_first + i as u32)
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
            block_size: bs as u32,
        };
        // Use None mode so checksum verification is skipped; this test covers
        // write accumulation only.
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::None));
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
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::None));
        st.scratch.copy_from_slice(&blk);
        let r = process_revocation(&mut st).expect("process revocation");
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
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::V3Crc32c));
        st.pending.writes.push(PendingWrite {
            fs_block: 7,
            content: alloc::vec![0u8; bs].into_boxed_slice(),
            escape: false,
        });
        st.pending.descriptor_count = 1;

        let blk = compute_commit_block_bytes(bs, st.seed, st.expected_seq);
        st.scratch.copy_from_slice(&blk);
        let stop = process_commit(&mut st).expect("process commit");
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
        let source = dummy_source(bs as u32, mode);

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
            block_size: bs as u32,
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
        let mut source = dummy_source(bs as u32, mode);
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
            block_size: bs as u32,
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
        let mut source = dummy_source(bs as u32, mode);
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
            block_size: bs as u32,
        };

        let mut plan = ReplayPlan::default();
        walk(&source, &mut mem, &mut plan).expect("walk");
        assert_eq!(plan.committed.len(), 1);
    }

    #[test]
    fn apply_restores_escape_and_suppresses_revoked() {
        let bs = 4096usize;
        let mode = JournalChecksumMode::None;
        let source = dummy_source(bs as u32, mode);
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
        let source = dummy_source(bs as u32, JournalChecksumMode::None);
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
            block_size: bs as u32,
        };
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::None));
        mem.read_block(1, &mut st.scratch).expect("read descriptor");
        let reason = process_descriptor(&mut mem, &mut st).expect("stop, not error");
        assert_eq!(reason, Some(StopReason::DescriptorBodyInvalid));
    }

    #[test]
    fn walk_propagates_real_io_errors() {
        struct IoErrorReader;
        impl JournalBlockReader for IoErrorReader {
            fn read_block(&mut self, _b: u32, _buf: &mut [u8]) -> Result<()> {
                Err(
                    crate::io::Error::new(crate::io::ErrorKind::PermissionDenied, "injected")
                        .into(),
                )
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
            block_size: bs as u32,
        };
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::V3Crc32c));
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
        let mut source = dummy_source(bs as u32, mode);
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
            block_size: bs as u32,
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

    #[test]
    fn descriptor_rejects_bad_data_checksum_v3() {
        let bs = 4096usize;
        let mut desc = alloc::vec![0u8; bs];
        desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, 1));
        desc[12..16].copy_from_slice(&42u32.to_be_bytes());
        desc[16..20].copy_from_slice(&crate::journal::tags::TAG_FLAG_LAST.to_be_bytes());
        desc[20..24].copy_from_slice(&0u32.to_be_bytes());
        // Tag's per-block checksum field: plant a wrong value so the per-tag
        // check fires once the descriptor tail checksum has been satisfied.
        desc[24..28].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

        // Compute a valid descriptor tail checksum so we reach the per-tag
        // check rather than stopping on DescriptorTailChecksumInvalid first.
        let seed = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::V3Crc32c)).seed;
        let tail_off = bs - 4;
        let tail_csum =
            crate::journal::checksum::block_tail_checksum_split(seed, &desc[..tail_off], &[]);
        desc[tail_off..tail_off + 4].copy_from_slice(&tail_csum.to_be_bytes());

        let mut data = alloc::vec![0u8; bs];
        data[0..8].copy_from_slice(b"WRONGCSM");

        let mut mem = InMemJournal {
            blocks: alloc::vec![alloc::vec![0u8; bs], desc, data, alloc::vec![0u8; bs]],
            block_size: bs as u32,
        };
        let mut st = WalkState::new(&dummy_source(bs as u32, JournalChecksumMode::V3Crc32c));
        mem.read_block(1, &mut st.scratch).expect("read descriptor");
        let reason = process_descriptor(&mut mem, &mut st).expect("process");
        assert!(matches!(
            reason,
            Some(StopReason::DataBlockChecksumInvalid { fs_block: 42 })
        ));
    }

    // ---- issue #118: external journal device replay ----

    const EXT_JOURNAL_BLOCKS: u32 = 8;
    const EXT_JOURNAL_SEQ: u32 = 100;

    /// Build an `mke2fs -O journal_dev`-shaped external-journal device
    /// image. Device block 0 is the journal device's own ext4
    /// superblock region (unread by the parser, left as padding here);
    /// the jbd2 area begins at device block `base` — block `base` is the
    /// jbd2 superblock, and jbd2 block `N` is at device block `base + N`.
    /// jbd2 blocks 1..3 hold one classic transaction (descriptor, data,
    /// commit) targeting filesystem block `target_fs_block`, whose
    /// content is `data_fill`. `feature_incompat` is left zero so the
    /// un-checksummed blocks validate.
    fn build_external_journal(
        block_size: u32,
        uuid: [u8; 16],
        target_fs_block: u32,
        data_fill: u8,
    ) -> Vec<u8> {
        let bs = block_size as usize;
        let base = crate::journal::source::external_journal_base_block(block_size) as usize;
        // Device blocks: [0..base) ext4-device-sb region, then the
        // `EXT_JOURNAL_BLOCKS`-block jbd2 journal area.
        let mut buf = alloc::vec![0u8; bs * (base + EXT_JOURNAL_BLOCKS as usize)];

        // --- jbd2 block 0 (device block `base`): superblock v2 (BE) ---
        let sb = &mut buf[base * bs..(base + 1) * bs];
        sb[0x00..0x04].copy_from_slice(&JBD_MAGIC.to_be_bytes());
        sb[0x04..0x08].copy_from_slice(&4u32.to_be_bytes()); // h_blocktype: superblock v2
        sb[0x0C..0x10].copy_from_slice(&block_size.to_be_bytes()); // s_blocksize
        sb[0x10..0x14].copy_from_slice(&EXT_JOURNAL_BLOCKS.to_be_bytes()); // s_maxlen
        sb[0x14..0x18].copy_from_slice(&1u32.to_be_bytes()); // s_first
        sb[0x18..0x1C].copy_from_slice(&EXT_JOURNAL_SEQ.to_be_bytes()); // s_sequence
        sb[0x1C..0x20].copy_from_slice(&1u32.to_be_bytes()); // s_start
        // 0x28 feature_incompat stays 0 → no journal checksums.
        sb[0x30..0x40].copy_from_slice(&uuid); // s_uuid
        sb[0x40..0x44].copy_from_slice(&1u32.to_be_bytes()); // s_nr_users

        // jbd2 block N → device block `base + N`.
        let jbd_block = |n: usize| (base + n) * bs;

        // --- jbd2 block 1: descriptor with one classic tag ---
        let desc_off = jbd_block(1);
        let desc = &mut buf[desc_off..desc_off + bs];
        desc[..12].copy_from_slice(&hdr(BT_DESCRIPTOR, EXT_JOURNAL_SEQ));
        desc[12..16].copy_from_slice(&target_fs_block.to_be_bytes()); // tag blocknr
        desc[16..18].copy_from_slice(&0u16.to_be_bytes()); // tag checksum
        desc[18..20].copy_from_slice(
            &((crate::journal::tags::TAG_FLAG_LAST | crate::journal::tags::TAG_FLAG_SAME_UUID)
                as u16)
                .to_be_bytes(),
        );

        // --- jbd2 block 2: the data block (first 4 bytes ≠ JBD_MAGIC) ---
        buf[jbd_block(2)..jbd_block(2) + bs].fill(data_fill);

        // --- jbd2 block 3: commit ---
        buf[jbd_block(3)..jbd_block(3) + 12].copy_from_slice(&hdr(BT_COMMIT, EXT_JOURNAL_SEQ));

        buf
    }

    #[test]
    fn external_journal_uuid_mismatch_is_rejected() {
        // ext4.img is an internal-journal filesystem → s_journal_uuid is
        // all-zero. An external journal advertising a different UUID must
        // be rejected.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let bytes = std::fs::read(path).expect("read ext4 fixture");
        let mut fs = std::io::Cursor::new(bytes);
        let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");

        let wrong_uuid = [0xAA; 16];
        let journal_buf = build_external_journal(ext.block_size(), wrong_uuid, 500, 0xCD);
        let mut journal = std::io::Cursor::new(journal_buf);

        let err = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
            .expect_err("UUID mismatch must be rejected");
        match err {
            crate::error::ExtError::JournalUuidMismatch {
                fs_uuid,
                journal_uuid,
            } => {
                assert_eq!(fs_uuid, [0u8; 16]);
                assert_eq!(journal_uuid, wrong_uuid);
            }
            other => panic!("expected JournalUuidMismatch, got {other:?}"),
        }
    }

    #[test]
    fn external_journal_replays_classic_transaction() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let bytes = std::fs::read(path).expect("read ext4 fixture");
        let mut fs = std::io::Cursor::new(bytes);
        let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");
        // ext4.img has an internal journal, so s_journal_uuid is zero;
        // the synthetic external journal carries the same zero UUID.
        let target = 500u32;
        let journal_buf =
            build_external_journal(ext.block_size(), ext.journal_uuid(), target, 0xCD);
        let mut journal = std::io::Cursor::new(journal_buf);

        let jr = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
            .expect("external journal replay");

        // The classic transaction from the *external* device was walked
        // and committed; its single data block was applied.
        assert_eq!(jr.plan().committed.len(), 1, "one committed transaction");
        assert_eq!(jr.plan().committed[0].data_blocks_applied, 1);

        // The overlay now serves the journal-recorded content for the
        // target filesystem block.
        let mut overlay_reader = crate::OverlayReader::new(&mut fs, &jr);
        overlay_reader
            .seek(SeekFrom::Start(
                u64::from(target) * u64::from(ext.block_size()),
            ))
            .expect("seek overlay");
        let mut block = alloc::vec![0u8; ext.block_size() as usize];
        overlay_reader
            .read_exact(&mut block)
            .expect("read overlay block");
        assert!(
            block.iter().all(|&b| b == 0xCD),
            "external-journal data block must be applied to the overlay",
        );
    }

    #[test]
    fn open_with_external_journal_gates_journal_dev_flag() {
        // Patch ext4.img to advertise INCOMPAT_JOURNAL_DEV (bit 0x0008
        // at superblock offset 0x60). The single-reader open paths must
        // reject it; open_with_external_journal must accept it.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let mut bytes = std::fs::read(path).expect("read ext4 fixture");
        let incompat_off = 1024 + 0x60;
        let mut incompat = u32::from_le_bytes(
            bytes[incompat_off..incompat_off + 4]
                .try_into()
                .expect("fixed slice"),
        );
        incompat |= 0x0000_0008; // INCOMPAT_JOURNAL_DEV
        bytes[incompat_off..incompat_off + 4].copy_from_slice(&incompat.to_le_bytes());

        // Single-reader paths reject.
        let mut fs = std::io::Cursor::new(bytes.clone());
        assert!(matches!(
            crate::Ext::open_lenient(&mut fs),
            Err(crate::error::ExtError::UnsupportedJournalDevice),
        ));
        let mut fs = std::io::Cursor::new(bytes.clone());
        assert!(matches!(
            crate::Ext::new(&mut fs),
            Err(crate::error::ExtError::UnsupportedJournalDevice),
        ));

        // The dual-reader path parses the filesystem and validates the
        // external journal (zero UUID matches the untouched s_journal_uuid).
        let block_size = 4096u32;
        let journal_buf = build_external_journal(block_size, [0u8; 16], 500, 0xCD);
        let mut fs = std::io::Cursor::new(bytes);
        let mut journal = std::io::Cursor::new(journal_buf);
        let ext = crate::Ext::open_with_external_journal(&mut fs, &mut journal)
            .expect("open_with_external_journal must accept INCOMPAT_JOURNAL_DEV");
        assert!(ext.uses_external_journal());
    }

    #[test]
    fn external_journal_with_fast_commit_is_rejected() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let bytes = std::fs::read(path).expect("read ext4 fixture");
        let mut fs = std::io::Cursor::new(bytes);
        let ext = crate::Ext::open_lenient(&mut fs).expect("open ext4.img");

        let mut journal_buf =
            build_external_journal(ext.block_size(), ext.journal_uuid(), 500, 0xCD);
        // Set JBD2_FEATURE_INCOMPAT_FAST_COMMIT (0x0020) in the jbd2 sb,
        // which lives at device block `base`, not byte 0.
        let bs = ext.block_size() as usize;
        let sb_off =
            crate::journal::source::external_journal_base_block(ext.block_size()) as usize * bs;
        let fc_bit = 0x0000_0020u32;
        journal_buf[sb_off + 0x28..sb_off + 0x2C].copy_from_slice(&fc_bit.to_be_bytes());
        let mut journal = std::io::Cursor::new(journal_buf);

        let err = JournalReplay::build_with_external_journal(&ext, &mut fs, &mut journal)
            .expect_err("external journal + fast-commit must be rejected");
        assert!(matches!(
            err,
            crate::error::ExtError::ExternalJournalFastCommitUnsupported
        ));
    }
}
