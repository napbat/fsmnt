//! `INCOMPAT_FAST_COMMIT` replay engine for ext4 journals.
//!
//! See `docs/superpowers/specs/2026-04-25-fs-ext-fast-commit-design.md`
//! for the design.

use alloc::vec::Vec;

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{Read, Seek};
use crate::journal::replay::BlockOverlay;
use crate::journal::source::{JournalLocator, open_journal_file};
use crate::journal::superblock::JournalSource;
use crate::orphan::Mutator;

pub(crate) mod apply;
pub(crate) mod extents;
pub(crate) mod parse;
mod plan;
pub(crate) mod tlv;

#[cfg(test)]
#[allow(
    unfulfilled_lint_expectations,
    reason = "Task 11 scan tests exercise all current test-support helpers"
)]
pub(crate) mod test_support;

pub use plan::{
    DirectoryReplayReason, ExtentReplayReason, FastCommitPlan, FastCommitPosition, FastCommitStop,
    FastCommitStopReason, FastCommitTagCounts, FastCommitWarning, FastCommitWarningKind,
};

pub(crate) struct FastCommitReplay;

impl FastCommitReplay {
    /// Run pass-A scan, pass-B apply, and pass-C finalization over the journal's
    /// fast-commit region, layering FC mutations on top of classic replay.
    pub(crate) fn build<T: Read + Seek>(
        ext: &Ext,
        fs: &mut T,
        source: &JournalSource,
        locator: &JournalLocator,
        classic_overlay: BlockOverlay,
        expected_tid: u32,
    ) -> Result<(BlockOverlay, FastCommitPlan)> {
        let n = source.effective_num_fc_blocks();
        if n == 0 {
            return Ok((classic_overlay, FastCommitPlan::default()));
        }

        if n >= source.maxlen {
            return Err(ExtError::InvalidJournalSuperblock {
                reason: "s_num_fc_blks exceeds journal s_maxlen",
            });
        }

        let block_size = source.block_size;
        let fc_first = source.maxlen - n + 1;

        let (mut fc_block_bufs, block_size_usize) = reserve_fc_block_storage(n, block_size)?;
        {
            let mut journal_file = open_journal_file(ext, fs, source, locator)?;
            for i in 0..n {
                let mut buf = Vec::new();
                buf.try_reserve_exact(block_size_usize)
                    .map_err(|_| fc_region_too_large())?;
                buf.resize(block_size_usize, 0);
                journal_file.read_block(fs, u64::from(fc_first + i), &mut buf)?;
                fc_block_bufs.push(buf);
            }
        }
        let mut block_refs: Vec<&[u8]> = Vec::new();
        block_refs
            .try_reserve_exact(fc_block_bufs.len())
            .map_err(|_| fc_region_too_large())?;
        for block in &fc_block_bufs {
            block_refs.push(block.as_slice());
        }

        let scan = parse::scan_fc_region(&block_refs, block_size, fc_first, expected_tid);
        let apply_state = apply::apply_pass(
            ext,
            fs,
            classic_overlay,
            &block_refs,
            block_size,
            fc_first,
            &scan,
        )?;
        let mut plan = apply_state.plan;
        let mut composed_overlay = apply_state.composed_overlay;
        let modified_inodes = apply_state.modified_inodes;

        if !modified_inodes.is_empty() {
            let sb_host_bytes = composed_overlay.sb_host_block_content.to_vec();
            let mutator = Mutator::new(ext, &sb_host_bytes);
            let delta = {
                let mut overlay_reader = crate::OverlayReader::new(fs, &composed_overlay);
                let mutator = apply::finalize_pass(
                    ext,
                    &mut overlay_reader,
                    mutator,
                    &modified_inodes,
                    &mut plan,
                )?;
                mutator
                    .finalize(&mut overlay_reader)
                    .map_err(apply::mutator_error_to_ext)?
            };
            apply::merge_delta_into_overlay(&mut composed_overlay, delta);
        }

        Ok((composed_overlay, plan))
    }
}

fn reserve_fc_block_storage(n: u32, block_size: u32) -> Result<(Vec<Vec<u8>>, usize)> {
    let n_usize = usize::try_from(n).map_err(|_| fc_region_too_large())?;
    let block_size_usize = usize::try_from(block_size).map_err(|_| fc_region_too_large())?;
    let total_bytes = n_usize
        .checked_mul(block_size_usize)
        .ok_or_else(fc_region_too_large)?;
    if total_bytes_exceeds_isize_max(total_bytes) {
        return Err(fc_region_too_large());
    }

    let mut fc_block_bufs = Vec::new();
    fc_block_bufs
        .try_reserve_exact(n_usize)
        .map_err(|_| fc_region_too_large())?;
    Ok((fc_block_bufs, block_size_usize))
}

/// Whether a proposed total-bytes allocation exceeds the platform's
/// `isize::MAX`, which is the documented upper bound for `Vec` capacity.
///
/// Extracted so `#[cfg_attr(test, mutants::skip)]` applies only to this
/// boundary check: at `total_bytes == isize::MAX` the host's allocator
/// has already failed any prior `try_reserve_exact`, so `>` vs `>=`
/// only differ by one byte at a boundary that no real input can reach
/// — the `> -> >=` mutant is therefore diagnostic-only. See
/// `crates/fs-ext/docs/mutation-testing.md`.
#[cfg_attr(test, mutants::skip)]
fn total_bytes_exceeds_isize_max(total_bytes: usize) -> bool {
    total_bytes > isize::MAX as usize
}

fn fc_region_too_large() -> ExtError {
    ExtError::InvalidJournalSuperblock {
        reason: "fast-commit region too large",
    }
}

#[cfg(test)]
mod build_tests {
    use alloc::collections::BTreeMap;

    use super::*;
    use crate::journal::features::{
        JournalChecksumMode, JournalIncompatFeatures, JournalSuperblockVersion,
    };
    use crate::journal::replay::BlockOverlay;
    use crate::journal::superblock::JournalSource;

    fn fixture_ext() -> (crate::Ext, std::io::Cursor<Vec<u8>>) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/ext4.img");
        let bytes = std::fs::read(path).expect("read ext4 fixture");
        let mut cursor = std::io::Cursor::new(bytes);
        let ext = crate::Ext::open_lenient(&mut cursor).expect("open ext4 fixture");
        (ext, cursor)
    }

    fn source_with(
        features: JournalIncompatFeatures,
        maxlen: u32,
        num_fc_blocks: u32,
    ) -> JournalSource {
        JournalSource {
            block_size: 4096,
            maxlen,
            first: 1,
            sequence: 1,
            start: 0,
            version: JournalSuperblockVersion::V2,
            features,
            checksum_mode: JournalChecksumMode::None,
            uuid: [0u8; 16],
            num_fc_blocks,
            fc_head: 0,
        }
    }

    fn classic_overlay() -> BlockOverlay {
        BlockOverlay {
            block_size: 4096,
            blocks: BTreeMap::new(),
            sb_host_block: 1,
            sb_host_block_content: alloc::vec![0u8; 4096].into_boxed_slice(),
        }
    }

    #[test]
    fn fc_replay_build_with_no_fc_region_returns_default_plan() {
        let (ext, mut cursor) = fixture_ext();
        let source = source_with(JournalIncompatFeatures::empty(), 8192, 0);

        let (_overlay, plan) = FastCommitReplay::build(
            &ext,
            &mut cursor,
            &source,
            &JournalLocator::Inode,
            classic_overlay(),
            1,
        )
        .expect("build");

        assert_eq!(plan.transactions_replayed, 0);
        assert_eq!(plan.inodes_modified, 0);
        assert!(plan.last_committed_tid.is_none());
        assert_eq!(plan.tag_counts, FastCommitTagCounts::default());
        assert_eq!(plan.allocation_units_marked_free, 0);
        assert_eq!(plan.allocation_units_marked_allocated, 0);
        assert!(plan.stop.is_none());
        assert!(plan.warnings.is_empty());
        assert!(!plan.warnings_truncated);
    }

    #[test]
    fn fc_replay_build_with_empty_fc_region_reads_blocks_and_returns_default_plan() {
        let (ext, mut cursor) = fixture_ext();
        let source = source_with(JournalIncompatFeatures::FAST_COMMIT, 2, 1);

        let (_overlay, plan) = FastCommitReplay::build(
            &ext,
            &mut cursor,
            &source,
            &JournalLocator::Inode,
            classic_overlay(),
            1,
        )
        .expect("build");

        assert_eq!(plan.transactions_replayed, 0);
        assert_eq!(plan.inodes_modified, 0);
        assert!(plan.last_committed_tid.is_none());
        assert_eq!(plan.tag_counts, FastCommitTagCounts::default());
        assert_eq!(plan.allocation_units_marked_free, 0);
        assert_eq!(plan.allocation_units_marked_allocated, 0);
        assert!(plan.stop.is_none());
        assert!(plan.warnings.is_empty());
        assert!(!plan.warnings_truncated);
    }

    #[test]
    fn fc_replay_block_buffer_reservation_rejects_oversized_region() {
        let err = reserve_fc_block_storage(u32::MAX, u32::MAX)
            .expect_err("oversized FC region must be rejected");

        assert!(matches!(
            err,
            crate::error::ExtError::InvalidJournalSuperblock {
                reason: "fast-commit region too large"
            }
        ));
    }

    #[test]
    fn fc_replay_build_rejects_num_fc_blks_exceeding_maxlen() {
        let (ext, mut cursor) = fixture_ext();
        let source = source_with(JournalIncompatFeatures::FAST_COMMIT, 32, 64);

        let err = FastCommitReplay::build(
            &ext,
            &mut cursor,
            &source,
            &JournalLocator::Inode,
            classic_overlay(),
            1,
        )
        .expect_err("malformed FC range must error");

        assert!(matches!(
            err,
            crate::error::ExtError::InvalidJournalSuperblock {
                reason: "s_num_fc_blks exceeds journal s_maxlen"
            }
        ));
    }
}
