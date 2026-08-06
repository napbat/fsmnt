//! The reaper (`nx_reaper_phys_t`) — deferred object deletion.
//!
//! The reaper frees objects too large to delete between two transactions,
//! tracking the deletion across multiple transactions. Reaper state names
//! objects that were mid-deletion — a forensic indicator of recently removed
//! large files or volumes.
//!
//! Apple File System Reference, `17-reaper.md`.

use alloc::vec::Vec;

use bitflags::bitflags;

use crate::error::{ApfsError, Result};
use crate::object::OBJ_PHYS_SIZE;

/// Offset of the `nrl_entries` array within `nx_reap_list_phys_t`.
const NRL_ENTRIES_OFFSET: usize = OBJ_PHYS_SIZE + 8 + 6 * 4;
/// Size of an `nx_reap_list_entry_t`.
const REAP_LIST_ENTRY_SIZE: usize = 40;
/// Size of the `nx_reaper_phys_t` prefix this parser decodes.
const REAPER_PREFIX_SIZE: usize = OBJ_PHYS_SIZE + 0x48;

bitflags! {
    /// Reaper flags (`nr_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReaperFlags: u32 {
        /// The reaper is between hashed-object-map phases.
        const BHM_FLAG = 0x0000_0001;
        /// The reaper has more work and should continue.
        const CONTINUE = 0x0000_0002;
    }
}

bitflags! {
    /// Reap-list entry flags (`nrle_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ReapListEntryFlags: u32 {
        /// The entry is valid.
        const VALID = 0x0000_0001;
        /// The entry is a reap-id record.
        const REAP_ID_RECORD = 0x0000_0002;
        /// The entry needs a reaper callback.
        const CALL = 0x0000_0004;
        /// The entry marks a completion.
        const COMPLETION = 0x0000_0008;
        /// The entry marks a cleanup step.
        const CLEANUP = 0x0000_0010;
    }
}

/// A volume reaper phase (`APFS_REAP_PHASE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReapPhase {
    /// The reaper has not started.
    Start,
    /// The reaper is freeing snapshots.
    Snapshots,
    /// The reaper is freeing the active file system.
    ActiveFs,
    /// The reaper is destroying the object map.
    DestroyOmap,
    /// The reaper has finished.
    Done,
    /// A phase value this parser does not recognize.
    Unknown(u32),
}

impl ReapPhase {
    /// Decodes a reap-phase value.
    #[must_use]
    pub fn from_value(value: u32) -> Self {
        match value {
            0 => Self::Start,
            1 => Self::Snapshots,
            2 => Self::ActiveFs,
            3 => Self::DestroyOmap,
            4 => Self::Done,
            other => Self::Unknown(other),
        }
    }
}

/// A parsed container reaper (`nx_reaper_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaper {
    /// The next reap identifier to assign.
    pub next_reap_id: u64,
    /// The most recently completed reap identifier.
    pub completed_id: u64,
    /// Object id of the first reap list in the chain.
    pub head: u64,
    /// Object id of the last reap list in the chain.
    pub tail: u64,
    /// Reaper flags.
    pub flags: ReaperFlags,
    /// Number of reap lists in the chain.
    pub list_count: u32,
    /// Object id of the object currently being reaped.
    pub current_oid: u64,
    /// Volume object id the current object belongs to.
    pub current_fs_oid: u64,
    /// Transaction id of the current reap.
    pub current_xid: u64,
}

impl Reaper {
    /// Parses a reaper from its (ephemeral) block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < REAPER_PREFIX_SIZE {
            return Err(ApfsError::Truncated {
                structure: "nx_reaper_phys_t",
                expected: REAPER_PREFIX_SIZE,
                actual: block.len(),
            });
        }
        let u64_at =
            |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().expect("8 bytes"));
        let u32_at =
            |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().expect("4 bytes"));
        Ok(Self {
            next_reap_id: u64_at(0x20),
            completed_id: u64_at(0x28),
            head: u64_at(0x30),
            tail: u64_at(0x38),
            flags: ReaperFlags::from_bits_retain(u32_at(0x40)),
            list_count: u32_at(0x44),
            current_fs_oid: u64_at(0x50),
            current_oid: u64_at(0x58),
            current_xid: u64_at(0x60),
        })
    }

    /// Whether the reaper has deletions in progress.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.flags.contains(ReaperFlags::CONTINUE) || self.current_oid != 0
    }
}

/// One entry of a reap list (`nx_reap_list_entry_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReapListEntry {
    /// Index of the next entry in the list, or all-ones for the end.
    pub next: u32,
    /// Entry flags.
    pub flags: ReapListEntryFlags,
    /// The object's type.
    pub obj_type: u32,
    /// The object's size.
    pub size: u32,
    /// Volume object id the object belongs to.
    pub fs_oid: u64,
    /// The object's identifier.
    pub oid: u64,
    /// Transaction id of the reap.
    pub xid: u64,
}

/// A parsed reap list (`nx_reap_list_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReapList {
    /// Object id of the next reap list in the chain (zero at the end).
    pub next: u64,
    /// The list's entries.
    pub entries: Vec<ReapListEntry>,
}

impl ReapList {
    /// Parses a reap-list block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] or [`ApfsError::Malformed`] when the
    /// declared entry count does not fit the block.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < NRL_ENTRIES_OFFSET {
            return Err(ApfsError::Truncated {
                structure: "nx_reap_list_phys_t",
                expected: NRL_ENTRIES_OFFSET,
                actual: block.len(),
            });
        }
        let next = u64::from_le_bytes(
            block[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 8]
                .try_into()
                .expect("8 bytes"),
        );
        // nx_reap_list_phys_t: nrl_next (u64), nrl_flags, nrl_max, then
        // nrl_count. The live entry count is nrl_count at offset +16 — not
        // nrl_max (capacity) at +12.
        let count = u32::from_le_bytes(
            block[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20]
                .try_into()
                .expect("4 bytes"),
        ) as usize;

        let needed = NRL_ENTRIES_OFFSET + count.saturating_mul(REAP_LIST_ENTRY_SIZE);
        if needed > block.len() {
            return Err(ApfsError::Malformed {
                structure: "nx_reap_list_phys_t",
                reason: "reap-list entry count exceeds the block",
            });
        }

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let base = NRL_ENTRIES_OFFSET + i * REAP_LIST_ENTRY_SIZE;
            let u32_at = |off: usize| {
                u32::from_le_bytes(
                    block[base + off..base + off + 4]
                        .try_into()
                        .expect("4 bytes"),
                )
            };
            let u64_at = |off: usize| {
                u64::from_le_bytes(
                    block[base + off..base + off + 8]
                        .try_into()
                        .expect("8 bytes"),
                )
            };
            entries.push(ReapListEntry {
                next: u32_at(0),
                flags: ReapListEntryFlags::from_bits_retain(u32_at(4)),
                obj_type: u32_at(8),
                size: u32_at(12),
                fs_oid: u64_at(16),
                oid: u64_at(24),
                xid: u64_at(32),
            });
        }
        Ok(Self { next, entries })
    }

    /// The valid entries of the list — objects pending reap.
    #[must_use]
    pub fn pending(&self) -> Vec<ReapListEntry> {
        self.entries
            .iter()
            .copied()
            .filter(|entry| entry.flags.contains(ReapListEntryFlags::VALID))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reap_phase_decodes() {
        assert_eq!(ReapPhase::from_value(0), ReapPhase::Start);
        assert_eq!(ReapPhase::from_value(2), ReapPhase::ActiveFs);
        assert_eq!(ReapPhase::from_value(4), ReapPhase::Done);
        assert_eq!(ReapPhase::from_value(9), ReapPhase::Unknown(9));
    }

    #[test]
    fn parses_an_active_reaper() {
        let mut b = vec![0u8; REAPER_PREFIX_SIZE];
        b[0x20..0x28].copy_from_slice(&50u64.to_le_bytes()); // next_reap_id
        b[0x40..0x44].copy_from_slice(&ReaperFlags::CONTINUE.bits().to_le_bytes());
        b[0x44..0x48].copy_from_slice(&3u32.to_le_bytes()); // list_count
        b[0x58..0x60].copy_from_slice(&808u64.to_le_bytes()); // current_oid
        let reaper = Reaper::parse(&b).unwrap();
        assert_eq!(reaper.next_reap_id, 50);
        assert_eq!(reaper.list_count, 3);
        assert_eq!(reaper.current_oid, 808);
        assert!(reaper.is_active());
    }

    #[test]
    fn idle_reaper_is_not_active() {
        let reaper = Reaper::parse(&[0u8; REAPER_PREFIX_SIZE]).unwrap();
        assert!(!reaper.is_active());
    }

    #[test]
    fn reaper_rejects_a_short_block() {
        assert!(matches!(
            Reaper::parse(&[0u8; 16]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn parses_a_reap_list_and_filters_valid_entries() {
        let mut b = vec![0u8; NRL_ENTRIES_OFFSET + 2 * REAP_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 8].copy_from_slice(&0u64.to_le_bytes()); // next
        b[OBJ_PHYS_SIZE + 12..OBJ_PHYS_SIZE + 16].copy_from_slice(&8u32.to_le_bytes()); // nrl_max
        b[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20].copy_from_slice(&2u32.to_le_bytes()); // nrl_count
        // Entry 0: valid, oid 900.
        let e0 = NRL_ENTRIES_OFFSET;
        b[e0 + 4..e0 + 8].copy_from_slice(&ReapListEntryFlags::VALID.bits().to_le_bytes());
        b[e0 + 24..e0 + 32].copy_from_slice(&900u64.to_le_bytes());
        // Entry 1: not valid.
        let list = ReapList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 2);
        let pending = list.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].oid, 900);
    }

    #[test]
    fn reap_list_rejects_an_oversized_count() {
        let mut b = vec![0u8; NRL_ENTRIES_OFFSET + REAP_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20].copy_from_slice(&1000u32.to_le_bytes());
        assert!(matches!(
            ReapList::parse(&b),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn reaper_reports_full_expected_size_on_truncation() {
        // The error must declare the parser's full prefix size — an
        // arithmetic typo on the constant (`*` for `+`) reports a wildly
        // different number and downstream tooling can no longer trust it.
        let err = Reaper::parse(&[0u8; 16]).unwrap_err();
        match err {
            ApfsError::Truncated {
                structure,
                expected,
                actual,
            } => {
                assert_eq!(structure, "nx_reaper_phys_t");
                assert_eq!(expected, REAPER_PREFIX_SIZE);
                assert_eq!(expected, OBJ_PHYS_SIZE + 0x48);
                assert_eq!(actual, 16);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn reaper_is_active_with_only_continue_flag() {
        // `CONTINUE` set, but no current object — the reaper still has work
        // to do. A short-circuit AND would treat this as idle.
        let mut b = vec![0u8; REAPER_PREFIX_SIZE];
        b[0x40..0x44].copy_from_slice(&ReaperFlags::CONTINUE.bits().to_le_bytes());
        let reaper = Reaper::parse(&b).unwrap();
        assert_eq!(reaper.current_oid, 0);
        assert!(reaper.is_active());
    }

    #[test]
    fn reaper_is_active_with_only_current_oid() {
        // No `CONTINUE` flag, but a current object is set — a partial
        // deletion is in progress and the reaper is active.
        let mut b = vec![0u8; REAPER_PREFIX_SIZE];
        b[0x58..0x60].copy_from_slice(&42u64.to_le_bytes()); // current_oid
        let reaper = Reaper::parse(&b).unwrap();
        assert!(!reaper.flags.contains(ReaperFlags::CONTINUE));
        assert_eq!(reaper.current_oid, 42);
        assert!(reaper.is_active());
    }

    #[test]
    fn reap_list_parses_at_the_exact_prefix_boundary() {
        // A block of exactly `NRL_ENTRIES_OFFSET` bytes with zero entries
        // must parse — this pins the truncation check to a strict
        // less-than, ruling out an equality or less-than-or-equal flip.
        let b = vec![0u8; NRL_ENTRIES_OFFSET];
        let list = ReapList::parse(&b).unwrap();
        assert_eq!(list.next, 0);
        assert!(list.entries.is_empty());
    }

    #[test]
    fn reap_list_entries_live_at_documented_offset_64() {
        // The `nrl_entries` array starts 64 bytes into the block
        // (`obj_phys_t` = 32, plus `nrl_next` (8) and six `u32` fields). This
        // test uses literal byte offsets so an arithmetic typo on the
        // offset constant shifts the parser's read away from the bytes the
        // test wrote, instead of moving the test offset in lock step.
        const ENTRY_OFFSET: usize = 64;
        const BLOCK_LEN: usize = 200;
        let mut b = vec![0u8; BLOCK_LEN];
        // `nrl_count` lives at OBJ_PHYS_SIZE + 16 = 48.
        b[48..52].copy_from_slice(&1u32.to_le_bytes());
        // Entry 0's fields, at the documented byte offsets.
        b[ENTRY_OFFSET..ENTRY_OFFSET + 4].copy_from_slice(&5u32.to_le_bytes()); // next
        b[ENTRY_OFFSET + 4..ENTRY_OFFSET + 8]
            .copy_from_slice(&ReapListEntryFlags::VALID.bits().to_le_bytes());
        b[ENTRY_OFFSET + 8..ENTRY_OFFSET + 12].copy_from_slice(&99u32.to_le_bytes()); // obj_type
        b[ENTRY_OFFSET + 12..ENTRY_OFFSET + 16].copy_from_slice(&4096u32.to_le_bytes()); // size
        b[ENTRY_OFFSET + 16..ENTRY_OFFSET + 24].copy_from_slice(&1_111u64.to_le_bytes()); // fs_oid
        b[ENTRY_OFFSET + 24..ENTRY_OFFSET + 32].copy_from_slice(&2_222u64.to_le_bytes()); // oid
        b[ENTRY_OFFSET + 32..ENTRY_OFFSET + 40].copy_from_slice(&3_333u64.to_le_bytes()); // xid

        let list = ReapList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 1);
        let entry = list.entries[0];
        assert_eq!(entry.next, 5);
        assert!(entry.flags.contains(ReapListEntryFlags::VALID));
        assert_eq!(entry.obj_type, 99);
        assert_eq!(entry.size, 4096);
        assert_eq!(entry.fs_oid, 1_111);
        assert_eq!(entry.oid, 2_222);
        assert_eq!(entry.xid, 3_333);
    }

    #[test]
    fn reap_list_parses_entries_at_consecutive_offsets() {
        // Two valid entries with distinct oids — the per-entry base must
        // advance by `REAP_LIST_ENTRY_SIZE` for each step. A `-` for `+` at
        // the base computation would read entry 1 from a non-entry region
        // (or panic on underflow), and a `+` for `*` on the offset constant
        // would read both entries from the same place.
        let mut b = vec![0u8; NRL_ENTRIES_OFFSET + 2 * REAP_LIST_ENTRY_SIZE];
        b[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 20].copy_from_slice(&2u32.to_le_bytes());

        let e0 = NRL_ENTRIES_OFFSET;
        b[e0 + 4..e0 + 8].copy_from_slice(&ReapListEntryFlags::VALID.bits().to_le_bytes());
        b[e0 + 24..e0 + 32].copy_from_slice(&100u64.to_le_bytes()); // entry 0 oid

        let e1 = NRL_ENTRIES_OFFSET + REAP_LIST_ENTRY_SIZE;
        b[e1 + 4..e1 + 8].copy_from_slice(&ReapListEntryFlags::VALID.bits().to_le_bytes());
        b[e1 + 24..e1 + 32].copy_from_slice(&200u64.to_le_bytes()); // entry 1 oid

        let list = ReapList::parse(&b).unwrap();
        assert_eq!(list.entries.len(), 2);
        assert_eq!(list.entries[0].oid, 100);
        assert_eq!(list.entries[1].oid, 200);
        // Both entries must surface from `pending`, in order.
        let pending = list.pending();
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].oid, 100);
        assert_eq!(pending[1].oid, 200);
    }
}
