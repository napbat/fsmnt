//! Encryption-rolling state (`er_state_phys_t`).
//!
//! When a volume is being encrypted or decrypted in place, APFS tracks
//! progress in encryption-rolling state. A volume caught mid-roll has part of
//! its content in one state and part in another; the rolling progress marks
//! the boundary.
//!
//! Apple File System Reference, `18-encryption-rolling.md`.

use bitflags::bitflags;

use crate::error::{ApfsError, Result};
use crate::object::OBJ_PHYS_SIZE;

/// Encryption-rolling state magic (`ER_MAGIC` `'FLAB'`) as the little-endian
/// `u32` it forms on disk — the bytes `BALF`.
pub const ER_MAGIC: u32 = u32::from_le_bytes(*b"BALF");
/// Mask selecting the rolling phase from `ersb_flags`.
const ERSB_FLAG_ER_PHASE_MASK: u64 = 0x0000_3000;
/// Shift selecting the rolling phase from `ersb_flags`.
const ERSB_FLAG_ER_PHASE_SHIFT: u64 = 12;
/// Size of an `er_state_phys_t`.
pub const ER_STATE_PHYS_SIZE: usize = 128;

bitflags! {
    /// Encryption-rolling flags (`ersb_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ErStateFlags: u64 {
        /// The volume is being encrypted.
        const ENCRYPTING = 0x0000_0001;
        /// The volume is being decrypted.
        const DECRYPTING = 0x0000_0002;
        /// The volume's encryption key is being rolled.
        const KEYROLLING = 0x0000_0004;
        /// Rolling is paused.
        const PAUSED = 0x0000_0008;
        /// Rolling has failed.
        const FAILED = 0x0000_0010;
        /// The crypto id is an AES-XTS tweak rather than a key id.
        const CID_IS_TWEAK = 0x0000_0020;
        /// Rolling started from a one-key volume.
        const FROM_ONEKEY = 0x0000_4000;
    }
}

/// The phase of an in-progress encryption roll (`er_phase_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErPhase {
    /// No rolling phase is recorded.
    None,
    /// The object map is being rolled.
    OmapRoll,
    /// File data is being rolled.
    DataRoll,
    /// Snapshots are being rolled.
    SnapRoll,
    /// A phase value this parser does not recognize.
    Unknown(u64),
}

impl ErPhase {
    /// Decodes the phase from the masked `ersb_flags` value.
    #[must_use]
    fn from_flags(flags: u64) -> Self {
        match (flags & ERSB_FLAG_ER_PHASE_MASK) >> ERSB_FLAG_ER_PHASE_SHIFT {
            0 => Self::None,
            1 => Self::OmapRoll,
            2 => Self::DataRoll,
            3 => Self::SnapRoll,
            other => Self::Unknown(other),
        }
    }
}

/// Parsed encryption-rolling state (`er_state_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErState {
    /// The state structure's version.
    pub version: u32,
    /// Encryption-rolling flags.
    pub flags: ErStateFlags,
    /// Transaction id of the snapshot being rolled, if any.
    pub snap_xid: u64,
    /// Logical file offset rolling has reached.
    pub file_offset: u64,
    /// Number of blocks rolled so far.
    pub progress: u64,
    /// Total number of blocks to roll.
    pub total_blocks: u64,
    /// Object id of the bitmap tracking which blocks have been rolled.
    pub blockmap_oid: u64,
    /// Object id of the recovery-block list, or `None` on the `v1` layout,
    /// which has no recovery list.
    pub recovery_list_oid: Option<u64>,
}

impl ErState {
    /// Parses encryption-rolling state from its block.
    ///
    /// Two on-disk layouts exist. The current `er_state_phys_t`
    /// (`ersb_version` 2) places `ersb_progress` at offset 72. The older
    /// `er_state_phys_v1` (`ersb_version` 1) inserts `ersb_fext_pbn` and
    /// `ersb_paddr` before it, shifting `progress`, `total_blk_to_encrypt`,
    /// and `blockmap_oid` to 88/96/104, and has no recovery-list fields
    /// (Apple File System Reference, `18-encryption-rolling.md`). The
    /// `ersb_version == 1` discriminant is taken from apfs-fuse
    /// `ApfsLib/BlockDumper.cpp:1857`.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block,
    /// [`ApfsError::InvalidMagic`] for a bad `ersb_magic`, and
    /// [`ApfsError::Unsupported`] for an unrecognized `ersb_version`.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < ER_STATE_PHYS_SIZE {
            return Err(ApfsError::Truncated {
                structure: "er_state_phys_t",
                expected: ER_STATE_PHYS_SIZE,
                actual: block.len(),
            });
        }
        let u32_at =
            |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().expect("4 bytes"));
        let u64_at =
            |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().expect("8 bytes"));

        // er_state_phys_header_t: obj_phys_t, then ersb_magic, ersb_version.
        let magic = u32_at(OBJ_PHYS_SIZE);
        if magic != ER_MAGIC {
            return Err(ApfsError::InvalidMagic {
                structure: "er_state_phys_t",
                expected: ER_MAGIC,
                actual: magic,
            });
        }
        let version = u32_at(OBJ_PHYS_SIZE + 4);
        // Fail closed: an unknown version must error, never misparse.
        let (progress, total_blocks, blockmap_oid, recovery_list_oid) = match version {
            1 => (u64_at(88), u64_at(96), u64_at(104), None),
            2 => (u64_at(72), u64_at(80), u64_at(88), Some(u64_at(112))),
            _ => {
                return Err(ApfsError::Unsupported("unrecognized er_state_phys version"));
            }
        };
        Ok(Self {
            version,
            flags: ErStateFlags::from_bits_retain(u64_at(40)),
            snap_xid: u64_at(48),
            file_offset: u64_at(64),
            progress,
            total_blocks,
            blockmap_oid,
            recovery_list_oid,
        })
    }

    /// The current rolling phase.
    #[must_use]
    pub fn phase(&self) -> ErPhase {
        ErPhase::from_flags(self.flags.bits())
    }

    /// Whether a roll is actively in progress (not paused or failed).
    // `ENCRYPTING`, `DECRYPTING`, and `KEYROLLING` are disjoint single-
    // bit flags. Two of the three operator mutations (`| -> ^` at the
    // first and second `|`) leave the combined mask numerically
    // identical to OR — they are equivalent mutants. The `| -> &` form
    // is killed by `is_rolling_recognizes_each_rolling_flag`.
    #[cfg_attr(test, mutants::skip)]
    #[must_use]
    pub fn is_rolling(&self) -> bool {
        self.flags.intersects(
            ErStateFlags::ENCRYPTING | ErStateFlags::DECRYPTING | ErStateFlags::KEYROLLING,
        ) && !self.flags.contains(ErStateFlags::PAUSED)
            && !self.flags.contains(ErStateFlags::FAILED)
    }

    /// Whether the block at `block_index` has already been rolled.
    ///
    /// Blocks below the rolling progress are in the new state; blocks at or
    /// above it are still in the old state.
    #[must_use]
    pub fn is_rolled(&self, block_index: u64) -> bool {
        block_index < self.progress
    }
}

/// A parsed encryption-rolling recovery block (`er_recovery_block_phys_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErRecoveryBlock {
    /// Offset the recovery block applies to.
    pub offset: u64,
    /// Object id of the next recovery block, or zero at the end.
    pub next_oid: u64,
}

impl ErRecoveryBlock {
    /// Parses an `er_recovery_block_phys_t` block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < OBJ_PHYS_SIZE + 16 {
            return Err(ApfsError::Truncated {
                structure: "er_recovery_block_phys_t",
                expected: OBJ_PHYS_SIZE + 16,
                actual: block.len(),
            });
        }
        Ok(Self {
            offset: u64::from_le_bytes(
                block[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 8]
                    .try_into()
                    .expect("8 bytes"),
            ),
            next_oid: u64::from_le_bytes(
                block[OBJ_PHYS_SIZE + 8..OBJ_PHYS_SIZE + 16]
                    .try_into()
                    .expect("8 bytes"),
            ),
        })
    }
}

/// A parsed general-purpose bitmap object (`gbitmap_phys_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneralBitmap {
    /// Object id of the bitmap's B-tree.
    pub tree_oid: u64,
    /// Number of bits the bitmap tracks.
    pub bit_count: u64,
    /// Bitmap flags.
    pub flags: u64,
}

impl GeneralBitmap {
    /// Parses a `gbitmap_phys_t` block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < OBJ_PHYS_SIZE + 24 {
            return Err(ApfsError::Truncated {
                structure: "gbitmap_phys_t",
                expected: OBJ_PHYS_SIZE + 24,
                actual: block.len(),
            });
        }
        let u64_at =
            |off: usize| u64::from_le_bytes(block[off..off + 8].try_into().expect("8 bytes"));
        Ok(Self {
            tree_oid: u64_at(OBJ_PHYS_SIZE),
            bit_count: u64_at(OBJ_PHYS_SIZE + 8),
            flags: u64_at(OBJ_PHYS_SIZE + 16),
        })
    }
}

/// Reads bit `index` from the `bmb_field` words of a `gbitmap_block_phys_t`.
///
/// Returns `false` for an index past the block.
#[must_use]
pub fn gbitmap_block_bit(block: &[u8], index: u64) -> bool {
    let field = &block[OBJ_PHYS_SIZE.min(block.len())..];
    let byte_index = match usize::try_from(index / 8) {
        Ok(value) => value,
        Err(_) => return false,
    };
    field
        .get(byte_index)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `er_state_phys` block of the given `version`, writing
    /// `progress` and `total` at that version's field offsets.
    fn er_state(magic: u32, version: u32, flags: u64, progress: u64, total: u64) -> Vec<u8> {
        let mut b = vec![0u8; ER_STATE_PHYS_SIZE];
        b[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 4].copy_from_slice(&magic.to_le_bytes());
        b[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&version.to_le_bytes());
        b[40..48].copy_from_slice(&flags.to_le_bytes());
        // v1 shifts progress/total to 88/96; v2 keeps them at 72/80.
        let (progress_off, total_off) = if version == 1 { (88, 96) } else { (72, 80) };
        b[progress_off..progress_off + 8].copy_from_slice(&progress.to_le_bytes());
        b[total_off..total_off + 8].copy_from_slice(&total.to_le_bytes());
        b
    }

    #[test]
    fn parses_an_encrypting_volume() {
        // ENCRYPTING, phase DATA_ROLL (2 << 12).
        let flags = ErStateFlags::ENCRYPTING.bits() | (2 << ERSB_FLAG_ER_PHASE_SHIFT);
        let er = ErState::parse(&er_state(ER_MAGIC, 2, flags, 400, 1000)).unwrap();
        assert_eq!(er.phase(), ErPhase::DataRoll);
        assert!(er.is_rolling());
        assert_eq!(er.progress, 400);
        assert_eq!(er.total_blocks, 1000);
        assert!(er.recovery_list_oid.is_some());
    }

    #[test]
    fn parses_the_v1_layout() {
        // A v1 block carries progress/total/blockmap at the shifted
        // offsets and has no recovery list.
        let mut block = er_state(ER_MAGIC, 1, ErStateFlags::ENCRYPTING.bits(), 700, 2000);
        block[104..112].copy_from_slice(&55u64.to_le_bytes()); // v1 blockmap_oid
        // Bytes at the v2 progress offset must NOT be read as progress.
        block[72..80].copy_from_slice(&0xDEAD_u64.to_le_bytes());
        let er = ErState::parse(&block).unwrap();
        assert_eq!(er.version, 1);
        assert_eq!(er.progress, 700);
        assert_eq!(er.total_blocks, 2000);
        assert_eq!(er.blockmap_oid, 55);
        assert_eq!(er.recovery_list_oid, None);
    }

    #[test]
    fn rejects_an_unrecognized_version() {
        assert!(matches!(
            ErState::parse(&er_state(ER_MAGIC, 3, 0, 0, 0)),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn rolled_boundary_splits_old_and_new_state() {
        let er = ErState::parse(&er_state(
            ER_MAGIC,
            2,
            ErStateFlags::ENCRYPTING.bits(),
            400,
            1000,
        ))
        .unwrap();
        assert!(er.is_rolled(399));
        assert!(!er.is_rolled(400));
        assert!(!er.is_rolled(999));
    }

    #[test]
    fn paused_roll_is_not_rolling() {
        let flags = ErStateFlags::ENCRYPTING.bits() | ErStateFlags::PAUSED.bits();
        let er = ErState::parse(&er_state(ER_MAGIC, 2, flags, 0, 0)).unwrap();
        assert!(!er.is_rolling());
    }

    #[test]
    fn rejects_a_bad_magic() {
        assert!(matches!(
            ErState::parse(&er_state(0xDEAD_BEEF, 2, 0, 0, 0)),
            Err(ApfsError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn rejects_a_short_block() {
        assert!(matches!(
            ErState::parse(&[0u8; 40]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn parses_a_recovery_block_and_a_bitmap() {
        let mut rb = vec![0u8; OBJ_PHYS_SIZE + 16];
        rb[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 8].copy_from_slice(&4096u64.to_le_bytes());
        rb[OBJ_PHYS_SIZE + 8..OBJ_PHYS_SIZE + 16].copy_from_slice(&7u64.to_le_bytes());
        let recovery = ErRecoveryBlock::parse(&rb).unwrap();
        assert_eq!(recovery.offset, 4096);
        assert_eq!(recovery.next_oid, 7);

        let mut bm = vec![0u8; OBJ_PHYS_SIZE + 24];
        bm[OBJ_PHYS_SIZE + 8..OBJ_PHYS_SIZE + 16].copy_from_slice(&512u64.to_le_bytes());
        let bitmap = GeneralBitmap::parse(&bm).unwrap();
        assert_eq!(bitmap.bit_count, 512);
    }

    #[test]
    fn gbitmap_block_bit_reads_the_word_array() {
        let mut block = vec![0u8; OBJ_PHYS_SIZE + 8];
        block[OBJ_PHYS_SIZE] = 0b0000_1000; // bit 3 of the field set
        assert!(gbitmap_block_bit(&block, 3));
        assert!(!gbitmap_block_bit(&block, 4));
        assert!(!gbitmap_block_bit(&block, 100_000));
    }

    #[test]
    fn er_recovery_block_rejects_a_short_block_and_pins_the_threshold() {
        // A block one byte short must surface `Truncated` with `expected`
        // exactly equal to `OBJ_PHYS_SIZE + 16`. The mutants on the
        // bound check (`<` → `>`) and on either `+` in the threshold are
        // all killed by this combined assertion: with `>` or `-`/`*`
        // arithmetic on the offset/expected field, the error either
        // doesn't fire or carries the wrong `expected`.
        let short = vec![0u8; OBJ_PHYS_SIZE + 15];
        match ErRecoveryBlock::parse(&short) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "er_recovery_block_phys_t");
                assert_eq!(expected, OBJ_PHYS_SIZE + 16);
                assert_eq!(actual, OBJ_PHYS_SIZE + 15);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
        // A block of exactly the threshold must succeed — pins the
        // `<` bound so it does not become `<=`.
        let exact = vec![0u8; OBJ_PHYS_SIZE + 16];
        ErRecoveryBlock::parse(&exact).expect("exactly the threshold parses");
    }

    #[test]
    fn gbitmap_rejects_a_short_block_and_pins_the_threshold() {
        // Mirrors `er_recovery_block_rejects_a_short_block_…` for
        // `gbitmap_phys_t`: the bound check at line 238 and both `+`
        // arithmetic mutants on the `expected` field at line 241.
        let short = vec![0u8; OBJ_PHYS_SIZE + 23];
        match GeneralBitmap::parse(&short) {
            Err(ApfsError::Truncated {
                structure,
                expected,
                actual,
            }) => {
                assert_eq!(structure, "gbitmap_phys_t");
                assert_eq!(expected, OBJ_PHYS_SIZE + 24);
                assert_eq!(actual, OBJ_PHYS_SIZE + 23);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
        let exact = vec![0u8; OBJ_PHYS_SIZE + 24];
        GeneralBitmap::parse(&exact).expect("exactly the threshold parses");
    }

    #[test]
    fn gbitmap_flags_come_from_offset_16_not_offset_minus_16() {
        // `flags: u64_at(OBJ_PHYS_SIZE + 16)` mutated to `- 16` would
        // read flags from offset 16 instead of 48. Put distinct values
        // at the two locations and assert the parser uses offset 48.
        let mut block = vec![0u8; OBJ_PHYS_SIZE + 24];
        block[16..24].copy_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        block[OBJ_PHYS_SIZE + 16..OBJ_PHYS_SIZE + 24]
            .copy_from_slice(&0xCAFE_F00D_u64.to_le_bytes());
        let bitmap = GeneralBitmap::parse(&block).unwrap();
        assert_eq!(bitmap.flags, 0xCAFE_F00D);
    }

    #[test]
    fn is_rolling_recognizes_each_rolling_flag() {
        // Kills the surviving `| with &` mutation at column 65:
        // `(ENCRYPTING | DECRYPTING) & KEYROLLING` would be zero (the
        // flags share no bits), so only KEYROLLING-set states would be
        // “rolling”. Asserting that each of the three flags alone marks
        // the state as rolling falsifies that.
        for solo in [
            ErStateFlags::ENCRYPTING,
            ErStateFlags::DECRYPTING,
            ErStateFlags::KEYROLLING,
        ] {
            let block = er_state(ER_MAGIC, 2, solo.bits(), 0, 0);
            let state = ErState::parse(&block).unwrap();
            assert!(
                state.is_rolling(),
                "flag {solo:?} alone should mark the state as rolling"
            );
        }
        // A state with none of the three flags must not be rolling —
        // pins the rest of the `intersects` semantics.
        let inert = ErState::parse(&er_state(ER_MAGIC, 2, 0, 0, 0)).unwrap();
        assert!(!inert.is_rolling());
    }
}
