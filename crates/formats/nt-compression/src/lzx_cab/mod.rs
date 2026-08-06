mod decompress;

pub use decompress::{decompress, decompress_lenient};

/// CAB LZX window size, specified in the CAB folder header.
///
/// Must be a power of 2 from 2^15 (32 KB) to 2^21 (2 MB).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowSize {
    /// 32 KiB window.
    KB32 = 15,
    /// 64 KiB window.
    KB64 = 16,
    /// 128 KiB window.
    KB128 = 17,
    /// 256 KiB window.
    KB256 = 18,
    /// 512 KiB window.
    KB512 = 19,
    /// 1 MiB window.
    MB1 = 20,
    /// 2 MiB window.
    MB2 = 21,
}

impl WindowSize {
    /// Window size in bytes.
    #[must_use]
    pub fn bytes(self) -> usize {
        1 << (self as u32)
    }

    /// Number of position slots for this window size.
    #[must_use]
    pub fn position_slots(self) -> usize {
        match self {
            Self::KB32 => 30,
            Self::KB64 => 32,
            Self::KB128 => 34,
            Self::KB256 => 36,
            Self::KB512 => 38,
            Self::MB1 => 42,
            Self::MB2 => 50,
        }
    }

    /// The power-of-two exponent (15..=21).
    #[must_use]
    pub fn bits(self) -> u32 {
        self as u32
    }
}

impl TryFrom<u32> for WindowSize {
    type Error = crate::Error;

    /// Convert a power-of-two exponent (15..=21) into a `WindowSize`.
    fn try_from(bits: u32) -> crate::Result<Self> {
        match bits {
            15 => Ok(Self::KB32),
            16 => Ok(Self::KB64),
            17 => Ok(Self::KB128),
            18 => Ok(Self::KB256),
            19 => Ok(Self::KB512),
            20 => Ok(Self::MB1),
            21 => Ok(Self::MB2),
            _ => Err(crate::Error::InvalidData {
                offset: 0,
                reason: alloc::format!("CAB LZX window size exponent {bits} out of range 15..=21"),
            }),
        }
    }
}

/// Length tree size (249 symbols) — same as all LZX variants.
const LENGTH_TREE_SIZE: usize = 249;

/// Aligned offset tree size (8 symbols).
const ALIGNED_TREE_SIZE: usize = 8;

/// Pre-tree size (20 symbols).
const PRE_TREE_SIZE: usize = 20;

/// Pre-tree code lengths are stored in 4 bits.
const PRE_TREE_CODE_BITS: u32 = 4;

/// Number of distinct code lengths (0-16), used as the modulus for
/// delta encoding/decoding.
const NUM_CODE_LENGTHS: u32 = 17;

/// Pre-tree symbol 17: short run of zeros (4-19).
const PRETREE_ZERO_SHORT: u8 = 17;

/// Pre-tree symbol 18: long run of zeros (20-51).
const PRETREE_ZERO_LONG: u8 = 18;

/// Pre-tree symbol 19: repeated delta value (4-5 copies).
const PRETREE_REPEAT: u8 = 19;

/// Base count for short zero runs (symbol 17) and repeats (symbol 19).
const SHORT_RUN_BASE: usize = 4;

/// Extra bits for short zero run length (symbol 17).
const SHORT_RUN_BITS: u32 = 4;

/// Base count for long zero runs (symbol 18).
const LONG_RUN_BASE: usize = 20;

/// Extra bits for long zero run length (symbol 18).
const LONG_RUN_BITS: u32 = 5;

/// Extra bits for repeat count (symbol 19).
const REPEAT_BITS: u32 = 1;

/// Aligned offset codes are 3 bits max.
const ALIGNED_CODE_BITS: u32 = 3;

/// Match offsets are stored as offset + 2.
const OFFSET_ADJUSTMENT: u32 = 2;

/// Minimum match length in LZX.
const MIN_MATCH_LEN: usize = 2;

/// Number of length headers encoded per position slot.
const LEN_HEADER_COUNT: usize = 8;

/// Block types signaled in the bitstream.
const BLOCK_VERBATIM: u32 = 1;
const BLOCK_ALIGNED: u32 = 2;
const BLOCK_UNCOMPRESSED: u32 = 3;

/// E8 post-processing frame size (32 KB).
const E8_FRAME_SIZE: usize = 32768;

/// Maximum number of position slots (2 MB window).
const MAX_POSITION_SLOTS: usize = 50;

/// Compute footer bits for a position slot.
///
/// Slots 0-1: 0 bits. Slots 2-37: `slot / 2 - 1`. Slots 38+: 17.
#[allow(
    clippy::cast_possible_truncation,
    reason = "only slots 2 through 37 reach the cast, so slot / 2 - 1 is at most 17"
)]
const fn footer_bits_for_slot(slot: usize) -> u8 {
    if slot < 2 {
        0
    } else if slot < 38 {
        (slot / 2 - 1) as u8
    } else {
        17
    }
}

/// Position slot tables computed for a given window size.
struct SlotTables {
    base_position: [u32; MAX_POSITION_SLOTS],
    footer_bits: [u8; MAX_POSITION_SLOTS],
    num_slots: usize,
}

impl SlotTables {
    fn new(window: WindowSize) -> Self {
        let num_slots = window.position_slots();
        let mut base_position = [0u32; MAX_POSITION_SLOTS];
        let mut footer_bits = [0u8; MAX_POSITION_SLOTS];

        for (i, fb) in footer_bits[..num_slots].iter_mut().enumerate() {
            *fb = footer_bits_for_slot(i);
        }
        for i in 1..num_slots {
            base_position[i] = base_position[i - 1] + (1u32 << footer_bits_for_slot(i - 1));
        }

        Self {
            base_position,
            footer_bits,
            num_slots,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_size_bytes() {
        assert_eq!(WindowSize::KB32.bytes(), 32_768);
        assert_eq!(WindowSize::KB64.bytes(), 65_536);
        assert_eq!(WindowSize::KB128.bytes(), 131_072);
        assert_eq!(WindowSize::KB256.bytes(), 262_144);
        assert_eq!(WindowSize::KB512.bytes(), 524_288);
        assert_eq!(WindowSize::MB1.bytes(), 1_048_576);
        assert_eq!(WindowSize::MB2.bytes(), 2_097_152);
    }

    #[test]
    fn position_slots_per_window() {
        assert_eq!(WindowSize::KB32.position_slots(), 30);
        assert_eq!(WindowSize::KB64.position_slots(), 32);
        assert_eq!(WindowSize::KB128.position_slots(), 34);
        assert_eq!(WindowSize::KB256.position_slots(), 36);
        assert_eq!(WindowSize::KB512.position_slots(), 38);
        assert_eq!(WindowSize::MB1.position_slots(), 42);
        assert_eq!(WindowSize::MB2.position_slots(), 50);
    }

    #[test]
    fn footer_bits_spec_table() {
        assert_eq!(footer_bits_for_slot(0), 0);
        assert_eq!(footer_bits_for_slot(1), 0);
        assert_eq!(footer_bits_for_slot(2), 0);
        assert_eq!(footer_bits_for_slot(3), 0);
        assert_eq!(footer_bits_for_slot(4), 1);
        assert_eq!(footer_bits_for_slot(5), 1);
        assert_eq!(footer_bits_for_slot(6), 2);
        assert_eq!(footer_bits_for_slot(30), 14);
        assert_eq!(footer_bits_for_slot(36), 17);
        assert_eq!(footer_bits_for_slot(37), 17);
        assert_eq!(footer_bits_for_slot(38), 17);
        assert_eq!(footer_bits_for_slot(49), 17);
    }

    #[test]
    fn slot_tables_32kb() {
        let tables = SlotTables::new(WindowSize::KB32);
        assert_eq!(tables.num_slots, 30);
        assert_eq!(tables.base_position[0], 0);
        assert_eq!(tables.base_position[3], 3);
        assert_eq!(tables.base_position[4], 4);
        assert_eq!(tables.base_position[6], 8);
        let last = tables.num_slots - 1;
        let range_end = tables.base_position[last] + (1u32 << tables.footer_bits[last]) - 1;
        assert!(range_end >= 32_767);
    }

    #[test]
    fn slot_tables_2mb() {
        let tables = SlotTables::new(WindowSize::MB2);
        assert_eq!(tables.num_slots, 50);
        let last = tables.num_slots - 1;
        let range_end = tables.base_position[last] + (1u32 << tables.footer_bits[last]) - 1;
        assert!(range_end >= 2_097_151);
    }

    #[test]
    fn window_size_try_from_valid() {
        for bits in 15u32..=21 {
            let ws = WindowSize::try_from(bits).expect("valid exponent");
            assert_eq!(ws.bits(), bits);
        }
    }

    #[test]
    fn window_size_try_from_invalid() {
        assert!(WindowSize::try_from(14).is_err());
        assert!(WindowSize::try_from(22).is_err());
    }
}
