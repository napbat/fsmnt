#[cfg(feature = "compress-lzx")]
mod compress;
mod decompress;

#[cfg(feature = "compress-lzx")]
pub use compress::{Compressor, compress, compress_bound};
pub use decompress::{decompress, decompress_lenient};

/// LZX WIM window size (32 KB).
pub(super) const WINDOW_SIZE: usize = 32768;

/// Number of position slots for 32 KB window.
pub(super) const NUM_POSITION_SLOTS: usize = 30;

/// Main tree: 256 literals + position_slots * 8 length headers.
pub(super) const MAIN_TREE_SIZE: usize = 256 + NUM_POSITION_SLOTS * 8;

/// Length tree size (249 symbols).
pub(super) const LENGTH_TREE_SIZE: usize = 249;

/// Aligned offset tree size (8 symbols).
pub(super) const ALIGNED_TREE_SIZE: usize = 8;

/// Pre-tree size (20 symbols).
pub(super) const PRE_TREE_SIZE: usize = 20;

/// Pre-tree code lengths are stored in 4 bits.
pub(super) const PRE_TREE_CODE_BITS: u32 = 4;

// -- Pre-tree delta protocol symbols and parameters -------

/// Number of distinct code lengths (0-16), used as the modulus
/// for delta encoding/decoding.
pub(super) const NUM_CODE_LENGTHS: u32 = 17;

/// Pre-tree symbol 17: short run of zeros (4-19).
pub(super) const PRETREE_ZERO_SHORT: u8 = 17;

/// Pre-tree symbol 18: long run of zeros (20-51).
pub(super) const PRETREE_ZERO_LONG: u8 = 18;

/// Pre-tree symbol 19: repeated delta value (4-5 copies).
pub(super) const PRETREE_REPEAT: u8 = 19;

/// Base count for short zero runs (symbol 17) and repeats
/// (symbol 19).
pub(super) const SHORT_RUN_BASE: usize = 4;

/// Extra bits for short zero run length (symbol 17).
pub(super) const SHORT_RUN_BITS: u32 = 4;

/// Base count for long zero runs (symbol 18).
pub(super) const LONG_RUN_BASE: usize = 20;

/// Extra bits for long zero run length (symbol 18).
pub(super) const LONG_RUN_BITS: u32 = 5;

/// Extra bits for repeat count (symbol 19).
pub(super) const REPEAT_BITS: u32 = 1;

/// Aligned offset codes are 3 bits max.
#[allow(dead_code, reason = "used by aligned offset blocks")]
pub(super) const ALIGNED_CODE_BITS: u32 = 3;

/// Magic file size for E8 pre/post-processing.
pub(super) const E8_FILE_SIZE: i32 = 12_000_000;

/// Match offsets are stored as offset + 2 (to distinguish from
/// repeat offset codes 0, 1, 2).
pub(super) const OFFSET_ADJUSTMENT: u32 = 2;

/// Minimum match length in LZX.
pub(super) const MIN_MATCH_LEN: usize = 2;

/// Number of length headers encoded per position slot.
pub(super) const LEN_HEADER_COUNT: usize = 8;

/// Block types signaled in the bitstream.
pub(super) const BLOCK_VERBATIM: u32 = 1;
#[allow(dead_code, reason = "aligned blocks are a future optimization")]
pub(super) const BLOCK_ALIGNED: u32 = 2;
pub(super) const BLOCK_UNCOMPRESSED: u32 = 3;

/// Position slot base offsets (first offset using each slot).
pub(super) const POSITION_BASE: [u32; NUM_POSITION_SLOTS] = {
    let mut table = [0u32; NUM_POSITION_SLOTS];
    let mut i = 1;
    while i < NUM_POSITION_SLOTS {
        table[i] = table[i - 1] + (1 << footer_bits_const(i - 1));
        i += 1;
    }
    table
};

/// Extra (footer) bits per position slot.
pub(super) const FOOTER_BITS: [u8; NUM_POSITION_SLOTS] = {
    let mut table = [0u8; NUM_POSITION_SLOTS];
    let mut i = 0;
    while i < NUM_POSITION_SLOTS {
        table[i] = footer_bits_const(i) as u8;
        i += 1;
    }
    table
};

/// Compute footer bits for a position slot (const-compatible).
pub(super) const fn footer_bits_const(slot: usize) -> u32 {
    if slot < 2 { 0 } else { (slot as u32) / 2 - 1 }
}
