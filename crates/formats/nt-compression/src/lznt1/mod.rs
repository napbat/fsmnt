#[cfg(feature = "compress-lznt1")]
mod compress;
pub mod decompress;

#[cfg(feature = "compress-lznt1")]
pub use compress::{compress, compress_bound};
pub use decompress::{decompress, decompress_lenient};

/// Maximum decompressed size of a single LZNT1 chunk (4 KB).
pub(super) const CHUNK_SIZE: usize = 4096;

/// Expected signature in bits [14:12] of the chunk header.
pub(super) const CHUNK_SIGNATURE: u16 = 0b011;

/// Compute displacement_bits from the current position within the
/// chunk. Returns `(length_bits, displacement_bits)`.
///
/// At positions 0..=15 the shift is clamped to 12 (4 displacement
/// bits, 12 length bits). As position grows, the shift decreases
/// by 1 for each power-of-two crossed.
pub(super) fn bit_widths(pos_in_chunk: usize) -> (u32, u32) {
    let mut shift: u32 = 12;
    let mut threshold: usize = 0x10; // 16
    while threshold < pos_in_chunk {
        shift -= 1;
        threshold <<= 1;
    }
    // shift = length_bits, 16 - shift = displacement_bits
    (shift, 16 - shift)
}
