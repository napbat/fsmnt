//! LZX WIM compression.
//!
//! Compresses a single LZX WIM chunk (≤ 32768 bytes). LZX WIM chunks
//! are externally framed (by WOF/WIM container); multi-chunk input is
//! the caller's responsibility.

use alloc::vec;
use alloc::vec::Vec;

use crate::bitstream::BitWriter;
use crate::e8::apply_e8_preprocessing;
use crate::huffman::{assign_canonical_codes, build_code_lengths, count_per_length};
use crate::lz77::{MatchFinder, Token};
use crate::{Error, Result};

use super::{
    BLOCK_VERBATIM, E8_FILE_SIZE, FOOTER_BITS, LEN_HEADER_COUNT, LENGTH_TREE_SIZE, LONG_RUN_BASE,
    LONG_RUN_BITS, MAIN_TREE_SIZE, MIN_MATCH_LEN, NUM_CODE_LENGTHS, OFFSET_ADJUSTMENT,
    POSITION_BASE, PRE_TREE_CODE_BITS, PRE_TREE_SIZE, PRETREE_ZERO_LONG, PRETREE_ZERO_SHORT,
    SHORT_RUN_BASE, SHORT_RUN_BITS, WINDOW_SIZE,
};

/// Maximum representable match length in LZX encoding.
/// length_header(7) + max_length_symbol(248) + MIN_MATCH_LEN(2) = 257.
const MAX_MATCH_LEN: usize = 7 + LENGTH_TREE_SIZE - 1 + MIN_MATCH_LEN;

/// Worst-case compressed size for LZX WIM.
pub fn compress_bound(input_len: usize) -> usize {
    // Single chunk ≤ 32 KB. Tree headers + bitstream overhead.
    input_len + 300
}

/// Reusable LZX WIM compressor.
///
/// Holds the `MatchFinder` and working buffers so they can be
/// allocated once and reused across multiple `compress()` calls.
pub struct Compressor {
    finder: MatchFinder,
    preprocessed: Vec<u8>,
    main_freqs: Vec<u32>,
    len_freqs: Vec<u32>,
}

impl Compressor {
    /// Create a new compressor with pre-allocated buffers.
    pub fn new() -> Self {
        Self {
            finder: MatchFinder::standard(WINDOW_SIZE as u32, MAX_MATCH_LEN as u32, 128),
            preprocessed: Vec::with_capacity(WINDOW_SIZE),
            main_freqs: vec![0u32; MAIN_TREE_SIZE],
            len_freqs: vec![0u32; LENGTH_TREE_SIZE],
        }
    }

    /// Compress `input` using LZX WIM.
    ///
    /// Input MUST be ≤ 32768 bytes. Returns the number of bytes
    /// written to `output`.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        if input.len() > WINDOW_SIZE {
            return Err(Error::InvalidData {
                offset: 0,
                reason: alloc::format!(
                    "LZX WIM chunk size {} exceeds maximum {WINDOW_SIZE}",
                    input.len()
                ),
            });
        }

        // E8 preprocessing: reuse buffer.
        self.preprocessed.clear();
        self.preprocessed.extend_from_slice(input);
        apply_e8_preprocessing(&mut self.preprocessed, E8_FILE_SIZE, 0);

        // LZ77 tokenize. Reset the match finder so stale hash
        // chains from the previous call are not followed.
        self.finder.reset();
        let tokens = self.finder.tokenize(&self.preprocessed);

        // Reuse freq buffers.
        self.main_freqs.fill(0);
        self.len_freqs.fill(0);
        let symbols = tokens_to_symbols(&tokens, &mut self.main_freqs, &mut self.len_freqs);

        // Build Huffman code lengths.
        let main_lens = build_code_lengths(&self.main_freqs, 16)?;

        // Ensure the length tree has at least one valid symbol,
        // even when no matches use the length extension. The
        // decompressor always reads the length tree for verbatim
        // blocks.
        if self.len_freqs.iter().all(|f| *f == 0) {
            self.len_freqs[0] = 1;
        }
        let len_lens = build_code_lengths(&self.len_freqs, 16)?;

        // Ensure at least one symbol in each tree used by the block.
        if main_lens.iter().all(|l| *l == 0) {
            return Err(Error::InvalidData {
                offset: 0,
                reason: "LZX block produced no main tree symbols".into(),
            });
        }

        encode_block(
            input.len(),
            &self.preprocessed,
            &symbols,
            &main_lens,
            &len_lens,
            output,
        )
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compress `input` using LZX WIM.
///
/// Convenience wrapper that allocates a fresh `Compressor` per call.
/// For repeated compression, construct a [`Compressor`] and reuse it.
///
/// Input MUST be ≤ 32768 bytes. Returns the number of bytes written
/// to `output`.
pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    Compressor::new().compress(input, output)
}

/// Encode a single verbatim block into `output`.
fn encode_block(
    input_len: usize,
    preprocessed: &[u8],
    symbols: &[SymbolEntry],
    main_lens: &[u8],
    len_lens: &[u8],
    output: &mut [u8],
) -> Result<usize> {
    let mut writer = BitWriter::with_capacity(input_len);

    // Block header: type (3 bits) + size.
    writer.write_bits(BLOCK_VERBATIM, 3);
    write_block_size(&mut writer, preprocessed.len() as u32);

    // Write main tree via pre-tree (two halves).
    let prev_main = [0u8; MAIN_TREE_SIZE];
    write_pretree_encoded(&mut writer, &main_lens[..256], &prev_main[..256])?;
    write_pretree_encoded(
        &mut writer,
        &main_lens[256..MAIN_TREE_SIZE],
        &prev_main[256..MAIN_TREE_SIZE],
    )?;

    // Write length tree via pre-tree.
    let prev_len = [0u8; LENGTH_TREE_SIZE];
    write_pretree_encoded(&mut writer, len_lens, &prev_len)?;

    // Assign canonical codes.
    let main_counts = count_per_length(main_lens);
    let main_codes = assign_canonical_codes(main_lens, &main_counts);
    let len_counts = count_per_length(len_lens);
    let len_codes = assign_canonical_codes(len_lens, &len_counts);

    // Encode symbols.
    for sym_entry in symbols {
        let (code, code_len) = main_codes[sym_entry.main_symbol as usize];
        writer.write_bits(code, u32::from(code_len));

        // Length tree symbol (if any).
        if let Some(len_sym) = sym_entry.length_symbol {
            let (lc, ll) = len_codes[len_sym as usize];
            writer.write_bits(lc, u32::from(ll));
        }

        // Footer bits for explicit offsets.
        if sym_entry.footer_bits_count > 0 {
            writer.write_bits(sym_entry.footer_bits_value, sym_entry.footer_bits_count);
        }
    }

    let mut bitstream = writer.finish();
    // Trailing padding so the BitReader can always refill for the
    // last symbol's ensure_bits call.
    bitstream.extend_from_slice(&[0, 0, 0, 0]);
    if bitstream.len() > output.len() {
        return Err(Error::OutputTooSmall {
            expected: bitstream.len(),
            actual: output.len(),
        });
    }
    output[..bitstream.len()].copy_from_slice(&bitstream);
    Ok(bitstream.len())
}

/// Write block size: 1 if default (32768), else 0 + 16-bit size.
fn write_block_size(writer: &mut BitWriter, size: u32) {
    if size == WINDOW_SIZE as u32 {
        writer.write_bits(1, 1);
    } else {
        writer.write_bits(0, 1);
        writer.write_bits(size, 16);
    }
}

/// Find the position slot for a given match offset.
fn position_slot_for_offset(offset: usize) -> usize {
    let adjusted = offset as u32 + OFFSET_ADJUSTMENT;
    // Binary search in POSITION_BASE.
    let mut slot = 0;
    for (i, &base) in POSITION_BASE.iter().enumerate() {
        if base <= adjusted {
            slot = i;
        } else {
            break;
        }
    }
    slot
}

/// A symbol entry for the LZX bitstream.
struct SymbolEntry {
    main_symbol: u16,
    length_symbol: Option<u16>,
    footer_bits_value: u32,
    footer_bits_count: u32,
}

/// Convert LZ77 tokens to LZX symbols.
fn tokens_to_symbols(
    tokens: &[Token],
    main_freqs: &mut [u32],
    len_freqs: &mut [u32],
) -> Vec<SymbolEntry> {
    let mut entries = Vec::with_capacity(tokens.len());
    let mut r0: u32 = 1;
    let mut r1: u32 = 1;
    let mut r2: u32 = 1;

    for token in tokens {
        match token {
            Token::Literal(b) => {
                let sym = *b as u16;
                main_freqs[sym as usize] += 1;
                entries.push(SymbolEntry {
                    main_symbol: sym,
                    length_symbol: None,
                    footer_bits_value: 0,
                    footer_bits_count: 0,
                });
            }
            Token::Match(m) => {
                let offset = m.offset as usize;
                let length = m.length as usize;

                // Determine position slot and repeat offset handling.
                let (position_slot, footer_val, footer_count) = if offset as u32 == r0 {
                    (0, 0, 0)
                } else if offset as u32 == r1 {
                    core::mem::swap(&mut r0, &mut r1);
                    (1, 0, 0)
                } else if offset as u32 == r2 {
                    core::mem::swap(&mut r0, &mut r2);
                    (2, 0, 0)
                } else {
                    let slot = position_slot_for_offset(offset);
                    let adjusted = offset as u32 + OFFSET_ADJUSTMENT;
                    let base = POSITION_BASE[slot];
                    let extra_bits = u32::from(FOOTER_BITS[slot]);
                    let extra_val = adjusted - base;
                    r2 = r1;
                    r1 = r0;
                    r0 = offset as u32;
                    (slot, extra_val, extra_bits)
                };

                // Encode length: length_header = min(length - 2, 7).
                let base_len = length - MIN_MATCH_LEN;
                let (length_header, length_symbol) = if base_len < 7 {
                    (base_len, None)
                } else {
                    let extra = base_len - 7;
                    debug_assert!(
                        extra < LENGTH_TREE_SIZE,
                        "match length {length} exceeds LZX maximum \
                         {MAX_MATCH_LEN}; max_match_len config is wrong"
                    );
                    (7, Some(extra as u16))
                };

                let main_sym = 256 + position_slot * LEN_HEADER_COUNT + length_header;
                main_freqs[main_sym] += 1;
                if let Some(ls) = length_symbol {
                    len_freqs[ls as usize] += 1;
                }

                entries.push(SymbolEntry {
                    main_symbol: main_sym as u16,
                    length_symbol,
                    footer_bits_value: footer_val,
                    footer_bits_count: footer_count,
                });
            }
        }
    }

    entries
}

/// Maximum run encodable by short zero-run symbol (17).
const SHORT_RUN_MAX: usize = SHORT_RUN_BASE + (1 << SHORT_RUN_BITS) - 1;

/// Maximum run encodable by long zero-run symbol (18).
const LONG_RUN_MAX: usize = LONG_RUN_BASE + (1 << LONG_RUN_BITS) - 1;

/// Delta-encode code lengths and write via pre-tree.
fn write_pretree_encoded(writer: &mut BitWriter, target: &[u8], previous: &[u8]) -> Result<()> {
    // Compute delta symbols.
    let mut delta_syms: Vec<u8> = Vec::with_capacity(target.len());
    let mut i = 0;
    while i < target.len() {
        let old = if i < previous.len() { previous[i] } else { 0 };
        let new_val = target[i];

        if new_val == 0 {
            // Count run of zeros.
            let mut run = 0;
            while i + run < target.len() && target[i + run] == 0 {
                let old_v = if i + run < previous.len() {
                    previous[i + run]
                } else {
                    0
                };
                if old_v == 0 {
                    run += 1;
                } else {
                    break;
                }
            }

            if run >= LONG_RUN_BASE {
                let emit_run = run.min(LONG_RUN_MAX);
                delta_syms.push(PRETREE_ZERO_LONG);
                delta_syms.push((emit_run - LONG_RUN_BASE) as u8);
                i += emit_run;
            } else if run >= SHORT_RUN_BASE {
                let emit_run = run.min(SHORT_RUN_MAX);
                delta_syms.push(PRETREE_ZERO_SHORT);
                delta_syms.push((emit_run - SHORT_RUN_BASE) as u8);
                i += emit_run;
            } else {
                let delta =
                    ((old as u32 + NUM_CODE_LENGTHS - new_val as u32) % NUM_CODE_LENGTHS) as u8;
                delta_syms.push(delta);
                i += 1;
            }
        } else {
            let delta = ((old as u32 + NUM_CODE_LENGTHS - new_val as u32) % NUM_CODE_LENGTHS) as u8;
            delta_syms.push(delta);
            i += 1;
        }
    }

    // Count frequencies of pre-tree symbols (0-19).
    // Skip extra-value bytes that follow zero-run symbols.
    let mut pre_freqs = [0u32; PRE_TREE_SIZE];
    let mut k = 0;
    while k < delta_syms.len() {
        let sym = delta_syms[k];
        if sym < PRE_TREE_SIZE as u8 {
            pre_freqs[sym as usize] += 1;
        }
        if sym == PRETREE_ZERO_SHORT || sym == PRETREE_ZERO_LONG {
            k += 2; // skip the extra-value byte
        } else {
            k += 1;
        }
    }

    // Build pre-tree code lengths.
    let pre_lens = build_code_lengths(&pre_freqs, 6)?;

    // Write 20 x 4-bit pre-tree code lengths.
    for &pl in pre_lens.iter().take(PRE_TREE_SIZE) {
        writer.write_bits(u32::from(pl), PRE_TREE_CODE_BITS);
    }

    // Assign canonical codes for pre-tree.
    let pre_counts = count_per_length(&pre_lens);
    let pre_codes = assign_canonical_codes(&pre_lens, &pre_counts);

    // Encode delta symbols using pre-tree codes.
    let mut j = 0;
    while j < delta_syms.len() {
        let sym = delta_syms[j];
        if sym < PRETREE_ZERO_SHORT {
            let (code, code_len) = pre_codes[sym as usize];
            writer.write_bits(code, u32::from(code_len));
            j += 1;
        } else if sym == PRETREE_ZERO_SHORT {
            let (code, code_len) = pre_codes[PRETREE_ZERO_SHORT as usize];
            writer.write_bits(code, u32::from(code_len));
            let extra = delta_syms[j + 1];
            writer.write_bits(u32::from(extra), SHORT_RUN_BITS);
            j += 2;
        } else if sym == PRETREE_ZERO_LONG {
            let (code, code_len) = pre_codes[PRETREE_ZERO_LONG as usize];
            writer.write_bits(code, u32::from(code_len));
            let extra = delta_syms[j + 1];
            writer.write_bits(u32::from(extra), LONG_RUN_BITS);
            j += 2;
        } else {
            j += 1;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::lzx::decompress;

    #[test]
    fn compress_empty() {
        let mut output = [0u8; 512];
        let n = compress(&[], &mut output).expect("compress empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn compress_too_large() {
        let input = vec![0u8; 40000];
        let mut output = vec![0u8; 50000];
        let result = compress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn compress_roundtrip_literals() {
        let input: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed)
            .unwrap_or_else(|e| panic!("decompress failed (c_len={c_len}): {e}"));
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_match() {
        crate::assert_roundtrip_match(compress, decompress, compress_bound);
    }

    #[test]
    fn compress_roundtrip_full_chunk() {
        let mut input = vec![0u8; WINDOW_SIZE];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let patch: Vec<u8> = input[1000..2000].to_vec();
        input[20000..21000].copy_from_slice(&patch);

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed)
            .unwrap_or_else(|e| panic!("decompress failed (c_len={c_len}): {e}"));
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_medium() {
        for size in [200, 500, 1000, 2000, 4000, 8000] {
            let mut input = vec![0u8; size];
            for (i, byte) in input.iter_mut().enumerate() {
                *byte = (i % 251) as u8;
            }
            if size >= 400 {
                let patch: Vec<u8> = input[100..200].to_vec();
                input[size / 2..size / 2 + 100].copy_from_slice(&patch);
            }

            let bound = compress_bound(input.len());
            let mut compressed = vec![0u8; bound];
            let c_len = compress(&input, &mut compressed).expect("compress");

            let mut decompressed = vec![0u8; input.len()];
            let d_len = decompress(&compressed[..c_len], &mut decompressed)
                .unwrap_or_else(|e| panic!("decompress failed (size={size}, c_len={c_len}): {e}"));
            assert_eq!(d_len, input.len(), "size={size}");
            assert_eq!(decompressed, input, "size={size}");
        }
    }

    #[test]
    fn compress_roundtrip_all_zeros() {
        // All-zero input: tests long match splitting.
        for size in [100, 300, 500, 1000, 5000, 32768] {
            let input = vec![0u8; size];

            let bound = compress_bound(input.len());
            let mut compressed = vec![0u8; bound];
            let c_len = compress(&input, &mut compressed).expect("compress");

            let mut decompressed = vec![0u8; input.len()];
            let d_len = decompress(&compressed[..c_len], &mut decompressed)
                .unwrap_or_else(|e| panic!("decompress failed (size={size}, c_len={c_len}): {e}"));
            assert_eq!(d_len, input.len(), "size={size}");
            assert_eq!(decompressed, input, "size={size}");
        }
    }

    #[test]
    fn compress_output_too_small() {
        let input = vec![b'A'; 100];
        let mut output = [0u8; 4];
        let result = compress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn position_slot_lookup() {
        // Offset 0 → adjusted 2 → slot 2 (POSITION_BASE[2]=2)
        assert_eq!(position_slot_for_offset(0), 2);
        // Offset 1 → adjusted 3 → slot 3
        assert_eq!(position_slot_for_offset(1), 3);
        // Offset 2 → adjusted 4 → slot 4
        assert_eq!(position_slot_for_offset(2), 4);
        // Large offset
        assert_eq!(position_slot_for_offset(32766), 29);
    }
}
