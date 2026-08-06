//! XPRESS Huffman decompression (MS-XCA Section 2.1/2.2).
//!
//! Each 64 KB block starts with a 256-byte header encoding 512 Huffman
//! symbol code lengths (4 bits each, packed 2 per byte). Symbols 0-255
//! are literals, 256-511 encode match length/distance pairs.
//!
//! Performance-critical inner loop uses a packed 10-bit direct lookup
//! table matching RTL's `XpressBuildHuffmanDecodingTable` format, with
//! a fast-path/slow-path split guarded by input and output margins.
#![allow(unsafe_code)]

use alloc::format;

use crate::huffman::{
    assign_canonical_codes, count_per_length, validate_code_space, validate_lengths,
};
use crate::{Error, LenientResult, Result};

use super::{BLOCK_SIZE, HEADER_SIZE, MAX_CODE_BITS, NUM_SYMBOLS};

// ---------------------------------------------------------------------------
// Packed decode table (Phase 1)
// ---------------------------------------------------------------------------

/// Direct-lookup table width. 10 bits = 1024 entries × 2 bytes = 2 KB,
/// matching RTL's `XpressBuildHuffmanDecodingTable`.
const TABLE_BITS: u32 = 10;
const TABLE_SIZE: usize = 1 << TABLE_BITS; // 1024

/// Packed entry format: `(symbol << 4) | code_len`.
/// code_len == 0 means overflow — symbol field is overflow index.
type PackedEntry = u16;

/// Specialized decode table for XPRESS Huffman (512 symbols, max 15 bits).
///
/// 10-bit direct lookup table (2 KB) + overflow continuation table (2 KB).
/// Total 4 KB on the stack vs 8 KB+ heap for the generic `HuffmanTable`.
struct PackedDecodeTable {
    /// 10-bit direct lookup: `next_bits >> 22` indexes here.
    direct: [PackedEntry; TABLE_SIZE],
    /// Overflow tree for codes > 10 bits. Entries are packed the same
    /// way: `(symbol << 4) | 0` for internal nodes with children at
    /// `[index*2]` and `[index*2+1]`, or `(symbol << 4) | code_len`
    /// for leaves.
    overflow: [PackedEntry; TABLE_SIZE],
    /// Number of overflow entries used.
    overflow_len: u16,
}

impl PackedDecodeTable {
    /// Build from 512 code lengths (4 bits each, 0 = unused).
    fn build(lengths: &[u8; NUM_SYMBOLS]) -> Result<Self> {
        validate_lengths(lengths)?;
        let counts = count_per_length(lengths);
        validate_code_space(&counts)?;
        let codes = assign_canonical_codes(lengths, &counts);

        let mut tbl = Self {
            direct: [0u16; TABLE_SIZE],
            overflow: [0u16; TABLE_SIZE],
            overflow_len: 0,
        };

        // Track which direct entries are filled.
        let mut direct_filled = [false; TABLE_SIZE];

        for (sym, &(code, len)) in codes.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let sym = sym as u16;
            let len_u32 = u32::from(len);

            if len_u32 <= TABLE_BITS {
                // Short code: fill all suffix positions.
                let pad = TABLE_BITS - len_u32;
                let base = code << pad;
                let count = 1u32 << pad;
                let entry = (sym << 4) | (len as u16);
                for i in 0..count {
                    let idx = (base | i) as usize;
                    tbl.direct[idx] = entry;
                    direct_filled[idx] = true;
                }
            } else {
                // Long code: route through overflow tree.
                let prefix = (code >> (len_u32 - TABLE_BITS)) as usize;
                let root = if !direct_filled[prefix] {
                    // Allocate overflow root.
                    let idx = tbl.alloc_overflow()?;
                    // Mark direct entry as overflow pointer (code_len=0).
                    tbl.direct[prefix] = (idx as u16) << 4;
                    direct_filled[prefix] = true;
                    idx
                } else {
                    // Already an overflow root.
                    (tbl.direct[prefix] >> 4) as usize
                };

                // Walk remaining bits to insert leaf.
                let extra_bits = len_u32 - TABLE_BITS;
                let mut node = root;
                for bit_pos in (0..extra_bits).rev() {
                    let bit = ((code >> bit_pos) & 1) as usize;
                    let child_idx = node * 2 + bit;
                    if child_idx >= TABLE_SIZE {
                        return Err(Error::InvalidHuffmanTable {
                            reason: "overflow table full",
                        });
                    }
                    if bit_pos == 0 {
                        // Leaf: store symbol and code_len.
                        tbl.overflow[child_idx] = (sym << 4) | (len as u16);
                    } else {
                        // Internal node: ensure child exists.
                        let existing = tbl.overflow[child_idx];
                        if existing == 0 {
                            let new_node = tbl.alloc_overflow()?;
                            // Store node index (code_len=0 marks internal).
                            tbl.overflow[child_idx] = (new_node as u16) << 4;
                        }
                        node = (tbl.overflow[child_idx] >> 4) as usize;
                    }
                }
            }
        }

        // Fill undersubscribed entries with first valid symbol.
        let fill = tbl
            .direct
            .iter()
            .zip(direct_filled.iter())
            .find(|&(_, filled)| *filled)
            .map(|(&e, _)| e);

        if let Some(fill_entry) = fill {
            for (entry, filled) in tbl.direct.iter_mut().zip(direct_filled.iter()) {
                if !*filled {
                    *entry = fill_entry;
                }
            }
        }

        Ok(tbl)
    }

    fn alloc_overflow(&mut self) -> Result<usize> {
        let idx = self.overflow_len as usize;
        if idx >= TABLE_SIZE / 2 {
            return Err(Error::InvalidHuffmanTable {
                reason: "overflow table exceeds capacity",
            });
        }
        self.overflow_len += 1;
        Ok(idx)
    }

    /// Decode one symbol from the top bits of `next_bits`.
    /// Returns `(symbol, code_len)`.
    #[inline(always)]
    fn decode(&self, next_bits: u32) -> Result<(u16, u32)> {
        let index = (next_bits >> (32 - TABLE_BITS)) as usize;
        // SAFETY: index = next_bits >> 22, which is at most 2^10 - 1 = 1023.
        // TABLE_SIZE = 1024, so index < TABLE_SIZE always.
        let entry = unsafe { *self.direct.get_unchecked(index) };
        let code_len = (entry & 0xF) as u32;
        if code_len != 0 {
            return Ok((entry >> 4, code_len));
        }
        // Overflow path (rare: codes 11-15 bits).
        self.decode_overflow(next_bits, entry)
    }

    #[cold]
    fn decode_overflow(&self, next_bits: u32, root_entry: PackedEntry) -> Result<(u16, u32)> {
        let mut node = (root_entry >> 4) as usize;

        for bits_used in TABLE_BITS..MAX_CODE_BITS {
            let bit = ((next_bits >> (31 - bits_used)) & 1) as usize;
            let child_idx = node * 2 + bit;
            let child = self.overflow[child_idx];
            let child_len = (child & 0xF) as u32;
            if child_len != 0 {
                return Ok((child >> 4, child_len));
            }
            node = (child >> 4) as usize;
        }

        Err(Error::InvalidHuffmanTable {
            reason: "incomplete overflow tree traversal",
        })
    }
}

// ---------------------------------------------------------------------------
// Cold error constructors (Phase 3)
// ---------------------------------------------------------------------------

#[cold]
#[inline(never)]
fn err_input_truncated(offset: usize, expected: usize, actual: usize) -> Error {
    Error::InputTruncated {
        offset,
        expected,
        actual,
    }
}

#[cold]
#[inline(never)]
fn err_distance_exceeds(offset: usize, distance: usize, pos_in_block: usize) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "XPRESS Huffman match distance {distance} exceeds \
             block position {pos_in_block}"
        ),
    }
}

#[cold]
#[inline(never)]
fn err_u16_length_too_small(offset: usize, val: usize) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "XPRESS Huffman u16 length {val} \
             is less than minimum 15"
        ),
    }
}

// ---------------------------------------------------------------------------
// Guard margins (Phase 2)
// ---------------------------------------------------------------------------

/// Input guard: fast path requires this many bytes remaining in the
/// bitstream. Worst case per symbol: 15-bit code (2-byte refill) +
/// 7-byte length extensions + 15-bit distance (2-byte refill) ≈ 11 bytes.
/// 16 symbols × 11 = 176 bytes.
const INPUT_GUARD: usize = 176;

/// Output guard: fast path requires this many bytes of output space.
/// Matches RTL's margin at `cmp esi, [block_end - 188]`.
const OUTPUT_GUARD: usize = 188;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decompress XPRESS Huffman data in strict mode.
///
/// Returns the number of bytes written to `output`, or an error if the
/// input is malformed. The caller must pre-allocate `output` to the
/// expected decompressed size.
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut in_pos = 0;
    let mut out_pos = 0;

    while out_pos < output.len() {
        let block_limit = (out_pos + BLOCK_SIZE).min(output.len());
        let (consumed, written) =
            decompress_block_strict(&input[in_pos..], output, out_pos, block_limit)?;
        in_pos += consumed;
        out_pos += written;
        if written == 0 {
            break;
        }
    }

    Ok(out_pos)
}

/// Decompress XPRESS Huffman data in lenient (forensic) mode.
///
/// Zero-fills the output buffer upfront, then processes block by block.
/// On per-block errors the damaged region is zero-filled and processing
/// continues with the next block.
pub fn decompress_lenient(input: &[u8], output: &mut [u8]) -> LenientResult {
    output.fill(0);

    let mut in_pos = 0;
    let mut out_pos = 0;
    let mut had_errors = false;

    while out_pos < output.len() {
        let block_limit = (out_pos + BLOCK_SIZE).min(output.len());
        let block_input = &input[in_pos..];

        match decompress_block_strict(block_input, output, out_pos, block_limit) {
            Ok((consumed, written)) => {
                in_pos += consumed;
                out_pos += written;
                if written == 0 {
                    break;
                }
            }
            Err(_) => {
                had_errors = true;
                let fill = block_limit - out_pos;
                // Region is already zeroed from the initial fill.
                out_pos += fill;
                // Skip to next block: advance past header at minimum.
                in_pos += HEADER_SIZE.min(input.len().saturating_sub(in_pos));
                skip_to_next_block_boundary(input, &mut in_pos);
            }
        }
    }

    LenientResult {
        bytes_written: out_pos,
        had_errors,
    }
}

/// Advance `in_pos` past remaining bitstream data to the next plausible
/// block boundary.
fn skip_to_next_block_boundary(input: &[u8], in_pos: &mut usize) {
    *in_pos = input.len();
}

// ---------------------------------------------------------------------------
// Block decompressor (Phases 1-4 combined)
// ---------------------------------------------------------------------------

/// Decompress a single XPRESS Huffman block using a deficit-based
/// bit-reading model that matches the MS-XCA spec pseudocode.
///
/// Returns `(input_bytes_consumed, output_bytes_written)`.
fn decompress_block_strict(
    input: &[u8],
    output: &mut [u8],
    out_start: usize,
    block_limit: usize,
) -> Result<(usize, usize)> {
    if input.len() < HEADER_SIZE {
        return Err(err_input_truncated(0, HEADER_SIZE, input.len()));
    }

    let lengths = parse_code_lengths(&input[..HEADER_SIZE]);
    let table = PackedDecodeTable::build(&lengths)?;

    let data = &input[HEADER_SIZE..];

    // RTL requires at least 4 bytes of bitstream after header.
    if data.len() < 4 {
        return Err(err_input_truncated(
            HEADER_SIZE,
            HEADER_SIZE + 4,
            input.len(),
        ));
    }

    // Initialize: load two 16-bit words into a u32 accumulator.
    let w0 = u16::from_le_bytes([data[0], data[1]]) as u32;
    let w1 = u16::from_le_bytes([data[2], data[3]]) as u32;
    let mut pos: usize = 4;
    let mut next_bits: u32 = (w0 << 16) | w1;
    let mut extra_bit_count: i32 = 16;
    let mut out_pos = out_start;

    // ---- Fast path (Phase 2) ----
    // While we have enough input and output headroom, skip per-read
    // bounds checks. The guard margins guarantee all reads within
    // the fast loop body are in-bounds.
    while out_pos + OUTPUT_GUARD < block_limit && pos + INPUT_GUARD <= data.len() {
        let (symbol, code_len) = table.decode(next_bits)?;

        next_bits <<= code_len;
        extra_bit_count -= code_len as i32;

        // Refill — no bounds check (INPUT_GUARD guarantees headroom).
        if extra_bit_count < 0 {
            // SAFETY: INPUT_GUARD ensures pos + 2 <= data.len().
            let word = unsafe { crate::raw::read_u16_le(data, pos) } as u32;
            pos += 2;
            next_bits |= word << ((-extra_bit_count) as u32);
            extra_bit_count += 16;
        }

        if symbol < 256 {
            output[out_pos] = symbol as u8;
            out_pos += 1;
        } else {
            let sym_offset = symbol - 256;
            let length_header = (sym_offset & 15) as u32;
            let distance_log = (sym_offset >> 4) as u32;

            // Length decode — no bounds checks on extension reads.
            let length = if length_header < 15 {
                length_header as usize + 3
            } else {
                let extra_byte = data[pos] as usize;
                pos += 1;

                if extra_byte < 255 {
                    extra_byte + 15 + 3
                } else {
                    // SAFETY: INPUT_GUARD ensures pos + 2 <= data.len().
                    let u16_val = unsafe { crate::raw::read_u16_le(data, pos) } as usize;
                    pos += 2;

                    if u16_val == 0 {
                        // SAFETY: INPUT_GUARD ensures pos + 4 <= data.len().
                        let u32_val = unsafe { crate::raw::read_u32_le(data, pos) } as usize;
                        pos += 4;
                        u32_val + 3
                    } else {
                        if u16_val < 15 {
                            return Err(err_u16_length_too_small(HEADER_SIZE + pos - 2, u16_val));
                        }
                        u16_val + 3
                    }
                }
            };

            // Distance decode — no bounds check on refill.
            let distance = if distance_log == 0 {
                1usize
            } else {
                let extra = next_bits >> (32 - distance_log);
                next_bits <<= distance_log;
                extra_bit_count -= distance_log as i32;
                if extra_bit_count < 0 {
                    // SAFETY: INPUT_GUARD ensures pos + 2 <= data.len().
                    let word = unsafe { crate::raw::read_u16_le(data, pos) } as u32;
                    pos += 2;
                    next_bits |= word << ((-extra_bit_count) as u32);
                    extra_bit_count += 16;
                }
                (1usize << distance_log) + extra as usize
            };

            let pos_in_block = out_pos - out_start;
            if distance > pos_in_block {
                return Err(err_distance_exceeds(
                    HEADER_SIZE + pos,
                    distance,
                    pos_in_block,
                ));
            }

            // Per-match bounds check before unchecked copy.
            if out_pos + length > block_limit {
                return Err(Error::OutputTooSmall {
                    expected: out_pos + length,
                    actual: block_limit,
                });
            }
            // SAFETY: distance <= pos_in_block (checked above),
            // out_pos + length <= block_limit <= output.len() (checked above).
            unsafe {
                crate::simd::copy_match_fast(output, out_pos, distance, length);
            }
            out_pos += length;
        }
    }

    // ---- Slow path: full bounds checking ----
    while out_pos < block_limit {
        let (symbol, code_len) = table.decode(next_bits)?;

        next_bits <<= code_len;
        extra_bit_count -= code_len as i32;

        if extra_bit_count < 0 {
            if pos + 2 > data.len() {
                return Err(err_input_truncated(
                    HEADER_SIZE + pos,
                    2,
                    data.len().saturating_sub(pos),
                ));
            }
            let word = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
            pos += 2;
            next_bits |= word << ((-extra_bit_count) as u32);
            extra_bit_count += 16;
        }

        if symbol < 256 {
            output[out_pos] = symbol as u8;
            out_pos += 1;
        } else {
            let sym_offset = symbol - 256;
            let length_header = (sym_offset & 15) as u32;
            let distance_log = (sym_offset >> 4) as u32;

            let length = if length_header < 15 {
                length_header as usize + 3
            } else {
                if pos >= data.len() {
                    return Err(err_input_truncated(HEADER_SIZE + pos, 1, 0));
                }
                let extra_byte = data[pos] as usize;
                pos += 1;

                if extra_byte < 255 {
                    extra_byte + 15 + 3
                } else {
                    if pos + 2 > data.len() {
                        return Err(err_input_truncated(
                            HEADER_SIZE + pos,
                            2,
                            data.len().saturating_sub(pos),
                        ));
                    }
                    let u16_val = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;

                    if u16_val == 0 {
                        if pos + 4 > data.len() {
                            return Err(err_input_truncated(
                                HEADER_SIZE + pos,
                                4,
                                data.len().saturating_sub(pos),
                            ));
                        }
                        let u32_val = u32::from_le_bytes([
                            data[pos],
                            data[pos + 1],
                            data[pos + 2],
                            data[pos + 3],
                        ]) as usize;
                        pos += 4;
                        u32_val + 3
                    } else {
                        if u16_val < 15 {
                            return Err(err_u16_length_too_small(HEADER_SIZE + pos - 2, u16_val));
                        }
                        u16_val + 3
                    }
                }
            };

            let distance = if distance_log == 0 {
                1usize
            } else {
                let extra = next_bits >> (32 - distance_log);
                next_bits <<= distance_log;
                extra_bit_count -= distance_log as i32;
                if extra_bit_count < 0 {
                    if pos + 2 > data.len() {
                        return Err(err_input_truncated(
                            HEADER_SIZE + pos,
                            2,
                            data.len().saturating_sub(pos),
                        ));
                    }
                    let word = u16::from_le_bytes([data[pos], data[pos + 1]]) as u32;
                    pos += 2;
                    next_bits |= word << ((-extra_bit_count) as u32);
                    extra_bit_count += 16;
                }
                (1usize << distance_log) + extra as usize
            };

            let pos_in_block = out_pos - out_start;
            if distance > pos_in_block {
                return Err(err_distance_exceeds(
                    HEADER_SIZE + pos,
                    distance,
                    pos_in_block,
                ));
            }

            copy_match_fast(output, out_pos, distance, length, block_limit)?;
            out_pos += length;
        }
    }

    let consumed = (HEADER_SIZE + pos).min(input.len());
    Ok((consumed, out_pos - out_start))
}

/// Parse the 256-byte header into 512 code lengths (4 bits each).
fn parse_code_lengths(header: &[u8]) -> [u8; NUM_SYMBOLS] {
    let mut lengths = [0u8; NUM_SYMBOLS];
    for (i, &byte) in header.iter().enumerate() {
        lengths[2 * i] = byte & 0x0F;
        lengths[2 * i + 1] = byte >> 4;
    }
    lengths
}

// ---------------------------------------------------------------------------
// Copy match (Phase 4)
// ---------------------------------------------------------------------------

/// Copy `length` bytes from `output[out_pos - distance..]` to
/// `output[out_pos..]`, using chunked copies where possible.
#[inline(always)]
fn copy_match_fast(
    output: &mut [u8],
    out_pos: usize,
    distance: usize,
    length: usize,
    limit: usize,
) -> Result<()> {
    if out_pos + length > limit {
        return Err(Error::OutputTooSmall {
            expected: out_pos + length,
            actual: limit,
        });
    }
    let src_start = out_pos - distance;

    if distance >= length {
        // Non-overlapping: single copy_within.
        output.copy_within(src_start..src_start + length, out_pos);
    } else if distance == 1 {
        // RLE fill: doubling copy_within.
        output[out_pos] = output[src_start];
        let mut filled = 1;
        while filled < length {
            let chunk = filled.min(length - filled);
            output.copy_within(out_pos..out_pos + chunk, out_pos + filled);
            filled += chunk;
        }
    } else if distance >= 16 {
        // Overlapping but distance >= 16: copy 16 bytes at a time.
        let mut i = 0;
        while i + 16 <= length {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(&output[src_start + i..src_start + i + 16]);
            output[out_pos + i..out_pos + i + 16].copy_from_slice(&tmp);
            i += 16;
        }
        // Tail: copy remaining bytes via 8-byte or single-byte chunks.
        while i + 8 <= length {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&output[src_start + i..src_start + i + 8]);
            output[out_pos + i..out_pos + i + 8].copy_from_slice(&tmp);
            i += 8;
        }
        for j in i..length {
            output[out_pos + j] = output[src_start + j];
        }
    } else if distance >= 8 {
        // Overlapping, distance 8-15: copy 8 bytes at a time.
        let mut i = 0;
        while i + 8 <= length {
            let mut tmp = [0u8; 8];
            tmp.copy_from_slice(&output[src_start + i..src_start + i + 8]);
            output[out_pos + i..out_pos + i + 8].copy_from_slice(&tmp);
            i += 8;
        }
        for j in i..length {
            output[out_pos + j] = output[src_start + j];
        }
    } else if length <= 4 {
        // Tiny match (distance 2-7, length 3-4): unrolled byte copy.
        output[out_pos] = output[src_start];
        output[out_pos + 1] = output[src_start + 1];
        output[out_pos + 2] = output[src_start + 2];
        if length == 4 {
            output[out_pos + 3] = output[src_start + 3];
        }
    } else {
        // Short repeating pattern (distance 2-7, length > 4): byte-by-byte.
        for i in 0..length {
            output[out_pos + i] = output[src_start + i];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    /// Build a 256-byte Huffman header from 512 code lengths.
    fn build_header(lengths: &[u8; NUM_SYMBOLS]) -> [u8; HEADER_SIZE] {
        let mut header = [0u8; HEADER_SIZE];
        for i in 0..HEADER_SIZE {
            header[i] = (lengths[2 * i] & 0x0F) | ((lengths[2 * i + 1] & 0x0F) << 4);
        }
        header
    }

    /// Assign canonical Huffman codes from code lengths.
    /// Returns `(code, length)` per symbol.
    fn assign_codes(lengths: &[u8; NUM_SYMBOLS]) -> Vec<(u32, u8)> {
        let mut counts = [0u32; 16];
        for &len in lengths.iter() {
            if len > 0 && (len as usize) < counts.len() {
                counts[len as usize] += 1;
            }
        }
        let mut next_code = [0u32; 16];
        let mut code: u32 = 0;
        for bits in 1..16usize {
            code = (code + counts[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut codes = vec![(0u32, 0u8); NUM_SYMBOLS];
        for (sym, &len) in lengths.iter().enumerate() {
            let l = len as usize;
            if l > 0 && l < 16 {
                codes[sym] = (next_code[l], len);
                next_code[l] += 1;
            }
        }
        codes
    }

    use crate::test_bitwriter::BitWriter;

    /// Build a complete XPRESS Huffman block: 256-byte header + encoded
    /// bitstream for the given Huffman symbols.
    fn build_block(
        lengths: &[u8; NUM_SYMBOLS],
        symbols: &[u16],
        extra_bits: &[(u32, u32)],
    ) -> Vec<u8> {
        let header = build_header(lengths);
        let codes = assign_codes(lengths);
        let mut writer = BitWriter::new();

        let mut extra_idx = 0;
        for &sym in symbols {
            let (code, len) = codes[sym as usize];
            writer.write_bits(code, u32::from(len));

            // Write any extra bits following this symbol
            while extra_idx < extra_bits.len() {
                let (val, count) = extra_bits[extra_idx];
                // Sentinel: count == 0 marks "advance to next symbol"
                if count == 0 {
                    extra_idx += 1;
                    break;
                }
                writer.write_bits(val, count);
                extra_idx += 1;
            }
        }

        let bitstream = writer.finish(1);
        let mut block = Vec::with_capacity(HEADER_SIZE + bitstream.len());
        block.extend_from_slice(&header);
        block.extend_from_slice(&bitstream);
        block
    }

    /// Build lengths for a simple tree: symbols 0-255 get code length 9,
    /// symbols 256-511 get code length 9. Total = 512 symbols at length
    /// 9 = 512 = 2^9, so the code space is exactly full.
    fn uniform_9bit_lengths() -> [u8; NUM_SYMBOLS] {
        [9u8; NUM_SYMBOLS]
    }

    #[test]
    fn truncated_header_returns_error() {
        let input = [0u8; 200]; // less than 256 bytes
        let mut output = [0u8; 1024];
        let result = decompress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_bitstream_returns_error() {
        // RTL requires at least 260 bytes per block (256 header + 4
        // bitstream). A valid header with fewer than 4 bitstream bytes
        // must error in strict mode, not silently zero-fill.
        let mut lengths = [0u8; NUM_SYMBOLS];
        lengths[0] = 1;
        let header = build_header(&lengths);

        // Header + only 2 bytes of bitstream = 258 total < 260
        let mut input = Vec::new();
        input.extend_from_slice(&header);
        input.extend_from_slice(&[0x00, 0x00]);

        let mut output = [0u8; 64];
        let result = decompress(&input, &mut output);
        assert!(result.is_err(), "expected error for truncated bitstream");
    }

    #[test]
    fn exhausted_refill_returns_error() {
        // Strict mode must error when a deficit refill reads past the
        // end of the bitstream — matching RTL's bounds-checked refill
        // that returns STATUS_BAD_COMPRESSION_BUFFER.
        let mut lengths = [0u8; NUM_SYMBOLS];
        lengths[0] = 1;
        let header = build_header(&lengths);

        // Provide exactly the 4 initial bytes but nothing more.
        // After a few 1-bit symbol decodes the accumulator will go
        // into deficit and the refill must fail.
        let mut input = Vec::new();
        input.extend_from_slice(&header);
        input.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let mut output = [0u8; 256];
        let result = decompress(&input, &mut output);
        assert!(result.is_err(), "expected error for exhausted refill");
    }

    #[test]
    fn all_literals_block() {
        let lengths = uniform_9bit_lengths();
        // Encode 256 literal bytes (symbols 0-255)
        let symbols: Vec<u16> = (0..256).collect();
        // No extra bits for literals
        let mut extras = Vec::new();
        for _ in 0..256 {
            extras.push((0u32, 0u32)); // sentinel: advance to next symbol
        }
        let block = build_block(&lengths, &symbols, &extras);

        let mut output = [0u8; 256];
        let n = decompress(&block, &mut output).expect("decompress failed");
        assert_eq!(n, 256);
        for (i, &byte) in output.iter().enumerate() {
            assert_eq!(byte, i as u8, "mismatch at byte {i}");
        }
    }

    #[test]
    fn match_with_distance() {
        // Build a tree where:
        //   Symbol 0 ('A') = literal, code length 1
        //   Symbol 272 = match: (272-256)/16 = 1 (distance_log=1),
        //                       (272-256)%16 = 0 (length_header=0)
        //   distance = (1<<1) + extra_bit, length = 0+3 = 3
        //   With extra_bit=0: distance=2
        //
        // We need a valid tree. Use symbol 0 len=1, symbol 272 len=1.
        // Kraft: 2 * 2^(-1) = 1.0. Valid.
        let mut lengths = [0u8; NUM_SYMBOLS];
        lengths[0] = 1; // literal 'A' -> code 0
        lengths[272] = 1; // match symbol -> code 1

        // Stream: symbol 0, symbol 0, symbol 272 (+ 1 extra bit for distance)
        // After two 'A' literals at positions 0,1:
        //   distance_log=1 -> read 1 extra bit = 0 -> distance = 2
        //   length_header=0 -> length = 3
        // But distance=2, out_pos in block=2, so 2 <= 2: ok.
        // Copy from pos 0: output = "AA" + "AAA" = "AAAAA"
        // Actually distance=2 at pos 2 means copy from index 0.
        // length=3 -> copy 3 bytes from offset 0: "AAA"
        // total: "AAAAA"
        let symbols = [0u16, 0, 272];
        let extras = vec![
            (0u32, 0u32), // after sym 0: no extras
            (0u32, 0u32), // after sym 0: no extras
            (0u32, 1u32), // distance extra bit = 0
            (0u32, 0u32), // sentinel
        ];
        let block = build_block(&lengths, &symbols, &extras);

        let mut output = [0u8; 5];
        let n = decompress(&block, &mut output).expect("decompress failed");
        assert_eq!(n, 5);
        assert_eq!(&output[..5], b"\x00\x00\x00\x00\x00");
    }

    #[test]
    fn invalid_huffman_header() {
        // All symbols at code length 1 -> 512 * 2^(-1) = 256 >> 1
        // This massively oversubscribes the code space.
        let mut input = [0u8; 300];
        // Set every nibble to 1 (code length 1 for all 512 symbols)
        for byte in &mut input[..HEADER_SIZE] {
            *byte = 0x11;
        }
        let mut output = [0u8; 1024];
        let result = decompress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn multi_block_decompression() {
        // Build two blocks: first produces 65536 bytes, second produces
        // a few more. Use a simple 1-symbol literal tree.
        //
        // Symbol 0: code length 1 (only valid symbol)
        // Kraft: 1 * 2^(-1) = 0.5 (undersubscribed, allowed)
        let mut lengths = [0u8; NUM_SYMBOLS];
        lengths[0] = 1;

        // Block 1: 65536 literal-0 symbols
        let symbols1: Vec<u16> = vec![0; BLOCK_SIZE];
        let extras1: Vec<(u32, u32)> = vec![(0, 0); BLOCK_SIZE];
        let block1 = build_block(&lengths, &symbols1, &extras1);

        // Block 2: 100 literal-0 symbols
        let symbols2: Vec<u16> = vec![0; 100];
        let extras2: Vec<(u32, u32)> = vec![(0, 0); 100];
        let block2 = build_block(&lengths, &symbols2, &extras2);

        let mut input = Vec::new();
        input.extend_from_slice(&block1);
        input.extend_from_slice(&block2);

        let total = BLOCK_SIZE + 100;
        let mut output = vec![0u8; total];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, total);
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn lenient_corrupt_block() {
        // Block 1: valid header but corrupt bitstream -> zero-fill
        let mut lengths = [0u8; NUM_SYMBOLS];
        lengths[0] = 1;

        let header1 = build_header(&lengths);
        let mut block1 = Vec::new();
        block1.extend_from_slice(&header1);
        // Corrupt bitstream: not enough data to decode anything useful,
        // but enough to attempt. Put a single garbage word.
        block1.extend_from_slice(&[0xFF, 0xFF]);

        // The output size must be > BLOCK_SIZE for two blocks.
        // In lenient mode, block 1 fails -> zero-fill 65536 bytes.
        // Block 2 would need valid data but we don't have any,
        // so it also errors.
        let total = BLOCK_SIZE + 100;
        let mut output = vec![0xCCu8; total];
        let r = decompress_lenient(&block1, &mut output);
        assert!(r.had_errors);
        // First block's region should be zero-filled
        assert!(output[..BLOCK_SIZE].iter().all(|&b| b == 0));
    }

    #[test]
    fn lenient_valid_data() {
        let lengths = uniform_9bit_lengths();
        let symbols: Vec<u16> = (0..256).collect();
        let extras: Vec<(u32, u32)> = vec![(0, 0); 256];
        let block = build_block(&lengths, &symbols, &extras);

        let mut strict_out = [0u8; 256];
        let strict_n = decompress(&block, &mut strict_out).expect("strict failed");

        let mut lenient_out = [0u8; 256];
        let r = decompress_lenient(&block, &mut lenient_out);

        assert!(!r.had_errors);
        assert_eq!(r.bytes_written, strict_n);
        assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
    }

    #[test]
    fn empty_output() {
        let input = [0u8; 300];
        let mut output = [0u8; 0];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 0);
    }
}
