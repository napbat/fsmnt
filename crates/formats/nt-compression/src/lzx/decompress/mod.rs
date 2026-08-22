//! LZX WIM-variant decompression.
//!
//! Implements the LZX algorithm as used in WIM archives and WOF
//! (Windows Overlay Filter). This is NOT CAB LZX or LZXD delta.
//!
//! Each chunk is independently decompressible with a 32 KB window.
//! After decompression, E8 post-processing reverses x86 CALL target
//! pre-processing applied before compression.
#![allow(unsafe_code)]

use crate::bitstream::BitReader;
use crate::e8::undo_e8_preprocessing;
use crate::huffman::{
    SmallHuffmanTable, canonical_codes, count_per_length, validate_code_space, validate_lengths,
};
use crate::{Error, LenientResult, Result};

use super::{
    ALIGNED_CODE_BITS, ALIGNED_TREE_SIZE, BLOCK_ALIGNED, BLOCK_UNCOMPRESSED, BLOCK_VERBATIM,
    E8_FILE_SIZE, FOOTER_BITS, LEN_HEADER_COUNT, LENGTH_TREE_SIZE, LONG_RUN_BASE, LONG_RUN_BITS,
    MAIN_TREE_SIZE, MIN_MATCH_LEN, NUM_CODE_LENGTHS, NUM_POSITION_SLOTS, OFFSET_ADJUSTMENT,
    POSITION_BASE, PRE_TREE_CODE_BITS, PRE_TREE_SIZE, PRETREE_REPEAT, PRETREE_ZERO_LONG,
    PRETREE_ZERO_SHORT, REPEAT_BITS, SHORT_RUN_BASE, SHORT_RUN_BITS, WINDOW_SIZE,
};

// ---------------------------------------------------------------------------
// LzxDecodeTable — flat subtable decode (wimlib-style)
// ---------------------------------------------------------------------------

/// Per-tree table bit widths (matched to wimlib).
mod table;

use table::{
    LzxDecodeTable, err_input_truncated, err_invalid_data, err_match_offset_exceeds,
    err_offset_below_minimum, err_output_too_small, err_position_slot_exceeds,
};

const MAIN_TABLE_BITS: u32 = 11;
const LENGTH_TABLE_BITS: u32 = 9;
const ALIGNED_TABLE_BITS: u32 = 7;
/// Maximum code length in LZX.
#[allow(dead_code, reason = "documents the spec constraint")]
const MAX_CODE_BITS: u32 = 16;

/// Maximum root table size (main tree at 11 bits).
const MAX_ROOT_SIZE: usize = 1 << MAIN_TABLE_BITS; // 2048

/// Maximum overflow entries. Upper bound: each root overflow slot
/// spawns a subtable of at most `2^MAX_SUBTABLE_BITS` entries.
/// In practice far fewer are needed. 2048 is generous.
const MAX_OVERFLOW: usize = 2048;

/// Packed entry format:
///
/// - **Direct leaf**: `(symbol << 4) | code_len`
///   (`code_len` in 1..=15, fits in 4 bits)
///
/// - **Subtable pointer** (root only, `code_len == 0`):
///   `(overflow_offset << 4) | 0`
///   The subtable at `overflow[offset..]` has size `1 << subtable_bits`.
///   `subtable_bits` is stored separately in `subtable_bits_map`.
type PackedEntry = u16;

// ---------------------------------------------------------------------------
// Manual bit accumulator state
// ---------------------------------------------------------------------------

/// Manual 32-bit bit accumulator matching `BitReader`'s MSB-first,
/// 16-bit LE word refill semantics.
///
/// `next_bits` holds buffered bits MSB-aligned in a u32. After
/// consuming N bits (shift left + decrement `extra_bit_count`),
/// a refill loads one 16-bit LE word when `extra_bit_count` < 0.
struct BitAccum {
    /// Buffered bits, MSB-aligned.
    next_bits: u32,
    /// Number of valid bits minus 16. When negative, a refill is
    /// needed. `valid_bits = extra_bit_count + 16`.
    extra_bit_count: i32,
    /// Next byte to load from the input data.
    byte_pos: usize,
}

// ---------------------------------------------------------------------------
// Guard margins for fast path
// ---------------------------------------------------------------------------

/// Fast path requires this many bytes of input headroom. Worst case
/// per symbol: 16-bit main code refill + 16-bit length code refill +
/// 14 footer bits refill = ~6 bytes. 16 symbols × 8 = 128 bytes.
const INPUT_GUARD: usize = 128;

/// Fast path requires this many bytes of output headroom.
///
/// Set to the maximum possible LZX match length (7 + 248 + 2 = 257).
/// This guarantees that `out_pos + match_length <= block_end` for
/// any match decoded in the fast path, allowing us to skip the
/// per-match output bounds check entirely.
const OUTPUT_GUARD: usize = 257;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decompress LZX WIM data in strict mode.
///
/// Returns the number of bytes written to `output`. The caller
/// must pre-allocate `output` to the expected decompressed size
/// (at most 32768 bytes for WIM LZX).
///
/// # Errors
///
/// Returns an error when the bitstream is malformed or references data
/// outside the available input or output window.
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut ctx = DecompressCtx::new(input, output.len());
    let written = ctx.run(output)?;
    undo_e8_preprocessing(&mut output[..written], E8_FILE_SIZE, 0);
    Ok(written)
}

/// Decompress LZX WIM data in lenient (forensic) mode.
///
/// Zero-fills the output buffer upfront, then decompresses as far
/// as possible. On errors the damaged region stays zeroed and
/// `had_errors` is set.
pub fn decompress_lenient(input: &[u8], output: &mut [u8]) -> LenientResult {
    output.fill(0);
    let mut ctx = DecompressCtx::new(input, output.len());
    let (written, had_errors) = match ctx.run(output) {
        Ok(n) => (n, false),
        Err(_) => (ctx.out_pos.min(output.len()), true),
    };
    undo_e8_preprocessing(&mut output[..written], E8_FILE_SIZE, 0);
    LenientResult {
        bytes_written: written,
        had_errors,
    }
}

/// Persistent state across blocks within a single chunk.
struct DecompressCtx<'a> {
    reader: BitReader<'a>,
    /// Raw input slice (same data as reader).
    input: &'a [u8],
    /// Byte offset into `input` where the reader's data starts.
    /// After `copy_raw_bytes` recreates the reader from a
    /// sub-slice, this tracks the delta so that positions into
    /// `self.input` are computed correctly.
    reader_base: usize,
    out_pos: usize,
    out_len: usize,
    r0: u32,
    r1: u32,
    r2: u32,
    /// Previous block's main tree code lengths (for delta encoding).
    main_lens: [u8; MAIN_TREE_SIZE],
    /// Previous block's length tree code lengths (for delta encoding).
    length_lens: [u8; LENGTH_TREE_SIZE],
    /// Pre-tree lookup buffers retained across the three tree headers.
    pre_table: SmallHuffmanTable<PRE_TREE_SIZE>,
}

impl<'a> DecompressCtx<'a> {
    fn new(input: &'a [u8], out_len: usize) -> Self {
        let mut reader = BitReader::new(input);
        // LZX block headers specify exact output sizes, so the
        // decompressor stops reading at the right time. Enable
        // zero-fill so that bitstreams without trailing padding
        // (e.g. wimlib's tighter encoding) don't cause spurious
        // InputTruncated errors on the final ensure_bits call.
        reader.set_zero_fill(true);
        Self {
            reader,
            input,
            reader_base: 0,
            out_pos: 0,
            out_len,
            r0: 1,
            r1: 1,
            r2: 1,
            main_lens: [0; MAIN_TREE_SIZE],
            length_lens: [0; LENGTH_TREE_SIZE],
            pre_table: SmallHuffmanTable::new(),
        }
    }

    /// Run decompression across all blocks in the chunk.
    fn run(&mut self, output: &mut [u8]) -> Result<usize> {
        while self.out_pos < self.out_len {
            self.decode_block(output)?;
        }
        Ok(self.out_pos)
    }

    /// Decode a single LZX block (verbatim, aligned, or
    /// uncompressed).
    fn decode_block(&mut self, output: &mut [u8]) -> Result<()> {
        let block_type = self.reader.read_bits(3)?;
        let block_size = self.read_block_size()?;
        let block_end = (self.out_pos + block_size as usize).min(self.out_len);

        match block_type {
            BLOCK_VERBATIM => {
                let (main_tbl, len_tbl) = self.read_main_and_length_trees()?;
                self.decode_compressed(output, block_end, &main_tbl, &len_tbl, None)
            }
            BLOCK_ALIGNED => {
                let aligned_tbl = self.read_aligned_tree()?;
                let (main_tbl, len_tbl) = self.read_main_and_length_trees()?;
                self.decode_compressed(output, block_end, &main_tbl, &len_tbl, Some(&aligned_tbl))
            }
            BLOCK_UNCOMPRESSED => self.decode_uncompressed(output, block_end),
            _ => Err(err_invalid_data(
                self.reader.position(),
                "LZX invalid block type",
            )),
        }
    }

    /// Read block size: 1 bit flag; if 1 -> default (32768), else
    /// read 16 bits.
    fn read_block_size(&mut self) -> Result<u32> {
        let is_default = self.reader.read_bits(1)?;
        if is_default == 1 {
            return Ok(u32::try_from(WINDOW_SIZE).expect("the LZX window is exactly 32 KiB"));
        }
        let size = self.reader.read_bits(16)?;
        Ok(size)
    }
}

// -- Tree reading ----------------------------------------------------------

impl DecompressCtx<'_> {
    /// Read the aligned offset tree (8 entries, 3-bit code lengths).
    fn read_aligned_tree(&mut self) -> Result<LzxDecodeTable> {
        let mut lens = [0u8; ALIGNED_TREE_SIZE];
        for len in &mut lens {
            *len = u8::try_from(self.reader.read_bits(ALIGNED_CODE_BITS)?)
                .expect("aligned-tree code lengths are encoded in three bits");
        }
        LzxDecodeTable::build(&lens, ALIGNED_TABLE_BITS)
    }

    /// Read main tree (496 elements in two halves) and length tree
    /// (249 elements), each preceded by its own pre-tree.
    fn read_main_and_length_trees(&mut self) -> Result<(LzxDecodeTable, LzxDecodeTable)> {
        // Copy out to avoid double mutable borrow of self.
        let mut main_lens = self.main_lens;
        self.decode_pretree_delta(&mut main_lens[..256])?;
        self.decode_pretree_delta(&mut main_lens[256..MAIN_TREE_SIZE])?;
        self.main_lens = main_lens;

        let mut length_lens = self.length_lens;
        self.decode_pretree_delta(&mut length_lens[..LENGTH_TREE_SIZE])?;
        self.length_lens = length_lens;

        let main_tbl = LzxDecodeTable::build(&self.main_lens, MAIN_TABLE_BITS)?;
        let len_tbl = LzxDecodeTable::build(&self.length_lens, LENGTH_TABLE_BITS)?;
        Ok((main_tbl, len_tbl))
    }

    /// Read a 20-symbol pre-tree from the bitstream and decode
    /// delta-encoded code lengths into `lens[start..end]`.
    fn decode_pretree_delta(&mut self, lens: &mut [u8]) -> Result<()> {
        let mut pre_lens = [0u8; PRE_TREE_SIZE];
        for pl in &mut pre_lens {
            *pl = u8::try_from(self.reader.read_bits(PRE_TREE_CODE_BITS)?)
                .expect("pre-tree code lengths are encoded in four bits");
        }
        self.pre_table.rebuild(&pre_lens)?;
        decode_code_lengths(&mut self.reader, &self.pre_table, lens)
    }
}

/// Decode code lengths using a pre-tree, applying delta encoding
/// against the previous values already in `lens`.
///
/// Pre-tree symbol meanings:
/// - 0..=16: delta from previous length:
///   `new = (old - code + NUM_CODE_LENGTHS) % NUM_CODE_LENGTHS`
/// - `PRETREE_ZERO_SHORT` (17): read `SHORT_RUN_BITS` bits, run =
///   value + `SHORT_RUN_BASE`; fill that many zeros
/// - `PRETREE_ZERO_LONG` (18): read `LONG_RUN_BITS` bits, run =
///   value + `LONG_RUN_BASE`; fill that many zeros
/// - `PRETREE_REPEAT` (19): read `REPEAT_BITS` bit, run = value +
///   `SHORT_RUN_BASE`; decode one more pre-tree symbol for the
///   delta, then fill `run` positions with that length
fn decode_code_lengths(
    reader: &mut BitReader<'_>,
    pre_table: &SmallHuffmanTable<PRE_TREE_SIZE>,
    lens: &mut [u8],
) -> Result<()> {
    let total = lens.len();
    let mut i = 0;

    while i < total {
        let sym = u32::from(pre_table.decode_symbol(reader)?);

        if sym < u32::from(PRETREE_ZERO_SHORT) {
            let old = u32::from(lens[i]);
            lens[i] = ((old + NUM_CODE_LENGTHS - sym) % NUM_CODE_LENGTHS) as u8;
            i += 1;
        } else if sym == u32::from(PRETREE_ZERO_SHORT) {
            let run = reader.read_bits(SHORT_RUN_BITS)? as usize + SHORT_RUN_BASE;
            let end = (i + run).min(total);
            for slot in &mut lens[i..end] {
                *slot = 0;
            }
            i = end;
        } else if sym == u32::from(PRETREE_ZERO_LONG) {
            let run = reader.read_bits(LONG_RUN_BITS)? as usize + LONG_RUN_BASE;
            let end = (i + run).min(total);
            for slot in &mut lens[i..end] {
                *slot = 0;
            }
            i = end;
        } else if sym == u32::from(PRETREE_REPEAT) {
            let run = reader.read_bits(REPEAT_BITS)? as usize + SHORT_RUN_BASE;
            let delta_sym = u32::from(pre_table.decode_symbol(reader)?);
            let old = u32::from(lens[i]);
            let new_len = ((old + NUM_CODE_LENGTHS - delta_sym) % NUM_CODE_LENGTHS) as u8;
            let end = (i + run).min(total);
            for slot in &mut lens[i..end] {
                *slot = new_len;
            }
            i = end;
        } else {
            return Err(err_invalid_data(
                reader.position(),
                "LZX invalid pre-tree symbol",
            ));
        }
    }

    Ok(())
}

// -- Compressed block decoding ---------------------------------------------

/// Compute the logical bit position from `BitReader` state.
/// The reader has loaded words up to `byte_pos`, and has
/// `bits_remaining` bits buffered. The logical position (next
/// bit to decode) is `byte_pos`*8 - `bits_remaining`.
#[inline]
fn logical_bit_pos(reader_byte_pos: usize, reader_bits_remaining: u32) -> usize {
    reader_byte_pos * 8 - reader_bits_remaining as usize
}

/// Initialize a 32-bit accumulator from a position in the raw
/// input data. Loads up to two 16-bit LE words (32 bits).
///
/// `bit_pos` is the logical bit position in the input.
#[inline]
fn init_accumulator(input: &[u8], bit_pos: usize) -> BitAccum {
    let word_byte_pos = (bit_pos / 16) * 2;
    let skip_bits = u32::try_from(bit_pos % 16).expect("a bit offset within a word is below 16");

    // Load up to two 16-bit LE words (32 bits).
    let mut next_bits: u32 = 0;
    let mut byte_pos = word_byte_pos;
    let mut loaded_bits: i32 = 0;

    for _ in 0..2 {
        if byte_pos + 2 <= input.len() {
            let w = u32::from(u16::from_le_bytes([input[byte_pos], input[byte_pos + 1]]));
            byte_pos += 2;
            next_bits = (next_bits << 16) | w;
            loaded_bits += 16;
        } else {
            break;
        }
    }

    // Left-align in the 32-bit register.
    if loaded_bits < 32 {
        next_bits <<= 32 - loaded_bits;
    }

    // Skip bits already consumed.
    next_bits <<= skip_bits;
    let extra_bit_count = loaded_bits
        - 16
        - i32::try_from(skip_bits).expect("the initial skip is at most one 16-bit word");

    let mut a = BitAccum {
        next_bits,
        extra_bit_count,
        byte_pos,
    };

    // Top off if below the threshold.
    if a.extra_bit_count < 0 && a.byte_pos + 2 <= input.len() {
        let w = u32::from(u16::from_le_bytes([
            input[a.byte_pos],
            input[a.byte_pos + 1],
        ]));
        a.byte_pos += 2;
        let deficit = u32::try_from(-a.extra_bit_count)
            .expect("this refill branch requires a negative bit count");
        a.next_bits |= w << deficit;
        a.extra_bit_count += 16;
    }

    a
}

/// Restore `BitReader` state from a 64-bit accumulator position.
/// Creates a new `BitReader` pointing at the correct position in
/// the input and pre-loads any partially consumed word.
/// Returns `(reader, base_offset)` where `base_offset` is the
/// byte offset into `input` where the reader's sub-slice starts.
fn restore_reader<'a>(input: &'a [u8], accum: &BitAccum) -> (BitReader<'a>, usize) {
    let valid_bits = u32::try_from((accum.extra_bit_count + 16).max(0))
        .expect("max with zero makes the valid-bit count nonnegative");
    let end_bit_pos = accum.byte_pos * 8 - valid_bits as usize;
    let end_word_byte = (end_bit_pos / 16) * 2;
    let end_skip = u32::try_from(end_bit_pos % 16).expect("a bit offset within a word is below 16");

    let mut reader = BitReader::new(&input[end_word_byte..]);
    reader.set_zero_fill(true);

    // Load the partially consumed word and skip past
    // already-consumed bits.
    if end_skip > 0 {
        let _ = reader.ensure_bits(end_skip);
        reader.consume_bits(end_skip);
    }

    (reader, end_word_byte)
}

/// Refill the accumulator from the data stream.
/// Loads one 16-bit LE word when available, or zero-fills.
#[inline]
fn refill_checked(data: &[u8], accum: &mut BitAccum) {
    if accum.byte_pos + 2 <= data.len() {
        let w = u32::from(u16::from_le_bytes([
            data[accum.byte_pos],
            data[accum.byte_pos + 1],
        ]));
        accum.byte_pos += 2;
        let deficit = u32::try_from(-accum.extra_bit_count)
            .expect("this refill branch requires a negative bit count");
        accum.next_bits |= w << deficit;
        accum.extra_bit_count += 16;
    } else {
        // Zero-fill: no more data.
        accum.extra_bit_count += 16;
    }
}

#[inline]
fn literal_byte(symbol: u16) -> u8 {
    u8::try_from(symbol).expect("literal symbols are below 256")
}

/// Refill the accumulator using unchecked reads.
/// Loads one 16-bit LE word.
///
/// SAFETY: caller must ensure `accum.byte_pos + 2 <= data.len()`.
#[inline]
unsafe fn refill_unchecked(data: &[u8], accum: &mut BitAccum) {
    let w = u32::from(unsafe { crate::raw::read_u16_le(data, accum.byte_pos) });
    accum.byte_pos += 2;
    let deficit = u32::try_from(-accum.extra_bit_count)
        .expect("the unchecked refill requires a negative bit count");
    accum.next_bits |= w << deficit;
    accum.extra_bit_count += 16;
}

impl DecompressCtx<'_> {
    /// Decode compressed data (verbatim or aligned offset) until
    /// `block_end` output bytes are reached.
    ///
    /// Uses a manual bit accumulator with a fast-path/slow-path
    /// split for performance. The fast path skips per-symbol
    /// bounds checks using guard margins.
    fn decode_compressed(
        &mut self,
        output: &mut [u8],
        block_end: usize,
        main_tbl: &LzxDecodeTable,
        len_tbl: &LzxDecodeTable,
        aligned_tbl: Option<&LzxDecodeTable>,
    ) -> Result<()> {
        // Extract BitReader state into manual accumulator.
        let reader_pos = self.reader_base + self.reader.position();
        let reader_bits = self.reader.bits_in_buffer();
        let bit_pos = logical_bit_pos(reader_pos, reader_bits);

        let mut a = init_accumulator(self.input, bit_pos);
        let data = self.input;
        let data_len = data.len();

        // Extract ALL hot-path state into stack locals so the compiler
        // can keep everything in registers. Without this, &mut self and
        // &mut output may alias, forcing stores/reloads every iteration.
        // (wimlib uses the same technique: "Redeclare the input bitstream
        // on the stack... can improve the main loop's performance
        // significantly with both gcc and clang.")
        let mut out_pos = self.out_pos;
        let mut r0 = self.r0;
        let mut r1 = self.r1;
        let mut r2 = self.r2;

        // ---- Fast path: minimal per-symbol checks ----
        //
        // OUTPUT_GUARD >= max match length (257) guarantees:
        //   out_pos + length <= block_end   for any match
        //   out_pos < block_end             for any literal
        // so we can skip the out_of_range check entirely.
        //
        // The offset check is retained because it's a safety
        // precondition for the unsafe copy (prevents negative index).
        while out_pos + OUTPUT_GUARD < block_end && a.byte_pos + INPUT_GUARD <= data_len {
            let (symbol, code_len) = main_tbl.decode(a.next_bits);

            a.next_bits <<= code_len;
            a.extra_bit_count -=
                i32::try_from(code_len).expect("LZX code lengths are at most 16 bits");

            if a.extra_bit_count < 0 {
                // SAFETY: INPUT_GUARD ensures byte_pos + 2 <= data_len.
                unsafe { refill_unchecked(data, &mut a) };
            }

            if symbol < 256 {
                // SAFETY: OUTPUT_GUARD ensures out_pos < block_end
                // <= output.len().
                unsafe {
                    *output.get_unchecked_mut(out_pos) = literal_byte(symbol);
                }
                out_pos += 1;
            } else {
                // Inline match decode — no &mut self in the hot loop.
                let match_code = (symbol - 256) as usize;
                let position_slot = match_code / LEN_HEADER_COUNT;
                let length_header = match_code % LEN_HEADER_COUNT;

                let length = if length_header < 7 {
                    length_header + MIN_MATCH_LEN
                } else {
                    let (len_sym, len_code_len) = len_tbl.decode(a.next_bits);
                    a.next_bits <<= len_code_len;
                    a.extra_bit_count -=
                        i32::try_from(len_code_len).expect("LZX code lengths are at most 16 bits");
                    if a.extra_bit_count < 0 {
                        unsafe { refill_unchecked(data, &mut a) };
                    }
                    7 + len_sym as usize + MIN_MATCH_LEN
                };

                let offset = match position_slot {
                    0 => r0 as usize,
                    1 => {
                        core::mem::swap(&mut r0, &mut r1);
                        r0 as usize
                    }
                    2 => {
                        core::mem::swap(&mut r0, &mut r2);
                        r0 as usize
                    }
                    _ => {
                        let off = read_offset_fast(position_slot, aligned_tbl, data, &mut a);
                        r2 = r1;
                        r1 = r0;
                        r0 = u32::try_from(off)
                            .expect("LZX offsets are bounded by the 32 KiB window");
                        off
                    }
                };

                if offset > out_pos {
                    self.out_pos = out_pos;
                    self.r0 = r0;
                    self.r1 = r1;
                    self.r2 = r2;
                    return Err(err_match_offset_exceeds(a.byte_pos, offset, out_pos));
                }

                // SAFETY: offset <= out_pos (checked above);
                // OUTPUT_GUARD >= max match length, so
                // out_pos + length <= block_end <= output.len().
                unsafe {
                    crate::simd::copy_match_fast(output, out_pos, offset, length);
                }
                out_pos += length;
            }
        }

        // Write back locals before slow path.
        self.out_pos = out_pos;
        self.r0 = r0;
        self.r1 = r1;
        self.r2 = r2;

        // ---- Slow path: full bounds checking ----
        while self.out_pos < block_end {
            let (symbol, code_len) = main_tbl.decode(a.next_bits);

            a.next_bits <<= code_len;
            a.extra_bit_count -=
                i32::try_from(code_len).expect("LZX code lengths are at most 16 bits");

            if a.extra_bit_count < 0 {
                refill_checked(data, &mut a);
            }

            if symbol < 256 {
                if self.out_pos >= output.len() {
                    return Err(err_output_too_small(self.out_pos + 1, output.len()));
                }
                output[self.out_pos] = literal_byte(symbol);
                self.out_pos += 1;
            } else {
                let (offset, length) =
                    self.decode_match_slow(symbol, len_tbl, aligned_tbl, data, &mut a)?;

                copy_match(output, self.out_pos, offset, length, block_end)?;
                self.out_pos += length;
            }
        }

        // Restore BitReader from accumulator state.
        let (new_reader, new_base) = restore_reader(self.input, &a);
        self.reader = new_reader;
        self.reader_base = new_base;

        Ok(())
    }

    /// Slow-path match decode with full bounds checking.
    fn decode_match_slow(
        &mut self,
        symbol: u16,
        len_tbl: &LzxDecodeTable,
        aligned_tbl: Option<&LzxDecodeTable>,
        data: &[u8],
        a: &mut BitAccum,
    ) -> Result<(usize, usize)> {
        let match_code = (symbol - 256) as usize;
        let position_slot = match_code / LEN_HEADER_COUNT;
        let length_header = match_code % LEN_HEADER_COUNT;

        let length = if length_header < 7 {
            length_header + MIN_MATCH_LEN
        } else {
            let (len_sym, len_code_len) = len_tbl.decode(a.next_bits);
            a.next_bits <<= len_code_len;
            a.extra_bit_count -=
                i32::try_from(len_code_len).expect("LZX code lengths are at most 16 bits");
            if a.extra_bit_count < 0 {
                refill_checked(data, a);
            }
            7 + len_sym as usize + MIN_MATCH_LEN
        };

        let offset = self.decode_offset_slow(position_slot, aligned_tbl, data, a)?;

        if offset > self.out_pos {
            return Err(err_match_offset_exceeds(a.byte_pos, offset, self.out_pos));
        }

        Ok((offset, length))
    }

    /// Slow-path offset decode with checked refills.
    fn decode_offset_slow(
        &mut self,
        position_slot: usize,
        aligned_tbl: Option<&LzxDecodeTable>,
        data: &[u8],
        a: &mut BitAccum,
    ) -> Result<usize> {
        match position_slot {
            0 => Ok(self.r0 as usize),
            1 => {
                let offset = core::mem::replace(&mut self.r1, self.r0);
                self.r0 = offset;
                Ok(offset as usize)
            }
            2 => {
                let offset = core::mem::replace(&mut self.r2, self.r0);
                self.r0 = offset;
                Ok(offset as usize)
            }
            _ => {
                let offset = read_offset_slow(position_slot, aligned_tbl, data, a)?;
                self.r2 = self.r1;
                self.r1 = self.r0;
                self.r0 =
                    u32::try_from(offset).expect("LZX offsets are bounded by the 32 KiB window");
                Ok(offset)
            }
        }
    }
}

/// Read explicit offset in fast path (infallible).
///
/// # Safety invariants (no runtime checks needed):
/// - `position_slot < NUM_POSITION_SLOTS` is guaranteed because the
///   decode table only produces symbols `0..MAIN_TREE_SIZE`, giving
///   `position_slot` = (symbol - 256) / 8 in [0, 29].
/// - `raw >= OFFSET_ADJUSTMENT` is guaranteed for slot >= 3 because
///   `POSITION_BASE`[3] = 3 >= `OFFSET_ADJUSTMENT` = 2.
#[inline]
fn read_offset_fast(
    position_slot: usize,
    aligned_tbl: Option<&LzxDecodeTable>,
    data: &[u8],
    a: &mut BitAccum,
) -> usize {
    debug_assert!(position_slot < NUM_POSITION_SLOTS);

    // SAFETY: position_slot < NUM_POSITION_SLOTS (see doc above).
    let extra = u32::from(unsafe { *FOOTER_BITS.get_unchecked(position_slot) });
    let base = unsafe { *POSITION_BASE.get_unchecked(position_slot) };

    let verbatim_bits;
    let aligned_bits;

    if extra >= 3 {
        if let Some(atbl) = aligned_tbl {
            let vb_count = extra - 3;
            let vb = if vb_count > 0 {
                let v = a.next_bits >> (32 - vb_count);
                a.next_bits <<= vb_count;
                a.extra_bit_count -=
                    i32::try_from(vb_count).expect("LZX offset fields use at most 17 bits");
                if a.extra_bit_count < 0 {
                    // SAFETY: INPUT_GUARD headroom.
                    unsafe { refill_unchecked(data, a) };
                }
                v
            } else {
                0
            };
            verbatim_bits = vb << 3;

            let (aligned_sym, aligned_len) = atbl.decode(a.next_bits);
            a.next_bits <<= aligned_len;
            a.extra_bit_count -=
                i32::try_from(aligned_len).expect("aligned-tree codes use at most seven bits");
            if a.extra_bit_count < 0 {
                unsafe { refill_unchecked(data, a) };
            }
            aligned_bits = u32::from(aligned_sym);
        } else {
            let v = a.next_bits >> (32 - extra);
            a.next_bits <<= extra;
            a.extra_bit_count -=
                i32::try_from(extra).expect("LZX offset fields use at most 17 bits");
            if a.extra_bit_count < 0 {
                unsafe { refill_unchecked(data, a) };
            }
            verbatim_bits = v;
            aligned_bits = 0;
        }
    } else if extra > 0 {
        let v = a.next_bits >> (32 - extra);
        a.next_bits <<= extra;
        a.extra_bit_count -= i32::try_from(extra).expect("LZX offset fields use at most 17 bits");
        if a.extra_bit_count < 0 {
            unsafe { refill_unchecked(data, a) };
        }
        verbatim_bits = v;
        aligned_bits = 0;
    } else {
        verbatim_bits = 0;
        aligned_bits = 0;
    }

    let raw = base + verbatim_bits + aligned_bits;
    debug_assert!(raw >= OFFSET_ADJUSTMENT);
    (raw - OFFSET_ADJUSTMENT) as usize
}

/// Read explicit offset in slow path (free function to reduce
/// argument count on the method).
fn read_offset_slow(
    position_slot: usize,
    aligned_tbl: Option<&LzxDecodeTable>,
    data: &[u8],
    a: &mut BitAccum,
) -> Result<usize> {
    if position_slot >= NUM_POSITION_SLOTS {
        return Err(err_position_slot_exceeds(a.byte_pos, position_slot));
    }

    let extra = u32::from(FOOTER_BITS[position_slot]);
    let base = POSITION_BASE[position_slot];

    let verbatim_bits;
    let aligned_bits;

    if extra >= 3 {
        if let Some(atbl) = aligned_tbl {
            let vb_count = extra - 3;
            let vb = if vb_count > 0 {
                let v = a.next_bits >> (32 - vb_count);
                a.next_bits <<= vb_count;
                a.extra_bit_count -=
                    i32::try_from(vb_count).expect("LZX offset fields use at most 17 bits");
                if a.extra_bit_count < 0 {
                    refill_checked(data, a);
                }
                v
            } else {
                0
            };
            verbatim_bits = vb << 3;

            let (aligned_sym, aligned_len) = atbl.decode(a.next_bits);
            a.next_bits <<= aligned_len;
            a.extra_bit_count -=
                i32::try_from(aligned_len).expect("aligned-tree codes use at most seven bits");
            if a.extra_bit_count < 0 {
                refill_checked(data, a);
            }
            aligned_bits = u32::from(aligned_sym);
        } else {
            let v = a.next_bits >> (32 - extra);
            a.next_bits <<= extra;
            a.extra_bit_count -=
                i32::try_from(extra).expect("LZX offset fields use at most 17 bits");
            if a.extra_bit_count < 0 {
                refill_checked(data, a);
            }
            verbatim_bits = v;
            aligned_bits = 0;
        }
    } else if extra > 0 {
        let v = a.next_bits >> (32 - extra);
        a.next_bits <<= extra;
        a.extra_bit_count -= i32::try_from(extra).expect("LZX offset fields use at most 17 bits");
        if a.extra_bit_count < 0 {
            refill_checked(data, a);
        }
        verbatim_bits = v;
        aligned_bits = 0;
    } else {
        verbatim_bits = 0;
        aligned_bits = 0;
    }

    let raw = base + verbatim_bits + aligned_bits;
    if raw < OFFSET_ADJUSTMENT {
        return Err(err_offset_below_minimum(a.byte_pos, raw));
    }
    Ok((raw - OFFSET_ADJUSTMENT) as usize)
}

// -- Uncompressed block decoding -------------------------------------------

impl DecompressCtx<'_> {
    /// Decode an uncompressed block: align, read R0/R1/R2, copy raw
    /// bytes, and re-align if needed.
    fn decode_uncompressed(&mut self, output: &mut [u8], block_end: usize) -> Result<()> {
        self.reader.align_to_u16();

        self.r0 = self.reader.read_u32_le()?;
        self.r1 = self.reader.read_u32_le()?;
        self.r2 = self.reader.read_u32_le()?;

        let count = block_end - self.out_pos;
        self.copy_raw_bytes(output, count)?;

        // Re-align to a 16-bit boundary if the absolute byte
        // position is odd after reading the raw data.
        let abs_pos = self.reader_base + self.reader.position();
        if !abs_pos.is_multiple_of(2) {
            let _ = self.reader.read_raw_byte()?;
        }

        Ok(())
    }

    /// Copy `count` raw bytes from the input stream to the output
    /// using bulk copy after a single bounds validation.
    fn copy_raw_bytes(&mut self, output: &mut [u8], count: usize) -> Result<()> {
        let out_end = self.out_pos + count;
        if out_end > output.len() {
            return Err(err_output_too_small(out_end, output.len()));
        }

        // After align_to_u16, the reader is in raw byte mode.
        // Compute the absolute position in self.input.
        let abs_pos = self.reader_base + self.reader.position();
        if abs_pos + count > self.input.len() {
            return Err(err_input_truncated(
                abs_pos,
                count,
                self.input.len().saturating_sub(abs_pos),
            ));
        }

        output[self.out_pos..out_end].copy_from_slice(&self.input[abs_pos..abs_pos + count]);
        self.out_pos = out_end;

        // Create a new reader past the copied data.
        let new_pos = abs_pos + count;
        self.reader = BitReader::new(&self.input[new_pos..]);
        self.reader.set_zero_fill(true);
        self.reader_base = new_pos;

        Ok(())
    }
}

/// Copy `length` bytes from `output[out_pos - offset..]` to
/// `output[out_pos..]`, using chunked copies where possible.
#[inline]
fn copy_match(
    output: &mut [u8],
    out_pos: usize,
    offset: usize,
    length: usize,
    limit: usize,
) -> Result<()> {
    if out_pos + length > limit {
        return Err(err_output_too_small(out_pos + length, limit));
    }
    let src_start = out_pos - offset;
    if offset >= length {
        output.copy_within(src_start..src_start + length, out_pos);
    } else if offset == 1 {
        output[out_pos] = output[src_start];
        let mut filled = 1;
        while filled < length {
            let chunk = filled.min(length - filled);
            output.copy_within(out_pos..out_pos + chunk, out_pos + filled);
            filled += chunk;
        }
    } else if offset >= 8 {
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
    } else {
        for i in 0..length {
            output[out_pos + i] = output[src_start + i];
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../decompress_tests/mod.rs"]
mod tests;
