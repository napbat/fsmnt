//! LZX WIM-variant decompression.
//!
//! Implements the LZX algorithm as used in WIM archives and WOF
//! (Windows Overlay Filter). This is NOT CAB LZX or LZXD delta.
//!
//! Each chunk is independently decompressible with a 32 KB window.
//! After decompression, E8 post-processing reverses x86 CALL target
//! pre-processing applied before compression.
#![allow(unsafe_code)]

use alloc::format;

use crate::bitstream::BitReader;
use crate::e8::undo_e8_preprocessing;
use crate::huffman::{
    HuffmanTable, assign_canonical_codes, count_per_length, validate_code_space, validate_lengths,
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
const MAIN_TABLE_BITS: u32 = 11;
const LENGTH_TABLE_BITS: u32 = 9;
const ALIGNED_TABLE_BITS: u32 = 7;
#[allow(
    dead_code,
    reason = "used by pretree via HuffmanTable::from_code_lengths"
)]
const PRECODE_TABLE_BITS: u32 = 6;

/// Maximum code length in LZX.
#[allow(dead_code, reason = "documents the spec constraint")]
const MAX_CODE_BITS: u32 = 16;

/// Maximum root table size (main tree at 11 bits).
const MAX_ROOT_SIZE: usize = 1 << MAIN_TABLE_BITS; // 2048

/// Maximum overflow entries. Upper bound: each root overflow slot
/// spawns a subtable of at most 2^MAX_SUBTABLE_BITS entries.
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

/// Decode table with flat subtables for overflow codes.
///
/// Root table: `2^table_bits` entries (direct lookup).
/// Overflow: flat subtables indexed by remaining bits after root lookup.
/// Worst-case decode = exactly 2 array lookups (no loops, no tree walk).
struct LzxDecodeTable {
    /// Root direct-lookup table.
    direct: [PackedEntry; MAX_ROOT_SIZE],
    /// Flat subtables for codes longer than `table_bits`.
    overflow: [PackedEntry; MAX_OVERFLOW],
    /// Number of overflow entries allocated.
    overflow_len: u16,
    /// Root table bits for this instance.
    table_bits: u32,
    /// Per-root-slot subtable bit width. Only entries where
    /// `direct[i] & 0xF == 0` are meaningful. Stored separately
    /// to keep PackedEntry at 16 bits.
    subtable_bits_map: [u8; MAX_ROOT_SIZE],
}

impl LzxDecodeTable {
    /// Build a decode table from code lengths with the given root table width.
    fn build(lengths: &[u8], table_bits: u32) -> Result<Self> {
        debug_assert!((1..=11).contains(&table_bits));
        validate_lengths(lengths)?;
        let counts = count_per_length(lengths);
        validate_code_space(&counts)?;
        let codes = assign_canonical_codes(lengths, &counts);

        let root_size = 1usize << table_bits;

        let mut tbl = Self {
            direct: [0u16; MAX_ROOT_SIZE],
            overflow: [0u16; MAX_OVERFLOW],
            overflow_len: 0,
            table_bits,
            subtable_bits_map: [0u8; MAX_ROOT_SIZE],
        };

        // First pass: determine which root prefixes need subtables
        // and how many extra bits each needs.
        let mut max_extra_per_prefix = [0u8; MAX_ROOT_SIZE];
        for &(code, len) in &codes {
            if len == 0 {
                continue;
            }
            let len_u32 = u32::from(len);
            if len_u32 > table_bits {
                let prefix = (code >> (len_u32 - table_bits)) as usize;
                let extra = (len_u32 - table_bits) as u8;
                if extra > max_extra_per_prefix[prefix] {
                    max_extra_per_prefix[prefix] = extra;
                }
            }
        }

        // Allocate subtables for each prefix that needs one.
        // subtable_offset[prefix] = starting index in overflow[].
        let mut subtable_offset = [0u16; MAX_ROOT_SIZE];
        for prefix in 0..root_size {
            let extra = max_extra_per_prefix[prefix];
            if extra > 0 {
                let sub_size = 1usize << extra;
                let offset = tbl.overflow_len as usize;
                if offset + sub_size > MAX_OVERFLOW {
                    return Err(Error::InvalidHuffmanTable {
                        reason: "LZX overflow table exceeds capacity",
                    });
                }
                subtable_offset[prefix] = offset as u16;
                tbl.direct[prefix] = (offset as u16) << 4; // code_len=0 → subtable
                tbl.subtable_bits_map[prefix] = extra;
                tbl.overflow_len += sub_size as u16;
            }
        }

        // Second pass: populate direct table and subtables.
        // Track first valid direct entry for filling unused slots.
        let mut first_direct_entry: Option<PackedEntry> = None;

        for (sym, &(code, len)) in codes.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let sym = sym as u16;
            let len_u32 = u32::from(len);

            if len_u32 <= table_bits {
                // Short code: fill all suffix positions in root table.
                let pad = table_bits - len_u32;
                let base = (code << pad) as usize;
                let count = 1usize << pad;
                let entry = (sym << 4) | (len as u16);
                if first_direct_entry.is_none() {
                    first_direct_entry = Some(entry);
                }
                // Fill entries. For short codes (large pad), this is
                // the hot path during table build.
                let dest = &mut tbl.direct[base..base + count];
                dest.fill(entry);
            } else {
                // Long code: insert into the flat subtable.
                let prefix = (code >> (len_u32 - table_bits)) as usize;
                let sub_bits = max_extra_per_prefix[prefix] as u32;
                let offset = subtable_offset[prefix] as usize;

                // Suffix within the subtable, padded to subtable width.
                let suffix_bits = len_u32 - table_bits;
                let suffix = code & ((1 << suffix_bits) - 1);
                let pad = sub_bits - suffix_bits;
                let sub_base = (suffix << pad) as usize;
                let sub_count = 1usize << pad;
                let entry = (sym << 4) | (len as u16);

                let dest = &mut tbl.overflow[offset + sub_base..offset + sub_base + sub_count];
                dest.fill(entry);
            }
        }

        // Fill unused root entries with a valid entry (avoids
        // undefined behavior on malformed but parseable streams).
        if let Some(fill) = first_direct_entry {
            for (slot, &extra) in tbl.direct[..root_size]
                .iter_mut()
                .zip(&max_extra_per_prefix[..root_size])
            {
                if *slot == 0 && extra == 0 {
                    *slot = fill;
                }
            }
        }

        Ok(tbl)
    }

    /// Decode one symbol from the top bits of `next_bits`.
    /// Returns `(symbol, code_len)`.
    ///
    /// Worst case: exactly 2 array lookups (root + subtable).
    #[inline(always)]
    fn decode(&self, next_bits: u32) -> (u16, u32) {
        let index = (next_bits >> (32 - self.table_bits)) as usize;
        // SAFETY: index = next_bits >> (32 - table_bits).
        // For table_bits <= 11, index < 2048 = MAX_ROOT_SIZE.
        let entry = unsafe { *self.direct.get_unchecked(index) };
        let code_len = (entry & 0xF) as u32;
        if code_len != 0 {
            return (entry >> 4, code_len);
        }
        // Subtable lookup: one more indexed load, no loop.
        self.decode_subtable(next_bits, index, entry)
    }

    #[inline(always)]
    fn decode_subtable(
        &self,
        next_bits: u32,
        root_index: usize,
        root_entry: PackedEntry,
    ) -> (u16, u32) {
        let sub_offset = (root_entry >> 4) as usize;
        // SAFETY: subtable_bits_map has MAX_ROOT_SIZE entries,
        // root_index < MAX_ROOT_SIZE (checked by caller).
        let sub_bits = unsafe { *self.subtable_bits_map.get_unchecked(root_index) } as u32;
        // Extract the next `sub_bits` after the root bits.
        let sub_index = ((next_bits << self.table_bits) >> (32 - sub_bits)) as usize;
        // SAFETY: sub_offset + sub_index < overflow_len (guaranteed by build).
        let sub_entry = unsafe { *self.overflow.get_unchecked(sub_offset + sub_index) };
        (sub_entry >> 4, (sub_entry & 0xF) as u32)
    }
}

// ---------------------------------------------------------------------------
// Cold error constructors
// ---------------------------------------------------------------------------

#[cold]
#[inline(never)]
fn err_invalid_data(offset: usize, detail: &str) -> Error {
    Error::InvalidData {
        offset,
        reason: alloc::string::String::from(detail),
    }
}

#[cold]
#[inline(never)]
fn err_output_too_small(needed: usize, available: usize) -> Error {
    Error::OutputTooSmall {
        expected: needed,
        actual: available,
    }
}

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
fn err_match_offset_exceeds(offset: usize, match_offset: usize, out_pos: usize) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "LZX match offset {match_offset} exceeds \
             output position {out_pos}",
        ),
    }
}

#[cold]
#[inline(never)]
fn err_position_slot_exceeds(offset: usize, slot: usize) -> Error {
    Error::InvalidData {
        offset,
        reason: format!(
            "LZX position slot {slot} exceeds maximum {}",
            NUM_POSITION_SLOTS - 1,
        ),
    }
}

#[cold]
#[inline(never)]
fn err_offset_below_minimum(offset: usize, raw: u32) -> Error {
    Error::InvalidData {
        offset,
        reason: format!("LZX computed offset {raw} below minimum"),
    }
}

// ---------------------------------------------------------------------------
// Manual bit accumulator state
// ---------------------------------------------------------------------------

/// Manual 32-bit bit accumulator matching BitReader's MSB-first,
/// 16-bit LE word refill semantics.
///
/// `next_bits` holds buffered bits MSB-aligned in a u32. After
/// consuming N bits (shift left + decrement extra_bit_count),
/// a refill loads one 16-bit LE word when extra_bit_count < 0.
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
            return Ok(WINDOW_SIZE as u32);
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
            *len = self.reader.read_bits(ALIGNED_CODE_BITS)? as u8;
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
            *pl = self.reader.read_bits(PRE_TREE_CODE_BITS)? as u8;
        }
        let pre_table = HuffmanTable::from_code_lengths(&pre_lens, 6)?;
        decode_code_lengths(&mut self.reader, &pre_table, lens)
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
    pre_table: &HuffmanTable,
    lens: &mut [u8],
) -> Result<()> {
    let total = lens.len();
    let mut i = 0;

    while i < total {
        let sym = pre_table.decode_symbol(reader)? as u32;

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
            let delta_sym = pre_table.decode_symbol(reader)? as u32;
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

/// Compute the logical bit position from BitReader state.
/// The reader has loaded words up to byte_pos, and has
/// bits_remaining bits buffered. The logical position (next
/// bit to decode) is byte_pos*8 - bits_remaining.
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
    let skip_bits = (bit_pos % 16) as u32;

    // Load up to two 16-bit LE words (32 bits).
    let mut next_bits: u32 = 0;
    let mut byte_pos = word_byte_pos;
    let mut loaded_bits: i32 = 0;

    for _ in 0..2 {
        if byte_pos + 2 <= input.len() {
            let w = u16::from_le_bytes([input[byte_pos], input[byte_pos + 1]]) as u32;
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
    let extra_bit_count = loaded_bits - 16 - skip_bits as i32;

    let mut a = BitAccum {
        next_bits,
        extra_bit_count,
        byte_pos,
    };

    // Top off if below the threshold.
    if a.extra_bit_count < 0 && a.byte_pos + 2 <= input.len() {
        let w = u16::from_le_bytes([input[a.byte_pos], input[a.byte_pos + 1]]) as u32;
        a.byte_pos += 2;
        a.next_bits |= w << ((-a.extra_bit_count) as u32);
        a.extra_bit_count += 16;
    }

    a
}

/// Restore BitReader state from a 64-bit accumulator position.
/// Creates a new BitReader pointing at the correct position in
/// the input and pre-loads any partially consumed word.
/// Returns `(reader, base_offset)` where base_offset is the
/// byte offset into `input` where the reader's sub-slice starts.
fn restore_reader<'a>(input: &'a [u8], accum: &BitAccum) -> (BitReader<'a>, usize) {
    let valid_bits = (accum.extra_bit_count + 16).max(0) as u32;
    let end_bit_pos = accum.byte_pos * 8 - valid_bits as usize;
    let end_word_byte = (end_bit_pos / 16) * 2;
    let end_skip = (end_bit_pos % 16) as u32;

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
#[inline(always)]
fn refill_checked(data: &[u8], accum: &mut BitAccum) -> Result<()> {
    if accum.byte_pos + 2 <= data.len() {
        let w = u16::from_le_bytes([data[accum.byte_pos], data[accum.byte_pos + 1]]) as u32;
        accum.byte_pos += 2;
        accum.next_bits |= w << ((-accum.extra_bit_count) as u32);
        accum.extra_bit_count += 16;
    } else {
        // Zero-fill: no more data.
        accum.extra_bit_count += 16;
    }
    Ok(())
}

/// Refill the accumulator using unchecked reads.
/// Loads one 16-bit LE word.
///
/// SAFETY: caller must ensure `accum.byte_pos + 2 <= data.len()`.
#[inline(always)]
unsafe fn refill_unchecked(data: &[u8], accum: &mut BitAccum) {
    let w = unsafe { crate::raw::read_u16_le(data, accum.byte_pos) } as u32;
    accum.byte_pos += 2;
    accum.next_bits |= w << ((-accum.extra_bit_count) as u32);
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
            a.extra_bit_count -= code_len as i32;

            if a.extra_bit_count < 0 {
                // SAFETY: INPUT_GUARD ensures byte_pos + 2 <= data_len.
                unsafe { refill_unchecked(data, &mut a) };
            }

            if symbol < 256 {
                // SAFETY: OUTPUT_GUARD ensures out_pos < block_end
                // <= output.len().
                unsafe { *output.get_unchecked_mut(out_pos) = symbol as u8 };
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
                    a.extra_bit_count -= len_code_len as i32;
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
                        r0 = off as u32;
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
            a.extra_bit_count -= code_len as i32;

            if a.extra_bit_count < 0 {
                refill_checked(data, &mut a)?;
            }

            if symbol < 256 {
                if self.out_pos >= output.len() {
                    return Err(err_output_too_small(self.out_pos + 1, output.len()));
                }
                output[self.out_pos] = symbol as u8;
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
            a.extra_bit_count -= len_code_len as i32;
            if a.extra_bit_count < 0 {
                refill_checked(data, a)?;
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
                self.r0 = offset as u32;
                Ok(offset)
            }
        }
    }
}

/// Read explicit offset in fast path (infallible).
///
/// # Safety invariants (no runtime checks needed):
/// - `position_slot < NUM_POSITION_SLOTS` is guaranteed because the
///   decode table only produces symbols 0..MAIN_TREE_SIZE, giving
///   position_slot = (symbol - 256) / 8 in [0, 29].
/// - `raw >= OFFSET_ADJUSTMENT` is guaranteed for slot >= 3 because
///   POSITION_BASE[3] = 3 >= OFFSET_ADJUSTMENT = 2.
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
                a.extra_bit_count -= vb_count as i32;
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
            a.extra_bit_count -= aligned_len as i32;
            if a.extra_bit_count < 0 {
                unsafe { refill_unchecked(data, a) };
            }
            aligned_bits = aligned_sym as u32;
        } else {
            let v = a.next_bits >> (32 - extra);
            a.next_bits <<= extra;
            a.extra_bit_count -= extra as i32;
            if a.extra_bit_count < 0 {
                unsafe { refill_unchecked(data, a) };
            }
            verbatim_bits = v;
            aligned_bits = 0;
        }
    } else if extra > 0 {
        let v = a.next_bits >> (32 - extra);
        a.next_bits <<= extra;
        a.extra_bit_count -= extra as i32;
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
                a.extra_bit_count -= vb_count as i32;
                if a.extra_bit_count < 0 {
                    refill_checked(data, a)?;
                }
                v
            } else {
                0
            };
            verbatim_bits = vb << 3;

            let (aligned_sym, aligned_len) = atbl.decode(a.next_bits);
            a.next_bits <<= aligned_len;
            a.extra_bit_count -= aligned_len as i32;
            if a.extra_bit_count < 0 {
                refill_checked(data, a)?;
            }
            aligned_bits = aligned_sym as u32;
        } else {
            let v = a.next_bits >> (32 - extra);
            a.next_bits <<= extra;
            a.extra_bit_count -= extra as i32;
            if a.extra_bit_count < 0 {
                refill_checked(data, a)?;
            }
            verbatim_bits = v;
            aligned_bits = 0;
        }
    } else if extra > 0 {
        let v = a.next_bits >> (32 - extra);
        a.next_bits <<= extra;
        a.extra_bit_count -= extra as i32;
        if a.extra_bit_count < 0 {
            refill_checked(data, a)?;
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
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::test_bitwriter::BitWriter;

    // -- Canonical code assignment ----------------------------------------

    fn assign_codes(lengths: &[u8]) -> Vec<(u32, u8)> {
        let mut counts = [0u32; 17];
        for &len in lengths {
            if len > 0 && (len as usize) < counts.len() {
                counts[len as usize] += 1;
            }
        }
        let mut next_code = [0u32; 17];
        let mut code: u32 = 0;
        for bits in 1..17usize {
            code = (code + counts[bits - 1]) << 1;
            next_code[bits] = code;
        }
        let mut codes = vec![(0u32, 0u8); lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            let l = len as usize;
            if l > 0 && l < 17 {
                codes[sym] = (next_code[l], len);
                next_code[l] += 1;
            }
        }
        codes
    }

    fn encode_symbol(w: &mut BitWriter, codes: &[(u32, u8)], sym: usize) {
        let (code, len) = codes[sym];
        w.write_bits(code, u32::from(len));
    }

    // -- Pre-tree and tree encoding helpers --------------------------------

    /// Encode code lengths via a pre-tree, writing to the BitWriter.
    /// `prev` contains previous block's lengths (or zeros for first block).
    /// This writes the 20 x 4-bit pre-tree lengths, then the symbols.
    fn write_code_lengths_simple(w: &mut BitWriter, target_lens: &[u8], prev_lens: &[u8]) {
        // For simplicity in tests, we only use symbols 0-16 (direct
        // delta encoding). Compute deltas.
        let mut deltas = Vec::with_capacity(target_lens.len());
        for (i, &target) in target_lens.iter().enumerate() {
            let old = if i < prev_lens.len() { prev_lens[i] } else { 0 };
            let delta_sym =
                ((old as u32 + NUM_CODE_LENGTHS - target as u32) % NUM_CODE_LENGTHS) as u8;
            deltas.push(delta_sym);
        }

        // Collect unique delta symbols and assign short code lengths.
        // Use a uniform tree over all used delta symbols.
        let mut used = [false; PRE_TREE_SIZE];
        for &d in &deltas {
            used[d as usize] = true;
        }
        let used_count = used.iter().filter(|&&u| u).count();
        let code_len = if used_count <= 1 {
            1u8
        } else {
            // Smallest power of 2 >= used_count
            let mut bits = 1u8;
            while (1usize << bits) < used_count {
                bits += 1;
            }
            bits
        };

        // Assign code lengths: all used symbols get `code_len`.
        let mut pre_lens = [0u8; PRE_TREE_SIZE];
        for (i, &u) in used.iter().enumerate() {
            if u {
                pre_lens[i] = code_len;
            }
        }

        // Write the 20 pre-tree code lengths (4 bits each).
        for &pl in &pre_lens {
            w.write_bits(u32::from(pl), PRE_TREE_CODE_BITS);
        }

        // Build codes for the pre-tree.
        let pre_codes = assign_codes(&pre_lens);

        // Write each delta symbol using the pre-tree.
        for &d in &deltas {
            encode_symbol(w, &pre_codes, d as usize);
        }
    }

    /// Write a complete verbatim block header and body for the given
    /// literal bytes.
    fn build_verbatim_literals_block(literals: &[u8]) -> Vec<u8> {
        let mut w = BitWriter::new();

        // Block type = 1 (verbatim), 3 bits.
        w.write_bits(BLOCK_VERBATIM, 3);
        // Default block size flag = 1 (32768).
        w.write_bits(1, 1);

        // Build a main tree where all used literal symbols have the
        // same code length. The main tree has 496 symbols.
        let mut main_lens = [0u8; MAIN_TREE_SIZE];

        // Collect unique literals.
        let mut used_lits = [false; 256];
        for &b in literals {
            used_lits[b as usize] = true;
        }
        let lit_count = used_lits.iter().filter(|&&u| u).count().max(1);

        // Assign uniform code length.
        let code_len = {
            let mut bits = 1u8;
            while (1usize << bits) < lit_count {
                bits += 1;
            }
            bits
        };
        for (i, &u) in used_lits.iter().enumerate() {
            if u {
                main_lens[i] = code_len;
            }
        }

        // Write main tree: first half (0..256), second half (256..496).
        let prev_main = [0u8; MAIN_TREE_SIZE];
        write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
        write_code_lengths_simple(
            &mut w,
            &main_lens[256..MAIN_TREE_SIZE],
            &prev_main[256..MAIN_TREE_SIZE],
        );

        // Length tree: all zeros is fine since we have no matches.
        // But we must encode it. Use symbol 17 (run of zeros).
        // Actually, the length tree has 249 elements. We need at
        // least one non-zero. Let's just give symbol 0 a code length
        // of 1 for a valid single-symbol tree.
        let mut length_lens = [0u8; LENGTH_TREE_SIZE];
        length_lens[0] = 1;
        let prev_length = [0u8; LENGTH_TREE_SIZE];
        write_code_lengths_simple(&mut w, &length_lens, &prev_length);

        // Now encode the literal symbols.
        let main_codes = assign_codes(&main_lens);
        for &b in literals {
            encode_symbol(&mut w, &main_codes, b as usize);
        }

        w.finish(2)
    }

    /// Build a verbatim block with literals and matches.
    /// `ops` is a sequence of operations to encode.
    fn build_verbatim_block_with_matches(
        ops: &[TestOp],
        prev_main: &[u8; MAIN_TREE_SIZE],
        prev_length: &[u8; LENGTH_TREE_SIZE],
    ) -> (Vec<u8>, [u8; MAIN_TREE_SIZE], [u8; LENGTH_TREE_SIZE]) {
        let mut w = BitWriter::new();

        // Block type = 1 (verbatim).
        w.write_bits(BLOCK_VERBATIM, 3);
        // Default block size.
        w.write_bits(1, 1);

        // Determine which main tree and length tree symbols we need.
        let mut main_used = [false; MAIN_TREE_SIZE];
        let mut length_used = [false; LENGTH_TREE_SIZE];

        for op in ops {
            match op {
                TestOp::Literal(b) => {
                    main_used[*b as usize] = true;
                }
                TestOp::Match {
                    position_slot,
                    length_header,
                    length_extra,
                    ..
                } => {
                    let main_sym = 256 + position_slot * 8 + length_header;
                    main_used[main_sym] = true;
                    if *length_header == 7 {
                        length_used[*length_extra] = true;
                    }
                }
            }
        }

        // Assign code lengths for used symbols.
        let mut main_lens = [0u8; MAIN_TREE_SIZE];
        let main_count = main_used.iter().filter(|&&u| u).count().max(1);
        let main_cl = {
            let mut bits = 1u8;
            while (1usize << bits) < main_count {
                bits += 1;
            }
            bits
        };
        for (i, &u) in main_used.iter().enumerate() {
            if u {
                main_lens[i] = main_cl;
            }
        }

        let mut length_lens = [0u8; LENGTH_TREE_SIZE];
        let len_count = length_used.iter().filter(|&&u| u).count();
        if len_count > 0 {
            let len_cl = {
                let mut bits = 1u8;
                while (1usize << bits) < len_count {
                    bits += 1;
                }
                bits
            };
            for (i, &u) in length_used.iter().enumerate() {
                if u {
                    length_lens[i] = len_cl;
                }
            }
        } else {
            // Need at least one valid symbol.
            length_lens[0] = 1;
        }

        // Write trees.
        write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
        write_code_lengths_simple(
            &mut w,
            &main_lens[256..MAIN_TREE_SIZE],
            &prev_main[256..MAIN_TREE_SIZE],
        );
        write_code_lengths_simple(&mut w, &length_lens, prev_length);

        // Encode operations.
        let main_codes = assign_codes(&main_lens);
        let length_codes = assign_codes(&length_lens);

        for op in ops {
            match op {
                TestOp::Literal(b) => {
                    encode_symbol(&mut w, &main_codes, *b as usize);
                }
                TestOp::Match {
                    position_slot,
                    length_header,
                    length_extra,
                    footer_value,
                } => {
                    let main_sym = 256 + position_slot * 8 + length_header;
                    encode_symbol(&mut w, &main_codes, main_sym);

                    if *length_header == 7 {
                        encode_symbol(&mut w, &length_codes, *length_extra);
                    }

                    // Write footer bits for position slot.
                    if *position_slot >= 3 {
                        let extra = u32::from(FOOTER_BITS[*position_slot]);
                        w.write_bits(*footer_value, extra);
                    }
                }
            }
        }

        (w.finish(2), main_lens, length_lens)
    }

    #[derive(Clone)]
    enum TestOp {
        Literal(u8),
        Match {
            position_slot: usize,
            length_header: usize,
            length_extra: usize,
            footer_value: u32,
        },
    }

    // -- Uncompressed block builder ----------------------------------------

    fn build_uncompressed_block(data: &[u8], r0: u32, r1: u32, r2: u32) -> Vec<u8> {
        let mut w = BitWriter::new();
        // Block type = 3 (uncompressed), 3 bits.
        w.write_bits(BLOCK_UNCOMPRESSED, 3);
        // Non-default block size.
        w.write_bits(0, 1);
        w.write_bits(data.len() as u32, 16);

        // Flush the bitstream before writing raw bytes.
        let mut result = w.finish(2);
        // Remove the trailing padding from BitWriter::finish.
        result.truncate(result.len() - 4);

        // Align: the BitWriter already wrote full 16-bit words, so
        // byte_pos after align_to_u16 should be at the current position.
        // However, we need to ensure proper alignment. The data after
        // the bitstream should start at an even offset.
        if !result.len().is_multiple_of(2) {
            result.push(0);
        }

        // R0, R1, R2 as raw u32 LE.
        result.extend_from_slice(&r0.to_le_bytes());
        result.extend_from_slice(&r1.to_le_bytes());
        result.extend_from_slice(&r2.to_le_bytes());

        // Raw data bytes.
        result.extend_from_slice(data);

        // If odd count, add a padding byte.
        if !data.len().is_multiple_of(2) {
            result.push(0);
        }

        result
    }

    // -- Tests -------------------------------------------------------------

    #[test]
    fn uncompressed_block_passthrough() {
        let payload = b"Hello, LZX!";
        let input = build_uncompressed_block(payload, 1, 1, 1);
        let mut output = [0u8; 11];
        let n = decompress(&input, &mut output).expect("decompress failed");
        // E8 post-processing may modify data containing 0xE8, but
        // "Hello, LZX!" has no 0xE8 bytes so output should match.
        assert_eq!(n, 11);
        assert_eq!(&output[..n], payload);
    }

    #[test]
    fn verbatim_block_literals_only() {
        let literals = [0x41u8, 0x42, 0x43, 0x44]; // "ABCD"
        let input = build_verbatim_literals_block(&literals);
        let mut output = [0u8; 4];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 4);
        assert_eq!(&output[..4], b"ABCD");
    }

    #[test]
    fn verbatim_block_with_match() {
        // Write "ABCD", then a match that copies 4 bytes from offset 4.
        // Position slot 4 has base=4, footer_bits=1.
        // Offset = base + footer_value - 2 = 4 + 0 - 2 = 2.
        // Wait, we want offset=4. So 4 + footer_value - 2 = 4 →
        // footer_value = 2. But footer_bits for slot 4 is 1, max
        // value is 1. So slot 4 can encode offsets 2..3.
        //
        // For offset=4: 4 + 2 = 6 (stored). Slot 5: base=6,
        // footer_bits=1. 6 + footer - 2 = offset → 6+0-2=4. Yes!
        // Use position slot 5, footer_value=0.
        let ops = vec![
            TestOp::Literal(b'A'),
            TestOp::Literal(b'B'),
            TestOp::Literal(b'C'),
            TestOp::Literal(b'D'),
            TestOp::Match {
                position_slot: 5,
                length_header: 2, // length = 2 + 2 = 4
                length_extra: 0,
                footer_value: 0,
            },
        ];
        let prev_main = [0u8; MAIN_TREE_SIZE];
        let prev_length = [0u8; LENGTH_TREE_SIZE];
        let (input, _, _) = build_verbatim_block_with_matches(&ops, &prev_main, &prev_length);

        let mut output = [0u8; 8];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 8);
        assert_eq!(&output[..8], b"ABCDABCD");
    }

    #[test]
    fn aligned_offset_block() {
        // Build an aligned offset block. We need to construct one
        // manually since our test helpers only do verbatim.
        let mut w = BitWriter::new();

        // Block type = 2 (aligned), 3 bits.
        w.write_bits(BLOCK_ALIGNED, 3);
        // Default block size.
        w.write_bits(1, 1);

        // Aligned offset tree: 8 entries, 3 bits each.
        // Use uniform 3-bit codes for all 8 symbols.
        let aligned_lens = [3u8; ALIGNED_TREE_SIZE];
        for &al in &aligned_lens {
            w.write_bits(u32::from(al), ALIGNED_CODE_BITS);
        }

        // Main tree: we need literal 'X' (0x58) and a match symbol.
        // Use position slot 6 (base=8, footer=2): offset = 8+fb-2.
        // With aligned: read (2-3)=negative, so footer < 3 → read
        // directly. Actually footer_bits for slot 6 = 2 which is
        // < 3, so aligned tree isn't used for this slot.
        //
        // Use slot 7: base=12, footer=2. Still < 3.
        // Use slot 8: base=16, footer=3. Aligned IS used.
        // offset = 16 + (verbatim<<3) + aligned - 2
        // For offset=14: 16 + 0 + 0 - 2 = 14. Yes!
        //
        // We need 14 literal bytes first, then a match at offset 14.
        let mut ops = Vec::new();
        for i in 0..14u8 {
            ops.push(TestOp::Literal(b'A' + (i % 4)));
        }
        // Match: slot 8, length_header=2 (len=4), footer: verbatim
        // bits = 0 (0 bits since footer-3=0), aligned = 0.
        ops.push(TestOp::Match {
            position_slot: 8,
            length_header: 2,
            length_extra: 0,
            footer_value: 0, // Not used directly; handled below.
        });

        // Determine main/length tree symbols.
        let mut main_used = [false; MAIN_TREE_SIZE];
        let mut length_used = [false; LENGTH_TREE_SIZE];
        for op in &ops {
            match op {
                TestOp::Literal(b) => main_used[*b as usize] = true,
                TestOp::Match {
                    position_slot,
                    length_header,
                    length_extra,
                    ..
                } => {
                    main_used[256 + position_slot * 8 + length_header] = true;
                    if *length_header == 7 {
                        length_used[*length_extra] = true;
                    }
                }
            }
        }

        let mut main_lens = [0u8; MAIN_TREE_SIZE];
        let main_count = main_used.iter().filter(|&&u| u).count().max(1);
        let main_cl = {
            let mut bits = 1u8;
            while (1usize << bits) < main_count {
                bits += 1;
            }
            bits
        };
        for (i, &u) in main_used.iter().enumerate() {
            if u {
                main_lens[i] = main_cl;
            }
        }

        let mut length_lens = [0u8; LENGTH_TREE_SIZE];
        length_lens[0] = 1;

        let prev_main = [0u8; MAIN_TREE_SIZE];
        let prev_length = [0u8; LENGTH_TREE_SIZE];

        // Write main tree (two halves) and length tree.
        write_code_lengths_simple(&mut w, &main_lens[..256], &prev_main[..256]);
        write_code_lengths_simple(
            &mut w,
            &main_lens[256..MAIN_TREE_SIZE],
            &prev_main[256..MAIN_TREE_SIZE],
        );
        write_code_lengths_simple(&mut w, &length_lens, &prev_length);

        // Encode data.
        let main_codes = assign_codes(&main_lens);
        let aligned_codes = assign_codes(&aligned_lens);

        for op in &ops {
            match op {
                TestOp::Literal(b) => {
                    encode_symbol(&mut w, &main_codes, *b as usize);
                }
                TestOp::Match {
                    position_slot,
                    length_header,
                    length_extra,
                    ..
                } => {
                    let main_sym = 256 + position_slot * 8 + length_header;
                    encode_symbol(&mut w, &main_codes, main_sym);

                    if *length_header == 7 {
                        let length_codes_local = assign_codes(&length_lens);
                        encode_symbol(&mut w, &length_codes_local, *length_extra);
                    }

                    // Footer bits for slot 8: 3 bits.
                    // Aligned: read (3-3)=0 verbatim bits, then 3
                    // aligned bits.
                    // We want aligned_bits=0 → symbol 0.
                    encode_symbol(&mut w, &aligned_codes, 0);
                }
            }
        }

        let input = w.finish(2);
        let mut output = [0u8; 18]; // 14 + 4
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 18);
        // The match copies 4 bytes from offset 14 (the start).
        assert_eq!(&output[14..18], &output[0..4]);
    }

    #[test]
    fn repeat_offset_r0_r1_r2() {
        // Test the LRU repeat offset queue.
        // Write 8 bytes "ABCDABCD", then:
        //   Match slot 0 (R0): should copy from offset of last match
        //   Match slot 1 (R1): should swap R1↔R0
        //   Match slot 2 (R2): should rotate
        //
        // First, establish R0 = 4 by doing a match at offset 4.
        // Position slot 5: base=6, footer_bits=1, footer=0 → offset=4.
        // Then R0=4, R1=1, R2=1.
        //
        // Next, use slot 0 (R0=4): copy 2 bytes from offset 4.
        // R0 stays 4.
        //
        // Set R1 to something by doing another explicit match.
        // Position slot 3: base=3, footer_bits=0 → offset=3-2=1.
        // Now R0=1, R1=4, R2=1.
        //
        // Use slot 1 (R1=4): copy 2 from offset 4. R1↔R0 → R0=4,R1=1.
        // Use slot 2 (R2=1): copy 2 from offset 1. R2=R0(4)→R0=1→ wait.
        // Slot 2: offset=R2=1, then R2=R0, R0=offset. R0=1,R1=1,R2=4.

        // For simplicity let's just verify slot 0 reuse.
        let ops = vec![
            TestOp::Literal(b'A'),
            TestOp::Literal(b'B'),
            TestOp::Literal(b'C'),
            TestOp::Literal(b'D'),
            // Match offset=4 via slot 5 (base=6,footer=1,value=0→6+0-2=4)
            TestOp::Match {
                position_slot: 5,
                length_header: 0, // len = 0+2 = 2
                length_extra: 0,
                footer_value: 0,
            },
            // R0=4. Use slot 0 to repeat offset 4.
            TestOp::Match {
                position_slot: 0,
                length_header: 0, // len = 2
                length_extra: 0,
                footer_value: 0,
            },
            // Use slot 1 (R1=1, initial). len=2, copies 2 from offset 1.
            TestOp::Match {
                position_slot: 1,
                length_header: 0,
                length_extra: 0,
                footer_value: 0,
            },
        ];

        let prev_main = [0u8; MAIN_TREE_SIZE];
        let prev_length = [0u8; LENGTH_TREE_SIZE];
        let (input, _, _) = build_verbatim_block_with_matches(&ops, &prev_main, &prev_length);

        // Expected output:
        // Pos 0-3: ABCD
        // Pos 4-5: match offset=4, len=2 → copies [0..2] = "AB"
        // Pos 6-7: match R0=4, len=2 → copies [2..4] = "CD"
        // Pos 8-9: match R1=1, len=2 → copies [7..9] = "DD"
        // Wait, R1 was initially 1. After first explicit match (slot 5),
        // R2=R1=1, R1=R0=1, R0=4. So R1=1.
        // After slot 0: R0 stays 4, R1=1, R2=1.
        // After slot 1: offset=R1=1, then R1=R0=4, R0=1.
        //   Copy 2 from offset 1: output[7]=output[6], output[8]=output[7].
        //   At this point output[6..8] = "CD" (from R0 match).
        //   offset 1 from pos 8: copies output[7]='D', output[8]='D'
        // Total: "ABCD" + "AB" + "CD" + "DD" = "ABCDABCDDD"
        let mut output = [0u8; 10];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 10);
        assert_eq!(&output[..4], b"ABCD");
        assert_eq!(&output[4..6], b"AB");
        assert_eq!(&output[6..8], b"CD");
        assert_eq!(&output[8..10], b"DD");
    }

    #[test]
    fn invalid_block_type_returns_error() {
        let mut w = BitWriter::new();
        // Block type 0 is invalid.
        w.write_bits(0, 3);
        w.write_bits(1, 1); // default block size
        let input = w.finish(2);

        let mut output = [0u8; 32];
        let result = decompress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn e8_integration() {
        // E8 post-processing only scans buffers > 10 bytes and
        // only processes positions < len - 10. Use 13 bytes so
        // E8 at pos 2 is within the scan range (2 < 13-10 = 3).
        //
        // Raw decompressed: [0x90, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90*6]
        // E8 at pos 2: operand = 10. Relative = 10 - 2 = 8.
        let literals = [
            0x90u8, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ];
        let input = build_verbatim_literals_block(&literals);

        let mut output = [0u8; 13];
        let n = decompress(&input, &mut output).expect("decompress failed");
        assert_eq!(n, 13);
        assert_eq!(output[0], 0x90);
        assert_eq!(output[1], 0x90);
        assert_eq!(output[2], 0xE8);
        let operand = i32::from_le_bytes([output[3], output[4], output[5], output[6]]);
        assert_eq!(operand, 8);
    }

    #[test]
    fn lenient_corrupt_block() {
        // Feed a truncated/corrupt bitstream. Lenient mode should
        // return partial output with had_errors = true.
        let input = [0xFF, 0xFF, 0x00, 0x00]; // garbage
        let mut output = [0xCC; 32];
        let r = decompress_lenient(&input, &mut output);
        assert!(r.had_errors);
        // Output should be zero-filled (lenient fills zeros upfront).
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn lenient_valid_matches_strict() {
        let literals = [0x41u8, 0x42, 0x43, 0x44];
        let input = build_verbatim_literals_block(&literals);

        let mut strict_out = [0u8; 4];
        let strict_n = decompress(&input, &mut strict_out).expect("strict failed");

        let mut lenient_out = [0u8; 4];
        let r = decompress_lenient(&input, &mut lenient_out);

        assert!(!r.had_errors);
        assert_eq!(r.bytes_written, strict_n);
        assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
    }
}
