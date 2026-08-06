//! LZX CAB-variant decompression.
//!
//! Implements the LZX algorithm as used in Microsoft Cabinet (.cab)
//! files, MSI installers, and Windows Update packages. This variant
//! supports configurable window sizes (32 KB – 2 MB), inter-block
//! Huffman tree deltas, and E8 x86 CALL preprocessing.

use crate::bitstream::BitReader;
use crate::e8::undo_e8_preprocessing;
use crate::huffman::HuffmanTable;
use crate::{Error, LenientResult, Result};

use super::{
    ALIGNED_CODE_BITS, ALIGNED_TREE_SIZE, BLOCK_ALIGNED, BLOCK_UNCOMPRESSED, BLOCK_VERBATIM,
    E8_FRAME_SIZE, LEN_HEADER_COUNT, LENGTH_TREE_SIZE, LONG_RUN_BASE, LONG_RUN_BITS,
    MAX_POSITION_SLOTS, MIN_MATCH_LEN, NUM_CODE_LENGTHS, OFFSET_ADJUSTMENT, PRE_TREE_CODE_BITS,
    PRE_TREE_SIZE, PRETREE_REPEAT, PRETREE_ZERO_LONG, PRETREE_ZERO_SHORT, REPEAT_BITS,
    SHORT_RUN_BASE, SHORT_RUN_BITS, SlotTables, WindowSize,
};

/// Decompress CAB LZX data in strict mode.
///
/// `input` is the raw LZX bitstream (concatenated from CFDATA records
/// if applicable). `output` must be pre-allocated to the expected
/// decompressed size. `window_size` must match the value from the
/// CAB folder header.
///
/// Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error when the bitstream is malformed or references data
/// outside the configured CAB window.
pub fn decompress(input: &[u8], output: &mut [u8], window_size: WindowSize) -> Result<usize> {
    let tables = SlotTables::new(window_size);
    let mut ctx = DecompressCtx::new(input, output.len(), &tables);
    ctx.run(output)
}

/// Decompress CAB LZX data in lenient (forensic) mode.
///
/// Zero-fills the output buffer upfront, then decompresses as far
/// as possible. On errors the damaged region stays zeroed and
/// `had_errors` is set.
pub fn decompress_lenient(
    input: &[u8],
    output: &mut [u8],
    window_size: WindowSize,
) -> LenientResult {
    output.fill(0);
    let tables = SlotTables::new(window_size);
    let mut ctx = DecompressCtx::new(input, output.len(), &tables);
    let (written, had_errors) = match ctx.run(output) {
        Ok(n) => (n, false),
        Err(_) => (ctx.out_pos.min(output.len()), true),
    };
    LenientResult {
        bytes_written: written,
        had_errors,
    }
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

#[cold]
#[inline(never)]
fn err_invalid(offset: usize, reason: &str) -> Error {
    Error::InvalidData {
        offset,
        reason: alloc::string::String::from(reason),
    }
}

#[cold]
#[inline(never)]
fn err_output_too_small(needed: usize, actual: usize) -> Error {
    Error::OutputTooSmall {
        expected: needed,
        actual,
    }
}

#[cold]
#[inline(never)]
fn err_truncated(offset: usize, expected: usize, actual: usize) -> Error {
    Error::InputTruncated {
        offset,
        expected,
        actual,
    }
}

// ---------------------------------------------------------------------------
// Decompressor state
// ---------------------------------------------------------------------------

struct DecompressCtx<'a> {
    /// Raw input bytes (full stream).
    input: &'a [u8],
    /// `BitReader` over the input stream.
    reader: BitReader<'a>,
    /// Total expected output bytes.
    out_len: usize,
    /// Current output position.
    out_pos: usize,
    /// Repeat offset queue.
    r0: u32,
    r1: u32,
    r2: u32,
    /// Position slot tables for the configured window size.
    tables: &'a SlotTables,
    /// Main tree code lengths (carried across blocks).
    main_lens: [u8; 256 + MAX_POSITION_SLOTS * LEN_HEADER_COUNT],
    /// Effective main tree size for this window.
    main_tree_size: usize,
    /// Length tree code lengths (carried across blocks).
    length_lens: [u8; LENGTH_TREE_SIZE],
    /// E8 translation enabled (from stream header).
    e8_enabled: bool,
    /// E8 file size (from stream header, only valid if `e8_enabled`).
    e8_file_size: i32,
    /// Whether the stream header has been parsed.
    header_parsed: bool,
    /// Total uncompressed bytes emitted before the current E8 frame.
    e8_frame_offset: i64,
    /// Start of the current E8 frame in the output buffer.
    e8_frame_start: usize,
}

impl<'a> DecompressCtx<'a> {
    fn new(input: &'a [u8], out_len: usize, tables: &'a SlotTables) -> Self {
        let mut reader = BitReader::new(input);
        reader.set_zero_fill(true);
        let main_tree_size = 256 + tables.num_slots * LEN_HEADER_COUNT;
        Self {
            input,
            reader,
            out_len,
            out_pos: 0,
            r0: 1,
            r1: 1,
            r2: 1,
            tables,
            main_lens: [0u8; 256 + MAX_POSITION_SLOTS * LEN_HEADER_COUNT],
            main_tree_size,
            length_lens: [0u8; LENGTH_TREE_SIZE],
            e8_enabled: false,
            e8_file_size: 0,
            header_parsed: false,
            e8_frame_offset: 0,
            e8_frame_start: 0,
        }
    }

    /// Run decompression across all blocks in the stream.
    fn run(&mut self, output: &mut [u8]) -> Result<usize> {
        if !self.header_parsed {
            self.parse_header()?;
            self.header_parsed = true;
        }

        while self.out_pos < self.out_len {
            self.decode_block(output)?;
            self.apply_e8_if_frame_complete(output);
        }

        // Final E8 pass on any remaining partial frame.
        self.apply_e8_final(output);

        Ok(self.out_pos)
    }

    /// Parse the CAB LZX stream header (E8 translation flag + optional
    /// file size).
    fn parse_header(&mut self) -> Result<()> {
        let e8_flag = self.reader.read_bits(1)?;
        if e8_flag == 1 {
            let high = self.reader.read_bits(16)?;
            let low = self.reader.read_bits(16)?;
            self.e8_enabled = true;
            self.e8_file_size = ((high << 16) | low).cast_signed();
        }
        Ok(())
    }

    /// Apply E8 post-processing whenever a complete 32 KB frame has
    /// been emitted.
    fn apply_e8_if_frame_complete(&mut self, output: &mut [u8]) {
        if !self.e8_enabled {
            return;
        }
        while self.out_pos - self.e8_frame_start >= E8_FRAME_SIZE {
            let frame_end = self.e8_frame_start + E8_FRAME_SIZE;
            undo_e8_preprocessing(
                &mut output[self.e8_frame_start..frame_end],
                self.e8_file_size,
                self.e8_frame_offset,
            );
            self.e8_frame_offset +=
                i64::try_from(E8_FRAME_SIZE).expect("an E8 translation frame is exactly 32 KiB");
            self.e8_frame_start = frame_end;
        }
    }

    /// Apply E8 post-processing to the final partial frame.
    fn apply_e8_final(&mut self, output: &mut [u8]) {
        if !self.e8_enabled {
            return;
        }
        if self.out_pos > self.e8_frame_start {
            undo_e8_preprocessing(
                &mut output[self.e8_frame_start..self.out_pos],
                self.e8_file_size,
                self.e8_frame_offset,
            );
        }
    }

    /// Decode a single block (verbatim, aligned, or uncompressed).
    fn decode_block(&mut self, output: &mut [u8]) -> Result<()> {
        let block_type = self.reader.read_bits(3)?;
        let block_size = self.reader.read_bits(24)? as usize;
        let block_end = (self.out_pos + block_size).min(self.out_len);

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
            _ => Err(err_invalid(
                self.reader.position(),
                "CAB LZX invalid block type",
            )),
        }
    }
}

// -- Tree reading ----------------------------------------------------------

impl DecompressCtx<'_> {
    fn read_aligned_tree(&mut self) -> Result<HuffmanTable> {
        let mut lens = [0u8; ALIGNED_TREE_SIZE];
        for len in &mut lens {
            *len = u8::try_from(self.reader.read_bits(ALIGNED_CODE_BITS)?)
                .expect("aligned-tree code lengths are encoded in three bits");
        }
        HuffmanTable::from_code_lengths(&lens, 7)
    }

    fn read_main_and_length_trees(&mut self) -> Result<(HuffmanTable, HuffmanTable)> {
        let main_size = self.main_tree_size;

        let mut main_lens = self.main_lens;
        self.decode_pretree_delta(&mut main_lens[..256])?;
        self.decode_pretree_delta(&mut main_lens[256..main_size])?;
        self.main_lens = main_lens;

        let mut length_lens = self.length_lens;
        self.decode_pretree_delta(&mut length_lens[..LENGTH_TREE_SIZE])?;
        self.length_lens = length_lens;

        let main_tbl = HuffmanTable::from_code_lengths(&self.main_lens[..main_size], 11)?;
        let len_tbl = HuffmanTable::from_code_lengths(&self.length_lens, 9)?;
        Ok((main_tbl, len_tbl))
    }

    /// Read a 20-symbol pre-tree and decode delta-encoded code lengths.
    fn decode_pretree_delta(&mut self, lens: &mut [u8]) -> Result<()> {
        let mut pre_lens = [0u8; PRE_TREE_SIZE];
        for pl in &mut pre_lens {
            *pl = u8::try_from(self.reader.read_bits(PRE_TREE_CODE_BITS)?)
                .expect("pre-tree code lengths are encoded in four bits");
        }
        let pre_table = HuffmanTable::from_code_lengths(&pre_lens, 6)?;
        decode_code_lengths(&mut self.reader, &pre_table, lens)
    }
}

/// Decode code lengths using a pre-tree, applying delta encoding
/// against the previous values already in `lens`.
fn decode_code_lengths(
    reader: &mut BitReader<'_>,
    pre_table: &HuffmanTable,
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
            return Err(err_invalid(
                reader.position(),
                "CAB LZX invalid pre-tree symbol",
            ));
        }
    }

    Ok(())
}

// -- Compressed block decoding ---------------------------------------------

impl DecompressCtx<'_> {
    fn decode_compressed(
        &mut self,
        output: &mut [u8],
        block_end: usize,
        main_tbl: &HuffmanTable,
        len_tbl: &HuffmanTable,
        aligned_tbl: Option<&HuffmanTable>,
    ) -> Result<()> {
        while self.out_pos < block_end {
            let symbol = main_tbl.decode_symbol(&mut self.reader)? as usize;

            if symbol < 256 {
                if self.out_pos >= output.len() {
                    return Err(err_output_too_small(self.out_pos + 1, output.len()));
                }
                output[self.out_pos] = u8::try_from(symbol).expect("literal symbols are below 256");
                self.out_pos += 1;
            } else {
                let (offset, length) = self.decode_match(symbol, len_tbl, aligned_tbl)?;
                self.copy_match(output, offset, length, block_end)?;
            }
        }
        Ok(())
    }

    /// Decode a match: extract offset and length from the symbol and
    /// bitstream.
    fn decode_match(
        &mut self,
        symbol: usize,
        len_tbl: &HuffmanTable,
        aligned_tbl: Option<&HuffmanTable>,
    ) -> Result<(usize, usize)> {
        let match_code = symbol - 256;
        let position_slot = match_code / LEN_HEADER_COUNT;
        let length_header = match_code % LEN_HEADER_COUNT;

        let length = if length_header < 7 {
            length_header + MIN_MATCH_LEN
        } else {
            let len_sym = len_tbl.decode_symbol(&mut self.reader)? as usize;
            7 + len_sym + MIN_MATCH_LEN
        };

        let offset = self.decode_offset(position_slot, aligned_tbl)?;

        Ok((offset, length))
    }

    /// Decode match offset from position slot.
    fn decode_offset(
        &mut self,
        position_slot: usize,
        aligned_tbl: Option<&HuffmanTable>,
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
                if position_slot >= self.tables.num_slots {
                    return Err(err_invalid(
                        self.reader.position(),
                        "CAB LZX position slot exceeds window",
                    ));
                }

                let extra = u32::from(self.tables.footer_bits[position_slot]);
                let base = self.tables.base_position[position_slot];

                let (verbatim_bits, aligned_bits) = if extra >= 3 {
                    if let Some(atbl) = aligned_tbl {
                        let vb_count = extra - 3;
                        let vb = if vb_count > 0 {
                            self.reader.read_bits(vb_count)?
                        } else {
                            0
                        };
                        let ab = u32::from(atbl.decode_symbol(&mut self.reader)?);
                        ((vb << 3), ab)
                    } else {
                        (self.reader.read_bits(extra)?, 0)
                    }
                } else if extra > 0 {
                    (self.reader.read_bits(extra)?, 0)
                } else {
                    (0, 0)
                };

                let raw = base + verbatim_bits + aligned_bits;
                if raw < OFFSET_ADJUSTMENT {
                    return Err(err_invalid(
                        self.reader.position(),
                        "CAB LZX computed offset below minimum",
                    ));
                }
                let offset = (raw - OFFSET_ADJUSTMENT) as usize;

                self.r2 = self.r1;
                self.r1 = self.r0;
                self.r0 = u32::try_from(offset)
                    .expect("CAB LZX offsets are bounded by the configured window");
                Ok(offset)
            }
        }
    }

    /// Copy a match within the output buffer.
    fn copy_match(
        &mut self,
        output: &mut [u8],
        offset: usize,
        length: usize,
        block_end: usize,
    ) -> Result<()> {
        let dest_end = self.out_pos + length;
        if dest_end > block_end.min(output.len()) {
            return Err(err_output_too_small(dest_end, output.len()));
        }

        if offset == 0 || offset > self.out_pos {
            return Err(err_invalid(
                self.reader.position(),
                "CAB LZX match offset exceeds output position",
            ));
        }

        copy_within_output(output, self.out_pos, offset, length);
        self.out_pos += length;
        Ok(())
    }
}

// -- Uncompressed block decoding -------------------------------------------

impl DecompressCtx<'_> {
    fn decode_uncompressed(&mut self, output: &mut [u8], block_end: usize) -> Result<()> {
        // Align to 16-bit boundary.
        self.reader.align_to_u16();

        // Read R0, R1, R2.
        self.r0 = self.reader.read_u32_le()?;
        self.r1 = self.reader.read_u32_le()?;
        self.r2 = self.reader.read_u32_le()?;

        // Copy raw bytes.
        let count = block_end - self.out_pos;
        if self.out_pos + count > output.len() {
            return Err(err_output_too_small(self.out_pos + count, output.len()));
        }

        let reader_pos = self.reader.position();
        if reader_pos + count > self.input.len() {
            return Err(err_truncated(
                reader_pos,
                count,
                self.input.len().saturating_sub(reader_pos),
            ));
        }

        for _ in 0..count {
            output[self.out_pos] = self.reader.read_raw_byte()?;
            self.out_pos += 1;
        }

        // Re-align if the raw byte count was odd.
        if !count.is_multiple_of(2) {
            let _ = self.reader.read_raw_byte()?;
        }

        Ok(())
    }
}

/// Copy `length` bytes within the output buffer from
/// `out_pos - offset` to `out_pos`. Handles overlapping copies.
fn copy_within_output(output: &mut [u8], out_pos: usize, offset: usize, length: usize) {
    let src_start = out_pos - offset;
    if offset >= length {
        output.copy_within(src_start..src_start + length, out_pos);
    } else {
        for i in 0..length {
            output[out_pos + i] = output[src_start + i];
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "decompress_tests/mod.rs"]
mod tests;
