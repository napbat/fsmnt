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
    /// BitReader over the input stream.
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
    /// E8 file size (from stream header, only valid if e8_enabled).
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
            self.e8_file_size = ((high << 16) | low) as i32;
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
            self.e8_frame_offset += E8_FRAME_SIZE as i64;
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
            *len = self.reader.read_bits(ALIGNED_CODE_BITS)? as u8;
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
            *pl = self.reader.read_bits(PRE_TREE_CODE_BITS)? as u8;
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
                output[self.out_pos] = symbol as u8;
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
                        let ab = atbl.decode_symbol(&mut self.reader)? as u32;
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
                self.r0 = offset as u32;
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
mod tests {
    use super::*;
    use crate::lzx_cab::WindowSize;
    use crate::test_bitwriter::BitWriter;

    /// Build a CAB LZX stream header (E8 disabled).
    fn write_header_no_e8(w: &mut BitWriter) {
        w.write_bits(0, 1); // E8 disabled
    }

    /// Build a CAB LZX stream header (E8 enabled with given file_size).
    fn write_header_with_e8(w: &mut BitWriter, file_size: i32) {
        w.write_bits(1, 1); // E8 enabled
        let fs = file_size as u32;
        w.write_bits(fs >> 16, 16); // high 16 bits
        w.write_bits(fs & 0xFFFF, 16); // low 16 bits
    }

    /// Write a 4-symbol pretree: sym 0→00, 16→01, 17→10, 18→11.
    fn write_pretree_4sym(w: &mut BitWriter) {
        let mut lens = [0u8; 20];
        lens[0] = 2;
        lens[16] = 2;
        lens[17] = 2;
        lens[18] = 2;
        for &pl in &lens {
            w.write_bits(u32::from(pl), 4);
        }
    }

    /// Write a 3-symbol pretree: sym 0→0, 17→10, 18→11.
    fn write_pretree_3sym(w: &mut BitWriter) {
        let mut lens = [0u8; 20];
        lens[0] = 1;
        lens[17] = 2;
        lens[18] = 2;
        for &pl in &lens {
            w.write_bits(u32::from(pl), 4);
        }
    }

    /// Encode a run of `count` zeros. Pretree: 0→00, 17→10, 18→11.
    fn encode_zero_run_4sym(w: &mut BitWriter, mut count: usize) {
        while count >= 20 {
            let run = count.min(51);
            w.write_bits(0b11, 2); // sym 18
            w.write_bits((run - 20) as u32, 5);
            count -= run;
        }
        if count >= 4 {
            w.write_bits(0b10, 2); // sym 17
            w.write_bits((count - 4) as u32, 4);
            count = 0;
        }
        for _ in 0..count {
            w.write_bits(0b00, 2); // sym 0 (delta 0 = keep previous = 0)
        }
    }

    /// Encode zeros with 3-symbol pretree (0→0, 17→10, 18→11).
    fn encode_zero_run_3sym(w: &mut BitWriter, mut count: usize) {
        while count >= 20 {
            let run = count.min(51);
            w.write_bits(0b11, 2);
            w.write_bits((run - 20) as u32, 5);
            count -= run;
        }
        if count >= 4 {
            w.write_bits(0b10, 2);
            w.write_bits((count - 4) as u32, 4);
            count = 0;
        }
        for _ in 0..count {
            w.write_bits(0, 1);
        }
    }

    // -- Uncompressed block tests ------------------------------------------

    #[test]
    fn uncompressed_block_abc() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_UNCOMPRESSED, 3);
        w.write_bits(3, 24); // block size = 3

        let mut data = w.into_data();
        // Align to 16-bit boundary (writer should already be aligned).
        if !data.len().is_multiple_of(2) {
            data.push(0);
        }
        // R0, R1, R2 as raw u32 LE.
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        // Raw bytes.
        data.extend_from_slice(b"abc");
        data.push(0); // padding for odd count

        let mut output = [0u8; 3];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("uncompressed abc");
        assert_eq!(n, 3);
        assert_eq!(&output, b"abc");
    }

    #[test]
    fn uncompressed_block_all_window_sizes() {
        for &ws in &[
            WindowSize::KB32,
            WindowSize::KB64,
            WindowSize::KB128,
            WindowSize::KB256,
            WindowSize::KB512,
            WindowSize::MB1,
            WindowSize::MB2,
        ] {
            let mut w = BitWriter::new();
            write_header_no_e8(&mut w);
            w.write_bits(BLOCK_UNCOMPRESSED, 3);
            w.write_bits(5, 24);

            let mut data = w.into_data();
            if !data.len().is_multiple_of(2) {
                data.push(0);
            }
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(b"HELLO");
            data.push(0);

            let mut output = [0u8; 5];
            let n = decompress(&data, &mut output, ws)
                .unwrap_or_else(|e| panic!("failed with {ws:?}: {e}"));
            assert_eq!(n, 5);
            assert_eq!(&output, b"HELLO");
        }
    }

    // -- Verbatim block tests ----------------------------------------------

    #[test]
    fn verbatim_literals_only() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(2, 24); // block size = 2

        // KB32 → 30 position slots → main tree = 256 + 240 = 496
        // Main tree first half (256 elements): A=1, B=1, rest=0.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65); // skip to 'A' (0x41)
        w.write_bits(0b01, 2); // delta 16 for A
        w.write_bits(0b01, 2); // delta 16 for B
        encode_zero_run_4sym(&mut w, 193);

        // Main tree second half (240 elements): all zero.
        write_pretree_3sym(&mut w);
        encode_zero_run_3sym(&mut w, 240);

        // Length tree (249 elements): syms 0,1 get len=1.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2); // delta 16 for sym 0
        w.write_bits(0b01, 2); // delta 16 for sym 1
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: A(code 0), B(code 1).
        w.write_bits(0, 1);
        w.write_bits(1, 1);

        let data = w.into_data();

        let mut output = [0u8; 2];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("verbatim literals");
        assert_eq!(n, 2);
        assert_eq!(&output, b"AB");
    }

    #[test]
    fn verbatim_with_match() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(6, 24); // block size = 6 ("AAAAAA")

        // We'll encode: literal 'A', then match(offset=1, len=5).
        // offset=1 → formatted=3 → slot 3 (base=3, footer=0).
        // Match symbol = 256 + 3*8 + 3 = 283 (length_header=3 → len=5).
        // In the second half of main tree, index = 283 - 256 = 27.

        // Main first half (256): only A(0x41)=1.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2); // delta 16 for 'A'
        encode_zero_run_4sym(&mut w, 190);

        // Main second half (240): only index 27=1.
        // 240 = 27 zeros + 1 non-zero + 212 zeros
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 27);
        w.write_bits(0b01, 2); // delta 16 for match sym
        encode_zero_run_4sym(&mut w, 212);

        // Length tree: syms 0,1 get len=1.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: literal A (code 0), match 283 (code 1).
        w.write_bits(0, 1); // 'A'
        w.write_bits(1, 1); // match (slot=3, footer_bits=0, no footer needed)

        let data = w.into_data();

        let mut output = [0u8; 6];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("verbatim with match");
        assert_eq!(n, 6);
        assert_eq!(&output, b"AAAAAA");
    }

    // -- Aligned offset block test -----------------------------------------

    #[test]
    fn aligned_offset_block() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_ALIGNED, 3);
        w.write_bits(6, 24);

        // Aligned offset tree: 8 elements, 3 bits each.
        // Give syms 0,1 len=1 for a valid tree.
        let aligned_lens: [u8; 8] = [1, 1, 0, 0, 0, 0, 0, 0];
        for &al in &aligned_lens {
            w.write_bits(u32::from(al), 3);
        }

        // Same trees as verbatim_with_match test.
        // Main first half: A=1.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 190);

        // Main second half: index 27 (sym 283)=1.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 27);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 212);

        // Length tree.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: literal A, match (slot 3, no footer).
        w.write_bits(0, 1);
        w.write_bits(1, 1);

        let data = w.into_data();

        let mut output = [0u8; 6];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("aligned offset block");
        assert_eq!(n, 6);
        assert_eq!(&output, b"AAAAAA");
    }

    // -- Multi-block with inter-block tree carry-over ----------------------

    /// Encode N copies of pretree symbol 0 (delta=0, preserves
    /// previous code length). Pretree must have sym 0 at code_len=1.
    fn encode_delta_zero_run(w: &mut BitWriter, count: usize) {
        for _ in 0..count {
            w.write_bits(0, 1); // sym 0 = delta 0
        }
    }

    /// Write pretree with sym 0 at 1 bit (for delta-0 encoding).
    fn write_pretree_delta_zero(w: &mut BitWriter) {
        let mut lens = [0u8; 20];
        lens[0] = 1;
        for &pl in &lens {
            w.write_bits(u32::from(pl), 4);
        }
    }

    #[test]
    fn multi_block_tree_carry_over() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);

        // Block 1: verbatim, 2 bytes "AB".
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(2, 24);

        // KB32 → main tree size = 496, second half = 240.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2); // A
        w.write_bits(0b01, 2); // B
        encode_zero_run_4sym(&mut w, 193);

        write_pretree_3sym(&mut w);
        encode_zero_run_3sym(&mut w, 240);

        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        w.write_bits(0, 1); // A
        w.write_bits(1, 1); // B

        // Block 2: verbatim, 2 bytes "AB" — reuses trees from block 1.
        // Send delta=0 for every position to preserve previous trees.
        // (Cannot use zero-run syms 17/18 — those SET lengths to 0,
        // overwriting the non-zero entries from block 1.)
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(2, 24);

        // Main first half: 256 delta-0 symbols.
        write_pretree_delta_zero(&mut w);
        encode_delta_zero_run(&mut w, 256);

        // Main second half: 240 delta-0 symbols.
        write_pretree_delta_zero(&mut w);
        encode_delta_zero_run(&mut w, 240);

        // Length tree: 249 delta-0 symbols.
        write_pretree_delta_zero(&mut w);
        encode_delta_zero_run(&mut w, 249);

        // Same tokens as block 1.
        w.write_bits(0, 1); // A
        w.write_bits(1, 1); // B

        let data = w.into_data();

        let mut output = [0u8; 4];
        let n =
            decompress(&data, &mut output, WindowSize::KB32).expect("multi-block tree carry-over");
        assert_eq!(n, 4);
        assert_eq!(&output, b"ABAB");
    }

    // -- Repeat offset tests -----------------------------------------------

    #[test]
    fn repeat_offset_r0() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(8, 24); // "ABCDABCD"

        // Need: literals A,B,C,D + match(slot 5, len 2) + match(slot 0, len 2)
        // slot 5: base=6, footer=1, footer_val=0 → offset = 6+0-2 = 4
        // slot 0: R0 = 4, len 2

        // Main tree syms needed: A(65), B(66), C(67), D(68),
        //   match_slot5_lh0 = 256+5*8+0 = 296 (second half index 40),
        //   match_slot0_lh0 = 256+0*8+0 = 256 (second half index 0)
        // All get code_len = 3 (6 symbols → need 3 bits).

        // Build main first half: A,B,C,D get len 3.
        let mut main_first = [0u8; 256];
        main_first[65] = 3;
        main_first[66] = 3;
        main_first[67] = 3;
        main_first[68] = 3;

        // Build main second half (240): index 0 and 40 get len 3.
        let second_half_size = 240;
        let mut main_second = [0u8; 240];
        main_second[0] = 3;
        main_second[40] = 3;

        // Write main first half via pretree.
        write_simple_pretree_and_deltas(&mut w, &main_first, &[0u8; 256]);
        write_simple_pretree_and_deltas(&mut w, &main_second, &[0u8; 240]);

        // Length tree: sym 0 = 1 (we don't actually use it).
        let mut length_lens = [0u8; 249];
        length_lens[0] = 1;
        write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

        // Compute canonical codes for full main tree.
        let mut full_main = [0u8; 496];
        full_main[..256].copy_from_slice(&main_first);
        full_main[256..496].copy_from_slice(&main_second[..second_half_size]);

        let main_codes = assign_test_codes(&full_main);

        // Encode: A, B, C, D, match(slot5,lh0), match(slot0,lh0)
        encode_sym(&mut w, &main_codes, 65); // A
        encode_sym(&mut w, &main_codes, 66); // B
        encode_sym(&mut w, &main_codes, 67); // C
        encode_sym(&mut w, &main_codes, 68); // D
        encode_sym(&mut w, &main_codes, 296); // match slot 5
        w.write_bits(0, 1); // footer bit for slot 5
        encode_sym(&mut w, &main_codes, 256); // match slot 0 (R0)

        let data = w.into_data();

        let mut output = [0u8; 8];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r0");
        assert_eq!(n, 8);
        assert_eq!(&output, b"ABCDABCD");
    }

    #[test]
    fn repeat_offset_r1_swap() {
        // After an explicit match sets R0=4, R1=1 (initial),
        // use slot 1 which swaps R0↔R1. R0 becomes 1.
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(8, 24);

        // Syms: A(65), B(66), C(67), D(68)
        //   match_slot5_lh0(296): offset=4
        //   match_slot1_lh0(264): R1 swap → offset=1
        let mut main_lens = [0u8; 496];
        main_lens[65] = 3;
        main_lens[66] = 3;
        main_lens[67] = 3;
        main_lens[68] = 3;
        main_lens[264] = 3; // slot 1, lh 0
        main_lens[296] = 3; // slot 5, lh 0

        write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
        write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

        let mut length_lens = [0u8; 249];
        length_lens[0] = 1;
        write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

        let main_codes = assign_test_codes(&main_lens);

        encode_sym(&mut w, &main_codes, 65); // A
        encode_sym(&mut w, &main_codes, 66); // B
        encode_sym(&mut w, &main_codes, 67); // C
        encode_sym(&mut w, &main_codes, 68); // D
        encode_sym(&mut w, &main_codes, 296); // match slot5 → offset=4
        w.write_bits(0, 1); // footer for slot 5
        // Now R0=4, R1=1
        encode_sym(&mut w, &main_codes, 264); // match slot1 → R1=1, swap R0↔R1
        // R0=1, R1=4. Copy 2 bytes from offset 1.

        let data = w.into_data();
        let mut output = [0u8; 8];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r1");
        assert_eq!(n, 8);
        // Pos 0-3: ABCD, 4-5: AB (offset=4), 6-7: BB (offset=1 from pos 5='B')
        assert_eq!(&output[..4], b"ABCD");
        assert_eq!(&output[4..6], b"AB");
        assert_eq!(&output[6..8], b"BB");
    }

    #[test]
    fn repeat_offset_r2_rotate() {
        // Use slot 2 which takes R2 and rotates: R2=R0, R0=old_R2.
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(10, 24);

        // We need:
        //   4 literals (ABCD)
        //   match slot5 (offset=4, len=2) → R0=4
        //   match slot3 (offset=1, len=2) → R0=1, R1=4, R2=1
        //   match slot2 (R2=1, len=2) → R0=1, R2=old_R0=1
        let mut main_lens = [0u8; 496];
        main_lens[65] = 4; // A
        main_lens[66] = 4; // B
        main_lens[67] = 4; // C
        main_lens[68] = 4; // D
        main_lens[256] = 4; // slot 0, lh 0
        main_lens[272] = 4; // slot 2, lh 0
        main_lens[280] = 4; // slot 3, lh 0
        main_lens[296] = 4; // slot 5, lh 0

        write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
        write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

        let mut length_lens = [0u8; 249];
        length_lens[0] = 1;
        write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

        let main_codes = assign_test_codes(&main_lens);

        encode_sym(&mut w, &main_codes, 65); // A
        encode_sym(&mut w, &main_codes, 66); // B
        encode_sym(&mut w, &main_codes, 67); // C
        encode_sym(&mut w, &main_codes, 68); // D
        encode_sym(&mut w, &main_codes, 296); // slot 5 → offset=4
        w.write_bits(0, 1); // footer
        // R0=4, R1=1, R2=1
        encode_sym(&mut w, &main_codes, 280); // slot 3 → offset=1
        // R0=1, R1=4, R2=1
        encode_sym(&mut w, &main_codes, 272); // slot 2 → R2=1, R0=1, R2=old_R0=1
        // Copy 2 from offset=1 (R2)

        let data = w.into_data();
        let mut output = [0u8; 10];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("repeat offset r2");
        assert_eq!(n, 10);
        assert_eq!(&output[..4], b"ABCD");
        // pos 4-5: offset=4, len=2 → copies ABCD[0..2] = AB
        assert_eq!(&output[4..6], b"AB");
        // pos 6-7: offset=1, len=2 → copies from pos 5,6 = BB
        assert_eq!(&output[6..8], b"BB");
        // pos 8-9: R2=1, offset=1, len=2 → copies from pos 7,8 = BB
        assert_eq!(&output[8..10], b"BB");
    }

    #[test]
    fn length_tree_lookup() {
        // Test length_header == 7 which triggers length tree decode.
        // Match with length_header=7, length_extra=0 → len = 7+0+2 = 9.
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(10, 24); // 1 literal + 9 match = 10

        // We need: literal 'A' and match(slot 3, lh 7, len_extra 0).
        // slot 3 → offset=1, length=9: repeat 'A' 9 times.
        // Match sym = 256 + 3*8 + 7 = 287. Second half index = 31.
        let mut main_lens = [0u8; 496];
        main_lens[65] = 1; // A
        main_lens[287] = 1; // match slot3 lh7

        write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
        write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

        // Length tree: only sym 0 = 1.
        let mut length_lens = [0u8; 249];
        length_lens[0] = 1;
        write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

        let main_codes = assign_test_codes(&main_lens);
        let length_codes = assign_test_codes(&length_lens);

        encode_sym(&mut w, &main_codes, 65); // 'A'
        encode_sym(&mut w, &main_codes, 287); // match slot3 lh7
        encode_sym(&mut w, &length_codes, 0); // length extra = 0

        let data = w.into_data();
        let mut output = [0u8; 10];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("length tree lookup");
        assert_eq!(n, 10);
        assert_eq!(&output, b"AAAAAAAAAA");
    }

    #[test]
    fn aligned_block_with_large_footer() {
        // Test aligned block with position slot 8 (footer_bits=3).
        // In aligned mode, 3 footer bits = 0 verbatim + 3 aligned.
        // slot 8: base=16, footer=3. offset = 16 + aligned - 2.
        // With aligned_sym=0: offset = 16 + 0 - 2 = 14.
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_ALIGNED, 3);
        w.write_bits(18, 24); // 14 literals + 4 match = 18

        // Aligned tree: uniform 3-bit codes for all 8 symbols.
        for _ in 0..8 {
            w.write_bits(3, 3);
        }

        // Main tree: 14 unique literals (A-N) + match sym.
        // match(slot 8, lh 2) = 256 + 8*8 + 2 = 322. Second half idx = 66.
        let mut main_lens = [0u8; 496];
        for i in 0..14usize {
            main_lens[65 + i] = 5; // A through N
        }
        main_lens[322] = 5; // match sym

        write_simple_pretree_and_deltas(&mut w, &main_lens[..256], &[0u8; 256]);
        write_simple_pretree_and_deltas(&mut w, &main_lens[256..496], &[0u8; 240]);

        let mut length_lens = [0u8; 249];
        length_lens[0] = 1;
        write_simple_pretree_and_deltas(&mut w, &length_lens, &[0u8; 249]);

        let main_codes = assign_test_codes(&main_lens);
        let aligned_lens_arr = [3u8; 8];
        let aligned_codes = assign_test_codes(&aligned_lens_arr);

        // 14 literals: A B C D E F G H I J K L M N
        for i in 0..14usize {
            encode_sym(&mut w, &main_codes, 65 + i);
        }
        // Match: slot 8, lh 2 → len=4. Footer=3 bits.
        // Aligned mode: 0 verbatim bits (3-3=0), then 3 aligned bits.
        encode_sym(&mut w, &main_codes, 322);
        encode_sym(&mut w, &aligned_codes, 0); // aligned_sym=0 → offset=14

        let data = w.into_data();
        let mut output = [0u8; 18];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("aligned large footer");
        assert_eq!(n, 18);
        // Match at offset 14 copies the first 4 bytes.
        assert_eq!(&output[14..18], &output[0..4]);
    }

    // -- E8 post-processing test -------------------------------------------

    #[test]
    fn e8_integration() {
        // Build a stream with E8 enabled, then an uncompressed block
        // containing an E8 instruction.
        let mut w = BitWriter::new();
        write_header_with_e8(&mut w, 12_000_000);
        w.write_bits(BLOCK_UNCOMPRESSED, 3);
        w.write_bits(13, 24);

        let mut data = w.into_data();
        if !data.len().is_multiple_of(2) {
            data.push(0);
        }
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        // Raw: 0x90 0x90 0xE8 <absolute addr> 0x90*6
        // E8 at pos 2: operand = 0x0A (absolute). After undo: relative = 10 - 2 = 8.
        data.extend_from_slice(&[
            0x90, 0x90, 0xE8, 0x0A, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        ]);
        data.push(0); // padding for odd count

        let mut output = [0u8; 13];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("e8 integration");
        assert_eq!(n, 13);
        assert_eq!(output[2], 0xE8);
        let operand = i32::from_le_bytes([output[3], output[4], output[5], output[6]]);
        assert_eq!(operand, 8);
    }

    // -- Error handling tests ----------------------------------------------

    #[test]
    fn invalid_block_type_returns_error() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(0, 3); // block type 0 = invalid
        w.write_bits(1, 24);
        let data = w.into_data();

        let mut output = [0u8; 1];
        assert!(decompress(&data, &mut output, WindowSize::KB32).is_err());
    }

    #[test]
    fn truncated_input_returns_error() {
        let data = [0u8; 1]; // too short for header + block
        let mut output = [0u8; 10];
        assert!(decompress(&data, &mut output, WindowSize::KB32).is_err());
    }

    #[test]
    fn lenient_on_valid_matches_strict() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_UNCOMPRESSED, 3);
        w.write_bits(3, 24);

        let mut data = w.into_data();
        if !data.len().is_multiple_of(2) {
            data.push(0);
        }
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(b"xyz");
        data.push(0);

        let mut strict_out = [0u8; 3];
        let strict_n = decompress(&data, &mut strict_out, WindowSize::KB32).expect("strict");

        let mut lenient_out = [0u8; 3];
        let lenient_r = decompress_lenient(&data, &mut lenient_out, WindowSize::KB32);

        assert_eq!(strict_n, lenient_r.bytes_written);
        assert!(!lenient_r.had_errors);
        assert_eq!(strict_out, lenient_out);
    }

    #[test]
    fn lenient_corrupt_returns_partial() {
        let data = [0xFF, 0xFF, 0x00, 0x00]; // garbage
        let mut output = [0xCC; 32];
        let r = decompress_lenient(&data, &mut output, WindowSize::KB32);
        assert!(r.had_errors);
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn empty_output_succeeds() {
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        let data = w.into_data();

        let mut output = [0u8; 0];
        let n = decompress(&data, &mut output, WindowSize::KB32).expect("empty output");
        assert_eq!(n, 0);
    }

    // -- 64 KB window test -------------------------------------------------

    #[test]
    fn verbatim_64kb_window() {
        // KB64 → 32 position slots → main tree = 256 + 256 = 512,
        // second half = 256.
        let mut w = BitWriter::new();
        write_header_no_e8(&mut w);
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(2, 24);

        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2); // A
        w.write_bits(0b01, 2); // B
        encode_zero_run_4sym(&mut w, 193);

        // Second half is 256 elements for 64KB window.
        write_pretree_3sym(&mut w);
        encode_zero_run_3sym(&mut w, 256);

        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        w.write_bits(0, 1); // A
        w.write_bits(1, 1); // B

        let data = w.into_data();

        let mut output = [0u8; 2];
        let n = decompress(&data, &mut output, WindowSize::KB64).expect("verbatim 64kb");
        assert_eq!(n, 2);
        assert_eq!(&output, b"AB");
    }

    // -- Test helpers ------------------------------------------------------

    /// Write a pretree and encoded deltas for an arbitrary target
    /// code-length array against a previous array.
    fn write_simple_pretree_and_deltas(w: &mut BitWriter, target: &[u8], prev: &[u8]) {
        // Compute delta symbols.
        let mut deltas = alloc::vec::Vec::with_capacity(target.len());
        for (i, &t) in target.iter().enumerate() {
            let old = if i < prev.len() { prev[i] } else { 0 };
            let d = ((old as u32 + NUM_CODE_LENGTHS - t as u32) % NUM_CODE_LENGTHS) as u8;
            deltas.push(d);
        }

        // Collect unique delta symbols.
        let mut used = [false; 20];
        for &d in &deltas {
            used[d as usize] = true;
        }
        let used_count = used.iter().filter(|&&u| u).count();
        let code_len = if used_count <= 1 {
            1u8
        } else {
            let mut bits = 1u8;
            while (1usize << bits) < used_count {
                bits += 1;
            }
            bits
        };

        let mut pre_lens = [0u8; 20];
        for (i, &u) in used.iter().enumerate() {
            if u {
                pre_lens[i] = code_len;
            }
        }

        // Write 20 pre-tree code lengths.
        for &pl in &pre_lens {
            w.write_bits(u32::from(pl), 4);
        }

        // Build codes for the pretree.
        let pre_codes = assign_test_codes(&pre_lens);

        // Write each delta.
        for &d in &deltas {
            encode_sym(w, &pre_codes, d as usize);
        }
    }

    /// Assign canonical codes for test encoding.
    fn assign_test_codes(lengths: &[u8]) -> alloc::vec::Vec<(u32, u8)> {
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
        let mut codes = alloc::vec![(0u32, 0u8); lengths.len()];
        for (sym, &len) in lengths.iter().enumerate() {
            let l = len as usize;
            if l > 0 && l < 17 {
                codes[sym] = (next_code[l], len);
                next_code[l] += 1;
            }
        }
        codes
    }

    fn encode_sym(w: &mut BitWriter, codes: &[(u32, u8)], sym: usize) {
        let (code, len) = codes[sym];
        w.write_bits(code, u32::from(len));
    }
}
