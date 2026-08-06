//! LZXD (LZX DELTA) decompression.
//!
//! Implements the LZXD algorithm as specified in [MS-PATCH] v14.1.
//! LZXD extends LZX with reference data support (delta compression),
//! variable window sizes (128 KB – 32 MB), and match lengths up to
//! 32,768 bytes.

use crate::bitstream::BitReader;
use crate::e8::undo_e8_preprocessing;
use crate::huffman::HuffmanTable;
use crate::{Error, LenientResult, Result};

use super::{
    ALIGNED_CODE_BITS, ALIGNED_TREE_SIZE, BLOCK_ALIGNED, BLOCK_UNCOMPRESSED, BLOCK_VERBATIM,
    CHUNK_SIZE, LEN_HEADER_COUNT, LENGTH_TREE_SIZE, LONG_RUN_BASE, LONG_RUN_BITS,
    MAX_POSITION_SLOTS, MIN_MATCH_LEN, NUM_CODE_LENGTHS, OFFSET_ADJUSTMENT, PRE_TREE_CODE_BITS,
    PRE_TREE_SIZE, PRETREE_REPEAT, PRETREE_ZERO_LONG, PRETREE_ZERO_SHORT, REPEAT_BITS,
    SHORT_RUN_BASE, SHORT_RUN_BITS, SlotTables, WindowSize,
};

/// Decompress LZXD data in strict mode.
///
/// `input` is the LZXD compressed byte stream including 16-bit
/// chunk-size prefixes. `output` must be pre-allocated to the
/// expected decompressed size. `window_size` and `reference_data`
/// must match the values used during compression.
///
/// Returns the number of bytes written to `output`.
pub fn decompress(
    input: &[u8],
    output: &mut [u8],
    window_size: WindowSize,
    reference_data: &[u8],
) -> Result<usize> {
    let tables = SlotTables::new(window_size);
    let mut ctx = DecompressCtx::new(input, output.len(), &tables, reference_data);
    ctx.run(output)
}

/// Decompress LZXD data in lenient (forensic) mode.
///
/// Zero-fills the output buffer upfront, then decompresses as far
/// as possible. On errors the damaged region stays zeroed and
/// `had_errors` is set.
pub fn decompress_lenient(
    input: &[u8],
    output: &mut [u8],
    window_size: WindowSize,
    reference_data: &[u8],
) -> LenientResult {
    output.fill(0);
    let tables = SlotTables::new(window_size);
    let mut ctx = DecompressCtx::new(input, output.len(), &tables, reference_data);
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
    /// Current byte position in the input stream.
    input_pos: usize,
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
    /// Reference data for delta decompression.
    reference_data: &'a [u8],
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
    /// Total uncompressed bytes emitted before the current chunk
    /// (for E8 chunk_offset).
    chunk_offset: i64,
}

impl<'a> DecompressCtx<'a> {
    fn new(
        input: &'a [u8],
        out_len: usize,
        tables: &'a SlotTables,
        reference_data: &'a [u8],
    ) -> Self {
        let main_tree_size = 256 + tables.num_slots * LEN_HEADER_COUNT;
        Self {
            input,
            input_pos: 0,
            out_len,
            out_pos: 0,
            r0: 1,
            r1: 1,
            r2: 1,
            tables,
            reference_data,
            main_lens: [0u8; 256 + MAX_POSITION_SLOTS * LEN_HEADER_COUNT],
            main_tree_size,
            length_lens: [0u8; LENGTH_TREE_SIZE],
            e8_enabled: false,
            e8_file_size: 0,
            header_parsed: false,
            chunk_offset: 0,
        }
    }

    /// Run decompression across all chunks.
    fn run(&mut self, output: &mut [u8]) -> Result<usize> {
        while self.out_pos < self.out_len {
            self.decompress_chunk(output)?;
        }
        Ok(self.out_pos)
    }

    /// Decompress one chunk (up to 32 KB of output).
    fn decompress_chunk(&mut self, output: &mut [u8]) -> Result<()> {
        // Read 16-bit LE chunk-size prefix.
        if self.input_pos + 2 > self.input.len() {
            return Err(err_truncated(self.input_pos, 2, 0));
        }
        let chunk_compressed_size =
            u16::from_le_bytes([self.input[self.input_pos], self.input[self.input_pos + 1]])
                as usize;
        self.input_pos += 2;

        // Validate chunk data is available.
        let chunk_end = self.input_pos + chunk_compressed_size;
        if chunk_end > self.input.len() {
            return Err(err_truncated(
                self.input_pos,
                chunk_compressed_size,
                self.input.len() - self.input_pos,
            ));
        }

        let chunk_data = &self.input[self.input_pos..chunk_end];
        let mut reader = BitReader::new(chunk_data);
        reader.set_zero_fill(true);

        // Parse stream header from first chunk.
        if !self.header_parsed {
            self.parse_header(&mut reader)?;
            self.header_parsed = true;
        }

        // Determine how many output bytes this chunk produces.
        let chunk_out_start = self.out_pos;
        let chunk_out_limit = (self.out_pos + CHUNK_SIZE).min(self.out_len);

        // Decompress blocks within this chunk until we reach the limit.
        while self.out_pos < chunk_out_limit {
            self.decode_block(&mut reader, output, chunk_out_limit)?;
        }

        // Apply E8 post-processing to this chunk's output.
        let chunk_out_end = self.out_pos;
        if self.e8_enabled && chunk_out_end > chunk_out_start {
            undo_e8_preprocessing(
                &mut output[chunk_out_start..chunk_out_end],
                self.e8_file_size,
                self.chunk_offset,
            );
        }
        self.chunk_offset += (chunk_out_end - chunk_out_start) as i64;

        // Advance input past this chunk.
        self.input_pos = chunk_end;

        Ok(())
    }

    /// Parse the LZXD stream header (E8 translation flag + optional
    /// file size).
    fn parse_header(&mut self, reader: &mut BitReader<'_>) -> Result<()> {
        let e8_flag = reader.read_bits(1)?;
        if e8_flag == 1 {
            let high = reader.read_bits(16)?;
            let low = reader.read_bits(16)?;
            self.e8_enabled = true;
            self.e8_file_size = ((high << 16) | low) as i32;
        }
        Ok(())
    }

    /// Decode a single block (verbatim, aligned, or uncompressed).
    fn decode_block(
        &mut self,
        reader: &mut BitReader<'_>,
        output: &mut [u8],
        chunk_limit: usize,
    ) -> Result<()> {
        let block_type = reader.read_bits(3)?;
        let block_size = reader.read_bits(24)? as usize;
        let block_end = (self.out_pos + block_size).min(chunk_limit);

        match block_type {
            BLOCK_VERBATIM => {
                let (main_tbl, len_tbl) = self.read_main_and_length_trees(reader)?;
                self.decode_compressed(reader, output, block_end, &main_tbl, &len_tbl, None)
            }
            BLOCK_ALIGNED => {
                let aligned_tbl = self.read_aligned_tree(reader)?;
                let (main_tbl, len_tbl) = self.read_main_and_length_trees(reader)?;
                self.decode_compressed(
                    reader,
                    output,
                    block_end,
                    &main_tbl,
                    &len_tbl,
                    Some(&aligned_tbl),
                )
            }
            BLOCK_UNCOMPRESSED => self.decode_uncompressed(reader, output, block_end),
            _ => Err(err_invalid(reader.position(), "LZXD invalid block type")),
        }
    }
}

// -- Tree reading ----------------------------------------------------------

impl DecompressCtx<'_> {
    fn read_aligned_tree(&mut self, reader: &mut BitReader<'_>) -> Result<HuffmanTable> {
        let mut lens = [0u8; ALIGNED_TREE_SIZE];
        for len in &mut lens {
            *len = reader.read_bits(ALIGNED_CODE_BITS)? as u8;
        }
        HuffmanTable::from_code_lengths(&lens, 7)
    }

    fn read_main_and_length_trees(
        &mut self,
        reader: &mut BitReader<'_>,
    ) -> Result<(HuffmanTable, HuffmanTable)> {
        let main_size = self.main_tree_size;

        let mut main_lens = self.main_lens;
        decode_pretree_delta(reader, &mut main_lens[..256])?;
        decode_pretree_delta(reader, &mut main_lens[256..main_size])?;
        self.main_lens = main_lens;

        let mut length_lens = self.length_lens;
        decode_pretree_delta(reader, &mut length_lens[..LENGTH_TREE_SIZE])?;
        self.length_lens = length_lens;

        let main_tbl = HuffmanTable::from_code_lengths(&self.main_lens[..main_size], 11)?;
        let len_tbl = HuffmanTable::from_code_lengths(&self.length_lens, 9)?;
        Ok((main_tbl, len_tbl))
    }
}

/// Read a 20-symbol pre-tree and decode delta-encoded code lengths.
fn decode_pretree_delta(reader: &mut BitReader<'_>, lens: &mut [u8]) -> Result<()> {
    let mut pre_lens = [0u8; PRE_TREE_SIZE];
    for pl in &mut pre_lens {
        *pl = reader.read_bits(PRE_TREE_CODE_BITS)? as u8;
    }
    let pre_table = HuffmanTable::from_code_lengths(&pre_lens, 6)?;
    decode_code_lengths(reader, &pre_table, lens)
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
                "LZXD invalid pre-tree symbol",
            ));
        }
    }

    Ok(())
}

// -- Compressed block decoding ---------------------------------------------

impl DecompressCtx<'_> {
    fn decode_compressed(
        &mut self,
        reader: &mut BitReader<'_>,
        output: &mut [u8],
        block_end: usize,
        main_tbl: &HuffmanTable,
        len_tbl: &HuffmanTable,
        aligned_tbl: Option<&HuffmanTable>,
    ) -> Result<()> {
        while self.out_pos < block_end {
            let symbol = main_tbl.decode_symbol(reader)? as usize;

            if symbol < 256 {
                if self.out_pos >= output.len() {
                    return Err(err_output_too_small(self.out_pos + 1, output.len()));
                }
                output[self.out_pos] = symbol as u8;
                self.out_pos += 1;
            } else {
                let (offset, length) = self.decode_match(reader, symbol, len_tbl, aligned_tbl)?;
                self.copy_match(output, offset, length, block_end)?;
            }
        }
        Ok(())
    }

    /// Decode a match: extract offset and length from the symbol and
    /// bitstream.
    fn decode_match(
        &mut self,
        reader: &mut BitReader<'_>,
        symbol: usize,
        len_tbl: &HuffmanTable,
        aligned_tbl: Option<&HuffmanTable>,
    ) -> Result<(usize, usize)> {
        let match_code = symbol - 256;
        let position_slot = match_code / LEN_HEADER_COUNT;
        let length_header = match_code % LEN_HEADER_COUNT;

        // Decode base match length.
        let mut length = if length_header < 7 {
            length_header + MIN_MATCH_LEN
        } else {
            let len_sym = len_tbl.decode_symbol(reader)? as usize;
            7 + len_sym + MIN_MATCH_LEN
        };

        // Decode offset.
        let offset = self.decode_offset(reader, position_slot, aligned_tbl)?;

        // Extra length for matches >= 257 (LZXD extension).
        if length == 257 {
            length = 257 + decode_extra_length(reader)?;
        }

        Ok((offset, length))
    }

    /// Decode match offset from position slot.
    fn decode_offset(
        &mut self,
        reader: &mut BitReader<'_>,
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
                        reader.position(),
                        "LZXD position slot exceeds window",
                    ));
                }

                let extra = u32::from(self.tables.footer_bits[position_slot]);
                let base = self.tables.base_position[position_slot];

                let (verbatim_bits, aligned_bits) = if extra >= 3 {
                    if let Some(atbl) = aligned_tbl {
                        let vb_count = extra - 3;
                        let vb = if vb_count > 0 {
                            reader.read_bits(vb_count)?
                        } else {
                            0
                        };
                        let ab = atbl.decode_symbol(reader)? as u32;
                        ((vb << 3), ab)
                    } else {
                        (reader.read_bits(extra)?, 0)
                    }
                } else if extra > 0 {
                    (reader.read_bits(extra)?, 0)
                } else {
                    (0, 0)
                };

                let raw = base + verbatim_bits + aligned_bits;
                if raw < OFFSET_ADJUSTMENT {
                    return Err(err_invalid(
                        reader.position(),
                        "LZXD computed offset below minimum",
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

    /// Copy a match, handling offsets that reach into reference data.
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

        if offset == 0 {
            return Err(err_invalid(0, "LZXD zero match offset"));
        }

        let ref_len = self.reference_data.len();

        if offset > self.out_pos {
            // Match reaches into reference data. The conceptual window
            // is [reference_data ++ output], so bytes beyond out_pos
            // are sourced from the end of reference_data.
            let ref_reach = offset - self.out_pos;
            if ref_reach > ref_len {
                return Err(err_invalid(
                    0,
                    "LZXD match offset exceeds reference data + output",
                ));
            }
            let ref_start = ref_len - ref_reach;

            let from_ref = ref_reach.min(length);
            let from_out = length - from_ref;

            output[self.out_pos..self.out_pos + from_ref]
                .copy_from_slice(&self.reference_data[ref_start..ref_start + from_ref]);

            // After exhausting the reference portion, the next bytes
            // in the conceptual window are output[0..], since reference
            // data is logically prepended to the output.
            for i in 0..from_out {
                output[self.out_pos + from_ref + i] = output[i];
            }
        } else {
            // Normal match within output.
            copy_within_output(output, self.out_pos, offset, length);
        }

        self.out_pos += length;
        Ok(())
    }
}

/// Decode the LZXD extra length field (for match lengths >= 257).
///
/// Returns the extra_len value; caller adds 257 for total match length.
/// Prefix-coded: 0 → 8 bits (0..255), 10 → 10 bits + 256 (256..1279),
/// 110 → 12 bits + 1280 (1280..5375), 111 → 15 bits (0..32767).
fn decode_extra_length(reader: &mut BitReader<'_>) -> Result<usize> {
    let bit0 = reader.read_bits(1)?;
    if bit0 == 0 {
        return Ok(reader.read_bits(8)? as usize);
    }
    let bit1 = reader.read_bits(1)?;
    if bit1 == 0 {
        return Ok(reader.read_bits(10)? as usize + 256);
    }
    let bit2 = reader.read_bits(1)?;
    if bit2 == 0 {
        return Ok(reader.read_bits(12)? as usize + 256 + 1024);
    }
    Ok(reader.read_bits(15)? as usize)
}

// -- Uncompressed block decoding -------------------------------------------

impl DecompressCtx<'_> {
    fn decode_uncompressed(
        &mut self,
        reader: &mut BitReader<'_>,
        output: &mut [u8],
        block_end: usize,
    ) -> Result<()> {
        // Align to 16-bit boundary.
        reader.align_to_u16();

        // Read R0, R1, R2.
        self.r0 = reader.read_u32_le()?;
        self.r1 = reader.read_u32_le()?;
        self.r2 = reader.read_u32_le()?;

        // Copy raw bytes.
        let count = block_end - self.out_pos;
        if self.out_pos + count > output.len() {
            return Err(err_output_too_small(self.out_pos + count, output.len()));
        }

        for _ in 0..count {
            output[self.out_pos] = reader.read_raw_byte()?;
            self.out_pos += 1;
        }

        // Re-align if the raw byte count was odd.
        if !count.is_multiple_of(2) {
            let _ = reader.read_raw_byte()?;
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
    use crate::lzxd::WindowSize;

    /// MS-PATCH spec § 3 example: "abc" encoded as an uncompressed
    /// block. Raw hex (including 2-byte chunk-size prefix):
    /// 14 00 00 30 30 00 01 00 00 00 01 00 00 00 01 00 00 00 61 62 63 00
    #[test]
    fn spec_abc_uncompressed() {
        let input: &[u8] = &[
            0x14, 0x00, // chunk size: 20 bytes
            0x00, 0x30, 0x30, 0x00, // E8=0, block_type=3(uncompressed), block_size=3
            0x01, 0x00, 0x00, 0x00, // R0 = 1
            0x01, 0x00, 0x00, 0x00, // R1 = 1
            0x01, 0x00, 0x00, 0x00, // R2 = 1
            0x61, 0x62, 0x63, // "abc"
            0x00, // padding (odd count)
        ];
        let mut output = [0u8; 3];
        let n = decompress(input, &mut output, WindowSize::KB128, &[]).expect("spec abc example");
        assert_eq!(n, 3);
        assert_eq!(&output, b"abc");
    }

    /// Same as above but without the chunk-size prefix (testing the
    /// internal chunk data parsing via the Lonami/lzxd convention).
    /// We still need the prefix since our API expects it.
    #[test]
    fn spec_abc_with_32kb_window() {
        let input: &[u8] = &[
            0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
        ];
        let mut output = [0u8; 3];
        // WindowSize shouldn't matter for an uncompressed block.
        let n =
            decompress(input, &mut output, WindowSize::MB32, &[]).expect("abc with 32MB window");
        assert_eq!(n, 3);
        assert_eq!(&output, b"abc");
    }

    #[test]
    fn lenient_on_valid_matches_strict() {
        let input: &[u8] = &[
            0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
        ];
        let mut strict_out = [0u8; 3];
        let strict_n = decompress(input, &mut strict_out, WindowSize::KB128, &[]).expect("strict");

        let mut lenient_out = [0u8; 3];
        let lenient_r = decompress_lenient(input, &mut lenient_out, WindowSize::KB128, &[]);

        assert_eq!(strict_n, lenient_r.bytes_written);
        assert!(!lenient_r.had_errors);
        assert_eq!(strict_out, lenient_out);
    }

    #[test]
    fn truncated_input_returns_error() {
        let input: &[u8] = &[0x14]; // only 1 byte, needs 2 for chunk size
        let mut output = [0u8; 3];
        assert!(decompress(input, &mut output, WindowSize::KB128, &[]).is_err());
    }

    #[test]
    fn invalid_block_type_returns_error() {
        // Block type = 0 (invalid).
        let input: &[u8] = &[
            0x14, 0x00, // chunk size
            0x00, 0x00, 0x30, 0x00, // E8=0, block_type=0(invalid), block_size=3
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let mut output = [0u8; 3];
        assert!(decompress(input, &mut output, WindowSize::KB128, &[]).is_err());
    }

    #[test]
    fn extra_length_decode() {
        // Test the extra length prefix decoder in isolation.
        use crate::bitstream::BitReader;

        // Prefix 0: 8-bit value = 42 → extra_len = 42
        let mut w = crate::test_bitwriter::BitWriter::new();
        w.write_bits(0, 1); // prefix bit 0
        w.write_bits(42, 8);
        w.flush();
        let data = w.data();
        let mut r = BitReader::new(data);
        assert_eq!(decode_extra_length(&mut r).expect("p0"), 42);

        // Prefix 10: 10-bit value = 100 → extra_len = 100 + 256 = 356
        let mut w = crate::test_bitwriter::BitWriter::new();
        w.write_bits(1, 1); // prefix bit 1
        w.write_bits(0, 1); // prefix bit 0
        w.write_bits(100, 10);
        w.flush();
        let data = w.data();
        let mut r = BitReader::new(data);
        assert_eq!(decode_extra_length(&mut r).expect("p10"), 356);

        // Prefix 110: 12-bit value = 500 → extra_len = 500 + 1280 = 1780
        let mut w = crate::test_bitwriter::BitWriter::new();
        w.write_bits(0b110, 3);
        w.write_bits(500, 12);
        w.flush();
        let data = w.data();
        let mut r = BitReader::new(data);
        assert_eq!(decode_extra_length(&mut r).expect("p110"), 1780);

        // Prefix 111: 15-bit value = 1000 → extra_len = 1000
        let mut w = crate::test_bitwriter::BitWriter::new();
        w.write_bits(0b111, 3);
        w.write_bits(1000, 15);
        w.flush();
        let data = w.data();
        let mut r = BitReader::new(data);
        assert_eq!(decode_extra_length(&mut r).expect("p111"), 1000);
    }

    #[test]
    fn uncompressed_block_with_reference_data() {
        // Reference data = "HELLO", output should be "WORLD".
        // Just an uncompressed block — reference data isn't used
        // by uncompressed blocks, but verify it doesn't break.
        let input: &[u8] = &[
            0x18, 0x00, // chunk size: 24 bytes
            0x00, 0x30, 0x50, 0x00, // E8=0, block_type=3, block_size=5
            0x01, 0x00, 0x00, 0x00, // R0 = 1
            0x01, 0x00, 0x00, 0x00, // R1 = 1
            0x01, 0x00, 0x00, 0x00, // R2 = 1
            b'W', b'O', b'R', b'L', b'D', // "WORLD"
            0x00, // padding
            0x00, 0x00, // extra padding to fill chunk size
        ];
        let mut output = [0u8; 5];
        let n = decompress(input, &mut output, WindowSize::KB128, b"HELLO")
            .expect("uncompressed with ref");
        assert_eq!(n, 5);
        assert_eq!(&output, b"WORLD");
    }

    #[test]
    fn copy_within_output_non_overlapping() {
        let mut buf = [0u8; 20];
        buf[0..5].copy_from_slice(b"HELLO");
        copy_within_output(&mut buf, 10, 10, 5);
        assert_eq!(&buf[10..15], b"HELLO");
    }

    #[test]
    fn copy_within_output_overlapping() {
        // offset=1, length=5: repeats last byte 5 times.
        let mut buf = [0u8; 10];
        buf[0] = b'A';
        copy_within_output(&mut buf, 1, 1, 5);
        assert_eq!(&buf[1..6], b"AAAAA");
    }

    #[test]
    fn window_size_does_not_affect_uncompressed() {
        // The spec abc example should work with any window size.
        let input: &[u8] = &[
            0x14, 0x00, 0x00, 0x30, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x61, 0x62, 0x63, 0x00,
        ];
        for &ws in &[
            WindowSize::KB128,
            WindowSize::KB256,
            WindowSize::KB512,
            WindowSize::MB1,
            WindowSize::MB2,
            WindowSize::MB4,
            WindowSize::MB8,
            WindowSize::MB16,
            WindowSize::MB32,
        ] {
            let mut output = [0u8; 3];
            let n = decompress(input, &mut output, ws, &[])
                .unwrap_or_else(|e| panic!("failed with {ws:?}: {e}"));
            assert_eq!(n, 3);
            assert_eq!(&output, b"abc");
        }
    }

    /// Construct a synthetic verbatim block to test compressed data
    /// decompression with only literal bytes.
    #[test]
    fn synthetic_verbatim_literals_only() {
        use crate::test_bitwriter::BitWriter;

        // Encode "AB" using a verbatim block.
        // KB128 → 34 position slots → main tree = 256 + 272 = 528
        let mut w = BitWriter::new();
        w.write_raw_bytes(&[0x00, 0x00]); // chunk size placeholder
        w.write_bits(0, 1); // E8 disabled
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(2, 24); // block size = 2

        // Main tree first half (256 elements): A=1, B=1, rest=0.
        // Deltas: 65 zeros, code 16, code 16, 193 zeros.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2); // delta 16 for A
        w.write_bits(0b01, 2); // delta 16 for B
        encode_zero_run_4sym(&mut w, 193);

        // Main tree second half (272 elements): all zero.
        write_pretree_3sym(&mut w);
        encode_zero_run_3sym(&mut w, 272);

        // Length tree (249 elements): syms 0,1 get len=1 (minimal valid).
        // Deltas: code 16, code 16, 247 zeros.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2); // delta 16 for sym 0
        w.write_bits(0b01, 2); // delta 16 for sym 1
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: A(code 0), B(code 1).
        w.write_bits(0, 1);
        w.write_bits(1, 1);

        let mut data = w.into_data();
        patch_chunk_size(&mut data);

        let mut output = [0u8; 2];
        let n = decompress(&data, &mut output, WindowSize::KB128, &[]).expect("synthetic verbatim");
        assert_eq!(n, 2);
        assert_eq!(&output, b"AB");
    }

    /// Test reference data matches: match offset exceeds output position.
    #[test]
    fn reference_data_match() {
        use crate::test_bitwriter::BitWriter;

        // Ref="ABCDE", output: match(offset=5,len=3) + literal 'X' → "ABCX".
        // offset=5 → formatted=7 → slot 5 (base=6, footer=1), footer_val=1.
        // Match symbol = 256 + 5*8 + 1 = 297 (index 41 in second half).
        let mut w = BitWriter::new();
        w.write_raw_bytes(&[0x00, 0x00]);
        w.write_bits(0, 1); // E8 disabled
        w.write_bits(BLOCK_VERBATIM, 3);
        w.write_bits(4, 24);

        // Main first half: X(0x58)=1, rest=0. 88 zeros, code 16, 167 zeros.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 88);
        w.write_bits(0b01, 2); // delta 16 for X
        encode_zero_run_4sym(&mut w, 167);

        // Main second half: index 41=1, rest=0. 41 zeros, code 16, 230 zeros.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 41);
        w.write_bits(0b01, 2); // delta 16 for match sym
        encode_zero_run_4sym(&mut w, 230);

        // Length tree: syms 0,1 get len=1.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: match(code 1) + footer(1) + literal X(code 0).
        w.write_bits(1, 1);
        w.write_bits(1, 1);
        w.write_bits(0, 1);

        let mut data = w.into_data();
        patch_chunk_size(&mut data);

        let mut output = [0u8; 4];
        let n = decompress(&data, &mut output, WindowSize::KB128, b"ABCDE")
            .expect("reference data match");
        assert_eq!(n, 4);
        assert_eq!(&output, b"ABCX");
    }

    /// Test aligned offset block: match with offset requiring aligned bits.
    #[test]
    fn synthetic_aligned_offset_block() {
        use crate::test_bitwriter::BitWriter;

        // Encode "AAAAAA" using an aligned offset block.
        // 1 literal 'A', then match(offset=1, length=5) to repeat it.
        //
        // offset=1 → formatted_offset=3 → slot 3 (base=3, footer=0).
        // Match symbol = 256 + 3*8 + 3 = 283 (length_header=3 → len=5).
        // Slot 3 has 0 footer bits, so no aligned/verbatim bits needed.
        let mut w = BitWriter::new();
        w.write_raw_bytes(&[0x00, 0x00]); // chunk size placeholder
        w.write_bits(0, 1); // E8 disabled

        // Block type = aligned offset (2), size = 6.
        w.write_bits(BLOCK_ALIGNED, 3);
        w.write_bits(6, 24);

        // Aligned offset tree: 8 elements, 3 bits each.
        // Give syms 0,1 len=1 for a valid tree (others=0).
        let aligned_lens: [u8; 8] = [1, 1, 0, 0, 0, 0, 0, 0];
        for &al in &aligned_lens {
            w.write_bits(u32::from(al), 3);
        }

        // Main tree first half (256 elements): A(0x41)=1, rest=0.
        // But we need 2 symbols for valid tree. Add sym 283 in second half.
        // First half: 65 zeros, code 16, 190 zeros.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 65);
        w.write_bits(0b01, 2); // delta 16 for 'A'
        encode_zero_run_4sym(&mut w, 190);

        // Main tree second half (272 elements): index 27 (sym 283)=1.
        // 27 zeros, code 16, 244 zeros.
        write_pretree_4sym(&mut w);
        encode_zero_run_4sym(&mut w, 27);
        w.write_bits(0b01, 2); // delta 16 for match sym
        encode_zero_run_4sym(&mut w, 244);

        // Length tree: syms 0,1 get len=1.
        write_pretree_4sym(&mut w);
        w.write_bits(0b01, 2);
        w.write_bits(0b01, 2);
        encode_zero_run_4sym(&mut w, 247);

        // Tokens: literal A (code 0), match 283 (code 1).
        // Main tree: A=0x41(code 0, len 1), sym283(code 1, len 1).
        w.write_bits(0, 1); // 'A'
        w.write_bits(1, 1); // match (slot=3, no footer bits needed)

        let mut data = w.into_data();
        patch_chunk_size(&mut data);

        let mut output = [0u8; 6];
        let n =
            decompress(&data, &mut output, WindowSize::KB128, &[]).expect("aligned offset block");
        assert_eq!(n, 6);
        assert_eq!(&output, b"AAAAAA");
    }

    // -- Test helpers for building synthetic LZXD bitstreams ---------------

    /// Write 4-symbol pretree: sym 0→00, 16→01, 17→10, 18→11.
    fn write_pretree_4sym(w: &mut crate::test_bitwriter::BitWriter) {
        let mut lens = [0u8; 20];
        lens[0] = 2;
        lens[16] = 2;
        lens[17] = 2;
        lens[18] = 2;
        for &pl in &lens {
            w.write_bits(u32::from(pl), 4);
        }
    }

    /// Write 3-symbol pretree: sym 0→0, 17→10, 18→11.
    fn write_pretree_3sym(w: &mut crate::test_bitwriter::BitWriter) {
        let mut lens = [0u8; 20];
        lens[0] = 1;
        lens[17] = 2;
        lens[18] = 2;
        for &pl in &lens {
            w.write_bits(u32::from(pl), 4);
        }
    }

    /// Encode a run of `count` zeros. Pretree: 0→00, 17→10, 18→11.
    fn encode_zero_run_4sym(w: &mut crate::test_bitwriter::BitWriter, mut count: usize) {
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
            w.write_bits(0b00, 2);
        }
    }

    /// Encode zeros with 3-symbol pretree (0→0, 17→10, 18→11).
    fn encode_zero_run_3sym(w: &mut crate::test_bitwriter::BitWriter, mut count: usize) {
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

    fn patch_chunk_size(data: &mut [u8]) {
        let size = (data.len() - 2) as u16;
        data[0] = (size & 0xFF) as u8;
        data[1] = (size >> 8) as u8;
    }
}
