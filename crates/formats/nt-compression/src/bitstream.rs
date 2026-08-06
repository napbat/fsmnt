//! Shared 16-bit LE bitstream reader for XPRESS Huffman and LZX.
//!
//! Input is a sequence of 16-bit little-endian words. Bits are consumed
//! MSB-first within each word. A 32-bit accumulator holds buffered bits
//! with valid bits aligned to the MSB.

use alloc::vec::Vec;

use crate::{Error, Result};

/// Reads bits from a byte stream in 16-bit LE words, MSB-first.
///
/// Used by both XPRESS Huffman and LZX decompression. The accumulator
/// keeps valid bits in the high positions of a `u32`.
#[allow(
    dead_code,
    reason = "used by xpress-huffman and lzx when those features are enabled"
)]
pub(crate) struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_buffer: u64,
    bits_remaining: u32,
    /// When true, treat exhausted input as infinite zero bits instead
    /// of returning an error. Used by XPRESS Huffman where the
    /// encoder relies on the output-size limit to stop the decoder.
    zero_fill: bool,
}

#[allow(
    dead_code,
    reason = "used by xpress-huffman and lzx when those features are enabled"
)]
impl<'a> BitReader<'a> {
    /// Create a new `BitReader` over the given data slice.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_buffer: 0,
            bits_remaining: 0,
            zero_fill: false,
        }
    }

    /// Enable zero-fill mode: when the input is exhausted, behave
    /// as if infinite zero bytes follow instead of returning an error.
    pub fn set_zero_fill(&mut self, enabled: bool) {
        self.zero_fill = enabled;
    }

    /// Ensure at least `count` bits are available in the buffer.
    ///
    /// Loads 16-bit LE words from the input as needed. Returns an
    /// error if the input is exhausted before enough bits are
    /// available.
    #[inline]
    pub fn ensure_bits(&mut self, count: u32) -> Result<()> {
        while self.bits_remaining < count {
            if self.byte_pos + 2 <= self.data.len() {
                let word =
                    u16::from_le_bytes([self.data[self.byte_pos], self.data[self.byte_pos + 1]]);
                self.byte_pos += 2;
                let shift = 64 - self.bits_remaining - 16;
                self.bit_buffer |= u64::from(word) << shift;
                self.bits_remaining += 16;
            } else if self.zero_fill && self.byte_pos < self.data.len() {
                // Trailing odd byte — load as 8 bits into the MSB
                // positions of the accumulator.  Only in zero_fill
                // mode (XPRESS Huffman) where RTL can produce
                // non-word-aligned bitstreams.
                let byte = self.data[self.byte_pos];
                self.byte_pos += 1;
                let shift = 64 - self.bits_remaining - 8;
                self.bit_buffer |= u64::from(byte) << shift;
                self.bits_remaining += 8;
            } else if self.zero_fill {
                // Treat exhausted input as infinite zeros. The
                // already-buffered bits are MSB-aligned with zeros
                // in the low positions, so just claim we have enough.
                self.bits_remaining = count;
                break;
            } else {
                return Err(Error::InputTruncated {
                    offset: self.byte_pos,
                    expected: 2,
                    actual: 0,
                });
            }
        }
        Ok(())
    }

    /// Peek at the top `count` bits without consuming them.
    ///
    /// The caller must call `ensure_bits(count)` first. If fewer
    /// than `count` bits are buffered the result is undefined (but
    /// safe — just wrong).
    #[inline]
    pub fn peek_bits(&self, count: u32) -> u32 {
        if count == 0 {
            return 0;
        }
        u32::try_from(self.bit_buffer >> (64 - count))
            .expect("peeking at most 32 bits leaves no set bits above bit 31")
    }

    /// Consume `count` bits from the buffer (shift them out).
    #[inline]
    pub fn consume_bits(&mut self, count: u32) {
        self.bit_buffer <<= count;
        self.bits_remaining -= count;
    }

    /// Read `count` bits: ensure + peek + consume.
    #[inline]
    pub fn read_bits(&mut self, count: u32) -> Result<u32> {
        if count == 0 {
            return Ok(0);
        }
        self.ensure_bits(count)?;
        let value = self.peek_bits(count);
        self.consume_bits(count);
        Ok(value)
    }

    /// Current byte position in the input stream.
    pub fn position(&self) -> usize {
        self.byte_pos
    }

    /// Number of bits still buffered in the accumulator.
    pub fn bits_in_buffer(&self) -> u32 {
        self.bits_remaining
    }

    /// Align the reader to the next 16-bit word boundary.
    ///
    /// Discards any remaining bits in the accumulator and rounds
    /// `byte_pos` up to the next even offset. Used by LZX when
    /// switching from bitstream mode to raw-byte mode for
    /// uncompressed blocks.
    pub fn align_to_u16(&mut self) {
        self.bit_buffer = 0;
        self.bits_remaining = 0;
        self.byte_pos = (self.byte_pos + 1) & !1;
    }

    /// Read a raw `u16` LE value directly from the input.
    ///
    /// Must be called after `align_to_u16`. Used for LZX
    /// uncompressed blocks.
    pub fn read_u16_le(&mut self) -> Result<u16> {
        if self.byte_pos + 2 > self.data.len() {
            return Err(Error::InputTruncated {
                offset: self.byte_pos,
                expected: 2,
                actual: self.data.len().saturating_sub(self.byte_pos),
            });
        }
        let value = u16::from_le_bytes([self.data[self.byte_pos], self.data[self.byte_pos + 1]]);
        self.byte_pos += 2;
        Ok(value)
    }

    /// Read a raw byte directly from the current input position
    /// *without* going through the bit accumulator.
    ///
    /// Used by XPRESS Huffman for match-length extension bytes
    /// which are interleaved in the byte stream alongside the
    /// 16-bit bitstream words (see MS-XCA §2.1).
    pub fn read_interleaved_byte(&mut self) -> Result<u8> {
        if self.byte_pos >= self.data.len() {
            return Err(Error::InputTruncated {
                offset: self.byte_pos,
                expected: 1,
                actual: 0,
            });
        }
        let value = self.data[self.byte_pos];
        self.byte_pos += 1;
        Ok(value)
    }

    /// Read a raw `u16` LE value directly from the current input
    /// position *without* going through the bit accumulator.
    ///
    /// Used by XPRESS Huffman for match-length extension words
    /// which are interleaved in the byte stream (see MS-XCA §2.1).
    pub fn read_interleaved_u16_le(&mut self) -> Result<u16> {
        if self.byte_pos + 2 > self.data.len() {
            return Err(Error::InputTruncated {
                offset: self.byte_pos,
                expected: 2,
                actual: self.data.len().saturating_sub(self.byte_pos),
            });
        }
        let value = u16::from_le_bytes([self.data[self.byte_pos], self.data[self.byte_pos + 1]]);
        self.byte_pos += 2;
        Ok(value)
    }

    /// Read a single raw byte directly from the input.
    ///
    /// Must be called after `align_to_u16`. Used for LZX
    /// uncompressed blocks where data is byte-aligned.
    pub fn read_raw_byte(&mut self) -> Result<u8> {
        if self.byte_pos >= self.data.len() {
            return Err(Error::InputTruncated {
                offset: self.byte_pos,
                expected: 1,
                actual: 0,
            });
        }
        let value = self.data[self.byte_pos];
        self.byte_pos += 1;
        Ok(value)
    }

    /// Read a raw `u32` LE value directly from the input.
    ///
    /// Must be called after `align_to_u16`. Used for LZX
    /// uncompressed blocks.
    pub fn read_u32_le(&mut self) -> Result<u32> {
        if self.byte_pos + 4 > self.data.len() {
            return Err(Error::InputTruncated {
                offset: self.byte_pos,
                expected: 4,
                actual: self.data.len().saturating_sub(self.byte_pos),
            });
        }
        let value = u32::from_le_bytes([
            self.data[self.byte_pos],
            self.data[self.byte_pos + 1],
            self.data[self.byte_pos + 2],
            self.data[self.byte_pos + 3],
        ]);
        self.byte_pos += 4;
        Ok(value)
    }
}

/// Writes bits to a byte buffer in 16-bit LE words, MSB-first.
///
/// Mirrors the `BitReader` conventions: bits accumulate MSB-first in a
/// `u32` accumulator and are flushed as 16-bit LE words when ≥16 bits
/// are buffered.
#[allow(
    dead_code,
    reason = "used by compress-xpress-huffman and compress-lzx when those features are enabled"
)]
pub(crate) struct BitWriter {
    data: Vec<u8>,
    accum: u64,
    accum_bits: u32,
}

#[allow(
    dead_code,
    reason = "used by compress-xpress-huffman and compress-lzx when those features are enabled"
)]
impl BitWriter {
    /// Create a new empty `BitWriter`.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            accum: 0,
            accum_bits: 0,
        }
    }

    /// Create a new `BitWriter` with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            accum: 0,
            accum_bits: 0,
        }
    }

    /// Write `count` bits from the low bits of `value`, MSB-first.
    #[inline]
    pub fn write_bits(&mut self, value: u32, count: u32) {
        debug_assert!(count <= 16, "write_bits: count must be <= 16");
        self.accum = (self.accum << count) | u64::from(value & ((1 << count) - 1));
        self.accum_bits += count;
        if self.accum_bits >= 16 {
            self.accum_bits -= 16;
            let word = u16::try_from(self.accum >> self.accum_bits)
                .expect("the writer flushes one 16-bit word at a time");
            let le = word.to_le_bytes();
            self.data.push(le[0]);
            self.data.push(le[1]);
            self.accum &= (1u64 << self.accum_bits) - 1;
        }
    }

    /// Write a Huffman code plus extra bits in one operation.
    ///
    /// Combines what would be two `write_bits` calls into one,
    /// reducing intermediate accumulator shifts.
    #[inline]
    pub fn write_code_and_extra(&mut self, code: u32, code_bits: u32, extra: u32, extra_bits: u32) {
        let total_bits = code_bits + extra_bits;
        let merged = (u64::from(code & ((1 << code_bits) - 1)) << extra_bits)
            | u64::from(extra & ((1 << extra_bits) - 1));
        self.accum = (self.accum << total_bits) | merged;
        self.accum_bits += total_bits;
        while self.accum_bits >= 16 {
            self.accum_bits -= 16;
            let word = u16::try_from(self.accum >> self.accum_bits)
                .expect("the writer flushes one 16-bit word at a time");
            let le = word.to_le_bytes();
            self.data.push(le[0]);
            self.data.push(le[1]);
            self.accum &= (1u64 << self.accum_bits) - 1;
        }
    }

    /// Write a raw byte directly into the output stream WITHOUT
    /// flushing the bit accumulator.
    ///
    /// Used by XPRESS Huffman for match-length extension bytes that
    /// are interleaved in the byte stream between bitstream words.
    /// The decompressor reads these via `read_interleaved_byte`.
    pub fn write_interleaved_byte(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Write a raw `u16` LE value directly into the output stream
    /// WITHOUT flushing the bit accumulator.
    ///
    /// Used by XPRESS Huffman for match-length extension words
    /// interleaved in the byte stream.
    pub fn write_interleaved_u16_le(&mut self, value: u16) {
        let le = value.to_le_bytes();
        self.data.push(le[0]);
        self.data.push(le[1]);
    }

    /// Write a raw `u32` LE value directly into the output stream
    /// WITHOUT flushing the bit accumulator.
    ///
    /// Used by XPRESS Huffman for the 32-bit match-length extension
    /// interleaved in the byte stream.
    pub fn write_interleaved_u32_le(&mut self, value: u32) {
        let le = value.to_le_bytes();
        self.data.extend_from_slice(&le);
    }

    /// Write a raw `u16` value in little-endian byte order.
    ///
    /// The accumulator must be flushed (via `flush_bits` or
    /// `align_to_u16`) before calling this.
    pub fn write_u16_le(&mut self, value: u16) {
        debug_assert_eq!(
            self.accum_bits, 0,
            "write_u16_le: accumulator must be flushed"
        );
        let le = value.to_le_bytes();
        self.data.push(le[0]);
        self.data.push(le[1]);
    }

    /// Write a raw `u32` value in little-endian byte order.
    ///
    /// The accumulator must be flushed before calling this.
    pub fn write_u32_le(&mut self, value: u32) {
        debug_assert_eq!(
            self.accum_bits, 0,
            "write_u32_le: accumulator must be flushed"
        );
        let le = value.to_le_bytes();
        self.data.extend_from_slice(&le);
    }

    /// Write a single raw byte directly to the output.
    ///
    /// The accumulator must be flushed before calling this.
    pub fn write_raw_byte(&mut self, byte: u8) {
        debug_assert_eq!(
            self.accum_bits, 0,
            "write_raw_byte: accumulator must be flushed"
        );
        self.data.push(byte);
    }

    /// Flush any remaining bits in the accumulator, padding with zeros
    /// to fill a full 16-bit word.
    pub fn flush_bits(&mut self) {
        if self.accum_bits > 0 {
            let word = u16::try_from(self.accum << (16 - self.accum_bits))
                .expect("the final writer accumulator contains at most 16 bits");
            let le = word.to_le_bytes();
            self.data.push(le[0]);
            self.data.push(le[1]);
            self.accum = 0;
            self.accum_bits = 0;
        }
    }

    /// Flush bits and align the output to a 16-bit word boundary.
    ///
    /// If the byte position is odd after flushing, writes a zero pad
    /// byte.
    pub fn align_to_u16(&mut self) {
        self.flush_bits();
        if !self.data.len().is_multiple_of(2) {
            self.data.push(0);
        }
    }

    /// Flush and return the accumulated byte buffer.
    pub fn finish(mut self) -> Vec<u8> {
        self.flush_bits();
        self.data
    }

    /// Current byte position in the output buffer (not counting
    /// unflushed accumulator bits).
    pub fn position(&self) -> usize {
        self.data.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_single_bits() {
        // Input: [0x12, 0x34] → LE word 0x3412 = 0011_0100_0001_0010
        // MSB-first: bits are 0,0,1,1, 0,1,0,0, 0,0,0,0, 0,0,1,0 (wait...)
        // Actually 0x3412 = 0b0011_0100_0001_0010
        // Reading MSB-first: 0,0,1,1,0,1,0,0,0,0,0,1,0,0,1,0
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        let expected = [0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];
        for (i, &exp) in expected.iter().enumerate() {
            let bit = reader
                .read_bits(1)
                .unwrap_or_else(|_| panic!("failed at bit {i}"));
            assert_eq!(bit, exp, "mismatch at bit {i}");
        }
    }

    #[test]
    fn read_across_word_boundary() {
        // Two 16-bit LE words: [0x12, 0x34, 0x56, 0x78]
        // Word 1: 0x3412 = 0b0011_0100_0001_0010
        // Word 2: 0x7856 = 0b0111_1000_0101_0110
        //
        // Read 12 bits: top 12 of word 1 = 0b0011_0100_0001 = 0x341
        // Read 12 bits: bottom 4 of word 1 (0010) + top 8 of word 2
        //               = 0b0010_0111_1000 = 0x278
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut reader = BitReader::new(&data);

        let first_12 = reader.read_bits(12).expect("first 12 bits");
        assert_eq!(first_12, 0x341);

        let next_12 = reader.read_bits(12).expect("next 12 bits");
        assert_eq!(next_12, 0x278);
    }

    #[test]
    fn read_16_bits_exactly() {
        // [0x12, 0x34] → LE word 0x3412
        // Reading 16 bits MSB-first = 0x3412
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        let value = reader.read_bits(16).expect("16 bits");
        assert_eq!(value, 0x3412);
    }

    #[test]
    fn read_zero_bits() {
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        let value = reader.read_bits(0).expect("0 bits");
        assert_eq!(value, 0);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.bits_remaining, 0);
    }

    #[test]
    fn exhausted_input_returns_error() {
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        // Consume all 16 bits
        reader.read_bits(16).expect("16 bits");

        // Trying to read more should fail
        let result = reader.read_bits(1);
        assert!(result.is_err());
    }

    #[test]
    fn align_to_u16_discards_bits() {
        // Read some bits, then align — should discard buffered bits
        // and move byte_pos to the next even boundary.
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let mut reader = BitReader::new(&data);

        // Read 4 bits to load word 1 and partially consume it
        reader.read_bits(4).expect("4 bits");
        // byte_pos is now 2 (word 1 loaded), 12 bits remaining
        assert_eq!(reader.position(), 2);
        assert_eq!(reader.bits_remaining, 12);

        // Align — should discard the 12 remaining bits
        reader.align_to_u16();
        assert_eq!(reader.bits_remaining, 0);
        assert_eq!(reader.bit_buffer, 0);
        // byte_pos was 2 (already aligned), stays 2
        assert_eq!(reader.position(), 2);
    }

    #[test]
    fn align_to_u16_rounds_up_odd_position() {
        // Manually set an odd byte_pos to test rounding
        let data = [0x00; 6];
        let mut reader = BitReader::new(&data);
        reader.byte_pos = 3;

        reader.align_to_u16();
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn read_u16_le_after_align() {
        let data = [0xAB, 0xCD, 0xEF, 0x01];
        let mut reader = BitReader::new(&data);

        // Skip first word via bitstream
        reader.read_bits(16).expect("16 bits");
        reader.align_to_u16();

        let value = reader.read_u16_le().expect("u16");
        assert_eq!(value, 0x01EF);
    }

    #[test]
    fn read_u32_le_after_align() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut reader = BitReader::new(&data);

        // Skip first word via bitstream
        reader.read_bits(16).expect("16 bits");
        reader.align_to_u16();

        let value = reader.read_u32_le().expect("u32");
        assert_eq!(value, 0x0605_0403);

        let value2 = reader.read_u16_le().expect("u16");
        assert_eq!(value2, 0x0807);
    }

    #[test]
    fn read_u16_le_truncated_returns_error() {
        let data = [0x01];
        let mut reader = BitReader::new(&data);

        let result = reader.read_u16_le();
        assert!(result.is_err());
    }

    #[test]
    fn read_u32_le_truncated_returns_error() {
        let data = [0x01, 0x02, 0x03];
        let mut reader = BitReader::new(&data);

        let result = reader.read_u32_le();
        assert!(result.is_err());
    }

    #[test]
    fn peek_does_not_consume() {
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        reader.ensure_bits(8).expect("ensure 8 bits");
        let first = reader.peek_bits(8);
        let second = reader.peek_bits(8);
        assert_eq!(first, second);
        assert_eq!(reader.bits_remaining, 16);
    }

    #[test]
    fn ensure_bits_loads_multiple_words() {
        // 4 bytes = 2 words = 32 bits available
        let data = [0x12, 0x34, 0x56, 0x78];
        let mut reader = BitReader::new(&data);

        // Asking for 20 bits should load both words
        reader.ensure_bits(20).expect("ensure 20 bits");
        assert_eq!(reader.bits_remaining, 32);
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn four_msb_of_first_word() {
        // Input: [0x12, 0x34] → LE word 0x3412
        // 0x3412 = 0b0011_0100_0001_0010
        // Top 4 bits = 0b0011 = 0x3
        let data = [0x12, 0x34];
        let mut reader = BitReader::new(&data);

        let top4 = reader.read_bits(4).expect("4 bits");
        assert_eq!(top4, 0x3);
    }

    #[test]
    fn empty_input_returns_error_on_read() {
        let data: &[u8] = &[];
        let mut reader = BitReader::new(data);

        let result = reader.read_bits(1);
        assert!(result.is_err());
    }

    #[test]
    fn odd_length_input_errors_without_zero_fill() {
        // 3 bytes — first word loads fine, trailing odd byte
        // is rejected in default (strict) mode.
        let data = [0x01, 0x02, 0x03];
        let mut reader = BitReader::new(&data);

        reader.read_bits(16).expect("first word");
        let result = reader.read_bits(1);
        assert!(result.is_err());
    }

    #[test]
    fn odd_length_input_loads_trailing_byte_with_zero_fill() {
        // 3 bytes — first word loads fine, trailing odd byte
        // is loaded as 8 bits in zero_fill mode.
        let data = [0x01, 0x02, 0x03];
        let mut reader = BitReader::new(&data);
        reader.set_zero_fill(true);

        reader.read_bits(16).expect("first word");
        let val = reader.read_bits(8).expect("trailing byte");
        assert_eq!(val, 0x03);
        // Now truly exhausted — zero_fill keeps us going.
        let val = reader.read_bits(8).expect("zero fill");
        assert_eq!(val, 0);
    }

    // -- BitWriter tests --------------------------------------------------

    #[test]
    fn bitwriter_write_then_read_roundtrip() {
        let mut writer = BitWriter::new();
        // Write known bit patterns
        writer.write_bits(0b1101, 4); // 4 bits
        writer.write_bits(0b0010_1111, 8); // 8 bits
        writer.write_bits(0b1010, 4); // 4 bits = 16 total, flushes
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(4).unwrap(), 0b1101);
        assert_eq!(reader.read_bits(8).unwrap(), 0b0010_1111);
        assert_eq!(reader.read_bits(4).unwrap(), 0b1010);
    }

    #[test]
    fn bitwriter_crosses_word_boundary() {
        let mut writer = BitWriter::new();
        // Write 12 bits, then 12 bits (spans two 16-bit words)
        writer.write_bits(0x341, 12);
        writer.write_bits(0x278, 12);
        let data = writer.finish();

        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(12).unwrap(), 0x341);
        assert_eq!(reader.read_bits(12).unwrap(), 0x278);
    }

    #[test]
    fn bitwriter_flush_pads_with_zeros() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xFF, 8); // 8 bits — not a full word
        let data = writer.finish();

        // Should have flushed: 0xFF << 8 = 0xFF00 as LE word
        assert_eq!(data.len(), 2);
        let word = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(word, 0xFF00);
    }

    #[test]
    fn bitwriter_raw_writes_after_flush() {
        let mut writer = BitWriter::new();
        writer.write_bits(0xABCD, 16); // flush a full word
        writer.flush_bits();
        writer.write_u16_le(0x1234);
        writer.write_u32_le(0xDEAD_BEEF);
        writer.write_raw_byte(0x42);
        let data = writer.finish();

        // First 2 bytes: bitstream word
        let w0 = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(w0, 0xABCD);
        // Next 2 bytes: raw u16
        let w1 = u16::from_le_bytes([data[2], data[3]]);
        assert_eq!(w1, 0x1234);
        // Next 4 bytes: raw u32
        let w2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        assert_eq!(w2, 0xDEAD_BEEF);
        // Next byte: raw byte
        assert_eq!(data[8], 0x42);
    }

    #[test]
    fn bitwriter_with_capacity() {
        let writer = BitWriter::with_capacity(1024);
        assert_eq!(writer.position(), 0);
        let data = writer.finish();
        assert!(data.is_empty());
    }

    #[test]
    fn bitwriter_position_tracks_flushed_bytes() {
        let mut writer = BitWriter::new();
        assert_eq!(writer.position(), 0);
        writer.write_bits(0xFFFF, 16); // should flush one word
        assert_eq!(writer.position(), 2);
        writer.write_bits(0xFFFF, 16); // should flush another
        assert_eq!(writer.position(), 4);
    }

    #[test]
    fn bitwriter_align_to_u16_pads_odd_byte() {
        let mut writer = BitWriter::new();
        writer.flush_bits();
        writer.write_raw_byte(0x42);
        assert_eq!(writer.position(), 1); // odd
        writer.align_to_u16();
        assert_eq!(writer.position() % 2, 0);
    }
}
