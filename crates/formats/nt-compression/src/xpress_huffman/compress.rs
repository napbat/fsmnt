//! XPRESS Huffman compression.
//!
//! Compresses data in 64 KB blocks. Each block has a 256-byte Huffman
//! header followed by a bitstream of Huffman-encoded symbols.

use alloc::vec::Vec;

use crate::huffman::{
    HuffmanWorkspace, assign_canonical_codes_into, build_code_lengths_into, count_per_length,
};
use crate::lz77::{MatchFinder, Token};
use crate::{Error, Result};

use super::{BLOCK_SIZE, HEADER_SIZE, MAX_CODE_BITS, NUM_SYMBOLS};

/// Worst-case compressed size for XPRESS Huffman.
#[must_use]
pub fn compress_bound(input_len: usize) -> usize {
    let num_blocks = input_len.div_ceil(BLOCK_SIZE).max(1);
    // 256-byte header per block + bitstream (worst case same as input)
    input_len + num_blocks * (HEADER_SIZE + 4) + 16
}

/// Reusable XPRESS Huffman compressor.
///
/// Holds the `MatchFinder` and working buffers so they can be
/// allocated once and reused across multiple `compress()` calls.
pub struct Compressor {
    finder: MatchFinder,
    block: BlockWorkspace,
}

/// Buffers whose contents are rebuilt for each 64 KiB block.
struct BlockWorkspace {
    symbols: Vec<SymbolEntry>,
    stream: Vec<u8>,
    lengths: Vec<u8>,
    codes: Vec<(u32, u8)>,
    huffman: HuffmanWorkspace,
}

impl BlockWorkspace {
    fn new() -> Self {
        Self {
            symbols: Vec::with_capacity(65536),
            stream: Vec::with_capacity(65536),
            lengths: Vec::with_capacity(NUM_SYMBOLS),
            codes: Vec::with_capacity(NUM_SYMBOLS),
            huffman: HuffmanWorkspace::new(),
        }
    }
}

impl Compressor {
    /// Create a new compressor with pre-allocated buffers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            finder: MatchFinder::standard(65535, 65535, 32),
            block: BlockWorkspace::new(),
        }
    }

    /// Compress `input` using XPRESS Huffman.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns an error when `output` is too small for the encoded blocks.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        let mut in_pos = 0;
        let mut out_pos = 0;

        while in_pos < input.len() {
            let block_end = (in_pos + BLOCK_SIZE).min(input.len());
            let block_data = &input[in_pos..block_end];

            let written = compress_block(
                block_data,
                &mut output[out_pos..],
                &mut self.finder,
                &mut self.block,
            )?;
            out_pos += written;
            in_pos = block_end;
        }

        Ok(out_pos)
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Compress `input` using XPRESS Huffman.
///
/// Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error when `output` is too small for the encoded blocks.
pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    Compressor::new().compress(input, output)
}

/// Encode bits into the accumulator, flushing when a deficit occurs.
///
/// When a deficit occurs, the word flushed to `ptr0` combines the pending
/// accumulator bits with the leading bits of the new code. The remaining
/// code bits stay in the accumulator for the next flush.
#[inline]
fn encode_bits(
    stream: &mut Vec<u8>,
    ptr0: &mut usize,
    ptr1: &mut usize,
    accum: &mut u16,
    extra_bits: &mut i32,
    value: u32,
    count: u32,
) {
    if count == 0 {
        return;
    }
    let masked = u16::try_from(value & ((1 << count) - 1))
        .expect("XPRESS Huffman codes use at most 15 bits");
    let old_extra = *extra_bits;
    *extra_bits -= i32::try_from(count).expect("XPRESS Huffman codes use at most 15 bits");
    if *extra_bits < 0 {
        let deficit =
            u32::try_from(-*extra_bits).expect("this flush branch requires a negative bit budget");
        let old_extra = u32::try_from(old_extra).expect("the pre-flush bit budget is nonnegative");
        let word = (*accum << old_extra) | (masked >> deficit);
        let le = word.to_le_bytes();
        stream[*ptr0] = le[0];
        stream[*ptr0 + 1] = le[1];
        *ptr0 = *ptr1;
        *ptr1 = stream.len();
        stream.push(0);
        stream.push(0);
        *accum = masked;
        *extra_bits += 16;
    } else {
        *accum = (*accum << count) | masked;
    }
}

/// Tokenize one block and count the resulting Huffman symbols.
fn tokenize_block(
    block: &[u8],
    finder: &mut MatchFinder,
    symbols: &mut Vec<SymbolEntry>,
) -> [u32; NUM_SYMBOLS] {
    finder.reset();
    symbols.clear();
    let mut frequencies = [0u32; NUM_SYMBOLS];

    finder.tokenize_streaming(block, |token| match token {
        Token::Literal(byte) => {
            let symbol = u16::from(byte);
            frequencies[usize::from(symbol)] += 1;
            symbols.push(SymbolEntry {
                symbol,
                distance_extra_value: 0,
                distance_extra_count: 0,
                length_ext: LengthExt::None,
            });
        }
        Token::Match(matched) => {
            let distance = matched.offset as usize;
            let distance_u32 = matched.offset;
            let distance_log = if distance == 1 {
                0
            } else {
                32 - distance_u32.leading_zeros() - 1
            };
            let distance_extra = if distance_log == 0 {
                0
            } else {
                distance_u32 - (1 << distance_log)
            };
            let (length_header, length_ext) = encode_length(matched.length as usize);
            let symbol = 256
                + u16::try_from(distance_log).expect("XPRESS distance logarithms are at most 16")
                    * 16
                + length_header;
            frequencies[usize::from(symbol)] += 1;
            symbols.push(SymbolEntry {
                symbol,
                distance_extra_value: distance_extra,
                distance_extra_count: distance_log,
                length_ext,
            });
        }
    });

    frequencies
}

/// Compress a single 64KB block.
fn compress_block(
    block: &[u8],
    output: &mut [u8],
    finder: &mut MatchFinder,
    workspace: &mut BlockWorkspace,
) -> Result<usize> {
    let freqs = tokenize_block(block, finder, &mut workspace.symbols);

    // Step 3: Build Huffman code lengths.
    build_code_lengths_into(
        &freqs,
        u8::try_from(MAX_CODE_BITS).expect("XPRESS Huffman codes are capped at 15 bits"),
        &mut workspace.lengths,
        &mut workspace.huffman,
    );

    // Ensure at least one symbol has a non-zero length for valid table.
    if workspace.lengths.iter().all(|l| *l == 0) {
        // Edge case: no symbols (shouldn't happen with non-empty block).
        return Err(Error::InvalidData {
            offset: 0,
            reason: "XPRESS Huffman block produced no symbols".into(),
        });
    }

    // Step 4: Build the 256-byte header.
    if output.len() < HEADER_SIZE {
        return Err(Error::OutputTooSmall {
            expected: HEADER_SIZE,
            actual: output.len(),
        });
    }
    build_header(&workspace.lengths, &mut output[..HEADER_SIZE]);

    // Step 5: Encode symbols using a deficit-based 3-pointer scheme
    // that matches RTL's XpressDoHuffmanPass output format.
    //
    // The 3-pointer scheme maintains:
    //   ptr0 ("oldest"): position where the next word flush writes
    //   ptr1 ("middle"): becomes ptr0 on next flush
    //   write_cursor: where interleaved bytes and new word slots go
    //
    // Bitstream words are written to ptr0 (a past position), while
    // interleaved bytes go at write_cursor. This produces the exact
    // byte ordering the deficit-based decompressor expects.
    let counts = count_per_length(&workspace.lengths);
    assign_canonical_codes_into(&workspace.lengths, &counts, &mut workspace.codes);

    // Reuse the caller-provided stream buffer for the bitstream.
    workspace.stream.clear();
    // Reserve initial 4 bytes (2 words) for the first two fills.
    workspace.stream.extend_from_slice(&[0, 0, 0, 0]);
    let mut ptr0: usize = 0; // oldest word slot
    let mut ptr1: usize = 2; // middle word slot
    let mut accum: u16 = 0;
    let mut extra_bits: i32 = 16;

    for sym_entry in &workspace.symbols {
        let (code, len) = workspace.codes[sym_entry.symbol as usize];

        // MS-XCA order: Huffman code → length extensions → distance extra bits.
        encode_bits(
            &mut workspace.stream,
            &mut ptr0,
            &mut ptr1,
            &mut accum,
            &mut extra_bits,
            code,
            u32::from(len),
        );

        // Length extensions as interleaved bytes at write_cursor.
        match sym_entry.length_ext {
            LengthExt::None => {}
            LengthExt::Byte(val) => {
                workspace.stream.push(val);
            }
            LengthExt::ByteAndU16(byte_val, u16_val) => {
                workspace.stream.push(byte_val);
                workspace.stream.extend_from_slice(&u16_val.to_le_bytes());
            }
            LengthExt::ByteU16AndU32(byte_val, u16_val, large) => {
                workspace.stream.push(byte_val);
                workspace.stream.extend_from_slice(&u16_val.to_le_bytes());
                workspace.stream.extend_from_slice(&large.to_le_bytes());
            }
        }

        // Distance extra bits through the accumulator.
        if sym_entry.distance_extra_count > 0 {
            encode_bits(
                &mut workspace.stream,
                &mut ptr0,
                &mut ptr1,
                &mut accum,
                &mut extra_bits,
                sym_entry.distance_extra_value,
                sym_entry.distance_extra_count,
            );
        }
    }

    // Final flush: write remaining accumulated bits to ptr0, zero ptr1.
    let final_word =
        accum << u32::try_from(extra_bits).expect("the final bit budget is nonnegative");
    let le = final_word.to_le_bytes();
    workspace.stream[ptr0] = le[0];
    workspace.stream[ptr0 + 1] = le[1];
    workspace.stream[ptr1] = 0;
    workspace.stream[ptr1 + 1] = 0;

    let total = HEADER_SIZE + workspace.stream.len();
    if total > output.len() {
        return Err(Error::OutputTooSmall {
            expected: total,
            actual: output.len(),
        });
    }
    output[HEADER_SIZE..total].copy_from_slice(&workspace.stream);

    Ok(total)
}

/// Build the 256-byte header from 512 code lengths.
fn build_header(lengths: &[u8], header: &mut [u8]) {
    for i in 0..HEADER_SIZE {
        let low = lengths[2 * i] & 0x0F;
        let high = lengths[2 * i + 1] & 0x0F;
        header[i] = low | (high << 4);
    }
}

/// Length extension type for a symbol.
#[derive(Clone, Copy)]
enum LengthExt {
    None,
    Byte(u8),
    ByteAndU16(u8, u16),
    ByteU16AndU32(u8, u16, u32),
}

/// A symbol plus its associated extra bits.
struct SymbolEntry {
    symbol: u16,
    distance_extra_value: u32,
    distance_extra_count: u32,
    length_ext: LengthExt,
}

/// Encode match length into `length_header` (0-15) and optional
/// extension, matching the RTL decompressor's cascade.
///
/// The u16 and u32 extensions encode `match_length - 3`, not the
/// full match length.
fn encode_length(length: usize) -> (u16, LengthExt) {
    let base = length - 3;
    if base < 15 {
        return (
            u16::try_from(base).expect("the inline XPRESS length field is four bits"),
            LengthExt::None,
        );
    }

    // length_header = 15, need byte extension.
    let extra = base - 15;
    if extra < 255 {
        return (
            15,
            LengthExt::Byte(
                u8::try_from(extra).expect("the first XPRESS length extension is one byte"),
            ),
        );
    }

    // byte ext = 255, then u16 encoding match_length - 3.
    let encoded = length - 3;
    if encoded <= 65535 {
        return (
            15,
            LengthExt::ByteAndU16(
                255,
                u16::try_from(encoded).expect("the second XPRESS length extension is two bytes"),
            ),
        );
    }

    // u32 extension for very large lengths (> 65538).
    (
        15,
        LengthExt::ByteU16AndU32(
            255,
            0,
            u32::try_from(encoded).expect("XPRESS match lengths are represented in 32 bits"),
        ),
    )
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::xpress_huffman::decompress;

    #[test]
    fn compress_empty() {
        let mut output = [0u8; 512];
        let n = compress(&[], &mut output).expect("compress empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn compress_roundtrip_literals() {
        let input: Vec<u8> = (0..100)
            .map(|i| u8::try_from(i).expect("the test range is below 256"))
            .collect();
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");
        assert!(
            c_len >= HEADER_SIZE,
            "c_len={c_len} < HEADER_SIZE={HEADER_SIZE}"
        );

        let compressed_slice = &compressed[..c_len];
        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(compressed_slice, &mut decompressed)
            .unwrap_or_else(|e| panic!("decompress failed (c_len={c_len}): {e}"));
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_match() {
        crate::assert_roundtrip_match(compress, decompress, compress_bound);
    }

    #[test]
    fn compress_roundtrip_multi_block() {
        // Larger than one block (65536).
        let mut input = vec![0u8; 70000];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("the modulus limits values below 251");
        }
        let patch: Vec<u8> = input[1000..2000].to_vec();
        input[30000..31000].copy_from_slice(&patch);

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_full_block() {
        // Exactly one full block (65536 bytes).
        let mut input = vec![0u8; 65536];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("the modulus limits values below 251");
        }
        let patch: Vec<u8> = input[1000..2000].to_vec();
        input[30000..31000].copy_from_slice(&patch);

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
    fn compress_roundtrip_large_single_block() {
        // Just under one block — 60000 bytes with repetition.
        let mut input = vec![0u8; 60000];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("the modulus limits values below 251");
        }
        let patch: Vec<u8> = input[1000..2000].to_vec();
        input[30000..31000].copy_from_slice(&patch);

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
    fn compress_header_format() {
        let input = b"Test data for XPRESS Huffman header verification!!";
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(input, &mut compressed).expect("compress");
        assert!(c_len >= HEADER_SIZE, "output must contain header");
    }

    #[test]
    fn compress_output_too_small() {
        let input = vec![b'A'; 100];
        let mut output = [0u8; 10]; // Way too small.
        let result = compress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn compress_roundtrip_long_match() {
        // Create data with a very long match to test length extensions.
        let mut input = vec![0u8; 1000];
        for (i, byte) in input[..50].iter_mut().enumerate() {
            *byte = (i * 3 + 7).to_le_bytes()[0];
        }
        // Repeat the pattern many times.
        for chunk_start in (50..1000).step_by(50) {
            let end = (chunk_start + 50).min(1000);
            let len = end - chunk_start;
            let patch: Vec<u8> = input[..len].to_vec();
            input[chunk_start..end].copy_from_slice(&patch);
        }

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn reusable_compressor_resets_block_workspaces() {
        let first = vec![0x5a_u8; BLOCK_SIZE + 257];
        let second: Vec<u8> = (0_u8..=250).cycle().take(4_097).collect();
        let mut compressor = Compressor::new();
        let mut compressed = vec![0_u8; compress_bound(first.len())];

        compressor
            .compress(&first, &mut compressed)
            .expect("first compression");
        let second_len = compressor
            .compress(&second, &mut compressed)
            .expect("second compression");

        let mut decoded = vec![0_u8; second.len()];
        let decoded_len =
            decompress(&compressed[..second_len], &mut decoded).expect("second decompression");
        assert_eq!(decoded_len, second.len());
        assert_eq!(decoded, second);
    }
}
