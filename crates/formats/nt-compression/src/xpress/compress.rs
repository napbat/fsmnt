//! XPRESS Plain LZ77 compression.
//!
//! Encodes data in 32-item groups preceded by 4-byte LE flag DWORDs.
//! Uses the shared LZ77 match finder with a window of 8192 bytes.

use crate::lz77::{MatchFinder, Token};
use crate::{Error, Result};

/// Worst-case compressed size for XPRESS Plain.
#[must_use]
pub fn compress_bound(input_len: usize) -> usize {
    // 4-byte flag per 32 items + each item is at worst a literal (1 byte)
    // + some match overhead
    input_len + (input_len / 32 + 1) * 4 + 16
}

/// Compress `input` using XPRESS Plain LZ77.
///
/// This convenience function creates a fresh [`Compressor`]. Call
/// [`Compressor::compress`] when compressing multiple buffers to reuse the
/// match finder's working memory.
///
/// Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error when `output` is too small for the encoded stream.
pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    Compressor::new().compress(input, output)
}

/// Reusable XPRESS compressor.
///
/// The hash-chain tables are allocated once and reset between calls. Tokens
/// are encoded as the matcher emits them, so compression does not allocate a
/// token vector proportional to the input length.
pub struct Compressor {
    finder: MatchFinder,
}

impl Compressor {
    /// Create a compressor with pre-allocated match-finder tables.
    #[must_use]
    pub fn new() -> Self {
        Self {
            finder: MatchFinder::standard(8192, 65535, 32),
        }
    }

    /// Compress `input` into `output`, reusing this compressor's working
    /// memory.
    ///
    /// # Errors
    ///
    /// Returns an error when `output` is too small for the encoded stream.
    pub fn compress(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        self.finder.reset();
        let mut encoder = TokenEncoder::new(output);
        self.finder
            .tokenize_streaming(input, |token| encoder.push(token));
        encoder.finish()
    }
}

impl Default for Compressor {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming XPRESS token encoder.
struct TokenEncoder<'o> {
    output: &'o mut [u8],
    out_pos: usize,
    // Nibble position in the output buffer; carries across groups.
    nibble_pos: Option<usize>,
    flag_pos: usize,
    flags: u32,
    group_len: usize,
    error: Option<Error>,
}

impl<'o> TokenEncoder<'o> {
    fn new(output: &'o mut [u8]) -> Self {
        Self {
            output,
            out_pos: 0,
            nibble_pos: None,
            flag_pos: 0,
            flags: 0,
            group_len: 0,
            error: None,
        }
    }

    fn push(&mut self, token: Token) {
        if self.error.is_some() {
            return;
        }
        if let Err(error) = self.push_inner(token) {
            self.error = Some(error);
        }
    }

    fn push_inner(&mut self, token: Token) -> Result<()> {
        if self.group_len == 0 {
            // Reserve 4 bytes for the flag DWORD; fill payload after.
            self.flag_pos = self.out_pos;
            if self.out_pos + 4 > self.output.len() {
                return Err(Error::OutputTooSmall {
                    expected: self.out_pos + 4,
                    actual: self.output.len(),
                });
            }
            self.out_pos += 4;
            self.flags = 0;
        }

        match token {
            Token::Literal(b) => {
                if self.out_pos >= self.output.len() {
                    return Err(Error::OutputTooSmall {
                        expected: self.out_pos + 1,
                        actual: self.output.len(),
                    });
                }
                self.output[self.out_pos] = b;
                self.out_pos += 1;
            }
            Token::Match(m) => {
                self.flags |= 1 << (31 - self.group_len);
                self.out_pos = encode_match(
                    self.output,
                    self.out_pos,
                    &mut self.nibble_pos,
                    m.offset as usize,
                    m.length as usize,
                )?;
            }
        }

        self.group_len += 1;
        if self.group_len == 32 {
            self.finish_group();
        }
        Ok(())
    }

    fn finish_group(&mut self) {
        // Mark unused slots as match (bit=1) so decompressors that
        // read all 32 items hit the "output full → break" path for
        // matches rather than trying to read non-existent literal
        // bytes from the stream.
        for i in self.group_len..32 {
            self.flags |= 1 << (31 - i);
        }

        // Backfill the flag DWORD.
        let flag_bytes = self.flags.to_le_bytes();
        self.output[self.flag_pos..self.flag_pos + 4].copy_from_slice(&flag_bytes);
        self.group_len = 0;
    }

    fn finish(mut self) -> Result<usize> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.group_len != 0 {
            self.finish_group();
        }
        Ok(self.out_pos)
    }
}

/// Write a single byte to output, returning the updated position.
fn emit(output: &mut [u8], pos: usize, byte: u8) -> Result<usize> {
    if pos >= output.len() {
        return Err(Error::OutputTooSmall {
            expected: pos + 1,
            actual: output.len(),
        });
    }
    output[pos] = byte;
    Ok(pos + 1)
}

/// Encode a single match directly into the output buffer.
///
/// Returns the updated write position.
fn encode_match(
    output: &mut [u8],
    mut pos: usize,
    nibble_pos: &mut Option<usize>,
    offset: usize,
    length: usize,
) -> Result<usize> {
    let base_length = length - 3;

    let (field_val, remainder) = if base_length < 7 {
        (
            u16::try_from(base_length).expect("the inline XPRESS length field is three bits"),
            None,
        )
    } else {
        (7, Some(base_length - 7))
    };

    let word = (u16::try_from(offset - 1).expect("XPRESS match offsets are limited to 8192 bytes")
        << 3)
        | (field_val & 0x7);
    let wb = word.to_le_bytes();
    pos = emit(output, pos, wb[0])?;
    pos = emit(output, pos, wb[1])?;

    if let Some(rem) = remainder {
        // Nibble extension.
        let nibble_val =
            u8::try_from(rem.min(15)).expect("the XPRESS nibble extension is four bits");
        if let Some(np) = nibble_pos.take() {
            // Use high nibble of existing byte.
            output[np] |= nibble_val << 4;
        } else {
            // Write new byte with low nibble.
            *nibble_pos = Some(pos);
            pos = emit(output, pos, nibble_val)?;
        }

        if rem >= 15 {
            // Byte extension.
            let byte_rem = rem - 15;
            let byte_val =
                u8::try_from(byte_rem.min(255)).expect("the XPRESS byte extension is eight bits");
            pos = emit(output, pos, byte_val)?;

            if byte_rem >= 255 {
                // u16 extension stores match_length - MIN_MATCH_LEN (3).
                let u16_bytes = u16::try_from(length - 3)
                    .expect("XPRESS match lengths are capped at 65538 bytes")
                    .to_le_bytes();
                pos = emit(output, pos, u16_bytes[0])?;
                pos = emit(output, pos, u16_bytes[1])?;
            }
        }
    }

    Ok(pos)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::xpress::decompress;

    #[test]
    fn compress_empty() {
        let mut output = [0u8; 64];
        let n = compress(&[], &mut output).expect("compress empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn compress_roundtrip_literals() {
        // Short data with no repeats — all literals.
        let input: Vec<u8> = (0..32).collect();
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_match() {
        let input = b"ABCDABCDABCDABCD";
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(&decompressed[..d_len], &input[..]);
    }

    #[test]
    fn compress_roundtrip_long_match() {
        // Test length extension (nibble + byte + u16).
        let mut input = vec![0u8; 300];
        // Write a pattern then repeat it.
        for (i, byte) in input[..50].iter_mut().enumerate() {
            *byte = (i * 7).to_le_bytes()[0];
        }
        let patch: Vec<u8> = input[..50].to_vec();
        input[50..100].copy_from_slice(&patch);
        input[100..150].copy_from_slice(&patch);

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_max_offset() {
        // 8192 unique bytes, then a match at max offset.
        let mut input = vec![0u8; 8200];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i & 0xFF).expect("the mask limits the value to one byte");
        }
        // Make positions 8192..8195 match positions 0..3.
        input[8192] = input[0];
        input[8193] = input[1];
        input[8194] = input[2];

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_output_too_small() {
        let input = vec![b'A'; 100];
        let mut output = [0u8; 2];
        let result = compress(&input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn compress_roundtrip_nibble_carry_across_groups() {
        // Craft input where the last match in group 1 (items 0-31)
        // leaves an odd nibble, and the first match in group 2
        // (item 32+) must use the high nibble of the same byte.
        // This requires >32 tokens with extended matches spanning
        // the boundary.
        //
        // Strategy: 10-byte pattern repeated many times produces
        // matches with length=10 (base_length=7, field=7, nibble
        // extension needed). 33+ such matches will span groups.
        let mut input = vec![0u8; 500];
        for (i, byte) in input[..10].iter_mut().enumerate() {
            *byte = (u8::try_from(i).expect("the test range is shorter than 256 bytes") + 1) * 11;
        }
        for chunk in 1..50 {
            let start = chunk * 10;
            let end = (start + 10).min(input.len());
            for j in start..end {
                input[j] = input[j - 10];
            }
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
    fn compress_roundtrip_64kb() {
        let mut input = vec![0u8; 65536];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i % 251).expect("the modulus limits values below 251");
        }
        // Add some repetition.
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
}
