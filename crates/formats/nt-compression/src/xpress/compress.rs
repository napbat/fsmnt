//! XPRESS Plain LZ77 compression.
//!
//! Encodes data in 32-item groups preceded by 4-byte LE flag DWORDs.
//! Uses the shared LZ77 match finder with a window of 8192 bytes.

use crate::lz77::{MatchFinder, Token};
use crate::{Error, Result};

/// Worst-case compressed size for XPRESS Plain.
pub fn compress_bound(input_len: usize) -> usize {
    // 4-byte flag per 32 items + each item is at worst a literal (1 byte)
    // + some match overhead
    input_len + (input_len / 32 + 1) * 4 + 16
}

/// Compress `input` using XPRESS Plain LZ77.
///
/// Returns the number of bytes written to `output`.
pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }

    let mut finder = MatchFinder::standard(8192, 65535, 32);
    let tokens = finder.tokenize(input);

    encode_tokens(&tokens, output)
}

/// Encode LZ77 tokens into XPRESS format.
///
/// Writes directly to `output` so that nibble sharing state carries
/// across 32-item flag DWORD groups (matching the decompressor).
fn encode_tokens(tokens: &[Token], output: &mut [u8]) -> Result<usize> {
    let mut out_pos = 0;
    // Nibble position in the output buffer; carries across groups.
    let mut nibble_pos: Option<usize> = None;

    for group in tokens.chunks(32) {
        let mut flags: u32 = 0;

        // Reserve 4 bytes for the flag DWORD; fill payload after.
        let flag_pos = out_pos;
        if out_pos + 4 > output.len() {
            return Err(Error::OutputTooSmall {
                expected: out_pos + 4,
                actual: output.len(),
            });
        }
        out_pos += 4;

        for (i, token) in group.iter().enumerate() {
            match token {
                Token::Literal(b) => {
                    if out_pos >= output.len() {
                        return Err(Error::OutputTooSmall {
                            expected: out_pos + 1,
                            actual: output.len(),
                        });
                    }
                    output[out_pos] = *b;
                    out_pos += 1;
                }
                Token::Match(m) => {
                    flags |= 1 << (31 - i);
                    out_pos = encode_match(
                        output,
                        out_pos,
                        &mut nibble_pos,
                        m.offset as usize,
                        m.length as usize,
                    )?;
                }
            }
        }

        // Mark unused slots as match (bit=1) so decompressors that
        // read all 32 items hit the "output full → break" path for
        // matches rather than trying to read non-existent literal
        // bytes from the stream.
        for i in group.len()..32 {
            flags |= 1 << (31 - i);
        }

        // Backfill the flag DWORD.
        let flag_bytes = flags.to_le_bytes();
        output[flag_pos..flag_pos + 4].copy_from_slice(&flag_bytes);
    }

    Ok(out_pos)
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
        (base_length as u16, None)
    } else {
        (7, Some(base_length - 7))
    };

    let word = (((offset - 1) as u16) << 3) | (field_val & 0x7);
    let wb = word.to_le_bytes();
    pos = emit(output, pos, wb[0])?;
    pos = emit(output, pos, wb[1])?;

    if let Some(rem) = remainder {
        // Nibble extension.
        let nibble_val = rem.min(15) as u8;
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
            let byte_val = byte_rem.min(255) as u8;
            pos = emit(output, pos, byte_val)?;

            if byte_rem >= 255 {
                // u16 extension stores match_length - MIN_MATCH_LEN (3).
                let u16_bytes = ((length - 3) as u16).to_le_bytes();
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
            *byte = (i * 7) as u8;
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
            *byte = (i & 0xFF) as u8;
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
            *byte = (i as u8 + 1) * 11;
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
            *byte = (i % 251) as u8; // prime modulus for variety
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
