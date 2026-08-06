//! XPRESS Plain LZ77 decompression (MS-XCA Section 2.3/2.4).
//!
//! Every 32 items (literal or match) are preceded by a 4-byte LE flag
//! DWORD. Each bit: 0 = literal byte, 1 = match reference. MSB first.
//!
//! Match encoding: 16-bit LE word where the lower 3 bits encode length
//! and the upper 13 bits encode offset-1 (max offset = 8192).
//!
//! Length extension uses a nibble-sharing mechanism where consecutive
//! extended matches alternate between low and high nibbles of a shared
//! byte from the input stream.
#![allow(unsafe_code)]

use alloc::format;

use crate::{Error, LenientResult, Result};

/// Number of items (literal or match) governed by each flag DWORD.
const FLAG_GROUP_SIZE: u32 = 32;

/// Exact worst case input bytes per 32-item flag group:
/// 4 (flags) + 32 * 5.5 (match word + nibble + byte ext + u16 ext)
/// = 180 bytes. Rounded up to 196 for headroom.
const INPUT_GUARD: usize = 196;

/// Controls fast-path entry. NOT a bound on match length -- each match
/// is individually bounds-checked before `copy_match_unchecked`.
const OUTPUT_GUARD: usize = 256;

/// Decompress XPRESS Plain LZ77 data in strict mode.
///
/// Returns the number of bytes written to `output`, or an error if the
/// input is malformed. The caller must pre-allocate `output` to the
/// expected decompressed size.
///
/// # Errors
///
/// Returns an error when the stream is malformed or a match refers outside
/// the decoded output.
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut state = DecompressState::new(input, output.len());

    // Fast path: INPUT_GUARD guarantees flag DWORD + literal reads
    // are in-bounds. Match reads remain checked (read_match returns
    // Result). Each copy_match_unchecked is individually bounds-checked.
    while state.out_pos + OUTPUT_GUARD < state.out_len
        && state.in_pos + INPUT_GUARD <= state.input.len()
    {
        // SAFETY: INPUT_GUARD ensures in_pos + 4 <= input.len().
        let flags = unsafe { crate::raw::read_u32_le(state.input, state.in_pos) };
        state.in_pos += 4;

        for bit in 0..FLAG_GROUP_SIZE {
            if state.out_pos >= state.out_len {
                return Ok(state.out_pos);
            }
            if (flags >> (31 - bit)) & 1 == 0 {
                output[state.out_pos] = state.input[state.in_pos];
                state.in_pos += 1;
                state.out_pos += 1;
            } else {
                if state.in_pos >= state.input.len() {
                    return Ok(state.out_pos);
                }
                let (offset, length) = state.read_match()?;
                // Per-match bounds check -- required because match
                // length (up to 65538) can exceed OUTPUT_GUARD.
                if state.out_pos + length > state.out_len {
                    return Err(Error::OutputTooSmall {
                        expected: state.out_pos + length,
                        actual: state.out_len,
                    });
                }
                // SAFETY: offset <= out_pos (checked in read_match),
                // out_pos + length <= out_len (checked above).
                unsafe {
                    crate::simd::copy_match_fast(output, state.out_pos, offset, length);
                }
                state.out_pos += length;
            }
        }
    }

    // Slow path: full bounds checking near buffer boundaries.
    while state.out_pos < state.out_len {
        let flags = state.read_flag_dword()?;
        for bit in 0..FLAG_GROUP_SIZE {
            if state.out_pos >= state.out_len {
                return Ok(state.out_pos);
            }
            if (flags >> (31 - bit)) & 1 == 0 {
                let byte = state.read_literal()?;
                output[state.out_pos] = byte;
                state.out_pos += 1;
            } else {
                // MS-XCA Section 2.4: end-of-stream when a match
                // bit is set but all input has been consumed.
                if state.in_pos >= state.input.len() {
                    return Ok(state.out_pos);
                }
                let (offset, length) = state.read_match()?;
                copy_match(output, state.out_pos, offset, length)?;
                state.out_pos += length;
            }
        }
    }
    Ok(state.out_pos)
}

/// Decompress XPRESS Plain LZ77 data in lenient (forensic) mode.
///
/// Zero-fills the output buffer upfront, then decompresses as far as
/// possible. On errors the damaged region stays zeroed and
/// `had_errors` is set. Returns partial output even when the stream
/// is corrupt or truncated.
pub fn decompress_lenient(input: &[u8], output: &mut [u8]) -> LenientResult {
    output.fill(0);

    let mut state = DecompressState::new(input, output.len());
    let mut had_errors = false;

    while state.out_pos < state.out_len {
        let Ok(flags) = state.read_flag_dword() else {
            had_errors = true;
            break;
        };
        for bit in 0..FLAG_GROUP_SIZE {
            if state.out_pos >= state.out_len {
                return LenientResult {
                    bytes_written: state.out_pos,
                    had_errors,
                };
            }
            if (flags >> (31 - bit)) & 1 == 0 {
                if let Ok(byte) = state.read_literal() {
                    output[state.out_pos] = byte;
                    state.out_pos += 1;
                } else {
                    had_errors = true;
                    return LenientResult {
                        bytes_written: state.out_pos,
                        had_errors,
                    };
                }
            } else {
                // End-of-stream: match bit set but input exhausted.
                if state.in_pos >= state.input.len() {
                    return LenientResult {
                        bytes_written: state.out_pos,
                        had_errors,
                    };
                }
                if let Ok((offset, length)) = state.read_match() {
                    if copy_match(output, state.out_pos, offset, length).is_err() {
                        had_errors = true;
                        return LenientResult {
                            bytes_written: state.out_pos,
                            had_errors,
                        };
                    }
                    state.out_pos += length;
                } else {
                    had_errors = true;
                    return LenientResult {
                        bytes_written: state.out_pos,
                        had_errors,
                    };
                }
            }
        }
    }

    LenientResult {
        bytes_written: state.out_pos,
        had_errors,
    }
}

/// Tracks input cursor, output position, and nibble-sharing state.
struct DecompressState<'a> {
    input: &'a [u8],
    in_pos: usize,
    out_pos: usize,
    out_len: usize,
    /// Position of the shared nibble byte. `None` means the next
    /// extended match must read a new byte and take the low nibble.
    nibble_pos: Option<usize>,
}

impl<'a> DecompressState<'a> {
    fn new(input: &'a [u8], out_len: usize) -> Self {
        Self {
            input,
            in_pos: 0,
            out_pos: 0,
            out_len,
            nibble_pos: None,
        }
    }

    /// Read the 4-byte LE flag DWORD at the current input position.
    fn read_flag_dword(&mut self) -> Result<u32> {
        if self.in_pos + 4 > self.input.len() {
            return Err(Error::InputTruncated {
                offset: self.in_pos,
                expected: 4,
                actual: self.input.len().saturating_sub(self.in_pos),
            });
        }
        let bytes = [
            self.input[self.in_pos],
            self.input[self.in_pos + 1],
            self.input[self.in_pos + 2],
            self.input[self.in_pos + 3],
        ];
        self.in_pos += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    /// Read a single literal byte from the input stream.
    fn read_literal(&mut self) -> Result<u8> {
        if self.in_pos >= self.input.len() {
            return Err(Error::InputTruncated {
                offset: self.in_pos,
                expected: 1,
                actual: 0,
            });
        }
        let byte = self.input[self.in_pos];
        self.in_pos += 1;
        Ok(byte)
    }

    /// Read a 16-bit match word and decode offset + length,
    /// including any nibble/byte/u16 extensions.
    fn read_match(&mut self) -> Result<(usize, usize)> {
        let word = self.read_u16()?;
        let offset = ((word >> 3) as usize) + 1;
        let length_field = (word & 0x7) as usize;

        let length = if length_field < 7 {
            length_field + 3
        } else {
            let nibble = self.read_nibble_extension()? as usize;
            if nibble < 15 {
                length_field + 3 + nibble
            } else {
                let byte_ext = self.read_byte_extension()? as usize;
                if byte_ext < 255 {
                    length_field + 3 + nibble + byte_ext
                } else {
                    // u16 stores match_length - MIN_MATCH_LEN (3).
                    self.read_u16_extension()? as usize + 3
                }
            }
        };

        if offset > self.out_pos {
            return Err(Error::InvalidData {
                offset: self.in_pos - 2,
                reason: format!(
                    "XPRESS match offset {offset} exceeds \
                     output position {}",
                    self.out_pos
                ),
            });
        }

        Ok((offset, length))
    }

    fn read_u16(&mut self) -> Result<u16> {
        if self.in_pos + 2 > self.input.len() {
            return Err(Error::InputTruncated {
                offset: self.in_pos,
                expected: 2,
                actual: self.input.len().saturating_sub(self.in_pos),
            });
        }
        let val = u16::from_le_bytes([self.input[self.in_pos], self.input[self.in_pos + 1]]);
        self.in_pos += 2;
        Ok(val)
    }

    /// Read a 4-bit nibble extension using the shared-byte mechanism.
    fn read_nibble_extension(&mut self) -> Result<u8> {
        if let Some(pos) = self.nibble_pos.take() {
            Ok(self.input[pos] >> 4)
        } else {
            if self.in_pos >= self.input.len() {
                return Err(Error::InputTruncated {
                    offset: self.in_pos,
                    expected: 1,
                    actual: 0,
                });
            }
            let nibble = self.input[self.in_pos] & 0x0F;
            self.nibble_pos = Some(self.in_pos);
            self.in_pos += 1;
            Ok(nibble)
        }
    }

    fn read_byte_extension(&mut self) -> Result<u8> {
        if self.in_pos >= self.input.len() {
            return Err(Error::InputTruncated {
                offset: self.in_pos,
                expected: 1,
                actual: 0,
            });
        }
        let val = self.input[self.in_pos];
        self.in_pos += 1;
        Ok(val)
    }

    fn read_u16_extension(&mut self) -> Result<u16> {
        self.read_u16()
    }
}

/// Copy `length` bytes from `output[out_pos - offset..]` to
/// `output[out_pos..]`, using chunked copies where possible.
#[inline]
fn copy_match(output: &mut [u8], out_pos: usize, offset: usize, length: usize) -> Result<()> {
    if out_pos + length > output.len() {
        return Err(Error::OutputTooSmall {
            expected: out_pos + length,
            actual: output.len(),
        });
    }
    let src_start = out_pos - offset;
    if offset >= length {
        // Non-overlapping: single copy_within.
        output.copy_within(src_start..src_start + length, out_pos);
    } else if offset == 1 {
        // RLE fill: doubling copy_within.
        output[out_pos] = output[src_start];
        let mut filled = 1;
        while filled < length {
            let chunk = filled.min(length - filled);
            output.copy_within(out_pos..out_pos + chunk, out_pos + filled);
            filled += chunk;
        }
    } else if offset >= 8 {
        // Overlapping but distance >= 8: copy 8 bytes at a time via
        // stack temporary.
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
        // Short repeating pattern (distance 2-7): byte-by-byte.
        for i in 0..length {
            output[out_pos + i] = output[src_start + i];
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // ---- helpers ------------------------------------------------

    /// Build an XPRESS stream with a single flag DWORD and the given
    /// items. Each item is either `Item::Literal(byte)` or
    /// `Item::Match { offset, length }`.
    ///
    /// This constructs the binary stream automatically, including
    /// nibble-sharing for extended matches.
    enum Item {
        Literal(u8),
        Match { offset: usize, length: usize },
    }

    /// Encode a sequence of items into an XPRESS-compressed byte
    /// stream. Handles flag DWORD generation and nibble pairing.
    fn encode_xpress(items: &[Item]) -> Vec<u8> {
        let mut result = Vec::new();

        // Process in groups of 32
        for chunk in items.chunks(32) {
            let mut flags: u32 = 0;
            let mut payload = Vec::new();
            let mut nibble_byte: Option<usize> = None;

            for (i, item) in chunk.iter().enumerate() {
                match item {
                    Item::Literal(b) => {
                        payload.push(*b);
                    }
                    Item::Match { offset, length } => {
                        flags |= 1 << (31 - i);
                        encode_match(&mut payload, &mut nibble_byte, *offset, *length);
                    }
                }
            }

            result.extend_from_slice(&flags.to_le_bytes());
            result.extend_from_slice(&payload);
        }

        result
    }

    fn encode_match(
        payload: &mut Vec<u8>,
        nibble_byte: &mut Option<usize>,
        offset: usize,
        length: usize,
    ) {
        let base_length = length - 3;

        let (field_val, remainder) = if base_length < 7 {
            (
                u16::try_from(base_length).expect("the inline XPRESS length field is three bits"),
                None,
            )
        } else {
            (7, Some(base_length - 7))
        };

        let word = (u16::try_from(offset - 1)
            .expect("synthetic XPRESS offsets are limited to 8192 bytes")
            << 3)
            | (field_val & 0x7);
        payload.extend_from_slice(&word.to_le_bytes());

        if let Some(rem) = remainder {
            let nibble_val =
                u8::try_from(rem.min(15)).expect("the XPRESS nibble extension is four bits");
            if let Some(pos) = nibble_byte.take() {
                payload[pos] |= nibble_val << 4;
            } else {
                let pos = payload.len();
                payload.push(nibble_val);
                *nibble_byte = Some(pos);
            }

            if rem >= 15 {
                let byte_rem = rem - 15;
                let byte_val = u8::try_from(byte_rem.min(255))
                    .expect("the XPRESS byte extension is eight bits");
                payload.push(byte_val);

                if byte_rem >= 255 {
                    let u16_val = u16::try_from(length - 3)
                        .expect("synthetic XPRESS matches are capped at 65538 bytes");
                    payload.extend_from_slice(&u16_val.to_le_bytes());
                }
            }
        }
    }

    // ---- strict tests -------------------------------------------

    #[test]
    fn empty_output_zero_length() {
        let mut out = [0u8; 0];
        let n = decompress(&[], &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn all_literals_32() {
        let items: Vec<Item> = (0..32)
            .map(|i| Item::Literal(u8::try_from(i).expect("the test range is below 256")))
            .collect();
        let stream = encode_xpress(&items);

        let mut out = [0u8; 32];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, 32);
        for (i, &byte) in out.iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i).expect("the output buffer is shorter than 256 bytes")
            );
        }
    }

    #[test]
    fn literal_then_match() {
        // Write 4 literals "ABCD", then match offset=4, length=4
        // to produce "ABCDABCD".
        let items = [
            Item::Literal(b'A'),
            Item::Literal(b'B'),
            Item::Literal(b'C'),
            Item::Literal(b'D'),
            Item::Match {
                offset: 4,
                length: 4,
            },
        ];
        let stream = encode_xpress(&items);

        let mut out = [0u8; 8];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out[..8], b"ABCDABCD");
    }

    #[test]
    fn nibble_carry_edge_case() {
        // Two consecutive matches both needing nibble extension
        // (length=10 → field=7, nibble=0).
        // First match: reads new byte, takes low nibble.
        // Second match: takes high nibble from same byte.
        //
        // 10 literal bytes "0123456789", then two matches:
        //   match1: offset=10, length=10 (field=7, nibble=0)
        //   match2: offset=10, length=10 (field=7, nibble=0)
        let mut items = Vec::new();
        for i in 0..10 {
            items.push(Item::Literal(b'0' + i));
        }
        items.push(Item::Match {
            offset: 10,
            length: 10,
        });
        items.push(Item::Match {
            offset: 10,
            length: 10,
        });

        let stream = encode_xpress(&items);

        let mut out = [0u8; 30];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, 30);
        assert_eq!(&out[..10], b"0123456789");
        assert_eq!(&out[10..20], b"0123456789");
        assert_eq!(&out[20..30], b"0123456789");
    }

    #[test]
    fn offset_at_max() {
        // Maximum offset = 8192 (13 bits all ones + 1).
        // We need 8192 literal bytes first, then a match with
        // offset=8192, length=3.
        let mut items = Vec::new();
        for i in 0..8192 {
            items.push(Item::Literal(
                u8::try_from(i & 0xFF).expect("the mask limits the test value to one byte"),
            ));
        }
        items.push(Item::Match {
            offset: 8192,
            length: 3,
        });

        let stream = encode_xpress(&items);

        let expected_size = 8192 + 3;
        let mut out = alloc::vec![0u8; expected_size];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, expected_size);
        // Verify the match copied the correct bytes
        for i in 0..3 {
            assert_eq!(out[8192 + i], out[i]);
        }
    }

    #[test]
    fn truncated_flag_dword_returns_error() {
        // Input is only 3 bytes — not enough for a 4-byte flag DWORD.
        let input = [0x00, 0x00, 0x00];
        let mut out = [0u8; 32];
        let result = decompress(&input, &mut out);
        assert!(result.is_err());
    }

    // ---- lenient tests ------------------------------------------

    #[test]
    fn lenient_corrupt_data_partial_recovery() {
        // Valid 4-literal prefix, then garbage.
        let items = [
            Item::Literal(b'A'),
            Item::Literal(b'B'),
            Item::Literal(b'C'),
            Item::Literal(b'D'),
        ];
        let mut stream = encode_xpress(&items);
        // Append garbage that won't parse as valid XPRESS
        stream.extend_from_slice(&[0xFF; 3]);

        // Output buffer bigger than what the valid portion produces,
        // so decompression will attempt to read more and hit garbage.
        let mut out = [0xCCu8; 64];
        let r = decompress_lenient(&stream, &mut out);
        assert!(r.had_errors);
        // The first 4 bytes should be recovered
        assert_eq!(&out[..4], b"ABCD");
    }

    #[test]
    fn lenient_valid_data_matches_strict() {
        let items = [
            Item::Literal(b'H'),
            Item::Literal(b'e'),
            Item::Literal(b'l'),
            Item::Literal(b'l'),
            Item::Literal(b'o'),
            Item::Match {
                offset: 5,
                length: 5,
            },
        ];
        let stream = encode_xpress(&items);

        let mut strict_out = [0u8; 10];
        let strict_n = decompress(&stream, &mut strict_out).unwrap();

        let mut lenient_out = [0u8; 10];
        let r = decompress_lenient(&stream, &mut lenient_out);

        assert!(!r.had_errors);
        assert_eq!(r.bytes_written, strict_n);
        assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
    }
}
