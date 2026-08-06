use alloc::format;

use crate::{Error, LenientResult, Result};

use super::{CHUNK_SIGNATURE, CHUNK_SIZE, bit_widths};

/// Decompress LZNT1 data in strict mode.
///
/// Returns the number of bytes written to `output`, or an error if the
/// input is malformed. The caller must pre-allocate `output` to the
/// expected decompressed size.
pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut in_pos = 0;
    let mut out_pos = 0;

    while let Some(header) = read_chunk_header(input, in_pos)? {
        in_pos += 2;

        validate_chunk_signature(header, in_pos - 2)?;

        let chunk_data_size = (header & 0x0FFF) as usize + 1;
        let is_compressed = (header & 0x8000) != 0;

        if in_pos + chunk_data_size > input.len() {
            return Err(Error::InputTruncated {
                offset: in_pos,
                expected: chunk_data_size,
                actual: input.len() - in_pos,
            });
        }

        let chunk_data = &input[in_pos..in_pos + chunk_data_size];
        in_pos += chunk_data_size;

        if is_compressed {
            out_pos = decompress_chunk_strict(chunk_data, output, out_pos)?;
        } else {
            out_pos = copy_uncompressed_chunk(chunk_data, output, out_pos)?;
        }
    }

    Ok(out_pos)
}

/// Decompress LZNT1 data in lenient (forensic) mode.
///
/// On per-chunk errors the damaged region is zero-filled and processing
/// continues with the next chunk.  Returns partial output even when the
/// stream is truncated.
pub fn decompress_lenient(input: &[u8], output: &mut [u8]) -> LenientResult {
    output.fill(0);

    let mut in_pos = 0;
    let mut out_pos = 0;
    let mut had_errors = false;

    loop {
        if in_pos + 2 > input.len() {
            if in_pos < input.len() {
                had_errors = true;
            }
            break;
        }

        let header = u16::from_le_bytes([input[in_pos], input[in_pos + 1]]);

        if header == 0 {
            break;
        }

        in_pos += 2;

        let chunk_data_size = (header & 0x0FFF) as usize + 1;
        let is_compressed = (header & 0x8000) != 0;

        if in_pos + chunk_data_size > input.len() {
            had_errors = true;
            break;
        }

        if out_pos >= output.len() {
            break;
        }

        let chunk_data = &input[in_pos..in_pos + chunk_data_size];
        in_pos += chunk_data_size;

        if is_compressed {
            match decompress_chunk_strict(chunk_data, output, out_pos) {
                Ok(new_pos) => out_pos = new_pos,
                Err(_) => {
                    had_errors = true;
                    let fill = CHUNK_SIZE.min(output.len() - out_pos);
                    // Region is already zeroed from the initial fill.
                    out_pos += fill;
                }
            }
        } else {
            match copy_uncompressed_chunk(chunk_data, output, out_pos) {
                Ok(new_pos) => out_pos = new_pos,
                Err(_) => {
                    had_errors = true;
                    let fill = chunk_data_size.min(output.len() - out_pos);
                    out_pos += fill;
                }
            }
        }
    }

    LenientResult {
        bytes_written: out_pos,
        had_errors,
    }
}

/// Read and validate a 2-byte chunk header.
/// Returns `None` for a zero header (end of stream) or if there are
/// fewer than 2 bytes remaining.
fn read_chunk_header(input: &[u8], offset: usize) -> Result<Option<u16>> {
    if offset + 2 > input.len() {
        return Ok(None);
    }
    let header = u16::from_le_bytes([input[offset], input[offset + 1]]);
    if header == 0 {
        return Ok(None);
    }
    Ok(Some(header))
}

/// Validate the 3-bit signature in bits [14:12].
fn validate_chunk_signature(header: u16, header_offset: usize) -> Result<()> {
    let sig = (header >> 12) & 0b111;
    if sig != CHUNK_SIGNATURE {
        return Err(Error::InvalidData {
            offset: header_offset,
            reason: format!(
                "LZNT1 chunk signature {sig:#05b}, expected \
                 {CHUNK_SIGNATURE:#05b}"
            ),
        });
    }
    Ok(())
}

/// Copy an uncompressed chunk into the output buffer.
fn copy_uncompressed_chunk(chunk_data: &[u8], output: &mut [u8], out_pos: usize) -> Result<usize> {
    let len = chunk_data.len();
    if out_pos + len > output.len() {
        return Err(Error::OutputTooSmall {
            expected: out_pos + len,
            actual: output.len(),
        });
    }
    output[out_pos..out_pos + len].copy_from_slice(chunk_data);
    Ok(out_pos + len)
}

/// Decompress a single compressed chunk into `output` starting at
/// `out_pos`.  Returns the new output position.
fn decompress_chunk_strict(chunk_data: &[u8], output: &mut [u8], out_pos: usize) -> Result<usize> {
    let chunk_start = out_pos;
    let mut cp = 0; // cursor into chunk_data
    let mut wp = out_pos; // write position in output

    while cp < chunk_data.len() {
        let flags = chunk_data[cp];
        cp += 1;

        for bit in 0..8u8 {
            if cp >= chunk_data.len() {
                break;
            }

            if (flags >> bit) & 1 == 0 {
                // Literal byte.
                if wp >= output.len() {
                    return Err(Error::OutputTooSmall {
                        expected: wp + 1,
                        actual: output.len(),
                    });
                }
                output[wp] = chunk_data[cp];
                cp += 1;
                wp += 1;
            } else {
                // Compressed tuple (2 bytes LE).
                if cp + 2 > chunk_data.len() {
                    return Err(Error::InputTruncated {
                        offset: cp,
                        expected: 2,
                        actual: chunk_data.len() - cp,
                    });
                }
                let word = u16::from_le_bytes([chunk_data[cp], chunk_data[cp + 1]]);
                cp += 2;

                let pos_in_chunk = wp - chunk_start;
                let (displacement, length) = decode_match(word, pos_in_chunk)?;

                if displacement > pos_in_chunk {
                    return Err(Error::InvalidData {
                        offset: cp - 2,
                        reason: format!(
                            "LZNT1 displacement {displacement} \
                             exceeds position {pos_in_chunk}"
                        ),
                    });
                }

                if wp + length > output.len() {
                    return Err(Error::OutputTooSmall {
                        expected: wp + length,
                        actual: output.len(),
                    });
                }

                let src_start = wp - displacement;
                // Byte-by-byte copy to handle overlapping matches
                // (e.g. displacement=1 repeats a single byte).
                for i in 0..length {
                    output[wp + i] = output[src_start + i];
                }
                wp += length;
            }
        }
    }

    Ok(wp)
}

/// Decode a 2-byte match into `(displacement, length)`.
fn decode_match(word: u16, pos_in_chunk: usize) -> Result<(usize, usize)> {
    let (length_bits, _disp_bits) = bit_widths(pos_in_chunk);
    let length_mask = (1u16 << length_bits) - 1;

    let displacement = ((word >> length_bits) as usize) + 1;
    let length = (word & length_mask) as usize + 3;

    Ok((displacement, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- helpers ------------------------------------------------

    /// Build an uncompressed LZNT1 chunk (bit 15 = 0, sig = 0b011).
    fn make_uncompressed_chunk(data: &[u8]) -> alloc::vec::Vec<u8> {
        let size = data.len() as u16;
        let header = ((size - 1) & 0x0FFF) | (CHUNK_SIGNATURE << 12);
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&header.to_le_bytes());
        buf.extend_from_slice(data);
        buf
    }

    /// Build a compressed LZNT1 chunk from raw chunk body bytes.
    fn make_compressed_chunk(body: &[u8]) -> alloc::vec::Vec<u8> {
        let size = body.len() as u16;
        let header = ((size - 1) & 0x0FFF) | (CHUNK_SIGNATURE << 12) | 0x8000;
        let mut buf = alloc::vec::Vec::new();
        buf.extend_from_slice(&header.to_le_bytes());
        buf.extend_from_slice(body);
        buf
    }

    /// Append a zero terminator to a stream.
    fn terminate(stream: &mut alloc::vec::Vec<u8>) {
        stream.extend_from_slice(&[0x00, 0x00]);
    }

    // ---- strict tests -------------------------------------------

    #[test]
    fn empty_input_returns_zero() {
        let mut out = [0u8; 4096];
        let n = decompress(&[], &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn zero_header_terminates() {
        let mut out = [0u8; 4096];
        let n = decompress(&[0x00, 0x00], &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn uncompressed_chunk() {
        let data = b"Hello, NTFS!";
        let mut stream = make_uncompressed_chunk(data);
        terminate(&mut stream);

        let mut out = [0u8; 4096];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&out[..n], data);
    }

    #[test]
    fn truncated_chunk_returns_error() {
        // Header claims 100 bytes, but only 5 present.
        let header: u16 = 99 & 0x0FFF | (CHUNK_SIGNATURE << 12);
        let mut stream = alloc::vec::Vec::new();
        stream.extend_from_slice(&header.to_le_bytes());
        stream.extend_from_slice(&[0xAA; 5]);

        let mut out = [0u8; 4096];
        let result = decompress(&stream, &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn displacement_exceeds_position_returns_error() {
        // Construct a compressed chunk where the very first token
        // is a match — displacement must be > 0 at position 0,
        // which always exceeds the current position.
        //
        // Flag byte: 0x01 (bit 0 = match)
        // At position 0: length_bits=12, so word>>12 = disp-1.
        // displacement = 1, but position is 0 → error.
        let word: u16 = 0; // disp-1=0, len=0+3
        let body = [0x01, word as u8, (word >> 8) as u8];
        let mut stream = make_compressed_chunk(&body);
        terminate(&mut stream);

        let mut out = [0u8; 4096];
        let result = decompress(&stream, &mut out);
        assert!(result.is_err());
    }

    #[test]
    fn compressed_chunk_with_back_reference() {
        // Build: 4 literal bytes "ABCD", then a match that copies
        // the "ABCD" again (displacement=4, length=4).
        //
        // Position after 4 literals = 4.  At pos 4, bit_widths
        // gives shift=12, so length_bits=12, disp_bits=4.
        //   displacement = word >> 12 + 1 → need (4-1)=3 in top 4
        //   length       = word & 0xFFF + 3 → need 4-3=1 in low 12
        //
        // word = (3 << 12) | 1 = 0x3001
        //
        // Flag byte layout (2 groups possible but we only need 1):
        //   bits 0-3 = 0 (literal), bit 4 = 1 (match)
        //   → flag = 0b0001_0000 = 0x10
        //
        // Body: [flag, 'A', 'B', 'C', 'D', lo(0x3001), hi(0x3001)]
        let word: u16 = (3 << 12) | 1;
        let body = [
            0x10, // flag: bits 0-3 literal, bit 4 match
            b'A',
            b'B',
            b'C',
            b'D',
            word as u8,
            (word >> 8) as u8,
        ];
        let mut stream = make_compressed_chunk(&body);
        terminate(&mut stream);

        let mut out = [0u8; 4096];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out[..8], b"ABCDABCD");
    }

    #[test]
    fn overlapping_match_repeats_byte() {
        // 1 literal 'X', then match with displacement=1, length=7
        // → should produce "XXXXXXXX" (8 bytes).
        //
        // At pos 1, bit_widths → shift=12, disp_bits=4.
        //   displacement = word >> 12 + 1 → need 0 in top 4 bits
        //   length = word & 0xFFF + 3 → need 4 in low 12 bits
        // word = (0 << 12) | 4 = 0x0004
        let word: u16 = 0x0004;
        let body = [
            0x02, // flag: bit 0 literal, bit 1 match
            b'X',
            word as u8,
            (word >> 8) as u8,
        ];
        let mut stream = make_compressed_chunk(&body);
        terminate(&mut stream);

        let mut out = [0u8; 4096];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out[..8], b"XXXXXXXX");
    }

    #[test]
    fn bit_widths_at_boundary_positions() {
        // pos 0..=15 → shift=12, disp_bits=4
        assert_eq!(bit_widths(0), (12, 4));
        assert_eq!(bit_widths(1), (12, 4));
        assert_eq!(bit_widths(15), (12, 4));
        assert_eq!(bit_widths(16), (12, 4));

        // pos 17..=32 → shift=11, disp_bits=5
        assert_eq!(bit_widths(17), (11, 5));
        assert_eq!(bit_widths(32), (11, 5));

        // pos 33..=64 → shift=10, disp_bits=6
        assert_eq!(bit_widths(33), (10, 6));
        assert_eq!(bit_widths(64), (10, 6));
    }

    #[test]
    fn multiple_uncompressed_chunks() {
        let d1 = b"First";
        let d2 = b"Second";
        let mut stream = make_uncompressed_chunk(d1);
        stream.extend_from_slice(&make_uncompressed_chunk(d2));
        terminate(&mut stream);

        let mut out = [0u8; 4096];
        let n = decompress(&stream, &mut out).unwrap();
        assert_eq!(n, d1.len() + d2.len());
        assert_eq!(&out[..5], b"First");
        assert_eq!(&out[5..11], b"Second");
    }

    // ---- lenient tests ------------------------------------------

    #[test]
    fn lenient_corrupt_chunk_zero_fills() {
        // Compressed chunk with garbage body.
        let garbage = [0xFF; 10];
        let mut stream = make_compressed_chunk(&garbage);
        terminate(&mut stream);

        let mut out = [0xCCu8; 8192];
        let r = decompress_lenient(&stream, &mut out);
        assert!(r.had_errors);
        // The corrupt chunk's region should be zero-filled.
        assert!(out[..r.bytes_written].iter().all(|&b| b == 0));
    }

    #[test]
    fn lenient_truncated_input_partial_recovery() {
        // First chunk is valid uncompressed, second is truncated.
        let d1 = b"GoodData";
        let mut stream = make_uncompressed_chunk(d1);
        // Append a header claiming 200 bytes but only 3 present.
        let header: u16 = 199 & 0x0FFF | (CHUNK_SIGNATURE << 12);
        stream.extend_from_slice(&header.to_le_bytes());
        stream.extend_from_slice(&[0xBB; 3]);

        let mut out = [0xCCu8; 8192];
        let r = decompress_lenient(&stream, &mut out);
        assert!(r.had_errors);
        // First chunk was recovered.
        assert_eq!(&out[..d1.len()], d1);
        assert_eq!(r.bytes_written, d1.len());
    }

    #[test]
    fn lenient_valid_data_matches_strict() {
        let data = b"Hello, NTFS!";
        let mut stream = make_uncompressed_chunk(data);
        terminate(&mut stream);

        let mut strict_out = [0u8; 4096];
        let strict_n = decompress(&stream, &mut strict_out).unwrap();

        let mut lenient_out = [0u8; 4096];
        let r = decompress_lenient(&stream, &mut lenient_out);

        assert!(!r.had_errors);
        assert_eq!(r.bytes_written, strict_n);
        assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
    }

    #[test]
    fn lenient_compressed_valid_data_matches_strict() {
        // Also test with a compressed chunk to exercise both paths.
        let word: u16 = (3 << 12) | 1;
        let body = [0x10, b'A', b'B', b'C', b'D', word as u8, (word >> 8) as u8];
        let mut stream = make_compressed_chunk(&body);
        terminate(&mut stream);

        let mut strict_out = [0u8; 4096];
        let strict_n = decompress(&stream, &mut strict_out).unwrap();

        let mut lenient_out = [0u8; 4096];
        let r = decompress_lenient(&stream, &mut lenient_out);

        assert!(!r.had_errors);
        assert_eq!(r.bytes_written, strict_n);
        assert_eq!(&lenient_out[..r.bytes_written], &strict_out[..strict_n]);
    }
}
