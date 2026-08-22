//! LZNT1 compression.
//!
//! Splits input into 4 KB chunks, compresses each independently using
//! a chunk-local hash chain, and encodes with LZNT1's position-dependent
//! variable-width match format.

use crate::{Error, Result};

use super::{CHUNK_SIGNATURE, CHUNK_SIZE, bit_widths};

/// Worst-case compressed size for LZNT1.
///
/// Each chunk gets a 2-byte header, plus a 2-byte zero terminator.
/// Uncompressed chunks are at most `input_len` bytes total.
#[must_use]
pub fn compress_bound(input_len: usize) -> usize {
    let num_chunks = input_len.div_ceil(CHUNK_SIZE).max(1);
    // 2-byte header per chunk + chunk data + 2-byte terminator
    input_len + num_chunks * 2 + 2
}

/// Compress `input` using LZNT1.
///
/// Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns an error when `output` is too small for the encoded stream.
pub fn compress(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut in_pos = 0;
    let mut out_pos = 0;
    let mut compressed = [0u8; CHUNK_SIZE];

    while in_pos < input.len() {
        let chunk_end = (in_pos + CHUNK_SIZE).min(input.len());
        let chunk_data = &input[in_pos..chunk_end];

        // Try to compress the chunk.
        // Worst case for compressed data: same size as uncompressed.
        match compress_chunk(chunk_data, &mut compressed[..chunk_data.len()]) {
            Some(compressed_len) if compressed_len < chunk_data.len() => {
                write_chunk_header(output, &mut out_pos, compressed_len, true)?;
                write_bytes(output, &mut out_pos, &compressed[..compressed_len])?;
            }
            _ => {
                // Store uncompressed.
                write_chunk_header(output, &mut out_pos, chunk_data.len(), false)?;
                write_bytes(output, &mut out_pos, chunk_data)?;
            }
        }

        in_pos = chunk_end;
    }

    // Zero-header terminator.
    if out_pos + 2 > output.len() {
        return Err(Error::OutputTooSmall {
            expected: out_pos + 2,
            actual: output.len(),
        });
    }
    output[out_pos] = 0;
    output[out_pos + 1] = 0;
    out_pos += 2;

    Ok(out_pos)
}

/// Write a 2-byte chunk header.
fn write_chunk_header(
    output: &mut [u8],
    out_pos: &mut usize,
    data_size: usize,
    is_compressed: bool,
) -> Result<()> {
    if *out_pos + 2 > output.len() {
        return Err(Error::OutputTooSmall {
            expected: *out_pos + 2,
            actual: output.len(),
        });
    }
    let size_field =
        (u16::try_from(data_size).expect("an LZNT1 chunk contains at most 4096 bytes") - 1)
            & 0x0FFF;
    let compressed_flag = if is_compressed { 0x8000u16 } else { 0 };
    let header = size_field | (CHUNK_SIGNATURE << 12) | compressed_flag;
    let bytes = header.to_le_bytes();
    output[*out_pos] = bytes[0];
    output[*out_pos + 1] = bytes[1];
    *out_pos += 2;
    Ok(())
}

/// Write raw bytes to output.
fn write_bytes(output: &mut [u8], out_pos: &mut usize, data: &[u8]) -> Result<()> {
    if *out_pos + data.len() > output.len() {
        return Err(Error::OutputTooSmall {
            expected: *out_pos + data.len(),
            actual: output.len(),
        });
    }
    output[*out_pos..*out_pos + data.len()].copy_from_slice(data);
    *out_pos += data.len();
    Ok(())
}

/// Hash table size for chunk-local matching.
const HASH_SIZE: usize = 4096;

/// 3-byte hash for chunk-local matching.
fn hash3(data: &[u8], pos: usize) -> usize {
    let b0 = u32::from(data[pos]);
    let b1 = u32::from(data[pos + 1]);
    let b2 = u32::from(data[pos + 2]);
    let h = (b0 | (b1 << 8) | (b2 << 16)).wrapping_mul(0x9E37_79B1);
    (h >> 20) as usize & (HASH_SIZE - 1)
}

/// Compress a single chunk. Returns `Some(compressed_len)` on success,
/// `None` if the chunk can't be compressed smaller.
fn compress_chunk(chunk: &[u8], output: &mut [u8]) -> Option<usize> {
    let mut head = [0u16; HASH_SIZE];
    let mut out_pos = 0;
    let mut in_pos = 0;

    while in_pos < chunk.len() {
        // Reserve space for flag byte.
        if out_pos >= output.len() {
            return None;
        }
        let flag_pos = out_pos;
        output[flag_pos] = 0;
        out_pos += 1;

        let mut flags: u8 = 0;

        for bit in 0..8u8 {
            if in_pos >= chunk.len() {
                break;
            }

            // Try to find a match.
            let best_match = find_chunk_match(chunk, in_pos, &head);

            if let Some((displacement, length)) = best_match {
                flags |= 1 << bit;

                let (length_bits, _disp_bits) = bit_widths(in_pos);
                let length_mask = (1u16 << length_bits) - 1;
                let encoded_disp = u16::try_from(displacement - 1)
                    .expect("an LZNT1 displacement is limited to one 4096-byte chunk");
                let encoded_len = u16::try_from(length - 3)
                    .expect("the LZNT1 match finder caps encoded lengths at 4095");

                // Verify encoding fits.
                if encoded_len > length_mask {
                    // Can't encode this length, emit literal instead.
                    flags &= !(1 << bit);
                    if out_pos >= output.len() {
                        return None;
                    }
                    update_hash(chunk, in_pos, &mut head);
                    output[out_pos] = chunk[in_pos];
                    out_pos += 1;
                    in_pos += 1;
                    continue;
                }

                let word = (encoded_disp << length_bits) | encoded_len;

                if out_pos + 2 > output.len() {
                    return None;
                }
                let bytes = word.to_le_bytes();
                output[out_pos] = bytes[0];
                output[out_pos + 1] = bytes[1];
                out_pos += 2;

                // Update hash for all positions in the match.
                for i in 0..length {
                    update_hash(chunk, in_pos + i, &mut head);
                }
                in_pos += length;
            } else {
                if out_pos >= output.len() {
                    return None;
                }
                update_hash(chunk, in_pos, &mut head);
                output[out_pos] = chunk[in_pos];
                out_pos += 1;
                in_pos += 1;
            }
        }

        output[flag_pos] = flags;
    }

    Some(out_pos)
}

/// Update the hash table for position `pos`.
fn update_hash(chunk: &[u8], pos: usize, head: &mut [u16; HASH_SIZE]) {
    if pos + 3 <= chunk.len() {
        let h = hash3(chunk, pos);
        head[h] = u16::try_from(pos).expect("an LZNT1 hash position is below 4096");
    }
}

/// Find the best match at `pos` within the chunk.
/// Returns `Some((displacement, length))` or `None`.
fn find_chunk_match(chunk: &[u8], pos: usize, head: &[u16; HASH_SIZE]) -> Option<(usize, usize)> {
    if pos + 3 > chunk.len() || pos == 0 {
        return None;
    }

    let h = hash3(chunk, pos);
    let candidate = head[h] as usize;

    // Candidate must be before current position.
    if candidate >= pos {
        return None;
    }

    let displacement = pos - candidate;
    let (length_bits, _) = bit_widths(pos);
    let max_disp = 1usize << (16 - length_bits);
    if displacement > max_disp {
        return None;
    }

    // Count match length.
    let max_len_from_bits = ((1u32 << length_bits) - 1 + 3) as usize;
    let max_len = max_len_from_bits.min(chunk.len() - pos);
    let mut length = 0;
    while length < max_len && chunk[candidate + length] == chunk[pos + length] {
        length += 1;
    }

    if length >= 3 {
        Some((displacement, length))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::lznt1::decompress;

    #[test]
    fn compress_empty() {
        let mut output = [0u8; 64];
        let n = compress(&[], &mut output).expect("compress empty");
        // Just a zero terminator.
        assert_eq!(n, 2);
        assert_eq!(&output[..2], &[0, 0]);
    }

    #[test]
    fn compress_roundtrip_short() {
        let input = b"Hello, LZNT1 compression!";
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(&decompressed[..d_len], &input[..]);
    }

    #[test]
    fn compress_roundtrip_all_zeros() {
        let input = vec![0u8; 4096];
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");
        // Should achieve significant compression.
        assert!(c_len < input.len() / 2, "all-zeros should compress well");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_multi_chunk() {
        // Larger than one chunk (4096).
        let mut input = vec![0u8; 8200];
        for (i, byte) in input.iter_mut().enumerate() {
            *byte = u8::try_from(i % 256).expect("the modulus limits values to one byte");
        }
        // Add some repetition.
        let patch: Vec<u8> = input[100..200].to_vec();
        input[4100..4200].copy_from_slice(&patch);

        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compress_roundtrip_incompressible() {
        // Random-looking data that won't compress.
        let input: Vec<u8> = (0..200u32)
            .map(|i| (i.wrapping_mul(137) ^ 0xAB).to_le_bytes()[0])
            .collect();
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
        let input = b"Hello, world!";
        let mut output = [0u8; 2]; // Too small for header + data + terminator.
        let result = compress(input, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn compress_chunk_header_format() {
        let input = b"Test";
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(input, &mut compressed).expect("compress");

        // First two bytes are the chunk header.
        let header = u16::from_le_bytes([compressed[0], compressed[1]]);
        let sig = (header >> 12) & 0b111;
        assert_eq!(sig, CHUNK_SIGNATURE);

        // Last two bytes should be zero terminator.
        assert_eq!(
            &compressed[c_len - 2..c_len],
            &[0, 0],
            "expected zero terminator"
        );
    }

    #[test]
    fn compress_roundtrip_exact_chunk() {
        let input = vec![b'A'; CHUNK_SIZE];
        let bound = compress_bound(input.len());
        let mut compressed = vec![0u8; bound];
        let c_len = compress(&input, &mut compressed).expect("compress");

        let mut decompressed = vec![0u8; input.len()];
        let d_len = decompress(&compressed[..c_len], &mut decompressed).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(decompressed, input);
    }
}
