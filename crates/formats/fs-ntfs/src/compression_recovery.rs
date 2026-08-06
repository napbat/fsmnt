//! Lenient LZNT1 decompression with per-chunk error recovery.
//!
//! This module wraps [`nt_compression::lznt1::decompress_lenient`] for use
//! in [`CompressionRecoveryMode::BestEffort`] mode, enabling forensic data
//! recovery from partially damaged compressed files.
//!
//! [`CompressionRecoveryMode::BestEffort`]: crate::attribute_value::CompressionRecoveryMode::BestEffort

/// Result of a lenient LZNT1 decompression attempt.
#[derive(Clone, Debug)]
pub struct LenientDecompressionResult {
    /// Bytes written to the output buffer (including zero-filled regions).
    pub bytes_written: usize,
    /// Whether any decompression errors or truncation occurred.
    pub had_errors: bool,
}

/// Decompresses LZNT1 data with per-chunk error recovery.
///
/// Delegates to [`nt_compression::lznt1::decompress_lenient`], which
/// processes chunks sequentially and zero-fills damaged regions.
pub fn decompress_lznt1_lenient(input: &[u8], output: &mut [u8]) -> LenientDecompressionResult {
    let result = nt_compression::lznt1::decompress_lenient(input, output);
    LenientDecompressionResult {
        bytes_written: result.bytes_written,
        had_errors: result.had_errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_empty_input() {
        let mut output = [0xCCu8; 4096];
        let result = decompress_lznt1_lenient(&[], &mut output);
        assert_eq!(result.bytes_written, 0);
        assert!(!result.had_errors);
        assert!(output.iter().all(|&b| b == 0));
    }

    #[test]
    fn lenient_zero_terminator() {
        let input = [0x00, 0x00];
        let mut output = [0xCCu8; 4096];
        let result = decompress_lznt1_lenient(&input, &mut output);
        assert_eq!(result.bytes_written, 0);
        assert!(!result.had_errors);
    }

    #[test]
    fn lenient_uncompressed_chunk() {
        // Uncompressed LZNT1 chunk: bit 15 = 0, sig bits [14:12] = 0b011.
        let data = b"Hello";
        let chunk_data_size = u16::try_from(data.len()).expect("test value fits u16");
        let header = ((chunk_data_size - 1) & 0x0FFF) | (0b011 << 12);
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&header.to_le_bytes());
        input.extend_from_slice(data);
        input.extend_from_slice(&[0x00, 0x00]); // terminator

        let mut output = [0u8; 4096];
        let result = decompress_lznt1_lenient(&input, &mut output);
        assert_eq!(result.bytes_written, 5);
        assert!(!result.had_errors);
        assert_eq!(&output[..5], b"Hello");
    }

    #[test]
    fn lenient_truncated_input() {
        // Header claims 100 bytes but only 5 are present.
        let header: u16 = (0x63 & 0x0FFF) | (0b011 << 12);
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&header.to_le_bytes());
        input.extend_from_slice(&[0xAA; 5]);

        let mut output = [0u8; 4096];
        let result = decompress_lznt1_lenient(&input, &mut output);
        assert!(result.had_errors);
        assert_eq!(result.bytes_written, 0);
    }

    #[test]
    fn lenient_compressed_chunk_roundtrip() {
        // Build a compressed LZNT1 chunk: 4 literal bytes "ABCD"
        // then a back-reference that copies them again.
        //
        // At position 4: length_bits=12, disp_bits=4
        //   displacement = word >> 12 + 1 => need 3 in top 4 bits
        //   length = word & 0xFFF + 3 => need 1 in low 12 bits
        // word = (3 << 12) | 1 = 0x3001
        let word: u16 = (3 << 12) | 1;
        let body = [
            0x10, // flag: bits 0-3 literal, bit 4 match
            b'A',
            b'B',
            b'C',
            b'D',
            word.to_le_bytes()[0],
            word.to_le_bytes()[1],
        ];
        let chunk_data_size = u16::try_from(body.len()).expect("test value fits u16");
        let header = ((chunk_data_size - 1) & 0x0FFF) | (0b011 << 12) | 0x8000;
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&header.to_le_bytes());
        input.extend_from_slice(&body);
        input.extend_from_slice(&[0x00, 0x00]); // terminator

        let mut output = [0u8; 4096];
        let result = decompress_lznt1_lenient(&input, &mut output);
        assert!(!result.had_errors);
        assert_eq!(result.bytes_written, 8);
        assert_eq!(&output[..8], b"ABCDABCD");
    }

    #[test]
    fn lenient_corrupt_compressed_chunk() {
        // Compressed chunk with garbage body.
        let garbage = [0xFF; 10];
        let chunk_data_size = u16::try_from(garbage.len()).expect("test value fits u16");
        let header = ((chunk_data_size - 1) & 0x0FFF) | 0x8000 | (0b011 << 12);
        let mut input = alloc::vec::Vec::new();
        input.extend_from_slice(&header.to_le_bytes());
        input.extend_from_slice(&garbage);
        input.extend_from_slice(&[0x00, 0x00]); // terminator

        let mut output = [0xCCu8; 4096];
        let result = decompress_lznt1_lenient(&input, &mut output);
        assert!(result.had_errors);
        assert!(output[..result.bytes_written].iter().all(|&b| b == 0));
    }
}
