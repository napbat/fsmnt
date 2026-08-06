//! Cross-validation tests against wimlib compression APIs.
//!
//! Dynamically loads wimlib at runtime to verify that our compressor
//! output is compatible with wimlib's decompressor, and vice versa.
//! Skips gracefully when wimlib is not installed.
//!
//! wimlib exposes XPRESS (1), LZX (2), and LZMS (3). The RTL path
//! (`tests/windows_rtl.rs`) covers XPRESS on Windows; wimlib gives
//! us cross-platform coverage.
extern crate alloc;

use alloc::vec;

#[path = "../benches/wimlib_ffi.rs"]
mod wimlib_ffi;
use wimlib_ffi::*;

const LZX_WIM_BLOCK_SIZE: usize = 32_768;
const XPRESS_HUFF_BLOCK_SIZE: usize = 65_536;

// ---------------------------------------------------------------
// Test data patterns
// ---------------------------------------------------------------

fn test_patterns() -> vec::Vec<(&'static str, vec::Vec<u8>)> {
    let mut patterns = vec::Vec::new();

    // All zeros.
    patterns.push(("zeros_1k", vec![0u8; 1024]));

    // Sequential bytes.
    let sequential: vec::Vec<u8> = (0..512).map(|i| (i % 256) as u8).collect();
    patterns.push(("sequential_512", sequential));

    // Repetitive short pattern.
    let repetitive: vec::Vec<u8> = (0..2048).map(|i| b"ABCDEFGH"[i % 8]).collect();
    patterns.push(("repetitive_2k", repetitive));

    // Mixed: half structured, half pseudo-random.
    let mut mixed = vec![0u8; 4096];
    for (i, byte) in mixed.iter_mut().enumerate() {
        *byte = if i < 2048 {
            (i % 64) as u8
        } else {
            ((i * 7 + 13) % 251) as u8
        };
    }
    patterns.push(("mixed_4k", mixed));

    // High entropy (nearly incompressible).
    let high_entropy: vec::Vec<u8> = (0..4096)
        .map(|i| ((i as u64 * 2_654_435_761_u64) >> 16) as u8)
        .collect();
    patterns.push(("high_entropy_4k", high_entropy));

    // Full 32 KB chunk with repeated patches (LZX block size).
    let mut full_chunk_32k: vec::Vec<u8> = (0..32768).map(|i| (i % 251) as u8).collect();
    let patch = vec![0xAA_u8; 1000];
    full_chunk_32k[15000..16000].copy_from_slice(&patch);
    patterns.push(("full_chunk_32k", full_chunk_32k));

    // Full 64 KB chunk with repeated patches (XPRESS Huffman block size).
    let mut full_chunk_64k: vec::Vec<u8> = (0..65536).map(|i| (i % 251) as u8).collect();
    let patch64 = vec![0xBB_u8; 2000];
    full_chunk_64k[30000..32000].copy_from_slice(&patch64);
    patterns.push(("full_chunk_64k", full_chunk_64k));

    // Small input.
    patterns.push(("tiny", b"Hello, World!".to_vec()));

    patterns
}

// ---------------------------------------------------------------
// LZX WIM cross-validation
// ---------------------------------------------------------------

#[cfg(all(feature = "compress-lzx", feature = "lzx"))]
mod lzx_wim {
    use super::*;

    #[test]
    fn ours_compress_wimlib_decompress() {
        let Some(wimlib) = Wimlib::load() else {
            eprintln!("skipping: wimlib not available");
            return;
        };

        let decompressor =
            WimlibDecompressor::new(&wimlib, WimlibCompressionType::Lzx, LZX_WIM_BLOCK_SIZE)
                .expect("failed to create wimlib decompressor");

        for (name, input) in test_patterns()
            .into_iter()
            .filter(|(_, d)| d.len() <= LZX_WIM_BLOCK_SIZE)
        {
            let bound = nt_compression::lzx::compress_bound(input.len());
            let mut compressed = vec![0u8; bound];
            let c_len = nt_compression::lzx::compress(&input, &mut compressed)
                .unwrap_or_else(|e| panic!("{name}: compress failed: {e}"));

            let mut decompressed = vec![0u8; input.len()];
            decompressor
                .decompress(&compressed[..c_len], &mut decompressed)
                .unwrap_or_else(|e| panic!("{name}: wimlib decompress failed: {e}"));
            assert_eq!(decompressed, input, "{name}: wimlib decompress mismatch");
        }
    }

    #[test]
    fn wimlib_compress_ours_decompress() {
        let Some(wimlib) = Wimlib::load() else {
            eprintln!("skipping: wimlib not available");
            return;
        };

        let compressor =
            WimlibCompressor::new(&wimlib, WimlibCompressionType::Lzx, LZX_WIM_BLOCK_SIZE)
                .expect("failed to create wimlib compressor");

        for (name, input) in test_patterns()
            .into_iter()
            .filter(|(_, d)| d.len() <= LZX_WIM_BLOCK_SIZE)
        {
            let mut compressed = vec![0u8; input.len() + 4096];
            let c_len = compressor.compress(&input, &mut compressed);

            if c_len == 0 {
                // wimlib returns 0 for incompressible data.
                continue;
            }

            let mut decompressed = vec![0u8; input.len()];
            let d_len = nt_compression::lzx::decompress(&compressed[..c_len], &mut decompressed)
                .unwrap_or_else(|e| panic!("{name}: our decompress failed: {e}"));
            assert_eq!(d_len, input.len(), "{name}: length mismatch");
            assert_eq!(&decompressed[..d_len], &input[..], "{name}: data mismatch");
        }
    }
}

// ---------------------------------------------------------------
// XPRESS Huffman cross-validation
// ---------------------------------------------------------------

#[cfg(all(feature = "compress-xpress-huffman", feature = "xpress-huffman"))]
mod xpress_huffman {
    use super::*;

    /// Filter patterns to single-block size for wimlib compatibility.
    /// wimlib's XPRESS compressor works on single blocks (max 64 KB),
    /// while our compressor handles multi-block framing internally.
    /// Keep inputs ≤ block size so both sides agree on framing.
    fn single_block_patterns() -> vec::Vec<(&'static str, vec::Vec<u8>)> {
        test_patterns()
            .into_iter()
            .filter(|(_, data)| data.len() <= XPRESS_HUFF_BLOCK_SIZE)
            .collect()
    }

    #[test]
    fn ours_compress_wimlib_decompress() {
        let Some(wimlib) = Wimlib::load() else {
            eprintln!("skipping: wimlib not available");
            return;
        };

        let decompressor = WimlibDecompressor::new(
            &wimlib,
            WimlibCompressionType::Xpress,
            XPRESS_HUFF_BLOCK_SIZE,
        )
        .expect("failed to create wimlib XPRESS decompressor");

        for (name, input) in single_block_patterns() {
            let bound = nt_compression::xpress_huffman::compress_bound(input.len());
            let mut compressed = vec![0u8; bound];
            let c_len = nt_compression::xpress_huffman::compress(&input, &mut compressed)
                .unwrap_or_else(|e| panic!("{name}: compress failed: {e}"));

            let mut decompressed = vec![0u8; input.len()];
            decompressor
                .decompress(&compressed[..c_len], &mut decompressed)
                .unwrap_or_else(|e| panic!("{name}: wimlib decompress failed: {e}"));
            assert_eq!(decompressed, input, "{name}: wimlib decompress mismatch");
        }
    }

    #[test]
    fn wimlib_compress_ours_decompress() {
        let Some(wimlib) = Wimlib::load() else {
            eprintln!("skipping: wimlib not available");
            return;
        };

        let compressor = WimlibCompressor::new(
            &wimlib,
            WimlibCompressionType::Xpress,
            XPRESS_HUFF_BLOCK_SIZE,
        )
        .expect("failed to create wimlib XPRESS compressor");

        for (name, input) in single_block_patterns() {
            let mut compressed = vec![0u8; input.len() + 4096];
            let c_len = compressor.compress(&input, &mut compressed);

            if c_len == 0 {
                // wimlib returns 0 for incompressible data.
                continue;
            }

            let mut decompressed = vec![0u8; input.len()];
            let d_len =
                nt_compression::xpress_huffman::decompress(&compressed[..c_len], &mut decompressed)
                    .unwrap_or_else(|e| panic!("{name}: our decompress failed: {e}"));
            assert_eq!(d_len, input.len(), "{name}: length mismatch");
            assert_eq!(&decompressed[..d_len], &input[..], "{name}: data mismatch");
        }
    }
}
