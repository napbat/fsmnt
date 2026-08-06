//! Cross-validation tests against Windows RTL compression APIs.
//!
//! These tests call `ntdll.dll` functions via FFI to verify that our
//! compressor output is compatible with Microsoft's decompressor, and
//! vice versa. Only runs on `target_os = "windows"`.
//!
//! Windows RTL exposes LZNT1 (2), XPRESS (3), and XPRESS Huffman (4).
//! LZX is not available through the RTL API.
#![cfg(target_os = "windows")]
#![allow(unused_imports, unused_macros, dead_code)]

extern crate alloc;

use alloc::vec;

#[path = "../benches/rtl_ffi.rs"]
mod rtl_ffi;
use rtl_ffi::*;

// ---------------------------------------------------------------
// Test data patterns
// ---------------------------------------------------------------

/// Test data patterns for cross-validation.
fn test_patterns() -> vec::Vec<(&'static str, vec::Vec<u8>)> {
    let mut patterns = vec::Vec::new();

    // All zeros.
    patterns.push(("zeros_1k", vec![0u8; 1024]));

    // Sequential bytes.
    let sequential: vec::Vec<u8> = (0..512)
        .map(|i| u8::try_from(i % 256).expect("the modulus limits values to one byte"))
        .collect();
    patterns.push(("sequential_512", sequential));

    // Repetitive short pattern.
    let repetitive: vec::Vec<u8> = (0..2048).map(|i| b"ABCDEFGH"[i % 8]).collect();
    patterns.push(("repetitive_2k", repetitive));

    // Mixed: some compressible, some random-ish.
    let mut mixed = vec![0u8; 4096];
    for (i, byte) in mixed.iter_mut().enumerate() {
        *byte = if i < 2048 {
            u8::try_from(i % 64).expect("the modulus limits values below 64")
        } else {
            u8::try_from((i * 7 + 13) % 251).expect("the modulus limits values below 251")
        };
    }
    patterns.push(("mixed_4k", mixed));

    // Small input.
    patterns.push(("tiny", b"Hello, World!".to_vec()));

    patterns
}

// ---------------------------------------------------------------
// Macro to generate tests for a given algorithm
// ---------------------------------------------------------------

macro_rules! rtl_cross_tests {
    ($mod_name:ident, $rtl_format:expr, $algo_mod:path) => {
        mod $mod_name {
            use super::*;
            use $algo_mod as algo;

            #[test]
            fn ours_compress_rtl_decompress() {
                let (_, mut decompress_ws) = rtl_workspace($rtl_format);

                for (name, input) in test_patterns() {
                    let bound = algo::compress_bound(input.len());
                    let mut compressed = vec![0u8; bound];
                    let c_len = algo::compress(&input, &mut compressed)
                        .unwrap_or_else(|e| panic!("{name}: compress failed: {e}"));

                    let decompressed = rtl_decompress(
                        $rtl_format,
                        &compressed[..c_len],
                        input.len(),
                        &mut decompress_ws,
                    );
                    assert_eq!(decompressed, input, "{name}: RTL decompress mismatch");
                }
            }

            #[test]
            fn rtl_compress_ours_decompress() {
                let (mut compress_ws, _) = rtl_workspace($rtl_format);

                for (name, input) in test_patterns() {
                    let compressed = rtl_compress($rtl_format, &input, &mut compress_ws);

                    if compressed.is_empty() {
                        // RTL returns empty data for some inputs (e.g.
                        // all-zeros with STATUS_BUFFER_ALL_ZEROS).
                        // Skip these — nothing to cross-validate.
                        continue;
                    }

                    let mut decompressed = vec![0u8; input.len()];
                    let d_len = algo::decompress(&compressed, &mut decompressed)
                        .unwrap_or_else(|e| panic!("{name}: our decompress failed: {e}"));
                    assert_eq!(d_len, input.len(), "{name}: length mismatch");
                    assert_eq!(&decompressed[..d_len], &input[..], "{name}: data mismatch");
                }
            }
        }
    };
}

#[cfg(feature = "compress-lznt1")]
rtl_cross_tests!(lznt1, COMPRESSION_FORMAT_LZNT1, nt_compression::lznt1);
#[cfg(feature = "compress-xpress")]
rtl_cross_tests!(xpress, COMPRESSION_FORMAT_XPRESS, nt_compression::xpress);
#[cfg(feature = "compress-xpress-huffman")]
rtl_cross_tests!(
    xpress_huffman,
    COMPRESSION_FORMAT_XPRESS_HUFF,
    nt_compression::xpress_huffman
);
