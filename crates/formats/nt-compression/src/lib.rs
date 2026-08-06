//! NT compression algorithms: LZNT1, XPRESS, XPRESS Huffman, LZX, LZX CAB, and LZXD.
//!
//! Implements decompression for the algorithms used by Windows
//! NTFS native compression, Windows Overlay Filter (WOF),
//! Microsoft Cabinet (.cab) files, and Exchange Server OAB delta
//! compression.
#![no_std]
#![deny(unsafe_code)]

extern crate alloc;

pub(crate) mod bitstream;
#[cfg(any(feature = "lzx", feature = "lzxd", feature = "lzx-cab"))]
pub(crate) mod e8;
mod error;
pub(crate) mod huffman;
#[cfg(any(
    feature = "compress-xpress",
    feature = "compress-xpress-huffman",
    feature = "compress-lzx"
))]
pub(crate) mod lz77;
#[cfg(feature = "lznt1")]
/// LZNT1 compression and decompression.
pub mod lznt1;
#[cfg(feature = "lzx")]
/// WIM-flavoured LZX compression and decompression.
pub mod lzx;
#[cfg(feature = "lzx-cab")]
/// Microsoft Cabinet LZX decompression.
pub mod lzx_cab;
#[cfg(feature = "lzxd")]
/// Exchange Server LZXD delta decompression.
pub mod lzxd;
#[cfg(any(
    feature = "xpress",
    feature = "xpress-huffman",
    feature = "lzx",
    feature = "compress-xpress",
    feature = "compress-xpress-huffman",
    feature = "compress-lzx",
))]
pub(crate) mod raw;
#[cfg(any(
    feature = "xpress",
    feature = "xpress-huffman",
    feature = "lzx",
    feature = "compress-xpress",
    feature = "compress-xpress-huffman",
    feature = "compress-lzx",
))]
pub(crate) mod simd;
#[cfg(feature = "xpress")]
/// Plain XPRESS compression and decompression.
pub mod xpress;
#[cfg(feature = "xpress-huffman")]
/// Huffman-coded XPRESS compression and decompression.
pub mod xpress_huffman;

#[cfg(test)]
pub(crate) mod test_bitwriter;

/// Shared roundtrip test: compress → decompress a repeating pattern.
#[cfg(test)]
#[allow(unused)]
pub(crate) fn assert_roundtrip_match(
    compress_fn: impl Fn(&[u8], &mut [u8]) -> Result<usize>,
    decompress_fn: impl Fn(&[u8], &mut [u8]) -> Result<usize>,
    bound_fn: impl Fn(usize) -> usize,
) {
    let input = b"ABCDABCDABCDABCDABCDABCDABCDABCD";
    let bound = bound_fn(input.len());
    let mut compressed = alloc::vec![0u8; bound];
    let c_len = compress_fn(input, &mut compressed).expect("compress");
    let mut decompressed = alloc::vec![0u8; input.len()];
    let d_len = decompress_fn(&compressed[..c_len], &mut decompressed).expect("decompress");
    assert_eq!(d_len, input.len());
    assert_eq!(&decompressed[..d_len], &input[..]);
}

pub use error::{Error, LenientResult, Result};
pub use fs_common::SimdLevel;

/// Supported compression algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// LZNT1 -- LZ77 with variable-width encoding, 4 KB chunks.
    /// Used by NTFS native file compression.
    Lznt1,
    /// XPRESS Plain LZ77 -- 32-bit flag DWORDs, 13-bit offset.
    /// Used by WOF with 4K/8K/16K chunk sizes.
    Xpress,
    /// XPRESS Huffman -- LZ77 + canonical Huffman coding, 64 KB blocks.
    /// Used by SMB3 compression and WIM archives.
    XpressHuffman,
    /// LZX (WIM variant only) -- LZ77 + multiple Huffman trees + repeat
    /// offsets + E8 preprocessing. 32 KB chunks.
    /// Used by WOF. Not CAB LZX or LZXD delta.
    Lzx,
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lznt1 => write!(f, "LZNT1"),
            Self::Xpress => write!(f, "XPRESS"),
            Self::XpressHuffman => write!(f, "XPRESS Huffman"),
            Self::Lzx => write!(f, "LZX"),
        }
    }
}

/// Decompress `input` using the given algorithm.
///
/// `output` must be pre-allocated to the expected decompressed size.
/// Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns [`Error`] when the selected algorithm is disabled, the input is
/// malformed, or the output buffer is too small.
#[allow(unused_variables)]
pub fn decompress(algorithm: Algorithm, input: &[u8], output: &mut [u8]) -> Result<usize> {
    match algorithm {
        #[cfg(feature = "lznt1")]
        Algorithm::Lznt1 => lznt1::decompress(input, output),
        #[cfg(feature = "xpress")]
        Algorithm::Xpress => xpress::decompress(input, output),
        #[cfg(feature = "xpress-huffman")]
        Algorithm::XpressHuffman => xpress_huffman::decompress(input, output),
        #[cfg(feature = "lzx")]
        Algorithm::Lzx => lzx::decompress(input, output),
        #[allow(unreachable_patterns)]
        _ => Err(Error::InvalidData {
            offset: 0,
            reason: alloc::format!("algorithm {algorithm} not enabled"),
        }),
    }
}

/// Decompress `input` using the given algorithm in lenient (forensic) mode.
///
/// Decompresses as much as possible, zero-filling damaged regions.
/// Returns bytes written and whether errors were encountered.
#[allow(unused_variables)]
pub fn decompress_lenient(algorithm: Algorithm, input: &[u8], output: &mut [u8]) -> LenientResult {
    match algorithm {
        #[cfg(feature = "lznt1")]
        Algorithm::Lznt1 => lznt1::decompress_lenient(input, output),
        #[cfg(feature = "xpress")]
        Algorithm::Xpress => xpress::decompress_lenient(input, output),
        #[cfg(feature = "xpress-huffman")]
        Algorithm::XpressHuffman => xpress_huffman::decompress_lenient(input, output),
        #[cfg(feature = "lzx")]
        Algorithm::Lzx => lzx::decompress_lenient(input, output),
        #[allow(unreachable_patterns)]
        _ => {
            output.fill(0);
            LenientResult {
                bytes_written: output.len(),
                had_errors: true,
            }
        }
    }
}

/// Compress `input` using the given algorithm.
///
/// `output` must be at least `compress_bound(algorithm, input.len())`
/// bytes. Returns the number of bytes written to `output`.
///
/// # Errors
///
/// Returns [`Error`] when compression is disabled for the selected algorithm
/// or the output buffer is too small.
#[allow(unused_variables)]
pub fn compress(algorithm: Algorithm, input: &[u8], output: &mut [u8]) -> Result<usize> {
    match algorithm {
        #[cfg(feature = "compress-lznt1")]
        Algorithm::Lznt1 => lznt1::compress(input, output),
        #[cfg(feature = "compress-xpress")]
        Algorithm::Xpress => xpress::compress(input, output),
        #[cfg(feature = "compress-xpress-huffman")]
        Algorithm::XpressHuffman => xpress_huffman::compress(input, output),
        #[cfg(feature = "compress-lzx")]
        Algorithm::Lzx => lzx::compress(input, output),
        #[allow(unreachable_patterns)]
        _ => Err(Error::InvalidData {
            offset: 0,
            reason: alloc::format!("compression for algorithm {algorithm} not enabled"),
        }),
    }
}

/// Worst-case compressed size for the given algorithm and input length.
///
/// Callers should allocate output buffers of at least this size.
#[must_use]
pub fn compress_bound(algorithm: Algorithm, input_len: usize) -> usize {
    match algorithm {
        #[cfg(feature = "compress-lznt1")]
        Algorithm::Lznt1 => lznt1::compress_bound(input_len),
        #[cfg(feature = "compress-xpress")]
        Algorithm::Xpress => xpress::compress_bound(input_len),
        #[cfg(feature = "compress-xpress-huffman")]
        Algorithm::XpressHuffman => xpress_huffman::compress_bound(input_len),
        #[cfg(feature = "compress-lzx")]
        Algorithm::Lzx => lzx::compress_bound(input_len),
        #[allow(unreachable_patterns)]
        _ => input_len + input_len / 2 + 512,
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn algorithm_display() {
        assert_eq!(Algorithm::Lznt1.to_string(), "LZNT1");
        assert_eq!(Algorithm::Xpress.to_string(), "XPRESS");
        assert_eq!(Algorithm::XpressHuffman.to_string(), "XPRESS Huffman");
        assert_eq!(Algorithm::Lzx.to_string(), "LZX");
    }

    #[test]
    fn algorithm_eq() {
        assert_eq!(Algorithm::Lznt1, Algorithm::Lznt1);
        assert_ne!(Algorithm::Lznt1, Algorithm::Xpress);
    }

    #[test]
    #[cfg(feature = "lznt1")]
    fn dispatch_lznt1_empty() {
        let mut output = [0u8; 0];
        let n = decompress(Algorithm::Lznt1, &[], &mut output).expect("lznt1 empty");
        assert_eq!(n, 0);
    }

    #[test]
    #[cfg(feature = "xpress")]
    fn dispatch_xpress_empty() {
        let mut output = [0u8; 0];
        let n = decompress(Algorithm::Xpress, &[], &mut output).expect("xpress empty");
        assert_eq!(n, 0);
    }

    #[test]
    #[cfg(feature = "xpress-huffman")]
    fn dispatch_xpress_huffman_empty() {
        let mut output = [0u8; 0];
        let n =
            decompress(Algorithm::XpressHuffman, &[], &mut output).expect("xpress-huffman empty");
        assert_eq!(n, 0);
    }

    #[test]
    #[cfg(feature = "lznt1")]
    fn dispatch_lenient_lznt1_empty() {
        let mut output = [0u8; 0];
        let r = decompress_lenient(Algorithm::Lznt1, &[], &mut output);
        assert_eq!(r.bytes_written, 0);
        assert!(!r.had_errors);
    }

    // -- compress dispatch tests --

    #[test]
    #[cfg(feature = "compress-lznt1")]
    fn dispatch_compress_lznt1_roundtrip() {
        let input = b"ABCABCABCABCABC";
        let bound = compress_bound(Algorithm::Lznt1, input.len());
        let mut compressed = alloc::vec![0u8; bound];
        let c_len = compress(Algorithm::Lznt1, input, &mut compressed).expect("compress");
        let mut output = [0u8; 15];
        let d_len =
            decompress(Algorithm::Lznt1, &compressed[..c_len], &mut output).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(&output[..d_len], &input[..]);
    }

    #[test]
    #[cfg(feature = "compress-xpress")]
    fn dispatch_compress_xpress_roundtrip() {
        let input = b"ABCDEFABCDEFABCDEFABCDEF";
        let bound = compress_bound(Algorithm::Xpress, input.len());
        let mut compressed = alloc::vec![0u8; bound];
        let c_len = compress(Algorithm::Xpress, input, &mut compressed).expect("compress");
        let mut output = [0u8; 24];
        let d_len =
            decompress(Algorithm::Xpress, &compressed[..c_len], &mut output).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(&output[..d_len], &input[..]);
    }

    #[test]
    #[cfg(feature = "compress-xpress-huffman")]
    fn dispatch_compress_xpress_huffman_roundtrip() {
        let input: alloc::vec::Vec<u8> = (0..200)
            .map(|i| u8::try_from(i % 127).expect("the modulus limits values below 127"))
            .collect();
        let bound = compress_bound(Algorithm::XpressHuffman, input.len());
        let mut compressed = alloc::vec![0u8; bound];
        let c_len = compress(Algorithm::XpressHuffman, &input, &mut compressed).expect("compress");
        let mut output = alloc::vec![0u8; input.len()];
        let d_len = decompress(Algorithm::XpressHuffman, &compressed[..c_len], &mut output)
            .expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(output, input);
    }

    #[test]
    #[cfg(feature = "compress-lzx")]
    fn dispatch_compress_lzx_roundtrip() {
        let input: alloc::vec::Vec<u8> = (0..300)
            .map(|i| u8::try_from(i % 200).expect("the modulus limits values below 200"))
            .collect();
        let bound = compress_bound(Algorithm::Lzx, input.len());
        let mut compressed = alloc::vec![0u8; bound];
        let c_len = compress(Algorithm::Lzx, &input, &mut compressed).expect("compress");
        let mut output = alloc::vec![0u8; input.len()];
        let d_len =
            decompress(Algorithm::Lzx, &compressed[..c_len], &mut output).expect("decompress");
        assert_eq!(d_len, input.len());
        assert_eq!(output, input);
    }
}
