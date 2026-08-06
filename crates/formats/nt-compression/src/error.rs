//! Error types for nt-compression.

use alloc::string::String;

use thiserror::Error;

/// Central result type for nt-compression.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Compression/decompression error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "input truncated at offset {offset:#x}: \
         expected at least {expected} bytes, got {actual}"
    )]
    InputTruncated {
        offset: usize,
        expected: usize,
        actual: usize,
    },

    #[error(
        "output buffer too small: need {expected} bytes, \
         have {actual}"
    )]
    OutputTooSmall { expected: usize, actual: usize },

    #[error("invalid data at offset {offset:#x}: {reason}")]
    InvalidData { offset: usize, reason: String },

    #[error("invalid Huffman table: {reason}")]
    InvalidHuffmanTable { reason: &'static str },
}

/// Result of lenient (forensic) decompression.
#[derive(Clone, Debug)]
pub struct LenientResult {
    /// Bytes written to the output buffer
    /// (including zero-filled regions).
    pub bytes_written: usize,
    /// Whether any decompression errors or truncation occurred.
    pub had_errors: bool,
}
