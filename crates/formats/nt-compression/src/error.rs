//! Error types for nt-compression.

use alloc::string::String;

use thiserror::Error;

/// Central result type for nt-compression.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Compression/decompression error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The compressed input ended before a required field or payload.
    #[error(
        "input truncated at offset {offset:#x}: \
         expected at least {expected} bytes, got {actual}"
    )]
    InputTruncated {
        /// Byte offset where the truncated read began.
        offset: usize,
        /// Minimum number of bytes required at that location.
        expected: usize,
        /// Number of bytes actually available.
        actual: usize,
    },

    /// The caller-provided output buffer cannot hold the result.
    #[error(
        "output buffer too small: need {expected} bytes, \
         have {actual}"
    )]
    OutputTooSmall {
        /// Required output capacity in bytes.
        expected: usize,
        /// Available output capacity in bytes.
        actual: usize,
    },

    /// The stream contains an invalid field or encoding.
    #[error("invalid data at offset {offset:#x}: {reason}")]
    InvalidData {
        /// Byte offset associated with the invalid data.
        offset: usize,
        /// Human-readable explanation of the violated invariant.
        reason: String,
    },

    /// Canonical code lengths cannot form a valid Huffman table.
    #[error("invalid Huffman table: {reason}")]
    InvalidHuffmanTable {
        /// Static explanation of the table defect.
        reason: &'static str,
    },
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
