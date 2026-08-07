//! Error and result types for `fs-apfs`.

use fsmnt_parser_core::error::{self as fse, ParserError};
use thiserror::Error;

use crate::io;

/// Central result type of `fs-apfs`.
pub type Result<T, E = ApfsError> = core::result::Result<T, E>;

/// Central error type of `fs-apfs`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApfsError {
    /// A container or volume superblock had an unexpected magic value.
    #[error("Invalid {structure} magic: expected {expected:#010x}, found {actual:#010x}")]
    InvalidMagic {
        /// The structure being parsed (e.g. `nx_superblock_t`).
        structure: &'static str,
        /// The magic value the structure should have carried.
        expected: u32,
        /// The magic value found on disk.
        actual: u32,
    },

    /// An object's stored Fletcher-64 checksum did not match its contents.
    #[error("Checksum mismatch for object at block {block}")]
    ChecksumMismatch {
        /// The physical block address of the object.
        block: u64,
    },

    /// The image uses an APFS feature this parser does not implement.
    #[error("Unsupported APFS feature: {0}")]
    Unsupported(&'static str),

    /// A buffer was too short to contain a fixed-size on-disk structure.
    #[error("Truncated {structure}: need {expected} bytes, got {actual}")]
    Truncated {
        /// The structure being parsed (e.g. `obj_phys_t`).
        structure: &'static str,
        /// The number of bytes the structure requires.
        expected: usize,
        /// The number of bytes actually available.
        actual: usize,
    },

    /// An on-disk structure was internally inconsistent.
    #[error("Malformed {structure}: {reason}")]
    Malformed {
        /// The structure being parsed (e.g. `btree_node_phys_t`).
        structure: &'static str,
        /// What was wrong with it.
        reason: &'static str,
    },

    /// A lookup did not find the requested item.
    #[error("{what} not found")]
    NotFound {
        /// What was being looked up (e.g. `object id`).
        what: &'static str,
    },

    /// An I/O error surfaced from the underlying reader.
    #[error("I/O error: {0:?}")]
    Io(io::Error),
}

impl From<io::Error> for ApfsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

// In no_std mode, io::Error = IoError, so From<io::Error> already covers this.
// In std mode, the explicit conversion from fsmnt-parser-core's IoError is still needed.
#[cfg(feature = "std")]
impl From<fse::IoError> for ApfsError {
    fn from(error: fse::IoError) -> Self {
        Self::Io(error.into())
    }
}

impl ParserError for ApfsError {
    fn io_kind(&self) -> Option<fse::ErrorKind> {
        let Self::Io(error) = self else {
            return None;
        };
        Some(fse::ErrorKind::from(error.kind()))
    }

    fn byte_offset(&self) -> Option<u64> {
        None
    }
}

impl From<ApfsError> for io::Error {
    fn from(error: ApfsError) -> Self {
        match error {
            ApfsError::Io(error) => error,
            #[cfg(feature = "std")]
            other => std::io::Error::other(other),
            #[cfg(not(feature = "std"))]
            _ => io::ErrorKind::Other.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_io_error_wraps_io_variant() {
        let io_err: io::Error = io::ErrorKind::InvalidInput.into();
        let apfs_err: ApfsError = io_err.into();
        match apfs_err {
            ApfsError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            }
            _ => panic!("expected ApfsError::Io"),
        }
    }

    #[test]
    fn into_io_error_unwraps_io_variant() {
        let original: io::Error = io::ErrorKind::InvalidData.into();
        let converted: io::Error = ApfsError::Io(original).into();
        assert_eq!(converted.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn into_io_error_wraps_non_io_variant() {
        let converted: io::Error = ApfsError::Unsupported("fusion drives").into();
        assert_eq!(converted.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn io_kind_is_none_for_non_io_variant() {
        let err = ApfsError::Unsupported("snapshots");
        assert_eq!(ParserError::io_kind(&err), None);
    }

    #[test]
    fn io_kind_reports_underlying_kind() {
        let err = ApfsError::Io(io::ErrorKind::UnexpectedEof.into());
        assert_eq!(
            ParserError::io_kind(&err),
            Some(fse::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn byte_offset_is_always_none_for_apfs_errors() {
        // ApfsError variants do not carry byte positions today; the
        // `byte_offset` trait method must report None for every variant.
        // A mutant that hard-codes `Some(0)` / `Some(1)` is caught here.
        assert_eq!(ParserError::byte_offset(&ApfsError::Unsupported("x")), None);
        assert_eq!(
            ParserError::byte_offset(&ApfsError::Io(io::ErrorKind::Other.into())),
            None
        );
    }
}
