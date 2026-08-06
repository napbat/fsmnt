mod io;

pub use io::{ErrorKind, IoError};

#[cfg(feature = "std")]
mod std_bridge;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub use std_bridge::IntoStdIoError;

/// Common interface for filesystem error types.
///
/// Every fs crate's error enum implements this trait, enabling generic code
/// to inspect I/O category and byte-level provenance without knowing the
/// concrete error type.
pub trait FsError: From<IoError> + core::fmt::Debug {
    /// Returns the [`ErrorKind`] if this error originated from an I/O operation.
    fn io_kind(&self) -> Option<ErrorKind>;

    /// Returns the absolute byte offset (relative to the disk image) where the
    /// error occurred, if known.
    fn byte_offset(&self) -> Option<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal test error that implements FsError
    #[derive(Debug)]
    enum TestError {
        Io(IoError),
        Parse { offset: u64 },
    }

    impl From<IoError> for TestError {
        fn from(e: IoError) -> Self {
            Self::Io(e)
        }
    }

    impl FsError for TestError {
        fn io_kind(&self) -> Option<ErrorKind> {
            match self {
                Self::Io(e) => Some(e.kind()),
                Self::Parse { .. } => None,
            }
        }

        fn byte_offset(&self) -> Option<u64> {
            match self {
                Self::Io(_) => None,
                Self::Parse { offset } => Some(*offset),
            }
        }
    }

    #[test]
    fn fs_error_io_kind() {
        let err = TestError::Io(IoError::new(ErrorKind::Interrupted));
        assert_eq!(err.io_kind(), Some(ErrorKind::Interrupted));
    }

    #[test]
    fn fs_error_parse_has_no_io_kind() {
        let err = TestError::Parse { offset: 0x1000 };
        assert_eq!(err.io_kind(), None);
    }

    #[test]
    fn fs_error_byte_offset() {
        let err = TestError::Parse { offset: 0x1000 };
        assert_eq!(err.byte_offset(), Some(0x1000));
    }

    #[test]
    fn fs_error_from_io_error() {
        let io_err = IoError::new(ErrorKind::UnexpectedEof);
        let err: TestError = io_err.into();
        assert_eq!(err.io_kind(), Some(ErrorKind::UnexpectedEof));
    }
}
