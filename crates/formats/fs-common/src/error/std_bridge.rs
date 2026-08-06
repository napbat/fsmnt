use crate::error::{ErrorKind, FsError, IoError};

/// Lossy conversion from a filesystem error to [`std::io::Error`].
///
/// This is a blanket impl for all `FsError` types. The conversion maps
/// [`ErrorKind`] variants to their [`std::io::ErrorKind`] equivalents and
/// uses `Debug` output as the error message (lossy: structured context is lost).
pub trait IntoStdIoError {
    /// Converts this error into a [`std::io::Error`].
    fn into_std_io_error(self) -> std::io::Error;
}

impl From<std::io::ErrorKind> for ErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        match kind {
            std::io::ErrorKind::Interrupted => Self::Interrupted,
            std::io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            std::io::ErrorKind::InvalidData => Self::InvalidData,
            std::io::ErrorKind::InvalidInput => Self::InvalidInput,
            _ => Self::Other,
        }
    }
}

impl ErrorKind {
    /// Converts to the [`std::io::ErrorKind`] equivalent.
    #[must_use]
    pub const fn to_std(self) -> std::io::ErrorKind {
        match self {
            Self::Interrupted => std::io::ErrorKind::Interrupted,
            Self::UnexpectedEof => std::io::ErrorKind::UnexpectedEof,
            Self::InvalidData => std::io::ErrorKind::InvalidData,
            Self::InvalidInput => std::io::ErrorKind::InvalidInput,
            Self::Other => std::io::ErrorKind::Other,
        }
    }
}

impl From<IoError> for std::io::Error {
    fn from(e: IoError) -> Self {
        e.kind().to_std().into()
    }
}

impl<E: FsError> IntoStdIoError for E {
    fn into_std_io_error(self) -> std::io::Error {
        let kind = self
            .io_kind()
            .map_or(std::io::ErrorKind::Other, ErrorKind::to_std);
        std::io::Error::new(kind, format!("{self:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, FsError, IoError};

    #[derive(Debug)]
    enum TestError {
        Io(IoError),
        Parse,
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
                Self::Parse => None,
            }
        }

        fn byte_offset(&self) -> Option<u64> {
            None
        }
    }

    #[test]
    fn io_error_maps_to_std_interrupted() {
        let err = TestError::Io(IoError::new(ErrorKind::Interrupted));
        let std_err = err.into_std_io_error();
        assert_eq!(std_err.kind(), std::io::ErrorKind::Interrupted);
    }

    #[test]
    fn parse_error_maps_to_std_other() {
        let err = TestError::Parse;
        let std_err = err.into_std_io_error();
        assert_eq!(std_err.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn from_std_error_kind_known_variants() {
        assert_eq!(
            ErrorKind::from(std::io::ErrorKind::Interrupted),
            ErrorKind::Interrupted,
        );
        assert_eq!(
            ErrorKind::from(std::io::ErrorKind::UnexpectedEof),
            ErrorKind::UnexpectedEof,
        );
        assert_eq!(
            ErrorKind::from(std::io::ErrorKind::InvalidData),
            ErrorKind::InvalidData,
        );
        assert_eq!(
            ErrorKind::from(std::io::ErrorKind::InvalidInput),
            ErrorKind::InvalidInput,
        );
    }

    #[test]
    fn from_std_error_kind_unknown_maps_to_other() {
        assert_eq!(
            ErrorKind::from(std::io::ErrorKind::NotFound),
            ErrorKind::Other,
        );
    }

    #[test]
    fn to_std_round_trip() {
        for kind in [
            ErrorKind::Interrupted,
            ErrorKind::UnexpectedEof,
            ErrorKind::InvalidData,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert_eq!(ErrorKind::from(kind.to_std()), kind);
        }
    }
}
