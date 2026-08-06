use core::fmt;

/// I/O error category for `no_std` environments.
///
/// Mirrors a subset of [`std::io::ErrorKind`] that filesystem crates need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Read was interrupted (retry-safe).
    Interrupted,
    /// Reached end-of-file before the expected amount of data was read.
    UnexpectedEof,
    /// Data was syntactically or semantically invalid.
    InvalidData,
    /// A parameter was incorrect.
    InvalidInput,
    /// Any I/O error not covered by the other variants.
    Other,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Minimal I/O error for `no_std` environments.
///
/// This is a tiny `Copy`/`Clone`/`Eq` struct that wraps an [`ErrorKind`].
/// It carries no heap-allocated message — just the error category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoError {
    kind: ErrorKind,
}

impl IoError {
    /// Creates a new `IoError` from the given [`ErrorKind`].
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the [`ErrorKind`] of this error.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Creates an [`ErrorKind::Interrupted`] error.
    pub const fn interrupted() -> Self {
        Self::new(ErrorKind::Interrupted)
    }

    /// Creates an [`ErrorKind::UnexpectedEof`] error.
    pub const fn unexpected_eof() -> Self {
        Self::new(ErrorKind::UnexpectedEof)
    }

    /// Creates an [`ErrorKind::InvalidData`] error.
    pub const fn invalid_data() -> Self {
        Self::new(ErrorKind::InvalidData)
    }

    /// Creates an [`ErrorKind::InvalidInput`] error.
    pub const fn invalid_input() -> Self {
        Self::new(ErrorKind::InvalidInput)
    }

    /// Creates an [`ErrorKind::Other`] error.
    pub const fn other() -> Self {
        Self::new(ErrorKind::Other)
    }
}

impl From<ErrorKind> for IoError {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I/O error: {:?}", self.kind)
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::format;

    use super::*;

    #[test]
    fn io_error_kind_round_trip() {
        let err = IoError::new(ErrorKind::UnexpectedEof);
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn io_error_is_copy() {
        let err = IoError::new(ErrorKind::Interrupted);
        let err2 = err;
        assert_eq!(err, err2);
    }

    #[test]
    fn error_kind_eq() {
        assert_eq!(ErrorKind::Other, ErrorKind::Other);
        assert_ne!(ErrorKind::Interrupted, ErrorKind::UnexpectedEof);
    }

    #[test]
    fn error_kind_display_writes_variant_name() {
        // The Display impl forwards to Debug, so each variant renders as
        // its identifier. A short-circuit `Ok(())` body would produce "".
        assert_eq!(format!("{}", ErrorKind::Interrupted), "Interrupted");
        assert_eq!(format!("{}", ErrorKind::UnexpectedEof), "UnexpectedEof");
        assert_eq!(format!("{}", ErrorKind::InvalidData), "InvalidData");
        assert_eq!(format!("{}", ErrorKind::InvalidInput), "InvalidInput");
        assert_eq!(format!("{}", ErrorKind::Other), "Other");
    }

    #[test]
    fn io_error_display_includes_prefix_and_kind() {
        // The Display impl writes "I/O error: {Debug kind}", so the
        // formatted string must mention both the prefix and the kind.
        let err = IoError::new(ErrorKind::UnexpectedEof);
        assert_eq!(format!("{err}"), "I/O error: UnexpectedEof");

        let err = IoError::new(ErrorKind::Interrupted);
        assert_eq!(format!("{err}"), "I/O error: Interrupted");
    }
}
