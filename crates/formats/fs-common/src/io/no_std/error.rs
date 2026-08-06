//! `no_std` I/O error types — pure aliases for [`IoError`](crate::error::IoError).

pub use crate::error::ErrorKind;

/// I/O error type for `no_std` environments.
///
/// In `no_std` mode this is [`IoError`](crate::error::IoError) directly.
/// In `std` mode the `io` module re-exports [`std::io::Error`] instead.
pub type Error = crate::error::IoError;

/// A specialized [`Result`] type for I/O operations.
pub type Result<T> = core::result::Result<T, Error>;
