//! Mostly imported from https://github.com/rust-lang/rust/blob/561364e4d5ccc506f610208a4989e91fdbdc8ca7/library/std/src/io/mod.rs

use super::{Error, ErrorKind, Result};

/// Simplified version of [`std::io::Read`] for `no_std` environments.
///
/// See its documentation for more details.
pub trait Read {
    /// See [`std::io::Read::read`].
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// See [`std::io::Read::read_exact`].
    //
    // Verbatim port of the upstream stdlib at rust-lang/rust@561364e4. Only
    // compiled in `no_std` builds; `FsReadSeek::read_exact` in
    // `crate::io::traits` is the parallel std-feature implementation and
    // is exhaustively tested there.
    #[cfg_attr(test, mutants::skip)]
    fn read_exact(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &mut buf[n..];
                }
                Err(ref e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }

        if !buf.is_empty() {
            Err(Error::unexpected_eof())
        } else {
            Ok(())
        }
    }
}
