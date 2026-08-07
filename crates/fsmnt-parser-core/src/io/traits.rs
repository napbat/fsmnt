use crate::error::{ErrorKind, IoError, ParserError};
use crate::io::{Read, Seek, SeekFrom};

/// Unified reader trait for filesystem value readers.
///
/// Replaces the duplicated `NtfsReadSeek` and `FatReadSeek` traits.
/// The reader `R` is bound at the trait level for composable bounds:
/// `where V: FsReadSeek<R>`.
pub trait FsReadSeek<R: Read + Seek> {
    /// The error type returned by read/seek operations.
    type Error: ParserError;

    /// Reads bytes from this value into `buf`, using `r` as the
    /// device reader.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined error when data cannot be read.
    fn read(&mut self, r: &mut R, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Seeks to `pos` within this value's stream, using `r` as the
    /// device reader.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined error when the target is invalid.
    fn seek(&mut self, r: &mut R, pos: SeekFrom) -> Result<u64, Self::Error>;

    /// Logical position within this value reader's stream.
    /// This is NOT the underlying device stream position.
    fn stream_position(&self) -> u64;

    /// Total length of the data in bytes.
    fn len(&self) -> u64;

    /// Returns `true` if the data is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads exactly `buf.len()` bytes, returning `UnexpectedEof`
    /// on short read.
    ///
    /// # Errors
    ///
    /// Returns the first read error, including `UnexpectedEof` on a short read.
    fn read_exact(&mut self, r: &mut R, mut buf: &mut [u8]) -> Result<(), Self::Error> {
        while !buf.is_empty() {
            match self.read(r, buf) {
                Ok(0) => {
                    return Err(IoError::new(ErrorKind::UnexpectedEof).into());
                }
                Ok(n) => buf = &mut buf[n..],
                Err(e) => {
                    if e.io_kind() == Some(ErrorKind::Interrupted) {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, IoError, ParserError};
    use std::vec;

    fn offset_position(base: u64, offset: i64) -> u64 {
        if offset.is_negative() {
            base.checked_sub(offset.unsigned_abs())
                .expect("test seek stays at or after zero")
        } else {
            base.checked_add(offset.unsigned_abs())
                .expect("test seek position fits u64")
        }
    }

    #[derive(Debug)]
    enum TestError {
        Io(IoError),
    }

    impl From<IoError> for TestError {
        fn from(e: IoError) -> Self {
            Self::Io(e)
        }
    }

    impl ParserError for TestError {
        fn io_kind(&self) -> Option<ErrorKind> {
            match self {
                Self::Io(e) => Some(e.kind()),
            }
        }

        fn byte_offset(&self) -> Option<u64> {
            None
        }
    }

    /// Minimal value reader: reads from a fixed slice.
    struct SliceReader {
        data: &'static [u8],
        pos: u64,
    }

    impl<R: Read + Seek> FsReadSeek<R> for SliceReader {
        type Error = TestError;

        fn read(&mut self, _r: &mut R, buf: &mut [u8]) -> Result<usize, TestError> {
            let position = usize::try_from(self.pos).expect("test position fits usize");
            let remaining = &self.data[position..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += u64::try_from(n).expect("read length fits u64");
            Ok(n)
        }

        fn seek(&mut self, _r: &mut R, pos: SeekFrom) -> Result<u64, TestError> {
            match pos {
                SeekFrom::Start(n) => self.pos = n,
                SeekFrom::Current(n) => {
                    self.pos = offset_position(self.pos, n);
                }
                SeekFrom::End(n) => {
                    let end = u64::try_from(self.data.len()).expect("slice length fits u64");
                    self.pos = offset_position(end, n);
                }
            }
            Ok(self.pos)
        }

        fn stream_position(&self) -> u64 {
            self.pos
        }

        fn len(&self) -> u64 {
            u64::try_from(self.data.len()).expect("slice length fits u64")
        }
    }

    #[test]
    fn read_exact_success() {
        let mut reader = SliceReader {
            data: b"hello",
            pos: 0,
        };
        let mut dummy = std::io::Cursor::new(vec![]);
        let mut buf = [0u8; 5];
        reader.read_exact(&mut dummy, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn read_exact_eof_returns_error() {
        let mut reader = SliceReader {
            data: b"hi",
            pos: 0,
        };
        let mut dummy = std::io::Cursor::new(vec![]);
        let mut buf = [0u8; 10];
        let err = reader.read_exact(&mut dummy, &mut buf).unwrap_err();
        assert_eq!(err.io_kind(), Some(ErrorKind::UnexpectedEof));
    }

    /// Reader that returns `Interrupted` on the first call, then
    /// succeeds on subsequent calls.
    struct InterruptOnceReader {
        data: &'static [u8],
        pos: u64,
        interrupted: bool,
    }

    impl<R: Read + Seek> FsReadSeek<R> for InterruptOnceReader {
        type Error = TestError;

        fn read(&mut self, _r: &mut R, buf: &mut [u8]) -> Result<usize, TestError> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(IoError::new(ErrorKind::Interrupted).into());
            }
            let position = usize::try_from(self.pos).expect("test position fits usize");
            let remaining = &self.data[position..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += u64::try_from(n).expect("read length fits u64");
            Ok(n)
        }

        fn seek(&mut self, _r: &mut R, pos: SeekFrom) -> Result<u64, TestError> {
            match pos {
                SeekFrom::Start(n) => self.pos = n,
                SeekFrom::Current(n) => {
                    self.pos = offset_position(self.pos, n);
                }
                SeekFrom::End(n) => {
                    let end = u64::try_from(self.data.len()).expect("slice length fits u64");
                    self.pos = offset_position(end, n);
                }
            }
            Ok(self.pos)
        }

        fn stream_position(&self) -> u64 {
            self.pos
        }

        fn len(&self) -> u64 {
            u64::try_from(self.data.len()).expect("slice length fits u64")
        }
    }

    #[test]
    fn read_exact_retries_on_interrupted() {
        let mut reader = InterruptOnceReader {
            data: b"hello",
            pos: 0,
            interrupted: false,
        };
        let mut dummy = std::io::Cursor::new(vec![]);
        let mut buf = [0u8; 5];
        reader.read_exact(&mut dummy, &mut buf).unwrap();
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn is_empty() {
        let reader = SliceReader { data: b"", pos: 0 };
        assert!(FsReadSeek::<std::io::Cursor<Vec<u8>>>::is_empty(&reader));

        let reader2 = SliceReader { data: b"x", pos: 0 };
        assert!(!FsReadSeek::<std::io::Cursor<Vec<u8>>>::is_empty(&reader2));
    }
}
