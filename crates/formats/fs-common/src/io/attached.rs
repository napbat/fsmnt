#[cfg(not(feature = "std"))]
use crate::error::FsError;
use crate::io::{FsReadSeek, Read, Seek, SeekFrom};

/// Adapter that bundles a value reader with its device reader.
///
/// Eliminates the need to pass `&mut R` to every read/seek call.
/// Per-crate `*Attached` wrappers (e.g. `NtfsAttributeValueAttached`)
/// are replaced by this generic adapter.
pub struct Attached<'a, V, R> {
    value: V,
    reader: &'a mut R,
}

impl<'a, V, R> Attached<'a, V, R> {
    /// Creates a new `Attached` adapter.
    pub fn new(value: V, reader: &'a mut R) -> Self {
        Self { value, reader }
    }

    /// Consumes the adapter, returning the value and reader.
    pub fn into_parts(self) -> (V, &'a mut R) {
        (self.value, self.reader)
    }

    /// Returns a reference to the value.
    pub fn value(&self) -> &V {
        &self.value
    }

    /// Returns a mutable reference to the value.
    pub fn value_mut(&mut self) -> &mut V {
        &mut self.value
    }
}

impl<V, R> Attached<'_, V, R>
where
    V: FsReadSeek<R>,
    R: Read + Seek,
{
    /// Reads bytes from the value.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, V::Error> {
        self.value.read(self.reader, buf)
    }

    /// Seeks within the value's stream.
    pub fn seek(&mut self, pos: SeekFrom) -> Result<u64, V::Error> {
        self.value.seek(self.reader, pos)
    }

    /// Reads exactly `buf.len()` bytes.
    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), V::Error> {
        self.value.read_exact(self.reader, buf)
    }

    /// Logical position within the value's stream.
    pub fn stream_position(&self) -> u64 {
        self.value.stream_position()
    }

    /// Total length of the value's data.
    pub fn len(&self) -> u64 {
        self.value.len()
    }

    /// Returns `true` if the value's data is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

#[cfg(not(feature = "std"))]
impl<V, R> Read for Attached<'_, V, R>
where
    V: FsReadSeek<R>,
    R: Read + Seek,
{
    #[cfg_attr(test, mutants::skip)] // cfg(not(feature="std")) — mirrors the std impl below, only built in no_std.
    fn read(&mut self, buf: &mut [u8]) -> crate::io::Result<usize> {
        self.value.read(self.reader, buf).map_err(|e| {
            crate::error::IoError::new(e.io_kind().unwrap_or(crate::error::ErrorKind::Other))
        })
    }
}

#[cfg(not(feature = "std"))]
impl<V, R> Seek for Attached<'_, V, R>
where
    V: FsReadSeek<R>,
    R: Read + Seek,
{
    #[cfg_attr(test, mutants::skip)] // cfg(not(feature="std")) — mirrors the std impl below, only built in no_std.
    fn seek(&mut self, pos: SeekFrom) -> crate::io::Result<u64> {
        self.value.seek(self.reader, pos).map_err(|e| {
            crate::error::IoError::new(e.io_kind().unwrap_or(crate::error::ErrorKind::Other))
        })
    }
}

#[cfg(feature = "std")]
impl<V, R> std::io::Read for Attached<'_, V, R>
where
    V: FsReadSeek<R>,
    V::Error: crate::error::IntoStdIoError,
    R: std::io::Read + std::io::Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.value
            .read(self.reader, buf)
            .map_err(crate::error::IntoStdIoError::into_std_io_error)
    }
}

#[cfg(feature = "std")]
impl<V, R> std::io::Seek for Attached<'_, V, R>
where
    V: FsReadSeek<R>,
    V::Error: crate::error::IntoStdIoError,
    R: std::io::Read + std::io::Seek,
{
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let fs_pos = match pos {
            std::io::SeekFrom::Start(n) => SeekFrom::Start(n),
            std::io::SeekFrom::End(n) => SeekFrom::End(n),
            std::io::SeekFrom::Current(n) => SeekFrom::Current(n),
        };
        self.value
            .seek(self.reader, fs_pos)
            .map_err(crate::error::IntoStdIoError::into_std_io_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, FsError, IoError};
    use std::vec;

    #[derive(Debug)]
    enum TestError {
        Io(IoError),
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
            }
        }

        fn byte_offset(&self) -> Option<u64> {
            None
        }
    }

    struct SliceReader {
        data: &'static [u8],
        pos: u64,
    }

    impl<R: Read + Seek> FsReadSeek<R> for SliceReader {
        type Error = TestError;

        fn read(&mut self, _r: &mut R, buf: &mut [u8]) -> Result<usize, TestError> {
            let remaining = &self.data[self.pos as usize..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n as u64;
            Ok(n)
        }

        fn seek(&mut self, _r: &mut R, pos: SeekFrom) -> Result<u64, TestError> {
            match pos {
                SeekFrom::Start(n) => self.pos = n,
                SeekFrom::Current(n) => {
                    self.pos = (self.pos as i64 + n) as u64;
                }
                SeekFrom::End(n) => {
                    self.pos = (self.data.len() as i64 + n) as u64;
                }
            }
            Ok(self.pos)
        }

        fn stream_position(&self) -> u64 {
            self.pos
        }

        fn len(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn new_and_into_parts() {
        let reader = SliceReader {
            data: b"test",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(std::vec::Vec::<u8>::new());
        let attached = Attached::new(reader, &mut cursor);
        let (value, _reader) = attached.into_parts();
        assert_eq!(value.data, b"test");
    }

    #[test]
    fn read_delegates() {
        let reader = SliceReader {
            data: b"hello",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut attached = Attached::new(reader, &mut cursor);
        let mut buf = [0u8; 5];
        let n = attached.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn seek_delegates() {
        let reader = SliceReader {
            data: b"hello",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut attached = Attached::new(reader, &mut cursor);
        let pos = attached.seek(SeekFrom::Start(3)).unwrap();
        assert_eq!(pos, 3);
        assert_eq!(attached.stream_position(), 3);
    }

    #[test]
    fn len_and_is_empty() {
        let reader = SliceReader {
            data: b"hello",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let attached = Attached::new(reader, &mut cursor);
        assert_eq!(attached.len(), 5);
        assert!(!attached.is_empty());
    }

    #[test]
    fn is_empty_true_on_empty_value() {
        // is_empty -> false would survive without an empty-data case.
        let reader = SliceReader { data: b"", pos: 0 };
        let mut cursor = std::io::Cursor::new(vec![]);
        let attached = Attached::new(reader, &mut cursor);
        assert_eq!(attached.len(), 0);
        assert!(attached.is_empty());
    }

    #[test]
    fn read_exact_delegates_and_fills_buf() {
        // read_exact -> Ok(()) without writing into buf would leave it
        // zeroed, so the explicit slice comparison catches the mutant.
        let reader = SliceReader {
            data: b"forensic",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut attached = Attached::new(reader, &mut cursor);
        let mut buf = [0u8; 8];
        attached.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"forensic");
        assert_eq!(attached.stream_position(), 8);
    }

    #[cfg(feature = "std")]
    #[test]
    fn attached_std_read() {
        let reader = SliceReader {
            data: b"world",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut attached = Attached::new(reader, &mut cursor);
        let mut buf = [0u8; 5];
        std::io::Read::read(&mut attached, &mut buf).unwrap();
        assert_eq!(&buf, b"world");
    }

    #[cfg(feature = "std")]
    #[test]
    fn attached_std_seek() {
        let reader = SliceReader {
            data: b"world",
            pos: 0,
        };
        let mut cursor = std::io::Cursor::new(vec![]);
        let mut attached = Attached::new(reader, &mut cursor);
        let pos = std::io::Seek::seek(&mut attached, std::io::SeekFrom::Start(2)).unwrap();
        assert_eq!(pos, 2);
    }
}
