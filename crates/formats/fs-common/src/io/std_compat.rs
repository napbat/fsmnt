//! Standard-library reader adapters for no_std-mode parser tests.

use super::{Error, Read, Result, Seek, SeekFrom};
use crate::error::ErrorKind;

fn map_error(error: std::io::Error) -> Error {
    Error::new(ErrorKind::from(error.kind()))
}

impl<T> Read for std::io::Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        std::io::Read::read(self, buf).map_err(map_error)
    }
}

impl<T> Seek for std::io::Cursor<T>
where
    T: AsRef<[u8]>,
{
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let pos = match pos {
            SeekFrom::Start(offset) => std::io::SeekFrom::Start(offset),
            SeekFrom::End(offset) => std::io::SeekFrom::End(offset),
            SeekFrom::Current(offset) => std::io::SeekFrom::Current(offset),
        };
        std::io::Seek::seek(self, pos).map_err(map_error)
    }
}
