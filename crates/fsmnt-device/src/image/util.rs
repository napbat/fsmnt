//! Shared bounded I/O and path helpers for image readers.

use std::fs::File;
use std::io::{self, Read, SeekFrom};
use std::path::Path;

pub(super) const SIGNATURE_LENGTH: usize = 8;

pub(super) fn seek_position(current: u64, length: u64, position: SeekFrom) -> io::Result<u64> {
    let target = match position {
        SeekFrom::Start(offset) => Some(offset),
        SeekFrom::Current(delta) => current.checked_add_signed(delta),
        SeekFrom::End(delta) => length.checked_add_signed(delta),
    };
    target.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before image start"))
}

pub(super) fn read_signature(file: &mut File) -> io::Result<Vec<u8>> {
    let mut signature = vec![0_u8; SIGNATURE_LENGTH];
    let mut filled = 0;
    while filled < signature.len() {
        match file.read(&mut signature[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    signature.truncate(filled);
    Ok(signature)
}

pub(super) fn has_extension(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extensions
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seek_rejects_only_positions_before_the_image() {
        assert_eq!(seek_position(10, 100, SeekFrom::Start(200)).unwrap(), 200);
        assert_eq!(seek_position(10, 100, SeekFrom::Current(-5)).unwrap(), 5);
        assert_eq!(seek_position(10, 100, SeekFrom::End(-1)).unwrap(), 99);
        assert!(seek_position(0, 100, SeekFrom::Current(-1)).is_err());
        assert!(seek_position(0, 100, SeekFrom::End(-101)).is_err());
    }
}
