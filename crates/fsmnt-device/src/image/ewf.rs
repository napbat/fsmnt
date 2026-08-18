//! Expert Witness Format detection and decoded-media reader.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use tracing::debug;

use super::container::ImageContainer;
use super::error::ImageOpenError;
use super::format::ImageFormat;
use super::util::has_extension;

const SIGNATURE_LENGTH: usize = 8;
const EWF2_SIGNATURE: [u8; SIGNATURE_LENGTH] = [b'E', b'V', b'F', b'2', 0x0d, 0x0a, 0x81, 0x00];
const LEF2_SIGNATURE: [u8; SIGNATURE_LENGTH] = [b'L', b'E', b'F', b'2', 0x0d, 0x0a, 0x81, 0x00];

pub(super) struct EwfImageReader {
    inner: ::ewf::EwfReader,
    length: u64,
}

impl EwfImageReader {
    pub(super) fn open(path: &Path) -> Result<Self, ImageOpenError> {
        let inner =
            ::ewf::EwfReader::open_lazy(path).map_err(|error| ImageOpenError::new(path, error))?;
        let length = inner.total_size();
        // The remaining segments are discovered by the EWF reader, which
        // does not report how many it found, so the log names the segment
        // the set was entered through and the media it decodes to.
        debug!(
            first_segment = %path.display(),
            size_bytes = length,
            "opened an EWF segment set"
        );
        Ok(Self { inner, length })
    }
}

impl Read for EwfImageReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Seek for EwfImageReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

impl ImageContainer for EwfImageReader {
    fn format(&self) -> ImageFormat {
        ImageFormat::Ewf
    }

    fn len(&self) -> u64 {
        self.length
    }
}

pub(super) fn has_signature(signature: &[u8]) -> bool {
    signature == ::ewf::EVF_SIGNATURE || signature == EWF2_SIGNATURE || signature == LEF2_SIGNATURE
}

pub(super) fn has_first_segment_extension(path: &Path) -> bool {
    has_extension(path, &["e01", "l01", "ex01", "lx01"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_first_segment_extensions_without_a_signature() {
        for path in ["case.E01", "case.l01", "case.Ex01", "case.Lx01"] {
            assert!(has_first_segment_extension(Path::new(path)));
        }
        for path in ["case.img", "case.E02", "case.exe", "case"] {
            assert!(!has_first_segment_extension(Path::new(path)));
        }
    }

    #[test]
    fn recognizes_supported_signatures() {
        assert!(has_signature(&::ewf::EVF_SIGNATURE));
        assert!(has_signature(&EWF2_SIGNATURE));
        assert!(has_signature(&LEF2_SIGNATURE));
        assert!(!has_signature(b"raw image"));
    }
}
