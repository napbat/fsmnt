//! Automatic image-format selection and unified decoded-media reader.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use super::container::ImageContainer;
use super::error::ImageOpenError;
use super::format::ImageFormat;
use super::raw::RawImageReader;
use super::util::read_signature;
use super::{ewf, vhd, vhdx};

/// A seekable decoded view of a supported disk-image container.
///
/// [`ImageReader::open`] detects EWF and VHDX from their on-disk signatures,
/// and VHD from its trailing footer. Declared container extensions are also
/// recognized so a corrupt `.E01`, `.VHD`, `.VHDX`, `.AVHD`, or `.AVHDX` file
/// produces a format-specific error instead of being mistaken for raw media.
/// EWF segment sets and sparse virtual-disk blocks are decoded on demand.
pub struct ImageReader {
    inner: Box<dyn ImageContainer>,
}

impl ImageReader {
    /// Open a raw file or a supported disk-image container.
    ///
    /// EWF data is exposed as decoded logical media bytes. Fixed, dynamic, and
    /// differencing VHD containers are supported. Fixed and dynamic VHDX
    /// containers are supported, along with Hyper-V `.avhdx` checkpoint chains
    /// whose parent locators resolve to accessible files. All container readers
    /// fetch payload blocks on demand rather than loading the virtual disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be inspected, a declared container
    /// is invalid, an EWF segment or virtual-disk parent is missing, or required
    /// container metadata cannot be parsed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ImageOpenError> {
        let path = path.as_ref();
        let mut file = File::open(path).map_err(|error| ImageOpenError::new(path, error))?;
        let length = file
            .metadata()
            .map_err(|error| ImageOpenError::new(path, error))?
            .len();
        let signature =
            read_signature(&mut file).map_err(|error| ImageOpenError::new(path, error))?;

        if ewf::has_signature(&signature) || ewf::has_first_segment_extension(path) {
            return Ok(Self {
                inner: Box::new(ewf::EwfImageReader::open(path)?),
            });
        }

        if vhdx::has_signature(&signature) || vhdx::has_extension(path) {
            let reader =
                vhdx::VhdxReader::open(path).map_err(|error| ImageOpenError::new(path, error))?;
            return Ok(Self {
                inner: Box::new(reader),
            });
        }

        let has_vhd_footer = vhd::has_footer_signature(&mut file, length)
            .map_err(|error| ImageOpenError::new(path, error))?;
        if has_vhd_footer || vhd::has_extension(path) {
            let reader =
                vhd::VhdReader::open(path).map_err(|error| ImageOpenError::new(path, error))?;
            return Ok(Self {
                inner: Box::new(reader),
            });
        }

        file.seek(SeekFrom::Start(0))
            .map_err(|error| ImageOpenError::new(path, error))?;
        Ok(Self {
            inner: Box::new(RawImageReader::new(file, length)),
        })
    }

    /// Container format selected while opening the image.
    #[must_use]
    pub fn format(&self) -> ImageFormat {
        self.inner.format()
    }

    /// Length of the decoded logical media in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.inner.len()
    }

    /// Whether the decoded logical media is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Read for ImageReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer)
    }
}

impl Seek for ImageReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}

impl ImageContainer for ImageReader {
    fn format(&self) -> ImageFormat {
        self.inner.format()
    }

    fn len(&self) -> u64 {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_virtual_disk_extensions() {
        for path in ["disk.vhd", "checkpoint.AVHD"] {
            assert!(vhd::has_extension(Path::new(path)));
        }
        for path in ["disk.vhdx", "checkpoint.AVHDX"] {
            assert!(vhdx::has_extension(Path::new(path)));
        }
        for path in ["disk.img", "disk.vhds", "disk"] {
            assert!(!vhd::has_extension(Path::new(path)));
            assert!(!vhdx::has_extension(Path::new(path)));
        }
    }
}
