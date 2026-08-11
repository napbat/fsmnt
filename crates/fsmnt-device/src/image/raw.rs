//! Byte-for-byte raw disk-image reader.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use super::container::ImageContainer;
use super::format::ImageFormat;

pub(super) struct RawImageReader {
    file: File,
    length: u64,
}

impl RawImageReader {
    pub(super) fn new(file: File, length: u64) -> Self {
        Self { file, length }
    }
}

impl Read for RawImageReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}

impl Seek for RawImageReader {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

impl ImageContainer for RawImageReader {
    fn format(&self) -> ImageFormat {
        ImageFormat::Raw
    }

    fn len(&self) -> u64 {
        self.length
    }
}
