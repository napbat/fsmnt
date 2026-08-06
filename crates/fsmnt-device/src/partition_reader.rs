//! Offset-adjusted reader for accessing partitions within a disk.

use std::io::{Read, Result, Seek, SeekFrom};

/// A reader that provides access to a partition within a larger disk.
///
/// This wraps an underlying reader and adjusts all seek/read operations to
/// be relative to the partition's start offset.
///
/// The inner reader `S` can be either a borrowed reference (`&mut R`) or an
/// owned value (`R`), making this type usable for both temporary partition
/// views and owned filesystem construction.
pub struct PartitionReader<S> {
    inner: S,
    /// Absolute offset of the partition start on the disk.
    base_offset: u64,
    /// Size of the partition in bytes.
    size: u64,
    /// Current position within the partition (relative to `base_offset`).
    position: u64,
    /// Last absolute position that the inner reader was seeked to.
    /// Used to skip redundant seek syscalls on sequential reads.
    inner_position: Option<u64>,
}

impl<S: Read + Seek> PartitionReader<S> {
    /// Create a new partition reader.
    ///
    /// - `reader` — the underlying disk reader (owned or borrowed).
    /// - `base_offset` — absolute byte offset where the partition starts.
    /// - `size` — size of the partition in bytes (use `u64::MAX` for
    ///   unbounded).
    pub fn new(reader: S, base_offset: u64, size: u64) -> Self {
        Self {
            inner: reader,
            base_offset,
            size,
            position: 0,
            inner_position: None,
        }
    }

    /// Absolute byte offset where the partition starts on the disk.
    #[must_use]
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// Size of the partition in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Current position within the partition.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Consume and return the underlying reader.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read + Seek> Read for PartitionReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Limit the read to the partition bounds.
        let remaining = self.size.saturating_sub(self.position);
        let max_read = usize::try_from(remaining.min(buf.len() as u64)).unwrap_or(buf.len());

        if max_read == 0 {
            return Ok(0);
        }

        // Only seek the inner reader when necessary (skip for sequential
        // reads).
        let abs_pos = self.base_offset + self.position;
        if self.inner_position != Some(abs_pos) {
            self.inner.seek(SeekFrom::Start(abs_pos))?;
        }

        let bytes_read = self.inner.read(&mut buf[..max_read])?;
        self.position += bytes_read as u64;
        self.inner_position = Some(abs_pos + bytes_read as u64);
        Ok(bytes_read)
    }
}

impl<S: Read + Seek> Seek for PartitionReader<S> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => i64::try_from(offset).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek offset too large")
            })?,
            SeekFrom::End(offset) => {
                let size = i64::try_from(self.size).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "partition size too large for seek",
                    )
                })?;
                size.checked_add(offset).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek offset overflow")
                })?
            }
            SeekFrom::Current(offset) => {
                let pos = i64::try_from(self.position).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "current position too large for seek",
                    )
                })?;
                pos.checked_add(offset).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek offset overflow")
                })?
            }
        };

        if new_pos < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }

        self.position = new_pos.unsigned_abs();
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_within_partition_window() {
        let data: Vec<u8> = (0..100).collect();
        let mut cursor = Cursor::new(data);

        // Partition from offset 20, size 30.
        let mut reader = PartitionReader::new(&mut cursor, 20, 30);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf, &[20, 21, 22, 23, 24, 25, 26, 27, 28, 29]);
    }

    #[test]
    fn seek_is_partition_relative() {
        let data: Vec<u8> = (0..100).collect();
        let mut cursor = Cursor::new(data);

        let mut reader = PartitionReader::new(&mut cursor, 20, 30);

        reader.seek(SeekFrom::Start(5)).unwrap();

        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[25, 26, 27, 28, 29]);
    }

    #[test]
    fn read_is_clamped_to_partition_size() {
        let data: Vec<u8> = (0..100).collect();
        let mut cursor = Cursor::new(data);

        // Partition from offset 90, size 10 (ends at 100).
        let mut reader = PartitionReader::new(&mut cursor, 90, 10);

        let mut buf = [0u8; 20]; // Try to read more than available.
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..10], &[90, 91, 92, 93, 94, 95, 96, 97, 98, 99]);
    }

    #[test]
    fn owned_reader_round_trips() {
        let data: Vec<u8> = (0..100).collect();
        let cursor = Cursor::new(data);

        let mut reader = PartitionReader::new(cursor, 10, 50);

        let mut buf = [0u8; 5];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &[10, 11, 12, 13, 14]);

        let _inner = reader.into_inner();
    }

    #[test]
    fn negative_seek_is_rejected() {
        let cursor = Cursor::new(vec![0u8; 10]);
        let mut reader = PartitionReader::new(cursor, 0, 10);
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
    }
}
