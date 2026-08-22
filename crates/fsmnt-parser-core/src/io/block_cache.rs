//! Bounded cache for repeated reads from one fixed-size source block.

use alloc::vec::Vec;

use super::{ErrorKind, Read, Result, Seek, SeekFrom};

/// Caches the most recently read fixed-size block from a seekable byte source.
///
/// The backing allocation is lazy and never grows beyond `block_size`. A miss
/// replaces the previous block, which keeps memory bounded for large devices.
#[derive(Clone, Debug)]
pub struct BlockCache {
    block_size: usize,
    start: Option<u64>,
    bytes: Vec<u8>,
}

impl BlockCache {
    /// Creates an empty cache for blocks of `block_size` bytes.
    ///
    /// Allocation is deferred until the first cache miss.
    ///
    /// # Panics
    ///
    /// Panics when `block_size` is zero.
    #[must_use]
    pub fn new(block_size: usize) -> Self {
        assert!(block_size != 0, "a cached block cannot be empty");
        Self {
            block_size,
            start: None,
            bytes: Vec::new(),
        }
    }

    /// Returns the configured block size.
    #[must_use]
    pub const fn block_size(&self) -> usize {
        self.block_size
    }

    /// Invalidates the cached block without releasing its allocation.
    pub fn clear(&mut self) {
        self.start = None;
    }

    /// Reads and caches the complete block beginning at `start`.
    ///
    /// A repeated call with the same `start` returns the cached bytes without
    /// seeking or reading the source again.
    ///
    /// # Errors
    ///
    /// Returns the source seek or read error when a cache miss cannot load a
    /// complete block.
    pub fn read_block<'a, R>(&'a mut self, reader: &mut R, start: u64) -> Result<&'a [u8]>
    where
        R: Read + Seek,
    {
        if self.start != Some(start) {
            if self.bytes.len() != self.block_size {
                self.bytes.resize(self.block_size, 0);
            }
            // Invalidate before I/O so a partial read can never be returned as
            // a hit for the block that previously occupied this allocation.
            self.start = None;
            reader.seek(SeekFrom::Start(start))?;
            reader.read_exact(&mut self.bytes)?;
            self.start = Some(start);
        }
        Ok(&self.bytes)
    }

    /// Copies bytes at absolute `offset` into `output`, loading aligned blocks
    /// through this cache as needed.
    ///
    /// Requests crossing a block boundary are split transparently. The final
    /// block touched remains cached.
    ///
    /// # Errors
    ///
    /// Returns invalid input when offset arithmetic exceeds `u64`, or the
    /// source seek/read error when a required block cannot be loaded fully.
    pub fn read_exact_at<R>(&mut self, reader: &mut R, offset: u64, output: &mut [u8]) -> Result<()>
    where
        R: Read + Seek,
    {
        let block_size = u64::try_from(self.block_size).map_err(|_| ErrorKind::InvalidInput)?;
        let mut copied = 0_usize;
        while copied < output.len() {
            let position = offset
                .checked_add(u64::try_from(copied).map_err(|_| ErrorKind::InvalidInput)?)
                .ok_or(ErrorKind::InvalidInput)?;
            let block_start = (position / block_size)
                .checked_mul(block_size)
                .ok_or(ErrorKind::InvalidInput)?;
            let within =
                usize::try_from(position - block_start).map_err(|_| ErrorKind::InvalidInput)?;
            let chunk = (self.block_size - within).min(output.len() - copied);
            let block = self.read_block(reader, block_start)?;
            output[copied..copied + chunk].copy_from_slice(&block[within..within + chunk]);
            copied += chunk;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CountingCursor {
        inner: std::io::Cursor<Vec<u8>>,
        reads: usize,
        seeks: usize,
    }

    impl Read for CountingCursor {
        fn read(&mut self, output: &mut [u8]) -> Result<usize> {
            self.reads += 1;
            self.inner.read(output)
        }
    }

    impl Seek for CountingCursor {
        fn seek(&mut self, position: SeekFrom) -> Result<u64> {
            self.seeks += 1;
            self.inner.seek(position)
        }
    }

    #[test]
    fn repeated_and_adjacent_reads_share_a_block_load() {
        let mut reader = CountingCursor {
            inner: std::io::Cursor::new((0_u8..32).collect()),
            reads: 0,
            seeks: 0,
        };
        let mut cache = BlockCache::new(8);
        let mut output = [0_u8; 3];

        cache.read_exact_at(&mut reader, 1, &mut output).unwrap();
        assert_eq!(output, [1, 2, 3]);
        cache.read_exact_at(&mut reader, 5, &mut output).unwrap();
        assert_eq!(output, [5, 6, 7]);
        assert_eq!((reader.reads, reader.seeks), (1, 1));

        cache.read_exact_at(&mut reader, 7, &mut output).unwrap();
        assert_eq!(output, [7, 8, 9]);
        assert_eq!((reader.reads, reader.seeks), (2, 2));
    }
}
