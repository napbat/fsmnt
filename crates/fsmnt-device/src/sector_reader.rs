//! Arbitrary byte reads over a sector-constrained block source.

use std::io::{Error, ErrorKind, Result};

use nostdio::{Read, Seek, SeekFrom};

/// A reader that translates arbitrary byte reads into sector-aligned I/O.
///
/// Raw block-device handles on platforms such as Windows can reject reads
/// whose offset or length is not a multiple of the device's logical sector
/// size. Filesystem parsers, however, legitimately read smaller structures
/// such as 256-byte ext inodes. `SectorReader` bridges those contracts by
/// reading complete sectors and copying only the requested bytes.
pub struct SectorReader<S> {
    inner: S,
    length: u64,
    position: u64,
    sector_size: u32,
    sector: Vec<u8>,
    cached_sector: Option<u64>,
}

impl<S: Read + Seek> SectorReader<S> {
    /// Create a sector-aligning view over `inner`.
    ///
    /// `length` is the readable logical length exposed by this view.
    ///
    /// # Errors
    ///
    /// Returns an error when the sector size is zero or not a power of two,
    /// the logical length is not sector-aligned, the sector size does not fit
    /// the current platform, or the sector buffer cannot be allocated.
    pub fn new(inner: S, length: u64, sector_size: u32) -> Result<Self> {
        if sector_size == 0 || !sector_size.is_power_of_two() {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid logical sector size {sector_size}"),
            ));
        }

        let sector_length = u64::from(sector_size);
        if !length.is_multiple_of(sector_length) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "device length {length} is not a multiple of logical sector size {sector_size}"
                ),
            ));
        }

        let buffer_length = usize::try_from(sector_size).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "logical sector size does not fit this platform",
            )
        })?;
        let mut sector = Vec::new();
        sector.try_reserve_exact(buffer_length).map_err(|error| {
            Error::new(
                ErrorKind::OutOfMemory,
                format!("cannot allocate logical-sector buffer: {error}"),
            )
        })?;
        sector.resize(buffer_length, 0);

        Ok(Self {
            inner,
            length,
            position: 0,
            sector_size,
            sector,
            cached_sector: None,
        })
    }

    /// Return the readable logical length.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Return whether the readable logical view is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Return the logical sector size in bytes.
    #[must_use]
    pub const fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// Return the current logical byte position.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Consume this adapter and return its underlying reader.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }

    fn load_sector(&mut self, sector_start: u64) -> Result<()> {
        if self.cached_sector == Some(sector_start) {
            return Ok(());
        }

        let sector_length = u64::from(self.sector_size);
        let sector_end = sector_start
            .checked_add(sector_length)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "sector end overflow"))?;
        if !sector_start.is_multiple_of(sector_length) || sector_end > self.length {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "sector read is outside the aligned device extent",
            ));
        }

        self.cached_sector = None;
        self.inner.seek(SeekFrom::Start(sector_start))?;
        self.inner.read_exact(&mut self.sector)?;
        self.cached_sector = Some(sector_start);
        Ok(())
    }

    fn advance(&mut self, amount: usize) -> Result<()> {
        let amount = u64::try_from(amount)
            .map_err(|_| Error::new(ErrorKind::InvalidData, "read length exceeds u64"))?;
        self.position = self
            .position
            .checked_add(amount)
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "reader position overflow"))?;
        Ok(())
    }
}

impl<S: Read + Seek> Read for SectorReader<S> {
    fn read(&mut self, output: &mut [u8]) -> Result<usize> {
        if output.is_empty() || self.position >= self.length {
            return Ok(0);
        }

        let remaining = self.length - self.position;
        let output_length = u64::try_from(output.len()).unwrap_or(u64::MAX);
        let wanted = usize::try_from(remaining.min(output_length)).unwrap_or(output.len());
        let sector_length = usize::try_from(self.sector_size).map_err(|_| {
            Error::new(
                ErrorKind::InvalidInput,
                "logical sector size does not fit this platform",
            )
        })?;
        let sector_length_u64 = u64::from(self.sector_size);
        let mut written = 0;

        let head_offset_u64 = self.position % sector_length_u64;
        if head_offset_u64 != 0 {
            let sector_start = self.position - head_offset_u64;
            self.load_sector(sector_start)?;
            let head_offset = usize::try_from(head_offset_u64).map_err(|_| {
                Error::new(
                    ErrorKind::InvalidInput,
                    "sector-relative offset does not fit this platform",
                )
            })?;
            let count = (sector_length - head_offset).min(wanted);
            output[..count].copy_from_slice(&self.sector[head_offset..head_offset + count]);
            self.advance(count)?;
            written = count;
        }

        let remaining = wanted - written;
        let aligned_length = remaining - (remaining % sector_length);
        if aligned_length != 0 {
            self.inner.seek(SeekFrom::Start(self.position))?;
            self.inner
                .read_exact(&mut output[written..written + aligned_length])?;
            self.advance(aligned_length)?;
            written += aligned_length;
        }

        let tail_length = wanted - written;
        if tail_length != 0 {
            self.load_sector(self.position)?;
            output[written..wanted].copy_from_slice(&self.sector[..tail_length]);
            self.advance(tail_length)?;
            written = wanted;
        }

        Ok(written)
    }
}

impl<S: Read + Seek> Seek for SectorReader<S> {
    fn seek(&mut self, position: SeekFrom) -> Result<u64> {
        let next = match position {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::End(offset) => offset_position(self.length, offset),
            SeekFrom::Current(offset) => offset_position(self.position, offset),
        }
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "invalid seek position"))?;

        self.position = next;
        Ok(next)
    }
}

fn offset_position(base: u64, offset: i64) -> Option<u64> {
    if offset.is_negative() {
        base.checked_sub(offset.unsigned_abs())
    } else {
        base.checked_add(offset.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    struct StrictSectorDevice {
        inner: Cursor<Vec<u8>>,
        sector_size: u64,
    }

    impl StrictSectorDevice {
        fn new(data: Vec<u8>, sector_size: u64) -> Self {
            Self {
                inner: Cursor::new(data),
                sector_size,
            }
        }
    }

    impl Read for StrictSectorDevice {
        fn read(&mut self, output: &mut [u8]) -> Result<usize> {
            let output_length = u64::try_from(output.len()).map_err(|_| {
                Error::new(ErrorKind::InvalidInput, "test buffer length exceeds u64")
            })?;
            if !self.inner.position().is_multiple_of(self.sector_size)
                || !output_length.is_multiple_of(self.sector_size)
            {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "underlying read was not sector-aligned",
                ));
            }
            self.inner.read(output)
        }
    }

    impl Seek for StrictSectorDevice {
        fn seek(&mut self, position: SeekFrom) -> Result<u64> {
            self.inner.seek(position)
        }
    }

    fn reader() -> SectorReader<StrictSectorDevice> {
        let data: Vec<u8> = (0_u8..32).collect();
        SectorReader::new(StrictSectorDevice::new(data, 4), 32, 4).expect("test geometry is valid")
    }

    #[test]
    fn reads_unaligned_range_across_a_sector_boundary() {
        let mut reader = reader();
        reader.seek(SeekFrom::Start(1)).unwrap();
        let mut output = [0_u8; 6];

        assert_eq!(reader.read(&mut output).unwrap(), output.len());
        assert_eq!(output, [1, 2, 3, 4, 5, 6]);
        assert_eq!(reader.position(), 7);
    }

    #[test]
    fn reads_aligned_multi_sector_range_directly() {
        let mut reader = reader();
        reader.seek(SeekFrom::Start(8)).unwrap();
        let mut output = [0_u8; 12];

        assert_eq!(reader.read(&mut output).unwrap(), output.len());
        assert_eq!(output, [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    }

    #[test]
    fn sequential_small_reads_share_sector_sized_io() {
        let mut reader = reader();
        reader.seek(SeekFrom::Start(2)).unwrap();
        let mut first = [0_u8; 2];
        let mut second = [0_u8; 2];

        reader.read_exact(&mut first).unwrap();
        reader.read_exact(&mut second).unwrap();

        assert_eq!(first, [2, 3]);
        assert_eq!(second, [4, 5]);
        assert_eq!(reader.position(), 6);
    }

    #[test]
    fn read_is_clamped_at_the_logical_end() {
        let mut reader = reader();
        reader.seek(SeekFrom::Start(30)).unwrap();
        let mut output = [0_u8; 8];

        assert_eq!(reader.read(&mut output).unwrap(), 2);
        assert_eq!(&output[..2], &[30, 31]);
        assert_eq!(reader.read(&mut output).unwrap(), 0);
    }

    #[test]
    fn seek_is_logical_and_checked() {
        let mut reader = reader();

        assert_eq!(reader.seek(SeekFrom::End(-2)).unwrap(), 30);
        assert_eq!(reader.seek(SeekFrom::Current(1)).unwrap(), 31);
        assert!(reader.seek(SeekFrom::Current(-32)).is_err());
        assert!(reader.seek(SeekFrom::End(i64::MIN)).is_err());
    }

    #[test]
    fn rejects_invalid_geometry() {
        assert!(SectorReader::new(Cursor::new(vec![0_u8; 8]), 8, 0).is_err());
        assert!(SectorReader::new(Cursor::new(vec![0_u8; 8]), 8, 3).is_err());
        assert!(SectorReader::new(Cursor::new(vec![0_u8; 7]), 7, 4).is_err());
    }

    #[test]
    fn accessors_and_into_inner_preserve_geometry() {
        let reader = reader();

        assert_eq!(reader.len(), 32);
        assert!(!reader.is_empty());
        assert_eq!(reader.sector_size(), 4);
        assert_eq!(reader.position(), 0);
        assert_eq!(reader.into_inner().inner.into_inner().len(), 32);
    }
}
