use std::io;
use std::io::{Read, Seek, SeekFrom};

/// `SectorReader` encapsulates any reader and only performs read and seek operations on it
/// on boundaries of the given sector size.
///
/// This can be very useful for readers that only accept sector-sized reads (like reading
/// from a raw partition on Windows).
/// The sector size must be a power of two.
///
/// This reader does not keep any buffer.
/// You are advised to encapsulate `SectorReader` in a buffered reader, as unbuffered reads of
/// just a few bytes here and there are highly inefficient.
pub struct SectorReader<R>
where
    R: Read + Seek,
{
    /// The inner reader stream.
    inner: R,
    /// The sector size set at creation.
    sector_size: u64,
    /// The current stream position as requested by the caller through `read` or `seek`.
    /// The implementation will internally make sure to only read/seek on sector boundaries.
    stream_position: u64,
    /// This buffer is only part of the struct as a small performance optimization (keeping it allocated between reads).
    temp_buf: Vec<u8>,
}

impl<R> SectorReader<R>
where
    R: Read + Seek,
{
    /// Creates a reader that aligns its underlying I/O to `sector_size`.
    ///
    /// # Errors
    ///
    /// Returns an error when the sector size is not a power of two or cannot
    /// be represented as a 64-bit stream offset.
    pub fn new(inner: R, sector_size: usize) -> io::Result<Self> {
        if !sector_size.is_power_of_two() {
            return Err(io::Error::other("sector_size is not a power of two"));
        }
        let sector_size = u64::try_from(sector_size)
            .map_err(|_| io::Error::other("sector_size does not fit in u64"))?;

        Ok(Self {
            inner,
            sector_size,
            stream_position: 0,
            temp_buf: Vec::new(),
        })
    }

    fn align_down_to_sector_size(&self, n: u64) -> u64 {
        n / self.sector_size * self.sector_size
    }

    fn align_up_to_sector_size(&self, n: u64) -> u64 {
        self.align_down_to_sector_size(n) + self.sector_size
    }
}

impl<R> Read for SectorReader<R>
where
    R: Read + Seek,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // We can only read from a sector boundary, and `self.stream_position` specifies the position where the
        // caller thinks we are.
        // Align down to a sector boundary to determine the position where we really are (see our `seek` implementation).
        let aligned_position = self.align_down_to_sector_size(self.stream_position);

        // We have to read more bytes now to make up for the alignment difference.
        // We can also only read in multiples of the sector size, so align up to the next sector boundary.
        let start = usize::try_from(self.stream_position - aligned_position)
            .map_err(|_| io::Error::other("alignment offset does not fit in usize"))?;
        let end = start
            .checked_add(buf.len())
            .ok_or_else(|| io::Error::other("aligned read length overflowed"))?;
        let end_u64 =
            u64::try_from(end).map_err(|_| io::Error::other("read length does not fit in u64"))?;
        let aligned_bytes_to_read = usize::try_from(self.align_up_to_sector_size(end_u64))
            .map_err(|_| io::Error::other("aligned read length does not fit in usize"))?;

        // Perform the sector-sized read and copy the actually requested bytes into the given buffer.
        self.temp_buf.resize(aligned_bytes_to_read, 0);
        self.inner.read_exact(&mut self.temp_buf)?;
        buf.copy_from_slice(&self.temp_buf[start..end]);

        // We are done.
        let bytes_read = u64::try_from(buf.len())
            .map_err(|_| io::Error::other("read length does not fit in u64"))?;
        self.stream_position = self
            .stream_position
            .checked_add(bytes_read)
            .ok_or_else(|| io::Error::other("stream position overflowed"))?;
        Ok(buf.len())
    }
}

impl<R> Seek for SectorReader<R>
where
    R: Read + Seek,
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::End(_n) => {
                // This is unsupported, because it's not safely possible under Windows.
                // We cannot seek to the end to determine the raw partition size.
                // Which makes it impossible to set `self.stream_position`.
                return Err(io::Error::other(
                    "SeekFrom::End is unsupported for SectorReader",
                ));
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.stream_position.checked_add(n.unsigned_abs())
                } else {
                    self.stream_position.checked_sub(n.unsigned_abs())
                }
            }
        };

        match new_pos {
            Some(n) => {
                // We can only seek on sector boundaries, so align down the requested seek position and seek to that.
                let aligned_n = self.align_down_to_sector_size(n);
                self.inner.seek(SeekFrom::Start(aligned_n))?;

                // Make the caller believe that we seeked to the actually requested position.
                // Our `read` implementation will cover the difference.
                self.stream_position = n;
                Ok(self.stream_position)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to a negative or overflowing position",
            )),
        }
    }
}
