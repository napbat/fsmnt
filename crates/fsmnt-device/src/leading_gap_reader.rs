//! A medium that begins *inside* the volume it belongs to.
//!
//! An acquisition does not always start at byte zero of a filesystem: a
//! slice cut out of an eMMC, a `dd` that began late, a vendor partition
//! imaged out of the middle of an ext4 volume. The bytes in front of such a
//! medium are not zeros and they are not an end of file — they are a range
//! the medium does not carry at all, and a reader that answered them with
//! zeros would invent evidence that was never acquired.
//!
//! [`LeadingGapReader`] presents the whole volume — `gap` absent bytes,
//! then everything the medium holds — so a filesystem opened through a
//! surviving backup superblock can address its structures at the offsets
//! its own geometry names, instead of every offset being wrong by `gap`. A
//! read that touches the absent head fails, carrying an [`AbsentHead`]
//! marker inside the `io::Error`; that marker is how
//! [`TolerantReader`](crate::TolerantReader) tells "never acquired" apart
//! from "the drive failed this sector" and counts the two separately.

use std::io::{self, Read, Seek, SeekFrom};

/// Marker payload inside the `io::Error` a [`LeadingGapReader`] fails an
/// absent-head read with.
///
/// `io::ErrorKind` has no variant for "these bytes are not part of this
/// medium", and inventing one is not in this crate's gift, so the fact
/// travels as the error's inner value: build it with
/// [`io::Error::other`] and recover it with
/// [`AbsentHead::in_error`], which downcasts through
/// [`io::Error::get_ref`]. Anything that merely propagates the error keeps
/// the marker intact, so an adapter several layers up can still act on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbsentHead {
    /// Bytes at the front of the volume the medium does not carry.
    gap: u64,
    /// Volume offset the failed read started at, which lies inside the gap.
    read_offset: u64,
    /// Length of the failed read, so a log says how much was being asked
    /// for and not just where.
    read_length: u64,
}

impl AbsentHead {
    /// Record a read that reached into the first `gap` bytes of a volume.
    #[must_use]
    pub const fn new(gap: u64, read_offset: u64, read_length: u64) -> Self {
        Self {
            gap,
            read_offset,
            read_length,
        }
    }

    /// The marker inside `error`, or `None` when the failure was an
    /// ordinary I/O error rather than an absent head.
    ///
    /// This is the discrimination the whole design exists for: a bad sector
    /// is a defect of the medium, an absent head is a boundary of the
    /// acquisition, and a report that folded them together would say the
    /// evidence was damaged when it was merely incomplete.
    #[must_use]
    pub fn in_error(error: &io::Error) -> Option<&Self> {
        error.get_ref()?.downcast_ref::<Self>()
    }

    /// Bytes at the front of the volume the medium does not carry.
    #[must_use]
    pub const fn gap(&self) -> u64 {
        self.gap
    }

    /// Volume offset the failed read started at.
    #[must_use]
    pub const fn read_offset(&self) -> u64 {
        self.read_offset
    }

    /// Length of the failed read.
    #[must_use]
    pub const fn read_length(&self) -> u64 {
        self.read_length
    }
}

impl std::fmt::Display for AbsentHead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the medium begins {gap} bytes into this volume; bytes 0..{gap} are absent (the \
             {length}-byte read at {offset} lies in them)",
            gap = self.gap,
            length = self.read_length,
            offset = self.read_offset,
        )
    }
}

impl std::error::Error for AbsentHead {}

/// `Read + Seek` adapter that presents a volume whose first `gap` bytes the
/// medium never carried.
///
/// The reader is `gap + inner_len` bytes long. Everything from `gap`
/// onwards maps to the inner reader at `position - gap`; everything before
/// it fails with an [`AbsentHead`] error. A read that would straddle the
/// boundary from the absent side fails whole rather than returning the tail
/// it could satisfy: a partial read at an offset the caller did not ask for
/// is harder to reason about than a refusal, and the caller that wants the
/// present bytes can simply seek to `gap`.
pub struct LeadingGapReader<R> {
    inner: R,
    /// Bytes at the front of the volume that the medium does not carry.
    gap: u64,
    /// Length of what the medium does carry.
    inner_len: u64,
    /// Position within the volume, counting the absent head.
    position: u64,
}

impl<R: Read + Seek> LeadingGapReader<R> {
    /// Present `inner` as the bytes from `gap` onwards of a longer volume.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of `inner` cannot be determined.
    pub fn new(inner: R, gap: u64) -> io::Result<Self> {
        let mut inner = inner;
        let inner_len = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner,
            gap,
            inner_len,
            position: 0,
        })
    }

    /// Bytes at the front of the volume the medium does not carry.
    #[must_use]
    pub const fn gap(&self) -> u64 {
        self.gap
    }

    /// Length of the whole volume: the absent head plus what the medium
    /// carries.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.gap.saturating_add(self.inner_len)
    }

    /// Whether the volume has no bytes at all, absent or present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes the medium actually carries.
    #[must_use]
    pub const fn carried_len(&self) -> u64 {
        self.inner_len
    }

    /// Consume the adapter and return the medium underneath it.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read + Seek> Read for LeadingGapReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let total = self.len();
        if buf.is_empty() || self.position >= total {
            return Ok(0);
        }
        let want = (total - self.position).min(buf.len() as u64);
        if self.position < self.gap {
            return Err(io::Error::other(AbsentHead::new(
                self.gap,
                self.position,
                want,
            )));
        }

        let inner_position = self.position - self.gap;
        let want = usize::try_from(want).unwrap_or(buf.len());
        self.inner.seek(SeekFrom::Start(inner_position))?;
        let read = self.inner.read(&mut buf[..want])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for LeadingGapReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // Seeking into the absent head is allowed and only the read fails:
        // callers routinely seek to a structure and then decide, from what
        // they know, whether to read it.
        let new = match pos {
            SeekFrom::Start(offset) => Some(offset),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.len().checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?;
        self.position = new;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A 100-byte medium that begins 40 bytes into its volume.
    fn reader() -> LeadingGapReader<Cursor<Vec<u8>>> {
        LeadingGapReader::new(Cursor::new((0..100u8).collect::<Vec<_>>()), 40)
            .expect("a cursor states its length")
    }

    #[test]
    fn the_volume_is_the_gap_plus_what_the_medium_carries() {
        let reader = reader();
        assert_eq!(reader.gap(), 40);
        assert_eq!(reader.carried_len(), 100);
        assert_eq!(reader.len(), 140);
        assert!(!reader.is_empty());
    }

    #[test]
    fn bytes_from_the_gap_onwards_are_the_mediums_own() {
        let mut reader = reader();
        reader
            .seek(SeekFrom::Start(40))
            .expect("seek to the medium");
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf).expect("the medium starts here");
        assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        reader.seek(SeekFrom::Start(139)).expect("seek to the last");
        let mut last = [0u8; 1];
        reader.read_exact(&mut last).expect("the last byte");
        assert_eq!(last, [99]);
        assert_eq!(reader.read(&mut last).expect("past the end"), 0);
    }

    #[test]
    fn a_read_in_the_absent_head_fails_and_says_why() {
        let mut reader = reader();
        let mut buf = [0u8; 8];
        let error = reader.read(&mut buf).expect_err("the head is absent");
        let marker = AbsentHead::in_error(&error).expect("the marker travels in the error");
        assert_eq!(marker.gap(), 40);
        assert_eq!(marker.read_offset(), 0);
        assert_eq!(marker.read_length(), 8);
        assert!(
            error
                .to_string()
                .contains("the medium begins 40 bytes into this volume; bytes 0..40 are absent"),
            "the message names the gap: {error}"
        );
    }

    #[test]
    fn a_read_that_straddles_the_boundary_from_below_fails_whole() {
        let mut reader = reader();
        reader
            .seek(SeekFrom::Start(36))
            .expect("seek near the edge");
        let mut buf = [0u8; 8];
        let error = reader.read(&mut buf).expect_err("four absent bytes first");
        let marker = AbsentHead::in_error(&error).expect("marked absent");
        assert_eq!((marker.read_offset(), marker.read_length()), (36, 8));
        assert!(
            buf.iter().all(|&b| b == 0),
            "a failed read leaves the buffer alone"
        );
    }

    #[test]
    fn an_ordinary_io_error_is_not_mistaken_for_an_absent_head() {
        let error = io::Error::other("medium error");
        assert!(AbsentHead::in_error(&error).is_none());
    }

    #[test]
    fn seeking_spans_the_whole_volume_and_stops_at_its_start() {
        let mut reader = reader();
        assert_eq!(reader.seek(SeekFrom::End(0)).expect("to the end"), 140);
        assert_eq!(reader.seek(SeekFrom::End(-100)).expect("back"), 40);
        assert_eq!(reader.seek(SeekFrom::Current(-40)).expect("back"), 0);
        assert!(
            reader.seek(SeekFrom::Current(-1)).is_err(),
            "there is nothing before the volume"
        );
    }

    #[test]
    fn a_medium_read_never_runs_past_the_end_of_the_volume() {
        let mut reader = reader();
        reader.seek(SeekFrom::Start(135)).expect("near the end");
        let mut buf = [0xFFu8; 16];
        let read = reader.read(&mut buf).expect("the last five bytes");
        assert_eq!(read, 5);
        assert_eq!(&buf[..5], &[95, 96, 97, 98, 99]);
    }
}
