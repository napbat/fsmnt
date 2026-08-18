//! Best-effort reads over damaged or truncated media.
//!
//! A filesystem parser asks for exact byte ranges and gives up on the first
//! read that cannot be satisfied — which turns a dump that ends 100 MB
//! early, or a drive with a handful of bad sectors, into a volume where
//! whole files (or the directory tree) are "unreadable" even though nearly
//! all their bytes are right there. [`TolerantReader`] substitutes zeros for
//! the bytes it cannot get — past the source's end, or in a sector that
//! fails to read — so the parser keeps going and the caller can copy out
//! what exists. Every substitution is counted in [`ReadSubstitutions`],
//! because zeros are not data and a report must say how many there were.
//!
//! This is opt-in: substituted zeros can look like an empty file or a
//! zeroed directory block, and the default open would rather fail loudly.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::{debug, trace};

/// Granularity at which a failing read is written off as zeros: one
/// sector, so a bad-sector error costs 512 bytes, not the whole request.
const ERROR_ZERO_FILL_GRANULE: u64 = 512;

/// What a [`TolerantReader`] substituted, as *distinct* byte ranges.
///
/// Filesystems re-read the same blocks many times over the life of a mount
/// (a whole-file read behind every chunk, directory blocks on every lookup),
/// so a per-read tally would say "gigabytes of zeros" about a 100 MB gap.
/// The ranges are coalesced instead: the totals are the bytes of the media
/// that were asked for and were not there, each counted once.
///
/// Shared (`Arc`) between the reader and whoever reports at the end, since
/// the reader is moved into the filesystem driver.
#[derive(Debug, Default)]
pub struct ReadSubstitutions {
    /// Coalesced `start..end` ranges served as zeros because they lie past
    /// the end of the source.
    missing: Mutex<Ranges>,
    /// Coalesced ranges served as zeros because the source reported an I/O
    /// error.
    errored: Mutex<Ranges>,
    /// Number of I/O errors that were absorbed (every occurrence, since a
    /// sector that fails on every read is still one bad sector but the
    /// count says how often it was hit).
    read_errors: AtomicU64,
}

/// A coalesced set of half-open byte ranges keyed by start.
#[derive(Debug, Default)]
struct Ranges(BTreeMap<u64, u64>);

impl Ranges {
    /// Add `start..end`, merging with anything it touches.
    fn add(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let (mut start, mut end) = (start, end);
        // Absorb the predecessor if it reaches into the new range.
        if let Some((&prev_start, &prev_end)) = self.0.range(..=start).next_back()
            && prev_end >= start
        {
            start = prev_start;
            end = end.max(prev_end);
            self.0.remove(&prev_start);
        }
        // Absorb every successor the (possibly extended) range reaches.
        while let Some((&next_start, &next_end)) = self.0.range(start..).next()
            && next_start <= end
        {
            end = end.max(next_end);
            self.0.remove(&next_start);
        }
        self.0.insert(start, end);
    }

    /// Total bytes covered.
    fn total(&self) -> u64 {
        self.0.iter().map(|(s, e)| e - s).sum()
    }
}

impl ReadSubstitutions {
    /// Distinct bytes past the end of the source that were served as zeros.
    #[must_use]
    pub fn missing_bytes(&self) -> u64 {
        self.missing.lock().map_or(0, |ranges| ranges.total())
    }

    /// Distinct bytes served as zeros because the source failed to read them.
    #[must_use]
    pub fn errored_bytes(&self) -> u64 {
        self.errored.lock().map_or(0, |ranges| ranges.total())
    }

    /// I/O errors that were absorbed.
    #[must_use]
    pub fn read_errors(&self) -> u64 {
        self.read_errors.load(Ordering::Relaxed)
    }

    /// Whether anything at all was substituted.
    #[must_use]
    pub fn any(&self) -> bool {
        self.missing_bytes() > 0 || self.errored_bytes() > 0
    }

    fn record(&self, why: Substituted, start: u64, end: u64) {
        let ranges = match why {
            Substituted::Missing => &self.missing,
            Substituted::Errored => &self.errored,
        };
        if let Ok(mut ranges) = ranges.lock() {
            ranges.add(start, end);
        }
    }
}

/// Why a range was zero-filled; selects the counter it is charged to.
#[derive(Clone, Copy)]
enum Substituted {
    /// Past the source's real end.
    Missing,
    /// The source returned an I/O error.
    Errored,
}

impl Substituted {
    /// Phrase naming this reason in a log record.
    const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "past the end of the source",
            Self::Errored => "the source failed to read the sector",
        }
    }
}

/// `Read + Seek` adapter that zero-fills what its source cannot provide.
///
/// The reader presents `length` bytes: reads beyond the source's actual end
/// (up to `length`) return zeros, and a read the source fails with an I/O
/// error returns zeros for one sector and moves on. Reads at or beyond
/// `length` return 0 bytes like any end of file.
pub struct TolerantReader<R> {
    inner: R,
    /// Where the source actually ends.
    inner_len: u64,
    /// Where this reader claims to end (≥ `inner_len`).
    length: u64,
    position: u64,
    stats: Arc<ReadSubstitutions>,
    /// Whether this reader has already substituted anything, so the first
    /// one can be announced. Logging only; nothing else reads it.
    substituted: bool,
}

impl<R: Read + Seek> TolerantReader<R> {
    /// Wrap `inner`, presenting at least `declared_length` bytes.
    ///
    /// `declared_length` is what the caller believes the media should hold
    /// (a partition's extent, a filesystem's own size); if the source is
    /// longer, its real length is used. Substitution counts are shared
    /// through the returned [`ReadSubstitutions`].
    ///
    /// # Errors
    ///
    /// Returns an error if the source's length cannot be determined.
    pub fn new(inner: R, declared_length: u64) -> io::Result<(Self, Arc<ReadSubstitutions>)> {
        let stats = Arc::new(ReadSubstitutions::default());
        let reader = Self::with_stats(inner, declared_length, Arc::clone(&stats))?;
        Ok((reader, stats))
    }

    /// Like [`new`](Self::new), but charge substitutions to an existing
    /// counter — so several readers (the members of a multi-device
    /// filesystem, say) report one total.
    ///
    /// # Errors
    ///
    /// Returns an error if the source's length cannot be determined.
    pub fn with_stats(
        mut inner: R,
        declared_length: u64,
        stats: Arc<ReadSubstitutions>,
    ) -> io::Result<Self> {
        let inner_len = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(0))?;
        Ok(Self {
            inner,
            inner_len,
            length: declared_length.max(inner_len),
            position: 0,
            stats,
            substituted: false,
        })
    }

    /// The length this reader presents.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.length
    }

    /// Whether the reader presents no bytes at all.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Bytes past the source's real end that this reader zero-fills.
    #[must_use]
    pub const fn missing_tail(&self) -> u64 {
        self.length - self.inner_len
    }

    fn zero_fill(&mut self, buf: &mut [u8], count: usize, why: Substituted) -> usize {
        buf[..count].fill(0);
        let end = self.position + count as u64;
        let reason = why.reason();
        if !self.substituted {
            self.substituted = true;
            debug!(
                offset = self.position,
                len = count,
                reason,
                "best-effort reads are now serving zeros for bytes the source cannot give"
            );
        }
        trace!(
            offset = self.position,
            len = count,
            reason,
            "substituted zeros"
        );
        self.stats.record(why, self.position, end);
        self.position = end;
        count
    }
}

impl<R: Read + Seek> Read for TolerantReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.length {
            return Ok(0);
        }
        let want = usize::try_from((self.length - self.position).min(buf.len() as u64))
            .unwrap_or(buf.len());

        // Entirely past the source: zeros up to the declared length.
        if self.position >= self.inner_len {
            let n = self.zero_fill(buf, want, Substituted::Missing);
            return Ok(n);
        }

        // Within the source: read what is there, never crossing its end in
        // one call so the tail is served by the branch above.
        let available = usize::try_from(self.inner_len - self.position).unwrap_or(want);
        let n = want.min(available);
        self.inner.seek(SeekFrom::Start(self.position))?;
        match self.inner.read(&mut buf[..n]) {
            Ok(0) => {
                // The source is shorter than it said. Treat like the tail.
                self.inner_len = self.position;
                let filled = self.zero_fill(buf, n, Substituted::Missing);
                Ok(filled)
            }
            Ok(read) => {
                self.position += read as u64;
                Ok(read)
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(0),
            Err(_) => {
                // Write off one sector (bounded by the request) as zeros and
                // let the caller continue past the bad spot.
                let granule = usize::try_from(ERROR_ZERO_FILL_GRANULE).unwrap_or(n);
                let count = granule.min(n);
                self.stats.read_errors.fetch_add(1, Ordering::Relaxed);
                let filled = self.zero_fill(buf, count, Substituted::Errored);
                Ok(filled)
            }
        }
    }
}

impl<R: Read + Seek> Seek for TolerantReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => self
                .position
                .checked_add_signed(delta)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(delta) => self
                .length
                .checked_add_signed(delta)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
        };
        self.position = new;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_past_the_source_end_are_zeros_and_counted() {
        let (mut reader, stats) = TolerantReader::new(Cursor::new(vec![7u8; 1000]), 1600).unwrap();
        assert_eq!(reader.len(), 1600);
        assert_eq!(reader.missing_tail(), 600);

        reader.seek(SeekFrom::Start(900)).unwrap();
        let mut buf = vec![0xFFu8; 300];
        reader.read_exact(&mut buf).unwrap();
        assert!(buf[..100].iter().all(|&b| b == 7), "real bytes first");
        assert!(buf[100..].iter().all(|&b| b == 0), "then zeros");
        assert_eq!(stats.missing_bytes(), 200);
        assert_eq!(stats.errored_bytes(), 0);

        // Beyond the declared length is a plain EOF.
        reader.seek(SeekFrom::Start(1600)).unwrap();
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
        assert_eq!(reader.seek(SeekFrom::End(0)).unwrap(), 1600);
    }

    #[test]
    fn a_longer_source_keeps_its_real_length() {
        let (reader, _) = TolerantReader::new(Cursor::new(vec![0u8; 4096]), 100).unwrap();
        assert_eq!(reader.len(), 4096);
        assert_eq!(reader.missing_tail(), 0);
    }

    /// A source that fails every read inside a bad range.
    struct BadSectors {
        data: Cursor<Vec<u8>>,
        bad: std::ops::Range<u64>,
    }

    impl Read for BadSectors {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let pos = self.data.position();
            if self.bad.contains(&pos) {
                return Err(io::Error::other("medium error"));
            }
            // Never read into the bad range in one go, like a real device.
            let limit = if pos < self.bad.start {
                usize::try_from(self.bad.start - pos)
                    .unwrap_or(buf.len())
                    .min(buf.len())
            } else {
                buf.len()
            };
            self.data.read(&mut buf[..limit])
        }
    }

    impl Seek for BadSectors {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.data.seek(pos)
        }
    }

    #[test]
    fn read_errors_are_absorbed_one_sector_at_a_time() {
        let source = BadSectors {
            data: Cursor::new((0..4096u32).map(|i| (i % 251) as u8).collect()),
            bad: 1024..2048,
        };
        let (mut reader, stats) = TolerantReader::new(source, 0).unwrap();
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 4096, "the whole length is served");
        assert!(
            all[1024..2048].iter().all(|&b| b == 0),
            "bad range is zeros"
        );
        assert_eq!(all[1023], (1023u32 % 251) as u8);
        assert_eq!(all[2048], (2048u32 % 251) as u8);
        assert_eq!(stats.errored_bytes(), 1024);
        assert_eq!(stats.read_errors(), 2, "two 512-byte sectors failed");
        assert!(stats.any());

        // Reading the bad range again does not double-count the bytes, but
        // does count the errors — one bad sector hit twice is one bad
        // sector that failed twice.
        reader.seek(SeekFrom::Start(1024)).unwrap();
        let mut again = vec![0u8; 1024];
        reader.read_exact(&mut again).unwrap();
        assert_eq!(stats.errored_bytes(), 1024);
        assert_eq!(stats.read_errors(), 4);
    }

    #[test]
    fn ranges_coalesce_overlaps_and_neighbours() {
        let mut ranges = Ranges::default();
        ranges.add(10, 20);
        ranges.add(30, 40);
        assert_eq!(ranges.total(), 20);
        ranges.add(20, 30); // bridges the two
        assert_eq!(ranges.0.len(), 1);
        assert_eq!(ranges.total(), 30);
        ranges.add(5, 15); // overlaps the front
        assert_eq!(ranges.total(), 35);
        ranges.add(50, 50); // empty
        assert_eq!(ranges.total(), 35);
        ranges.add(0, 100); // swallows everything
        assert_eq!(ranges.0.len(), 1);
        assert_eq!(ranges.total(), 100);
    }
}
