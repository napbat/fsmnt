//! A reader that overlays in-memory byte patches on another reader.
//!
//! Damaged media often keeps a *copy* of the structure a parser insists on
//! reading from a fixed place: FAT32 and exFAT carry a backup boot region,
//! NTFS mirrors its boot sector at the end of the volume, ext keeps backup
//! superblocks and group-descriptor tables in later block groups. Rather
//! than teaching every parser about every copy, a driver reads the copy,
//! and [`PatchedReader`] presents it at the primary location while every
//! other byte still comes from the source. Nothing is ever written back;
//! the patches live only in this process.

use std::io::{self, Read, Seek, SeekFrom};

/// One byte range served from memory instead of the underlying reader.
struct Patch {
    /// Absolute byte offset the patch starts at.
    offset: u64,
    /// The bytes presented at `offset..offset + bytes.len()`.
    bytes: Vec<u8>,
}

impl Patch {
    fn end(&self) -> u64 {
        self.offset + self.bytes.len() as u64
    }
}

/// `Read + Seek` adapter that substitutes in-memory patches for chosen
/// byte ranges of `inner`.
///
/// Reads never straddle a patch boundary: a read stops where the next patch
/// begins (or where the current one ends), so callers that use `read_exact`
/// see one seamless byte stream. Patches must not overlap; the last one
/// added wins if they do, but that is a caller bug rather than a feature.
pub struct PatchedReader<R> {
    inner: R,
    /// Kept sorted by offset.
    patches: Vec<Patch>,
    /// Logical read position.
    position: u64,
    /// Where `inner` currently is, to skip redundant seeks. `None` until
    /// the first read.
    inner_position: Option<u64>,
}

impl<R: Read + Seek> PatchedReader<R> {
    /// Wrap `inner` with no patches yet.
    #[must_use]
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            patches: Vec::new(),
            position: 0,
            inner_position: None,
        }
    }

    /// Present `bytes` at `offset` instead of whatever `inner` holds there.
    #[must_use]
    pub fn with_patch(mut self, offset: u64, bytes: Vec<u8>) -> Self {
        self.add_patch(offset, bytes);
        self
    }

    /// Present `bytes` at `offset` instead of whatever `inner` holds there.
    pub fn add_patch(&mut self, offset: u64, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let at = self.patches.partition_point(|patch| patch.offset < offset);
        self.patches.insert(at, Patch { offset, bytes });
    }

    /// Give back the underlying reader; the patches are dropped.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// The patch covering `position`, if any, together with the byte offset
    /// into it.
    fn patch_at(&self, position: u64) -> Option<(&Patch, usize)> {
        // The last patch starting at or before `position` is the only one
        // that can cover it, since patches do not overlap.
        let idx = self
            .patches
            .partition_point(|patch| patch.offset <= position)
            .checked_sub(1)?;
        let patch = &self.patches[idx];
        if position >= patch.end() {
            return None;
        }
        let into = usize::try_from(position - patch.offset).ok()?;
        Some((patch, into))
    }

    /// Start of the first patch that begins after `position`.
    fn next_patch_start(&self, position: u64) -> Option<u64> {
        let idx = self
            .patches
            .partition_point(|patch| patch.offset <= position);
        self.patches.get(idx).map(|patch| patch.offset)
    }
}

impl<R: Read + Seek> Read for PatchedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if let Some((patch, into)) = self.patch_at(self.position) {
            let available = &patch.bytes[into..];
            let n = available.len().min(buf.len());
            buf[..n].copy_from_slice(&available[..n]);
            self.position += n as u64;
            return Ok(n);
        }

        // Plain region: read from `inner`, but never past the start of the
        // next patch so its bytes are the patch's, not the source's.
        let limit = self
            .next_patch_start(self.position)
            .map_or(buf.len(), |start| {
                usize::try_from(start - self.position).map_or(buf.len(), |gap| gap.min(buf.len()))
            });
        if self.inner_position != Some(self.position) {
            self.inner.seek(SeekFrom::Start(self.position))?;
            self.inner_position = Some(self.position);
        }
        let n = self.inner.read(&mut buf[..limit])?;
        self.position += n as u64;
        self.inner_position = Some(self.position);
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for PatchedReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::Current(delta) => self
                .position
                .checked_add_signed(delta)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(delta) => {
                // The end is the source's end (patches only replace bytes
                // that exist, they do not extend the media).
                let end = self.inner.seek(SeekFrom::End(0))?;
                self.inner_position = Some(end);
                end.checked_add_signed(delta).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek before start")
                })?
            }
        };
        self.position = new;
        Ok(new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn source() -> Cursor<Vec<u8>> {
        Cursor::new((0..64u8).collect())
    }

    #[test]
    fn unpatched_reads_pass_through() {
        let mut reader = PatchedReader::new(source());
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn patch_replaces_its_range_and_nothing_else() {
        let mut reader = PatchedReader::new(source()).with_patch(4, vec![0xAA; 4]);
        let mut buf = [0u8; 12];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(
            buf,
            [0, 1, 2, 3, 0xAA, 0xAA, 0xAA, 0xAA, 8, 9, 10, 11],
            "bytes outside the patch must come from the source"
        );
    }

    #[test]
    fn seeking_into_a_patch_and_out_again() {
        let mut reader = PatchedReader::new(source()).with_patch(16, vec![0xBB; 3]);
        reader.seek(SeekFrom::Start(17)).unwrap();
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xBB, 0xBB, 19, 20]);
        assert_eq!(reader.seek(SeekFrom::Current(-2)).unwrap(), 19);
        assert_eq!(reader.seek(SeekFrom::End(-1)).unwrap(), 63);
        let mut last = [0u8; 1];
        reader.read_exact(&mut last).unwrap();
        assert_eq!(last, [63]);
    }

    #[test]
    fn multiple_patches_are_ordered_regardless_of_insertion() {
        let mut reader = PatchedReader::new(source())
            .with_patch(40, vec![2; 2])
            .with_patch(8, vec![1; 2]);
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all.len(), 64);
        assert_eq!(&all[8..10], &[1, 1]);
        assert_eq!(&all[40..42], &[2, 2]);
        assert_eq!(all[10], 10);
        assert_eq!(all[39], 39);
    }

    #[test]
    fn empty_patches_are_ignored_and_into_inner_returns_the_source() {
        let reader = PatchedReader::new(source()).with_patch(0, Vec::new());
        assert!(reader.patches.is_empty());
        assert_eq!(reader.into_inner().into_inner().len(), 64);
    }
}
