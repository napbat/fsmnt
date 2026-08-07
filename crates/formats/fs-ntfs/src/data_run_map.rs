use alloc::vec::Vec;
use fsmnt_parser_core::error::IoError;

use crate::attribute_value::NtfsDataRuns;
use crate::error::{NtfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::types::NtfsPosition;

/// A contiguous physical segment of an attribute's data on disk.
#[derive(Clone, Debug)]
struct DataRunSegment {
    /// Virtual byte offset within the attribute where this segment starts.
    virtual_offset: u64,
    /// Absolute byte position on disk (None for sparse).
    position: NtfsPosition,
    /// Size of this segment in bytes.
    size: u64,
}

/// Maps virtual byte offsets within a non-resident attribute to physical disk positions.
///
/// Built from an attribute's data runs and shared by `NtfsMftEntries`,
/// `NtfsUsnJournal`, and `NtfsClusterBitmap` to avoid duplicating the same
/// segment extraction and position resolution logic.
#[derive(Clone, Debug)]
pub(crate) struct DataRunMap {
    segments: Vec<DataRunSegment>,
}

impl DataRunMap {
    /// Builds a map from an attribute's data runs.
    pub(crate) fn from_data_runs(data_runs: NtfsDataRuns<'_, '_>) -> Result<Self> {
        let mut segments = Vec::new();
        let mut virtual_offset = 0u64;

        for run in data_runs {
            let run = run?;
            let size = run.allocated_size();
            segments.push(DataRunSegment {
                virtual_offset,
                position: run.data_position(),
                size,
            });
            virtual_offset += size;
        }

        Ok(Self { segments })
    }

    /// Extends this map with additional data runs, appending them
    /// after the existing segments.
    pub(crate) fn extend_data_runs(&mut self, data_runs: NtfsDataRuns<'_, '_>) -> Result<()> {
        let mut virtual_offset = self.total_size();
        for run in data_runs {
            let run = run?;
            let size = run.allocated_size();
            self.segments.push(DataRunSegment {
                virtual_offset,
                position: run.data_position(),
                size,
            });
            virtual_offset += size;
        }
        Ok(())
    }

    /// Total size spanned by all segments (sum of all data run sizes).
    pub(crate) fn total_size(&self) -> u64 {
        self.segments
            .last()
            .map_or(0, |s| s.virtual_offset + s.size)
    }

    /// Number of segments in the map.
    pub(crate) fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Returns the position and size of a segment by index.
    ///
    /// Used by `NtfsMftEntries` for sequential iteration through segments.
    pub(crate) fn segment(&self, index: usize) -> Option<(NtfsPosition, u64)> {
        self.segments.get(index).map(|s| (s.position, s.size))
    }

    /// Resolves a virtual byte offset to an absolute disk position and the
    /// number of remaining bytes in that segment.
    ///
    /// Returns `None` if `offset` is outside all segments.
    pub(crate) fn resolve_position(&self, offset: u64) -> Option<(NtfsPosition, u64)> {
        for segment in &self.segments {
            let seg_end = segment.virtual_offset + segment.size;
            if offset >= segment.virtual_offset && offset < seg_end {
                let offset_in_seg = offset - segment.virtual_offset;
                let remaining = segment.size - offset_in_seg;
                let pos = segment.position + offset_in_seg;
                return Some((pos, remaining));
            }
        }
        None
    }

    /// Resolves a virtual byte offset to a segment index and the byte offset
    /// within that segment.
    ///
    /// Used by `NtfsMftEntries::seek_to_record` to position the sequential
    /// iterator at an arbitrary record.
    pub(crate) fn resolve_index(&self, offset: u64) -> Option<(usize, u64)> {
        for (i, segment) in self.segments.iter().enumerate() {
            if offset < segment.virtual_offset + segment.size {
                return Some((i, offset - segment.virtual_offset));
            }
        }
        None
    }

    /// Finds the next non-sparse virtual offset at or after `offset`.
    ///
    /// Used by `NtfsUsnRecords` to skip sparse holes in the `$J` stream.
    pub(crate) fn next_non_sparse_offset(&self, offset: u64) -> Option<u64> {
        for segment in &self.segments {
            let seg_end = segment.virtual_offset + segment.size;
            if seg_end <= offset {
                continue;
            }
            // This segment overlaps or follows offset.
            if segment.position.value().is_none() {
                // Sparse — skip.
                continue;
            }
            // Non-sparse segment found. If `offset` already lies inside it,
            // return `offset`; otherwise return the segment's start. Both cases
            // are the larger of the two values.
            return Some(offset.max(segment.virtual_offset));
        }
        None
    }

    /// Reads `buf.len()` bytes starting at virtual byte `offset`.
    ///
    /// Handles reads that cross segment boundaries and fills zeros
    /// for sparse segments.  Returns the disk position of the first
    /// byte (for error context).
    pub(crate) fn read_at<T: Read + Seek>(
        &self,
        fs: &mut T,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<NtfsPosition> {
        let total = u64::try_from(buf.len()).expect("a slice length fits u64");
        if total == 0 {
            return Ok(NtfsPosition::none());
        }

        let end = offset
            .checked_add(total)
            .ok_or(NtfsError::from(IoError::invalid_input()))?;
        if end > self.total_size() {
            return Err(IoError::unexpected_eof().into());
        }

        let first_position = self
            .resolve_position(offset)
            .map_or(NtfsPosition::none(), |(pos, _)| pos);

        let mut bytes_filled = 0u64;
        while bytes_filled < total {
            let current_offset = offset + bytes_filled;
            let (pos, remaining) = self
                .resolve_position(current_offset)
                .ok_or(NtfsError::from(IoError::unexpected_eof()))?;

            let to_read = usize::try_from((total - bytes_filled).min(remaining))
                .expect("the read length is bounded by the destination slice");
            let destination_start = usize::try_from(bytes_filled)
                .expect("the filled length is bounded by the destination slice");
            let dst = &mut buf[destination_start..destination_start + to_read];

            if let Some(disk_pos) = pos.value() {
                fs.seek(SeekFrom::Start(disk_pos.get()))?;
                fs.read_exact(dst)?;
            } else {
                dst.fill(0);
            }

            bytes_filled += u64::try_from(to_read).expect("a slice length fits u64");
        }

        Ok(first_position)
    }

    /// Returns the end offset of the segment containing `offset`.
    ///
    /// Falls back to `total_size()` if `offset` is not within any segment.
    /// Used by `NtfsUsnRecords` for corruption recovery (skip to next segment
    /// boundary on encountering zero or invalid record lengths).
    pub(crate) fn segment_end(&self, offset: u64) -> u64 {
        for segment in &self.segments {
            let seg_end = segment.virtual_offset + segment.size;
            if offset >= segment.virtual_offset && offset < seg_end {
                return seg_end;
            }
        }
        self.total_size()
    }

    /// Builds a `DataRunMap` directly from `(position, size)` pairs.
    ///
    /// Test-only constructor shared with other modules' tests (e.g. the
    /// cluster-bitmap and USN-journal iterators) that need a synthetic map
    /// without a backing `NtfsDataRuns`.
    #[cfg(test)]
    pub(crate) fn from_segments_for_test(runs: &[(Option<u64>, u64)]) -> Self {
        let mut segments = Vec::new();
        let mut virtual_offset = 0u64;
        for &(pos, size) in runs {
            segments.push(DataRunSegment {
                virtual_offset,
                position: match pos {
                    Some(p) => NtfsPosition::new(p),
                    None => NtfsPosition::none(),
                },
                size,
            });
            virtual_offset += size;
        }
        Self { segments }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribute_value::NtfsDataRuns;
    use core::num::NonZeroU64;
    use fsmnt_testkit::Cursor;

    /// Helper: build a `DataRunMap` from raw (position, size) pairs.
    fn map_from_raw(runs: &[(Option<u64>, u64)]) -> DataRunMap {
        let mut segments = Vec::new();
        let mut virtual_offset = 0u64;
        for &(pos, size) in runs {
            segments.push(DataRunSegment {
                virtual_offset,
                position: match pos {
                    Some(p) => NtfsPosition::new(p),
                    None => NtfsPosition::none(),
                },
                size,
            });
            virtual_offset += size;
        }
        DataRunMap { segments }
    }

    #[test]
    fn test_total_size_empty() {
        let map = DataRunMap {
            segments: Vec::new(),
        };
        assert_eq!(map.total_size(), 0);
        assert_eq!(map.segment_count(), 0);
    }

    #[test]
    fn test_total_size_and_count() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);
        assert_eq!(map.total_size(), 1536);
        assert_eq!(map.segment_count(), 2);
    }

    #[test]
    fn test_segment_access() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);

        let (pos, size) = map.segment(0).unwrap();
        assert_eq!(pos.value().unwrap(), NonZeroU64::new(1000).unwrap());
        assert_eq!(size, 512);

        let (pos, size) = map.segment(1).unwrap();
        assert_eq!(pos.value().unwrap(), NonZeroU64::new(2000).unwrap());
        assert_eq!(size, 1024);

        assert!(map.segment(2).is_none());
    }

    #[test]
    fn test_resolve_position_first_segment() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);

        let (pos, remaining) = map.resolve_position(100).unwrap();
        assert_eq!(pos.value().unwrap(), NonZeroU64::new(1100).unwrap());
        assert_eq!(remaining, 412);
    }

    #[test]
    fn test_resolve_position_second_segment() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);

        let (pos, remaining) = map.resolve_position(600).unwrap();
        // offset 600 is 88 bytes into second segment (virtual_offset=512)
        assert_eq!(pos.value().unwrap(), NonZeroU64::new(2088).unwrap());
        assert_eq!(remaining, 936);
    }

    #[test]
    fn test_resolve_position_sparse() {
        let map = map_from_raw(&[(None, 512), (Some(2000), 1024)]);

        let (pos, remaining) = map.resolve_position(100).unwrap();
        // Sparse: NtfsPosition::none() + 100 stays None
        assert!(pos.value().is_none());
        assert_eq!(remaining, 412);
    }

    #[test]
    fn test_resolve_position_past_end() {
        let map = map_from_raw(&[(Some(1000), 512)]);
        assert!(map.resolve_position(512).is_none());
        assert!(map.resolve_position(9999).is_none());
    }

    #[test]
    fn test_resolve_index() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);

        let (idx, off) = map.resolve_index(0).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(off, 0);

        let (idx, off) = map.resolve_index(511).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(off, 511);

        let (idx, off) = map.resolve_index(512).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(off, 0);

        let (idx, off) = map.resolve_index(1000).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(off, 488);

        assert!(map.resolve_index(1536).is_none());
    }

    #[test]
    fn test_next_non_sparse_offset_skip_holes() {
        // sparse hole (0..512), then real data (512..1536)
        let map = map_from_raw(&[(None, 512), (Some(2000), 1024)]);

        // From offset 0 (inside sparse) → jumps to 512
        assert_eq!(map.next_non_sparse_offset(0), Some(512));
        // From offset 256 (still sparse) → jumps to 512
        assert_eq!(map.next_non_sparse_offset(256), Some(512));
        // From offset 512 (start of real data) → stays at 512
        assert_eq!(map.next_non_sparse_offset(512), Some(512));
        // From offset 600 (inside real data) → stays at 600
        assert_eq!(map.next_non_sparse_offset(600), Some(600));
        // From offset 1536 (past end) → None
        assert_eq!(map.next_non_sparse_offset(1536), None);
    }

    #[test]
    fn test_next_non_sparse_offset_all_sparse() {
        let map = map_from_raw(&[(None, 512), (None, 1024)]);
        assert_eq!(map.next_non_sparse_offset(0), None);
    }

    #[test]
    fn test_segment_end() {
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);

        assert_eq!(map.segment_end(0), 512);
        assert_eq!(map.segment_end(511), 512);
        assert_eq!(map.segment_end(512), 1536);
        assert_eq!(map.segment_end(1000), 1536);
        // Past end → total_size fallback
        assert_eq!(map.segment_end(9999), 1536);
    }

    #[test]
    fn test_next_non_sparse_offset_boundary() {
        // Segment 0 ends at 512. From offset 512 (== seg_end of segment 0), the
        // `seg_end <= offset` continue must skip segment 0 and land in segment 1.
        // A `<` mutation would incorrectly stop inside segment 0.
        let map = map_from_raw(&[(Some(1000), 512), (Some(2000), 1024)]);
        assert_eq!(map.next_non_sparse_offset(512), Some(512));
        // From offset 511 (still inside segment 0) it returns 511 (already inside).
        assert_eq!(map.next_non_sparse_offset(511), Some(511));
    }

    /// In-memory disk where byte `i` equals the low byte of `i`, used to verify reads.
    fn indexed_disk(len: usize) -> Cursor<Vec<u8>> {
        let mut data = vec![0u8; len];
        for (i, b) in data.iter_mut().enumerate() {
            *b = i.to_le_bytes()[0];
        }
        Cursor::new(data)
    }

    #[test]
    fn test_read_at_zero_length() {
        let map = map_from_raw(&[(Some(100), 512)]);
        let mut disk = indexed_disk(4096);
        // A zero-length read returns NtfsPosition::none() without touching disk.
        let pos = map.read_at(&mut disk, 0, &mut []).unwrap();
        assert!(pos.value().is_none());
    }

    #[test]
    fn test_read_at_within_single_segment() {
        // One real segment of 256 bytes at disk position 1000.
        let map = map_from_raw(&[(Some(1000), 256)]);
        let mut disk = indexed_disk(4096);

        let mut buf = [0u8; 4];
        let pos = map.read_at(&mut disk, 8, &mut buf).unwrap();
        // First byte position = disk 1000 + offset 8 = 1008.
        assert_eq!(pos.value().unwrap().get(), 1008);
        // Bytes come from disk positions 1008..1012.
        assert_eq!(
            buf,
            [
                1008_u32.to_le_bytes()[0],
                1009_u32.to_le_bytes()[0],
                1010_u32.to_le_bytes()[0],
                1011_u32.to_le_bytes()[0]
            ]
        );
    }

    #[test]
    fn test_read_at_crosses_segment_boundary() {
        // Two real segments: 0..16 at disk 1000, 16..32 at disk 2000.
        let map = map_from_raw(&[(Some(1000), 16), (Some(2000), 16)]);
        let mut disk = indexed_disk(4096);

        // Read 8 bytes starting at offset 12: 4 from segment 0, 4 from segment 1.
        let mut buf = [0u8; 8];
        let pos = map.read_at(&mut disk, 12, &mut buf).unwrap();
        assert_eq!(pos.value().unwrap().get(), 1012);
        // Segment 0: disk 1012..1016. Segment 1: disk 2000..2004.
        assert_eq!(
            buf,
            [
                1012_u32.to_le_bytes()[0],
                1013_u32.to_le_bytes()[0],
                1014_u32.to_le_bytes()[0],
                1015_u32.to_le_bytes()[0],
                2000_u32.to_le_bytes()[0],
                2001_u32.to_le_bytes()[0],
                2002_u32.to_le_bytes()[0],
                2003_u32.to_le_bytes()[0],
            ]
        );
    }

    #[test]
    fn test_read_at_sparse_zero_fills() {
        // Sparse segment 0 (0..8), real segment 1 (8..16) at disk 2000.
        let map = map_from_raw(&[(None, 8), (Some(2000), 8)]);
        let mut disk = indexed_disk(4096);

        let mut buf = [0xAAu8; 12];
        map.read_at(&mut disk, 0, &mut buf).unwrap();
        // First 8 bytes are sparse zeros.
        assert!(buf[..8].iter().all(|&b| b == 0));
        // Next 4 bytes come from disk 2000..2004.
        assert_eq!(
            buf[8..],
            [
                2000_u32.to_le_bytes()[0],
                2001_u32.to_le_bytes()[0],
                2002_u32.to_le_bytes()[0],
                2003_u32.to_le_bytes()[0]
            ]
        );
    }

    #[test]
    fn test_read_at_past_end_is_error() {
        let map = map_from_raw(&[(Some(1000), 16)]);
        let mut disk = indexed_disk(4096);

        // total_size is 16. Reading 4 bytes at offset 14 ends at 18 > 16 => error.
        let mut buf = [0u8; 4];
        assert!(map.read_at(&mut disk, 14, &mut buf).is_err());

        // Reading exactly to the end (offset 12, len 4, end 16) succeeds.
        let mut buf2 = [0u8; 4];
        assert!(map.read_at(&mut disk, 12, &mut buf2).is_ok());
    }

    #[test]
    fn test_from_data_runs_accumulates_virtual_offsets() {
        let (ntfs, _disk) = make_ntfs();
        let runs = NtfsDataRuns::new(&ntfs, DATA_RUNS, NtfsPosition::new(0x4000));
        let map = DataRunMap::from_data_runs(runs).unwrap();

        // Three runs of 1024, 1536, 512 bytes => total 3072.
        assert_eq!(map.segment_count(), 3);
        assert_eq!(map.total_size(), 3072);

        // Virtual offsets accumulate by addition (1024, then 1024+1536=2560).
        let (pos0, size0) = map.segment(0).unwrap();
        assert_eq!(size0, 1024);
        assert_eq!(pos0.value().unwrap().get(), 2560);

        // Segment 1 is sparse (no disk position) and begins at virtual offset 1024.
        let (pos1, size1) = map.segment(1).unwrap();
        assert_eq!(size1, 1536);
        assert!(pos1.value().is_none());
        assert_eq!(map.resolve_index(1024).unwrap(), (1, 0));

        // Segment 2 begins at virtual offset 2560.
        let (_pos2, size2) = map.segment(2).unwrap();
        assert_eq!(size2, 512);
        assert_eq!(map.resolve_index(2560).unwrap(), (2, 0));
    }

    #[test]
    fn test_extend_data_runs_appends_after_existing() {
        let (ntfs, _disk) = make_ntfs();
        let runs = NtfsDataRuns::new(&ntfs, DATA_RUNS, NtfsPosition::new(0x4000));
        let mut map = DataRunMap::from_data_runs(runs).unwrap();
        assert_eq!(map.total_size(), 3072);

        // Extend with the same runs again. New segments must be appended starting
        // at virtual offset 3072 (the previous total_size), accumulating onward.
        let more = NtfsDataRuns::new(&ntfs, DATA_RUNS, NtfsPosition::new(0x4000));
        map.extend_data_runs(more).unwrap();

        assert_eq!(map.segment_count(), 6);
        assert_eq!(map.total_size(), 6144);
        // The first appended segment starts at virtual offset 3072.
        assert_eq!(map.resolve_index(3072).unwrap(), (3, 0));
        // The second appended segment (1536 bytes later) starts at 3072+1024=4096.
        assert_eq!(map.resolve_index(4096).unwrap(), (4, 0));
    }

    /// Synthetic NTFS boot sector with cluster size 512, as in
    /// `attribute_value::non_resident::tests`.
    fn synthetic_boot_sector() -> [u8; 512] {
        let mut buf = [0u8; 512];
        buf[0] = 0xEB;
        buf[1] = 0x52;
        buf[2] = 0x90;
        buf[3..11].copy_from_slice(b"NTFS    ");
        buf[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        buf[0x0D] = 1;
        buf[0x28..0x30].copy_from_slice(&0x0010_0000u64.to_le_bytes());
        buf[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
        buf[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
        buf[0x40] = (-10i8).cast_unsigned();
        buf[0x44] = (-12i8).cast_unsigned();
        buf[510] = 0x55;
        buf[511] = 0xAA;
        buf
    }

    fn make_ntfs() -> (crate::ntfs::Ntfs, Cursor<Vec<u8>>) {
        let mut disk = vec![0u8; 4096];
        disk[..512].copy_from_slice(&synthetic_boot_sector());
        let mut cursor = Cursor::new(disk);
        let ntfs = crate::ntfs::Ntfs::new(&mut cursor).unwrap();
        (ntfs, cursor)
    }

    /// Same encoding as `attribute_value::non_resident::tests::DATA_RUNS`:
    /// real(1024B @ 2560), sparse(1536B), real(512B @ 3584), terminator.
    const DATA_RUNS: &[u8] = &[0x21, 0x02, 0x05, 0x00, 0x01, 0x03, 0x11, 0x01, 0x02, 0x00];
}
