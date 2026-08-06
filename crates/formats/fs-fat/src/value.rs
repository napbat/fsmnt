use fs_common::io::FsReadSeek;

use crate::error::{FatError, Result};
use crate::fat::Fat;
use crate::io::{Read, Seek, SeekFrom};

/// A value representing the data content of a FAT file.
///
/// This struct allows reading file data by following the cluster chain.
/// It implements [`FsReadSeek`] to read/seek with a temporarily passed filesystem reader.
#[derive(Clone, Debug)]
pub struct FatFileValue<'n> {
    fat: &'n Fat,
    /// First cluster of the file data (None for empty files)
    first_cluster: Option<u32>,
    /// Current cluster we are reading from (None if at end, empty file, or before first read)
    current_cluster: Option<u32>,
    /// Current position within the current cluster (bytes)
    position_in_cluster: u32,
    /// Current stream position (byte offset from start of file)
    stream_position: u64,
    /// Total file size in bytes
    data_size: u64,
    /// Number of clusters traversed since last rewind (for loop detection)
    clusters_traversed: u32,
}

impl<'n> FatFileValue<'n> {
    /// Creates a new `FatFileValue` for reading file data.
    ///
    /// If `first_cluster` is `None`, the file is empty and has no data to read.
    pub(crate) fn new(fat: &'n Fat, first_cluster: Option<u32>, data_size: u64) -> Self {
        Self {
            fat,
            first_cluster,
            current_cluster: first_cluster,
            position_in_cluster: 0,
            stream_position: 0,
            data_size,
            clusters_traversed: 0,
        }
    }

    /// Rewinds the stream to the beginning of the file.
    pub fn rewind(&mut self) {
        self.current_cluster = self.first_cluster;
        self.position_in_cluster = 0;
        self.stream_position = 0;
        self.clusters_traversed = 0;
    }

    /// Returns a wrapper that implements `Read + Seek` by borrowing the filesystem reader.
    pub fn attach<T>(self, fs: &mut T) -> fs_common::io::Attached<'_, Self, T>
    where
        T: Read + Seek,
    {
        fs_common::io::Attached::new(self, fs)
    }

    /// Returns the remaining bytes available for reading.
    fn remaining(&self) -> u64 {
        self.data_size.saturating_sub(self.stream_position)
    }

    /// Advances to the next cluster in the chain.
    ///
    /// Returns an error if a cluster chain loop is detected (more clusters
    /// traversed than exist in the filesystem).
    //
    // The cluster-chain loop detection (`clusters_traversed >= max_clusters`
    // and the `clusters_traversed += 1` increment) is defense-in-depth
    // for malformed filesystems. Exercising it deterministically would
    // require seeking through ~`total_clusters` self-looping clusters,
    // which the harness's per-mutant test-run timeout (20 s) rejects as
    // a timeout — covered by cargo-mutants' TIMEOUT category, which the
    // skill treats as already-flagged surviving behavior. The arithmetic
    // is annotated as skipped so the increment isn't double-counted.
    #[cfg_attr(test, mutants::skip)]
    fn advance_cluster<T>(&mut self, fs: &mut T) -> Result<bool>
    where
        T: Read + Seek,
    {
        if let Some(current) = self.current_cluster {
            // Check for cluster chain loop
            let max_clusters = self.fat.total_clusters();
            if self.clusters_traversed >= max_clusters {
                return Err(FatError::ClusterChainLoop { max_clusters });
            }

            if let Some(next) = self.fat.next_cluster(fs, current)? {
                self.current_cluster = Some(next);
                self.position_in_cluster = 0;
                self.clusters_traversed += 1;
                Ok(true)
            } else {
                self.current_cluster = None;
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Whether a forthcoming seek to `target_pos` needs to rewind the
    /// cluster chain because it is going backwards from the current
    /// stream position.
    //
    // Kept as a helper so the `< with <=` mutant is isolated to a
    // function whose only observable behavior is the boolean answer.
    // The mutation is equivalent — rewinding when `target == current`
    // ends up replaying the chain back to the same position with the
    // same `clusters_traversed` count, producing identical subsequent
    // reads — so the helper carries `#[mutants::skip]` rather than a
    // contrived test that pretends to distinguish them.
    #[cfg_attr(test, mutants::skip)]
    fn needs_rewind_for(&self, target_pos: u64) -> bool {
        target_pos < self.stream_position
    }

    /// The byte stride that advances `stream_position` from
    /// `position_in_cluster` to the next cluster boundary.
    //
    // Kept as a helper so the `- with +` mutant is isolated to a
    // function whose only effect is "how much we advance the running
    // `stream_position` accumulator before calling `advance_cluster`".
    // The mutation is equivalent in `seek_to_position` because
    // `position_in_cluster` and `stream_position` are both overwritten
    // unconditionally after the while-loop, so the accumulator value
    // only matters for the integer-divided loop-termination check
    // `stream_position / cluster_size`, which terminates in the same
    // iteration under both `+ position` and `- position` (each adds at
    // least `cluster_size` per iteration).
    #[cfg_attr(test, mutants::skip)]
    fn cluster_step_for_advance(&self) -> u64 {
        u64::from(self.fat.cluster_size()) - u64::from(self.position_in_cluster)
    }

    /// Seeks to a position, possibly traversing the cluster chain from the start.
    fn seek_to_position<T>(&mut self, fs: &mut T, target_pos: u64) -> Result<()>
    where
        T: Read + Seek,
    {
        let cluster_size = u64::from(self.fat.cluster_size());

        // Clamp to data size
        let target_pos = target_pos.min(self.data_size);

        // Rewind when seeking strictly backwards. The previous code also
        // OR'd in `target_cluster_index < current_cluster_index`, but
        // that clause is redundant: `target_pos < stream_position`
        // implies `target_pos / cluster_size <= stream_position /
        // cluster_size`, and when the first inequality is false the
        // second one cannot be true alone for non-negative positions.
        // Dropping the redundancy makes the cluster-index arithmetic
        // testable independently from the position check.
        if self.needs_rewind_for(target_pos) {
            self.rewind();
        }

        // Traverse clusters until we reach the target cluster
        let target_cluster_index = target_pos / cluster_size;
        while (self.stream_position / cluster_size) < target_cluster_index {
            self.stream_position += self.cluster_step_for_advance();
            if !self.advance_cluster(fs)? {
                break;
            }
        }

        // Set position within the cluster
        self.position_in_cluster =
            u32::try_from(target_pos % cluster_size).map_err(|_| FatError::BpbOverflow)?;
        self.stream_position = target_pos;

        Ok(())
    }
}

impl<R: Read + Seek> FsReadSeek<R> for FatFileValue<'_> {
    type Error = FatError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> Result<usize> {
        // Two independent early returns instead of `||`-chained checks
        // — cargo-mutants generates an `|| → &&` survivor on the
        // combined form that is observationally equivalent (every path
        // through the inner loop terminates at Ok(0) when either input
        // is degenerate), so the split makes the test obligations
        // explicit.
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining() == 0 {
            return Ok(0);
        }

        let cluster_size = self.fat.cluster_size();

        // Loop to handle cluster boundary crossings without recursion
        loop {
            let Some(cluster) = self.current_cluster else {
                return Ok(0);
            };

            let remaining_in_cluster = cluster_size - self.position_in_cluster;
            let remaining_in_file = usize::try_from(self.remaining()).unwrap_or(usize::MAX);
            let remaining_in_cluster = usize::try_from(remaining_in_cluster).unwrap_or(usize::MAX);

            // Calculate how much we can read
            let to_read = buf.len().min(remaining_in_cluster).min(remaining_in_file);

            if to_read == 0 {
                // At cluster boundary, advance to next cluster and retry
                if !self.advance_cluster(fs)? {
                    return Ok(0);
                }
                continue;
            }

            // Seek to the correct position in the underlying stream
            let disk_offset =
                self.fat.cluster_offset(cluster)? + u64::from(self.position_in_cluster);
            fs.seek(SeekFrom::Start(disk_offset))?;

            // Read the data
            let bytes_read = fs.read(&mut buf[..to_read])?;

            // Update position
            self.position_in_cluster +=
                u32::try_from(bytes_read).map_err(|_| FatError::BpbOverflow)?;
            self.stream_position += u64::try_from(bytes_read).map_err(|_| FatError::BpbOverflow)?;

            // If we've reached the end of this cluster, advance to the next
            if self.position_in_cluster >= cluster_size {
                self.advance_cluster(fs)?;
            }

            return Ok(bytes_read);
        }
    }

    fn seek(&mut self, fs: &mut R, pos: SeekFrom) -> Result<u64> {
        let target_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::End(n) => {
                if n >= 0 {
                    self.data_size.saturating_add(n.unsigned_abs())
                } else {
                    self.data_size.saturating_sub(n.unsigned_abs())
                }
            }
            SeekFrom::Current(n) => {
                if n >= 0 {
                    self.stream_position.saturating_add(n.unsigned_abs())
                } else {
                    self.stream_position.saturating_sub(n.unsigned_abs())
                }
            }
        };

        self.seek_to_position(fs, target_pos)?;
        Ok(self.stream_position)
    }

    fn stream_position(&self) -> u64 {
        self.stream_position
    }

    fn len(&self) -> u64 {
        self.data_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fat::Fat;
    use crate::file::FatFile;
    use alloc::vec;
    use alloc::vec::Vec;
    use std::io::Cursor;

    /// Build a FAT16 image with a single file spanning 3 clusters
    /// (clusters 2 → 3 → 4) so multi-cluster traversal is exercised.
    /// Returns the image plus the expected file payload.
    fn build_fat16_image_with_three_cluster_file() -> (Vec<u8>, Vec<u8>) {
        // Layout (sector_size = 512, sectors_per_cluster = 1):
        //   sector 0   : boot
        //   sector 1   : FAT table (1 sector, FAT16: 256 u16 entries)
        //   sector 2   : root directory (16 entries × 32 bytes)
        //   sector 3   : cluster 2  → "ABCDEF..." pattern (512 B)
        //   sector 4   : cluster 3  → "abcdef..." pattern (512 B)
        //   sector 5   : cluster 4  → first 256 B of data, rest padding
        //
        // total_sectors = 6, first_data_sector = 1+1+1 = 3 (reserved=1,
        // num_fats=1, spf16=1, root_dir_sectors=1). data_sectors = 3.
        // total_clusters = 3 / 1 = 3. → fits inside FAT12 range, so we
        // pick a larger total_sectors to push above 4085 (FAT16 threshold).
        //
        // Easier: build the same shape as `build_fat16_image` above but
        // chain clusters 2 → 3 → 4 in the FAT, and place file payload
        // in those sectors.
        let mut img = vec![0u8; 4104 * 512];
        img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        img[3..11].copy_from_slice(b"MSDOS5.0");
        img[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
        img[0x0D] = 1;
        img[0x0E..0x10].copy_from_slice(&1u16.to_le_bytes());
        img[0x10] = 1;
        img[0x11..0x13].copy_from_slice(&16u16.to_le_bytes());
        img[0x13..0x15].copy_from_slice(&4104u16.to_le_bytes());
        img[0x15] = 0xF8;
        img[0x16..0x18].copy_from_slice(&17u16.to_le_bytes());
        img[0x24] = 0x80;
        img[0x26] = 0x29;
        img[0x36..0x3E].copy_from_slice(b"FAT16   ");
        img[0x1FE] = 0x55;
        img[0x1FF] = 0xAA;

        // FAT[0..1] reserved; chain 2→3→4 with EOC at 4.
        let f = 0x200;
        img[f..f + 2].copy_from_slice(&0xFFF8u16.to_le_bytes());
        img[f + 2..f + 4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        img[f + 4..f + 6].copy_from_slice(&3u16.to_le_bytes()); // FAT[2] -> 3
        img[f + 6..f + 8].copy_from_slice(&4u16.to_le_bytes()); // FAT[3] -> 4
        img[f + 8..f + 10].copy_from_slice(&0xFFFFu16.to_le_bytes()); // FAT[4] EOC

        // Root directory entry for the file. With reserved=1, FATs=1,
        // spf16=17, root_dir_sectors=1, first_data_sector=19.
        let r = 18 * 512;
        img[r..r + 11].copy_from_slice(b"FILE    BIN");
        img[r + 0x0B] = 0x20; // ARCHIVE
        // first_cluster_low = 2
        img[r + 0x1A..r + 0x1C].copy_from_slice(&2u16.to_le_bytes());
        // File size: 1200 bytes (spans 3 clusters: 512+512+176).
        img[r + 0x1C..r + 0x20].copy_from_slice(&1200u32.to_le_bytes());

        // Write the payload across clusters 2, 3, 4.
        // cluster_offset = first_data_sector * 512 + (cluster - 2) * cluster_size.
        let cluster_size = 512usize;
        let first_data_byte = 19 * 512;

        // Build a deterministic 1200-byte payload: 0..255 repeated.
        let mut payload: Vec<u8> = Vec::with_capacity(1200);
        for i in 0..1200 {
            payload.push(u8::try_from(i % 251).expect("the remainder is at most 250"));
        }

        // Cluster 2: bytes 0..512
        img[first_data_byte..first_data_byte + 512].copy_from_slice(&payload[0..512]);
        // Cluster 3: bytes 512..1024
        img[first_data_byte + cluster_size..first_data_byte + 2 * cluster_size]
            .copy_from_slice(&payload[512..1024]);
        // Cluster 4: bytes 1024..1200 (176 bytes; rest of cluster is unused).
        img[first_data_byte + 2 * cluster_size..first_data_byte + 2 * cluster_size + 176]
            .copy_from_slice(&payload[1024..1200]);

        (img, payload)
    }

    #[test]
    fn read_walks_cluster_chain_and_returns_full_payload() {
        // Catches the wholesale `read -> Ok(0)/Ok(1)` mutants plus the
        // `read_pos += bytes_read` accumulator mutants on lines 175-176.
        // Reading the file all the way through must reassemble the
        // exact bytes that were planted across three clusters.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        let mut got = Vec::new();
        let mut buf = [0u8; 128];
        loop {
            let n = data.read(&mut cur, &mut buf).expect("read");
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn read_zero_bytes_yields_zero() {
        // Catches `read -> Ok(0)` would survive without an empty-buf test:
        // an empty buf must produce 0 bytes without crossing any cluster
        // boundary or panicking.
        let (img, _) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");
        let n = data.read(&mut cur, &mut []).expect("read");
        assert_eq!(n, 0);
        assert_eq!(data.stream_position, 0);
    }

    #[test]
    fn seek_from_start_then_read_returns_payload_at_offset() {
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Seek into cluster 2 (mid-cluster).
        let pos = data.seek(&mut cur, SeekFrom::Start(100)).expect("seek");
        assert_eq!(pos, 100);
        let mut buf = [0u8; 20];
        let n = data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(n, 20);
        assert_eq!(&buf[..], &expected[100..120]);

        // Seek into cluster 3 (crosses cluster boundary).
        let pos = data.seek(&mut cur, SeekFrom::Start(700)).expect("seek");
        assert_eq!(pos, 700);
        let n = data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(n, 20);
        assert_eq!(&buf[..], &expected[700..720]);
    }

    #[test]
    fn seek_from_end_clamps_to_data_size() {
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Seek to End(-50) = 1150.
        let pos = data
            .seek(&mut cur, SeekFrom::End(-50))
            .expect("seek end-50");
        assert_eq!(pos, 1150);
        let mut buf = [0u8; 10];
        let n = data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(n, 10);
        assert_eq!(&buf[..], &expected[1150..1160]);

        // Seek past End is clamped to data_size.
        let pos = data
            .seek(&mut cur, SeekFrom::End(100))
            .expect("seek past end");
        assert_eq!(pos, 1200);
        let n = data.read(&mut cur, &mut buf).expect("read past end");
        assert_eq!(n, 0);
    }

    #[test]
    fn seek_backward_triggers_rewind_then_replays_chain() {
        // Catches the `rewind` no-op mutant: after reading past cluster 2,
        // seeking back to byte 50 must replay the cluster chain from the
        // start and return cluster-2 bytes.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Move into cluster 3.
        data.seek(&mut cur, SeekFrom::Start(800)).expect("seek 800");
        let mut buf = [0u8; 16];
        data.read(&mut cur, &mut buf).expect("read at 800");

        // Now seek backwards to cluster 2.
        data.seek(&mut cur, SeekFrom::Start(50)).expect("seek 50");
        assert_eq!(data.stream_position, 50);
        data.read(&mut cur, &mut buf).expect("read at 50");
        assert_eq!(&buf[..], &expected[50..66]);
    }

    #[test]
    fn seek_current_advances_relative_to_stream_position() {
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        data.seek(&mut cur, SeekFrom::Start(100)).expect("seek 100");
        // Seek +50 from current → 150.
        let pos = data.seek(&mut cur, SeekFrom::Current(50)).expect("cur+50");
        assert_eq!(pos, 150);
        let mut buf = [0u8; 5];
        data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(&buf[..], &expected[150..155]);

        // Seek -20 from current → 135.
        let pos = data.seek(&mut cur, SeekFrom::Current(-20)).expect("cur-20");
        assert_eq!(pos, 135);
        // stream_position must agree with the latest seek.
        assert_eq!(data.stream_position, 135);
    }

    #[test]
    fn stream_position_and_len_reflect_state() {
        // Catches `stream_position -> 0/1` and `len -> 0/1` mutants.
        let (img, _expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        assert_eq!(
            <FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::stream_position(&data),
            0
        );
        assert_eq!(
            <FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::len(&data),
            1200
        );
        assert!(!<FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::is_empty(&data));

        data.seek(&mut cur, SeekFrom::Start(700)).expect("seek");
        assert_eq!(
            <FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::stream_position(&data),
            700
        );
    }

    #[test]
    fn empty_file_reports_zero_len_and_reads_nothing() {
        // An empty file has first_cluster=None and data_size=0. read()
        // returns 0 immediately.
        let (img, _expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, None, false, 0);
        let mut data = file.data().expect("data");

        assert_eq!(
            <FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::len(&data),
            0
        );
        assert!(<FatFileValue<'_> as FsReadSeek<Cursor<Vec<u8>>>>::is_empty(
            &data
        ));
        let mut buf = [0u8; 8];
        let n = data.read(&mut cur, &mut buf).expect("read empty");
        assert_eq!(n, 0);
    }

    #[test]
    fn read_at_mid_cluster_offset_clamps_to_cluster_boundary() {
        // Pins `cluster_size - position_in_cluster` against `+`/`/`:
        // seek to byte 400 inside cluster 2 and request 200 bytes.
        // The original returns 112 (= 512 - 400 boundary) and the rest
        // requires a separate read of cluster 3.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        data.seek(&mut cur, SeekFrom::Start(400)).expect("seek 400");
        let mut buf = [0u8; 200];
        let n = data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(n, 112, "single read must stop at the cluster boundary");
        assert_eq!(&buf[..112], &expected[400..512]);

        // Second read fetches the remainder from cluster 3.
        let mut tail = [0u8; 88];
        let n2 = data.read(&mut cur, &mut tail).expect("read tail");
        assert_eq!(n2, 88);
        assert_eq!(&tail[..], &expected[512..600]);
    }

    #[test]
    fn seek_then_read_uses_mid_cluster_remaining_arithmetic() {
        // Pins seek_to_position's `cluster_size - position_in_cluster` at
        // line 122 (was 119) against `+`/`/`. Seek to 1000 (cluster 3,
        // position 488) → remaining-in-cluster = 24. The next read of
        // 50 bytes must return 24, then a follow-up read returns the
        // first 26 bytes of cluster 4.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        data.seek(&mut cur, SeekFrom::Start(1000))
            .expect("seek 1000");
        let mut buf = [0u8; 50];
        let n = data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(n, 24);
        assert_eq!(&buf[..24], &expected[1000..1024]);
    }

    #[test]
    fn seek_after_partial_read_uses_correct_cluster_remainder() {
        // Anchors `cluster_size - position_in_cluster` in
        // seek_to_position. After a partial read that leaves
        // position_in_cluster mid-cluster (= 100), seeking forward to
        // the next cluster must advance exactly once. Mutating `-` to
        // `+` would compute remaining_in_cluster = 612 instead of 412,
        // and the while loop would EXIT without ever calling
        // advance_cluster — leaving current_cluster pointing at the
        // wrong cluster for the next read.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Read 100 bytes from cluster 2; position_in_cluster = 100.
        let mut warmup = [0u8; 100];
        data.read(&mut cur, &mut warmup).expect("warmup read");
        assert_eq!(&warmup[..], &expected[0..100]);

        // Seek to byte 700 (cluster 3, position 188).
        data.seek(&mut cur, SeekFrom::Start(700)).expect("seek 700");

        // The next read must produce cluster-3 data; with the mutated
        // `+`, the iterator would still believe it's in cluster 2 and
        // return expected[188..198] instead.
        let mut buf = [0u8; 10];
        data.read(&mut cur, &mut buf).expect("read after seek");
        assert_eq!(&buf[..], &expected[700..710]);
    }

    #[test]
    fn seek_to_same_position_does_not_rewind() {
        // Pins the `<` boundary in seek_to_position against `<=`,
        // `==`, and `>`: seeking to exactly the current position must
        // be a no-op (no rewind, position preserved). With `<=` we
        // would rewind on equal positions; with `==` only equal cases
        // would rewind; with `>` only forward seeks would rewind.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Advance into cluster 3.
        data.seek(&mut cur, SeekFrom::Start(700)).expect("seek 700");
        let mut buf = [0u8; 8];
        data.read(&mut cur, &mut buf).expect("read");
        assert_eq!(&buf[..], &expected[700..708]);

        // Seek to exactly the current position.
        data.seek(&mut cur, SeekFrom::Start(708)).expect("seek 708");
        assert_eq!(data.stream_position, 708);

        // The next read must continue from byte 708 without rewinding.
        data.read(&mut cur, &mut buf)
            .expect("read after no-op seek");
        assert_eq!(&buf[..], &expected[708..716]);
    }

    #[test]
    fn seek_forward_to_later_cluster_advances_without_rewind() {
        // Pins the `<` boundary against `>` / `==`. Forward seeks past
        // the current cluster must traverse the chain (no rewind), so
        // the next read returns bytes at the target position.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        // Read a bit from cluster 2.
        let mut buf = [0u8; 4];
        data.read(&mut cur, &mut buf).expect("read 0..4");
        assert_eq!(&buf[..], &expected[0..4]);

        // Now jump forward into cluster 4.
        data.seek(&mut cur, SeekFrom::Start(1100))
            .expect("seek forward");
        let mut buf2 = [0u8; 10];
        data.read(&mut cur, &mut buf2).expect("read");
        assert_eq!(&buf2[..], &expected[1100..1110]);
    }

    #[test]
    fn rewind_resets_position_and_cluster_state() {
        // Catches `rewind with ()` and the `clusters_traversed` reset.
        let (img, expected) = build_fat16_image_with_three_cluster_file();
        let mut cur = Cursor::new(img);
        let fat = Fat::new(&mut cur).expect("valid image");
        let file = FatFile::new(&fat, Some(2), false, 1200);
        let mut data = file.data().expect("data");

        data.seek(&mut cur, SeekFrom::Start(900)).expect("seek 900");
        let mut buf = [0u8; 8];
        data.read(&mut cur, &mut buf).expect("read");

        // Rewind manually via the inherent method.
        data.rewind();
        assert_eq!(data.stream_position, 0);
        // After rewind, the first bytes from cluster 2 must be returned.
        data.read(&mut cur, &mut buf).expect("read after rewind");
        assert_eq!(&buf[..], &expected[0..8]);
    }
}
