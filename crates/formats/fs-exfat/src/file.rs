//! File data reader for exFAT.
//!
//! [`ExFatFile`] provides seekable, read-only access to a file's data
//! stream. It supports both FAT-chained and contiguous (`NoFatChain`)
//! cluster layouts.

use alloc::vec::Vec;

use crate::error::{ExFatError, Result};
use crate::exfat::ExFat;
use crate::io::{Read, Seek, SeekFrom};
use fs_common::FsReadSeek;

/// Read-only handle to an exFAT file's data stream.
///
/// Created via [`ExFat::open_file`] or from an [`ExFatEntrySet`].
/// Implements [`FsReadSeek`] for streaming reads with a
/// temporarily borrowed filesystem reader.
///
/// # Cluster layout modes
///
/// - **FAT-chained** (default): clusters are linked via the FAT.
///   The full chain is resolved at construction time for O(1) seek.
/// - **Contiguous** (`NoFatChain` flag): clusters are laid out
///   sequentially from `first_cluster`. No FAT lookups needed.
#[derive(Debug, Clone)]
pub struct ExFatFile<'e> {
    exfat: &'e ExFat,
    first_cluster: u32,
    data_length: u64,
    position: u64,
    contiguous: bool,
    /// Pre-resolved cluster chain (FAT-chained mode only).
    /// Empty when `contiguous` is true.
    cluster_chain: Vec<u32>,
}

impl<'e> ExFatFile<'e> {
    /// Creates a file handle from its stream metadata.
    ///
    /// For FAT-chained files, resolves the full cluster chain
    /// upfront by walking the FAT. For contiguous files, no FAT
    /// access is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the FAT chain cannot be read, contains an
    /// invalid cluster, or is shorter than `data_length` requires.
    pub fn new<T>(
        exfat: &'e ExFat,
        fs: &mut T,
        first_cluster: u32,
        data_length: u64,
        contiguous: bool,
    ) -> Result<Self>
    where
        T: Read + Seek,
    {
        let cluster_chain = if contiguous || data_length == 0 {
            Vec::new()
        } else {
            let mut chain = Vec::new();
            let mut iter = exfat.cluster_iter(first_cluster);
            while let Some(result) = iter.next(fs) {
                chain.push(result?);
            }

            // Validate chain covers the declared data length
            let cluster_size = u64::from(exfat.cluster_size());
            let clusters_needed = data_length.saturating_add(cluster_size - 1) / cluster_size;
            if u64::try_from(chain.len()).unwrap_or(u64::MAX) < clusters_needed {
                return Err(ExFatError::InvalidEntrySet {
                    reason: "FAT chain too short for declared data length",
                    byte_offset: 0,
                });
            }

            chain
        };

        Ok(Self {
            exfat,
            first_cluster,
            data_length,
            position: 0,
            contiguous,
            cluster_chain,
        })
    }

    /// Returns the cluster number containing the given byte offset.
    fn cluster_at_offset(&self, offset: u64) -> Result<u32> {
        let cluster_size = u64::from(self.exfat.cluster_size());
        let cluster_index =
            usize::try_from(offset / cluster_size).map_err(|_| ExFatError::InvalidEntrySet {
                reason: "file offset exceeds addressable memory",
                byte_offset: offset,
            })?;

        if self.contiguous {
            let idx = u32::try_from(cluster_index).map_err(|_| ExFatError::InvalidCluster {
                cluster: self.first_cluster,
            })?;
            let cluster = self
                .first_cluster
                .checked_add(idx)
                .ok_or(ExFatError::InvalidCluster { cluster: u32::MAX })?;
            Ok(cluster)
        } else {
            self.cluster_chain
                .get(cluster_index)
                .copied()
                .ok_or(ExFatError::InvalidCluster {
                    cluster: self.first_cluster,
                })
        }
    }

    /// Logical position within this file's data stream.
    #[must_use]
    pub fn stream_position(&self) -> u64 {
        self.position
    }

    /// Total length of the file data in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.data_length
    }

    /// Returns `true` if the file has zero data length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data_length == 0
    }
}

impl<R: Read + Seek> FsReadSeek<R> for ExFatFile<'_> {
    type Error = ExFatError;

    fn read(&mut self, fs: &mut R, buf: &mut [u8]) -> core::result::Result<usize, ExFatError> {
        if self.position >= self.data_length || buf.is_empty() {
            return Ok(0);
        }

        let remaining = usize::try_from(self.data_length - self.position).unwrap_or(usize::MAX);
        let to_read = remaining.min(buf.len());

        let cluster_size = u64::from(self.exfat.cluster_size());
        let mut bytes_read = 0usize;

        while bytes_read < to_read {
            let cluster = self.cluster_at_offset(self.position)?;
            let offset_in_cluster = self.position % cluster_size;
            let cluster_remaining =
                usize::try_from(cluster_size - offset_in_cluster).map_err(|_| {
                    ExFatError::InvalidEntrySet {
                        reason: "cluster size exceeds addressable memory",
                        byte_offset: self.position,
                    }
                })?;
            let chunk = (to_read - bytes_read).min(cluster_remaining);

            let disk_offset = self.exfat.cluster_offset(cluster)? + offset_in_cluster;
            fs.seek(SeekFrom::Start(disk_offset))?;
            fs.read_exact(&mut buf[bytes_read..bytes_read + chunk])?;

            bytes_read += chunk;
            self.position += u64::try_from(chunk).map_err(|_| ExFatError::InvalidEntrySet {
                reason: "read length exceeds the supported range",
                byte_offset: self.position,
            })?;
        }

        Ok(bytes_read)
    }

    fn seek(&mut self, _fs: &mut R, pos: SeekFrom) -> core::result::Result<u64, ExFatError> {
        let invalid = || {
            // `io::Error::new(kind, msg)` is std-only; the `no_std` shim's
            // `io::Error` is a message-less `IoError`. `From<ErrorKind>` is
            // implemented for both, so this builds either way.
            ExFatError::Io(crate::io::ErrorKind::InvalidInput.into())
        };

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    self.data_length
                        .checked_add(offset.unsigned_abs())
                        .ok_or_else(invalid)?
                } else {
                    self.data_length
                        .checked_sub(offset.unsigned_abs())
                        .ok_or_else(invalid)?
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    self.position
                        .checked_add(offset.unsigned_abs())
                        .ok_or_else(invalid)?
                } else {
                    self.position
                        .checked_sub(offset.unsigned_abs())
                        .ok_or_else(invalid)?
                }
            }
        };

        self.position = new_pos;
        Ok(self.position)
    }

    fn stream_position(&self) -> u64 {
        self.position
    }

    fn len(&self) -> u64 {
        self.data_length
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use alloc::vec;
    use std::io::Cursor;

    #[test]
    fn read_contiguous_file() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        // Write file data in clusters 5 and 6 (contiguous)
        let data_off = cluster_heap_offset(5);
        for i in 0..1024 {
            image[data_off + i] = u8::try_from(i % 256).expect("the remainder fits in one byte");
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 1024, true).unwrap();

        assert_eq!(file.len(), 1024);
        assert_eq!(file.stream_position(), 0);

        let mut buf = vec![0u8; 1024];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 1024);

        for (i, &byte) in buf.iter().enumerate() {
            assert_eq!(
                byte,
                u8::try_from(i % 256).expect("the remainder fits in one byte"),
                "mismatch at byte {i}"
            );
        }

        assert_eq!(file.stream_position(), 1024);
        // Reading past end returns 0
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_fat_chained_file() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        // Cluster chain: 5 -> 8 -> 3 -> EOC (non-contiguous)
        set_fat_entry(&mut image, 5, 8);
        set_fat_entry(&mut image, 8, 3);
        set_fat_entry(&mut image, 3, 0xFFFF_FFFF);

        // Write data: cluster 5 = 0xAA, cluster 8 = 0xBB, cluster 3 = 0xCC
        let off5 = cluster_heap_offset(5);
        for b in &mut image[off5..off5 + BPS] {
            *b = 0xAA;
        }
        let off8 = cluster_heap_offset(8);
        for b in &mut image[off8..off8 + BPS] {
            *b = 0xBB;
        }
        let off3 = cluster_heap_offset(3);
        for b in &mut image[off3..off3 + BPS] {
            *b = 0xCC;
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // File is 1200 bytes across 3 clusters (512 each)
        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 1200, false).unwrap();

        let mut buf = vec![0u8; 1200];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 1200);

        // First 512 bytes from cluster 5
        assert!(buf[..512].iter().all(|&b| b == 0xAA));
        // Next 512 from cluster 8
        assert!(buf[512..1024].iter().all(|&b| b == 0xBB));
        // Last 176 from cluster 3
        assert!(buf[1024..1200].iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn seek_and_read() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        // Write recognizable data in cluster 5
        let off = cluster_heap_offset(5);
        for i in 0..BPS {
            image[off + i] = u8::try_from(i % 256).expect("the remainder fits in one byte");
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(
            &exfat,
            &mut cursor,
            5,
            u64::try_from(BPS).expect("BPS fits u64"),
            true,
        )
        .unwrap();

        // Seek to offset 100
        let pos = file.seek(&mut cursor, SeekFrom::Start(100)).unwrap();
        assert_eq!(pos, 100);
        assert_eq!(file.stream_position(), 100);

        let mut buf = [0u8; 4];
        file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(buf, [100, 101, 102, 103]);

        // Seek relative
        file.seek(&mut cursor, SeekFrom::Current(-4)).unwrap();
        assert_eq!(file.stream_position(), 100);

        // Seek from end
        file.seek(&mut cursor, SeekFrom::End(-10)).unwrap();
        assert_eq!(
            file.stream_position(),
            u64::try_from(BPS).expect("BPS fits u64") - 10
        );
    }

    #[test]
    fn seek_negative_returns_error() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 100, true).unwrap();

        let result = file.seek(&mut cursor, SeekFrom::Current(-1));
        assert!(result.is_err());
    }

    #[test]
    fn read_empty_file() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(&exfat, &mut cursor, 0, 0, true).unwrap();

        assert_eq!(file.len(), 0);
        assert!(file.is_empty());

        let mut buf = [0u8; 10];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_crosses_cluster_boundary() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        // Contiguous clusters 5, 6
        let off5 = cluster_heap_offset(5);
        for b in &mut image[off5..off5 + BPS] {
            *b = 0x11;
        }
        let off6 = cluster_heap_offset(6);
        for b in &mut image[off6..off6 + BPS] {
            *b = 0x22;
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(
            &exfat,
            &mut cursor,
            5,
            u64::try_from(2 * BPS).expect("test length fits u64"),
            true,
        )
        .unwrap();

        // Seek to 500 (12 bytes before cluster boundary at 512)
        file.seek(&mut cursor, SeekFrom::Start(500)).unwrap();

        let mut buf = [0u8; 24];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 24);

        // First 12 bytes from cluster 5 (0x11)
        assert!(buf[..12].iter().all(|&b| b == 0x11));
        // Next 12 bytes from cluster 6 (0x22)
        assert!(buf[12..24].iter().all(|&b| b == 0x22));
    }

    #[test]
    fn partial_read_at_end_of_file() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let off = cluster_heap_offset(5);
        for i in 0..BPS {
            image[off + i] = 0xFF;
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // File is 100 bytes, not a full cluster
        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 100, true).unwrap();

        // Try to read 200 bytes — should only get 100
        let mut buf = vec![0u8; 200];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 100);
        assert!(buf[..100].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn seek_past_eof_then_read_returns_zero() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 100, true).unwrap();

        // Seek past end
        let pos = file.seek(&mut cursor, SeekFrom::Start(200)).unwrap();
        assert_eq!(pos, 200);

        // Read should return 0 bytes (past EOF)
        let mut buf = [0u8; 10];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    /// A non-empty file must report `is_empty() == false`. Default
    /// `read_empty_file` only covers the 0-length case, leaving
    /// the `→ true` accessor mutation alive.
    #[test]
    fn is_empty_returns_false_for_non_zero_length() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let file = ExFatFile::new(&exfat, &mut cursor, 5, 1, true).unwrap();
        assert!(!file.is_empty());
        assert_eq!(file.len(), 1);
    }

    /// After seeking partway in, a `read` larger than the remaining
    /// bytes must cap at `data_length - position`. Mutating `-` to
    /// `+` would inflate the cap to `data_length + position`,
    /// returning more bytes than the file holds.
    #[test]
    fn read_with_seek_caps_at_remaining_data_length() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        let off = cluster_heap_offset(5);
        for b in &mut image[off..off + BPS] {
            *b = 0xAA;
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 100, true).unwrap();

        file.seek(&mut cursor, SeekFrom::Start(60)).unwrap();
        let mut buf = vec![0u8; 200];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 40, "100 - 60 = 40 remaining bytes");
    }

    /// Within a single iteration of the inner read loop,
    /// `cluster_remaining = cluster_size - offset_in_cluster` caps
    /// the per-cluster chunk. Mutating `-` to `+` (line 143) or `%`
    /// to `+` (line 142) inflates the cap so the read pulls bytes
    /// from physically-adjacent disk space instead of following the
    /// FAT chain. A non-contiguous chain (5 -> 8) plus a seek to a
    /// non-zero offset within cluster 5 exposes the divergence.
    #[test]
    fn read_chained_seek_into_cluster_follows_chain() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        // Chain: 5 -> 8 -> EOC; cluster 6 is physically between 5
        // and 8 on disk but is *not* in the chain.
        set_fat_entry(&mut image, 5, 8);
        set_fat_entry(&mut image, 8, 0xFFFF_FFFF);

        let off5 = cluster_heap_offset(5);
        for b in &mut image[off5..off5 + BPS] {
            *b = 0xAA;
        }
        // Cluster 6 holds a different byte to expose disk reads
        // that follow physical layout instead of the FAT chain.
        let off6 = cluster_heap_offset(6);
        for b in &mut image[off6..off6 + BPS] {
            *b = 0x55;
        }
        let off8 = cluster_heap_offset(8);
        for b in &mut image[off8..off8 + BPS] {
            *b = 0xBB;
        }

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut file = ExFatFile::new(
            &exfat,
            &mut cursor,
            5,
            u64::try_from(2 * BPS).expect("test length fits u64"),
            false,
        )
        .unwrap();

        // Seek to within cluster 5 (offset 500); read across the
        // 5 -> 8 boundary. Correct chain-following read yields
        // 12 bytes of 0xAA then 38 bytes of 0xBB.
        file.seek(&mut cursor, SeekFrom::Start(500)).unwrap();
        let mut buf = [0u8; 50];
        let n = file.read(&mut cursor, &mut buf).unwrap();
        assert_eq!(n, 50);
        assert!(
            buf[..12].iter().all(|&b| b == 0xAA),
            "first 12 from cluster 5"
        );
        assert!(
            buf[12..].iter().all(|&b| b == 0xBB),
            "last 38 from cluster 8"
        );
    }

    /// When a file's `data_length` is an exact multiple of
    /// `cluster_size` and the chain is the minimum length, the
    /// read loop must terminate at `bytes_read == to_read` without
    /// stepping past the last cluster in `cluster_chain`. Mutating
    /// `< → <=` reruns the loop once with `bytes_read == to_read`,
    /// which calls `cluster_at_offset(data_length)` — beyond the
    /// chain — and errors with `InvalidCluster`.
    #[test]
    fn read_exact_cluster_size_terminates_without_extra_chain_step() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        set_fat_entry(&mut image, 5, 0xFFFF_FFFF);
        let off = cluster_heap_offset(5);
        for i in 0..BPS {
            image[off + i] = u8::try_from(i % 256).expect("the remainder fits in one byte");
        }
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut file = ExFatFile::new(
            &exfat,
            &mut cursor,
            5,
            u64::try_from(BPS).expect("BPS fits u64"),
            false,
        )
        .unwrap();

        let mut buf = vec![0u8; BPS];
        let n = file
            .read(&mut cursor, &mut buf)
            .expect("read should succeed");
        assert_eq!(n, BPS);
    }

    /// `FsReadSeek::stream_position` is a *separate* method from the
    /// inherent `stream_position`; tests that call `file.stream_position()`
    /// resolve to the inherent impl. Dispatching through the trait
    /// keeps both surfaces covered and kills `→ 0` / `→ 1` mutations
    /// on the trait impl.
    #[test]
    fn fsreadseek_trait_stream_position_returns_actual_position() {
        fn pos<R: Read + Seek, F: FsReadSeek<R>>(f: &F) -> u64 {
            f.stream_position()
        }

        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let mut file = ExFatFile::new(&exfat, &mut cursor, 5, 100, true).unwrap();
        file.seek(&mut cursor, SeekFrom::Start(42)).unwrap();
        assert_eq!(pos::<Cursor<Vec<u8>>, _>(&file), 42);
    }

    /// Same as the `stream_position` trait test but for
    /// `FsReadSeek::len`. Pins the trait impl to the actual file
    /// length so `→ 0` / `→ 1` mutations are caught.
    #[test]
    fn fsreadseek_trait_len_returns_actual_length() {
        fn len<R: Read + Seek, F: FsReadSeek<R>>(f: &F) -> u64 {
            f.len()
        }

        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();
        let file = ExFatFile::new(&exfat, &mut cursor, 5, 123, true).unwrap();
        assert_eq!(len::<Cursor<Vec<u8>>, _>(&file), 123);
    }

    #[test]
    fn truncated_fat_chain_rejected() {
        let mut image = make_image();
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);
        // Chain: 5 -> EOC (only 1 cluster = 512 bytes)
        set_fat_entry(&mut image, 5, 0xFFFF_FFFF);

        let mut cursor = Cursor::new(image);
        let exfat = ExFat::new(&mut cursor).unwrap();

        // Declare data_length = 1024 but chain only has 1 cluster (512)
        let result = ExFatFile::new(&exfat, &mut cursor, 5, 1024, false);
        assert!(result.is_err());
    }
}
