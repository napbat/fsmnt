use alloc::vec;
use alloc::vec::Vec;
use fs_common::error::IoError;

use crate::attribute::NtfsAttributeType;
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek, SeekFrom};
use crate::ntfs::Ntfs;
use crate::types::NtfsPosition;

/// Result of querying allocation status for a range of clusters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterRangeStatus {
    /// Number of clusters marked as allocated.
    pub allocated: u64,
    /// Number of clusters marked as free.
    pub free: u64,
}

/// Provides query access to the NTFS cluster allocation bitmap (`$Bitmap`, MFT entry 6).
///
/// Bit N of the bitmap is set if cluster N is allocated. This is essential for
/// forensic analysis: distinguishing live data from deleted/unallocated regions.
///
/// Created via [`Ntfs::cluster_bitmap`] or [`NtfsClusterBitmap::load`].
/// Caches one cluster of bitmap data at a time for efficient sequential queries.
#[derive(Clone, Debug)]
pub struct NtfsClusterBitmap {
    /// Physical layout of the bitmap data on disk (from data runs).
    map: DataRunMap,
    /// Total number of clusters on the volume.
    total_clusters: u64,
    /// Cluster size in bytes.
    cluster_size: u32,
    /// One cluster of cached bitmap data.
    cache: Vec<u8>,
    /// Which bitmap cluster is currently cached (None = cache empty).
    cached_cluster: Option<u64>,
}

impl NtfsClusterBitmap {
    /// Loads the cluster allocation bitmap from the filesystem.
    ///
    /// Opens MFT record 6 (`$Bitmap`), extracts its `$DATA` attribute data runs,
    /// and prepares the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the `$Bitmap` record or its non-resident data cannot
    /// be read, parsed, or represented in memory on this target.
    pub fn load<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        let bitmap_file = ntfs.file(fs, KnownNtfsFileRecordNumber::Bitmap.as_u64())?;
        let data_attribute =
            bitmap_file.find_resident_attribute(NtfsAttributeType::Data, None, None)?;
        let non_resident_value = data_attribute.non_resident_value()?;
        let map = DataRunMap::from_data_runs(non_resident_value.data_runs())?;

        let total_clusters = ntfs.size() / u64::from(ntfs.cluster_size());
        let cluster_size = ntfs.cluster_size();
        let cache_size = usize::try_from(cluster_size).map_err(|_| IoError::invalid_input())?;

        Ok(Self {
            map,
            total_clusters,
            cluster_size,
            cache: vec![0u8; cache_size],
            cached_cluster: None,
        })
    }

    /// Builds a bitmap directly from its component parts.
    ///
    /// Test-only helper that bypasses [`Self::load`] so synthetic bitmaps can
    /// be exercised without a full NTFS volume.
    #[cfg(test)]
    pub(crate) fn from_parts_for_test(
        map: DataRunMap,
        total_clusters: u64,
        cluster_size: u32,
    ) -> Self {
        let cache_size =
            usize::try_from(cluster_size).expect("synthetic cluster size fits in memory");
        Self {
            map,
            total_clusters,
            cluster_size,
            cache: vec![0u8; cache_size],
            cached_cluster: None,
        }
    }

    /// Returns the total number of clusters on the volume.
    #[must_use]
    pub fn total_clusters(&self) -> u64 {
        self.total_clusters
    }

    /// Returns whether the given cluster is marked as allocated in the bitmap.
    ///
    /// # Errors
    ///
    /// Returns [`NtfsError::ClusterOutOfRange`] when `cluster` lies beyond the
    /// volume, or an I/O error when its bitmap byte cannot be read.
    pub fn is_allocated<T: Read + Seek>(&mut self, fs: &mut T, cluster: u64) -> Result<bool> {
        if cluster >= self.total_clusters {
            return Err(NtfsError::ClusterOutOfRange {
                cluster,
                total: self.total_clusters,
            });
        }

        let bits_per_cache = u64::from(self.cluster_size) * 8;
        let bitmap_cluster = cluster / bits_per_cache;
        let bit_offset = cluster % bits_per_cache;

        self.ensure_cached(fs, bitmap_cluster)?;

        let byte_index = usize::try_from(bit_offset / 8).map_err(|_| IoError::invalid_input())?;
        let bit_index = u32::try_from(bit_offset % 8).map_err(|_| IoError::invalid_input())?;
        let bitmap_byte = self
            .cache
            .get(byte_index)
            .copied()
            .ok_or(IoError::invalid_data())?;
        Ok((bitmap_byte & (1 << bit_index)) != 0)
    }

    /// Returns allocation statistics for a range of clusters.
    ///
    /// Counts how many clusters in `start..start+count` are allocated vs free.
    /// Clusters beyond `total_clusters` are silently excluded from the count.
    ///
    /// # Errors
    ///
    /// Returns an error if any bitmap cluster covering the requested range
    /// cannot be read.
    pub fn range_status<T: Read + Seek>(
        &mut self,
        fs: &mut T,
        start: u64,
        count: u64,
    ) -> Result<ClusterRangeStatus> {
        let mut allocated = 0u64;
        let mut free = 0u64;

        let end = start.saturating_add(count).min(self.total_clusters);
        for cluster in start..end {
            if self.is_allocated(fs, cluster)? {
                allocated += 1;
            } else {
                free += 1;
            }
        }

        Ok(ClusterRangeStatus { allocated, free })
    }

    /// Returns the total number of free (unallocated) clusters on the volume.
    ///
    /// Uses bulk popcount for efficiency — `O(bitmap_size` / `cluster_size`) I/O
    /// operations instead of `O(total_clusters)`.
    ///
    /// # Errors
    ///
    /// Returns an error if bitmap data cannot be read or a bitmap offset cannot
    /// be represented on this target.
    pub fn free_clusters<T: Read + Seek>(&mut self, fs: &mut T) -> Result<u64> {
        let bits_per_cache = u64::from(self.cluster_size) * 8;
        let bitmap_clusters = self.total_clusters.div_ceil(bits_per_cache);
        let mut allocated: u64 = 0;

        for bc in 0..bitmap_clusters {
            self.ensure_cached(fs, bc)?;

            // For the last bitmap cluster, only count bits up to total_clusters.
            let bits_in_this_chunk = if bc + 1 == bitmap_clusters {
                let remainder = self.total_clusters % bits_per_cache;
                if remainder == 0 {
                    bits_per_cache
                } else {
                    remainder
                }
            } else {
                bits_per_cache
            };

            let full_bytes =
                usize::try_from(bits_in_this_chunk / 8).map_err(|_| IoError::invalid_input())?;
            let remaining_bits =
                u32::try_from(bits_in_this_chunk % 8).map_err(|_| IoError::invalid_input())?;

            // Popcount full bytes
            allocated += self
                .cache
                .iter()
                .take(full_bytes)
                .map(|b| u64::from(b.count_ones()))
                .sum::<u64>();

            // Handle partial last byte
            if remaining_bits > 0
                && let Some(&last_byte) = self.cache.get(full_bytes)
            {
                let mask = u8::MAX >> (u8::BITS - remaining_bits);
                allocated += u64::from((last_byte & mask).count_ones());
            }
        }

        Ok(self.total_clusters - allocated)
    }

    /// Ensures the cache contains the bitmap data for the given bitmap cluster index.
    fn ensure_cached<T: Read + Seek>(&mut self, fs: &mut T, bitmap_cluster: u64) -> Result<()> {
        if self.cached_cluster == Some(bitmap_cluster) {
            return Ok(());
        }

        let byte_offset = bitmap_cluster * u64::from(self.cluster_size);
        let disk_position = self
            .map
            .resolve_position(byte_offset)
            .map_or(NtfsPosition::none(), |(p, _)| p);

        match disk_position.value() {
            Some(pos) => {
                fs.seek(SeekFrom::Start(pos.get()))?;
                fs.read_exact(&mut self.cache)?;
            }
            None => {
                // Sparse segment: treat as all zeros (all free).
                self.cache.fill(0);
            }
        }

        self.cached_cluster = Some(bitmap_cluster);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_run_map::DataRunMap;

    /// Cluster size for synthetic fixtures: 8 bytes -> 64 bits per cached
    /// bitmap cluster, so cluster->bitmap-cluster division is observable.
    const SYNTH_CLUSTER_SIZE: u32 = 8;
    /// Disk offset at which the synthetic bitmap bytes begin (non-zero so
    /// positions resolve to valid `NtfsPosition`s).
    const SYNTH_BASE: u64 = 512;
    /// Total clusters spanning three 64-bit bitmap clusters (0-63, 64-127,
    /// 128-129) so the last (partial) chunk path is exercised.
    const SYNTH_TOTAL: u64 = 130;

    /// Builds a synthetic bitmap plus a backing cursor.
    ///
    /// `set_bits` lists the cluster numbers marked allocated. The bitmap
    /// occupies `ceil(SYNTH_TOTAL/8)` bytes (rounded up to whole cached
    /// clusters), laid out on disk starting at `SYNTH_BASE`.
    fn build_bitmap(set_bits: &[u64]) -> (NtfsClusterBitmap, fsmnt_testkit::Cursor<Vec<u8>>) {
        build_bitmap_with_total(SYNTH_TOTAL, set_bits)
    }

    /// Like [`build_bitmap`] but with an explicit `total_clusters`.
    fn build_bitmap_with_total(
        total: u64,
        set_bits: &[u64],
    ) -> (NtfsClusterBitmap, fsmnt_testkit::Cursor<Vec<u8>>) {
        let bits_per_cache = u64::from(SYNTH_CLUSTER_SIZE) * 8;
        let bitmap_clusters = total.div_ceil(bits_per_cache);
        let bitmap_len = usize::try_from(bitmap_clusters * u64::from(SYNTH_CLUSTER_SIZE))
            .expect("test value fits usize");

        let mut bitmap = vec![0u8; bitmap_len];
        for &c in set_bits {
            let byte = usize::try_from(c / 8).expect("test cluster index fits usize");
            let bit = u32::try_from(c % 8).expect("bit index is below eight");
            bitmap[byte] |= 1 << bit;
        }

        // Disk image: SYNTH_BASE bytes of padding, then the bitmap bytes.
        let mut disk = vec![0u8; usize::try_from(SYNTH_BASE).expect("test value fits usize")];
        disk.extend_from_slice(&bitmap);
        let cursor = fsmnt_testkit::Cursor::new(disk);

        // One contiguous segment maps virtual offset 0 -> disk SYNTH_BASE.
        let bitmap_len_u64 = u64::try_from(bitmap_len).expect("test bitmap length fits u64");
        let map = DataRunMap::from_segments_for_test(&[(Some(SYNTH_BASE), bitmap_len_u64)]);
        let bm = NtfsClusterBitmap::from_parts_for_test(map, total, SYNTH_CLUSTER_SIZE);
        (bm, cursor)
    }

    #[test]
    fn synth_total_clusters() {
        let (bm, _fs) = build_bitmap(&[]);
        assert_eq!(bm.total_clusters(), SYNTH_TOTAL);
    }

    #[test]
    fn synth_is_allocated_specific_bits() {
        // Allocate clusters in each of the three bitmap clusters, at bit
        // positions that exercise the division/modulo/shift arithmetic.
        let (mut bm, mut fs) = build_bitmap(&[5, 70, 128]);

        // Cluster 5: bitmap_cluster 0, byte 0, bit 5.
        assert!(bm.is_allocated(&mut fs, 5).unwrap());
        // Cluster 70: bitmap_cluster 1 (70/64=1), bit_offset 6, byte 0, bit 6.
        assert!(bm.is_allocated(&mut fs, 70).unwrap());
        // Cluster 128: bitmap_cluster 2 (128/64=2), bit_offset 0, byte 0, bit 0.
        assert!(bm.is_allocated(&mut fs, 128).unwrap());

        // Neighbours of the set bits must read as free, pinning the exact
        // byte/bit selection (kills byte/bit index and shift mutants).
        assert!(!bm.is_allocated(&mut fs, 4).unwrap());
        assert!(!bm.is_allocated(&mut fs, 6).unwrap());
        assert!(!bm.is_allocated(&mut fs, 69).unwrap());
        assert!(!bm.is_allocated(&mut fs, 71).unwrap());
        assert!(!bm.is_allocated(&mut fs, 129).unwrap());
        assert!(!bm.is_allocated(&mut fs, 0).unwrap());
    }

    #[test]
    fn synth_is_allocated_out_of_range_boundary() {
        let (mut bm, mut fs) = build_bitmap(&[]);
        // The last in-range cluster index is SYNTH_TOTAL - 1 (free here).
        assert!(!bm.is_allocated(&mut fs, SYNTH_TOTAL - 1).unwrap());
        // Exactly SYNTH_TOTAL is out of range (kills `>=` -> `<`).
        let err = bm.is_allocated(&mut fs, SYNTH_TOTAL).unwrap_err();
        match err {
            NtfsError::ClusterOutOfRange { cluster, total } => {
                assert_eq!(cluster, SYNTH_TOTAL);
                assert_eq!(total, SYNTH_TOTAL);
            }
            other => panic!("expected ClusterOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn synth_is_allocated_distinguishes_bitmap_clusters() {
        // Bit 6 set in byte 0 means cluster 6 (bitmap cluster 0) is allocated.
        // Cluster 70 (bitmap cluster 1, same byte/bit within its chunk) must
        // NOT be reported allocated unless its own byte is set — this kills a
        // `/`->`%`/`*` swap in `bitmap_cluster = cluster / bits_per_cache`,
        // which would conflate the two chunks.
        let (mut bm, mut fs) = build_bitmap(&[6]);
        assert!(bm.is_allocated(&mut fs, 6).unwrap());
        assert!(!bm.is_allocated(&mut fs, 70).unwrap());
    }

    #[test]
    fn synth_range_status_counts() {
        // Clusters 1, 2, 3 allocated within the queried range [0, 8).
        let (mut bm, mut fs) = build_bitmap(&[1, 2, 3]);
        let status = bm.range_status(&mut fs, 0, 8).unwrap();
        assert_eq!(status.allocated, 3);
        assert_eq!(status.free, 5);
        assert_eq!(status.allocated + status.free, 8);
    }

    #[test]
    fn synth_range_status_clamped_to_total() {
        // count overshoots total; the range is clamped to SYNTH_TOTAL.
        let (mut bm, mut fs) = build_bitmap(&[0]);
        let status = bm.range_status(&mut fs, 0, SYNTH_TOTAL + 50).unwrap();
        assert_eq!(status.allocated, 1);
        assert_eq!(status.allocated + status.free, SYNTH_TOTAL);
    }

    #[test]
    fn synth_free_clusters_counts_unset_bits() {
        // 3 clusters allocated across all three chunks; the rest are free.
        // Cluster 129 (the second bit of the partial last chunk) is left
        // free, so the partial-byte masking must not over- or under-count.
        let (mut bm, mut fs) = build_bitmap(&[5, 70, 128]);
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), SYNTH_TOTAL - 3);
    }

    #[test]
    fn synth_free_clusters_partial_chunk_masking() {
        // Set a bit at position 130 (cluster index beyond total) inside the
        // last cached chunk's byte. The mask must exclude it so it is not
        // counted as allocated (kills the `<< - 1` mask and `% 8` mutants).
        let bits_per_cache = u64::from(SYNTH_CLUSTER_SIZE) * 8;
        let bitmap_clusters = SYNTH_TOTAL.div_ceil(bits_per_cache);
        let bitmap_len = usize::try_from(bitmap_clusters * u64::from(SYNTH_CLUSTER_SIZE))
            .expect("test value fits usize");
        let mut bitmap = vec![0u8; bitmap_len];
        // Cluster 128 (in range) allocated.
        bitmap[16] |= 1 << 0;
        // Cluster 130 (out of range, same byte, bit 2) also set on disk.
        bitmap[16] |= 1 << 2;

        let mut disk = vec![0u8; usize::try_from(SYNTH_BASE).expect("test value fits usize")];
        disk.extend_from_slice(&bitmap);
        let mut fs = fsmnt_testkit::Cursor::new(disk);
        let bitmap_len_u64 = u64::try_from(bitmap_len).expect("test bitmap length fits u64");
        let map = DataRunMap::from_segments_for_test(&[(Some(SYNTH_BASE), bitmap_len_u64)]);
        let mut bm = NtfsClusterBitmap::from_parts_for_test(map, SYNTH_TOTAL, SYNTH_CLUSTER_SIZE);

        // Only cluster 128 counts as allocated; 130 is masked out.
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), SYNTH_TOTAL - 1);
    }

    #[test]
    fn synth_free_clusters_last_chunk_remainder() {
        // total = 100 spans two 64-bit chunks; the last chunk's bit count is
        // `100 % 64 = 36`, which differs from `100 / 64 = 1`. A bit set at
        // cluster 90 (within the 36-bit remainder, but outside the single bit
        // a `%`->`/` swap would count) must be tallied as allocated.
        let (mut bm, mut fs) = build_bitmap_with_total(100, &[90]);
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), 100 - 1);
    }

    #[test]
    fn synth_free_clusters_all_free_and_all_allocated() {
        // All free.
        let (mut bm, mut fs) = build_bitmap(&[]);
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), SYNTH_TOTAL);

        // All in-range clusters allocated -> zero free.
        let all: Vec<u64> = (0..SYNTH_TOTAL).collect();
        let (mut bm, mut fs) = build_bitmap(&all);
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), 0);
    }

    #[test]
    fn synth_sparse_segment_reads_as_free() {
        // A sparse map (None position) yields an all-zero cache, so every
        // cluster reads as free and the whole volume is free.
        let bits_per_cache = u64::from(SYNTH_CLUSTER_SIZE) * 8;
        let bitmap_clusters = SYNTH_TOTAL.div_ceil(bits_per_cache);
        let bitmap_len = bitmap_clusters * u64::from(SYNTH_CLUSTER_SIZE);
        let map = DataRunMap::from_segments_for_test(&[(None, bitmap_len)]);
        let mut bm = NtfsClusterBitmap::from_parts_for_test(map, SYNTH_TOTAL, SYNTH_CLUSTER_SIZE);
        let mut fs = fsmnt_testkit::Cursor::new(Vec::<u8>::new());

        assert!(!bm.is_allocated(&mut fs, 0).unwrap());
        assert_eq!(bm.free_clusters(&mut fs).unwrap(), SYNTH_TOTAL);
    }

    #[test]
    fn synth_ensure_cached_reuses_and_refreshes() {
        // Two clusters in different bitmap clusters force a cache refresh.
        // If `ensure_cached`'s `cached_cluster == Some(..)` guard or its
        // `bitmap_cluster * cluster_size` offset were wrong, the second read
        // would return stale or misaligned data.
        let (mut bm, mut fs) = build_bitmap(&[1, 65]);
        // Read cluster 1 (bitmap cluster 0).
        assert!(bm.is_allocated(&mut fs, 1).unwrap());
        // Re-read same bitmap cluster (cache hit) — still correct.
        assert!(!bm.is_allocated(&mut fs, 2).unwrap());
        // Read cluster 65 (bitmap cluster 1) — forces a refresh to a new
        // disk offset; must reflect bit 65, not stale chunk-0 data.
        assert!(bm.is_allocated(&mut fs, 65).unwrap());
        // Cluster 64 (same bitmap cluster, adjacent bit) is free; if the
        // refresh kept stale chunk-0 bytes, bit 1 of chunk-0 would leak in.
        assert!(!bm.is_allocated(&mut fs, 64).unwrap());
    }

    #[test]
    fn test_cluster_bitmap_load() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let bitmap = NtfsClusterBitmap::load(&ntfs, &mut testfs1).unwrap();
        assert!(bitmap.total_clusters() > 0);
    }

    #[test]
    fn test_cluster_bitmap_system_clusters_allocated() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut bitmap = NtfsClusterBitmap::load(&ntfs, &mut testfs1).unwrap();

        // The first few clusters (containing the MFT and system files) should be allocated.
        for cluster in 0..4 {
            assert!(
                bitmap.is_allocated(&mut testfs1, cluster).unwrap(),
                "cluster {cluster} should be allocated (system area)"
            );
        }
    }

    #[test]
    fn test_cluster_bitmap_out_of_range() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut bitmap = NtfsClusterBitmap::load(&ntfs, &mut testfs1).unwrap();
        let total = bitmap.total_clusters();

        let err = bitmap.is_allocated(&mut testfs1, total + 1).unwrap_err();
        match err {
            NtfsError::ClusterOutOfRange { cluster, total: t } => {
                assert_eq!(cluster, total + 1);
                assert_eq!(t, total);
            }
            other => panic!("expected ClusterOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn test_cluster_bitmap_range_status() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut bitmap = NtfsClusterBitmap::load(&ntfs, &mut testfs1).unwrap();

        let count = 64u64.min(bitmap.total_clusters());
        let status = bitmap.range_status(&mut testfs1, 0, count).unwrap();

        // allocated + free should equal the number of clusters queried.
        assert_eq!(status.allocated + status.free, count);
        // The start of the volume should have some allocated clusters.
        assert!(
            status.allocated > 0,
            "expected some allocated clusters at start of volume"
        );
    }

    #[test]
    fn test_cluster_bitmap_via_ntfs_convenience() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let mut bitmap = ntfs.cluster_bitmap(&mut testfs1).unwrap();
        assert!(bitmap.total_clusters() > 0);

        // Basic query should work.
        let allocated = bitmap.is_allocated(&mut testfs1, 0).unwrap();
        assert!(allocated, "cluster 0 should be allocated");
    }
}
