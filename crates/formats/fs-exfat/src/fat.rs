use crate::error::{ExFatError, Result};
use crate::exfat::ExFat;
use crate::io::{Read, Seek, SeekFrom};

/// exFAT FAT entry special values (full 32-bit, unlike FAT32's 28-bit).
const FAT_ENTRY_FREE: u32 = 0x0000_0000;
const FAT_ENTRY_BAD: u32 = 0xFFFF_FFF7;
/// Minimum end-of-chain marker value.
const FAT_ENTRY_EOC_MIN: u32 = 0xFFFF_FFF8;

impl ExFat {
    /// Reads the next cluster number from the FAT for the given
    /// cluster.
    ///
    /// Returns `Ok(Some(next))` when the chain continues,
    /// `Ok(None)` at end-of-chain (0xFFFFFFF8..=0xFFFFFFFF),
    /// or an appropriate error for bad/invalid entries.
    pub fn next_cluster<T>(&self, fs: &mut T, cluster: u32) -> Result<Option<u32>>
    where
        T: Read + Seek,
    {
        // Validate cluster range: valid indices are 2 through
        // cluster_count + 1.
        if cluster < 2 || cluster > self.cluster_count().saturating_add(1) {
            return Err(ExFatError::InvalidCluster { cluster });
        }

        // Seek to the FAT entry for this cluster.
        let entry_offset = self.fat_offset() + cluster as u64 * 4;
        fs.seek(SeekFrom::Start(entry_offset))?;

        let mut buf = [0u8; 4];
        fs.read_exact(&mut buf)?;
        let value = u32::from_le_bytes(buf);

        match value {
            FAT_ENTRY_EOC_MIN..=u32::MAX => Ok(None),
            FAT_ENTRY_BAD => Err(ExFatError::BadCluster { cluster }),
            // Free/unused FAT entry — treat as end-of-chain.
            // This occurs for NoFatChain directories/files whose
            // clusters have no FAT entries populated.
            FAT_ENTRY_FREE | 1 => Ok(None),
            v if v < 2 || v > self.cluster_count().saturating_add(1) => {
                Err(ExFatError::InvalidCluster { cluster: v })
            }
            v => Ok(Some(v)),
        }
    }

    /// Creates a lazy cluster chain iterator starting at the given
    /// cluster.
    pub fn cluster_iter(&self, start_cluster: u32) -> ExFatClusterIterator<'_> {
        ExFatClusterIterator::new(self, start_cluster)
    }
}

/// A lazy iterator over a cluster chain in an exFAT volume.
///
/// Yields one cluster index per [`next`](ExFatClusterIterator::next)
/// call, following the FAT chain until end-of-chain is reached or
/// an error occurs. Detects cluster chain loops by tracking the
/// number of clusters traversed against the volume's cluster count.
pub struct ExFatClusterIterator<'e> {
    exfat: &'e ExFat,
    current_cluster: Option<u32>,
    clusters_traversed: u32,
}

impl<'e> ExFatClusterIterator<'e> {
    /// Creates a new iterator starting at `start_cluster`.
    pub fn new(exfat: &'e ExFat, start_cluster: u32) -> Self {
        Self {
            exfat,
            current_cluster: Some(start_cluster),
            clusters_traversed: 0,
        }
    }

    /// Advances the iterator and returns the next cluster in the
    /// chain.
    ///
    /// Returns `None` when the chain is exhausted. Returns
    /// `Some(Err(_))` on bad clusters, invalid entries, or loop
    /// detection.
    pub fn next<T>(&mut self, fs: &mut T) -> Option<Result<u32>>
    where
        T: Read + Seek,
    {
        let cluster = self.current_cluster?;

        self.clusters_traversed += 1;
        if self.clusters_traversed > self.exfat.cluster_count() {
            self.current_cluster = None;
            return Some(Err(ExFatError::ChainLoop {
                max_clusters: self.exfat.cluster_count(),
            }));
        }

        match self.exfat.next_cluster(fs, cluster) {
            Ok(None) => self.current_cluster = None,
            Ok(Some(next)) => self.current_cluster = Some(next),
            Err(e) => {
                self.current_cluster = None;
                return Some(Err(e));
            }
        }

        Some(Ok(cluster))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;
    use alloc::vec;

    // ---------------------------------------------------------------
    // next_cluster tests
    // ---------------------------------------------------------------

    #[test]
    fn test_next_cluster_follows_chain() {
        let mut image = make_image();
        // Chain: 2 -> 3 -> 4 -> EOC
        set_fat_entry(&mut image, 2, 3);
        set_fat_entry(&mut image, 3, 4);
        set_fat_entry(&mut image, 4, 0xFFFF_FFFF);

        let (exfat, mut cursor) = make_exfat(image);
        assert_eq!(exfat.next_cluster(&mut cursor, 2).unwrap(), Some(3));
        assert_eq!(exfat.next_cluster(&mut cursor, 3).unwrap(), Some(4));
        assert_eq!(exfat.next_cluster(&mut cursor, 4).unwrap(), None);
    }

    #[test]
    fn test_next_cluster_eoc_variants() {
        let mut image = make_image();
        // 0xFFFFFFF8 (min EOC), 0xFFFFFFFE, 0xFFFFFFFF
        set_fat_entry(&mut image, 2, 0xFFFF_FFF8);
        set_fat_entry(&mut image, 3, 0xFFFF_FFFE);
        set_fat_entry(&mut image, 4, 0xFFFF_FFFF);

        let (exfat, mut cursor) = make_exfat(image);
        assert_eq!(
            exfat.next_cluster(&mut cursor, 2).unwrap(),
            None,
            "0xFFFFFFF8 should be end-of-chain"
        );
        assert_eq!(
            exfat.next_cluster(&mut cursor, 3).unwrap(),
            None,
            "0xFFFFFFFE should be end-of-chain"
        );
        assert_eq!(
            exfat.next_cluster(&mut cursor, 4).unwrap(),
            None,
            "0xFFFFFFFF should be end-of-chain"
        );
    }

    #[test]
    fn test_next_cluster_bad_cluster() {
        let mut image = make_image();
        set_fat_entry(&mut image, 5, FAT_ENTRY_BAD);

        let (exfat, mut cursor) = make_exfat(image);
        let err = exfat.next_cluster(&mut cursor, 5).unwrap_err();
        assert!(
            matches!(err, ExFatError::BadCluster { cluster: 5 }),
            "Expected BadCluster for 0xFFFFFFF7, got: {err:?}"
        );
    }

    #[test]
    fn test_next_cluster_invalid_range_zero() {
        let image = make_image();
        let (exfat, mut cursor) = make_exfat(image);
        let err = exfat.next_cluster(&mut cursor, 0).unwrap_err();
        assert!(
            matches!(err, ExFatError::InvalidCluster { cluster: 0 }),
            "Expected InvalidCluster for cluster 0, got: {err:?}"
        );
    }

    #[test]
    fn test_next_cluster_invalid_range_one() {
        let image = make_image();
        let (exfat, mut cursor) = make_exfat(image);
        let err = exfat.next_cluster(&mut cursor, 1).unwrap_err();
        assert!(
            matches!(err, ExFatError::InvalidCluster { cluster: 1 }),
            "Expected InvalidCluster for cluster 1, got: {err:?}"
        );
    }

    #[test]
    fn test_next_cluster_out_of_range() {
        let image = make_image();
        let (exfat, mut cursor) = make_exfat(image);
        // cluster_count=100 => max valid = 101, so 102 is invalid
        let err = exfat.next_cluster(&mut cursor, 102).unwrap_err();
        assert!(
            matches!(err, ExFatError::InvalidCluster { cluster: 102 }),
            "Expected InvalidCluster for cluster 102, got: {err:?}"
        );
    }

    #[test]
    fn test_next_cluster_free_entry_is_eoc() {
        let mut image = make_image();
        // FAT[6] = 0x00000000 (free cluster)
        set_fat_entry(&mut image, 6, FAT_ENTRY_FREE);

        let (exfat, mut cursor) = make_exfat(image);
        // Free entries are treated as end-of-chain (NoFatChain
        // directories/files have unpopulated FAT entries).
        let result = exfat.next_cluster(&mut cursor, 6).unwrap();
        assert_eq!(result, None);
    }

    // ---------------------------------------------------------------
    // cluster_iter tests
    // ---------------------------------------------------------------

    #[test]
    fn test_cluster_iter_basic() {
        let mut image = make_image();
        // Chain: 2 -> 3 -> 4 -> EOC
        set_fat_entry(&mut image, 2, 3);
        set_fat_entry(&mut image, 3, 4);
        set_fat_entry(&mut image, 4, 0xFFFF_FFFF);

        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(2);
        let mut clusters = Vec::new();
        while let Some(result) = iter.next(&mut cursor) {
            clusters.push(result.unwrap());
        }
        assert_eq!(clusters, vec![2, 3, 4]);
    }

    #[test]
    fn test_cluster_iter_single_cluster() {
        let mut image = make_image();
        // FAT[2] = EOC
        set_fat_entry(&mut image, 2, 0xFFFF_FFFF);

        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(2);
        let mut clusters = Vec::new();
        while let Some(result) = iter.next(&mut cursor) {
            clusters.push(result.unwrap());
        }
        assert_eq!(clusters, vec![2]);
    }

    #[test]
    fn test_cluster_iter_loop_detection() {
        let mut image = make_image();
        // Create a loop: 2 -> 3 -> 4 -> 2
        set_fat_entry(&mut image, 2, 3);
        set_fat_entry(&mut image, 3, 4);
        set_fat_entry(&mut image, 4, 2);

        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(2);

        // Should yield some clusters then a ChainLoop error.
        let mut saw_loop_error = false;
        let mut count = 0u32;
        loop {
            match iter.next(&mut cursor) {
                Some(Ok(_)) => {
                    count += 1;
                    // Safety: prevent infinite test if detection fails.
                    if count > 200 {
                        panic!(
                            "Loop detection did not trigger \
                             after 200 iterations"
                        );
                    }
                }
                Some(Err(ExFatError::ChainLoop { .. })) => {
                    saw_loop_error = true;
                    break;
                }
                Some(Err(e)) => {
                    panic!("Unexpected error: {e:?}");
                }
                None => break,
            }
        }
        assert!(
            saw_loop_error,
            "Expected ChainLoop error, iterator ended \
             without it after {count} clusters"
        );
        // After the error, iterator should be exhausted.
        assert!(iter.next(&mut cursor).is_none());
    }

    /// Spec §7.1.5: valid cluster indices are `2..=ClusterCount+1`.
    /// Cluster_count = 100 means cluster 101 is the inclusive
    /// boundary. Kills `> → >=` at the upper bound check.
    #[test]
    fn test_next_cluster_accepts_last_valid_cluster() {
        let mut image = make_image();
        // Mark FAT[101] = EOC so it's a valid chain terminator.
        set_fat_entry(&mut image, 101, 0xFFFF_FFFF);
        let (exfat, mut cursor) = make_exfat(image);
        assert_eq!(exfat.next_cluster(&mut cursor, 101).unwrap(), None);
    }

    /// FAT entry values must themselves fall in the valid range
    /// `2..=cluster_count+1`. A FAT entry pointing to a far
    /// out-of-range cluster must surface `InvalidCluster{v}` rather
    /// than be passed through. This kills mutations that disable
    /// the match guard (`guard → false`, `|| → &&`, `> → ==`).
    #[test]
    fn test_next_cluster_rejects_out_of_range_chain_value() {
        let mut image = make_image();
        // FAT[5] = 200, well beyond cluster_count + 1 = 101.
        set_fat_entry(&mut image, 5, 200);
        let (exfat, mut cursor) = make_exfat(image);
        let err = exfat.next_cluster(&mut cursor, 5).unwrap_err();
        assert!(
            matches!(err, ExFatError::InvalidCluster { cluster: 200 }),
            "got: {err:?}"
        );
    }

    /// FAT entry value equal to `cluster_count + 1` is the inclusive
    /// upper bound and must be accepted as a valid next cluster.
    /// Kills `> → >=` at the guard's upper bound check.
    #[test]
    fn test_next_cluster_accepts_last_valid_chain_value() {
        let mut image = make_image();
        set_fat_entry(&mut image, 5, 101); // 101 = cluster_count + 1
        let (exfat, mut cursor) = make_exfat(image);
        assert_eq!(exfat.next_cluster(&mut cursor, 5).unwrap(), Some(101));
    }

    /// `cluster_iter` triggers `ChainLoop` only when traversed
    /// strictly exceeds `cluster_count`. A valid chain whose length
    /// equals `cluster_count` must complete without raising the
    /// loop-detection error. Kills `> → ==` and `> → >=` at the
    /// loop-detection check.
    #[test]
    fn test_cluster_iter_does_not_trigger_loop_for_max_length_chain() {
        let mut image = make_image();
        // Build a 100-cluster chain: 2 -> 3 -> 4 -> ... -> 101 -> EOC.
        for c in 2u32..=100 {
            set_fat_entry(&mut image, c, c + 1);
        }
        set_fat_entry(&mut image, 101, 0xFFFF_FFFF);

        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(2);
        let mut count = 0u32;
        while let Some(result) = iter.next(&mut cursor) {
            let _ = result.expect("a 100-cluster chain must not raise ChainLoop");
            count += 1;
        }
        assert_eq!(count, 100, "expected the full 100-cluster chain");
    }

    /// A single `.next()` call on a fresh `ExFatClusterIterator` must
    /// yield the start cluster. This bounded test catches the
    /// `next → Some(Ok(0))` and `next → Some(Ok(1))` constant
    /// replacements that would otherwise hang any draining caller
    /// (timeouts in cargo-mutants do not count as kills).
    #[test]
    fn test_cluster_iter_first_call_returns_start_cluster() {
        let mut image = make_image();
        set_fat_entry(&mut image, 5, 0xFFFF_FFFF);
        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(5);
        let first = iter
            .next(&mut cursor)
            .expect("at least one cluster")
            .expect("read should succeed");
        assert_eq!(first, 5);
    }

    #[test]
    fn test_cluster_iter_bad_cluster_in_chain() {
        let mut image = make_image();
        // Chain: 2 -> 3, FAT[3] = BAD
        set_fat_entry(&mut image, 2, 3);
        set_fat_entry(&mut image, 3, FAT_ENTRY_BAD);

        let (exfat, mut cursor) = make_exfat(image);
        let mut iter = exfat.cluster_iter(2);

        // First yield: cluster 2 (Ok).
        let first = iter.next(&mut cursor).unwrap().unwrap();
        assert_eq!(first, 2);

        // Second yield: cluster 3 is readable but its *next* entry
        // is BAD. The iterator yields 3 then discovers the bad
        // marker.  Actually, re-read the plan: "Chain 2->3,
        // FAT[3]=BAD. Verify iterator yields 2, then BadCluster
        // error." This means FAT[2] points to 3, but when we look up
        // FAT[3] we find BAD. The iterator yields cluster 2 first
        // (and in doing so, reads FAT[2]=3, setting
        // current_cluster=3). On the second call it yields cluster 3
        // and reads FAT[3]=BAD => error on advance. Per the
        // implementation sketch the error on advance causes
        // current_cluster = None and the function returns
        // Some(Err(e)) -- so the second call returns BadCluster.
        // Wait, no: re-read the plan's implementation sketch more
        // carefully. On error from next_cluster, it returns
        // Some(Err(e)) -- it does NOT yield the current cluster.
        // Let me look at the sketch:
        //   Err(e) => { self.current_cluster = None; return Some(Err(e)); }
        // Yes -- the error is returned directly, not the cluster.
        // So: call 1 => Some(Ok(2)), call 2 => Some(Err(BadCluster{3}))
        let second = iter.next(&mut cursor);
        match second {
            Some(Err(ExFatError::BadCluster { cluster: 3 })) => {}
            other => panic!("Expected BadCluster for cluster 3, got: {other:?}"),
        }

        // Iterator exhausted after error.
        assert!(iter.next(&mut cursor).is_none());
    }
}
