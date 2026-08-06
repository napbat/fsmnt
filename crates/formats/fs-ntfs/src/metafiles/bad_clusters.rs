use alloc::vec::Vec;

use crate::attribute::NtfsAttributeType;
use crate::data_run_map::DataRunMap;
use crate::error::{NtfsError, Result};
use crate::file::KnownNtfsFileRecordNumber;
use crate::io::{Read, Seek};
use crate::ntfs::Ntfs;
use crate::types::Lcn;

/// Provides analysis of the `$BadClus` metafile (MFT entry 8).
///
/// The `$Bad` named data stream of `$BadClus` is a sparse file spanning the
/// entire filesystem. Non-sparse data runs indicate bad clusters. On a healthy
/// volume, the stream consists of a single sparse run covering all clusters.
///
/// TSK detects the "single sparse run = entire FS" case and frees the run list
/// (returning NULL). This type provides equivalent functionality: [`has_bad_clusters`]
/// returns `false` when there are no non-sparse runs.
///
/// Created via [`Ntfs::bad_clusters`] or [`NtfsBadClusters::load`].
///
/// [`has_bad_clusters`]: NtfsBadClusters::has_bad_clusters
#[derive(Clone, Debug)]
pub struct NtfsBadClusters {
    /// Non-sparse data run segments: (start LCN, cluster count).
    bad_ranges: Vec<(Lcn, u64)>,
}

impl NtfsBadClusters {
    /// Loads the `$BadClus` metafile and analyses its `$Bad` data stream.
    ///
    /// Opens MFT record 8, finds the `$Bad` named `$DATA` attribute, and
    /// identifies non-sparse data runs.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested NTFS metafile is missing, malformed, or cannot be read.
    pub fn load<T: Read + Seek>(ntfs: &Ntfs, fs: &mut T) -> Result<Self> {
        let badclus_file = ntfs.file(fs, KnownNtfsFileRecordNumber::BadClus.as_u64())?;

        // Find the $DATA attribute named "$Bad" by iterating raw attributes.
        // This avoids requiring the upcase table.
        let mut found = false;
        let mut bad_ranges = Vec::new();

        for attribute in badclus_file.attributes_raw() {
            let attribute = attribute?;

            if attribute.ty()? != NtfsAttributeType::Data {
                continue;
            }

            if attribute.name()? != "$Bad" {
                continue;
            }

            found = true;

            // The $Bad stream should be non-resident (it spans the entire FS).
            let non_resident_value = attribute.non_resident_value()?;
            let map = DataRunMap::from_data_runs(non_resident_value.data_runs())?;
            let cluster_size = u64::from(ntfs.cluster_size());

            for i in 0..map.segment_count() {
                if let Some((position, size)) = map.segment(i) {
                    // Sparse segments (position = None) are normal — the FS has no
                    // bad clusters there. Only non-sparse segments are bad.
                    if let Some(pos) = position.value() {
                        let lcn = Lcn::from(pos.get() / cluster_size);
                        let cluster_count = size / cluster_size;
                        if cluster_count > 0 {
                            bad_ranges.push((lcn, cluster_count));
                        }
                    }
                }
            }

            break;
        }

        if !found {
            return Err(NtfsError::AttributeNotFound {
                position: badclus_file.position(),
                ty: NtfsAttributeType::Data,
            });
        }

        Ok(Self { bad_ranges })
    }

    /// Returns `true` if there are any non-sparse data runs, indicating
    /// bad clusters on the volume.
    #[must_use]
    pub fn has_bad_clusters(&self) -> bool {
        !self.bad_ranges.is_empty()
    }

    /// Returns an iterator over the bad cluster ranges.
    ///
    /// Each item is `(start_lcn, cluster_count)` identifying a contiguous
    /// range of bad clusters.
    pub fn bad_cluster_ranges(&self) -> impl Iterator<Item = (Lcn, u64)> + '_ {
        self.bad_ranges.iter().copied()
    }

    /// Returns the total number of bad clusters on the volume.
    #[must_use]
    pub fn total_bad_clusters(&self) -> u64 {
        self.bad_ranges.iter().map(|&(_, count)| count).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntfs::Ntfs;

    /// Builds an [`NtfsBadClusters`] directly from synthetic ranges so the
    /// accessors can be tested without a full NTFS image (`load` requires
    /// MFT record 8, which only a mounted image provides).
    fn from_ranges(ranges: &[(u64, u64)]) -> NtfsBadClusters {
        NtfsBadClusters {
            bad_ranges: ranges.iter().map(|&(lcn, n)| (Lcn::from(lcn), n)).collect(),
        }
    }

    #[test]
    fn test_has_bad_clusters_reflects_ranges() {
        // No ranges -> false; some ranges -> true. Catches the hardcoded
        // true/false and the `delete !` mutants at line 91.
        assert!(!from_ranges(&[]).has_bad_clusters());
        assert!(from_ranges(&[(100, 4)]).has_bad_clusters());
    }

    #[test]
    fn test_bad_cluster_ranges_yields_each_range() {
        // Catches `bad_cluster_ranges -> empty()` (line 99).
        let bad = from_ranges(&[(100, 4), (500, 8)]);
        let ranges: Vec<(Lcn, u64)> = bad.bad_cluster_ranges().collect();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].0.value(), 100);
        assert_eq!(ranges[0].1, 4);
        assert_eq!(ranges[1].0.value(), 500);
        assert_eq!(ranges[1].1, 8);
    }

    #[test]
    fn test_total_bad_clusters_sums_counts() {
        // 4 + 8 = 12, distinct from the hardcoded 0/1 mutants (line 104).
        assert_eq!(from_ranges(&[(100, 4), (500, 8)]).total_bad_clusters(), 12);
        // Empty -> 0.
        assert_eq!(from_ranges(&[]).total_bad_clusters(), 0);
    }

    #[test]
    fn test_bad_clusters_load() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let bad = NtfsBadClusters::load(&ntfs, &mut testfs1).unwrap();
        // A normal test filesystem should have no bad clusters.
        assert!(!bad.has_bad_clusters());
        assert_eq!(bad.total_bad_clusters(), 0);
    }

    #[test]
    fn test_bad_clusters_no_ranges() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let bad = NtfsBadClusters::load(&ntfs, &mut testfs1).unwrap();
        let ranges: Vec<_> = bad.bad_cluster_ranges().collect();
        assert!(
            ranges.is_empty(),
            "expected no bad cluster ranges on a healthy FS"
        );
    }

    #[test]
    fn test_bad_clusters_via_ntfs_convenience() {
        let Some(mut testfs1) = crate::helpers::tests::testfs1() else {
            return;
        };
        let ntfs = Ntfs::new(&mut testfs1).unwrap();

        let bad = ntfs.bad_clusters(&mut testfs1).unwrap();
        assert!(!bad.has_bad_clusters());
    }
}
