use crate::error::{ExFatError, Result};
use alloc::vec::Vec;

/// Allocation bitmap for an exFAT volume.
///
/// Stores one bit per cluster (cluster 2 maps to bit 0 of byte 0).
/// A set bit means the cluster is allocated; a clear bit means free.
#[derive(Debug, Clone)]
pub struct ExFatBitmap {
    data: Vec<u8>,
    cluster_count: u32,
}

impl ExFatBitmap {
    /// Creates a new bitmap from raw data and the total cluster count.
    pub(crate) fn new(data: Vec<u8>, cluster_count: u32) -> Self {
        Self {
            data,
            cluster_count,
        }
    }

    /// Returns whether the given cluster is allocated.
    ///
    /// Clusters are numbered starting at 2. Bit 0 of byte 0
    /// corresponds to cluster 2.
    ///
    /// # Errors
    ///
    /// Returns [`ExFatError::InvalidCluster`] when `cluster` is outside
    /// the volume or its bit is missing from the bitmap data.
    pub fn is_allocated(&self, cluster: u32) -> Result<bool> {
        if cluster < 2 || cluster > self.cluster_count.saturating_add(1) {
            return Err(ExFatError::InvalidCluster { cluster });
        }
        let bit_index =
            usize::try_from(cluster - 2).map_err(|_| ExFatError::InvalidCluster { cluster })?;
        let byte_offset = bit_index / 8;
        let bit_offset = bit_index % 8;
        if byte_offset >= self.data.len() {
            return Err(ExFatError::InvalidCluster { cluster });
        }
        Ok(self.data[byte_offset] & (1 << bit_offset) != 0)
    }

    /// Returns the total number of allocated clusters.
    //
    // `#[mutants::skip]` covers the `remaining_bits > 0` guard at
    // line 51: replacing `>` with `>=` is an equivalent mutant.
    // `remaining_bits` is a `usize` mask result so the `>= 0` branch
    // always enters, but when `remaining_bits == 0` the mask
    // `(1u8 << 0) - 1` evaluates to `0`, so `(last_byte & 0).count_ones()`
    // adds zero — observationally identical to the short-circuit.
    #[cfg_attr(test, mutants::skip)]
    #[must_use]
    pub fn allocated_count(&self) -> u32 {
        let total_bits = usize::try_from(self.cluster_count).unwrap_or(usize::MAX);
        let full_bytes = total_bits / 8;
        let remaining_bits = total_bits % 8;

        let mut count: u32 = self.data[..full_bytes.min(self.data.len())]
            .iter()
            .map(|b| b.count_ones())
            .sum();

        if remaining_bits > 0
            && let Some(&last_byte) = self.data.get(full_bytes)
        {
            let mask = (1u8 << remaining_bits) - 1;
            count += (last_byte & mask).count_ones();
        }

        count
    }

    /// Returns the total number of free clusters.
    #[must_use]
    pub fn free_count(&self) -> u32 {
        self.cluster_count - self.allocated_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn is_allocated_basic() {
        // Byte 0x05 = 0b00000101 -> clusters 2, 4 allocated; 3 free
        let bitmap = ExFatBitmap::new(vec![0x05, 0x00], 16);
        assert!(bitmap.is_allocated(2).unwrap()); // bit 0
        assert!(!bitmap.is_allocated(3).unwrap()); // bit 1
        assert!(bitmap.is_allocated(4).unwrap()); // bit 2
        assert!(!bitmap.is_allocated(5).unwrap()); // bit 3
    }

    #[test]
    fn is_allocated_rejects_invalid_clusters() {
        let bitmap = ExFatBitmap::new(vec![0xFF], 8);
        assert!(bitmap.is_allocated(0).is_err()); // below 2
        assert!(bitmap.is_allocated(1).is_err()); // below 2
        assert!(bitmap.is_allocated(10).is_err()); // cluster_count+2 = 10, out of range
    }

    #[test]
    fn allocated_and_free_counts() {
        // 0xFF = 8 set bits, 0x03 = 2 set bits -> 10 allocated
        let bitmap = ExFatBitmap::new(vec![0xFF, 0x03], 10);
        assert_eq!(bitmap.allocated_count(), 10);
        assert_eq!(bitmap.free_count(), 0);
    }

    #[test]
    fn allocated_count_capped_at_cluster_count() {
        // 0xFF = 8 set bits but only 5 clusters
        let bitmap = ExFatBitmap::new(vec![0xFF], 5);
        assert_eq!(bitmap.allocated_count(), 5);
        assert_eq!(bitmap.free_count(), 0);
    }

    #[test]
    fn allocated_count_masks_trailing_bits() {
        // 0xFF = 8 set bits, but only 5 clusters exist.
        // Bits 5-7 are beyond cluster_count and must not be counted.
        let bitmap = ExFatBitmap::new(vec![0xFF], 5);
        assert_eq!(bitmap.allocated_count(), 5);
        assert_eq!(bitmap.free_count(), 0);

        // 0xFF, 0xFF = 16 set bits, but only 10 clusters.
        // Second byte bits 2-7 are beyond cluster_count.
        let bitmap = ExFatBitmap::new(vec![0xFF, 0xFF], 10);
        assert_eq!(bitmap.allocated_count(), 10);
        assert_eq!(bitmap.free_count(), 0);

        // 0xFF, 0x07 = 11 set bits, 10 clusters.
        // Second byte bit 2 is beyond cluster_count.
        let bitmap = ExFatBitmap::new(vec![0xFF, 0x07], 10);
        assert_eq!(bitmap.allocated_count(), 10);
    }

    #[test]
    fn free_count_correct() {
        // 0x00 = 0 set bits, 8 clusters
        let bitmap = ExFatBitmap::new(vec![0x00], 8);
        assert_eq!(bitmap.allocated_count(), 0);
        assert_eq!(bitmap.free_count(), 8);
    }

    /// Spec §7.1.5 lists valid clusters as `2..=ClusterCount+1`; the
    /// inclusive upper bound must accept the last valid cluster. This
    /// kills mutations that tighten the range check from `>` to `>=`.
    #[test]
    fn is_allocated_accepts_last_valid_cluster() {
        // cluster_count = 8 -> valid clusters are 2..=9
        let bitmap = ExFatBitmap::new(vec![0xFF, 0x01], 8);
        assert!(
            bitmap.is_allocated(9).is_ok(),
            "cluster_count+1 (= 9) is the highest valid cluster"
        );
    }

    /// Clusters far beyond `cluster_count + 1` must still be rejected;
    /// this kills the `>` → `==` mutation that only flags the exact
    /// `cluster_count + 1 + 1` boundary.
    #[test]
    fn is_allocated_rejects_far_out_of_range() {
        let bitmap = ExFatBitmap::new(vec![0xFF], 8);
        let err = bitmap.is_allocated(100).unwrap_err();
        assert!(matches!(err, ExFatError::InvalidCluster { cluster: 100 }));
    }
}
