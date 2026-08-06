//! Journal checksum primitives.
//!
//! - CSUM_V2/V3 use CRC32C with seed = `crc32c(~0, journal_uuid)`.
//! - COMPAT_CHECKSUM uses CRC32 (IEEE polynomial) with seed 0, computed over
//!   the concatenated data blocks in tag order.
//! - Descriptor/revocation/commit block checksums use the CRC32C seed above
//!   over the block bytes with the checksum field zeroed.

use super::features::JournalChecksumMode;
use crate::checksum::ext4_crc32c;

/// CRC32C seed from the journal UUID.
pub(crate) fn journal_csum_seed(journal_uuid: &[u8; 16]) -> u32 {
    ext4_crc32c(!0, journal_uuid)
}

/// Per-block tag checksum under CSUM_V2/V3.
///
/// Input: `crc32c(seed, BE(sequence) || data_block)`.
/// V2 takes the low 16 bits; V3 keeps the full 32-bit value.
pub(crate) fn tag_block_checksum(
    mode: JournalChecksumMode,
    seed: u32,
    sequence: u32,
    data_block: &[u8],
) -> u32 {
    let mut crc = ext4_crc32c(seed, &sequence.to_be_bytes());
    crc = ext4_crc32c(crc, data_block);
    match mode {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "intentional 16-bit truncation for CSUM_V2"
        )]
        JournalChecksumMode::V2Crc32c => u32::from(crc as u16),
        JournalChecksumMode::V3Crc32c => crc,
        _ => 0,
    }
}

/// Descriptor / revocation tail checksum and commit-block checksum (V2/V3).
///
/// Split-range zero-copy variant: hashes `before` bytes, then 4 zero bytes
/// in place of the stored checksum field, then `after` bytes. Avoids
/// allocating a mutated copy of the block.
pub(crate) fn block_tail_checksum_split(seed: u32, before_csum: &[u8], after_csum: &[u8]) -> u32 {
    let mut crc = ext4_crc32c(seed, before_csum);
    crc = ext4_crc32c(crc, &[0u8; 4]);
    ext4_crc32c(crc, after_csum)
}

/// Incremental CRC32 helper for COMPAT_CHECKSUM commit-block validation.
///
/// Callers create one hasher, push each pending transaction's data block
/// into it in tag order, and compare the final value against the commit
/// block's `h_chksum[0]`. No `Vec<&[u8]>` allocation required.
pub(crate) struct CompatCrc32(crc32fast::Hasher);

impl CompatCrc32 {
    pub(crate) fn new() -> Self {
        Self(crc32fast::Hasher::new())
    }

    pub(crate) fn update(&mut self, block: &[u8]) {
        self.0.update(block);
    }

    pub(crate) fn finalize(self) -> u32 {
        self.0.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn v2_tag_checksum_truncates_to_16_bits() {
        let seed = 0x1234_5678;
        let full = tag_block_checksum(JournalChecksumMode::V3Crc32c, seed, 1, &[0u8; 16]);
        let trunc = tag_block_checksum(JournalChecksumMode::V2Crc32c, seed, 1, &[0u8; 16]);
        assert_eq!(trunc, u32::from(full as u16));
    }

    #[test]
    fn seed_uses_uuid() {
        let uuid = [0u8; 16];
        let seed = journal_csum_seed(&uuid);
        assert_ne!(seed, 0);
    }

    #[test]
    fn compat_commit_empty_data_is_zero() {
        assert_eq!(CompatCrc32::new().finalize(), 0);
    }

    #[test]
    fn compat_commit_matches_known_vector() {
        let v = b"123456789";
        let mut h = CompatCrc32::new();
        h.update(&v[..4]);
        h.update(&v[4..]);
        assert_eq!(h.finalize(), 0xCBF4_3926);
    }

    #[test]
    fn tail_split_matches_zeroed_buffer() {
        let seed = 0xDEAD_BEEF;
        let mut full = vec![0xAAu8; 64];
        full[40..44].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        let mut zeroed = full.clone();
        zeroed[40..44].fill(0);
        let direct = ext4_crc32c(seed, &zeroed);
        let split = block_tail_checksum_split(seed, &full[..40], &full[44..]);
        assert_eq!(direct, split);
    }
}
