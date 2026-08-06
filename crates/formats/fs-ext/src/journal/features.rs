//! Journal feature types consumed across the journal module tree.

use bitflags::bitflags;

/// Violation of an invariant enforced at journal parse or replay time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum JournalInvariantKind {
    /// Both `CSUM_V2` and `CSUM_V3` bits set on the journal superblock.
    ChecksumModeConflict,
    /// `ASYNC_COMMIT` set without `CSUM_V2` or `CSUM_V3`.
    AsyncWithoutCsum,
}

/// Orthogonal journal incompat bits that survive into replay behavior.
///
/// `CSUM_V2` / `CSUM_V3` are consumed at parse time and are deliberately
/// absent here - they surface as `JournalChecksumMode`. `FAST_COMMIT` is
/// plumbed through because the post-classic FC phase is gated on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JournalIncompatFeatures(u32);

bitflags! {
    impl JournalIncompatFeatures: u32 {
        const REVOKE       = 0x0001;
        const _64BIT       = 0x0002;
        const ASYNC_COMMIT = 0x0004;
        const FAST_COMMIT  = 0x0020;
    }
}

/// How the journal validates transactions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalChecksumMode {
    /// No checksumming.
    None,
    /// COMPAT_CHECKSUM generation 1: CRC32 over concatenated data blocks in
    /// the commit block's `h_chksum[0]`. No per-tag or tail checksums.
    CompatCrc32,
    /// CSUM_V2: CRC32C per block (16-bit truncated in tag), descriptor and
    /// revocation tails, commit block checksum.
    V2Crc32c,
    /// CSUM_V3: CRC32C per block (full 32-bit in tag), descriptor and
    /// revocation tails, commit block checksum. Otherwise identical to V2.
    V3Crc32c,
}

/// Journal superblock version discriminated by `h_blocktype`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JournalSuperblockVersion {
    /// `h_blocktype == 3`. Only static geometry fields present.
    V1,
    /// `h_blocktype == 4`. Feature flags, UUID, checksum, sharing array.
    V2,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mode_variants_are_distinct() {
        use JournalChecksumMode::*;
        let all = [None, CompatCrc32, V2Crc32c, V3Crc32c];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
    }

    #[test]
    fn incompat_features_empty_has_no_bits() {
        assert_eq!(JournalIncompatFeatures::empty().bits(), 0);
    }

    #[test]
    fn incompat_features_include_expected_bits() {
        assert_eq!(JournalIncompatFeatures::REVOKE.bits(), 0x0001);
        assert_eq!(JournalIncompatFeatures::_64BIT.bits(), 0x0002);
        assert_eq!(JournalIncompatFeatures::ASYNC_COMMIT.bits(), 0x0004);
    }

    #[test]
    fn incompat_features_include_fast_commit_bit() {
        assert_eq!(JournalIncompatFeatures::FAST_COMMIT.bits(), 0x0020);
    }
}
