//! jbd2 superblock on-disk structures and parsing.
//!
//! All multi-byte fields are big-endian. See
//! `crates/fs-ext/docs/jbd2/01-superblock.md` for the authoritative layout.

use zerocopy::byteorder::U32;
use zerocopy::{BigEndian as BE, FromBytes, Immutable, KnownLayout, Unaligned};

use super::features::{
    JournalChecksumMode, JournalIncompatFeatures, JournalInvariantKind, JournalSuperblockVersion,
};
use crate::checksum::ext4_crc32c;
use crate::error::{ExtError, Result};

/// Journal magic number (`0xC03B3998`).
pub(crate) const JBD_MAGIC: u32 = 0xC03B_3998;

/// Offset of the journal superblock within the journal file.
///
/// Retained for documentation; the reader seeks from position 0 implicitly
/// via `ExtFile::read`, so this constant is not referenced directly.
#[expect(dead_code, reason = "forensic documentation of jbd2 layout")]
pub(crate) const JBD_SUPERBLOCK_OFFSET: u64 = 0;

/// 12-byte journal block header present on every jbd2 metadata block.
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical jbd2 h_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct JbdHeader {
    pub h_magic: U32<BE>,
    pub h_blocktype: U32<BE>,
    pub h_sequence: U32<BE>,
}

/// Raw jbd2 superblock. V1 images populate only the first fields up to
/// `s_errno`; later fields (UUID, features, checksum) are valid only in V2.
#[allow(
    dead_code,
    reason = "on-disk padding/reserved fields are populated but never read"
)]
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical jbd2 s_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct JbdSuperblockRaw {
    pub s_header: JbdHeader,          // 0x00
    pub s_blocksize: U32<BE>,         // 0x0C
    pub s_maxlen: U32<BE>,            // 0x10
    pub s_first: U32<BE>,             // 0x14
    pub s_sequence: U32<BE>,          // 0x18
    pub s_start: U32<BE>,             // 0x1C
    pub s_errno: U32<BE>,             // 0x20
    pub s_feature_compat: U32<BE>,    // 0x24 (V2 only)
    pub s_feature_incompat: U32<BE>,  // 0x28
    pub s_feature_ro_compat: U32<BE>, // 0x2C
    pub s_uuid: [u8; 16],             // 0x30
    pub s_nr_users: U32<BE>,          // 0x40
    pub s_dynsuper: U32<BE>,          // 0x44
    pub s_max_transaction: U32<BE>,   // 0x48
    pub s_max_trans_data: U32<BE>,    // 0x4C
    pub s_checksum_type: u8,          // 0x50
    pub s_padding2: [u8; 3],          // 0x51
    pub s_num_fc_blocks: U32<BE>,     // 0x54
    pub s_head: U32<BE>,              // 0x58
    pub s_padding: [U32<BE>; 40],     // 0x5C..0xFC
    pub s_checksum: U32<BE>,          // 0xFC
    pub s_users: [u8; 768],           // 0x100..0x400
}

/// Offset of `s_checksum` within the superblock.
pub(crate) const JBD_SB_CHECKSUM_OFFSET: usize = 0xFC;

/// Validate the journal magic and decode `h_blocktype` into a version.
pub(crate) fn parse_superblock_version(buf: &[u8; 1024]) -> Result<JournalSuperblockVersion> {
    let sb =
        JbdSuperblockRaw::ref_from_bytes(buf).map_err(|_| ExtError::InvalidJournalSuperblock {
            reason: "superblock buffer too short",
        })?;
    if sb.s_header.h_magic.get() != JBD_MAGIC {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "bad magic",
        });
    }
    match sb.s_header.h_blocktype.get() {
        3 => Ok(JournalSuperblockVersion::V1),
        4 => Ok(JournalSuperblockVersion::V2),
        _ => Err(ExtError::InvalidJournalSuperblock {
            reason: "invalid h_blocktype",
        }),
    }
}

/// Verify the jbd2 superblock checksum. Input `buf` contains the full 1024
/// bytes of the journal superblock with `s_checksum` stored at offset 0xFC.
///
/// Callers must only invoke this under `CSUM_V2` or `CSUM_V3`.
pub(crate) fn verify_jbd_superblock_checksum(buf: &[u8; 1024]) -> Result<()> {
    let stored = u32::from_be_bytes(
        buf[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4]
            .try_into()
            .expect("fixed slice"),
    );
    let mut scratch = *buf;
    scratch[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);
    let computed = ext4_crc32c(!0, &scratch);
    if computed == stored {
        Ok(())
    } else {
        Err(ExtError::InvalidJournalSuperblock {
            reason: "superblock checksum invalid",
        })
    }
}

/// Parsed journal superblock — all fields normalized from on-disk bytes.
#[derive(Debug)]
pub(crate) struct JournalSource {
    pub block_size: u32,
    pub maxlen: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub version: JournalSuperblockVersion,
    pub features: JournalIncompatFeatures,
    pub checksum_mode: JournalChecksumMode,
    pub uuid: [u8; 16],
    /// On-disk `s_num_fc_blks` (offset 0x54). Zero on filesystems
    /// without `INCOMPAT_FAST_COMMIT`. The kernel default fallback
    /// (`JBD2_DEFAULT_FAST_COMMIT_BLOCKS = 256`) is applied at usage
    /// time via `effective_num_fc_blocks()`.
    pub num_fc_blocks: u32,
    /// On-disk `s_head` (offset 0x58).
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "consumed by fast-commit replay scanning in Task 11"
        )
    )]
    pub fc_head: u32,
}

/// Kernel default fallback for `s_num_fc_blks` when on-disk value is
/// zero. Matches `include/linux/jbd2.h` `JBD2_DEFAULT_FAST_COMMIT_BLOCKS`.
pub(crate) const JBD2_DEFAULT_FAST_COMMIT_BLOCKS: u32 = 256;

impl JournalSource {
    /// Number of fast-commit blocks to scan, accounting for the
    /// kernel's default fallback when `s_num_fc_blks == 0`. Returns 0
    /// when the journal does not have `INCOMPAT_FAST_COMMIT`.
    pub(crate) fn effective_num_fc_blocks(&self) -> u32 {
        if !self.features.contains(JournalIncompatFeatures::FAST_COMMIT) {
            return 0;
        }
        if self.num_fc_blocks != 0 {
            self.num_fc_blocks
        } else {
            JBD2_DEFAULT_FAST_COMMIT_BLOCKS
        }
    }

    /// Expected TID for the first fast-commit transaction. Matches the
    /// kernel's `info->end_transaction` boundary used by `fc_do_one_pass`.
    pub(crate) fn expected_fc_tid(&self, last_classic_seq: Option<u32>) -> u32 {
        match last_classic_seq {
            Some(last) => last.wrapping_add(1),
            None => self.sequence,
        }
    }
}

const JBD_FEATURE_COMPAT_CHECKSUM: u32 = 0x0001;
const JBD_FEATURE_INCOMPAT_REVOKE: u32 = 0x0001;
const JBD_FEATURE_INCOMPAT_64BIT: u32 = 0x0002;
const JBD_FEATURE_INCOMPAT_ASYNC_COMMIT: u32 = 0x0004;
const JBD_FEATURE_INCOMPAT_CSUM_V2: u32 = 0x0008;
const JBD_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0010;
const JBD_FEATURE_INCOMPAT_FAST_COMMIT: u32 = 0x0020;

const JBD_INCOMPAT_RECOGNIZED: u32 = JBD_FEATURE_INCOMPAT_REVOKE
    | JBD_FEATURE_INCOMPAT_64BIT
    | JBD_FEATURE_INCOMPAT_ASYNC_COMMIT
    | JBD_FEATURE_INCOMPAT_CSUM_V2
    | JBD_FEATURE_INCOMPAT_CSUM_V3
    | JBD_FEATURE_INCOMPAT_FAST_COMMIT;

#[derive(Clone, Copy)]
struct JournalGeometry {
    block_size: u32,
    maxlen: u32,
    first: u32,
}

fn journal_geometry(sb: &JbdSuperblockRaw) -> Result<JournalGeometry> {
    let block_size = sb.s_blocksize.get();
    if block_size < 1024 || !block_size.is_power_of_two() {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "invalid s_blocksize",
        });
    }
    let maxlen = sb.s_maxlen.get();
    if maxlen == 0 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "s_maxlen is zero",
        });
    }
    let first = sb.s_first.get();
    if first >= maxlen {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "s_first >= s_maxlen",
        });
    }
    Ok(JournalGeometry {
        block_size,
        maxlen,
        first,
    })
}

fn checksum_mode_from_features(
    sb: &JbdSuperblockRaw,
    raw_incompat: u32,
) -> Result<JournalChecksumMode> {
    let unknown = raw_incompat & !JBD_INCOMPAT_RECOGNIZED;
    if unknown != 0 {
        return Err(ExtError::JournalUnsupportedFeature { flags: unknown });
    }

    let has_v2 = raw_incompat & JBD_FEATURE_INCOMPAT_CSUM_V2 != 0;
    let has_v3 = raw_incompat & JBD_FEATURE_INCOMPAT_CSUM_V3 != 0;
    if has_v2 && has_v3 {
        return Err(ExtError::JournalInvariant {
            kind: JournalInvariantKind::ChecksumModeConflict,
        });
    }
    let mode = if has_v3 {
        JournalChecksumMode::V3Crc32c
    } else if has_v2 {
        JournalChecksumMode::V2Crc32c
    } else if sb.s_feature_compat.get() & JBD_FEATURE_COMPAT_CHECKSUM != 0 {
        JournalChecksumMode::CompatCrc32
    } else {
        JournalChecksumMode::None
    };
    let modern_checksum = matches!(
        mode,
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c
    );
    if raw_incompat & JBD_FEATURE_INCOMPAT_ASYNC_COMMIT != 0 && !modern_checksum {
        return Err(ExtError::JournalInvariant {
            kind: JournalInvariantKind::AsyncWithoutCsum,
        });
    }
    if modern_checksum && sb.s_checksum_type != 4 {
        return Err(ExtError::JournalUnsupportedChecksumType {
            code: sb.s_checksum_type,
        });
    }
    Ok(mode)
}

fn normalized_incompat_features(raw_incompat: u32) -> JournalIncompatFeatures {
    let mut features = JournalIncompatFeatures::empty();
    if raw_incompat & JBD_FEATURE_INCOMPAT_REVOKE != 0 {
        features |= JournalIncompatFeatures::REVOKE;
    }
    if raw_incompat & JBD_FEATURE_INCOMPAT_64BIT != 0 {
        features |= JournalIncompatFeatures::_64BIT;
    }
    if raw_incompat & JBD_FEATURE_INCOMPAT_ASYNC_COMMIT != 0 {
        features |= JournalIncompatFeatures::ASYNC_COMMIT;
    }
    if raw_incompat & JBD_FEATURE_INCOMPAT_FAST_COMMIT != 0 {
        features |= JournalIncompatFeatures::FAST_COMMIT;
    }
    features
}

/// Parse a jbd2 superblock buffer into a normalized `JournalSource`.
///
/// Applies all Section-2 rejections: bad magic/blocktype, invalid checksum
/// under `CSUM_V2/V3`, unsupported unknown bits, `JournalInvariant`
/// violations, and unsupported checksum type codes.
pub(crate) fn parse_journal_superblock(buf: &[u8; 1024]) -> Result<JournalSource> {
    let version = parse_superblock_version(buf)?;
    let sb = JbdSuperblockRaw::ref_from_bytes(buf).expect("validated by parse_superblock_version");
    let geometry = journal_geometry(sb)?;

    if matches!(version, JournalSuperblockVersion::V1) {
        return Ok(JournalSource {
            block_size: geometry.block_size,
            maxlen: geometry.maxlen,
            first: geometry.first,
            sequence: sb.s_sequence.get(),
            start: sb.s_start.get(),
            version,
            features: JournalIncompatFeatures::empty(),
            checksum_mode: JournalChecksumMode::None,
            uuid: [0u8; 16],
            num_fc_blocks: 0,
            fc_head: 0,
        });
    }

    let raw_incompat = sb.s_feature_incompat.get();
    let checksum_mode = checksum_mode_from_features(sb, raw_incompat)?;

    if matches!(
        checksum_mode,
        JournalChecksumMode::V2Crc32c | JournalChecksumMode::V3Crc32c
    ) {
        verify_jbd_superblock_checksum(buf)?;
    }

    Ok(JournalSource {
        block_size: geometry.block_size,
        maxlen: geometry.maxlen,
        first: geometry.first,
        sequence: sb.s_sequence.get(),
        start: sb.s_start.get(),
        version,
        features: normalized_incompat_features(raw_incompat),
        checksum_mode,
        uuid: sb.s_uuid,
        num_fc_blocks: sb.s_num_fc_blocks.get(),
        fc_head: sb.s_head.get(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn superblock_struct_size_is_1024() {
        assert_eq!(core::mem::size_of::<JbdSuperblockRaw>(), 1024);
    }

    #[test]
    fn header_struct_size_is_12() {
        assert_eq!(core::mem::size_of::<JbdHeader>(), 12);
    }

    #[test]
    fn parses_zeroed_superblock_bytes() {
        let buf = [0u8; 1024];
        let sb =
            JbdSuperblockRaw::ref_from_bytes(&buf).expect("zerocopy should parse any 1024 bytes");
        assert_eq!(sb.s_header.h_magic.get(), 0);
    }

    use crate::error::ExtError;

    fn make_raw_v2() -> [u8; 1024] {
        let mut buf = [0u8; 1024];
        buf[0..4].copy_from_slice(&JBD_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&4u32.to_be_bytes());
        buf[8..12].copy_from_slice(&1u32.to_be_bytes());
        buf[0x0C..0x10].copy_from_slice(&4096u32.to_be_bytes());
        buf[0x10..0x14].copy_from_slice(&32u32.to_be_bytes());
        buf[0x14..0x18].copy_from_slice(&1u32.to_be_bytes());
        buf[0x18..0x1C].copy_from_slice(&1u32.to_be_bytes());
        buf[0x1C..0x20].copy_from_slice(&1u32.to_be_bytes());
        buf
    }

    #[test]
    fn parses_minimal_v2_superblock() {
        let buf = make_raw_v2();
        let parsed = parse_superblock_version(&buf).expect("parse V2");
        assert_eq!(parsed, JournalSuperblockVersion::V2);
    }

    #[test]
    fn parses_minimal_v1_superblock() {
        let mut buf = make_raw_v2();
        buf[4..8].copy_from_slice(&3u32.to_be_bytes());
        let parsed = parse_superblock_version(&buf).expect("parse V1");
        assert_eq!(parsed, JournalSuperblockVersion::V1);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = make_raw_v2();
        buf[0..4].copy_from_slice(&0u32.to_be_bytes());
        let err = parse_superblock_version(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidJournalSuperblock {
                    reason: "bad magic"
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_bad_blocktype() {
        let mut buf = make_raw_v2();
        buf[4..8].copy_from_slice(&99u32.to_be_bytes());
        let err = parse_superblock_version(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidJournalSuperblock {
                    reason: "invalid h_blocktype"
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn v2_superblock_checksum_round_trip() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(&0x10u32.to_be_bytes());
        buf[0x50] = 4;
        let mut scratch = buf;
        scratch[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);
        let expected = crate::checksum::ext4_crc32c(!0, &scratch);
        buf[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&expected.to_be_bytes());
        verify_jbd_superblock_checksum(&buf).expect("valid csum");
    }

    #[test]
    fn v2_superblock_checksum_rejects_bad_value() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(&0x10u32.to_be_bytes());
        buf[0x50] = 4;
        let err = verify_jbd_superblock_checksum(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidJournalSuperblock {
                    reason: "superblock checksum invalid"
                }
            ),
            "got {err:?}",
        );
    }

    use crate::journal::features::{JournalChecksumMode, JournalIncompatFeatures};

    #[test]
    fn parses_v2_csum_v3_source() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(
            &(JBD_FEATURE_INCOMPAT_CSUM_V3
                | JBD_FEATURE_INCOMPAT_64BIT
                | JBD_FEATURE_INCOMPAT_REVOKE)
                .to_be_bytes(),
        );
        buf[0x50] = 4;
        let mut scratch = buf;
        scratch[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);
        let csum = crate::checksum::ext4_crc32c(!0, &scratch);
        buf[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&csum.to_be_bytes());

        let src = parse_journal_superblock(&buf).expect("parse");
        assert_eq!(src.version, JournalSuperblockVersion::V2);
        assert_eq!(src.checksum_mode, JournalChecksumMode::V3Crc32c);
        assert!(src.features.contains(JournalIncompatFeatures::REVOKE));
        assert!(src.features.contains(JournalIncompatFeatures::_64BIT));
        assert_eq!(src.block_size, 4096);
        assert_eq!(src.maxlen, 32);
    }

    #[test]
    fn accepts_fast_commit_and_captures_fc_fields() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(
            &(JBD_FEATURE_INCOMPAT_FAST_COMMIT | JBD_FEATURE_INCOMPAT_CSUM_V3).to_be_bytes(),
        );
        buf[0x50] = 4;
        buf[0x54..0x58].copy_from_slice(&64u32.to_be_bytes());
        buf[0x58..0x5C].copy_from_slice(&7u32.to_be_bytes());
        let mut scratch = buf;
        scratch[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4].fill(0);
        let csum = crate::checksum::ext4_crc32c(!0, &scratch);
        buf[JBD_SB_CHECKSUM_OFFSET..JBD_SB_CHECKSUM_OFFSET + 4]
            .copy_from_slice(&csum.to_be_bytes());

        let src = parse_journal_superblock(&buf).expect("parse fast-commit journal");
        assert!(src.features.contains(JournalIncompatFeatures::FAST_COMMIT));
        assert_eq!(src.num_fc_blocks, 64);
        assert_eq!(src.fc_head, 7);
    }

    #[test]
    fn rejects_unknown_incompat_bits() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        let err = parse_journal_superblock(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::JournalUnsupportedFeature { flags: 0x8000_0000 }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_both_csum_v2_and_v3() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(
            &(JBD_FEATURE_INCOMPAT_CSUM_V2 | JBD_FEATURE_INCOMPAT_CSUM_V3).to_be_bytes(),
        );
        let err = parse_journal_superblock(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::JournalInvariant {
                    kind: JournalInvariantKind::ChecksumModeConflict
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_async_commit_without_csum() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(&JBD_FEATURE_INCOMPAT_ASYNC_COMMIT.to_be_bytes());
        let err = parse_journal_superblock(&buf).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::JournalInvariant {
                    kind: JournalInvariantKind::AsyncWithoutCsum
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn rejects_bad_checksum_type_under_csum_v3() {
        let mut buf = make_raw_v2();
        buf[0x28..0x2C].copy_from_slice(&JBD_FEATURE_INCOMPAT_CSUM_V3.to_be_bytes());
        buf[0x50] = 2;
        let err = parse_journal_superblock(&buf).unwrap_err();
        assert!(
            matches!(err, ExtError::JournalUnsupportedChecksumType { code: 2 }),
            "got {err:?}",
        );
    }

    #[test]
    fn v1_returns_source_with_empty_features() {
        let mut buf = make_raw_v2();
        buf[4..8].copy_from_slice(&3u32.to_be_bytes());
        let src = parse_journal_superblock(&buf).expect("V1 parse");
        assert_eq!(src.version, JournalSuperblockVersion::V1);
        assert_eq!(src.features, JournalIncompatFeatures::empty());
        assert_eq!(src.checksum_mode, JournalChecksumMode::None);
        assert_eq!(src.uuid, [0u8; 16]);
    }
}

#[cfg(test)]
mod source_accessor_tests {
    use super::*;
    use crate::journal::features::{
        JournalChecksumMode, JournalIncompatFeatures, JournalSuperblockVersion,
    };

    fn source_with(num_fc_blocks: u32, features: JournalIncompatFeatures) -> JournalSource {
        JournalSource {
            block_size: 4096,
            maxlen: 8192,
            first: 1,
            sequence: 100,
            start: 0,
            version: JournalSuperblockVersion::V2,
            features,
            checksum_mode: JournalChecksumMode::None,
            uuid: [0u8; 16],
            num_fc_blocks,
            fc_head: 0,
        }
    }

    #[test]
    fn effective_num_fc_blocks_uses_on_disk_value_when_nonzero() {
        let src = source_with(64, JournalIncompatFeatures::FAST_COMMIT);
        assert_eq!(src.effective_num_fc_blocks(), 64);
    }

    #[test]
    fn effective_num_fc_blocks_falls_back_to_kernel_default_when_zero() {
        let src = source_with(0, JournalIncompatFeatures::FAST_COMMIT);
        assert_eq!(src.effective_num_fc_blocks(), 256);
    }

    #[test]
    fn effective_num_fc_blocks_zero_when_feature_absent() {
        let src = source_with(64, JournalIncompatFeatures::empty());
        assert_eq!(src.effective_num_fc_blocks(), 0);
    }

    #[test]
    fn expected_fc_tid_uses_classic_seq_plus_one_when_present() {
        let src = source_with(64, JournalIncompatFeatures::FAST_COMMIT);
        assert_eq!(src.expected_fc_tid(Some(99)), 100);
    }

    #[test]
    fn expected_fc_tid_falls_back_to_source_sequence_when_no_classic_tx() {
        let src = source_with(64, JournalIncompatFeatures::FAST_COMMIT);
        assert_eq!(src.expected_fc_tid(None), 100);
    }

    #[test]
    fn expected_fc_tid_wraps_on_overflow() {
        let mut src = source_with(64, JournalIncompatFeatures::FAST_COMMIT);
        src.sequence = 0;
        assert_eq!(src.expected_fc_tid(Some(u32::MAX)), 0);
    }
}
