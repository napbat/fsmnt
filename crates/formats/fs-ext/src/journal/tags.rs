//! Descriptor block tag on-disk structures and iterator.

use zerocopy::byteorder::U32;
use zerocopy::{BigEndian as BE, FromBytes, Immutable, KnownLayout, Unaligned};

use crate::error::{ExtError, Result};
use crate::journal::features::JournalChecksumMode;

/// Tag flag: first 4 bytes of the data block were the journal magic.
pub(crate) const TAG_FLAG_ESCAPE: u32 = 0x1;
/// Tag flag: UUID omitted (same as previous tag).
pub(crate) const TAG_FLAG_SAME_UUID: u32 = 0x2;
/// Tag flag: block was freed by this transaction (informational).
#[allow(
    dead_code,
    reason = "forensic documentation; jbd2 walkers ignore this bit"
)]
pub(crate) const TAG_FLAG_DELETED: u32 = 0x4;
/// Tag flag: last tag in the descriptor.
pub(crate) const TAG_FLAG_LAST: u32 = 0x8;

/// v3 (`CSUM_V3`) tag: 16-byte body + optional 16-byte UUID.
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical jbd2 t_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct JbdBlockTagV3 {
    pub t_blocknr: U32<BE>,
    pub t_flags: U32<BE>,
    pub t_blocknr_high: U32<BE>,
    pub t_checksum: U32<BE>,
}

/// Pre-v3 (`CSUM_V2` or legacy) tag: 8-byte body, optional 4-byte `blocknr_high`,
/// optional 16-byte UUID.
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical jbd2 t_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct JbdBlockTagLegacy {
    pub t_blocknr: U32<BE>,
    pub t_checksum: [u8; 2],
    pub t_flags: [u8; 2],
}

/// v3 descriptor body length = 16 + (16 if !`SAME_UUID`).
pub(crate) fn tag_len_v3(flags: u32) -> usize {
    if flags & TAG_FLAG_SAME_UUID != 0 {
        16
    } else {
        32
    }
}

/// Legacy descriptor body length = 8 + (4 if 64BIT) + (16 if !`SAME_UUID`).
pub(crate) fn tag_len_legacy(flags: u32, is_64bit: bool) -> usize {
    let base = if is_64bit { 12 } else { 8 };
    base + if flags & TAG_FLAG_SAME_UUID != 0 {
        0
    } else {
        16
    }
}

/// Parsed descriptor tag result.
#[derive(Debug)]
pub(crate) struct ParsedTag {
    pub fs_block: u64,
    pub escape: bool,
    pub last: bool,
    pub checksum: u32,
}

/// Streaming iterator over the tags in a descriptor block's body.
///
/// The body slice is borrowed from the walker's scratch buffer; no tags are
/// copied into owned storage. Each `next()` call yields `Some(Ok(tag))` for
/// a valid tag, `Some(Err(..))` once when the body is structurally invalid
/// (and stops iterating), and `None` after the `TAG_FLAG_LAST` tag has
/// been returned.
pub(crate) struct DescriptorTagIter<'a> {
    body: &'a [u8],
    mode: JournalChecksumMode,
    is_64bit: bool,
    done: bool,
}

impl Iterator for DescriptorTagIter<'_> {
    type Item = Result<ParsedTag>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if self.body.is_empty() {
            self.done = true;
            return Some(Err(ExtError::InvalidJournalSuperblock {
                reason: "descriptor ended without LAST_TAG",
            }));
        }
        let (tag, advance) = if self.mode == JournalChecksumMode::V3Crc32c {
            if self.body.len() < 16 {
                self.done = true;
                return Some(Err(ExtError::InvalidJournalSuperblock {
                    reason: "descriptor body truncated",
                }));
            }
            let raw = JbdBlockTagV3::ref_from_bytes(&self.body[..16]).expect("length checked");
            let flags = raw.t_flags.get();
            let fs_block =
                (u64::from(raw.t_blocknr_high.get()) << 32) | u64::from(raw.t_blocknr.get());
            let parsed = ParsedTag {
                fs_block,
                escape: flags & TAG_FLAG_ESCAPE != 0,
                last: flags & TAG_FLAG_LAST != 0,
                checksum: raw.t_checksum.get(),
            };
            let len = tag_len_v3(flags);
            if self.body.len() < len {
                self.done = true;
                return Some(Err(ExtError::InvalidJournalSuperblock {
                    reason: "descriptor UUID truncated",
                }));
            }
            (parsed, len)
        } else {
            if self.body.len() < 8 {
                self.done = true;
                return Some(Err(ExtError::InvalidJournalSuperblock {
                    reason: "descriptor body truncated",
                }));
            }
            let raw = JbdBlockTagLegacy::ref_from_bytes(&self.body[..8]).expect("length checked");
            let flags = u32::from(u16::from_be_bytes(raw.t_flags));
            let checksum_16 = u16::from_be_bytes(raw.t_checksum);
            let mut fs_block = u64::from(raw.t_blocknr.get());
            let mut consumed = 8usize;
            if self.is_64bit {
                if self.body.len() < 12 {
                    self.done = true;
                    return Some(Err(ExtError::InvalidJournalSuperblock {
                        reason: "descriptor 64BIT high half truncated",
                    }));
                }
                let high = u32::from_be_bytes(self.body[8..12].try_into().expect("fixed slice"));
                fs_block |= u64::from(high) << 32;
                consumed = 12;
            }
            let parsed = ParsedTag {
                fs_block,
                escape: flags & TAG_FLAG_ESCAPE != 0,
                last: flags & TAG_FLAG_LAST != 0,
                checksum: u32::from(checksum_16),
            };
            let total = tag_len_legacy(flags, self.is_64bit);
            if total < consumed || self.body.len() < total {
                self.done = true;
                return Some(Err(ExtError::InvalidJournalSuperblock {
                    reason: "descriptor UUID truncated",
                }));
            }
            (parsed, total)
        };
        self.body = &self.body[advance..];
        if tag.last {
            self.done = true;
        }
        Some(Ok(tag))
    }
}

/// Iterate tag bytes (exclusive of `journal_header` and, when CSUM enabled,
/// exclusive of the 4-byte descriptor tail) without allocating an owned
/// tag vector on the hot path.
pub(crate) fn parse_descriptor_tags(
    body: &[u8],
    mode: JournalChecksumMode,
    is_64bit: bool,
) -> DescriptorTagIter<'_> {
    DescriptorTagIter {
        body,
        mode,
        is_64bit,
        done: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_tag_struct_size() {
        assert_eq!(core::mem::size_of::<JbdBlockTagV3>(), 16);
    }

    #[test]
    fn legacy_tag_struct_size() {
        assert_eq!(core::mem::size_of::<JbdBlockTagLegacy>(), 8);
    }

    #[test]
    fn v3_tag_len_matches_same_uuid_bit() {
        assert_eq!(tag_len_v3(0), 32);
        assert_eq!(tag_len_v3(TAG_FLAG_SAME_UUID), 16);
    }

    #[test]
    fn legacy_tag_len_matches_64bit_and_uuid() {
        assert_eq!(tag_len_legacy(0, false), 24);
        assert_eq!(tag_len_legacy(TAG_FLAG_SAME_UUID, false), 8);
        assert_eq!(tag_len_legacy(0, true), 28);
        assert_eq!(tag_len_legacy(TAG_FLAG_SAME_UUID, true), 12);
    }

    use crate::journal::features::JournalChecksumMode;
    use alloc::vec;
    use alloc::vec::Vec;

    fn make_v3_two_tag_block(block_size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        let off_tag0 = 12;
        buf[off_tag0..off_tag0 + 4].copy_from_slice(&100u32.to_be_bytes());
        buf[off_tag0 + 4..off_tag0 + 8].copy_from_slice(&0u32.to_be_bytes());
        buf[off_tag0 + 8..off_tag0 + 12].copy_from_slice(&0u32.to_be_bytes());
        buf[off_tag0 + 12..off_tag0 + 16].copy_from_slice(&0u32.to_be_bytes());

        let off_tag1 = off_tag0 + 32;
        buf[off_tag1..off_tag1 + 4].copy_from_slice(&200u32.to_be_bytes());
        buf[off_tag1 + 4..off_tag1 + 8]
            .copy_from_slice(&(TAG_FLAG_SAME_UUID | TAG_FLAG_LAST).to_be_bytes());
        buf[off_tag1 + 8..off_tag1 + 12].copy_from_slice(&0u32.to_be_bytes());
        buf[off_tag1 + 12..off_tag1 + 16].copy_from_slice(&0u32.to_be_bytes());
        buf
    }

    fn collect_tags(
        body: &[u8],
        mode: JournalChecksumMode,
        is_64bit: bool,
    ) -> Result<Vec<ParsedTag>> {
        parse_descriptor_tags(body, mode, is_64bit).collect()
    }

    #[test]
    fn walks_v3_descriptor_two_tags() {
        let block_size = 4096;
        let buf = make_v3_two_tag_block(block_size);
        let tags = collect_tags(
            &buf[12..block_size - 4],
            JournalChecksumMode::V3Crc32c,
            false,
        )
        .expect("parse");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].fs_block, 100);
        assert!(!tags[0].escape);
        assert!(!tags[0].last);
        assert_eq!(tags[1].fs_block, 200);
        assert!(tags[1].last);
    }

    #[test]
    fn walks_legacy_non_64bit_two_tags() {
        let block_size = 4096usize;
        let mut buf = vec![0u8; block_size];
        buf[12..16].copy_from_slice(&5u32.to_be_bytes());
        buf[16..18].copy_from_slice(&0u16.to_be_bytes());
        buf[18..20].copy_from_slice(&0u16.to_be_bytes());
        let off1 = 12 + 8 + 16;
        buf[off1..off1 + 4].copy_from_slice(&7u32.to_be_bytes());
        buf[off1 + 4..off1 + 6].copy_from_slice(&0u16.to_be_bytes());
        let flags = u16::try_from(TAG_FLAG_SAME_UUID | TAG_FLAG_LAST)
            .expect("the test fixture value fits in u16");
        buf[off1 + 6..off1 + 8].copy_from_slice(&flags.to_be_bytes());

        let tags = collect_tags(
            &buf[12..block_size - 4],
            JournalChecksumMode::V2Crc32c,
            false,
        )
        .expect("parse legacy");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].fs_block, 5);
        assert_eq!(tags[1].fs_block, 7);
        assert!(tags[1].last);
    }

    #[test]
    fn rejects_body_without_last_tag() {
        let body = vec![0u8; 32];
        let err = collect_tags(&body, JournalChecksumMode::V3Crc32c, false).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::ExtError::InvalidJournalSuperblock {
                    reason: "descriptor ended without LAST_TAG"
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn iterator_stops_after_error() {
        // After yielding Some(Err(..)) once, the iterator must yield None.
        let body = vec![0u8; 32];
        let mut iter = parse_descriptor_tags(&body, JournalChecksumMode::V3Crc32c, false);
        // 32 bytes / 32 bytes-per-tag = 1 tag, plus one error yield on exhaustion.
        // The first yield is a valid (zero) tag without LAST, then an error.
        assert!(iter.next().expect("first yield").is_ok());
        assert!(iter.next().expect("error yield").is_err());
        assert!(iter.next().is_none());
    }
}
