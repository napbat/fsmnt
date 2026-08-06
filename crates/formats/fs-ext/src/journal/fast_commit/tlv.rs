//! Fast-commit TLV on-disk structure and per-record payload decoding.
//!
//! All fields little-endian per `fs/ext4/fast_commit.h`. See spec §4.2.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "consumed by later fast-commit replay tasks")
)]

use crate::error::{ExtError, Result};

/// Tag values per `fs/ext4/fast_commit.h`.
pub(crate) const FC_TAG_ADD_RANGE: u16 = 0x0001;
pub(crate) const FC_TAG_DEL_RANGE: u16 = 0x0002;
pub(crate) const FC_TAG_CREAT: u16 = 0x0003;
pub(crate) const FC_TAG_LINK: u16 = 0x0004;
pub(crate) const FC_TAG_UNLINK: u16 = 0x0005;
pub(crate) const FC_TAG_INODE: u16 = 0x0006;
pub(crate) const FC_TAG_PAD: u16 = 0x0007;
pub(crate) const FC_TAG_TAIL: u16 = 0x0008;
pub(crate) const FC_TAG_HEAD: u16 = 0x0009;

/// `EXT4_FC_TAG_BASE_LEN = sizeof(struct ext4_fc_tl)`.
pub(crate) const FC_TL_SIZE: usize = 4;

/// `EXT4_FC_SUPPORTED_FEATURES` per current kernel (v6.12).
pub(crate) const FC_SUPPORTED_FEATURES: u32 = 0x0;

/// Maximum ext4 directory entry name length (`EXT4_NAME_LEN`).
pub(crate) const EXT4_NAME_LEN: u16 = 255;

/// Validate that `fc_len` is acceptable for `tag` per
/// `ext4_fc_value_len_isvalid`.
///
/// INODE TLVs only check the fixed `fc_ino` + minimum raw inode prefix
/// here. The upper bound depends on runtime `s_inode_size` and is enforced
/// later by the INODE apply handler.
pub(crate) fn fc_value_len_isvalid(tag: u16, fc_len: u16) -> bool {
    match tag {
        FC_TAG_HEAD => fc_len == 8,
        FC_TAG_TAIL => fc_len >= 8,
        FC_TAG_INODE => fc_len >= 4 + 128,
        FC_TAG_CREAT | FC_TAG_LINK | FC_TAG_UNLINK => (9..=8 + EXT4_NAME_LEN).contains(&fc_len),
        FC_TAG_ADD_RANGE => fc_len == 16,
        FC_TAG_DEL_RANGE => fc_len == 12,
        FC_TAG_PAD => true,
        _ => false,
    }
}

/// View into a single TLV in a byte buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    pub tag: u16,
    pub fc_len: u16,
    pub payload: &'a [u8],
}

impl Tlv<'_> {
    /// Total bytes consumed including the 4-byte TL header.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "used by block-local TLV consumers as they land")
    )]
    pub(crate) fn total_len(&self) -> usize {
        FC_TL_SIZE + self.fc_len as usize
    }
}

/// Iterator over TLVs within a single FC block.
pub(crate) struct TlvIter<'a> {
    buf: &'a [u8],
    pos: usize,
    error: Option<TlvDecodeError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlvDecodeError {
    /// Header (4 bytes) doesn't fit in remaining buffer.
    TruncatedHeader { offset: usize },
    /// `fc_len` declared more bytes than remain in the block.
    LengthExceedsBlock {
        offset: usize,
        tag: u16,
        fc_len: u16,
    },
    /// `fc_len` doesn't match the kernel's per-tag validation.
    InvalidLengthForTag {
        offset: usize,
        tag: u16,
        fc_len: u16,
    },
}

impl<'a> TlvIter<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            error: None,
        }
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn error(&self) -> Option<TlvDecodeError> {
        self.error
    }
}

impl<'a> Iterator for TlvIter<'a> {
    type Item = Tlv<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.error.is_some() || self.pos >= self.buf.len() {
            return None;
        }
        if self.pos + FC_TL_SIZE > self.buf.len() {
            self.error = Some(TlvDecodeError::TruncatedHeader { offset: self.pos });
            return None;
        }

        let offset = self.pos;
        let tag = u16::from_le_bytes([self.buf[offset], self.buf[offset + 1]]);
        let fc_len = u16::from_le_bytes([self.buf[offset + 2], self.buf[offset + 3]]);
        let payload_start = offset + FC_TL_SIZE;
        let payload_end = payload_start.saturating_add(fc_len as usize);

        if payload_end > self.buf.len() {
            self.error = Some(TlvDecodeError::LengthExceedsBlock {
                offset,
                tag,
                fc_len,
            });
            return None;
        }
        if !fc_value_len_isvalid(tag, fc_len) {
            self.error = Some(TlvDecodeError::InvalidLengthForTag {
                offset,
                tag,
                fc_len,
            });
            return None;
        }

        self.pos = payload_end;
        Some(Tlv {
            tag,
            fc_len,
            payload: &self.buf[payload_start..payload_end],
        })
    }
}

/// HEAD payload decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FcHead {
    pub features: u32,
    pub tid: u32,
}

/// TAIL payload decoded. Any bytes after the first 8 are ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FcTail {
    pub tid: u32,
    pub crc: u32,
}

/// `ADD_RANGE` payload decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FcAddRange {
    pub fc_ino: u32,
    pub raw_extent: [u8; 12],
}

/// `DEL_RANGE` payload decoded.
#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical ext4 fc_* fast-commit identifiers"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FcDelRange {
    pub fc_ino: u32,
    pub fc_lblk: u32,
    pub fc_len: u32,
}

/// CREAT / LINK / UNLINK payload view.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FcDentry<'a> {
    pub parent_inum: u32,
    pub child_inum: u32,
    pub name: &'a [u8],
}

/// INODE payload view.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FcInode<'a> {
    pub fc_ino: u32,
    pub raw_inode: &'a [u8],
}

pub(crate) fn decode_head(payload: &[u8]) -> Result<FcHead> {
    if payload.len() != 8 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit HEAD payload not 8 bytes",
        });
    }
    Ok(FcHead {
        features: u32::from_le_bytes(payload[0..4].try_into().expect("len 8")),
        tid: u32::from_le_bytes(payload[4..8].try_into().expect("len 8")),
    })
}

pub(crate) fn decode_tail(payload: &[u8]) -> Result<FcTail> {
    if payload.len() < 8 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit TAIL payload < 8 bytes",
        });
    }
    Ok(FcTail {
        tid: u32::from_le_bytes(payload[0..4].try_into().expect("len >= 8")),
        crc: u32::from_le_bytes(payload[4..8].try_into().expect("len >= 8")),
    })
}

pub(crate) fn decode_add_range(payload: &[u8]) -> Result<FcAddRange> {
    if payload.len() != 16 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit ADD_RANGE payload not 16 bytes",
        });
    }
    let mut raw_extent = [0u8; 12];
    raw_extent.copy_from_slice(&payload[4..16]);
    Ok(FcAddRange {
        fc_ino: u32::from_le_bytes(payload[0..4].try_into().expect("len 16")),
        raw_extent,
    })
}

pub(crate) fn decode_del_range(payload: &[u8]) -> Result<FcDelRange> {
    if payload.len() != 12 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit DEL_RANGE payload not 12 bytes",
        });
    }
    Ok(FcDelRange {
        fc_ino: u32::from_le_bytes(payload[0..4].try_into().expect("len 12")),
        fc_lblk: u32::from_le_bytes(payload[4..8].try_into().expect("len 12")),
        fc_len: u32::from_le_bytes(payload[8..12].try_into().expect("len 12")),
    })
}

pub(crate) fn decode_dentry(payload: &[u8]) -> Result<FcDentry<'_>> {
    if payload.len() < 4 + 4 + 1 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit dentry payload < 9 bytes",
        });
    }
    Ok(FcDentry {
        parent_inum: u32::from_le_bytes(payload[0..4].try_into().expect("len >= 9")),
        child_inum: u32::from_le_bytes(payload[4..8].try_into().expect("len >= 9")),
        name: &payload[8..],
    })
}

pub(crate) fn decode_inode(payload: &[u8]) -> Result<FcInode<'_>> {
    if payload.len() < 4 + 128 {
        return Err(ExtError::InvalidJournalSuperblock {
            reason: "fast-commit INODE payload < 132 bytes",
        });
    }
    Ok(FcInode {
        fc_ino: u32::from_le_bytes(payload[0..4].try_into().expect("len >= 132")),
        raw_inode: &payload[4..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::fast_commit::test_support::FcTxBuilder;
    use alloc::vec::Vec;

    #[test]
    fn fc_value_len_accepts_head_8_bytes() {
        assert!(fc_value_len_isvalid(FC_TAG_HEAD, 8));
        assert!(!fc_value_len_isvalid(FC_TAG_HEAD, 7));
        assert!(!fc_value_len_isvalid(FC_TAG_HEAD, 9));
    }

    #[test]
    fn fc_value_len_accepts_tail_at_least_8() {
        assert!(fc_value_len_isvalid(FC_TAG_TAIL, 8));
        assert!(fc_value_len_isvalid(FC_TAG_TAIL, 4096));
        assert!(!fc_value_len_isvalid(FC_TAG_TAIL, 7));
    }

    #[test]
    fn fc_value_len_accepts_inode_at_least_132() {
        assert!(fc_value_len_isvalid(FC_TAG_INODE, 132));
        assert!(fc_value_len_isvalid(FC_TAG_INODE, 256));
        assert!(!fc_value_len_isvalid(FC_TAG_INODE, 131));
    }

    #[test]
    fn fc_value_len_rejects_unknown_tag() {
        assert!(!fc_value_len_isvalid(0x00FF, 4));
        assert!(!fc_value_len_isvalid(0x000A, 8));
    }

    #[test]
    fn fc_value_len_accepts_pad_any_length() {
        assert!(fc_value_len_isvalid(FC_TAG_PAD, 0));
        assert!(fc_value_len_isvalid(FC_TAG_PAD, 4096));
    }

    #[test]
    fn fc_value_len_accepts_add_range_16_bytes() {
        assert!(fc_value_len_isvalid(FC_TAG_ADD_RANGE, 16));
        assert!(!fc_value_len_isvalid(FC_TAG_ADD_RANGE, 15));
    }

    #[test]
    fn fc_value_len_accepts_del_range_12_bytes() {
        assert!(fc_value_len_isvalid(FC_TAG_DEL_RANGE, 12));
        assert!(!fc_value_len_isvalid(FC_TAG_DEL_RANGE, 13));
    }

    #[test]
    fn fc_value_len_accepts_dentry_name_len_one_through_255() {
        for tag in [FC_TAG_CREAT, FC_TAG_LINK, FC_TAG_UNLINK] {
            assert!(!fc_value_len_isvalid(tag, 8));
            assert!(fc_value_len_isvalid(tag, 9));
            assert!(fc_value_len_isvalid(tag, 8 + 255));
            assert!(!fc_value_len_isvalid(tag, 8 + 256));
        }
    }

    fn tlv_bytes(tag: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + payload.len());
        v.extend_from_slice(&tag.to_le_bytes());
        v.extend_from_slice(
            &(u16::try_from(payload.len()).expect("the test fixture value fits in u16"))
                .to_le_bytes(),
        );
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn tlv_iter_yields_two_records_then_stops_at_end() {
        let head = tlv_bytes(FC_TAG_HEAD, &[0u8; 8]);
        let pad = tlv_bytes(FC_TAG_PAD, &[0u8; 4]);
        let mut buf = head.clone();
        buf.extend_from_slice(&pad);

        let mut it = TlvIter::new(&buf);
        let first = it.next().expect("head");
        assert_eq!(first.tag, FC_TAG_HEAD);
        assert_eq!(first.fc_len, 8);
        let second = it.next().expect("pad");
        assert_eq!(second.tag, FC_TAG_PAD);
        assert!(it.next().is_none());
        assert!(it.error().is_none());
    }

    #[test]
    fn iter_parses_full_tx_built_by_builder() {
        let bytes = FcTxBuilder::new(42)
            .head(FC_SUPPORTED_FEATURES)
            .inode(2, &[0xCDu8; 128])
            .add_range(2, 3, 4, 0x1_0000_0005, false)
            .del_range(2, 8, 2)
            .creat(10, 2, b"a.txt")
            .link(11, 2, b"b.txt")
            .unlink(12, 2, b"c.txt")
            .pad(16)
            .build();

        let mut it = TlvIter::new(&bytes);

        let head = it.next().expect("HEAD TLV");
        assert_eq!(head.tag, FC_TAG_HEAD);
        assert_eq!(head.fc_len, 8);
        assert_eq!(decode_head(head.payload).expect("decode HEAD").tid, 42);

        let inode = it.next().expect("INODE TLV");
        assert_eq!(inode.tag, FC_TAG_INODE);
        let inode = decode_inode(inode.payload).expect("decode INODE");
        assert_eq!(inode.fc_ino, 2);
        assert_eq!(inode.raw_inode.len(), 128);

        let add_range = it.next().expect("ADD_RANGE TLV");
        assert_eq!(add_range.tag, FC_TAG_ADD_RANGE);
        assert_eq!(add_range.fc_len, 16);
        assert_eq!(
            decode_add_range(add_range.payload)
                .expect("decode ADD_RANGE")
                .fc_ino,
            2
        );

        let del_range = it.next().expect("DEL_RANGE TLV");
        assert_eq!(del_range.tag, FC_TAG_DEL_RANGE);
        assert_eq!(del_range.fc_len, 12);
        let del_range = decode_del_range(del_range.payload).expect("decode DEL_RANGE");
        assert_eq!(del_range.fc_ino, 2);
        assert_eq!(del_range.fc_lblk, 8);
        assert_eq!(del_range.fc_len, 2);

        let creat = it.next().expect("CREAT TLV");
        assert_eq!(creat.tag, FC_TAG_CREAT);
        let creat = decode_dentry(creat.payload).expect("decode CREAT");
        assert_eq!(creat.parent_inum, 10);
        assert_eq!(creat.child_inum, 2);
        assert_eq!(creat.name, b"a.txt");

        let link = it.next().expect("LINK TLV");
        assert_eq!(link.tag, FC_TAG_LINK);
        let link = decode_dentry(link.payload).expect("decode LINK");
        assert_eq!(link.parent_inum, 11);
        assert_eq!(link.child_inum, 2);
        assert_eq!(link.name, b"b.txt");

        let unlink = it.next().expect("UNLINK TLV");
        assert_eq!(unlink.tag, FC_TAG_UNLINK);
        let unlink = decode_dentry(unlink.payload).expect("decode UNLINK");
        assert_eq!(unlink.parent_inum, 12);
        assert_eq!(unlink.child_inum, 2);
        assert_eq!(unlink.name, b"c.txt");

        let pad = it.next().expect("PAD TLV");
        assert_eq!(pad.tag, FC_TAG_PAD);
        assert_eq!(pad.fc_len, 16);

        let tail = it.next().expect("TAIL TLV");
        assert_eq!(tail.tag, FC_TAG_TAIL);
        assert_eq!(decode_tail(tail.payload).expect("decode TAIL").tid, 42);

        assert!(it.next().is_none());
        assert!(it.error().is_none());
        assert_eq!(it.position(), bytes.len());
    }

    #[test]
    fn iter_handles_variable_length_tail_padding() {
        let bytes = FcTxBuilder::new(42)
            .head(FC_SUPPORTED_FEATURES)
            .with_tail_padding(64)
            .build();

        let mut iter = TlvIter::new(&bytes);
        let tail = iter
            .by_ref()
            .find(|tlv| tlv.tag == FC_TAG_TAIL)
            .expect("TAIL TLV");

        assert_eq!(tail.fc_len, 8 + 64);
        assert!(iter.error().is_none());
    }

    #[test]
    fn iter_consumes_entire_buffer_then_stops_clean() {
        let bytes = FcTxBuilder::new(42).head(FC_SUPPORTED_FEATURES).build();
        let mut iter = TlvIter::new(&bytes);

        while iter.next().is_some() {}

        assert!(iter.error().is_none());
        assert_eq!(iter.position(), bytes.len());
    }

    #[test]
    fn tlv_iter_reports_truncated_header() {
        let buf = [0x09u8, 0x00, 0x08];
        let mut it = TlvIter::new(&buf);
        assert!(it.next().is_none());
        assert_eq!(
            it.error(),
            Some(TlvDecodeError::TruncatedHeader { offset: 0 })
        );
    }

    #[test]
    fn tlv_iter_reports_length_exceeds_block() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&FC_TAG_PAD.to_le_bytes());
        buf.extend_from_slice(&256u16.to_le_bytes());
        buf.extend_from_slice(&[0u8; 4]);
        let mut it = TlvIter::new(&buf);
        assert!(it.next().is_none());
        assert!(matches!(
            it.error(),
            Some(TlvDecodeError::LengthExceedsBlock {
                offset: 0,
                tag,
                fc_len: 256
            }) if tag == FC_TAG_PAD
        ));
    }

    #[test]
    fn tlv_iter_reports_invalid_length_for_tag() {
        let buf = tlv_bytes(FC_TAG_ADD_RANGE, &[0u8; 12]);
        let mut it = TlvIter::new(&buf);
        assert!(it.next().is_none());
        assert!(matches!(
            it.error(),
            Some(TlvDecodeError::InvalidLengthForTag {
                offset: 0,
                tag: FC_TAG_ADD_RANGE,
                fc_len: 12,
            })
        ));
    }

    #[test]
    fn decode_head_extracts_features_and_tid() {
        let mut payload = [0u8; 8];
        payload[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        payload[4..8].copy_from_slice(&100u32.to_le_bytes());
        let h = decode_head(&payload).expect("decode");
        assert_eq!(h.features, 0xDEAD_BEEF);
        assert_eq!(h.tid, 100);
    }

    #[test]
    fn decode_tail_reads_first_8_bytes_only() {
        let mut payload = [0u8; 32];
        payload[0..4].copy_from_slice(&77u32.to_le_bytes());
        payload[4..8].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        let t = decode_tail(&payload).expect("decode");
        assert_eq!(t.tid, 77);
        assert_eq!(t.crc, 0xCAFE_BABE);
    }

    #[test]
    fn decode_add_range_extracts_inum_and_raw_extent() {
        let mut payload = [0u8; 16];
        payload[0..4].copy_from_slice(&12u32.to_le_bytes());
        payload[4] = 0xAB;
        let r = decode_add_range(&payload).expect("decode");
        assert_eq!(r.fc_ino, 12);
        assert_eq!(r.raw_extent[0], 0xAB);
    }

    #[test]
    fn decode_del_range_extracts_inum_lblk_len() {
        let mut payload = [0u8; 12];
        payload[0..4].copy_from_slice(&12u32.to_le_bytes());
        payload[4..8].copy_from_slice(&100u32.to_le_bytes());
        payload[8..12].copy_from_slice(&50u32.to_le_bytes());
        let r = decode_del_range(&payload).expect("decode");
        assert_eq!(r.fc_ino, 12);
        assert_eq!(r.fc_lblk, 100);
        assert_eq!(r.fc_len, 50);
    }

    #[test]
    fn decode_dentry_extracts_parent_child_name() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&12u32.to_le_bytes());
        payload.extend_from_slice(b"hello.txt");
        let d = decode_dentry(&payload).expect("decode");
        assert_eq!(d.parent_inum, 2);
        assert_eq!(d.child_inum, 12);
        assert_eq!(d.name, b"hello.txt");
    }

    #[test]
    fn decode_inode_extracts_inum_and_raw_prefix() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&12u32.to_le_bytes());
        payload.extend_from_slice(&[0xCDu8; 128]);
        let i = decode_inode(&payload).expect("decode");
        assert_eq!(i.fc_ino, 12);
        assert_eq!(i.raw_inode.len(), 128);
        assert_eq!(i.raw_inode[0], 0xCD);
    }

    #[test]
    fn decode_inode_rejects_payload_below_minimum() {
        let payload = [0u8; 100];
        assert!(decode_inode(&payload).is_err());
    }

    /// `total_len` is `FC_TL_SIZE (4) + fc_len`. Killable mutants on
    /// the body include `-> 0`, `-> 1`, `+ -> -`, `+ -> *`. The
    /// existing `tlv_iter_*` tests never call `total_len` because the
    /// iterator advances `pos` directly; we exercise it here.
    #[test]
    fn tlv_total_len_equals_header_size_plus_fc_len() {
        // fc_len = 0 distinguishes `+ -> -` (would underflow) only on
        // a debug build; the more reliable distinguisher is fc_len > 0
        // where `4 + 8 == 12`, `4 - 8` underflows, `4 * 8 == 32`.
        let tlv = Tlv {
            tag: FC_TAG_HEAD,
            fc_len: 8,
            payload: &[0u8; 8],
        };
        assert_eq!(
            tlv.total_len(),
            FC_TL_SIZE + 8,
            "total_len must be 4 + fc_len (kills `+ -> -`, `+ -> *`, and the `-> 0`/`-> 1` body mutants)"
        );
        // A second, non-equal value rules out a constant-body return:
        // `-> 1` would return 1 here too; `-> 0` would return 0.
        let big = Tlv {
            tag: FC_TAG_PAD,
            fc_len: 4096,
            payload: &[],
        };
        assert_eq!(big.total_len(), FC_TL_SIZE + 4096);
        assert_ne!(big.total_len(), tlv.total_len());
    }

    /// `TlvIter::next` rejects with `TruncatedHeader` when the
    /// remaining buffer is strictly shorter than `FC_TL_SIZE` bytes.
    /// The boundary case — exactly `FC_TL_SIZE` bytes remaining — must
    /// parse normally; otherwise the `> -> >=` mutant on line 117
    /// would reject a zero-payload PAD record whose header sits at
    /// the very end of the buffer.
    #[test]
    fn tlv_iter_accepts_header_that_exactly_fills_buffer() {
        // Single 4-byte PAD header with fc_len = 0, no payload.
        // self.pos + FC_TL_SIZE == self.buf.len() (4 == 4) must NOT
        // trigger TruncatedHeader.
        let buf = tlv_bytes(FC_TAG_PAD, &[]);
        assert_eq!(buf.len(), FC_TL_SIZE);

        let mut it = TlvIter::new(&buf);
        let pad = it.next().expect(
            "PAD with fc_len=0 at end of buffer must parse — \
             kills `> -> >=` on the header-fits check",
        );
        assert_eq!(pad.tag, FC_TAG_PAD);
        assert_eq!(pad.fc_len, 0);
        assert!(it.next().is_none());
        assert!(
            it.error().is_none(),
            "no error after consuming clean header"
        );
    }

    /// `decode_dentry` requires the payload to be at least 9 bytes
    /// (`u32 parent + u32 child + ≥1 name byte`). The `< 4 + 4 + 1`
    /// expression has five surviving expression-level mutants
    /// (`< -> ==`, `< -> <=`, `+ -> -` in two positions, `+ -> *`).
    /// Each one shifts the minimum-length boundary; precise length
    /// tests on either side of 9 kill them all.
    #[test]
    fn decode_dentry_boundary_at_nine_bytes_distinguishes_arithmetic_mutants() {
        // Reference: `4 + 4 + 1 = 9` is the inclusive minimum.

        // 8 bytes: rejected by original (`8 < 9`). The `+ -> *` mutant
        // (`4 + 4 * 1 = 8`) would change the boundary to `< 8`, accepting
        // an 8-byte payload (decode_dentry would then read past the
        // header into empty name slice). Original must reject.
        let eight = [0u8; 8];
        assert!(
            decode_dentry(&eight).is_err(),
            "8-byte payload must be rejected — kills `+ -> *` (4+4*1=8) and `< -> <=` (would accept 8)"
        );

        // 9 bytes (minimum): accepted by original. `+ -> -` mutants
        // shift the boundary to 1, 7, or 3; the `< -> ==`/`< -> <=`
        // mutants reject 9 specifically.
        let mut nine = [0u8; 9];
        nine[0..4].copy_from_slice(&123u32.to_le_bytes());
        nine[4..8].copy_from_slice(&456u32.to_le_bytes());
        nine[8] = b'a';
        let d = decode_dentry(&nine).expect(
            "9-byte payload must be accepted — kills `< -> ==` and `< -> <=` \
             (would reject exactly-9-bytes)",
        );
        assert_eq!(d.parent_inum, 123);
        assert_eq!(d.child_inum, 456);
        assert_eq!(d.name, b"a");

        // 17-byte payload also accepted — the `+ -> *` mutant in the
        // OTHER position (`4 * 4 + 1 = 17`) would change the boundary
        // to `< 17`, rejecting our 9-byte minimum but also rejecting
        // anything below 17. We assert acceptance of a 16-byte
        // payload (1-byte short of the mutant boundary) to be sure.
        let mut sixteen = [0u8; 16];
        sixteen[0..4].copy_from_slice(&7u32.to_le_bytes());
        sixteen[4..8].copy_from_slice(&8u32.to_le_bytes());
        sixteen[8..16].copy_from_slice(b"namename");
        let d = decode_dentry(&sixteen).expect(
            "16-byte payload must be accepted — kills `+ -> *` (4*4+1=17 would reject this)",
        );
        assert_eq!(d.parent_inum, 7);
        assert_eq!(d.child_inum, 8);
        assert_eq!(d.name, b"namename");
    }
}
