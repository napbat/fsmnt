//! Synthetic FC record/transaction/region builders for unit tests.
//!
//! See spec section 10.2.

#![cfg(test)]
#![expect(
    dead_code,
    reason = "synthetic builders are consumed incrementally by later fast-commit tests"
)]

use alloc::vec::Vec;

use super::tlv::{
    EXT4_NAME_LEN, FC_TAG_ADD_RANGE, FC_TAG_CREAT, FC_TAG_DEL_RANGE, FC_TAG_HEAD, FC_TAG_INODE,
    FC_TAG_LINK, FC_TAG_PAD, FC_TAG_TAIL, FC_TAG_UNLINK, FC_TL_SIZE,
};
use crate::checksum::ext4_crc32c;

/// Compute a per-transaction raw CRC32C with caller-provided chaining seed.
fn fc_crc(seed: u32, data: &[u8]) -> u32 {
    ext4_crc32c(seed, data)
}

/// Construct one TLV with little-endian tag/len header plus payload.
pub(crate) fn fc_tlv(tag: u16, payload: &[u8]) -> Vec<u8> {
    let fc_len = u16::try_from(payload.len()).expect("TLV payload must fit u16 fc_len");
    let mut v = Vec::with_capacity(FC_TL_SIZE + payload.len());
    v.extend_from_slice(&tag.to_le_bytes());
    v.extend_from_slice(&fc_len.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

pub(crate) fn fc_head(features: u32, tid: u32) -> Vec<u8> {
    let mut payload = [0u8; 8];
    payload[0..4].copy_from_slice(&features.to_le_bytes());
    payload[4..8].copy_from_slice(&tid.to_le_bytes());
    fc_tlv(FC_TAG_HEAD, &payload)
}

/// Build a TAIL with total payload length `fc_len_total` (>= 8).
///
/// The first 8 payload bytes are `tid` and `crc`; trailing bytes are zeroed.
pub(crate) fn fc_tail(running_crc: u32, tid: u32, fc_len_total: u16) -> Vec<u8> {
    assert!(fc_len_total >= 8, "TAIL fc_len must be at least 8");
    let mut payload = alloc::vec![0u8; usize::from(fc_len_total)];
    payload[0..4].copy_from_slice(&tid.to_le_bytes());
    payload[4..8].copy_from_slice(&running_crc.to_le_bytes());
    fc_tlv(FC_TAG_TAIL, &payload)
}

/// FC transaction builder. Tracks the running CRC32C internally and emits a
/// final TAIL with the correct CRC at `build()`.
pub(crate) struct FcTxBuilder {
    tid: u32,
    bytes: Vec<u8>,
    running_crc: u32,
    tail_extra_padding: u16,
}

impl FcTxBuilder {
    pub(crate) fn new(tid: u32) -> Self {
        Self {
            tid,
            bytes: Vec::new(),
            running_crc: 0,
            tail_extra_padding: 0,
        }
    }

    pub(crate) fn head(mut self, features: u32) -> Self {
        self.push_crc_tlv(fc_head(features, self.tid));
        self
    }

    pub(crate) fn pad(mut self, len: u16) -> Self {
        self.push_crc_tlv(fc_tlv(FC_TAG_PAD, &alloc::vec![0u8; usize::from(len)]));
        self
    }

    pub(crate) fn inode(mut self, inum: u32, raw_inode: &[u8]) -> Self {
        assert!(
            raw_inode.len() >= 128,
            "INODE builder requires raw_inode >= 128 bytes; build malformed INODE TLVs with fc_tlv directly"
        );
        let mut payload = Vec::with_capacity(4 + raw_inode.len());
        payload.extend_from_slice(&inum.to_le_bytes());
        payload.extend_from_slice(raw_inode);
        self.push_crc_tlv(fc_tlv(FC_TAG_INODE, &payload));
        self
    }

    pub(crate) fn add_range(
        mut self,
        inum: u32,
        ee_block: u32,
        ee_len: u16,
        ee_pblk: u64,
        unwritten: bool,
    ) -> Self {
        let mut payload = [0u8; 16];
        payload[0..4].copy_from_slice(&inum.to_le_bytes());
        payload[4..8].copy_from_slice(&ee_block.to_le_bytes());
        let encoded_len = if unwritten { ee_len | 0x8000 } else { ee_len };
        payload[8..10].copy_from_slice(&encoded_len.to_le_bytes());
        let ee_start_hi = ((ee_pblk >> 32) & 0xFFFF) as u16;
        let ee_start_lo = (ee_pblk & 0xFFFF_FFFF) as u32;
        payload[10..12].copy_from_slice(&ee_start_hi.to_le_bytes());
        payload[12..16].copy_from_slice(&ee_start_lo.to_le_bytes());
        self.push_crc_tlv(fc_tlv(FC_TAG_ADD_RANGE, &payload));
        self
    }

    pub(crate) fn del_range(mut self, inum: u32, lblk: u32, len: u32) -> Self {
        let mut payload = [0u8; 12];
        payload[0..4].copy_from_slice(&inum.to_le_bytes());
        payload[4..8].copy_from_slice(&lblk.to_le_bytes());
        payload[8..12].copy_from_slice(&len.to_le_bytes());
        self.push_crc_tlv(fc_tlv(FC_TAG_DEL_RANGE, &payload));
        self
    }

    pub(crate) fn creat(self, parent: u32, child: u32, name: &[u8]) -> Self {
        self.dentry(FC_TAG_CREAT, parent, child, name)
    }

    pub(crate) fn link(self, parent: u32, child: u32, name: &[u8]) -> Self {
        self.dentry(FC_TAG_LINK, parent, child, name)
    }

    pub(crate) fn unlink(self, parent: u32, child: u32, name: &[u8]) -> Self {
        self.dentry(FC_TAG_UNLINK, parent, child, name)
    }

    /// Add extra zero bytes to the TAIL payload after the `tid` and `crc`.
    pub(crate) fn with_tail_padding(mut self, extra: u16) -> Self {
        self.tail_extra_padding = extra;
        self
    }

    /// Finalize by emitting a TAIL whose CRC covers TL header plus `fc_tid`.
    pub(crate) fn build(mut self) -> Vec<u8> {
        let fc_len = 8u16
            .checked_add(self.tail_extra_padding)
            .expect("TAIL fc_len overflow");
        self.running_crc = fc_crc(self.running_crc, &self.tail_crc_input(fc_len));
        let tail = fc_tail(self.running_crc, self.tid, fc_len);
        self.bytes.extend_from_slice(&tail);
        self.bytes
    }

    /// Build with an intentionally wrong CRC for negative tests.
    pub(crate) fn build_with_bad_crc(mut self) -> Vec<u8> {
        let fc_len = 8u16
            .checked_add(self.tail_extra_padding)
            .expect("TAIL fc_len overflow");
        let tail = fc_tail(0xDEAD_BEEF, self.tid, fc_len);
        self.bytes.extend_from_slice(&tail);
        self.bytes
    }

    fn dentry(mut self, tag: u16, parent: u32, child: u32, name: &[u8]) -> Self {
        assert!(
            !name.is_empty(),
            "dentry builder requires non-empty names; build malformed dentry TLVs with fc_tlv directly"
        );
        assert!(
            name.len() <= usize::from(EXT4_NAME_LEN),
            "dentry name must be <= EXT4_NAME_LEN"
        );
        let mut payload = Vec::with_capacity(8 + name.len());
        payload.extend_from_slice(&parent.to_le_bytes());
        payload.extend_from_slice(&child.to_le_bytes());
        payload.extend_from_slice(name);
        self.push_crc_tlv(fc_tlv(tag, &payload));
        self
    }

    fn push_crc_tlv(&mut self, tlv: Vec<u8>) {
        self.running_crc = fc_crc(self.running_crc, &tlv);
        self.bytes.extend_from_slice(&tlv);
    }

    fn tail_crc_input(&self, fc_len: u16) -> Vec<u8> {
        let mut input = Vec::with_capacity(FC_TL_SIZE + 4);
        input.extend_from_slice(&FC_TAG_TAIL.to_le_bytes());
        input.extend_from_slice(&fc_len.to_le_bytes());
        input.extend_from_slice(&self.tid.to_le_bytes());
        input
    }
}

/// Lay transaction bytes linearly into zero-filled FC blocks.
///
/// Each transaction starts in the current block if it fits there; otherwise
/// the current block's residual bytes stay zeroed and the transaction starts
/// at offset 0 of the next block. Panics if a transaction cannot fit.
pub(crate) fn fc_region(
    transactions: Vec<Vec<u8>>,
    num_fc_blocks: u32,
    block_size: u32,
) -> Vec<Vec<u8>> {
    let block_size = usize::try_from(block_size).expect("block_size must fit usize");
    assert!(block_size > 0, "block_size must be non-zero");
    let block_count = usize::try_from(num_fc_blocks).expect("num_fc_blocks must fit usize");

    let mut blocks: Vec<Vec<u8>> = (0..block_count)
        .map(|_| alloc::vec![0u8; block_size])
        .collect();
    let mut block_idx = 0usize;
    let mut block_off = 0usize;
    for tx in transactions {
        assert!(tx.len() <= block_size, "fc_region: transaction too large");
        if block_off + tx.len() > block_size {
            block_idx += 1;
            block_off = 0;
        }
        assert!(
            block_idx < blocks.len(),
            "fc_region: not enough blocks for transactions"
        );
        blocks[block_idx][block_off..block_off + tx.len()].copy_from_slice(&tx);
        block_off += tx.len();
    }
    blocks
}

#[cfg(test)]
mod self_tests {
    use super::*;
    use crate::journal::fast_commit::tlv::{
        FC_TAG_HEAD, FC_TAG_INODE, FC_TAG_TAIL, TlvIter, decode_tail,
    };

    #[test]
    fn builder_round_trip_with_inode() {
        let bytes = FcTxBuilder::new(100)
            .head(0)
            .inode(2, &[0xCDu8; 128])
            .build();
        let mut it = TlvIter::new(&bytes);
        assert_eq!(it.next().unwrap().tag, FC_TAG_HEAD);
        assert_eq!(it.next().unwrap().tag, FC_TAG_INODE);
        assert_eq!(it.next().unwrap().tag, FC_TAG_TAIL);
        assert!(it.next().is_none());
    }

    #[test]
    fn region_layout_packs_one_tx_into_one_block() {
        let tx = FcTxBuilder::new(1).head(0).build();
        let blocks = fc_region(alloc::vec![tx.clone()], 4, 4096);
        assert_eq!(blocks.len(), 4);
        assert_eq!(&blocks[0][..tx.len()], tx.as_slice());
        assert_eq!(blocks[0][tx.len()], 0u8);
    }

    #[test]
    fn region_layout_starts_next_tx_on_fresh_block_when_current_remainder_too_small() {
        let tx1 = FcTxBuilder::new(1).head(0).pad(24).build();
        let tx2 = FcTxBuilder::new(2).head(0).build();
        assert!(tx1.len() < 64);
        assert!(64 - tx1.len() < tx2.len());

        let blocks = fc_region(alloc::vec![tx1.clone(), tx2.clone()], 2, 64);

        assert_eq!(&blocks[0][..tx1.len()], tx1.as_slice());
        assert!(blocks[0][tx1.len()..].iter().all(|&b| b == 0));
        assert_eq!(&blocks[1][..tx2.len()], tx2.as_slice());
    }

    #[test]
    #[should_panic(expected = "malformed INODE TLVs")]
    fn builder_rejects_short_inode_payload() {
        let _ = FcTxBuilder::new(1).inode(2, &[0u8; 127]);
    }

    #[test]
    #[should_panic(expected = "malformed dentry TLVs")]
    fn builder_rejects_empty_dentry_name() {
        let _ = FcTxBuilder::new(1).creat(2, 3, b"");
    }

    #[test]
    fn builder_tail_crc_excludes_crc_field_and_padding() {
        let head = fc_head(0, 42);
        let mut expected_crc = fc_crc(0, &head);
        let mut tail_crc_input = Vec::with_capacity(FC_TL_SIZE + 4);
        tail_crc_input.extend_from_slice(&FC_TAG_TAIL.to_le_bytes());
        tail_crc_input.extend_from_slice(&12u16.to_le_bytes());
        tail_crc_input.extend_from_slice(&42u32.to_le_bytes());
        expected_crc = fc_crc(expected_crc, &tail_crc_input);

        let bytes = FcTxBuilder::new(42).head(0).with_tail_padding(4).build();
        let tail = TlvIter::new(&bytes).last().expect("tail TLV");
        assert_eq!(tail.tag, FC_TAG_TAIL);
        assert_eq!(tail.fc_len, 12);
        let decoded = decode_tail(tail.payload).expect("decode tail");
        assert_eq!(decoded.crc, expected_crc);
    }
}
