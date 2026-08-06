//! Fast-commit scan pass: validate TLVs and per-transaction CRC32C
//! without mutating any state. See spec §5.1.

use alloc::vec::Vec;

use super::plan::{FastCommitPosition, FastCommitStop, FastCommitStopReason};
use super::tlv::{
    FC_SUPPORTED_FEATURES, FC_TAG_ADD_RANGE, FC_TAG_CREAT, FC_TAG_DEL_RANGE, FC_TAG_HEAD,
    FC_TAG_INODE, FC_TAG_LINK, FC_TAG_PAD, FC_TAG_TAIL, FC_TAG_UNLINK, FC_TL_SIZE, decode_head,
    decode_tail, fc_value_len_isvalid,
};
use crate::checksum::ext4_crc32c;

/// Result of the FC scan pass.
#[derive(Debug, Default)]
pub(crate) struct ScanResult {
    /// Tags in transactions whose TAILs validated.
    pub valid_tag_count: u32,
    /// TID carried by the final validated TAIL.
    pub last_good_tid: Option<u32>,
    /// Stop reason (None on clean end-of-region).
    pub stop: Option<FastCommitStop>,
}

/// Walk the FC region linearly. Each block is a contiguous slice of
/// `block_size` bytes; total `blocks.len() == effective_num_fc_blocks`.
/// `expected_tid` is compared against every HEAD and TAIL in the region.
/// `fc_first` is the journal-relative block index of the first FC block
/// (used for diagnostic positions).
pub(crate) fn scan_fc_region(
    blocks: &[&[u8]],
    block_size: u32,
    fc_first: u32,
    expected_tid: u32,
) -> ScanResult {
    let mut result = ScanResult::default();
    if blocks.is_empty() || blocks[0].len() < FC_TL_SIZE {
        return result;
    }

    let first_tag = u16::from_le_bytes([blocks[0][0], blocks[0][1]]);
    if first_tag != FC_TAG_HEAD {
        return result;
    }

    let mut cursor = RegionCursor::new(blocks);
    let mut tx_open = false;
    let mut running_crc = 0u32;
    let mut tags_in_pending_tx = 0u32;
    let mut scan_boundary = (0usize, 0usize);

    while !cursor.at_end() {
        let (rel_block, record_offset) = cursor.position();
        let mut record_cursor = cursor.clone();
        let Some(header) = record_cursor.read_header() else {
            result.stop = Some(stop_at(
                rel_block,
                record_offset,
                block_size,
                fc_first,
                result.last_good_tid,
                if tx_open {
                    FastCommitStopReason::RegionExhaustedMidTransaction
                } else {
                    FastCommitStopReason::MalformedRecord {
                        tag: 0,
                        fc_len: 0,
                        reason: "truncated header",
                    }
                },
            ));
            return result;
        };

        let tag = u16::from_le_bytes([header[0], header[1]]);
        let fc_len = u16::from_le_bytes([header[2], header[3]]);

        if tag == 0 && fc_len == 0 {
            if tx_open {
                result.stop = Some(stop_at(
                    rel_block,
                    record_offset,
                    block_size,
                    fc_first,
                    result.last_good_tid,
                    FastCommitStopReason::RegionExhaustedMidTransaction,
                ));
                return result;
            }
            cursor.advance_to_next_block();
            scan_boundary = cursor.position();
            continue;
        }

        if !tx_open && tag != FC_TAG_HEAD {
            let reason = if tag == FC_TAG_TAIL {
                "TAIL without HEAD"
            } else {
                "record outside transaction"
            };
            result.stop = Some(stop_at(
                rel_block,
                record_offset,
                block_size,
                fc_first,
                result.last_good_tid,
                FastCommitStopReason::MalformedRecord {
                    tag,
                    fc_len,
                    reason,
                },
            ));
            return result;
        }

        if !is_supported_record_tag(tag) {
            result.stop = Some(stop_at(
                rel_block,
                record_offset,
                block_size,
                fc_first,
                result.last_good_tid,
                FastCommitStopReason::UnsupportedTag { tag },
            ));
            return result;
        }

        if !fc_value_len_isvalid(tag, fc_len) {
            result.stop = Some(stop_at(
                rel_block,
                record_offset,
                block_size,
                fc_first,
                result.last_good_tid,
                FastCommitStopReason::MalformedRecord {
                    tag,
                    fc_len,
                    reason: "length not valid for tag",
                },
            ));
            return result;
        }

        let Some(payload) = record_cursor.read_exact_vec(usize::from(fc_len)) else {
            result.stop = Some(stop_at(
                rel_block,
                record_offset,
                block_size,
                fc_first,
                result.last_good_tid,
                FastCommitStopReason::MalformedRecord {
                    tag,
                    fc_len,
                    reason: "length exceeds block",
                },
            ));
            return result;
        };
        cursor = record_cursor;
        scan_boundary = cursor.position();

        match tag {
            FC_TAG_HEAD => {
                if tx_open {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::MalformedRecord {
                            tag: FC_TAG_HEAD,
                            fc_len,
                            reason: "nested HEAD",
                        },
                    ));
                    return result;
                }

                let head = match decode_head(&payload) {
                    Ok(head) => head,
                    Err(_) => {
                        result.stop = Some(stop_at(
                            rel_block,
                            record_offset,
                            block_size,
                            fc_first,
                            result.last_good_tid,
                            FastCommitStopReason::MalformedRecord {
                                tag: FC_TAG_HEAD,
                                fc_len,
                                reason: "head decode failure",
                            },
                        ));
                        return result;
                    }
                };

                if head.features & !FC_SUPPORTED_FEATURES != 0 {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::UnsupportedHeadFeatures {
                            features: head.features,
                        },
                    ));
                    return result;
                }
                if head.tid != expected_tid {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::HeadTidMismatch {
                            expected: expected_tid,
                            seen: head.tid,
                        },
                    ));
                    return result;
                }

                tx_open = true;
                running_crc = crc_tlv(running_crc, &header, &payload);
                tags_in_pending_tx += 1;
            }
            FC_TAG_TAIL => {
                if !tx_open {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::MalformedRecord {
                            tag: FC_TAG_TAIL,
                            fc_len,
                            reason: "TAIL without HEAD",
                        },
                    ));
                    return result;
                }

                let tail = match decode_tail(&payload) {
                    Ok(tail) => tail,
                    Err(_) => {
                        result.stop = Some(stop_at(
                            rel_block,
                            record_offset,
                            block_size,
                            fc_first,
                            result.last_good_tid,
                            FastCommitStopReason::MalformedRecord {
                                tag: FC_TAG_TAIL,
                                fc_len,
                                reason: "tail decode failure",
                            },
                        ));
                        return result;
                    }
                };

                let computed = crc_tail(running_crc, &header, tail.tid);
                if tail.tid != expected_tid || tail.crc != computed {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::TailChecksumInvalid {
                            tid_seen: tail.tid,
                            tid_expected: expected_tid,
                            crc_seen: tail.crc,
                            crc_computed: computed,
                        },
                    ));
                    return result;
                }

                tags_in_pending_tx += 1;
                result.valid_tag_count += tags_in_pending_tx;
                result.last_good_tid = Some(expected_tid);
                tx_open = false;
                running_crc = 0;
                tags_in_pending_tx = 0;
            }
            tag => {
                if !tx_open {
                    result.stop = Some(stop_at(
                        rel_block,
                        record_offset,
                        block_size,
                        fc_first,
                        result.last_good_tid,
                        FastCommitStopReason::MalformedRecord {
                            tag,
                            fc_len,
                            reason: "record outside transaction",
                        },
                    ));
                    return result;
                }

                running_crc = crc_tlv(running_crc, &header, &payload);
                tags_in_pending_tx += 1;
            }
        }
    }

    if tx_open {
        result.stop = Some(stop_at(
            scan_boundary.0,
            scan_boundary.1,
            block_size,
            fc_first,
            result.last_good_tid,
            FastCommitStopReason::RegionExhaustedMidTransaction,
        ));
    }

    result
}

fn is_supported_record_tag(tag: u16) -> bool {
    matches!(
        tag,
        FC_TAG_ADD_RANGE
            | FC_TAG_DEL_RANGE
            | FC_TAG_CREAT
            | FC_TAG_LINK
            | FC_TAG_UNLINK
            | FC_TAG_INODE
            | FC_TAG_PAD
            | FC_TAG_TAIL
            | FC_TAG_HEAD
    )
}

fn crc_tlv(seed: u32, header: &[u8; FC_TL_SIZE], payload: &[u8]) -> u32 {
    ext4_crc32c(ext4_crc32c(seed, header), payload)
}

fn crc_tail(seed: u32, header: &[u8; FC_TL_SIZE], tid: u32) -> u32 {
    ext4_crc32c(ext4_crc32c(seed, header), &tid.to_le_bytes())
}

#[derive(Clone)]
pub(super) struct RegionCursor<'blocks, 'data> {
    blocks: &'blocks [&'data [u8]],
    rel_block: usize,
    block_offset: usize,
}

impl<'blocks, 'data> RegionCursor<'blocks, 'data> {
    pub(super) fn new(blocks: &'blocks [&'data [u8]]) -> Self {
        Self {
            blocks,
            rel_block: 0,
            block_offset: 0,
        }
    }

    pub(super) fn position(&self) -> (usize, usize) {
        let (rel_block, block_offset) = self.normalized_position();
        if rel_block < self.blocks.len() {
            (rel_block, block_offset)
        } else {
            let last = self.blocks.len().saturating_sub(1);
            (last, self.blocks.get(last).map_or(0, |block| block.len()))
        }
    }

    fn at_end(&self) -> bool {
        let (rel_block, block_offset) = self.normalized_position();
        rel_block >= self.blocks.len() || block_offset >= self.blocks[rel_block].len()
    }

    pub(super) fn read_header(&mut self) -> Option<[u8; FC_TL_SIZE]> {
        let bytes = self.read_exact_vec(FC_TL_SIZE)?;
        Some(bytes.try_into().expect("read_exact_vec returned 4 bytes"))
    }

    pub(super) fn read_exact_vec(&mut self, len: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            self.normalize();
            if self.rel_block >= self.blocks.len() {
                return None;
            }

            let block = self.blocks[self.rel_block];
            let available = block.len().saturating_sub(self.block_offset);
            if available == 0 {
                return None;
            }

            let take = available.min(len - out.len());
            out.extend_from_slice(&block[self.block_offset..self.block_offset + take]);
            self.block_offset += take;
        }
        self.normalize();
        Some(out)
    }

    pub(super) fn advance_to_next_block(&mut self) {
        self.normalize();
        if self.rel_block < self.blocks.len() {
            self.rel_block += 1;
            self.block_offset = 0;
            self.normalize();
        }
    }

    fn normalize(&mut self) {
        let (rel_block, block_offset) = self.normalized_position();
        self.rel_block = rel_block;
        self.block_offset = block_offset;
    }

    fn normalized_position(&self) -> (usize, usize) {
        let mut rel_block = self.rel_block;
        let mut block_offset = self.block_offset;
        while rel_block + 1 < self.blocks.len() && block_offset >= self.blocks[rel_block].len() {
            rel_block += 1;
            block_offset = 0;
        }
        (rel_block, block_offset)
    }
}

fn stop_at(
    rel_block: usize,
    block_offset: usize,
    block_size: u32,
    fc_first: u32,
    last_committed_tid: Option<u32>,
    reason: FastCommitStopReason,
) -> FastCommitStop {
    let fc_block = fc_first.saturating_add(rel_block as u32);
    let block_offset = block_offset as u32;
    let fs_byte_offset = u64::from(fc_block) * u64::from(block_size) + u64::from(block_offset);
    FastCommitStop {
        position: FastCommitPosition {
            fc_block,
            block_offset,
            fs_byte_offset,
        },
        last_committed_tid,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::journal::FastCommitStopReason;
    use crate::journal::fast_commit::test_support::{FcTxBuilder, fc_head, fc_region, fc_tlv};
    use crate::journal::fast_commit::tlv::{
        FC_TAG_HEAD, FC_TAG_INODE, FC_TAG_PAD, FC_TAG_TAIL, FC_TL_SIZE,
    };

    const BS: u32 = 4096;
    const FC_FIRST: u32 = 100;

    fn run_scan(blocks: &[Vec<u8>], expected_tid: u32) -> ScanResult {
        let refs: Vec<&[u8]> = blocks.iter().map(Vec::as_slice).collect();
        scan_fc_region(&refs, BS, FC_FIRST, expected_tid)
    }

    fn fc_region_allowing_large_tx(
        transactions: Vec<Vec<u8>>,
        num_fc_blocks: u32,
        block_size: u32,
    ) -> Vec<Vec<u8>> {
        let block_size = usize::try_from(block_size).expect("block_size must fit usize");
        let block_count = usize::try_from(num_fc_blocks).expect("num_fc_blocks must fit usize");
        let mut blocks = alloc::vec![alloc::vec![0u8; block_size]; block_count];
        let mut cursor = 0usize;
        for tx in transactions {
            assert!(
                cursor + tx.len() <= block_count * block_size,
                "fc_region: not enough blocks for transactions"
            );
            let mut tx_offset = 0usize;
            while tx_offset < tx.len() {
                let block_idx = cursor / block_size;
                let block_off = cursor % block_size;
                let chunk_len = (block_size - block_off).min(tx.len() - tx_offset);
                blocks[block_idx][block_off..block_off + chunk_len]
                    .copy_from_slice(&tx[tx_offset..tx_offset + chunk_len]);
                cursor += chunk_len;
                tx_offset += chunk_len;
            }
        }
        blocks
    }

    #[test]
    fn empty_region_returns_zero_tags_no_stop() {
        let blocks = alloc::vec![alloc::vec![0u8; BS as usize]; 4];
        let r = run_scan(&blocks, 100);
        assert_eq!(r.valid_tag_count, 0);
        assert!(r.last_good_tid.is_none());
        assert!(r.stop.is_none());
    }

    #[test]
    fn one_valid_tx_validates_and_counts_tags() {
        let tx = FcTxBuilder::new(100).head(0).inode(2, &[0u8; 128]).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);
        assert_eq!(r.last_good_tid, Some(100));
        assert!(r.stop.is_none());
        assert_eq!(r.valid_tag_count, 3);
    }

    #[test]
    fn multiple_valid_txs_validate_with_shared_expected_tid() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let tx2 = FcTxBuilder::new(100).head(0).build();
        let blocks = fc_region(alloc::vec![tx1, tx2], 4, BS);
        let r = run_scan(&blocks, 100);
        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 4);
        assert!(r.stop.is_none());
    }

    #[test]
    fn unsupported_head_features_stops() {
        let tx = FcTxBuilder::new(100).head(0xFF).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);
        assert!(r.last_good_tid.is_none());
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::UnsupportedHeadFeatures { features: 0xFF }),
        ));
    }

    #[test]
    fn head_tid_mismatch_stops() {
        let tx = FcTxBuilder::new(999).head(0).build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::HeadTidMismatch {
                expected: 100,
                seen: 999
            }),
        ));
    }

    #[test]
    fn second_head_with_mismatched_tid_stops() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let tx2 = FcTxBuilder::new(101).head(0).build();
        let blocks = fc_region(alloc::vec![tx1, tx2], 4, BS);
        let r = run_scan(&blocks, 100);

        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 2);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::HeadTidMismatch {
                expected: 100,
                seen: 101
            }),
        ));
    }

    #[test]
    fn bad_tail_crc_stops_with_last_good_tid_preserved() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let tx2 = FcTxBuilder::new(100).head(0).build_with_bad_crc();
        let blocks = fc_region(alloc::vec![tx1, tx2], 4, BS);
        let r = run_scan(&blocks, 100);
        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 2);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::TailChecksumInvalid { .. }),
        ));
    }

    #[test]
    fn nested_head_stops_without_committing_pending_transaction() {
        let mut tx = fc_head(0, 100);
        let nested_head_offset = tx.len();
        tx.extend_from_slice(&fc_head(0, 100));
        tx.extend_from_slice(&FcTxBuilder::new(100).head(0).build()[FC_TL_SIZE + 8..]);

        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);

        assert!(r.last_good_tid.is_none());
        assert_eq!(r.valid_tag_count, 0);
        let stop = r.stop.as_ref().expect("nested HEAD stop");
        assert_eq!(stop.position.block_offset, nested_head_offset as u32);
        assert!(matches!(
            stop.reason,
            FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_HEAD,
                fc_len: 8,
                reason: "nested HEAD",
            },
        ));
    }

    #[test]
    fn standalone_tail_after_committed_tx_stops_without_losing_committed_state() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let mut tail = FcTxBuilder::new(100).head(0).build();
        tail.drain(..FC_TL_SIZE + 8);
        let mut blocks = fc_region(alloc::vec![tx1], 4, BS);
        blocks[1][..tail.len()].copy_from_slice(&tail);

        let r = run_scan(&blocks, 100);

        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 2);
        let stop = r.stop.as_ref().expect("TAIL without HEAD stop");
        assert_eq!(stop.position.block_offset, 0);
        assert!(matches!(
            stop.reason,
            FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_TAIL,
                fc_len: 8,
                reason: "TAIL without HEAD",
            },
        ));
    }

    #[test]
    fn standalone_record_after_committed_tx_stops_without_losing_committed_state() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let record = fc_tlv(FC_TAG_PAD, &[0u8; 4]);
        let mut blocks = fc_region(alloc::vec![tx1], 4, BS);
        blocks[1][..record.len()].copy_from_slice(&record);

        let r = run_scan(&blocks, 100);

        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 2);
        let stop = r.stop.as_ref().expect("record outside transaction stop");
        assert_eq!(stop.position.block_offset, 0);
        assert!(matches!(
            stop.reason,
            FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_PAD,
                fc_len: 4,
                reason: "record outside transaction",
            },
        ));
    }

    #[test]
    fn truncated_or_malformed_length_stops_as_malformed_record() {
        let mut blocks = alloc::vec![alloc::vec![0u8; BS as usize]; 1];
        blocks[0][0..2].copy_from_slice(&FC_TAG_HEAD.to_le_bytes());
        blocks[0][2..4].copy_from_slice(&7u16.to_le_bytes());

        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_HEAD,
                fc_len: 7,
                ..
            }),
        ));
    }

    #[test]
    fn unknown_tag_outside_transaction_stops_as_malformed_after_committed_tx() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let mut blocks = fc_region(alloc::vec![tx1], 4, BS);
        blocks[1][0..2].copy_from_slice(&0x00FFu16.to_le_bytes());
        blocks[1][2..4].copy_from_slice(&0u16.to_le_bytes());
        let r = run_scan(&blocks, 100);
        assert_eq!(r.last_good_tid, Some(100));
        assert_eq!(r.valid_tag_count, 2);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::MalformedRecord {
                tag: 0x00FF,
                fc_len: 0,
                reason: "record outside transaction",
            }),
        ));
    }

    #[test]
    fn unknown_tag_inside_open_transaction_stops_as_unsupported_tag() {
        let mut blocks = fc_region(alloc::vec![fc_head(0, 100)], 4, BS);
        let off = FC_TL_SIZE + 8;
        blocks[0][off..off + 2].copy_from_slice(&0x00FFu16.to_le_bytes());
        blocks[0][off + 2..off + 4].copy_from_slice(&0u16.to_le_bytes());

        let r = run_scan(&blocks, 100);
        assert!(r.last_good_tid.is_none());
        assert_eq!(r.valid_tag_count, 0);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::UnsupportedTag { tag: 0x00FF }),
        ));
    }

    #[test]
    fn region_exhausted_mid_tx_emits_stop() {
        let blocks = fc_region(alloc::vec![fc_head(0, 100)], 4, BS);
        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::RegionExhaustedMidTransaction),
        ));
        assert!(r.last_good_tid.is_none());
    }

    #[test]
    fn region_exhausted_at_end_of_final_block_reports_scan_boundary() {
        let block_size = 12;
        let block = fc_head(0, 100);
        assert_eq!(block.len(), block_size as usize);
        let refs = alloc::vec![block.as_slice()];

        let r = scan_fc_region(&refs, block_size, FC_FIRST, 100);

        let stop = r.stop.expect("region exhausted stop");
        assert!(matches!(
            stop.reason,
            FastCommitStopReason::RegionExhaustedMidTransaction
        ));
        assert_eq!(stop.position.fc_block, FC_FIRST);
        assert_eq!(stop.position.block_offset, block_size);
        assert_eq!(
            stop.position.fs_byte_offset,
            u64::from(FC_FIRST) * u64::from(block_size) + u64::from(block_size)
        );
        assert!(r.last_good_tid.is_none());
        assert_eq!(r.valid_tag_count, 0);
    }

    #[test]
    fn first_tag_not_head_returns_clean_with_no_tags() {
        let blocks = fc_region(alloc::vec![fc_tlv(FC_TAG_PAD, &[])], 4, BS);
        let r = run_scan(&blocks, 100);
        assert_eq!(r.valid_tag_count, 0);
        assert!(r.stop.is_none());
    }

    #[test]
    fn non_tail_valid_record_contributes_to_crc_and_pending_count() {
        let tx = FcTxBuilder::new(100)
            .head(0)
            .pad(4)
            .inode(2, &[0u8; 128])
            .build();
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);
        assert_eq!(r.valid_tag_count, 4);
        assert_eq!(r.last_good_tid, Some(100));
        assert!(r.stop.is_none());
    }

    #[test]
    fn transaction_split_across_blocks_validates_with_continuous_crc_state() {
        let tx = FcTxBuilder::new(100).head(0).inode(2, &[0u8; 128]).build();
        let split = FC_TL_SIZE + 8;
        let blocks = alloc::vec![tx[..split].to_vec(), tx[split..].to_vec()];

        let r = run_scan(&blocks, 100);

        assert_eq!(r.valid_tag_count, 3);
        assert_eq!(r.last_good_tid, Some(100));
        assert!(r.stop.is_none());
    }

    #[test]
    fn large_transaction_spanning_fc_blocks_validates_with_continuous_crc_state() {
        let raw_inode = [0u8; 128];
        let mut builder = FcTxBuilder::new(100).head(0);
        let inode_count = 31usize;
        for offset in 0..inode_count {
            builder = builder.inode(2 + offset as u32, &raw_inode);
        }
        let tx = builder.build();
        assert!(tx.len() > BS as usize);

        let blocks = fc_region_allowing_large_tx(alloc::vec![tx], 8, BS);
        let r = run_scan(&blocks, 100);

        assert_eq!(r.valid_tag_count, (inode_count + 2) as u32);
        assert_eq!(r.last_good_tid, Some(100));
        assert!(r.stop.is_none());
    }

    #[test]
    fn malformed_length_after_head_stops_as_region_exhausted_mid_tx_for_zero_fill() {
        let mut bytes = FcTxBuilder::new(100).head(0).inode(2, &[0u8; 128]).build();
        bytes.truncate(12 + 4 + 4);
        let blocks = fc_region(alloc::vec![bytes], 4, BS);
        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::RegionExhaustedMidTransaction),
        ));
    }

    #[test]
    fn tail_tid_mismatch_reports_tail_checksum_invalid() {
        let mut tx = FcTxBuilder::new(100).head(0).build();
        let tail_tid_offset = tx.len() - 8;
        tx[tail_tid_offset..tail_tid_offset + 4].copy_from_slice(&101u32.to_le_bytes());
        let blocks = fc_region(alloc::vec![tx], 4, BS);
        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::TailChecksumInvalid {
                tid_seen: 101,
                tid_expected: 100,
                ..
            }),
        ));
    }

    #[test]
    fn malformed_nonzero_length_exceeding_block_stops_as_malformed_record() {
        let mut blocks = alloc::vec![alloc::vec![0u8; BS as usize]; 1];
        let head = fc_head(0, 100);
        blocks[0][..head.len()].copy_from_slice(&head);
        let off = head.len();
        blocks[0][off..off + 2].copy_from_slice(&FC_TAG_INODE.to_le_bytes());
        blocks[0][off + 2..off + 4].copy_from_slice(&(BS as u16).to_le_bytes());

        let r = run_scan(&blocks, 100);
        assert!(matches!(
            r.stop.as_ref().map(|s| s.reason),
            Some(FastCommitStopReason::MalformedRecord {
                tag: FC_TAG_INODE,
                ..
            }),
        ));
    }

    #[test]
    fn stop_position_uses_fc_block_block_offset_and_fs_byte_offset() {
        let tx = FcTxBuilder::new(100).head(0).build();
        let mut blocks = fc_region(alloc::vec![tx], 4, BS);
        blocks[1][0..2].copy_from_slice(&0x00FFu16.to_le_bytes());
        blocks[1][2..4].copy_from_slice(&0u16.to_le_bytes());

        let r = run_scan(&blocks, 100);
        let stop = r.stop.expect("unsupported tag stop");
        assert_eq!(stop.position.fc_block, FC_FIRST + 1);
        assert_eq!(stop.position.block_offset, 0);
        assert_eq!(
            stop.position.fs_byte_offset,
            u64::from(FC_FIRST + 1) * u64::from(BS)
        );
    }

    #[test]
    fn bad_tail_crc_stop_position_points_to_tail_start() {
        let tx1 = FcTxBuilder::new(100).head(0).build();
        let tx2 = FcTxBuilder::new(100).head(0).build_with_bad_crc();
        let tail_offset = FC_TL_SIZE + 8;
        let expected_record_offset = tx1.len() + tail_offset;
        let blocks = fc_region(alloc::vec![tx1, tx2], 4, BS);

        let r = run_scan(&blocks, 100);
        let stop = r.stop.expect("bad tail CRC stop");
        assert_eq!(stop.position.fc_block, FC_FIRST);
        assert_eq!(stop.position.block_offset, expected_record_offset as u32);
    }

    #[test]
    fn tail_record_constant_import_is_used() {
        assert_eq!(FC_TAG_TAIL, 0x0008);
    }

    /// `scan_fc_region`'s initial guard `if blocks.is_empty() ||
    /// blocks[0].len() < FC_TL_SIZE` keeps the `blocks[0]` index on
    /// line 41 safe. Three mutants survive without specific boundary
    /// coverage:
    ///
    /// - `|| -> &&` makes the guard true only when *both* conditions
    ///   hold, so an empty slice would no longer return early and
    ///   would panic on `blocks[0]`.
    /// - `< -> ==` only rejects when the first block is *exactly*
    ///   FC_TL_SIZE bytes.
    /// - `< -> <=` rejects FC_TL_SIZE-byte blocks too.
    ///
    /// We exercise the empty slice (kills `||`) and a 4-byte block
    /// carrying a HEAD tag (kills `< -> ==` and `< -> <=`: a 4-byte
    /// block has the header but not the 8-byte HEAD payload, so the
    /// scan continues to the cursor read and stops with a malformed
    /// record — whereas the `<=`/`==` mutants would return default
    /// with `stop.is_none()`).
    #[test]
    fn scan_fc_region_empty_slice_returns_default_without_panic() {
        let refs: &[&[u8]] = &[];
        let r = scan_fc_region(refs, BS, FC_FIRST, 100);
        assert_eq!(r.valid_tag_count, 0);
        assert!(r.stop.is_none());
        assert!(r.last_good_tid.is_none());
    }

    #[test]
    fn scan_fc_region_four_byte_block_with_head_tag_continues_to_payload_read() {
        // A 4-byte slice containing exactly a HEAD record header (tag
        // 0x0009, fc_len = 8) but no 8-byte payload — the guard at
        // line 37 (`< FC_TL_SIZE`) must NOT reject a block whose length
        // equals FC_TL_SIZE. The scan continues to read the HEAD
        // payload, finds the buffer exhausted, and reports a stop.
        let head_only = alloc::vec![
            (FC_TAG_HEAD & 0xFF) as u8,
            (FC_TAG_HEAD >> 8) as u8,
            8u8,
            0u8,
        ];
        assert_eq!(head_only.len(), FC_TL_SIZE);
        let refs: &[&[u8]] = &[&head_only];
        let r = scan_fc_region(refs, BS, FC_FIRST, 100);
        // Either we get a stop (cursor exhausted while reading the
        // payload) or — at a minimum — the scan does NOT short-circuit
        // at the initial guard. The `< -> ==` / `< -> <=` mutants would
        // hit the guard and return a default ScanResult here.
        assert!(
            r.stop.is_some(),
            "4-byte block containing only a HEAD header must trigger a stop \
             during payload read, not a silent early return — kills `< -> ==` \
             and `< -> <=` on the guard"
        );
    }

    /// `RegionCursor::position()` clamps to the last block when its
    /// internal `rel_block` is past the end. The `< -> <=` mutant on
    /// line 370 would treat `rel_block == blocks.len()` as in-range,
    /// returning `(blocks.len(), block_offset)` instead of the clamped
    /// `(last, last.len())`. We assert against `position()` rather
    /// than `normalized_position()` so the clamping branch itself is
    /// exercised.
    #[test]
    fn region_cursor_position_clamps_to_last_block_past_end() {
        let a: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
        let b: &[u8] = &[10, 11, 12, 13];
        let blocks: alloc::vec::Vec<&[u8]> = alloc::vec![a, b];
        let mut cursor = RegionCursor::new(&blocks);
        // Drain the entire region so rel_block advances past the end.
        let _ = cursor.read_exact_vec(a.len() + b.len()).expect("drain");
        // Force normalize to push rel_block to blocks.len(): the next
        // advance_to_next_block call leaves rel_block == blocks.len().
        cursor.advance_to_next_block();

        let (rel_block, block_offset) = cursor.position();
        // Original clamps to (last=1, last.len()=4).
        // `< -> <=` mutant: `2 <= 2 = T`, returns (2, 0) — out of range.
        assert_eq!(
            rel_block,
            blocks.len() - 1,
            "position() must clamp rel_block to the last in-range block — \
             kills line 370 `< -> <=` which returns blocks.len() instead"
        );
        assert_eq!(
            block_offset,
            blocks[rel_block].len(),
            "position() must return the last block's full length when past-end"
        );
    }

    /// `RegionCursor::advance_to_next_block`'s guard `if rel_block <
    /// blocks.len()` keeps it idempotent past the end. The `< -> <=`
    /// mutant on line 412 fires the increment when rel_block ==
    /// blocks.len(), pushing the internal state to (blocks.len() + 1,
    /// 0). `position()` and `at_end()` mask the difference (clamp /
    /// short-circuit), but `normalized_position()` exposes it directly.
    #[test]
    fn region_cursor_advance_past_end_does_not_overshoot() {
        let a: &[u8] = &[1, 2, 3, 4];
        let blocks: alloc::vec::Vec<&[u8]> = alloc::vec![a];
        let mut cursor = RegionCursor::new(&blocks);
        cursor.advance_to_next_block(); // rel_block -> 1 (== blocks.len())
        cursor.advance_to_next_block(); // must be a no-op; `<=` mutant pushes to 2

        // Direct `normalized_position` observation. Original after
        // two advances reports (1, 0). The `<=` mutant on the second
        // advance pushes rel_block to 2, which normalize then leaves
        // alone (the loop guard rejects rel_block + 1 < blocks.len()
        // for rel_block=2, blocks.len()=1).
        let (rel_block, block_offset) = cursor.normalized_position();
        assert_eq!(
            rel_block,
            blocks.len(),
            "second advance_to_next_block past the end must NOT overshoot — \
             kills line 412 `< -> <=`"
        );
        assert_eq!(block_offset, 0);
    }

    /// `RegionCursor::normalized_position` walks past exhausted
    /// blocks via `while rel_block + 1 < blocks.len() && offset >=
    /// blocks[rel_block].len()`. After fully draining a two-block
    /// region the cursor's last-stored state is `(1, blocks[1].len())`,
    /// where the loop's first iteration would not fire under either
    /// the `< -> <=` or `+ -> *` mutant on line 428: both flip the
    /// loop guard to keep iterating past the last block, ending at
    /// `(blocks.len(), 0)` instead of `(1, blocks[1].len())`.
    /// `position()` then clamps both back to the same observable
    /// value, so we assert directly against `normalized_position()`.
    #[test]
    fn region_cursor_normalized_position_stops_at_last_block_when_fully_drained() {
        let a: &[u8] = &[1, 2, 3, 4];
        let b: &[u8] = &[10, 11, 12, 13];
        let blocks: alloc::vec::Vec<&[u8]> = alloc::vec![a, b];
        let mut cursor = RegionCursor::new(&blocks);

        // Drain both blocks fully (8 bytes total).
        let drained = cursor.read_exact_vec(a.len() + b.len()).expect("drain");
        assert_eq!(drained, alloc::vec![1, 2, 3, 4, 10, 11, 12, 13]);

        // Direct `normalized_position` observation. Original returns
        // `(1, 4)` — the last block's index with its full length.
        // `< -> <=` mutant: `1 + 1 <= 2 = T`, walks one extra step, returns `(2, 0)`.
        // `+ -> *` mutant: `1 * 1 < 2 = T`, walks one extra step, returns `(2, 0)`.
        let (rel_block, block_offset) = cursor.normalized_position();
        assert_eq!(
            rel_block, 1,
            "normalized_position must terminate at the last in-range block — \
             kills line 428 `< -> <=` and `+ -> *`"
        );
        assert_eq!(
            block_offset,
            b.len(),
            "normalized_position must preserve the last block's saturated offset"
        );
    }
}
