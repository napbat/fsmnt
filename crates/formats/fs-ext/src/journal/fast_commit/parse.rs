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
    if blocks.is_empty() || blocks[0].len() < FC_TL_SIZE {
        return ScanResult::default();
    }
    let first_tag = u16::from_le_bytes([blocks[0][0], blocks[0][1]]);
    if first_tag != FC_TAG_HEAD {
        return ScanResult::default();
    }
    let mut cursor = RegionCursor::new(blocks);
    let mut state = ScanState::new(block_size, fc_first, expected_tid);
    while !cursor.at_end() && scan_one_record(&mut state, &mut cursor) {}
    if state.result.stop.is_none() && state.transaction_open {
        state.stop(
            state.scan_boundary.0,
            state.scan_boundary.1,
            FastCommitStopReason::RegionExhaustedMidTransaction,
        );
    }
    state.result
}

struct ScanState {
    result: ScanResult,
    transaction_open: bool,
    running_crc: u32,
    pending_tag_count: u32,
    scan_boundary: (usize, usize),
    block_size: u32,
    fc_first: u32,
    expected_tid: u32,
}

impl ScanState {
    fn new(block_size: u32, fc_first: u32, expected_tid: u32) -> Self {
        Self {
            result: ScanResult::default(),
            transaction_open: false,
            running_crc: 0,
            pending_tag_count: 0,
            scan_boundary: (0, 0),
            block_size,
            fc_first,
            expected_tid,
        }
    }

    fn stop(&mut self, relative_block: usize, record_offset: usize, reason: FastCommitStopReason) {
        self.result.stop = Some(stop_at(
            relative_block,
            record_offset,
            self.block_size,
            self.fc_first,
            self.result.last_good_tid,
            reason,
        ));
    }

    fn process_head(
        &mut self,
        relative_block: usize,
        record_offset: usize,
        header: [u8; FC_TL_SIZE],
        payload: &[u8],
        value_len: u16,
    ) -> bool {
        if self.transaction_open {
            self.stop(
                relative_block,
                record_offset,
                malformed(FC_TAG_HEAD, value_len, "nested HEAD"),
            );
            return false;
        }
        let Ok(head) = decode_head(payload) else {
            self.stop(
                relative_block,
                record_offset,
                malformed(FC_TAG_HEAD, value_len, "head decode failure"),
            );
            return false;
        };
        if head.features & !FC_SUPPORTED_FEATURES != 0 {
            self.stop(
                relative_block,
                record_offset,
                FastCommitStopReason::UnsupportedHeadFeatures {
                    features: head.features,
                },
            );
            return false;
        }
        if head.tid != self.expected_tid {
            self.stop(
                relative_block,
                record_offset,
                FastCommitStopReason::HeadTidMismatch {
                    expected: self.expected_tid,
                    seen: head.tid,
                },
            );
            return false;
        }
        self.transaction_open = true;
        self.running_crc = crc_tlv(self.running_crc, header, payload);
        self.pending_tag_count += 1;
        true
    }

    fn process_tail(
        &mut self,
        relative_block: usize,
        record_offset: usize,
        header: [u8; FC_TL_SIZE],
        payload: &[u8],
        value_len: u16,
    ) -> bool {
        let Ok(tail) = decode_tail(payload) else {
            self.stop(
                relative_block,
                record_offset,
                malformed(FC_TAG_TAIL, value_len, "tail decode failure"),
            );
            return false;
        };
        let computed_crc = crc_tail(self.running_crc, header, tail.tid);
        if tail.tid != self.expected_tid || tail.crc != computed_crc {
            self.stop(
                relative_block,
                record_offset,
                FastCommitStopReason::TailChecksumInvalid {
                    tid_seen: tail.tid,
                    tid_expected: self.expected_tid,
                    crc_seen: tail.crc,
                    crc_computed: computed_crc,
                },
            );
            return false;
        }
        self.pending_tag_count += 1;
        self.result.valid_tag_count += self.pending_tag_count;
        self.result.last_good_tid = Some(self.expected_tid);
        self.transaction_open = false;
        self.running_crc = 0;
        self.pending_tag_count = 0;
        true
    }
}

fn malformed(tag: u16, fc_len: u16, reason: &'static str) -> FastCommitStopReason {
    FastCommitStopReason::MalformedRecord {
        tag,
        fc_len,
        reason,
    }
}

fn scan_one_record(state: &mut ScanState, cursor: &mut RegionCursor<'_, '_>) -> bool {
    let (relative_block, record_offset) = cursor.position();
    let mut record_cursor = cursor.clone();
    let Some(header) = record_cursor.read_header() else {
        let reason = if state.transaction_open {
            FastCommitStopReason::RegionExhaustedMidTransaction
        } else {
            malformed(0, 0, "truncated header")
        };
        state.stop(relative_block, record_offset, reason);
        return false;
    };
    let tag = u16::from_le_bytes([header[0], header[1]]);
    let value_len = u16::from_le_bytes([header[2], header[3]]);
    if tag == 0 && value_len == 0 {
        if state.transaction_open {
            state.stop(
                relative_block,
                record_offset,
                FastCommitStopReason::RegionExhaustedMidTransaction,
            );
            return false;
        }
        cursor.advance_to_next_block();
        state.scan_boundary = cursor.position();
        return true;
    }
    if !state.transaction_open && tag != FC_TAG_HEAD {
        let reason = if tag == FC_TAG_TAIL {
            "TAIL without HEAD"
        } else {
            "record outside transaction"
        };
        state.stop(
            relative_block,
            record_offset,
            malformed(tag, value_len, reason),
        );
        return false;
    }
    if !is_supported_record_tag(tag) {
        state.stop(
            relative_block,
            record_offset,
            FastCommitStopReason::UnsupportedTag { tag },
        );
        return false;
    }
    if !fc_value_len_isvalid(tag, value_len) {
        state.stop(
            relative_block,
            record_offset,
            malformed(tag, value_len, "length not valid for tag"),
        );
        return false;
    }
    let Some(payload) = record_cursor.read_exact_vec(usize::from(value_len)) else {
        state.stop(
            relative_block,
            record_offset,
            malformed(tag, value_len, "length exceeds block"),
        );
        return false;
    };
    *cursor = record_cursor;
    state.scan_boundary = cursor.position();
    match tag {
        FC_TAG_HEAD => {
            state.process_head(relative_block, record_offset, header, &payload, value_len)
        }
        FC_TAG_TAIL => {
            state.process_tail(relative_block, record_offset, header, &payload, value_len)
        }
        _ => {
            state.running_crc = crc_tlv(state.running_crc, header, &payload);
            state.pending_tag_count += 1;
            true
        }
    }
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

fn crc_tlv(seed: u32, header: [u8; FC_TL_SIZE], payload: &[u8]) -> u32 {
    ext4_crc32c(ext4_crc32c(seed, &header), payload)
}

fn crc_tail(seed: u32, header: [u8; FC_TL_SIZE], tid: u32) -> u32 {
    ext4_crc32c(ext4_crc32c(seed, &header), &tid.to_le_bytes())
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
    let fc_block = fc_first.saturating_add(
        u32::try_from(rel_block)
            .expect("a fast-commit region cannot contain more than u32::MAX blocks"),
    );
    let block_offset = u32::try_from(block_offset)
        .expect("a fast-commit record offset is bounded by the u32 block size");
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
#[path = "parse_tests/mod.rs"]
mod tests;
