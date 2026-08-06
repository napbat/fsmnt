use super::{
    EXTENT_ENTRY_SIZE, EXTENT_HEADER_SIZE, Ext, ExtError, ExtentReplayReason, ExtentSurgeryOutcome,
    IndexRecord, LeafRecord, MAX_EXTENT_DEPTH, MAX_INITIALIZED_EXTENT_LEN,
    MAX_UNWRITTEN_EXTENT_LEN, MutatorError, RawExtent, Result, SurgeryError, UNWRITTEN_FLAG, Vec,
    can_merge, merge_records, parse_header,
};

pub(super) fn checked_header(buf: &[u8], inum: u32) -> Result<crate::extent::RawExtentHeader> {
    if buf.len() < EXTENT_HEADER_SIZE {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    parse_header(buf, inum)
}

pub(super) fn validate_node_header(
    buf: &[u8],
    hdr: crate::extent::RawExtentHeader,
    inum: u32,
) -> Result<()> {
    let entries = usize::from(hdr.eh_entries.get());
    let max = usize::from(hdr.eh_max.get());
    let depth = hdr.eh_depth.get();
    if depth > MAX_EXTENT_DEPTH || entries > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let capacity = buf.len().saturating_sub(EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
    if entries > capacity || max > capacity {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    Ok(())
}

pub(super) fn validate_index_order(buf: &[u8], entries: u16, inum: u32) -> Result<()> {
    let mut previous = None;
    for idx in 0..usize::from(entries) {
        let current = read_index_record(buf, idx, inum)?;
        if let Some(previous) = previous
            && current.logical <= previous
        {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        previous = Some(current.logical);
    }
    Ok(())
}

pub(super) fn choose_child_entry(
    buf: &[u8],
    entries: u16,
    inum: u32,
    logical: u32,
) -> Result<(usize, u64)> {
    if entries == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }

    let mut chosen = read_index_record(buf, 0, inum)?;
    let mut chosen_idx = 0;
    if chosen.logical > logical {
        return Ok((chosen_idx, chosen.child));
    }

    for idx in 1..usize::from(entries) {
        let current = read_index_record(buf, idx, inum)?;
        if current.logical > logical {
            break;
        }
        chosen = current;
        chosen_idx = idx;
    }

    Ok((chosen_idx, chosen.child))
}

pub(super) fn read_index_record(buf: &[u8], idx: usize, inum: u32) -> Result<IndexRecord> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let logical = read_u32_le(buf, off);
    let child_lo = read_u32_le(buf, off + 4);
    let child_hi = read_u16_le(buf, off + 8);
    let child = (u64::from(child_hi) << 32) | u64::from(child_lo);
    Ok(IndexRecord { logical, child })
}

pub(super) fn index_records(buf: &[u8], entries: usize, inum: u32) -> Result<Vec<IndexRecord>> {
    let mut records = Vec::new();
    for idx in 0..entries {
        records.push(read_index_record(buf, idx, inum)?);
    }
    Ok(records)
}

pub(super) fn read_leaf_record(buf: &[u8], idx: usize, inum: u32) -> Result<LeafRecord> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let logical = read_u32_le(buf, off);
    let raw_len = read_u16_le(buf, off + 4);
    let unwritten = raw_len > UNWRITTEN_FLAG;
    let len = if unwritten {
        raw_len - UNWRITTEN_FLAG
    } else {
        raw_len
    };
    if len == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let pblk_hi = read_u16_le(buf, off + 6);
    let pblk_lo = read_u32_le(buf, off + 8);
    let pblk = (u64::from(pblk_hi) << 32) | u64::from(pblk_lo);
    Ok(LeafRecord {
        logical,
        len,
        pblk,
        unwritten,
    })
}

pub(super) fn leaf_records(buf: &[u8], entries: usize, inum: u32) -> Result<Vec<LeafRecord>> {
    let mut records = Vec::new();
    for idx in 0..entries {
        records.push(read_leaf_record(buf, idx, inum)?);
    }
    Ok(records)
}

pub(super) fn validate_leaf_order(buf: &[u8], entries: usize, inum: u32) -> Result<()> {
    let mut previous_end = None;
    for idx in 0..entries {
        let current = read_leaf_record(buf, idx, inum)?;
        let current_end = logical_end(current, inum)?;
        if let Some(previous_end) = previous_end
            && current.logical < previous_end
        {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        previous_end = Some(current_end);
    }
    Ok(())
}

pub(super) fn coalesce_records(
    records: Vec<LeafRecord>,
    blocks_per_cluster: u32,
    inum: u32,
) -> Result<Vec<LeafRecord>> {
    let mut out: Vec<LeafRecord> = Vec::new();
    for record in records {
        if let Some(last) = out.last_mut()
            && can_merge(*last, record, blocks_per_cluster)
        {
            *last = merge_records(*last, record, inum)?;
            continue;
        }
        out.push(record);
    }
    Ok(out)
}

pub(super) fn rewrite_leaf_records(
    buf: &mut [u8],
    records: &[LeafRecord],
    max: usize,
    inum: u32,
) -> Result<()> {
    write_entry_count(buf, records.len(), inum)?;
    for slot in 0..max {
        let off = entry_offset(slot);
        if off + EXTENT_ENTRY_SIZE > buf.len() {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        buf[off..off + EXTENT_ENTRY_SIZE].fill(0);
    }
    for (idx, record) in records.iter().enumerate() {
        write_leaf_record(buf, idx, *record, inum)?;
    }
    Ok(())
}

pub(super) fn rewrite_index_records(
    buf: &mut [u8],
    records: &[IndexRecord],
    max: usize,
    inum: u32,
) -> Result<()> {
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    write_entry_count(buf, records.len(), inum)?;
    for slot in 0..max {
        let off = entry_offset(slot);
        if off + EXTENT_ENTRY_SIZE > buf.len() {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        buf[off..off + EXTENT_ENTRY_SIZE].fill(0);
    }
    for (idx, record) in records.iter().enumerate() {
        write_index_record(buf, idx, *record, inum)?;
    }
    Ok(())
}

/// Capacity of an external extent block, accounting for the 4-byte
/// `ext4_extent_tail` checksum slot (`eh_max = (block_size-12)/12 - 1`).
pub(super) fn external_node_max(ext: &Ext) -> Result<usize> {
    let capacity = usize::try_from(ext.block_size())
        .map_err(|_| ExtError::InvalidExtentHeader { inode: 0 })?
        .checked_sub(EXTENT_HEADER_SIZE)
        .map(|usable| usable / EXTENT_ENTRY_SIZE)
        .ok_or(ExtError::InvalidExtentHeader { inode: 0 })?;
    capacity
        .checked_sub(1)
        .ok_or(ExtError::InvalidExtentHeader { inode: 0 })
}

pub(super) fn write_node_header(
    buf: &mut [u8],
    entries: usize,
    max: usize,
    depth: u16,
    generation: u32,
) {
    buf[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    buf[2..4].copy_from_slice(
        &u16::try_from(entries)
            .expect("an ext extent node has fewer than u16::MAX records")
            .to_le_bytes(),
    );
    buf[4..6].copy_from_slice(
        &u16::try_from(max)
            .expect("an ext extent node has fewer than u16::MAX record slots")
            .to_le_bytes(),
    );
    buf[6..8].copy_from_slice(&depth.to_le_bytes());
    buf[8..12].copy_from_slice(&generation.to_le_bytes());
}

/// Read every leaf record present in `node` (driven by `eh_entries`).
pub(super) fn node_leaf_records(node: &[u8], inum: u32) -> Result<Vec<LeafRecord>> {
    let hdr = checked_header(node, inum)?;
    validate_node_header(node, hdr, inum)?;
    leaf_records(node, usize::from(hdr.eh_entries.get()), inum)
}

/// Read every index record present in `node` (driven by `eh_entries`).
pub(super) fn node_index_records(node: &[u8], inum: u32) -> Result<Vec<IndexRecord>> {
    let hdr = checked_header(node, inum)?;
    validate_node_header(node, hdr, inum)?;
    index_records(node, usize::from(hdr.eh_entries.get()), inum)
}

/// Build a fresh external leaf block holding `records`.
pub(super) fn build_leaf_block(
    ext: &Ext,
    records: &[LeafRecord],
    generation: u32,
    inum: u32,
) -> Result<Vec<u8>> {
    let max = external_node_max(ext)?;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let mut block = alloc::vec![0u8; ext.block_size() as usize];
    write_node_header(&mut block, records.len(), max, 0, generation);
    for (idx, record) in records.iter().enumerate() {
        write_leaf_record(&mut block, idx, *record, inum)?;
    }
    Ok(block)
}

/// Build a fresh external index block holding `records` at `depth`.
pub(super) fn build_index_block(
    ext: &Ext,
    records: &[IndexRecord],
    depth: u16,
    generation: u32,
    inum: u32,
) -> Result<Vec<u8>> {
    let max = external_node_max(ext)?;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let mut block = alloc::vec![0u8; ext.block_size() as usize];
    write_node_header(&mut block, records.len(), max, depth, generation);
    for (idx, record) in records.iter().enumerate() {
        write_index_record(&mut block, idx, *record, inum)?;
    }
    Ok(block)
}

/// Rewrite an existing leaf node's entries in place, preserving its `eh_max`.
pub(super) fn rewrite_node_leaf(node: &[u8], records: &[LeafRecord], inum: u32) -> Result<Vec<u8>> {
    let hdr = checked_header(node, inum)?;
    let max = usize::from(hdr.eh_max.get());
    let mut patched = node.to_vec();
    rewrite_leaf_records(&mut patched, records, max, inum)?;
    Ok(patched)
}

/// Rewrite an existing index node's entries in place, preserving its `eh_max`.
pub(super) fn rewrite_node_index(
    node: &[u8],
    records: &[IndexRecord],
    inum: u32,
) -> Result<Vec<u8>> {
    let hdr = checked_header(node, inum)?;
    let max = usize::from(hdr.eh_max.get());
    let mut patched = node.to_vec();
    rewrite_index_records(&mut patched, records, max, inum)?;
    Ok(patched)
}

/// Build a 60-byte inline index root one level above its single child.
pub(super) fn build_inline_index_root(
    root: &[u8],
    records: &[IndexRecord],
    inum: u32,
) -> Result<Vec<u8>> {
    build_inline_index_root_at_depth(root, records, 1, inum)
}

/// Build a 60-byte inline index root at `depth` holding `records`. The inode
/// `i_block` root holds at most 4 entries.
pub(super) fn build_inline_index_root_at_depth(
    root: &[u8],
    records: &[IndexRecord],
    depth: u16,
    inum: u32,
) -> Result<Vec<u8>> {
    if root.len() != 60 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let max = (60 - EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
    if records.len() > max {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let generation = u32::from_le_bytes(root[8..12].try_into().expect("len 4"));
    let mut new_root = alloc::vec![0u8; 60];
    write_node_header(&mut new_root, records.len(), max, depth, generation);
    for (idx, record) in records.iter().enumerate() {
        write_index_record(&mut new_root, idx, *record, inum)?;
    }
    Ok(new_root)
}

/// Insert `new_entry` into `records` keeping ascending `logical` order. A
/// duplicate logical key is structural corruption.
pub(super) fn insert_index_record_sorted(
    records: &mut Vec<IndexRecord>,
    new_entry: IndexRecord,
    inum: u32,
) -> Result<()> {
    let mut insert_pos = records.len();
    for (idx, record) in records.iter().enumerate() {
        if record.logical == new_entry.logical {
            return Err(ExtError::InvalidExtentHeader { inode: inum });
        }
        if record.logical > new_entry.logical {
            insert_pos = idx;
            break;
        }
    }
    records.insert(insert_pos, new_entry);
    Ok(())
}

pub(super) fn write_index_record(
    buf: &mut [u8],
    idx: usize,
    record: IndexRecord,
    inum: u32,
) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[off..off + 4].copy_from_slice(&record.logical.to_le_bytes());
    let child_bytes = record.child.to_le_bytes();
    buf[off + 4..off + 8].copy_from_slice(&child_bytes[..4]);
    buf[off + 8..off + 10].copy_from_slice(&child_bytes[4..6]);
    buf[off + 10..off + 12].fill(0);
    Ok(())
}

pub(super) fn write_leaf_record(
    buf: &mut [u8],
    idx: usize,
    record: LeafRecord,
    inum: u32,
) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let encoded_len = encode_extent_len(record.len, record.unwritten, inum)?;
    buf[off..off + 4].copy_from_slice(&record.logical.to_le_bytes());
    buf[off + 4..off + 6].copy_from_slice(&encoded_len.to_le_bytes());
    let physical_bytes = record.pblk.to_le_bytes();
    buf[off + 6..off + 8].copy_from_slice(&physical_bytes[4..6]);
    buf[off + 8..off + 12].copy_from_slice(&physical_bytes[..4]);
    Ok(())
}

pub(super) fn write_index_logical(
    buf: &mut [u8],
    idx: usize,
    logical: u32,
    inum: u32,
) -> Result<()> {
    let off = entry_offset(idx);
    if off + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[off..off + 4].copy_from_slice(&logical.to_le_bytes());
    Ok(())
}

pub(super) fn remove_leaf_record(
    buf: &mut [u8],
    idx: usize,
    entries: usize,
    inum: u32,
) -> Result<()> {
    for slot in idx + 1..entries {
        let record = read_leaf_record(buf, slot, inum)?;
        write_leaf_record(buf, slot - 1, record, inum)?;
    }
    let last = entry_offset(entries - 1);
    if last + EXTENT_ENTRY_SIZE > buf.len() {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    buf[last..last + EXTENT_ENTRY_SIZE].fill(0);
    Ok(())
}

pub(super) fn write_entry_count(buf: &mut [u8], entries: usize, inum: u32) -> Result<()> {
    let entries =
        u16::try_from(entries).map_err(|_| ExtError::InvalidExtentHeader { inode: inum })?;
    buf[2..4].copy_from_slice(&entries.to_le_bytes());
    Ok(())
}

pub(super) fn logical_end(record: LeafRecord, inum: u32) -> Result<u32> {
    record
        .logical
        .checked_add(u32::from(record.len))
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })
}

pub(super) fn first_leaf_logical(leaf: &[u8], inum: u32) -> Result<Option<u32>> {
    let hdr = checked_header(leaf, inum)?;
    validate_node_header(leaf, hdr, inum)?;
    if hdr.eh_depth.get() != 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    if hdr.eh_entries.get() == 0 {
        return Ok(None);
    }
    Ok(Some(read_leaf_record(leaf, 0, inum)?.logical))
}

pub(super) fn empty_inline_leaf_root(root: &[u8], inum: u32) -> Result<Vec<u8>> {
    if root.len() != 60 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    let hdr = checked_header(root, inum)?;
    let mut empty = alloc::vec![0u8; 60];
    empty[0..2].copy_from_slice(&hdr.eh_magic.get().to_le_bytes());
    empty[4..6].copy_from_slice(&4u16.to_le_bytes());
    Ok(empty)
}

pub(super) fn extent_len_encodes(len: u16, unwritten: bool) -> bool {
    encode_extent_len(len, unwritten, u32::MAX).is_ok()
}

pub(super) fn encode_extent_len(len: u16, unwritten: bool, inum: u32) -> Result<u16> {
    if len == 0 {
        return Err(ExtError::InvalidExtentHeader { inode: inum });
    }
    if unwritten {
        // ext4 stores unwritten extents as raw ee_len > 0x8000.
        // 0x8000 itself is reserved for initialized length 32768, so
        // the largest encodable unwritten actual length is 32767.
        if len <= MAX_UNWRITTEN_EXTENT_LEN {
            Ok(len + UNWRITTEN_FLAG)
        } else {
            Err(ExtError::InvalidExtentHeader { inode: inum })
        }
    } else if len <= MAX_INITIALIZED_EXTENT_LEN {
        Ok(len)
    } else {
        Err(ExtError::InvalidExtentHeader { inode: inum })
    }
}

pub(super) fn validate_new_extent(inum: u32, ext: RawExtent) -> Result<()> {
    encode_extent_len(ext.ee_len, ext.unwritten, inum)?;
    ext.ee_block
        .checked_add(u32::from(ext.ee_len))
        .ok_or(ExtError::InvalidExtentHeader { inode: inum })?;
    Ok(())
}

pub(super) fn validate_physical_range(ext: &Ext, extent: RawExtent) -> Result<()> {
    if extent.ee_pblk < u64::from(ext.first_data_block) {
        return Err(ExtError::BlockOutOfRange {
            block: extent.ee_pblk,
        });
    }
    let end =
        extent
            .ee_pblk
            .checked_add(u64::from(extent.ee_len))
            .ok_or(ExtError::BlockOutOfRange {
                block: extent.ee_pblk,
            })?;
    if extent.ee_pblk >= ext.blocks_count || end > ext.blocks_count {
        return Err(ExtError::BlockOutOfRange { block: end });
    }
    Ok(())
}

pub(super) fn logical_range_len_for_outcome(lblk_start: u32, lblk_end_inclusive: u32) -> u32 {
    if lblk_start > lblk_end_inclusive {
        return 0;
    }
    let len = u64::from(lblk_end_inclusive) - u64::from(lblk_start) + 1;
    u32::try_from(len).unwrap_or(u32::MAX)
}

impl LeafRecord {
    pub(super) fn from_raw(ext: RawExtent) -> Self {
        Self {
            logical: ext.ee_block,
            len: ext.ee_len,
            pblk: ext.ee_pblk,
            unwritten: ext.unwritten,
        }
    }
}

pub(super) fn entry_offset(idx: usize) -> usize {
    EXTENT_HEADER_SIZE + idx * EXTENT_ENTRY_SIZE
}

pub(super) fn read_u16_le(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().expect("len 2"))
}

pub(super) fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().expect("len 4"))
}

pub(super) fn mutator_error_to_ext(err: MutatorError) -> ExtError {
    match err {
        MutatorError::Ext(err) => err,
        MutatorError::BigallocClusterOverlap { inode, .. } => {
            ExtError::InvalidExtentHeader { inode }
        }
    }
}

pub(super) fn surgery_error_to_outcome(err: SurgeryError) -> Result<ExtentSurgeryOutcome> {
    match err {
        SurgeryError::Failed(reason) => Ok(ExtentSurgeryOutcome::Failed(reason)),
        SurgeryError::RequiresMetadataAllocation => {
            Ok(ExtentSurgeryOutcome::RequiresMetadataAllocation)
        }
        SurgeryError::Ext(err) => structural_error_to_outcome(err),
    }
}

pub(super) fn structural_error_to_outcome(err: ExtError) -> Result<ExtentSurgeryOutcome> {
    match err {
        ExtError::InvalidExtentHeader { .. } => Ok(ExtentSurgeryOutcome::Failed(
            ExtentReplayReason::ExtentHeaderMalformed,
        )),
        ExtError::Io(err) => Err(ExtError::Io(err)),
        err => Err(err),
    }
}
