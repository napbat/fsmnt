use alloc::vec;
use zerocopy::byteorder::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{Read, Seek, SeekFrom};

/// Magic number present in every extent tree node header.
const EXTENT_MAGIC: u16 = 0xF30A;

/// Maximum extent tree depth (root at depth 5 -> leaves at depth 0).
const MAX_DEPTH: u16 = 5;

/// On-disk extent tree node header (12 bytes).
///
/// Present at the start of every extent tree node: the in-inode root,
/// interior index nodes, and leaf nodes.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawExtentHeader {
    pub eh_magic: U16<LE>,
    pub eh_entries: U16<LE>,
    pub eh_max: U16<LE>,
    pub eh_depth: U16<LE>,
    pub eh_generation: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawExtentHeader>() == 12,
    "RawExtentHeader must be exactly 12 bytes"
);

/// On-disk extent index entry (12 bytes) -- interior node.
///
/// Points to a child node one level deeper in the extent tree.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawExtentIndex {
    pub ei_block: U32<LE>,
    pub ei_leaf_lo: U32<LE>,
    pub ei_leaf_hi: U16<LE>,
    pub _padding: U16<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawExtentIndex>() == 12,
    "RawExtentIndex must be exactly 12 bytes"
);

/// On-disk extent leaf entry (12 bytes).
///
/// Maps a contiguous range of logical blocks to physical blocks.
/// If `ee_len > 32768`, the extent is uninitialized (preallocated).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawExtent {
    pub ee_block: U32<LE>,
    pub ee_len: U16<LE>,
    pub ee_start_hi: U16<LE>,
    pub ee_start_lo: U32<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawExtent>() == 12,
    "RawExtent must be exactly 12 bytes"
);

/// Resolved extent: a contiguous range of physical blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extent {
    pub logical_block: u32,
    pub physical_block: u64,
    pub len: u32,
    pub uninitialized: bool,
}

/// Parse an extent header from a 12-byte slice, validating the magic.
pub(crate) fn parse_header(buf: &[u8], inode: u32) -> Result<RawExtentHeader> {
    let hdr = *RawExtentHeader::ref_from_bytes(&buf[..12])
        .map_err(|_| ExtError::InvalidExtentHeader { inode })?;
    if hdr.eh_magic.get() != EXTENT_MAGIC {
        return Err(ExtError::InvalidExtentHeader { inode });
    }
    Ok(hdr)
}

/// Decode a leaf extent entry into a resolved `Extent`.
pub(crate) fn decode_extent(raw: &RawExtent) -> Extent {
    let ee_len = raw.ee_len.get();
    let uninitialized = ee_len > 32768;
    let len = if uninitialized {
        u32::from(ee_len) - 32768
    } else {
        u32::from(ee_len)
    };
    let physical_block =
        (u64::from(raw.ee_start_hi.get()) << 32) | u64::from(raw.ee_start_lo.get());

    Extent {
        logical_block: raw.ee_block.get(),
        physical_block,
        len,
        uninitialized,
    }
}

/// Compute the physical block address of an index entry's child node.
pub(crate) fn index_child_block(idx: &RawExtentIndex) -> u64 {
    (u64::from(idx.ei_leaf_hi.get()) << 32) | u64::from(idx.ei_leaf_lo.get())
}

/// A tagged allocation from the extent tree, distinguishing leaf data runs
/// from internal index blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExtentAllocation {
    /// A contiguous run of data blocks belonging to one leaf extent.
    Data {
        /// Physical block number of the first block in the run.
        physical_start: u64,
        /// Number of blocks in the run (uninitialized flag already stripped).
        block_len: u32,
        /// `ee_block` value from the on-disk entry. The caller divides by
        /// `blocks_per_cluster` to get the logical cluster number.
        logical_block_start: u32,
    },
    /// An internal extent-tree index block.
    IndexBlock(u64),
}

/// Walk the entire extent tree and emit tagged allocations into `out`.
///
/// Leaf extents are emitted as `ExtentAllocation::Data` with the `ee_block`
/// field preserved so that callers can derive the logical cluster number on
/// bigalloc filesystems. Internal index blocks are emitted as
/// `ExtentAllocation::IndexBlock`. Uninitialized extents are included because
/// the blocks are allocated even if the data is not yet committed; the
/// uninitialized flag is stripped from `block_len`.
///
/// Returns `Err(InvalidExtentHeader)` if any node has a bad magic.
/// Returns `Err(BlockOutOfRange)` if a child pointer exceeds `blocks_count`.
pub(crate) fn collect_tagged_extent_blocks_into<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    i_block: &[u8; 60],
    out: &mut alloc::vec::Vec<ExtentAllocation>,
) -> Result<()> {
    collect_tagged_node(ext, fs, inode, generation, i_block, out)
}

/// Recursive helper: walk one node and emit tagged `ExtentAllocation` entries.
fn collect_tagged_node<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    node: &[u8],
    out: &mut alloc::vec::Vec<ExtentAllocation>,
) -> Result<()> {
    let hdr = parse_header(node, inode)?;
    let depth = hdr.eh_depth.get();
    let entries = hdr.eh_entries.get();

    if depth > MAX_DEPTH {
        return Err(ExtError::InvalidExtentHeader { inode });
    }

    let entry_data = &node[12..];

    if depth == 0 {
        collect_tagged_leaf_blocks(ext, entry_data, entries, out)?;
    } else {
        collect_tagged_index_blocks(ext, fs, inode, generation, entry_data, entries, out)?;
    }

    Ok(())
}

/// Emit `ExtentAllocation::Data` entries for every leaf extent.
fn collect_tagged_leaf_blocks(
    ext: &Ext,
    entry_data: &[u8],
    entries: u16,
    out: &mut alloc::vec::Vec<ExtentAllocation>,
) -> Result<()> {
    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }
        let Some(raw) = RawExtent::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };
        let decoded = decode_extent(raw);
        if decoded.len == 0 {
            continue;
        }
        let first_invalid = if decoded.physical_block >= ext.blocks_count {
            decoded.physical_block
        } else {
            ext.blocks_count
        };
        let last_block = decoded
            .physical_block
            .checked_add(u64::from(decoded.len - 1))
            .ok_or(ExtError::BlockOutOfRange {
                block: first_invalid,
            })?;
        if last_block >= ext.blocks_count {
            return Err(ExtError::BlockOutOfRange {
                block: first_invalid,
            });
        }
        out.push(ExtentAllocation::Data {
            physical_start: decoded.physical_block,
            block_len: decoded.len,
            logical_block_start: decoded.logical_block,
        });
    }
    Ok(())
}

/// Emit `ExtentAllocation::IndexBlock` for each index node and recurse into
/// its child.
fn collect_tagged_index_blocks<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    entry_data: &[u8],
    entries: u16,
    out: &mut alloc::vec::Vec<ExtentAllocation>,
) -> Result<()> {
    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }
        let Some(idx) = RawExtentIndex::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };
        let child_block = index_child_block(idx);
        if child_block >= ext.blocks_count {
            return Err(ExtError::BlockOutOfRange { block: child_block });
        }

        // The index block itself is metadata — tag it accordingly.
        out.push(ExtentAllocation::IndexBlock(child_block));

        let byte_offset = child_block * u64::from(ext.block_size);
        fs.seek(SeekFrom::Start(byte_offset))?;
        let mut buf = vec![0u8; ext.block_size as usize];
        fs.read_exact(&mut buf)?;

        if let Some(seed) = ext.checksum_seed {
            let state = crate::checksum::verify_extent_block(seed, inode, generation, &buf);
            if state != crate::checksum::ChecksumState::Valid {
                return Err(ExtError::InvalidExtentHeader { inode });
            }
        }

        collect_tagged_node(ext, fs, inode, generation, &buf, out)?;
    }
    Ok(())
}

/// Walk the entire extent tree and append every physical block number to `out`.
///
/// Each leaf `Extent` contributes `extent.physical_block .. physical_block + len`
/// block numbers. Index nodes themselves occupy physical blocks too; those are
/// collected via `index_blocks`. Uninitialized extents are included because
/// the blocks are allocated even if the data is not yet committed.
///
/// Returns `Err(InvalidExtentHeader)` if any node has a bad magic.
/// Returns `Err(BlockOutOfRange)` if a child pointer exceeds `blocks_count`.
pub(crate) fn collect_extents_into<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    i_block: &[u8; 60],
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    collect_node(ext, fs, inode, generation, i_block, out)
}

/// Recursive helper: walk one node, collecting leaf physical blocks and
/// recursing into index children.
fn collect_node<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    node: &[u8],
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    let hdr = parse_header(node, inode)?;
    let depth = hdr.eh_depth.get();
    let entries = hdr.eh_entries.get();

    if depth > MAX_DEPTH {
        return Err(ExtError::InvalidExtentHeader { inode });
    }

    let entry_data = &node[12..];

    if depth == 0 {
        collect_leaf_blocks(ext, entry_data, entries, out)?;
    } else {
        collect_index_blocks(ext, fs, inode, generation, entry_data, entries, out)?;
    }

    Ok(())
}

/// Append all physical blocks from leaf entries into `out`.
///
/// Returns `Err(BlockOutOfRange)` if any physical block number in a leaf
/// extent meets or exceeds `ext.blocks_count`.
fn collect_leaf_blocks(
    ext: &Ext,
    entry_data: &[u8],
    entries: u16,
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }
        let Some(raw) = RawExtent::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };
        let decoded = decode_extent(raw);
        for b in 0..u64::from(decoded.len) {
            let block = decoded.physical_block + b;
            if block >= ext.blocks_count {
                return Err(ExtError::BlockOutOfRange { block });
            }
            out.push(block);
        }
    }
    Ok(())
}

/// Recurse into index children, collecting their physical blocks.
fn collect_index_blocks<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    entry_data: &[u8],
    entries: u16,
    out: &mut alloc::vec::Vec<u64>,
) -> Result<()> {
    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }
        let Some(idx) = RawExtentIndex::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };
        let child_block = index_child_block(idx);
        if child_block >= ext.blocks_count {
            return Err(ExtError::BlockOutOfRange { block: child_block });
        }

        // The index block itself is an allocated block.
        out.push(child_block);

        let byte_offset = child_block * u64::from(ext.block_size);
        fs.seek(SeekFrom::Start(byte_offset))?;
        let mut buf = vec![0u8; ext.block_size as usize];
        fs.read_exact(&mut buf)?;

        if let Some(seed) = ext.checksum_seed {
            let state = crate::checksum::verify_extent_block(seed, inode, generation, &buf);
            if state != crate::checksum::ChecksumState::Valid {
                return Err(ExtError::InvalidExtentHeader { inode });
            }
        }

        collect_node(ext, fs, inode, generation, &buf, out)?;
    }
    Ok(())
}

/// Walk the extent tree to resolve a logical block to a physical extent.
///
/// Returns `Ok(None)` for sparse holes (no extent covers the block).
/// Returns `Err(InvalidExtentHeader)` if any node has a bad magic.
/// Returns `Err(BlockOutOfRange)` if a child pointer exceeds `blocks_count`.
pub(crate) fn resolve_extent<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    i_block: &[u8; 60],
    logical_block: u32,
) -> Result<Option<Extent>> {
    resolve_node(ext, fs, inode, generation, i_block, logical_block)
}

/// Recursive extent tree walker operating on a node buffer.
///
/// The first call uses the 60-byte in-inode root. Subsequent calls
/// read child blocks from disk. Recursion is bounded by `eh_depth`
/// (max 5).
fn resolve_node<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    node: &[u8],
    logical_block: u32,
) -> Result<Option<Extent>> {
    let hdr = parse_header(node, inode)?;
    let depth = hdr.eh_depth.get();
    let entries = hdr.eh_entries.get();

    if depth > MAX_DEPTH {
        return Err(ExtError::InvalidExtentHeader { inode });
    }

    let entry_data = &node[12..];

    if depth == 0 {
        search_leaf(entry_data, entries, logical_block)
    } else {
        search_index(
            ext,
            fs,
            inode,
            generation,
            entry_data,
            entries,
            logical_block,
        )
    }
}

/// Scan leaf entries for the extent covering `logical_block`.
fn search_leaf(entry_data: &[u8], entries: u16, logical_block: u32) -> Result<Option<Extent>> {
    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }

        let Some(raw) = RawExtent::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };

        let ext = decode_extent(raw);
        let start = ext.logical_block;
        if logical_block >= start && logical_block < start + ext.len {
            return Ok(Some(ext));
        }
    }

    Ok(None)
}

/// Predecessor binary search on index entries, then recurse into child.
fn search_index<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    inode: u32,
    generation: u32,
    entry_data: &[u8],
    entries: u16,
    logical_block: u32,
) -> Result<Option<Extent>> {
    let mut best: Option<&RawExtentIndex> = None;

    for i in 0..u32::from(entries) {
        let off = (i as usize) * 12;
        let end = off + 12;
        if end > entry_data.len() {
            break;
        }

        let Some(idx) = RawExtentIndex::ref_from_bytes(&entry_data[off..end]).ok() else {
            break;
        };

        if idx.ei_block.get() <= logical_block {
            best = Some(idx);
        } else {
            break;
        }
    }

    let Some(idx) = best else {
        return Ok(None);
    };

    let child_block = index_child_block(idx);
    if child_block >= ext.blocks_count {
        return Err(ExtError::BlockOutOfRange { block: child_block });
    }

    let byte_offset = child_block * u64::from(ext.block_size);
    fs.seek(SeekFrom::Start(byte_offset))?;

    let mut buf = vec![0u8; ext.block_size as usize];
    fs.read_exact(&mut buf)?;

    // Validate extent block checksum. On METADATA_CSUM filesystems,
    // external extent blocks must have a valid tail — Unknown (bad
    // eh_max) is corruption, not "checksum not applicable".
    if let Some(seed) = ext.checksum_seed {
        let state = crate::checksum::verify_extent_block(seed, inode, generation, &buf);
        if state != crate::checksum::ChecksumState::Valid {
            return Err(ExtError::InvalidExtentHeader { inode });
        }
    }

    resolve_node(ext, fs, inode, generation, &buf, logical_block)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 60-byte i_block with a valid extent header
    /// and the given leaf extents (depth 0).
    fn make_leaf_iblock(extents: &[(u32, u16, u16, u32)]) -> [u8; 60] {
        let mut buf = [0u8; 60];

        // Header: magic, entries, max=4, depth=0, generation=0
        buf[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        buf[2..4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
        buf[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
        // depth = 0, generation = 0 (already zeroed)

        for (i, &(ee_block, ee_len, ee_start_hi, ee_start_lo)) in extents.iter().enumerate() {
            let off = 12 + i * 12;
            buf[off..off + 4].copy_from_slice(&ee_block.to_le_bytes());
            buf[off + 4..off + 6].copy_from_slice(&ee_len.to_le_bytes());
            buf[off + 6..off + 8].copy_from_slice(&ee_start_hi.to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&ee_start_lo.to_le_bytes());
        }

        buf
    }

    /// Minimal Ext struct for testing (only block_size and blocks_count
    /// matter for extent resolution).
    fn test_ext() -> Ext {
        Ext {
            inodes_count: 100,
            blocks_count: 10000,
            block_size: 4096,
            group_count: 1,
            inodes_per_group: 100,
            inode_size: 256,
            first_data_block: 0,
            gdt_layout: crate::block_group::GdtLayout::from_parts(
                0,
                4096,
                8192,
                32,
                0,
                false,
                false,
                false,
                [0, 0],
                1,
                0,
            )
            .expect("test layout"),
            blocks_per_group: 8192,
            cluster_size: 4096,
            blocks_per_cluster: 1,
            clusters_per_group: 8192,
            backup_bgs: [0, 0],
            desc_size: 32,
            incompat: crate::feature_flags::IncompatFeatures::empty(),
            ro_compat: crate::feature_flags::RoCompatFeatures::empty(),
            compat: crate::feature_flags::CompatFeatures::empty(),
            journal_inum: 0,
            journal_uuid: [0u8; 16],
            orphan_file_inum: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            is_64bit: false,
            uuid: [0u8; 16],
            hash_seed: [0u32; 4],
            group_descs: alloc::vec![],
            checksum_seed: None,
            superblock_checksum: crate::checksum::ChecksumState::Unknown,
            encoding: 0,
            encoding_flags: 0,
            first_inode: 0,
            s_encrypt_pw_salt: [0u8; 16],
            s_encrypt_algos: [0u8; 4],
            mmp_block: 0,
            mmp_update_interval: 0,
            forensics: crate::superblock::ExtSuperblockForensics {
                mkfs_time_seconds: 0,
                mtime_seconds: 0,
                wtime_seconds: 0,
                lastcheck_seconds: 0,
                kbytes_written: 0,
                error_count: 0,
                mount_opts: [0u8; 64],
                first_error: None,
                last_error: None,
            },
            #[cfg(feature = "fscrypt")]
            fscrypt_keys: crate::fscrypt::keystore::FscryptKeystore::default(),
        }
    }

    #[test]
    fn depth0_single_extent_hit() {
        let ext = test_ext();
        // Extent: logical blocks 0-4 -> physical block 100
        let iblock = make_leaf_iblock(&[(0, 5, 0, 100)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        // Block 0 -> hit
        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0).expect("should not error");
        let e = result.expect("should find extent");
        assert_eq!(e.logical_block, 0);
        assert_eq!(e.physical_block, 100);
        assert_eq!(e.len, 5);
        assert!(!e.uninitialized);

        // Block 2 -> hit (same extent)
        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 2).expect("should not error");
        let e = result.expect("should find extent");
        assert_eq!(e.logical_block, 0);
        assert_eq!(e.physical_block, 100);

        // Block 4 -> hit (last block in extent)
        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 4).expect("should not error");
        assert!(result.is_some());

        // Block 5 -> miss (hole)
        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 5).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn depth0_multiple_extents() {
        let ext = test_ext();
        // Two extents: blocks 0-2 -> phys 100, blocks 10-11 -> phys 200
        let iblock = make_leaf_iblock(&[(0, 3, 0, 100), (10, 2, 0, 200)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 1).expect("should not error");
        let e = result.expect("should find extent");
        assert_eq!(e.physical_block, 100);
        assert_eq!(e.logical_block, 0);

        let result =
            resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 10).expect("should not error");
        let e = result.expect("should find extent");
        assert_eq!(e.physical_block, 200);
        assert_eq!(e.logical_block, 10);

        // Block 5 -> hole between extents
        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 5).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn depth0_uninitialized_extent() {
        let ext = test_ext();
        // ee_len = 32769 -> uninitialized, actual length = 1
        let iblock = make_leaf_iblock(&[(0, 32769, 0, 500)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0).expect("should not error");
        let e = result.expect("should find extent");
        assert!(e.uninitialized);
        assert_eq!(e.len, 1);
        assert_eq!(e.physical_block, 500);
    }

    #[test]
    fn bad_magic_returns_error() {
        let ext = test_ext();
        let mut iblock = [0u8; 60];
        // Write wrong magic
        iblock[0..2].copy_from_slice(&0xBEEFu16.to_le_bytes());
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let err = resolve_extent(&ext, &mut cursor, 42, 0, &iblock, 0)
            .expect_err("should fail with bad magic");
        match err {
            ExtError::InvalidExtentHeader { inode } => assert_eq!(inode, 42),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn depth_exceeds_max_returns_error() {
        let ext = test_ext();
        let mut iblock = [0u8; 60];
        // Valid magic but depth = 6 (exceeds MAX_DEPTH of 5)
        iblock[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        iblock[6..8].copy_from_slice(&6u16.to_le_bytes()); // eh_depth = 6
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let err = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0)
            .expect_err("should fail with excessive depth");
        match err {
            ExtError::InvalidExtentHeader { inode } => assert_eq!(inode, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn zero_entries_returns_none() {
        let ext = test_ext();
        let mut iblock = [0u8; 60];
        iblock[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        // eh_entries = 0, depth = 0
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn extent_48bit_physical_block() {
        let ext = test_ext();
        // ee_start_hi = 1, ee_start_lo = 0 -> physical = 0x1_0000_0000
        let iblock = make_leaf_iblock(&[(0, 1, 1, 0)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0).expect("should not error");
        let e = result.expect("should find extent");
        assert_eq!(e.physical_block, 0x1_0000_0000);
    }

    #[test]
    fn depth1_index_block_out_of_range() {
        let ext = test_ext(); // blocks_count = 10000
        let mut iblock = [0u8; 60];

        // Header: depth=1, entries=1
        iblock[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        iblock[2..4].copy_from_slice(&1u16.to_le_bytes()); // eh_entries
        iblock[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
        iblock[6..8].copy_from_slice(&1u16.to_le_bytes()); // eh_depth

        // Index entry at offset 12: ei_block=0, ei_leaf_lo=99999
        // (out of range for blocks_count=10000)
        let idx_off = 12;
        iblock[idx_off..idx_off + 4].copy_from_slice(&0u32.to_le_bytes());
        iblock[idx_off + 4..idx_off + 8].copy_from_slice(&99999u32.to_le_bytes());

        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let err = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0)
            .expect_err("should fail with block out of range");
        match err {
            ExtError::BlockOutOfRange { block } => assert_eq!(block, 99999),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn depth1_resolves_through_child_block() {
        let mut ext = test_ext();
        ext.block_size = 4096;
        ext.blocks_count = 10000;

        // Root node: depth=1, 1 index entry pointing to block 50
        let mut iblock = [0u8; 60];
        iblock[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        iblock[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries
        iblock[4..6].copy_from_slice(&4u16.to_le_bytes()); // max
        iblock[6..8].copy_from_slice(&1u16.to_le_bytes()); // depth

        // Index: ei_block=0, child at physical block 50
        let idx_off = 12;
        iblock[idx_off..idx_off + 4].copy_from_slice(&0u32.to_le_bytes());
        iblock[idx_off + 4..idx_off + 8].copy_from_slice(&50u32.to_le_bytes());

        // Build the child block (leaf at depth 0) at byte offset 50*4096
        let child_offset = 50u64 * 4096;
        let disk_size = (child_offset + 4096) as usize;
        let mut disk = vec![0u8; disk_size];

        // Child block header: depth=0, 1 extent entry
        let cb = &mut disk[child_offset as usize..];
        cb[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        cb[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries
        cb[4..6].copy_from_slice(&340u16.to_le_bytes()); // max
        // depth = 0 (already zeroed)

        // Leaf extent: logical block 0, len=10, physical block 200
        let ext_off = 12;
        cb[ext_off..ext_off + 4].copy_from_slice(&0u32.to_le_bytes());
        cb[ext_off + 4..ext_off + 6].copy_from_slice(&10u16.to_le_bytes());
        // ee_start_hi = 0 (zeroed), ee_start_lo = 200
        cb[ext_off + 8..ext_off + 12].copy_from_slice(&200u32.to_le_bytes());

        let mut cursor = std::io::Cursor::new(disk);

        let result = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 5).expect("should not error");
        let e = result.expect("should find extent through index");
        assert_eq!(e.logical_block, 0);
        assert_eq!(e.physical_block, 200);
        assert_eq!(e.len, 10);
        assert!(!e.uninitialized);

        // Block 10 -> hole (past the extent)
        let result =
            resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 10).expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn depth1_bad_extent_tail_is_error_when_checksums_enabled() {
        let mut ext = test_ext();
        ext.block_size = 4096;
        ext.blocks_count = 10000;
        ext.checksum_seed = Some(0x1234_5678);

        // Root node: depth=1, 1 index entry pointing to block 50.
        let mut iblock = [0u8; 60];
        iblock[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        iblock[2..4].copy_from_slice(&1u16.to_le_bytes());
        iblock[4..6].copy_from_slice(&4u16.to_le_bytes());
        iblock[6..8].copy_from_slice(&1u16.to_le_bytes());

        let idx_off = 12;
        iblock[idx_off..idx_off + 4].copy_from_slice(&0u32.to_le_bytes());
        iblock[idx_off + 4..idx_off + 8].copy_from_slice(&50u32.to_le_bytes());

        let child_offset = 50usize * 4096;
        let mut disk = vec![0u8; child_offset + 4096];
        let cb = &mut disk[child_offset..child_offset + 4096];

        cb[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        cb[2..4].copy_from_slice(&1u16.to_le_bytes()); // entries
        cb[4..6].copy_from_slice(&341u16.to_le_bytes()); // eh_max -> tail past block end

        let mut cursor = std::io::Cursor::new(disk);

        let err = resolve_extent(&ext, &mut cursor, 1, 0, &iblock, 0)
            .expect_err("bad extent tail placement should be rejected");
        match err {
            ExtError::InvalidExtentHeader { inode } => assert_eq!(inode, 1),
            other => panic!("unexpected error: {other}"),
        }
    }

    /// A leaf extent whose first physical block is exactly `blocks_count`
    /// must be rejected by `collect_extents_into` with `BlockOutOfRange`.
    #[test]
    fn leaf_extent_physical_block_at_blocks_count_is_rejected() {
        let mut ext = test_ext(); // blocks_count = 10000
        ext.blocks_count = 10000;
        // Extent: logical 0, len=3, physical_block=9999 -> blocks 9999, 10000, 10001
        // Block 10000 == blocks_count, so the second block must be rejected.
        let iblock = make_leaf_iblock(&[(0, 3, 0, 9999)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let mut out = alloc::vec::Vec::new();
        let err = collect_extents_into(&ext, &mut cursor, 1, 0, &iblock, &mut out)
            .expect_err("out-of-range block should be rejected");
        match err {
            ExtError::BlockOutOfRange { block } => assert_eq!(block, 10000),
            other => panic!("unexpected error: {other}"),
        }
    }

    /// The tagged walker used by orphan replay must preserve the same physical
    /// range validation as the plain extent collector.
    #[test]
    fn tagged_leaf_extent_physical_block_at_blocks_count_is_rejected() {
        let mut ext = test_ext(); // blocks_count = 10000
        ext.blocks_count = 10000;
        // Extent: physical blocks 9999, 10000, 10001. Block 10000 is the
        // first out-of-range block and must be reported.
        let iblock = make_leaf_iblock(&[(0, 3, 0, 9999)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let mut out = alloc::vec::Vec::new();
        let err = collect_tagged_extent_blocks_into(&ext, &mut cursor, 1, 0, &iblock, &mut out)
            .expect_err("tagged out-of-range block should be rejected");
        match err {
            ExtError::BlockOutOfRange { block } => assert_eq!(block, 10000),
            other => panic!("unexpected error: {other}"),
        }
    }

    /// A leaf extent whose physical block range lies entirely within
    /// `blocks_count` must succeed and emit every block number.
    #[test]
    fn leaf_extent_within_blocks_count_succeeds() {
        let mut ext = test_ext();
        ext.blocks_count = 10000;
        // Extent: logical 0, len=5, physical_block=100 -> blocks 100..104 (all < 10000)
        let iblock = make_leaf_iblock(&[(0, 5, 0, 100)]);
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());

        let mut out = alloc::vec::Vec::new();
        collect_extents_into(&ext, &mut cursor, 1, 0, &iblock, &mut out)
            .expect("in-range extent should succeed");
        assert_eq!(out, &[100, 101, 102, 103, 104]);
    }
}
