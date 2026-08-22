//! VFS v2r1 (vfsv1) quota-tree reader.
//!
//! Reads the per-user, per-group, or per-project disk-usage records stored
//! in the inodes referenced by `s_usr_quota_inum`, `s_grp_quota_inum`, and
//! `s_prj_quota_inum`. The on-disk format is the Linux VFS v2 quota tree
//! used by ext4's `RO_COMPAT_QUOTA` and `RO_COMPAT_PROJECT` features.
//!
//! Quota files are organized as 1024-byte "quota blocks" regardless of the
//! filesystem block size. Block 0 is the file header (magic + version +
//! `dqinfo`); block 1 is the root tree; the tree is `qtree_depth` levels
//! deep with 256 `__le32` next-block pointers per tree block. At the
//! deepest level, entries point to leaf blocks holding up to 14
//! `v2r1_disk_dqblk` records. For 1024-byte quota blocks `qtree_depth = 4`.
//!
//! Iteration walks every reachable leaf and yields each record whose
//! identity / usage / limit / grace bytes are non-zero. Cycles and
//! out-of-range pointers produce `ExtError::InvalidQuotaFile` rather than
//! infinite loops or panics.

use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use zerocopy::byteorder::{U16, U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};
use crate::ext::Ext;
use crate::io::{FsReadSeek, Read, Seek};

/// Size of one "quota block" inside a quota file (1024 bytes).
///
/// Independent of the filesystem block size. Defined by the VFS quota
/// format (`V2_DQBLKSIZE_BITS == 10`).
const QUOTA_BLOCK_SIZE: usize = 1024;

/// On-disk size of one `v2r1_disk_dqblk` record.
const DQBLK_SIZE: usize = 72;

/// On-disk size of the leaf-block header (`qt_disk_dqdbheader`).
const DQDBHEADER_SIZE: usize = 16;

/// Maximum number of records that fit in one leaf block
/// (`(1024 - 16) / 72 == 14`).
const ENTRIES_PER_LEAF: usize = (QUOTA_BLOCK_SIZE - DQDBHEADER_SIZE) / DQBLK_SIZE;

/// Magic for vfsv1 user quota files (`d9c01f11`).
const USRQUOTA_MAGIC: u32 = 0xd9c0_1f11;
/// Magic for vfsv1 group quota files (`d9c01927`).
const GRPQUOTA_MAGIC: u32 = 0xd9c0_1927;
/// Magic for vfsv1 project quota files (`d9c03f14`).
const PRJQUOTA_MAGIC: u32 = 0xd9c0_3f14;

/// VFS quota format version number for vfsv1.
const QUOTA_VERSION: u32 = 1;

/// Block number where the root tree block lives (`QT_TREEOFF`).
const ROOT_TREE_BLOCK: u32 = 1;

/// Indexing levels for a 1024-byte quota tree (`qtree_depth`).
///
/// Each level uses 8 bits of the 32-bit ID, so `4 * 8 == 32` covers the
/// full ID space. The leaf blocks are reached one indirection beyond the
/// deepest tree block.
const QTREE_DEPTH: u32 = 4;

/// Which of the three quota trees to read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuotaKind {
    /// Per-user quotas (`s_usr_quota_inum`).
    User,
    /// Per-group quotas (`s_grp_quota_inum`).
    Group,
    /// Per-project quotas (`s_prj_quota_inum`).
    Project,
}

impl QuotaKind {
    fn expected_magic(self) -> u32 {
        match self {
            Self::User => USRQUOTA_MAGIC,
            Self::Group => GRPQUOTA_MAGIC,
            Self::Project => PRJQUOTA_MAGIC,
        }
    }
}

/// One per-identity disk-usage and limit record.
///
/// All byte / inode counts are absolute values; the soft / hard limit
/// fields are zero when no limit is set. `block_grace` and `inode_grace`
/// are absolute Unix timestamps (seconds) at which the soft limit
/// expires, or zero when no grace timer is active.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotaRecord {
    /// Identity this record applies to (UID, GID, or project ID
    /// depending on the [`QuotaKind`] requested).
    pub id: u32,
    /// Number of inodes currently allocated to this identity.
    pub inodes_used: u64,
    /// Bytes of disk space currently allocated to this identity.
    pub bytes_used: u64,
    /// Soft inode limit (0 = unlimited).
    pub inodes_soft_limit: u64,
    /// Hard inode limit (0 = unlimited).
    pub inodes_hard_limit: u64,
    /// Soft byte limit (0 = unlimited). Stored on disk in 1024-byte quota
    /// blocks; this field is the converted byte count (matching the units
    /// of [`Self::bytes_used`]).
    pub bytes_soft_limit: u64,
    /// Hard byte limit (0 = unlimited). Same unit handling as
    /// [`Self::bytes_soft_limit`].
    pub bytes_hard_limit: u64,
    /// Unix timestamp at which the byte soft limit expires (0 = no grace).
    pub block_grace: u64,
    /// Unix timestamp at which the inode soft limit expires (0 = no grace).
    pub inode_grace: u64,
}

#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDqHeader {
    dqh_magic: U32<LE>,
    dqh_version: U32<LE>,
}

#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical quota dqi_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDqInfo {
    dqi_bgrace: U32<LE>,
    dqi_igrace: U32<LE>,
    dqi_flags: U32<LE>,
    dqi_blocks: U32<LE>,
    dqi_free_blk: U32<LE>,
    dqi_free_entry: U32<LE>,
}

#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical quota dqdh_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDqdbHeader {
    dqdh_next_free: U32<LE>,
    dqdh_prev_free: U32<LE>,
    dqdh_entries: U16<LE>,
    dqdh_pad1: U16<LE>,
    dqdh_pad2: U32<LE>,
}

#[allow(
    clippy::struct_field_names,
    reason = "field names preserve canonical quota dqb_* on-disk identifiers"
)]
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDqBlk {
    dqb_id: U32<LE>,
    dqb_pad: U32<LE>,
    dqb_ihardlimit: U64<LE>,
    dqb_isoftlimit: U64<LE>,
    dqb_curinodes: U64<LE>,
    dqb_bhardlimit: U64<LE>,
    dqb_bsoftlimit: U64<LE>,
    dqb_curspace: U64<LE>,
    dqb_btime: U64<LE>,
    dqb_itime: U64<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawDqBlk>() == DQBLK_SIZE,
    "RawDqBlk must be exactly 72 bytes"
);
const _: () = assert!(
    core::mem::size_of::<RawDqdbHeader>() == DQDBHEADER_SIZE,
    "RawDqdbHeader must be exactly 16 bytes"
);

/// Iterator yielding [`QuotaRecord`] values from a parsed quota file.
///
/// Construction reads the entire quota file into memory, validates the
/// header, and walks the tree to collect leaf-block numbers. Each
/// `next()` call decodes records from one leaf, returning records whose
/// id / usage / limit fields are not all zero.
pub struct QuotaIter {
    /// Full quota-file contents, indexed in `QUOTA_BLOCK_SIZE` chunks.
    /// Empty when no quota inum was set (returns no records).
    file: Vec<u8>,
    /// Inode this quota tree was read from (used for error context).
    inode: u32,
    /// Leaf block numbers to read, in DFS order.
    leaves: Vec<u32>,
    /// Current leaf index (next one to decode).
    next_leaf: usize,
    /// Buffer of pending records from the most recently decoded leaf.
    pending: Vec<QuotaRecord>,
    /// Read cursor inside [`Self::pending`].
    pending_cursor: usize,
}

impl QuotaIter {
    /// Empty iterator. Used for zero quota-inum (feature set but tree
    /// not allocated for this kind).
    fn empty() -> Self {
        Self {
            file: Vec::new(),
            inode: 0,
            leaves: Vec::new(),
            next_leaf: 0,
            pending: Vec::new(),
            pending_cursor: 0,
        }
    }
}

impl Iterator for QuotaIter {
    type Item = Result<QuotaRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.pending_cursor < self.pending.len() {
                let record = self.pending[self.pending_cursor];
                self.pending_cursor += 1;
                return Some(Ok(record));
            }
            if self.next_leaf >= self.leaves.len() {
                return None;
            }
            let leaf_block = self.leaves[self.next_leaf];
            self.next_leaf += 1;
            match decode_leaf(&self.file, leaf_block, self.inode) {
                Ok(records) => {
                    self.pending = records;
                    self.pending_cursor = 0;
                }
                Err(e) => {
                    self.next_leaf = self.leaves.len();
                    return Some(Err(e));
                }
            }
        }
    }
}

/// Read the full quota file at `inum` into memory, validate the header,
/// walk the tree, and return a [`QuotaIter`].
pub(crate) fn open_quota<T: Read + Seek>(
    ext: &Ext,
    fs: &mut T,
    kind: QuotaKind,
    inum: u32,
) -> Result<QuotaIter> {
    if inum == 0 {
        return Ok(QuotaIter::empty());
    }

    let inode = ext.inode(fs, inum)?;
    let size = inode.size();
    let mut file = inode.open_file()?;
    let size_usize = usize::try_from(size).map_err(|_| ExtError::InvalidQuotaFile {
        inode: inum,
        reason: "quota file size exceeds platform addressable memory",
    })?;
    if size_usize < 2 * QUOTA_BLOCK_SIZE {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "quota file shorter than header + root tree block",
        });
    }
    if !size_usize.is_multiple_of(QUOTA_BLOCK_SIZE) {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "quota file size not a multiple of 1024 bytes",
        });
    }

    let mut buf = vec![0u8; size_usize];
    let mut read = 0usize;
    while read < size_usize {
        let n = file.read(fs, &mut buf[read..])?;
        if n == 0 {
            return Err(ExtError::UnexpectedEof {
                context: "reading quota file",
                offset: u64::try_from(read).unwrap_or(u64::MAX),
            });
        }
        read += n;
    }

    validate_header(&buf, kind, inum)?;
    let file_blocks =
        u32::try_from(size_usize / QUOTA_BLOCK_SIZE).map_err(|_| ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "quota file has more than 2^32 blocks",
        })?;
    let info_blocks = read_dqi_blocks(&buf, inum)?;
    if info_blocks > file_blocks {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "dqi_blocks exceeds file length",
        });
    }
    // `dqi_blocks` is the authoritative tree-block count; the file may
    // have trailing fs-block padding (e.g. mkfs allocates round numbers
    // of 4 KiB blocks for a 6-KiB tree).
    let leaves = collect_leaves(&buf, info_blocks, inum)?;

    Ok(QuotaIter {
        file: buf,
        inode: inum,
        leaves,
        next_leaf: 0,
        pending: Vec::new(),
        pending_cursor: 0,
    })
}

fn validate_header(buf: &[u8], kind: QuotaKind, inum: u32) -> Result<()> {
    let header =
        RawDqHeader::ref_from_bytes(&buf[..core::mem::size_of::<RawDqHeader>()]).map_err(|_| {
            ExtError::InvalidQuotaFile {
                inode: inum,
                reason: "header truncated",
            }
        })?;
    let magic = header.dqh_magic.get();
    if magic != kind.expected_magic() {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "magic mismatch",
        });
    }
    let version = header.dqh_version.get();
    if version != QUOTA_VERSION {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "unsupported quota format version",
        });
    }
    Ok(())
}

fn read_dqi_blocks(buf: &[u8], inum: u32) -> Result<u32> {
    let header_size = core::mem::size_of::<RawDqHeader>();
    let info_end = header_size + core::mem::size_of::<RawDqInfo>();
    if buf.len() < info_end {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "header truncated",
        });
    }
    let info = RawDqInfo::ref_from_bytes(&buf[header_size..info_end]).map_err(|_| {
        ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "dqinfo truncated",
        }
    })?;
    Ok(info.dqi_blocks.get())
}

fn block_slice(buf: &[u8], block: u32, inum: u32) -> Result<&[u8]> {
    let start = usize::try_from(block)
        .map_err(|_| ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "tree block number exceeds addressable memory",
        })?
        .checked_mul(QUOTA_BLOCK_SIZE)
        .ok_or(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "tree block offset overflow",
        })?;
    let end = start
        .checked_add(QUOTA_BLOCK_SIZE)
        .ok_or(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "tree block offset overflow",
        })?;
    if end > buf.len() {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "tree block out of range",
        });
    }
    Ok(&buf[start..end])
}

fn collect_leaves(buf: &[u8], total_blocks: u32, inum: u32) -> Result<Vec<u32>> {
    let mut leaves = Vec::new();
    let mut visited = BTreeSet::new();
    walk_tree(
        buf,
        ROOT_TREE_BLOCK,
        0,
        total_blocks,
        inum,
        &mut visited,
        &mut leaves,
    )?;
    Ok(leaves)
}

fn walk_tree(
    buf: &[u8],
    block: u32,
    depth: u32,
    total_blocks: u32,
    inum: u32,
    visited: &mut BTreeSet<u32>,
    leaves: &mut Vec<u32>,
) -> Result<()> {
    if block == 0 || block >= total_blocks {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "tree block out of range",
        });
    }
    if !visited.insert(block) {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "cycle in quota tree",
        });
    }
    let slice = block_slice(buf, block, inum)?;
    let entries_point_to_leaves = depth + 1 == QTREE_DEPTH;
    for chunk in slice.as_chunks::<4>().0 {
        let next = u32::from_le_bytes(*chunk);
        if next == 0 {
            continue;
        }
        if next >= total_blocks {
            return Err(ExtError::InvalidQuotaFile {
                inode: inum,
                reason: "tree pointer exceeds dqi_blocks",
            });
        }
        if entries_point_to_leaves {
            // A leaf pointer pointing back at a block already used as a tree
            // is structurally inconsistent — flag as a cycle. Multiple leaf
            // pointers reaching the same leaf are legitimate (the kernel
            // shares a fill-leaf via `dqi_free_entry`); dedupe them.
            if !visited.insert(next) {
                if leaves.contains(&next) {
                    continue;
                }
                return Err(ExtError::InvalidQuotaFile {
                    inode: inum,
                    reason: "cycle in quota tree",
                });
            }
            leaves.push(next);
        } else {
            walk_tree(buf, next, depth + 1, total_blocks, inum, visited, leaves)?;
        }
    }
    Ok(())
}

fn decode_leaf(buf: &[u8], block: u32, inum: u32) -> Result<Vec<QuotaRecord>> {
    let slice = block_slice(buf, block, inum)?;
    let header = RawDqdbHeader::ref_from_bytes(&slice[..DQDBHEADER_SIZE]).map_err(|_| {
        ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "leaf header truncated",
        }
    })?;
    let claimed = usize::from(header.dqdh_entries.get());
    if claimed > ENTRIES_PER_LEAF {
        return Err(ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "leaf dqdh_entries exceeds capacity",
        });
    }
    // The on-disk format does not pack valid entries at the start: deletion
    // zeros a slot in place. Walk every slot, yielding any whose fields are
    // not all zero (root-id records have id=0 but non-zero usage/limits).
    let mut records = Vec::new();
    for i in 0..ENTRIES_PER_LEAF {
        let off = DQDBHEADER_SIZE + i * DQBLK_SIZE;
        let raw = &slice[off..off + DQBLK_SIZE];
        // Reject the kernel writer's escape sentinel: an otherwise-zero
        // record with `dqb_itime == 1` represents a real "id 0, no usage"
        // entry that the writer disambiguates from a free slot. Treat the
        // raw bytes as empty so the record is not yielded — we have no
        // forensic data to surface either way.
        if is_escape_sentinel(raw) {
            continue;
        }
        let entry = RawDqBlk::ref_from_bytes(raw).map_err(|_| ExtError::InvalidQuotaFile {
            inode: inum,
            reason: "leaf entry truncated",
        })?;
        let record = QuotaRecord {
            id: entry.dqb_id.get(),
            inodes_used: entry.dqb_curinodes.get(),
            bytes_used: entry.dqb_curspace.get(),
            inodes_soft_limit: entry.dqb_isoftlimit.get(),
            inodes_hard_limit: entry.dqb_ihardlimit.get(),
            // `dqb_b{soft,hard}limit` are stored in 1024-byte quota blocks;
            // convert to bytes so all byte-valued fields share units.
            bytes_soft_limit: qbtos(entry.dqb_bsoftlimit.get()),
            bytes_hard_limit: qbtos(entry.dqb_bhardlimit.get()),
            block_grace: entry.dqb_btime.get(),
            inode_grace: entry.dqb_itime.get(),
        };
        if !is_empty_record(&record) {
            records.push(record);
        }
    }
    Ok(records)
}

/// Convert a quota-block count to bytes (`v2_qbtos` in the kernel).
const fn qbtos(blocks: u64) -> u64 {
    blocks.saturating_mul(1024)
}

/// Detect the kernel's all-zero escape sentinel: every byte is zero
/// except `dqb_itime` (offset 0x40), which holds 1.
fn is_escape_sentinel(raw: &[u8]) -> bool {
    debug_assert_eq!(raw.len(), DQBLK_SIZE);
    let dqb_itime_off = 0x40;
    if raw[..dqb_itime_off].iter().any(|b| *b != 0) {
        return false;
    }
    let mut expected = [0u8; 8];
    expected[0] = 1;
    raw[dqb_itime_off..dqb_itime_off + 8] == expected
}

fn is_empty_record(r: &QuotaRecord) -> bool {
    r.id == 0
        && r.inodes_used == 0
        && r.bytes_used == 0
        && r.inodes_soft_limit == 0
        && r.inodes_hard_limit == 0
        && r.bytes_soft_limit == 0
        && r.bytes_hard_limit == 0
        && r.block_grace == 0
        && r.inode_grace == 0
}

impl Ext {
    /// Iterate the quota records for `kind`.
    ///
    /// Reads the inode referenced by `s_{usr,grp,prj}_quota_inum`, parses
    /// its vfsv1 header, walks the tree, and yields each non-empty record.
    /// When the corresponding inum is zero, returns an empty iterator
    /// (the feature can be set without all three trees populated).
    ///
    /// Returns [`ExtError::InvalidQuotaFile`] when the magic / version do
    /// not match, the file is too short, a tree pointer is out of range,
    /// or a cycle is detected. Inode-level errors (out-of-range, encrypted,
    /// EA inode) propagate from [`Ext::inode`].
    ///
    /// # Errors
    ///
    /// Returns an I/O or inode-access error, or
    /// [`ExtError::InvalidQuotaFile`] when the quota header or tree is
    /// malformed.
    pub fn quota<T: Read + Seek>(&self, fs: &mut T, kind: QuotaKind) -> Result<QuotaIter> {
        let inum = match kind {
            QuotaKind::User => self.usr_quota_inum,
            QuotaKind::Group => self.grp_quota_inum,
            QuotaKind::Project => self.prj_quota_inum,
        };
        open_quota(self, fs, kind, inum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic 6-block quota file with a given magic, mirroring
    /// the cascading-tree layout produced by `mkfs.ext4 -O quota` for an
    /// empty quota tree (root → tree → tree → tree → leaf with 1 entry).
    fn synth_quota_file(magic: u32, leaf_id: u32, leaf_curspace: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 6 * QUOTA_BLOCK_SIZE];
        // Block 0 header.
        buf[0..4].copy_from_slice(&magic.to_le_bytes());
        buf[4..8].copy_from_slice(&QUOTA_VERSION.to_le_bytes());
        // dqi_blocks = 6.
        buf[20..24].copy_from_slice(&6u32.to_le_bytes());
        // Tree blocks 1 -> 2 -> 3 -> 4 -> leaf 5.
        for (block, target) in [(1u32, 2u32), (2, 3), (3, 4), (4, 5)] {
            let off = usize::try_from(block)
                .expect("the synthetic quota block number fits in usize")
                * QUOTA_BLOCK_SIZE;
            buf[off..off + 4].copy_from_slice(&target.to_le_bytes());
        }
        // Leaf block 5: dqdh_entries = 1, then one record at offset 16.
        let leaf_off = 5 * QUOTA_BLOCK_SIZE;
        buf[leaf_off + 8..leaf_off + 10].copy_from_slice(&1u16.to_le_bytes());
        let entry_off = leaf_off + DQDBHEADER_SIZE;
        buf[entry_off..entry_off + 4].copy_from_slice(&leaf_id.to_le_bytes());
        // dqb_curspace at offset 0x30 inside the dqblk.
        buf[entry_off + 0x30..entry_off + 0x38].copy_from_slice(&leaf_curspace.to_le_bytes());
        buf
    }

    #[test]
    fn validate_header_accepts_correct_magic() {
        let buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        validate_header(&buf, QuotaKind::User, 3).expect("user magic accepted");
    }

    #[test]
    fn validate_header_rejects_wrong_kind() {
        let buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        let err = validate_header(&buf, QuotaKind::Group, 4).unwrap_err();
        assert!(
            matches!(
                err,
                ExtError::InvalidQuotaFile {
                    reason: "magic mismatch",
                    ..
                }
            ),
            "expected magic mismatch, got {err:?}"
        );
    }

    #[test]
    fn collect_leaves_traverses_cascading_tree() {
        let buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        let leaves = collect_leaves(&buf, 6, 3).expect("walk tree");
        assert_eq!(leaves, vec![5]);
    }

    #[test]
    fn collect_leaves_rejects_cycle() {
        let mut buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        // Patch tree block 4 to point back at the root tree (block 1).
        let off = 4 * QUOTA_BLOCK_SIZE;
        buf[off..off + 4].copy_from_slice(&1u32.to_le_bytes());
        let err = collect_leaves(&buf, 6, 3).unwrap_err();
        assert!(matches!(
            err,
            ExtError::InvalidQuotaFile {
                reason: "cycle in quota tree",
                ..
            }
        ));
    }

    #[test]
    fn collect_leaves_rejects_out_of_range_pointer() {
        let mut buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        // Patch tree block 1 to point at block 99 (beyond dqi_blocks=6).
        let off = QUOTA_BLOCK_SIZE;
        buf[off..off + 4].copy_from_slice(&99u32.to_le_bytes());
        let err = collect_leaves(&buf, 6, 3).unwrap_err();
        assert!(matches!(
            err,
            ExtError::InvalidQuotaFile {
                reason: "tree pointer exceeds dqi_blocks",
                ..
            }
        ));
    }

    #[test]
    fn decode_leaf_yields_root_record_with_nonzero_usage() {
        let buf = synth_quota_file(USRQUOTA_MAGIC, 0, 20480);
        let records = decode_leaf(&buf, 5, 3).expect("decode leaf");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, 0);
        assert_eq!(records[0].bytes_used, 20480);
    }

    #[test]
    fn decode_leaf_skips_fully_zero_slot() {
        // dqdh_entries says 0, all slots zero → no records yielded.
        let buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        let records = decode_leaf(&buf, 5, 3).expect("decode leaf");
        // Root record with curspace=0 is fully zero → skipped.
        assert!(records.is_empty(), "fully zero slots must not be yielded");
    }

    #[test]
    fn decode_leaf_skips_escape_sentinel() {
        let mut buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        let leaf_off = 5 * QUOTA_BLOCK_SIZE;
        // Force dqdh_entries=0 so the leaf bookkeeping says "empty".
        buf[leaf_off + 8..leaf_off + 10].copy_from_slice(&0u16.to_le_bytes());
        // First slot: all zeros except dqb_itime (offset 0x40 inside the
        // 72-byte record, i.e. leaf+16+0x40 from the leaf start).
        let entry_off = leaf_off + DQDBHEADER_SIZE;
        for b in &mut buf[entry_off..entry_off + DQBLK_SIZE] {
            *b = 0;
        }
        buf[entry_off + 0x40..entry_off + 0x48].copy_from_slice(&1u64.to_le_bytes());
        let records = decode_leaf(&buf, 5, 3).expect("decode leaf");
        assert!(
            records.is_empty(),
            "escape sentinel must not surface as a record"
        );
    }

    #[test]
    fn decode_leaf_converts_block_limits_from_quota_blocks_to_bytes() {
        let mut buf = synth_quota_file(USRQUOTA_MAGIC, 1000, 4096);
        let leaf_off = 5 * QUOTA_BLOCK_SIZE;
        let entry_off = leaf_off + DQDBHEADER_SIZE;
        // dqb_bsoftlimit at offset 0x28 inside the dqblk = 100 quota blocks.
        buf[entry_off + 0x28..entry_off + 0x30].copy_from_slice(&100u64.to_le_bytes());
        // dqb_bhardlimit at offset 0x20 inside the dqblk = 200 quota blocks.
        buf[entry_off + 0x20..entry_off + 0x28].copy_from_slice(&200u64.to_le_bytes());
        let records = decode_leaf(&buf, 5, 3).expect("decode leaf");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes_soft_limit, 100 * 1024);
        assert_eq!(records[0].bytes_hard_limit, 200 * 1024);
    }

    #[test]
    fn decode_leaf_rejects_oversized_dqdh_entries() {
        let mut buf = synth_quota_file(USRQUOTA_MAGIC, 0, 0);
        let leaf_off = 5 * QUOTA_BLOCK_SIZE;
        buf[leaf_off + 8..leaf_off + 10].copy_from_slice(&99u16.to_le_bytes());
        let err = decode_leaf(&buf, 5, 3).unwrap_err();
        assert!(matches!(
            err,
            ExtError::InvalidQuotaFile {
                reason: "leaf dqdh_entries exceeds capacity",
                ..
            }
        ));
    }
}
