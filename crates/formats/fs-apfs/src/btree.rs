//! Generic APFS B-tree node parsing and traversal.
//!
//! Every APFS lookup table — the object map, the volume catalog, the
//! space-manager free queues — is a B+ tree of [`btree_node_phys_t`] nodes.
//! This module parses a single node and walks a tree from its root.
//!
//! Apple File System Reference, `13-b-trees.md`.
//!
//! [`btree_node_phys_t`]: BtreeNode

use alloc::vec::Vec;
use core::cmp::Ordering;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned};

use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::object::OBJ_PHYS_SIZE;

/// Offset of the `btn_data` storage area within a node block.
///
/// `obj_phys_t` (32) + `btn_flags`/`btn_level`/`btn_nkeys` (8) + four
/// `nloc_t` (16) = 56.
pub const BTN_DATA_OFFSET: usize = OBJ_PHYS_SIZE + 8 + 16;

/// Size of the `btree_info_t` trailer stored at the end of a root node.
pub const BTREE_INFO_SIZE: usize = 40;

/// An `nloc_t` offset value meaning "no offset" (`BTOFF_INVALID`).
pub const BTOFF_INVALID: u16 = 0xFFFF;

bitflags! {
    /// Per-node flags (`btn_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BtnodeFlags: u16 {
        /// The node is the root of its tree.
        const ROOT = 0x0001;
        /// The node is a leaf node.
        const LEAF = 0x0002;
        /// Keys and values are both fixed size; the TOC stores only offsets.
        const FIXED_KV_SIZE = 0x0004;
        /// Non-leaf nodes store a hash of each child.
        const HASHED = 0x0008;
        /// The node is stored without an `obj_phys_t` header.
        const NOHEADER = 0x0010;
        /// Key offsets should be checked for `BTOFF_INVALID`.
        const CHECK_KOFF_INVAL = 0x8000;
    }
}

bitflags! {
    /// Whole-tree flags (`bt_flags` of `btree_info_fixed_t`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct BtreeFlags: u32 {
        /// Keys are 64-bit (a comparison hint).
        const UINT64_KEYS = 0x0000_0001;
        /// Entries are inserted sequentially (a packing hint).
        const SEQUENTIAL_INSERT = 0x0000_0002;
        /// The tree may contain keys with no value (ghosts).
        const ALLOW_GHOSTS = 0x0000_0004;
        /// Child links are ephemeral object identifiers.
        const EPHEMERAL = 0x0000_0008;
        /// Child links are physical object identifiers (block addresses).
        const PHYSICAL = 0x0000_0010;
        /// The tree is not persisted across unmounts.
        const NONPERSISTENT = 0x0000_0020;
        /// Keys and values are not eight-byte aligned.
        const KV_NONALIGNED = 0x0000_0040;
        /// Non-leaf nodes store child hashes.
        const HASHED = 0x0000_0080;
        /// Nodes are stored without object headers.
        const NOHEADER = 0x0000_0100;
    }
}

/// On-disk `nloc_t` — a location within a node.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawNloc {
    off: U16<LE>,
    len: U16<LE>,
}

/// On-disk `btree_node_phys_t` header fields that follow `obj_phys_t`.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawBtreeNodeHeader {
    btn_flags: U16<LE>,
    btn_level: U16<LE>,
    btn_nkeys: U32<LE>,
    btn_table_space: RawNloc,
    btn_free_space: RawNloc,
    btn_key_free_list: RawNloc,
    btn_val_free_list: RawNloc,
}

/// On-disk `btree_info_t` — the trailer of a root node.
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawBtreeInfo {
    bt_flags: U32<LE>,
    bt_node_size: U32<LE>,
    bt_key_size: U32<LE>,
    bt_val_size: U32<LE>,
    bt_longest_key: U32<LE>,
    bt_longest_val: U32<LE>,
    bt_key_count: U64<LE>,
    bt_node_count: U64<LE>,
}

/// Static and dynamic information about a whole B-tree (`btree_info_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtreeInfo {
    /// Whole-tree configuration flags.
    pub flags: BtreeFlags,
    /// On-disk size of every node in the tree, in bytes.
    pub node_size: u32,
    /// Fixed key size, or zero if keys are variable size.
    pub key_size: u32,
    /// Fixed value size, or zero if values are variable size.
    pub val_size: u32,
    /// Length of the longest key ever stored in the tree.
    pub longest_key: u32,
    /// Length of the longest value ever stored in the tree.
    pub longest_val: u32,
    /// Number of keys in the tree.
    pub key_count: u64,
    /// Number of nodes in the tree.
    pub node_count: u64,
}

/// One key/value pair within a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The entry's key bytes.
    pub key: &'a [u8],
    /// The entry's value bytes, or `None` for a ghost (a key with no value).
    pub value: Option<&'a [u8]>,
}

/// A parsed APFS B-tree node, owning its block.
#[derive(Debug, Clone)]
pub struct BtreeNode {
    block: Vec<u8>,
    flags: BtnodeFlags,
    level: u16,
    nkeys: u32,
    toc_off: usize,
    toc_len: usize,
}

impl BtreeNode {
    /// Parses a B-tree node from an owned block buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a block smaller than the node
    /// header, or [`ApfsError::Malformed`] when the table-of-contents extent
    /// lies outside the node's storage area.
    pub fn parse(block: Vec<u8>) -> Result<Self> {
        if block.len() < BTN_DATA_OFFSET {
            return Err(ApfsError::Truncated {
                structure: "btree_node_phys_t",
                expected: BTN_DATA_OFFSET,
                actual: block.len(),
            });
        }
        let header = RawBtreeNodeHeader::ref_from_bytes(&block[OBJ_PHYS_SIZE..BTN_DATA_OFFSET])
            .map_err(|_| ApfsError::Malformed {
                structure: "btree_node_phys_t",
                reason: "header did not parse",
            })?;

        let flags = BtnodeFlags::from_bits_retain(header.btn_flags.get());
        let level = header.btn_level.get();
        let nkeys = header.btn_nkeys.get();
        let toc_off = BTN_DATA_OFFSET + usize::from(header.btn_table_space.off.get());
        let toc_len = usize::from(header.btn_table_space.len.get());

        let toc_end = toc_off.checked_add(toc_len).ok_or(ApfsError::Malformed {
            structure: "btree_node_phys_t",
            reason: "table of contents extent overflows",
        })?;
        if toc_end > block.len() {
            return Err(ApfsError::Malformed {
                structure: "btree_node_phys_t",
                reason: "table of contents extends past the node",
            });
        }

        Ok(Self {
            block,
            flags,
            level,
            nkeys,
            toc_off,
            toc_len,
        })
    }

    /// The node's flags.
    #[must_use]
    pub fn flags(&self) -> BtnodeFlags {
        self.flags
    }

    /// Whether the node is a leaf (its level is zero).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.flags.contains(BtnodeFlags::LEAF)
    }

    /// Whether the node is the root of its tree.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.flags.contains(BtnodeFlags::ROOT)
    }

    /// The number of child levels below this node (zero for a leaf).
    #[must_use]
    pub fn level(&self) -> u16 {
        self.level
    }

    /// The number of keys stored in this node.
    #[must_use]
    pub fn key_count(&self) -> u32 {
        self.nkeys
    }

    /// The whole-tree information stored in a root node's trailer.
    ///
    /// Returns `None` for a non-root node.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Malformed`] when the root node is too small to
    /// hold a `btree_info_t` trailer.
    pub fn btree_info(&self) -> Result<Option<BtreeInfo>> {
        if !self.is_root() {
            return Ok(None);
        }
        let start = self
            .block
            .len()
            .checked_sub(BTREE_INFO_SIZE)
            .filter(|&s| s >= BTN_DATA_OFFSET)
            .ok_or(ApfsError::Malformed {
                structure: "btree_info_t",
                reason: "root node too small for the info trailer",
            })?;
        let raw = RawBtreeInfo::ref_from_bytes(&self.block[start..start + BTREE_INFO_SIZE])
            .map_err(|_| ApfsError::Malformed {
                structure: "btree_info_t",
                reason: "trailer did not parse",
            })?;
        Ok(Some(BtreeInfo {
            flags: BtreeFlags::from_bits_retain(raw.bt_flags.get()),
            node_size: raw.bt_node_size.get(),
            key_size: raw.bt_key_size.get(),
            val_size: raw.bt_val_size.get(),
            longest_key: raw.bt_longest_key.get(),
            longest_val: raw.bt_longest_val.get(),
            key_count: raw.bt_key_count.get(),
            node_count: raw.bt_node_count.get(),
        }))
    }

    /// The byte offset within the block where the key area begins.
    fn key_area_start(&self) -> usize {
        self.toc_off + self.toc_len
    }

    /// The byte offset within the block where the value area ends.
    ///
    /// For a root node the value area ends before the `btree_info_t` trailer.
    fn value_area_end(&self) -> usize {
        if self.is_root() {
            self.block.len().saturating_sub(BTREE_INFO_SIZE)
        } else {
            self.block.len()
        }
    }

    /// Returns the key/value pair at `index`.
    ///
    /// `key_len` and `val_len` are the fixed key and value lengths; they are
    /// used only for a [`BtnodeFlags::FIXED_KV_SIZE`] node, whose table of
    /// contents stores offsets but not lengths. For a variable-size node the
    /// lengths come from the table of contents and these arguments are
    /// ignored.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Malformed`] for an out-of-range index or a
    /// key/value extent that lies outside the node.
    pub fn entry(&self, index: u32, key_len: usize, val_len: usize) -> Result<Entry<'_>> {
        if index >= self.nkeys {
            return Err(ApfsError::Malformed {
                structure: "btree_node_phys_t",
                reason: "entry index out of range",
            });
        }
        let i = index as usize;
        let key_area = self.key_area_start();
        let value_end = self.value_area_end();

        let (k_off, k_len, v_off, v_len) = if self.flags.contains(BtnodeFlags::FIXED_KV_SIZE) {
            // kvoff_t: two u16 offsets, lengths implied.
            let base = self.toc_off + i * 4;
            let toc = self.toc_slice(base, 4)?;
            let k = u16::from_le_bytes([toc[0], toc[1]]);
            let v = u16::from_le_bytes([toc[2], toc[3]]);
            (k, key_len, v, val_len)
        } else {
            // kvloc_t: an nloc_t for the key and one for the value.
            let base = self.toc_off + i * 8;
            let toc = self.toc_slice(base, 8)?;
            let k_off = u16::from_le_bytes([toc[0], toc[1]]);
            let k_len = u16::from_le_bytes([toc[2], toc[3]]);
            let v_off = u16::from_le_bytes([toc[4], toc[5]]);
            let v_len = u16::from_le_bytes([toc[6], toc[7]]);
            (k_off, usize::from(k_len), v_off, usize::from(v_len))
        };

        let key_start = key_area
            .checked_add(usize::from(k_off))
            .ok_or_else(|| Self::malformed("key offset overflows"))?;
        let key = self
            .block
            .get(key_start..key_start.saturating_add(k_len))
            .ok_or_else(|| Self::malformed("key extends past the node"))?;

        let value = if v_off == BTOFF_INVALID {
            None
        } else {
            let value_start = value_end
                .checked_sub(usize::from(v_off))
                .ok_or_else(|| Self::malformed("value offset precedes the node"))?;
            Some(
                self.block
                    .get(value_start..value_start.saturating_add(v_len))
                    .ok_or_else(|| Self::malformed("value extends past the node"))?,
            )
        };
        Ok(Entry { key, value })
    }

    /// Slices `len` bytes of the table of contents starting at `base`.
    fn toc_slice(&self, base: usize, len: usize) -> Result<&[u8]> {
        let end = base.saturating_add(len);
        if end > self.toc_off + self.toc_len {
            return Err(Self::malformed("table-of-contents entry out of range"));
        }
        self.block
            .get(base..end)
            .ok_or_else(|| Self::malformed("table-of-contents entry out of range"))
    }

    fn malformed(reason: &'static str) -> ApfsError {
        ApfsError::Malformed {
            structure: "btree_node_phys_t",
            reason,
        }
    }

    /// Iterates the key/value pairs of this node in stored order.
    ///
    /// `key_len`/`val_len` are the fixed sizes used for a
    /// [`BtnodeFlags::FIXED_KV_SIZE`] node; see [`BtreeNode::entry`].
    #[must_use]
    pub fn entries(&self, key_len: usize, val_len: usize) -> NodeEntries<'_> {
        NodeEntries {
            node: self,
            key_len,
            val_len,
            index: 0,
        }
    }

    /// Finds, within this node, the entry whose key compares equal to
    /// `search` under `compare`.
    ///
    /// The table of contents is sorted by key, so a binary search is used.
    ///
    /// # Errors
    ///
    /// Propagates [`ApfsError::Malformed`] from [`BtreeNode::entry`].
    // Binary-search loop body — mutations on the midpoint arithmetic
    // (`+`/`*`, `/`/`%`) and on the loop guard (`<`/`<=`) produce
    // infinite loops the test harness's per-mutant timeout detects but
    // classifies separately from kills. Boundary behaviour is exercised
    // by `find_equal_locates_and_misses`.
    #[cfg_attr(test, mutants::skip)]
    pub fn find_equal<C>(
        &self,
        search: &[u8],
        key_len: usize,
        val_len: usize,
        compare: C,
    ) -> Result<Option<Entry<'_>>>
    where
        C: Fn(&[u8], &[u8]) -> Ordering,
    {
        let mut lo: u32 = 0;
        let mut hi: u32 = self.nkeys;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry(mid, key_len, val_len)?;
            match compare(search, entry.key) {
                Ordering::Equal => return Ok(Some(entry)),
                Ordering::Less => hi = mid,
                Ordering::Greater => lo = mid + 1,
            }
        }
        Ok(None)
    }

    /// Finds, within this node, the entry with the largest key that is
    /// `<= search` under `compare` — the predecessor lookup used by range
    /// queries such as object-map resolution.
    ///
    /// # Errors
    ///
    /// Propagates [`ApfsError::Malformed`] from [`BtreeNode::entry`].
    // Binary-search loop body — mutations on the midpoint arithmetic and
    // the loop guard produce infinite loops the test harness's
    // per-mutant timeout detects. Boundary behaviour is exercised by
    // `find_le_returns_the_predecessor`.
    #[cfg_attr(test, mutants::skip)]
    pub fn find_le<C>(
        &self,
        search: &[u8],
        key_len: usize,
        val_len: usize,
        compare: C,
    ) -> Result<Option<Entry<'_>>>
    where
        C: Fn(&[u8], &[u8]) -> Ordering,
    {
        let mut chosen: Option<u32> = None;
        let mut lo: u32 = 0;
        let mut hi: u32 = self.nkeys;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry(mid, key_len, val_len)?;
            if compare(entry.key, search) == Ordering::Greater {
                hi = mid;
            } else {
                chosen = Some(mid);
                lo = mid + 1;
            }
        }
        match chosen {
            Some(index) => Ok(Some(self.entry(index, key_len, val_len)?)),
            None => Ok(None),
        }
    }

    /// In a non-leaf node, finds the index of the child to descend into for
    /// `search`: the rightmost entry whose key is `<= search`.
    // Binary-search loop body — mutations on the midpoint arithmetic and
    // the loop guard produce infinite loops the test harness's
    // per-mutant timeout detects. The off-by-one on `chosen = mid + 1`
    // vs. `chosen = mid - 1` is exercised by
    // `child_index_descends_asymmetric_keys`.
    #[cfg_attr(test, mutants::skip)]
    fn child_index<C>(&self, search: &[u8], key_len: usize, compare: &C) -> Result<u32>
    where
        C: Fn(&[u8], &[u8]) -> Ordering,
    {
        if self.nkeys == 0 {
            return Err(Self::malformed("non-leaf node has no keys"));
        }
        // Largest index whose key <= search; fall back to the leftmost child
        // when search precedes every key.
        let mut chosen: u32 = 0;
        let mut lo: u32 = 0;
        let mut hi: u32 = self.nkeys;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.entry(mid, key_len, 8)?;
            if compare(entry.key, search) == Ordering::Greater {
                hi = mid;
            } else {
                chosen = mid;
                lo = mid + 1;
            }
        }
        Ok(chosen)
    }
}

/// A lending iterator over the entries of a single B-tree node.
///
/// The reader argument of [`fs_common`](crate::io)'s iterator trait is unused
/// — a node's entries are already in memory — but the trait is implemented so
/// node iteration composes with the rest of the crate.
pub struct NodeEntries<'a> {
    node: &'a BtreeNode,
    key_len: usize,
    val_len: usize,
    index: u32,
}

impl fs_common::iter::FsTryIteratorType for NodeEntries<'_> {
    type Error = ApfsError;
    type Item<'b> = Entry<'b>;
}

impl<R: Read + Seek> fs_common::iter::FsTryIterator<R> for NodeEntries<'_> {
    // Index-update mutation `self.index += 1` → `self.index *= 1` keeps
    // the iterator on the same entry forever; the test harness detects
    // the resulting infinite loop as a timeout. Iteration coverage is
    // exercised by `node_entries_iterator_yields_every_pair`.
    #[cfg_attr(test, mutants::skip)]
    fn try_next<'b>(&'b mut self, _reader: &mut R) -> Result<Option<Entry<'b>>> {
        if self.index >= self.node.key_count() {
            return Ok(None);
        }
        let entry = self.node.entry(self.index, self.key_len, self.val_len)?;
        self.index += 1;
        Ok(Some(entry))
    }
}

/// In a non-leaf node, returns the object identifier of the child node to
/// descend into for `search`.
fn child_link<C>(node: &BtreeNode, search: &[u8], key_len: usize, compare: &C) -> Result<u64>
where
    C: Fn(&[u8], &[u8]) -> Ordering,
{
    let child_idx = node.child_index(search, key_len, compare)?;
    // Non-leaf values are the eight-byte object identifiers of children.
    let entry = node.entry(child_idx, key_len, 8)?;
    let value = entry.value.ok_or(ApfsError::Malformed {
        structure: "btree_node_phys_t",
        reason: "non-leaf entry has no child link",
    })?;
    if value.len() < 8 {
        return Err(ApfsError::Malformed {
            structure: "btree_node_phys_t",
            reason: "child link shorter than an object identifier",
        });
    }
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

/// Walks a B-tree from `root` to the leaf and returns the value bytes of the
/// entry whose key compares equal to `search`.
///
/// `resolve` maps a child node's object identifier to its parsed node; the
/// caller supplies it so the same descent serves physical trees (where the
/// identifier is a block address) and virtual trees (resolved through an
/// object map). `compare` orders a search key against a stored key.
///
/// # Errors
///
/// Returns [`ApfsError::Malformed`] for a structurally invalid node, or any
/// error surfaced by `resolve`.
pub fn descend<R, F, C>(
    root: BtreeNode,
    reader: &mut R,
    mut resolve: F,
    search: &[u8],
    compare: C,
) -> Result<Option<Vec<u8>>>
where
    R: Read + Seek,
    F: FnMut(&mut R, u64) -> Result<BtreeNode>,
    C: Fn(&[u8], &[u8]) -> Ordering,
{
    let info = root.btree_info()?.ok_or(ApfsError::Malformed {
        structure: "btree_node_phys_t",
        reason: "descent must start at a root node",
    })?;
    let key_len = info.key_size as usize;
    let leaf_val_len = info.val_size as usize;

    let mut node = root;
    loop {
        if node.is_leaf() {
            let found = node.find_equal(search, key_len, leaf_val_len, &compare)?;
            return Ok(found.and_then(|entry| entry.value).map(<[u8]>::to_vec));
        }
        let child_oid = child_link(&node, search, key_len, &compare)?;
        node = resolve(reader, child_oid)?;
    }
}

/// Walks a B-tree from `root` to the leaf and returns the key and value bytes
/// of the entry with the largest key that is `<= search`.
///
/// This is the predecessor descent used by range lookups such as object-map
/// resolution, where the search key need not be present exactly. `resolve`
/// and `compare` behave as in [`descend`]. A ghost (a key with no value) at
/// the predecessor position yields `None`.
///
/// # Errors
///
/// Returns [`ApfsError::Malformed`] for a structurally invalid node, or any
/// error surfaced by `resolve`.
pub fn descend_le<R, F, C>(
    root: BtreeNode,
    reader: &mut R,
    mut resolve: F,
    search: &[u8],
    compare: C,
) -> Result<Option<(Vec<u8>, Vec<u8>)>>
where
    R: Read + Seek,
    F: FnMut(&mut R, u64) -> Result<BtreeNode>,
    C: Fn(&[u8], &[u8]) -> Ordering,
{
    let info = root.btree_info()?.ok_or(ApfsError::Malformed {
        structure: "btree_node_phys_t",
        reason: "descent must start at a root node",
    })?;
    let key_len = info.key_size as usize;
    let leaf_val_len = info.val_size as usize;

    let mut node = root;
    loop {
        if node.is_leaf() {
            let found = node.find_le(search, key_len, leaf_val_len, &compare)?;
            return Ok(found.and_then(|entry| {
                entry
                    .value
                    .map(|value| (entry.key.to_vec(), value.to_vec()))
            }));
        }
        let child_oid = child_link(&node, search, key_len, &compare)?;
        node = resolve(reader, child_oid)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_common::iter::FsTryIterator;
    use std::io::Cursor;

    const NODE_SIZE: usize = 4096;

    /// Builds a fixed-kv node with `u64` keys and `value_len`-byte values.
    ///
    /// `entries` are already sorted by key. When `root` is set, a
    /// `btree_info_t` trailer is appended describing 8-byte keys and
    /// `leaf_val_len`-byte leaf values.
    fn build_node(
        level: u16,
        leaf: bool,
        root: bool,
        entries: &[(u64, Vec<u8>)],
        leaf_val_len: usize,
    ) -> Vec<u8> {
        let mut block = vec![0u8; NODE_SIZE];
        let mut flags = BtnodeFlags::FIXED_KV_SIZE;
        if leaf {
            flags |= BtnodeFlags::LEAF;
        }
        if root {
            flags |= BtnodeFlags::ROOT;
        }
        block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
        block[34..36].copy_from_slice(&level.to_le_bytes());
        block[36..40].copy_from_slice(&(entries.len() as u32).to_le_bytes());

        // Table of contents directly after the header (btn_table_space.off 0).
        let toc_len = entries.len() * 4;
        block[40..42].copy_from_slice(&0u16.to_le_bytes());
        block[42..44].copy_from_slice(&(toc_len as u16).to_le_bytes());

        let key_area = BTN_DATA_OFFSET + toc_len;
        let value_end = if root {
            NODE_SIZE - BTREE_INFO_SIZE
        } else {
            NODE_SIZE
        };
        let val_len = entries.first().map_or(0, |(_, v)| v.len());

        for (i, (key, value)) in entries.iter().enumerate() {
            let k_off = (i * 8) as u16;
            let v_off = ((i + 1) * value.len()) as u16;
            let toc = BTN_DATA_OFFSET + i * 4;
            block[toc..toc + 2].copy_from_slice(&k_off.to_le_bytes());
            block[toc + 2..toc + 4].copy_from_slice(&v_off.to_le_bytes());

            let ks = key_area + i * 8;
            block[ks..ks + 8].copy_from_slice(&key.to_le_bytes());
            let vs = value_end - (i + 1) * value.len();
            block[vs..vs + value.len()].copy_from_slice(value);
        }

        if root {
            let info = NODE_SIZE - BTREE_INFO_SIZE;
            block[info..info + 4].copy_from_slice(&BtreeFlags::PHYSICAL.bits().to_le_bytes());
            block[info + 4..info + 8].copy_from_slice(&(NODE_SIZE as u32).to_le_bytes());
            block[info + 8..info + 12].copy_from_slice(&8u32.to_le_bytes());
            let stored_val = if leaf { leaf_val_len } else { val_len };
            block[info + 12..info + 16].copy_from_slice(&(stored_val as u32).to_le_bytes());
        }
        block
    }

    fn leaf_entries() -> Vec<(u64, Vec<u8>)> {
        vec![
            (10, vec![0xA0; 8]),
            (20, vec![0xA1; 8]),
            (30, vec![0xA2; 8]),
            (40, vec![0xA3; 8]),
        ]
    }

    fn cmp_u64(a: &[u8], b: &[u8]) -> Ordering {
        let av = u64::from_le_bytes(a[..8].try_into().unwrap());
        let bv = u64::from_le_bytes(b[..8].try_into().unwrap());
        av.cmp(&bv)
    }

    #[test]
    fn parses_header_fields() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        assert!(node.is_leaf());
        assert!(node.is_root());
        assert_eq!(node.level(), 0);
        assert_eq!(node.key_count(), 4);
        assert!(node.flags().contains(BtnodeFlags::FIXED_KV_SIZE));
    }

    #[test]
    fn rejects_a_block_smaller_than_the_header() {
        match BtreeNode::parse(vec![0u8; 16]) {
            Err(ApfsError::Truncated { structure, .. }) => {
                assert_eq!(structure, "btree_node_phys_t");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_toc_past_the_node() {
        let mut block = build_node(0, true, true, &leaf_entries(), 8);
        // Push btn_table_space.len well past the end of the block.
        block[42..44].copy_from_slice(&0xFFFFu16.to_le_bytes());
        match BtreeNode::parse(block) {
            Err(ApfsError::Malformed { reason, .. }) => {
                assert_eq!(reason, "table of contents extends past the node");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn entry_extracts_key_and_value() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        let entry = node.entry(2, 8, 8).unwrap();
        assert_eq!(u64::from_le_bytes(entry.key.try_into().unwrap()), 30);
        assert_eq!(entry.value.unwrap(), &[0xA2; 8]);
    }

    #[test]
    fn entry_index_out_of_range_is_rejected() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        assert!(node.entry(4, 8, 8).is_err());
    }

    #[test]
    fn btree_info_only_on_root() {
        let root = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        let info = root.btree_info().unwrap().unwrap();
        assert_eq!(info.key_size, 8);
        assert_eq!(info.val_size, 8);
        assert!(info.flags.contains(BtreeFlags::PHYSICAL));

        let nonroot = BtreeNode::parse(build_node(0, true, false, &leaf_entries(), 8)).unwrap();
        assert!(nonroot.btree_info().unwrap().is_none());
    }

    #[test]
    fn node_entries_iterator_yields_every_pair() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        let mut reader = Cursor::new(Vec::new());
        let mut iter = node.entries(8, 8);
        let mut keys = Vec::new();
        while let Some(entry) = iter.try_next(&mut reader).unwrap() {
            keys.push(u64::from_le_bytes(entry.key.try_into().unwrap()));
        }
        assert_eq!(keys, vec![10, 20, 30, 40]);
    }

    #[test]
    fn find_le_returns_the_predecessor() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        // Exact key present.
        let exact = node.find_le(&20u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
        assert_eq!(
            u64::from_le_bytes(exact.unwrap().key.try_into().unwrap()),
            20
        );
        // No exact key: the largest key below 25 is 20.
        let pred = node.find_le(&25u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
        assert_eq!(
            u64::from_le_bytes(pred.unwrap().key.try_into().unwrap()),
            20
        );
        // Search precedes every key.
        let none = node.find_le(&5u64.to_le_bytes(), 8, 8, cmp_u64).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn find_equal_locates_and_misses() {
        let node = BtreeNode::parse(build_node(0, true, true, &leaf_entries(), 8)).unwrap();
        let hit = node
            .find_equal(&30u64.to_le_bytes(), 8, 8, cmp_u64)
            .unwrap();
        assert_eq!(hit.unwrap().value.unwrap(), &[0xA2; 8]);
        let miss = node
            .find_equal(&25u64.to_le_bytes(), 8, 8, cmp_u64)
            .unwrap();
        assert!(miss.is_none());
    }

    #[test]
    fn descend_two_levels_to_a_leaf() {
        // Two leaves; a root index node keyed by each leaf's smallest key.
        let left = leaf_entries();
        let right = vec![(50u64, vec![0xB0; 8]), (60, vec![0xB1; 8])];
        let leaf_left = build_node(0, true, false, &left, 8);
        let leaf_right = build_node(0, true, false, &right, 8);

        // Root index node: key = leaf's first key, value = child oid.
        let index = vec![
            (10u64, 100u64.to_le_bytes().to_vec()),
            (50u64, 200u64.to_le_bytes().to_vec()),
        ];
        let root = BtreeNode::parse(build_node(1, false, true, &index, 8)).unwrap();

        let mut reader = Cursor::new(Vec::new());
        let resolve = |_: &mut Cursor<Vec<u8>>, oid: u64| {
            let block = match oid {
                100 => leaf_left.clone(),
                200 => leaf_right.clone(),
                _ => panic!("unexpected child oid {oid}"),
            };
            BtreeNode::parse(block)
        };

        let value = descend(
            root.clone(),
            &mut reader,
            resolve,
            &30u64.to_le_bytes(),
            cmp_u64,
        )
        .unwrap();
        assert_eq!(value.unwrap(), vec![0xA2; 8]);

        let value = descend(
            root.clone(),
            &mut reader,
            resolve,
            &60u64.to_le_bytes(),
            cmp_u64,
        )
        .unwrap();
        assert_eq!(value.unwrap(), vec![0xB1; 8]);

        let missing = descend(root, &mut reader, resolve, &35u64.to_le_bytes(), cmp_u64).unwrap();
        assert!(missing.is_none());
    }

    /// Builds a `BtnodeFlags::FIXED_KV_SIZE` node with `toc_off` and
    /// `toc_len` set independently of `nkeys` — used to forge the
    /// `nkeys`/TOC mismatch that exercises `toc_slice`'s bound check.
    fn build_node_with_toc(nkeys: u32, toc_off_in_data: u16, toc_len: u16, root: bool) -> Vec<u8> {
        let mut block = vec![0u8; NODE_SIZE];
        let mut flags = BtnodeFlags::FIXED_KV_SIZE | BtnodeFlags::LEAF;
        if root {
            flags |= BtnodeFlags::ROOT;
        }
        block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
        block[36..40].copy_from_slice(&nkeys.to_le_bytes());
        block[40..42].copy_from_slice(&toc_off_in_data.to_le_bytes());
        block[42..44].copy_from_slice(&toc_len.to_le_bytes());
        block
    }

    #[test]
    fn parse_accepts_a_block_exactly_the_header_size() {
        // A block whose length equals BTN_DATA_OFFSET has just enough room
        // for the header and an empty TOC; it must parse, not be rejected
        // as truncated.
        let block = vec![0u8; BTN_DATA_OFFSET];
        let node = BtreeNode::parse(block).unwrap();
        assert_eq!(node.key_count(), 0);
    }

    #[test]
    fn parse_honours_a_non_zero_table_space_offset() {
        // `btn_table_space.off` is an offset *within* `btn_data`, so
        // `toc_off` must be `BTN_DATA_OFFSET + off`, not `off` alone.
        // Forge a TOC that lives 16 bytes into the data area with a
        // single fixed-kv entry pointing at key 0xAA and value 0xBB.
        let mut block = vec![0u8; NODE_SIZE];
        let flags = BtnodeFlags::FIXED_KV_SIZE | BtnodeFlags::LEAF;
        block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
        block[36..40].copy_from_slice(&1u32.to_le_bytes()); // nkeys
        block[40..42].copy_from_slice(&16u16.to_le_bytes()); // table_space.off = 16
        block[42..44].copy_from_slice(&4u16.to_le_bytes()); // table_space.len = 4

        let toc = BTN_DATA_OFFSET + 16;
        // TOC: k_off = 4 (past the TOC itself), v_off = 8 (from value end).
        block[toc..toc + 2].copy_from_slice(&4u16.to_le_bytes());
        block[toc + 2..toc + 4].copy_from_slice(&8u16.to_le_bytes());
        // Key area starts at toc_off + toc_len = BTN_DATA_OFFSET + 20.
        let key_area = BTN_DATA_OFFSET + 16 + 4;
        block[key_area + 4..key_area + 12].copy_from_slice(&0xAAu64.to_le_bytes());
        let value_end = NODE_SIZE;
        block[value_end - 8..value_end].copy_from_slice(&0xBBu64.to_le_bytes());

        let node = BtreeNode::parse(block).unwrap();
        // If parse had used `BTN_DATA_OFFSET - off` (or anything but `+`)
        // for `toc_off`, the entry's key would read garbage instead of 0xAA.
        let entry = node.entry(0, 8, 8).unwrap();
        assert_eq!(u64::from_le_bytes(entry.key.try_into().unwrap()), 0xAA);
    }

    #[test]
    fn parse_accepts_a_toc_ending_exactly_at_the_block_end() {
        // Off-by-one boundary: `toc_end == block.len()` is in range; only
        // `>` is past the end. Build a non-root node whose TOC fills the
        // remainder of the data area.
        let toc_len_in_bytes = (NODE_SIZE - BTN_DATA_OFFSET) as u16;
        let block = build_node_with_toc(0, 0, toc_len_in_bytes, false);
        // Strictly equal to block.len() must succeed; only `toc_end >
        // block.len()` is the error path covered by
        // `rejects_a_toc_past_the_node`.
        BtreeNode::parse(block).unwrap();
    }

    #[test]
    fn level_returns_the_stored_value() {
        // Level is stored verbatim from `btn_level`; assert with a
        // non-{0,1} value so neither `-> 0` nor `-> 1` constant mutations
        // survive.
        let leaf = leaf_entries();
        let mut block = build_node(7, true, true, &leaf, 8);
        // build_node already wrote 7 at offset 34..36; sanity check.
        assert_eq!(
            u16::from_le_bytes(block[34..36].try_into().unwrap()),
            7,
            "test setup"
        );
        let node = BtreeNode::parse(block.clone()).unwrap();
        assert_eq!(node.level(), 7);

        // Also exercise a second non-trivial value to make `-> 7` constant
        // mutations equally unsurvivable.
        block[34..36].copy_from_slice(&42u16.to_le_bytes());
        let other = BtreeNode::parse(block).unwrap();
        assert_eq!(other.level(), 42);
    }

    #[test]
    fn toc_slice_uses_sum_not_product_for_bounds() {
        // Forge `nkeys=2` over a TOC that only holds one entry (4 bytes).
        // The bound `toc_off + toc_len` is `BTN_DATA_OFFSET + 4 = 60`;
        // `toc_off * toc_len` would be `224`, hiding the out-of-range
        // entry. `entry(1, ..)` must surface `Malformed`.
        let block = build_node_with_toc(2, 0, 4, false);
        let node = BtreeNode::parse(block).unwrap();
        let err = node.entry(1, 8, 8).unwrap_err();
        assert!(
            matches!(err, ApfsError::Malformed { reason, .. }
                if reason == "table-of-contents entry out of range"),
            "expected toc-out-of-range malformed, got {err:?}"
        );
    }

    /// Builds a `kvloc_t` (variable-size) non-leaf node with one entry
    /// whose value is `val_len` bytes long. Used to drive a value shorter
    /// than the 8-byte child-link minimum into `child_link`.
    fn build_kvloc_index_node(key: u64, value: &[u8]) -> Vec<u8> {
        let mut block = vec![0u8; NODE_SIZE];
        // Non-leaf, non-fixed-kv, root.
        let flags = BtnodeFlags::ROOT;
        block[32..34].copy_from_slice(&flags.bits().to_le_bytes());
        block[34..36].copy_from_slice(&1u16.to_le_bytes()); // level = 1
        block[36..40].copy_from_slice(&1u32.to_le_bytes()); // nkeys
        block[40..42].copy_from_slice(&0u16.to_le_bytes()); // table_space.off
        block[42..44].copy_from_slice(&8u16.to_le_bytes()); // table_space.len
        // kvloc_t: u16 k_off, k_len, v_off, v_len.
        let toc = BTN_DATA_OFFSET;
        block[toc..toc + 2].copy_from_slice(&0u16.to_le_bytes()); // k_off
        block[toc + 2..toc + 4].copy_from_slice(&8u16.to_le_bytes()); // k_len
        block[toc + 4..toc + 6].copy_from_slice(&(value.len() as u16).to_le_bytes()); // v_off
        block[toc + 6..toc + 8].copy_from_slice(&(value.len() as u16).to_le_bytes()); // v_len
        // Key bytes.
        let key_area = BTN_DATA_OFFSET + 8;
        block[key_area..key_area + 8].copy_from_slice(&key.to_le_bytes());
        // Value bytes — offset is measured back from the value-area end,
        // which for a root node is `NODE_SIZE - BTREE_INFO_SIZE`.
        let value_end = NODE_SIZE - BTREE_INFO_SIZE;
        let vs = value_end - value.len();
        block[vs..vs + value.len()].copy_from_slice(value);
        // btree_info_t trailer: 8-byte keys, 0 (variable) values.
        let info = NODE_SIZE - BTREE_INFO_SIZE;
        block[info + 4..info + 8].copy_from_slice(&(NODE_SIZE as u32).to_le_bytes());
        block[info + 8..info + 12].copy_from_slice(&8u32.to_le_bytes());
        block[info + 12..info + 16].copy_from_slice(&0u32.to_le_bytes());
        block
    }

    #[test]
    fn child_link_rejects_a_short_value() {
        // A kvloc_t non-leaf with a 4-byte value — shorter than the
        // 8-byte child-link minimum. `descend` must surface `Malformed`;
        // `< 8` mutated to `> 8` would let the short value through.
        let root = BtreeNode::parse(build_kvloc_index_node(10, &[1u8; 4])).unwrap();
        let mut reader = Cursor::new(Vec::new());
        let resolve =
            |_: &mut Cursor<Vec<u8>>, _: u64| -> Result<BtreeNode> { panic!("must not resolve") };
        let err = descend(root, &mut reader, resolve, &10u64.to_le_bytes(), cmp_u64).unwrap_err();
        assert!(
            matches!(err, ApfsError::Malformed { reason, .. }
                if reason == "child link shorter than an object identifier"),
            "expected short-child-link malformed, got {err:?}"
        );
    }

    #[test]
    fn child_index_descends_asymmetric_keys() {
        // Five-key index node: child_index must take multiple binary-
        // search iterations to land on key 30 → child oid 300.
        // The `lo + (hi - lo) / 2` midpoint mutated to `lo + (hi + lo) /
        // 2` returns out-of-range indices on the second iteration, so
        // the descent surfaces `Malformed` instead of the right child.
        let index = vec![
            (10u64, 100u64.to_le_bytes().to_vec()),
            (20u64, 200u64.to_le_bytes().to_vec()),
            (30u64, 300u64.to_le_bytes().to_vec()),
            (40u64, 400u64.to_le_bytes().to_vec()),
            (50u64, 500u64.to_le_bytes().to_vec()),
        ];
        let root_block = build_node(1, false, true, &index, 8);
        let root = BtreeNode::parse(root_block).unwrap();

        // Synthesise five distinct one-entry leaves keyed at each index.
        let leaves: Vec<Vec<u8>> = [10u64, 20, 30, 40, 50]
            .into_iter()
            .map(|k| build_node(0, true, false, &[(k, vec![k as u8; 8])], 8))
            .collect();

        let mut reader = Cursor::new(Vec::new());
        let resolve = |_: &mut Cursor<Vec<u8>>, oid: u64| {
            let i = match oid {
                100 => 0,
                200 => 1,
                300 => 2,
                400 => 3,
                500 => 4,
                _ => panic!("unexpected child oid {oid}"),
            };
            BtreeNode::parse(leaves[i].clone())
        };

        for (search, expected) in [(10u64, 10u8), (20, 20), (30, 30), (40, 40), (50, 50)] {
            let value = descend(
                root.clone(),
                &mut reader,
                resolve,
                &search.to_le_bytes(),
                cmp_u64,
            )
            .unwrap()
            .unwrap_or_else(|| panic!("missing value for {search}"));
            assert_eq!(value, vec![expected; 8]);
        }
    }
}
