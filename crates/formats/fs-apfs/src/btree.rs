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
#[allow(
    clippy::struct_field_names,
    reason = "the btn_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
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
#[allow(
    clippy::struct_field_names,
    reason = "the bt_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
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
/// The reader argument of [`fsmnt_parser_core`](crate::io)'s iterator trait is unused
/// — a node's entries are already in memory — but the trait is implemented so
/// node iteration composes with the rest of the crate.
pub struct NodeEntries<'a> {
    node: &'a BtreeNode,
    key_len: usize,
    val_len: usize,
    index: u32,
}

impl fsmnt_parser_core::iter::FsTryIteratorType for NodeEntries<'_> {
    type Error = ApfsError;
    type Item<'b> = Entry<'b>;
}

impl<R: Read + Seek> fsmnt_parser_core::iter::FsTryIterator<R> for NodeEntries<'_> {
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
#[path = "btree_tests/mod.rs"]
mod tests;
