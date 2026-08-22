//! File-system records: the `j_key_t` header, record-type dispatch, and the
//! volume catalog B-tree.
//!
//! A volume's files and directories live as key/value records in the catalog
//! (file-system) B-tree. Every record key begins with [`JKey`], an 8-byte
//! header packing an object identifier and a record type.
//!
//! Apple File System Reference, `07-file-system-objects.md` and
//! `08-file-system-constants.md`.

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::ops::ControlFlow;

use crate::btree::{BtreeNode, descend};
use crate::checkpoint::read_block;
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::omap::Omap;
use crate::types::{Oid, Xid};

/// Mask selecting the object identifier from `obj_id_and_type`.
pub const OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
/// Shift selecting the record type from `obj_id_and_type`.
pub const OBJ_TYPE_SHIFT: u64 = 60;
/// Smallest object identifier belonging to a volume group's system volume.
pub const SYSTEM_OBJ_ID_MARK: u64 = 0x0FFF_FFFF_0000_0000;

/// Size of the `j_key_t` header.
pub const J_KEY_SIZE: usize = 8;

/// A file-system record type (`j_obj_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JObjType {
    /// Any type (`APFS_TYPE_ANY`) — used as a wildcard, not stored.
    Any,
    /// Snapshot metadata.
    SnapMetadata,
    /// A physical extent record.
    Extent,
    /// An inode.
    Inode,
    /// An extended attribute.
    Xattr,
    /// A hard-link sibling.
    SiblingLink,
    /// A data-stream id record.
    DstreamId,
    /// Per-file encryption state.
    CryptoState,
    /// A file extent.
    FileExtent,
    /// A directory entry.
    DirRec,
    /// Directory statistics.
    DirStats,
    /// A snapshot name.
    SnapName,
    /// A hard-link sibling map.
    SiblingMap,
    /// File-info (sealed-volume content hashes).
    FileInfo,
    /// An invalid record type (`APFS_TYPE_INVALID`).
    Invalid,
    /// A record type this parser does not recognize.
    Unknown(u8),
}

impl JObjType {
    /// Decodes a record type from its 4-bit `j_obj_types` value.
    #[must_use]
    pub fn from_value(value: u8) -> Self {
        match value {
            0 => Self::Any,
            1 => Self::SnapMetadata,
            2 => Self::Extent,
            3 => Self::Inode,
            4 => Self::Xattr,
            5 => Self::SiblingLink,
            6 => Self::DstreamId,
            7 => Self::CryptoState,
            8 => Self::FileExtent,
            9 => Self::DirRec,
            10 => Self::DirStats,
            11 => Self::SnapName,
            12 => Self::SiblingMap,
            13 => Self::FileInfo,
            15 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }

    /// The 4-bit `j_obj_types` value of this record type.
    #[must_use]
    pub fn as_value(self) -> u8 {
        match self {
            Self::Any => 0,
            Self::SnapMetadata => 1,
            Self::Extent => 2,
            Self::Inode => 3,
            Self::Xattr => 4,
            Self::SiblingLink => 5,
            Self::DstreamId => 6,
            Self::CryptoState => 7,
            Self::FileExtent => 8,
            Self::DirRec => 9,
            Self::DirStats => 10,
            Self::SnapName => 11,
            Self::SiblingMap => 12,
            Self::FileInfo => 13,
            Self::Invalid => 15,
            Self::Unknown(value) => value,
        }
    }
}

/// A parsed `j_key_t` header — the prefix of every file-system record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JKey {
    /// The object identifier the record belongs to.
    pub obj_id: u64,
    /// The record's type.
    pub kind: JObjType,
}

impl JKey {
    /// Parses the `j_key_t` header from the start of a record key.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] when fewer than [`J_KEY_SIZE`] bytes
    /// are available.
    pub fn parse(key: &[u8]) -> Result<Self> {
        if key.len() < J_KEY_SIZE {
            return Err(ApfsError::Truncated {
                structure: "j_key_t",
                expected: J_KEY_SIZE,
                actual: key.len(),
            });
        }
        let raw = u64::from_le_bytes([
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
        ]);
        Ok(Self {
            obj_id: raw & OBJ_ID_MASK,
            kind: JObjType::from_value((raw >> OBJ_TYPE_SHIFT) as u8),
        })
    }

    /// Whether the object belongs to the system volume of a volume group.
    #[must_use]
    pub fn is_system_object(self) -> bool {
        self.obj_id >= SYSTEM_OBJ_ID_MARK
    }
}

/// Packs a `(obj_id, kind)` pair back into the raw `obj_id_and_type` word the
/// catalog stores as the first eight bytes of a record key.
///
/// The type sits in the top 4 bits (above `OBJ_TYPE_SHIFT`) and the object id
/// is masked to the bottom 60. The two halves are bit-disjoint, so combining
/// them with `|` and with `^` is mathematically equivalent here.
#[cfg_attr(test, mutants::skip)] // Equivalent: type and id bits do not overlap.
#[must_use]
fn pack_jkey(obj_id: u64, kind: JObjType) -> u64 {
    (u64::from(kind.as_value()) << OBJ_TYPE_SHIFT) | (obj_id & OBJ_ID_MASK)
}

/// Orders two catalog record keys by their `j_key_t` header — object id
/// ascending, then record type ascending.
///
/// A full catalog comparison appends a type-specific subkey comparison (by
/// name for directory entries and extended attributes, by logical offset for
/// file extents); those are supplied by the record-type modules.
#[must_use]
pub fn j_key_header_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let (Ok(a), Ok(b)) = (JKey::parse(a), JKey::parse(b)) else {
        // A malformed key sorts deterministically by raw bytes so traversal
        // stays total-ordered rather than panicking.
        return a.cmp(b);
    };
    a.obj_id
        .cmp(&b.obj_id)
        .then(a.kind.as_value().cmp(&b.kind.as_value()))
}

/// One file-system record read from the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRecord {
    /// The record's parsed `j_key_t` header.
    pub key_header: JKey,
    /// The complete record key, including the `j_key_t` header.
    pub key: Vec<u8>,
    /// The complete record value.
    pub value: Vec<u8>,
}

/// Maximum catalog B-tree depth walked before a tree is treated as corrupt.
const MAX_CATALOG_DEPTH: u32 = 32;

/// Whether the non-leaf subtree rooted at `node`'s entry `index` ends before
/// the bound `target`, and can be skipped without missing any matching record.
///
/// This is a pure performance optimization: when the *next* separator (the
/// first key of the following subtree) is still below `target`, every key in
/// the current subtree is also below `target`, so it cannot contribute. The
/// caller's leaf-level filter discards non-matching records anyway, so a
/// mutated `index + 1 < node.key_count()` that loses the lookahead only
/// descends extra subtrees — the records returned are unchanged.
#[cfg_attr(test, mutants::skip)] // Equivalent: leaf filter preserves correctness even without this prune.
fn subtree_ends_before(node: &BtreeNode, index: u32, target: u64) -> Result<bool> {
    if index + 1 < node.key_count() {
        let next = JKey::parse(node.entry(index + 1, 0, 0)?.key)?.obj_id;
        return Ok(next < target);
    }
    Ok(false)
}

/// A volume's catalog (file-system records) B-tree.
///
/// The catalog is a *virtual* tree: its nodes are virtual objects resolved
/// through the volume's object map.
#[derive(Debug, Clone)]
pub struct Catalog {
    root_oid: Oid,
    omap: Omap,
    block_size: u32,
    xid: Xid,
}

impl Catalog {
    /// Creates a catalog handle.
    ///
    /// `root_oid` is the volume's `apfs_root_tree_oid`; `omap` is the volume's
    /// object map; `xid` is the transaction to read the volume as of.
    #[must_use]
    pub fn new(root_oid: Oid, omap: Omap, block_size: u32, xid: Xid) -> Self {
        Self {
            root_oid,
            omap,
            block_size,
            xid,
        }
    }

    /// Resolves a virtual catalog-tree node identifier to a parsed node.
    fn resolve_node<T: Read + Seek>(&self, reader: &mut T, node_oid: u64) -> Result<BtreeNode> {
        let mapping = self
            .omap
            .resolve(reader, self.block_size, Oid(node_oid), self.xid)?
            .ok_or(ApfsError::NotFound {
                what: "catalog tree node",
            })?;
        let address = mapping.paddr.as_block().ok_or(ApfsError::Malformed {
            structure: "omap_val_t",
            reason: "catalog node address is negative",
        })?;
        BtreeNode::parse(read_block(reader, self.block_size, address)?)
    }

    /// Returns every catalog record belonging to `obj_id`, across all record
    /// types, in catalog order.
    ///
    /// Records for one object are contiguous in the catalog B-tree — object
    /// id is the primary sort key — so the walk descends only the subtrees
    /// whose key range can hold `obj_id`, not the whole tree.
    ///
    /// # Errors
    ///
    /// Propagates I/O and [`ApfsError::Malformed`] errors, and returns
    /// [`ApfsError::Malformed`] if the tree is deeper than
    /// `MAX_CATALOG_DEPTH`.
    pub fn records_for<T: Read + Seek>(
        &self,
        reader: &mut T,
        obj_id: u64,
    ) -> Result<Vec<CatalogRecord>> {
        self.collect(reader, &|header| header.obj_id == obj_id, Some(obj_id))
    }

    /// Visits records belonging to `obj_id` without cloning their key and
    /// value bytes into an intermediate collection.
    pub(crate) fn visit_records_for<T, F>(
        &self,
        reader: &mut T,
        obj_id: u64,
        mut visitor: F,
    ) -> Result<()>
    where
        T: Read + Seek,
        F: FnMut(JKey, &[u8], &[u8]) -> Result<()>,
    {
        let root = self.resolve_node(reader, self.root_oid.0)?;
        let _ = self.walk(
            reader,
            &root,
            &|header| header.obj_id == obj_id,
            Some(obj_id),
            0,
            &mut |header, key, value| {
                visitor(header, key, value)?;
                Ok(ControlFlow::Continue(()))
            },
        )?;
        Ok(())
    }

    /// Tests records belonging to `obj_id`, stopping at the first match.
    pub(crate) fn any_record_for<T, F>(
        &self,
        reader: &mut T,
        obj_id: u64,
        mut predicate: F,
    ) -> Result<bool>
    where
        T: Read + Seek,
        F: FnMut(JKey, &[u8], &[u8]) -> Result<bool>,
    {
        let root = self.resolve_node(reader, self.root_oid.0)?;
        let mut matched = false;
        let _ = self.walk(
            reader,
            &root,
            &|header| header.obj_id == obj_id,
            Some(obj_id),
            0,
            &mut |header, key, value| {
                matched = predicate(header, key, value)?;
                Ok(if matched {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                })
            },
        )?;
        Ok(matched)
    }

    /// Returns every catalog record of the given record type, tree-wide.
    ///
    /// Used to enumerate trees keyed by something other than an object id —
    /// for example the snapshot-metadata tree. Record type is not the tree's
    /// sort key, so this is necessarily a whole-tree walk.
    ///
    /// # Errors
    ///
    /// As [`Catalog::records_for`].
    pub fn records_of_kind<T: Read + Seek>(
        &self,
        reader: &mut T,
        kind: JObjType,
    ) -> Result<Vec<CatalogRecord>> {
        self.collect(reader, &|header| header.kind == kind, None)
    }

    /// Looks up the single catalog record identified by `(obj_id, kind)` and
    /// returns its value bytes, via a keyed B-tree descent.
    ///
    /// Suitable for record types with exactly one record per object — an
    /// inode, a physical-extent record, a sibling-map record. For record
    /// types that repeat per object (directory entries, extended attributes,
    /// file extents), use [`Catalog::records_for`].
    ///
    /// # Errors
    ///
    /// Propagates I/O and [`ApfsError::Malformed`] errors from the descent.
    pub fn find_record<T: Read + Seek>(
        &self,
        reader: &mut T,
        obj_id: u64,
        kind: JObjType,
    ) -> Result<Option<Vec<u8>>> {
        let root = self.resolve_node(reader, self.root_oid.0)?;
        let search = pack_jkey(obj_id, kind).to_le_bytes();
        descend(
            root,
            reader,
            |reader, child| self.resolve_node(reader, child),
            &search,
            j_key_header_cmp,
        )
    }

    /// Collects every leaf record whose `j_key_t` header satisfies `keep`.
    ///
    /// When `bound` is `Some(obj_id)`, non-leaf subtrees that cannot hold that
    /// object id are skipped; when `None`, the whole tree is walked.
    fn collect<T: Read + Seek>(
        &self,
        reader: &mut T,
        keep: &dyn Fn(&JKey) -> bool,
        bound: Option<u64>,
    ) -> Result<Vec<CatalogRecord>> {
        let root = self.resolve_node(reader, self.root_oid.0)?;
        let mut records = Vec::new();
        let _ = self.walk(reader, &root, keep, bound, 0, &mut |header, key, value| {
            records.push(CatalogRecord {
                key_header: header,
                key: key.to_vec(),
                value: value.to_vec(),
            });
            Ok(ControlFlow::Continue(()))
        })?;
        Ok(records)
    }

    /// Recursively collects matching records from `node` and its children,
    /// pruning subtrees that cannot hold `bound` when it is set.
    fn walk<T, F>(
        &self,
        reader: &mut T,
        node: &BtreeNode,
        keep: &dyn Fn(&JKey) -> bool,
        bound: Option<u64>,
        depth: u32,
        visitor: &mut F,
    ) -> Result<ControlFlow<()>>
    where
        T: Read + Seek,
        F: FnMut(JKey, &[u8], &[u8]) -> Result<ControlFlow<()>>,
    {
        if depth >= MAX_CATALOG_DEPTH {
            return Err(ApfsError::Malformed {
                structure: "fstree",
                reason: "catalog B-tree is deeper than the supported limit",
            });
        }
        for index in 0..node.key_count() {
            // The catalog tree has variable-size keys and values, so the
            // fixed-size arguments are unused.
            let entry = node.entry(index, 0, 0)?;
            if node.is_leaf() {
                let header = JKey::parse(entry.key)?;
                if keep(&header)
                    && visitor(header, entry.key, entry.value.unwrap_or(&[]))?.is_break()
                {
                    return Ok(ControlFlow::Break(()));
                }
                continue;
            }
            // A non-leaf separator is the first key of its subtree. With an
            // object-id bound, separators ascend, so a separator past the
            // target ends the walk and a subtree ending before the target is
            // skipped.
            if let Some(target) = bound {
                let separator = JKey::parse(entry.key)?.obj_id;
                if separator > target {
                    break;
                }
                if subtree_ends_before(node, index, target)? {
                    continue;
                }
            }
            let child = entry.value.ok_or(ApfsError::Malformed {
                structure: "fstree",
                reason: "non-leaf catalog entry has no child link",
            })?;
            if child.len() < 8 {
                return Err(ApfsError::Malformed {
                    structure: "fstree",
                    reason: "catalog child link shorter than an object id",
                });
            }
            let child_oid = u64::from_le_bytes([
                child[0], child[1], child[2], child[3], child[4], child[5], child[6], child[7],
            ]);
            let child_node = self.resolve_node(reader, child_oid)?;
            if self
                .walk(reader, &child_node, keep, bound, depth + 1, visitor)?
                .is_break()
            {
                return Ok(ControlFlow::Break(()));
            }
        }
        Ok(ControlFlow::Continue(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::object::OBJ_PHYSICAL;
    use fsmnt_testkit::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn j_key_splits_object_id_and_type() {
        let mut key = [0u8; 8];
        // type 3 (INODE) in the high nibble, object id 0x42 in the low bits.
        let raw = (3u64 << OBJ_TYPE_SHIFT) | 0x42;
        key.copy_from_slice(&raw.to_le_bytes());
        let parsed = JKey::parse(&key).unwrap();
        assert_eq!(parsed.obj_id, 0x42);
        assert_eq!(parsed.kind, JObjType::Inode);
    }

    #[test]
    fn j_key_rejects_a_short_buffer() {
        assert!(matches!(
            JKey::parse(&[0u8; 4]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn record_type_round_trips_and_handles_unknown() {
        for value in [0u8, 1, 3, 9, 13, 15] {
            assert_eq!(JObjType::from_value(value).as_value(), value);
        }
        assert_eq!(JObjType::from_value(14), JObjType::Unknown(14));
    }

    #[test]
    fn header_comparison_orders_by_object_id_then_type() {
        let key = |oid: u64, ty: u64| ((ty << OBJ_TYPE_SHIFT) | oid).to_le_bytes();
        // Object id is primary even though type sits in the high nibble.
        assert_eq!(j_key_header_cmp(&key(5, 9), &key(6, 1)), Ordering::Less);
        // Same object id: type breaks the tie.
        assert_eq!(j_key_header_cmp(&key(5, 3), &key(5, 9)), Ordering::Less);
        assert_eq!(j_key_header_cmp(&key(5, 9), &key(5, 9)), Ordering::Equal);
    }

    /// Builds a physical fixed-kv omap B-tree mapping node oids to addresses.
    fn omap_tree(entries: &[(u64, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes()); // ROOT|LEAF|FIXED
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(entries.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(entries.len() * 4)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        let key_area = BTN_DATA_OFFSET + entries.len() * 4;
        let value_end = BLK - BTREE_INFO_SIZE;
        for (i, &(oid, xid, paddr)) in entries.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 4;
            b[toc..toc + 2].copy_from_slice(
                &u16::try_from(i * 16)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 2..toc + 4].copy_from_slice(
                &u16::try_from((i + 1) * 16)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            let ks = key_area + i * 16;
            b[ks..ks + 8].copy_from_slice(&oid.to_le_bytes());
            b[ks + 8..ks + 16].copy_from_slice(&xid.to_le_bytes());
            let vs = value_end - (i + 1) * 16;
            b[vs + 4..vs + 8].copy_from_slice(
                &u32::try_from(BLK)
                    .expect("the test fixture value fits in u32")
                    .to_le_bytes(),
            );
            b[vs + 8..vs + 16].copy_from_slice(&paddr.to_le_bytes());
        }
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes());
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes());
        b
    }

    fn omap_phys(tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes());
        b[0x30..0x38].copy_from_slice(&tree_oid.to_le_bytes());
        b
    }

    /// Builds a variable-kv root+leaf catalog node from `(key, value)` pairs.
    fn catalog_leaf(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        catalog_node(records, 0x0003) // ROOT | LEAF
    }

    /// Builds a variable-kv catalog node with the given `btn_flags`.
    fn catalog_node(records: &[(Vec<u8>, Vec<u8>)], flags: u16) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(records.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        let toc_len = records.len() * 8; // kvloc entries
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(toc_len)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );

        let key_area = BTN_DATA_OFFSET + toc_len;
        // A root node reserves a btree_info trailer; the value area ends
        // before it. A non-root node's value area runs to the block end.
        let value_end = if flags & 0x0001 != 0 {
            BLK - BTREE_INFO_SIZE
        } else {
            BLK
        };
        let mut key_cursor = 0usize;
        let mut val_cursor = 0usize;
        for (i, (key, value)) in records.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 8;
            b[toc..toc + 2].copy_from_slice(
                &u16::try_from(key_cursor)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 2..toc + 4].copy_from_slice(
                &u16::try_from(key.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            val_cursor += value.len();
            b[toc + 4..toc + 6].copy_from_slice(
                &u16::try_from(val_cursor)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 6..toc + 8].copy_from_slice(
                &u16::try_from(value.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );

            let ks = key_area + key_cursor;
            b[ks..ks + key.len()].copy_from_slice(key);
            let vs = value_end - val_cursor;
            b[vs..vs + value.len()].copy_from_slice(value);
            key_cursor += key.len();
        }
        b
    }

    /// Builds a `j_key_t` key (header only) for object `oid` of type `ty`.
    fn jkey(oid: u64, ty: u64) -> Vec<u8> {
        ((ty << OBJ_TYPE_SHIFT) | oid).to_le_bytes().to_vec()
    }

    #[test]
    fn records_for_collects_every_record_of_an_object() {
        // A single-leaf catalog with records for objects 2 and 3.
        let leaf = catalog_leaf(&[
            (jkey(2, 3), vec![0xAA; 4]), // object 2, inode
            (jkey(2, 9), vec![0xBB; 6]), // object 2, dir-rec
            (jkey(3, 3), vec![0xCC; 4]), // object 3, inode
        ]);
        // Catalog root is virtual oid 200, mapped by the volume omap to the
        // catalog leaf block.
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(200, 1, 2)])); // (oid 200, xid 1) -> block 2
        image.extend(leaf); // block 2

        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(200),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let mut reader = Cursor::new(image);

        let object2 = catalog.records_for(&mut reader, 2).unwrap();
        assert_eq!(object2.len(), 2);
        assert_eq!(object2[0].key_header.kind, JObjType::Inode);
        assert_eq!(object2[1].key_header.kind, JObjType::DirRec);
        assert_eq!(object2[1].value, vec![0xBB; 6]);

        let object3 = catalog.records_for(&mut reader, 3).unwrap();
        assert_eq!(object3.len(), 1);

        let missing = catalog.records_for(&mut reader, 99).unwrap();
        assert!(missing.is_empty());
    }

    /// A two-level catalog: an index root over two leaves. Object 5's records
    /// straddle the leaf boundary — `(5, Inode)` and `(5, Xattr)` in leaf 1,
    /// `(5, DirRec)` in leaf 2 — so a pruned walk must still visit both.
    fn two_level_catalog() -> (Catalog, Cursor<Vec<u8>>) {
        let v = |byte: u8| vec![byte; 4];
        let leaf1 = catalog_node(
            &[
                (jkey(2, 3), v(0x02)), // (2, Inode)
                (jkey(5, 3), v(0x53)), // (5, Inode)
                (jkey(5, 4), v(0x54)), // (5, Xattr)
            ],
            0x0002, // LEAF
        );
        let leaf2 = catalog_node(
            &[
                (jkey(5, 9), v(0x59)), // (5, DirRec)
                (jkey(8, 3), v(0x83)), // (8, Inode)
            ],
            0x0002, // LEAF
        );
        // Index root: each separator is its child leaf's first key.
        let index = catalog_node(
            &[
                (jkey(2, 3), 301u64.to_le_bytes().to_vec()),
                (jkey(5, 9), 302u64.to_le_bytes().to_vec()),
            ],
            0x0001, // ROOT
        );
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(300, 1, 2), (301, 1, 3), (302, 1, 4)]));
        image.extend(index); // block 2
        image.extend(leaf1); // block 3
        image.extend(leaf2); // block 4
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(300),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn records_for_collects_an_object_spanning_two_leaves() {
        let (catalog, mut reader) = two_level_catalog();
        let obj5 = catalog.records_for(&mut reader, 5).unwrap();
        assert_eq!(
            obj5.iter().map(|r| r.key_header.kind).collect::<Vec<_>>(),
            [JObjType::Inode, JObjType::Xattr, JObjType::DirRec]
        );
        // Objects confined to a single leaf.
        assert_eq!(catalog.records_for(&mut reader, 2).unwrap().len(), 1);
        assert_eq!(catalog.records_for(&mut reader, 8).unwrap().len(), 1);
        assert!(catalog.records_for(&mut reader, 99).unwrap().is_empty());
    }

    #[test]
    fn find_record_descends_to_a_single_record() {
        let (catalog, mut reader) = two_level_catalog();
        // A record in either leaf is reached by the descent.
        assert_eq!(
            catalog
                .find_record(&mut reader, 5, JObjType::Inode)
                .unwrap(),
            Some(vec![0x53; 4])
        );
        assert_eq!(
            catalog
                .find_record(&mut reader, 5, JObjType::DirRec)
                .unwrap(),
            Some(vec![0x59; 4])
        );
        assert_eq!(
            catalog
                .find_record(&mut reader, 8, JObjType::Inode)
                .unwrap(),
            Some(vec![0x83; 4])
        );
        // A missing object, and an object that lacks the requested type.
        assert!(
            catalog
                .find_record(&mut reader, 99, JObjType::Inode)
                .unwrap()
                .is_none()
        );
        assert!(
            catalog
                .find_record(&mut reader, 2, JObjType::DirRec)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn inode_lookup_returns_present_record_and_none_for_missing() {
        // Drives `Inode::lookup`, whose body the mutator can replace with
        // `Ok(None)`. Two assertions are needed to catch that: a missing
        // object returns `None`, but a present one must return `Some`.
        use crate::inode::{Inode, J_INODE_VAL_SIZE};
        let leaf = catalog_leaf(&[(
            jkey(2, 3), // (object 2, inode)
            vec![0u8; J_INODE_VAL_SIZE],
        )]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(200, 1, 2)]));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(200),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let mut reader = Cursor::new(image);

        let present = Inode::lookup(&catalog, &mut reader, 2).unwrap();
        assert!(present.is_some(), "object 2 has an inode record");
        let missing = Inode::lookup(&catalog, &mut reader, 99).unwrap();
        assert!(missing.is_none(), "object 99 has no inode record");
    }

    #[test]
    fn is_system_object_classifies_around_the_mark() {
        // The predicate's threshold is asymmetric: one object on each side of
        // the system-volume mark must classify oppositely, killing both the
        // `true`/`false` body mutants and the `>=` → `<` operator flip.
        let above = JKey {
            obj_id: SYSTEM_OBJ_ID_MARK,
            kind: JObjType::Inode,
        };
        let just_below = JKey {
            obj_id: SYSTEM_OBJ_ID_MARK - 1,
            kind: JObjType::Inode,
        };
        let small = JKey {
            obj_id: 2,
            kind: JObjType::Inode,
        };
        assert!(above.is_system_object());
        assert!(!just_below.is_system_object());
        assert!(!small.is_system_object());
    }

    /// Builds a three-leaf catalog where target object 5's records live in
    /// the FIRST leaf and a separator just beyond the target sits in the
    /// index. The `next < target` pruning in `Catalog::walk` must descend
    /// leaf 1 anyway; a `>` mutation would skip it and miss the record.
    fn pruning_fixture() -> (Catalog, Cursor<Vec<u8>>) {
        let v = |byte: u8| vec![byte; 4];
        let leaf1 = catalog_node(
            &[
                (jkey(2, 3), v(0x02)), // (2, Inode)
                (jkey(5, 3), v(0x53)), // (5, Inode) — the target
            ],
            0x0002,
        );
        let leaf2 = catalog_node(&[(jkey(10, 3), v(0x83))], 0x0002);
        let index = catalog_node(
            &[
                (jkey(2, 3), 301u64.to_le_bytes().to_vec()),
                (jkey(10, 3), 302u64.to_le_bytes().to_vec()),
            ],
            0x0001,
        );
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(300, 1, 2), (301, 1, 3), (302, 1, 4)]));
        image.extend(index); // block 2
        image.extend(leaf1); // block 3
        image.extend(leaf2); // block 4
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(300),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn walk_descends_when_next_separator_lies_past_the_target() {
        // Target=5 with separators [2, 10]: the `next` separator (10) is past
        // the target, so the current subtree must still be descended. Flipping
        // `next < target` to `>` would skip it and return zero records.
        let (catalog, mut reader) = pruning_fixture();
        let obj5 = catalog.records_for(&mut reader, 5).unwrap();
        assert_eq!(obj5.len(), 1, "obj 5 must be found in leaf 1");
        assert_eq!(obj5[0].value, vec![0x53; 4]);
    }

    /// Builds an index node whose only child link is shorter than the eight
    /// bytes needed to decode an object id. `Catalog::walk` must reject it
    /// before the array read; a `< 8` → `> 8` flip lets the bounds check
    /// pass and the subsequent `child[7]` index panic.
    fn short_child_link_catalog() -> (Catalog, Cursor<Vec<u8>>) {
        // An index entry with a 4-byte child link instead of the required 8.
        let index = catalog_node(
            &[(jkey(2, 3), vec![0xAAu8; 4])], // child link too short
            0x0001,                           // ROOT
        );
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(300, 1, 2)]));
        image.extend(index);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(300),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn walk_rejects_a_short_child_link() {
        // A `>` mutant lets the bounds check pass and the read panic on
        // `child[7]`; the unmutated `<` returns Malformed before that.
        let (catalog, mut reader) = short_child_link_catalog();
        let result = catalog.records_for(&mut reader, 2);
        assert!(matches!(result, Err(ApfsError::Malformed { .. })));
    }

    /// Builds a single-block image whose index node loops back to itself —
    /// a corrupt tree of unbounded depth. `Catalog::walk` must terminate
    /// via the `depth >= MAX_CATALOG_DEPTH` guard; replacing `depth + 1`
    /// with `depth * 1` keeps depth at zero and recurses forever.
    fn cyclic_catalog() -> (Catalog, Cursor<Vec<u8>>) {
        // One index entry whose child link points back at the root oid.
        let index = catalog_node(
            &[(jkey(2, 3), 300u64.to_le_bytes().to_vec())],
            0x0001, // ROOT
        );
        let mut image = omap_phys(1);
        image.extend(omap_tree(&[(300, 1, 2)]));
        image.extend(index);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(300),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn walk_rejects_a_tree_deeper_than_the_supported_limit() {
        // The cyclic catalog recurses without progress; the depth guard must
        // surface a Malformed error rather than blowing the stack.
        let (catalog, mut reader) = cyclic_catalog();
        let result = catalog.records_of_kind(&mut reader, JObjType::Inode);
        match result {
            Err(ApfsError::Malformed { reason, .. }) => {
                assert!(reason.contains("deeper"), "{reason}");
            }
            other => panic!("expected Malformed depth error, got {other:?}"),
        }
    }
}
