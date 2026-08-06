//! Deleted-file recovery — snapshot diffing and free-space scanning.
//!
//! APFS deletes copy-on-write: a file removed from the live volume often
//! still exists in a snapshot, and its catalog records may persist in
//! unallocated blocks. This module recovers both.
//!
//! Apple File System Reference, `12-snapshot-metadata.md`, `16-space-manager.md`.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "std")]
use std::collections::{BTreeMap, BTreeSet};

use crate::btree::BtreeNode;
use crate::catalog::{Catalog, CatalogRecord, JKey, JObjType};
use crate::checkpoint::read_block;
use crate::checksum;
use crate::directory::DirEntry;
use crate::error::Result;
use crate::extended_field::ExtendedFields;
use crate::extent::{DataStream, File, FileExtent, parse_file_extent};
use crate::inode::{Inode, ROOT_DIR_INO_NUM};
use crate::io::{Read, Seek};
use crate::object::ObjPhys;
use crate::space_manager::SpaceManager;
use crate::types::ObjectType;
use crate::xattr::{Xattr, parse_xattr};

/// Upper bound on parent-directory hops while reconstructing a path,
/// guarding against a corrupt `parent_id` cycle.
const MAX_PATH_DEPTH: usize = 256;

/// Where a recovered item was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provenance {
    /// Recovered from a snapshot, identified by its transaction id.
    Snapshot(u64),
    /// Salvaged from an unallocated block, identified by its address.
    Unallocated(u64),
}

/// A file present in a snapshot but absent from the live volume.
#[derive(Debug, Clone)]
pub struct DeletedFile {
    /// The file's object identifier.
    pub obj_id: u64,
    /// The file's inode, as it existed in the snapshot.
    pub inode: Inode,
    /// Where the file was recovered from.
    pub provenance: Provenance,
    /// The file's reconstructed path components, root-first. Empty or
    /// partial when an ancestor link could not be resolved in the
    /// snapshot — the missing-data state is observable as a short path.
    pub path: Vec<String>,
}

/// Reconstructs a file's path by walking `parent_id` links up to the
/// volume root, naming each step from the pre-built directory-entry index.
///
/// A name or parent that cannot be resolved ends the walk early, yielding
/// a partial (root-relative) path rather than failing.
fn reconstruct_path(
    inodes: &BTreeMap<u64, Inode>,
    names: &BTreeMap<(u64, u64), String>,
    obj_id: u64,
) -> Vec<String> {
    let mut components: Vec<String> = Vec::new();
    let mut current = obj_id;
    for _ in 0..MAX_PATH_DEPTH {
        if current == ROOT_DIR_INO_NUM {
            break;
        }
        let Some(inode) = inodes.get(&current) else {
            break;
        };
        let parent = inode.parent_id;
        let Some(name) = names.get(&(parent, current)) else {
            break;
        };
        components.push(name.clone());
        current = parent;
    }
    components.reverse();
    components
}

/// Lists files that exist in `snapshot` but have been deleted from `live`.
///
/// Both catalogs are walked for inode records; an object id present in the
/// snapshot but not the live volume is a deleted file, recoverable from the
/// snapshot. Each result carries its reconstructed path.
///
/// The snapshot's inodes and directory entries are each indexed in a single
/// catalog walk, so reconstructing every deleted file's path costs map
/// lookups rather than a full-tree scan per parent hop.
///
/// # Errors
///
/// Propagates catalog-walk and parsing errors.
pub fn diff_snapshot<T: Read + Seek>(
    reader: &mut T,
    live: &Catalog,
    snapshot: &Catalog,
    snapshot_xid: u64,
) -> Result<Vec<DeletedFile>> {
    let live_ids: BTreeSet<u64> = live
        .records_of_kind(reader, JObjType::Inode)?
        .iter()
        .map(|record| record.key_header.obj_id)
        .collect();

    // Index every snapshot inode by object id, and every directory entry
    // by (parent dir id, child id) -> name, in one walk apiece.
    let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
    for record in snapshot.records_of_kind(reader, JObjType::Inode)? {
        if let Ok(inode) = Inode::parse(&record.value) {
            inodes.insert(record.key_header.obj_id, inode);
        }
    }
    let mut names: BTreeMap<(u64, u64), String> = BTreeMap::new();
    for record in snapshot.records_of_kind(reader, JObjType::DirRec)? {
        // A directory-entry key is hashed on a case-/normalization-
        // insensitive volume and plain otherwise; try both decodings.
        let entry =
            DirEntry::from_record(&record, true).or_else(|_| DirEntry::from_record(&record, false));
        if let Ok(entry) = entry {
            names
                .entry((record.key_header.obj_id, entry.file_id))
                .or_insert(entry.name);
        }
    }

    let mut deleted = Vec::new();
    for (&obj_id, inode) in &inodes {
        if !live_ids.contains(&obj_id) {
            deleted.push(DeletedFile {
                obj_id,
                inode: inode.clone(),
                provenance: Provenance::Snapshot(snapshot_xid),
                path: reconstruct_path(&inodes, &names, obj_id),
            });
        }
    }
    Ok(deleted)
}

/// Reads a recovered file's content from the catalog it was found in.
///
/// The logical size comes from the inode's data-stream extended field;
/// content is read through the file's extents — for a snapshot view this
/// reconstructs the file exactly as it existed at the snapshot.
///
/// # Errors
///
/// Propagates extended-field, data-stream, and I/O errors.
pub fn read_deleted_content<T: Read + Seek>(
    catalog: &Catalog,
    reader: &mut T,
    deleted: &DeletedFile,
    block_size: u32,
) -> Result<Vec<u8>> {
    let size = match ExtendedFields::parse(&deleted.inode.xfields)?.dstream() {
        Some(bytes) => DataStream::parse(bytes)?.size,
        None => 0,
    };
    File::open(catalog, reader, deleted.inode.private_id, size)?.read_all(reader, block_size)
}

/// A catalog leaf node salvaged from an unallocated block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanedNode {
    /// The block address the node was found at.
    pub block: u64,
    /// The file-system records recovered from the node.
    pub records: Vec<CatalogRecord>,
}

/// Attempts to salvage a catalog leaf node from a raw block.
///
/// Returns `Ok(None)` unless the block is a checksum-valid file-system-tree
/// leaf node — only then are its records trustworthy enough to recover.
///
/// # Errors
///
/// Propagates [`ApfsError::Malformed`](crate::error::ApfsError::Malformed)
/// from B-tree entry decoding of an otherwise plausible node.
pub fn salvage_block(block: &[u8], block_addr: u64) -> Result<Option<OrphanedNode>> {
    // A stale catalog node still carries a valid Fletcher-64 checksum; a
    // mismatch means the block has been reused for unrelated data.
    if !checksum::verify_block(block) {
        return Ok(None);
    }
    let Ok(header) = ObjPhys::parse(block) else {
        return Ok(None);
    };
    if header.object_kind() != ObjectType::BtreeNode || header.subtype_kind() != ObjectType::FsTree
    {
        return Ok(None);
    }
    let node = match BtreeNode::parse(block.to_vec()) {
        Ok(node) => node,
        Err(_) => return Ok(None),
    };
    if !node.is_leaf() {
        return Ok(None);
    }

    // `key_count()` is an unvalidated on-disk field; grow the vector as
    // entries are decoded rather than preallocating from a trusted count.
    let mut records = Vec::new();
    for index in 0..node.key_count() {
        let entry = node.entry(index, 0, 0)?;
        let Ok(key_header) = JKey::parse(entry.key) else {
            continue;
        };
        records.push(CatalogRecord {
            key_header,
            key: entry.key.to_vec(),
            value: entry.value.unwrap_or(&[]).to_vec(),
        });
    }
    Ok(Some(OrphanedNode {
        block: block_addr,
        records,
    }))
}

/// Scans the unallocated blocks in `[start, end)` for orphaned catalog leaf
/// nodes.
///
/// Blocks the space manager reports as allocated are skipped — live data is
/// not a recovery candidate. The range is caller-bounded so a forensic tool
/// can scan incrementally rather than the whole container at once; a range
/// that runs past the main device stops at the device's last block.
///
/// # Errors
///
/// Propagates I/O errors and allocation-query failures (for example an
/// unsupported chunk-info layout or an unreadable bitmap); any such failure
/// aborts the scan rather than silently dropping coverage.
pub fn scan_unallocated<T: Read + Seek>(
    reader: &mut T,
    space_manager: &SpaceManager,
    start: u64,
    end: u64,
) -> Result<Vec<OrphanedNode>> {
    let block_size = space_manager.block_size;
    let mut found = Vec::new();
    for addr in start..end {
        // The space manager only tracks main-device allocation; past its
        // last block there is nothing left to scan.
        if addr >= space_manager.main_device.block_count {
            break;
        }
        if space_manager.is_allocated(reader, addr)? {
            continue;
        }
        let block = read_block(reader, block_size, addr)?;
        if let Some(node) = salvage_block(&block, addr)? {
            found.push(node);
        }
    }
    Ok(found)
}

/// A deleted file-system object reconstructed from orphaned catalog
/// records salvaged out of unallocated space.
///
/// Each field is filled only when a corresponding record was recovered;
/// an absent inode, name, or extent list is the candidate's explicit
/// missing-data state.
#[derive(Debug, Clone)]
pub struct RecoveredObject {
    /// The object's identifier — the key shared by its records.
    pub obj_id: u64,
    /// The unallocated block the object's first record was salvaged from.
    pub provenance: Provenance,
    /// The object's inode, if an inode record was recovered.
    pub inode: Option<Inode>,
    /// The object's name, if a directory entry naming it was recovered.
    pub name: Option<String>,
    /// The object's extended attributes, from any recovered `XATTR` records.
    pub xattrs: Vec<Xattr>,
    /// The object's file extents, from any recovered `FILE_EXTENT` records.
    pub extents: Vec<FileExtent>,
}

impl RecoveredObject {
    /// Whether an inode record was recovered for this object.
    ///
    /// A candidate without an inode — orphaned extents, or a name with no
    /// inode behind it — is incomplete and reports `false`.
    #[must_use]
    pub fn has_inode(&self) -> bool {
        self.inode.is_some()
    }
}

/// Groups orphaned catalog records by object identifier into recovery
/// candidates.
///
/// Records salvaged from unallocated space are scattered across nodes; this
/// reassembles each object's inode, name, extended attributes, and file
/// extents. A malformed record is skipped rather than aborting the group,
/// so one bad record never sinks an otherwise recoverable object.
///
/// `FILE_EXTENT` records are keyed by the file's *data-stream* identifier
/// (`j_inode_val_t.private_id`), which differs from the inode's object id
/// for a cloned file; inode, name, and xattr records are keyed by the
/// inode's object id. Extents are therefore collected by stream id and
/// joined to their inode's candidate through `private_id`, so a clone's
/// content is not split into a separate, headerless candidate.
#[must_use]
pub fn group_orphans(nodes: &[OrphanedNode]) -> Vec<RecoveredObject> {
    let mut candidates: BTreeMap<u64, RecoveredObject> = BTreeMap::new();
    // Extents keyed by data-stream id: `stream_id -> (first block, extents)`.
    let mut extents_by_stream: BTreeMap<u64, (u64, Vec<FileExtent>)> = BTreeMap::new();
    let candidate = |map: &mut BTreeMap<u64, RecoveredObject>, obj_id, block| {
        map.entry(obj_id).or_insert_with(|| RecoveredObject {
            obj_id,
            provenance: Provenance::Unallocated(block),
            inode: None,
            name: None,
            xattrs: Vec::new(),
            extents: Vec::new(),
        });
    };
    for node in nodes {
        for record in &node.records {
            let obj_id = record.key_header.obj_id;
            match record.key_header.kind {
                JObjType::Inode => {
                    candidate(&mut candidates, obj_id, node.block);
                    if let Ok(inode) = Inode::parse(&record.value) {
                        candidates.get_mut(&obj_id).expect("just inserted").inode = Some(inode);
                    }
                }
                JObjType::FileExtent => {
                    if let Ok(extent) = parse_file_extent(&record.key, &record.value) {
                        extents_by_stream
                            .entry(obj_id)
                            .or_insert_with(|| (node.block, Vec::new()))
                            .1
                            .push(extent);
                    }
                }
                JObjType::Xattr => {
                    candidate(&mut candidates, obj_id, node.block);
                    if let Ok(xattr) = parse_xattr(&record.key, &record.value) {
                        candidates
                            .get_mut(&obj_id)
                            .expect("just inserted")
                            .xattrs
                            .push(xattr);
                    }
                }
                JObjType::DirRec => {
                    // A directory record names a *child* object; attach the
                    // name to that child's candidate, not the directory's.
                    let entry = DirEntry::from_record(record, true)
                        .or_else(|_| DirEntry::from_record(record, false));
                    if let Ok(entry) = entry {
                        candidate(&mut candidates, entry.file_id, node.block);
                        candidates
                            .get_mut(&entry.file_id)
                            .expect("just inserted")
                            .name
                            .get_or_insert(entry.name);
                    }
                }
                _ => {}
            }
        }
    }
    // Join each inode's extents through its `private_id`. A hard-linked or
    // cloned data stream can back more than one inode, so the extents are
    // cloned into every claiming candidate rather than moved.
    let mut claimed: BTreeSet<u64> = BTreeSet::new();
    for candidate in candidates.values_mut() {
        if let Some(inode) = &candidate.inode
            && let Some((_, extents)) = extents_by_stream.get(&inode.private_id)
        {
            candidate.extents = extents.clone();
            claimed.insert(inode.private_id);
        }
    }
    // Extents with no inode behind them stay recoverable as their own
    // incomplete candidate, keyed by the data-stream id.
    for (stream_id, (block, extents)) in extents_by_stream {
        if claimed.contains(&stream_id) {
            continue;
        }
        candidate(&mut candidates, stream_id, block);
        candidates
            .get_mut(&stream_id)
            .expect("just inserted")
            .extents = extents;
    }
    candidates.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::inode::J_INODE_VAL_SIZE;
    use crate::object::{OBJ_PHYS_SIZE, OBJ_PHYSICAL};
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use std::io::Cursor;

    const BLK: usize = 4096;

    fn omap_phys(tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes());
        b[0x30..0x38].copy_from_slice(&tree_oid.to_le_bytes());
        b
    }

    fn omap_tree(node_oid: u64, node_paddr: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
        b[0x2A..0x2C].copy_from_slice(&4u16.to_le_bytes());
        let key_area = BTN_DATA_OFFSET + 4;
        b[BTN_DATA_OFFSET + 2..BTN_DATA_OFFSET + 4].copy_from_slice(&16u16.to_le_bytes());
        b[key_area..key_area + 8].copy_from_slice(&node_oid.to_le_bytes());
        b[key_area + 8..key_area + 16].copy_from_slice(&1u64.to_le_bytes());
        let value_end = BLK - BTREE_INFO_SIZE;
        b[value_end - 16 + 8..value_end - 16 + 16].copy_from_slice(&node_paddr.to_le_bytes());
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes());
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes());
        b
    }

    /// Builds a variable-kv file-system-tree leaf node.
    ///
    /// When `as_root` is set the node is also a root (carrying a btree_info
    /// trailer); the `obj_phys` type/subtype mark it as a catalog node.
    fn fs_leaf(records: &[(Vec<u8>, Vec<u8>)], as_root: bool, headered: bool) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        if headered {
            // o_type BTREE_NODE (0x03), o_subtype FSTREE (0x0E).
            b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x03).to_le_bytes());
            b[0x1C..0x20].copy_from_slice(&0x0Eu32.to_le_bytes());
        }
        let flags: u16 = if as_root { 0x0003 } else { 0x0002 }; // LEAF (+ROOT)
        b[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&(records.len() as u32).to_le_bytes());
        b[0x2A..0x2C].copy_from_slice(&((records.len() * 8) as u16).to_le_bytes());
        let key_area = BTN_DATA_OFFSET + records.len() * 8;
        let value_end = BLK - BTREE_INFO_SIZE;
        let (mut kc, mut vc) = (0usize, 0usize);
        for (i, (key, value)) in records.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 8;
            b[toc..toc + 2].copy_from_slice(&(kc as u16).to_le_bytes());
            b[toc + 2..toc + 4].copy_from_slice(&(key.len() as u16).to_le_bytes());
            vc += value.len();
            b[toc + 4..toc + 6].copy_from_slice(&(vc as u16).to_le_bytes());
            b[toc + 6..toc + 8].copy_from_slice(&(value.len() as u16).to_le_bytes());
            b[key_area + kc..key_area + kc + key.len()].copy_from_slice(key);
            b[value_end - vc..value_end - vc + value.len()].copy_from_slice(value);
            kc += key.len();
        }
        b
    }

    fn inode_record(obj_id: u64) -> (Vec<u8>, Vec<u8>) {
        let key = (((JObjType::Inode.as_value() as u64) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        (key, vec![0u8; J_INODE_VAL_SIZE])
    }

    fn catalog(records: &[(Vec<u8>, Vec<u8>)], root_oid: u64) -> (Catalog, Vec<u8>) {
        let mut image = omap_phys(1);
        image.extend(omap_tree(root_oid, 2));
        image.extend(fs_leaf(records, true, true));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (Catalog::new(Oid(root_oid), omap, BLK as u32, Xid(1)), image)
    }

    #[test]
    fn diff_snapshot_finds_files_deleted_from_the_live_volume() {
        // Live volume has inodes 2 and 3; the snapshot also had inode 9.
        let (live, live_image) = catalog(&[inode_record(2), inode_record(3)], 100);
        let (snap, snap_image) = catalog(&[inode_record(2), inode_record(3), inode_record(9)], 200);
        // Reading two catalogs from one reader: lay them out at the same
        // offsets is impossible, so test them with their own readers.
        let mut live_reader = Cursor::new(live_image);
        let live_ids: BTreeSet<u64> = live
            .records_of_kind(&mut live_reader, JObjType::Inode)
            .unwrap()
            .iter()
            .map(|r| r.key_header.obj_id)
            .collect();
        assert_eq!(live_ids.len(), 2);

        let mut snap_reader = Cursor::new(snap_image);
        let deleted: Vec<u64> = snap
            .records_of_kind(&mut snap_reader, JObjType::Inode)
            .unwrap()
            .iter()
            .map(|r| r.key_header.obj_id)
            .filter(|id| !live_ids.contains(id))
            .collect();
        assert_eq!(deleted, vec![9]);
    }

    #[test]
    fn diff_snapshot_against_one_reader() {
        // When the live and snapshot catalogs share a reader, diff_snapshot
        // composes them directly.
        let (cat, image) = catalog(&[inode_record(2), inode_record(5)], 100);
        let mut reader = Cursor::new(image);
        // Diffing a catalog against itself yields nothing deleted.
        let deleted = diff_snapshot(&mut reader, &cat, &cat, 7).unwrap();
        assert!(deleted.is_empty());
    }

    #[test]
    fn salvages_a_checksum_valid_catalog_leaf() {
        let records = [inode_record(42)];
        let mut block = fs_leaf(&records, false, true);
        let csum = checksum::fletcher64(&block[OBJ_PHYS_SIZE.min(8)..]);
        block[..8].copy_from_slice(&csum.to_le_bytes());

        let node = salvage_block(&block, 500).unwrap().unwrap();
        assert_eq!(node.block, 500);
        assert_eq!(node.records.len(), 1);
        assert_eq!(node.records[0].key_header.obj_id, 42);
        assert_eq!(node.records[0].key_header.kind, JObjType::Inode);
    }

    #[test]
    fn salvage_rejects_a_corrupt_or_unrelated_block() {
        // A block with no valid checksum is not a recovery candidate.
        assert!(salvage_block(&vec![0xFFu8; BLK], 1).unwrap().is_none());

        // A checksum-valid block that is not a file-system-tree node.
        let mut other = vec![0u8; BLK];
        other[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes()); // OMAP
        let csum = checksum::fletcher64(&other[8..]);
        other[..8].copy_from_slice(&csum.to_le_bytes());
        assert!(salvage_block(&other, 2).unwrap().is_none());
    }

    // --- Deleted-file reconstruction --------------------------------------

    /// An inode record with the given parent and data-stream identifiers
    /// and trailing extended-field bytes.
    fn inode_record_full(
        obj_id: u64,
        parent_id: u64,
        private_id: u64,
        xfields: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let key = (((JObjType::Inode.as_value() as u64) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        let mut value = vec![0u8; J_INODE_VAL_SIZE];
        value[0x00..0x08].copy_from_slice(&parent_id.to_le_bytes());
        value[0x08..0x10].copy_from_slice(&private_id.to_le_bytes());
        value[0x50..0x52].copy_from_slice(&0o100_644u16.to_le_bytes()); // regular file
        value.extend_from_slice(xfields);
        (key, value)
    }

    /// An `xf_blob_t` carrying a single `INO_EXT_TYPE_DSTREAM` field.
    fn dstream_xfields(size: u64) -> Vec<u8> {
        let mut dstream = vec![0u8; 40];
        dstream[0..8].copy_from_slice(&size.to_le_bytes());
        let mut region = Vec::new();
        region.extend_from_slice(&1u16.to_le_bytes()); // xf_num_exts
        region.extend_from_slice(&(4u16 + 40).to_le_bytes()); // xf_used_data
        region.push(8); // INO_EXT_TYPE_DSTREAM
        region.push(0); // x_flags
        region.extend_from_slice(&40u16.to_le_bytes()); // x_size
        region.extend_from_slice(&dstream);
        region
    }

    /// A legacy (unhashed) `DIR_REC` record naming `child`.
    fn drec(dir_id: u64, name: &str, child: u64, file_type: u16) -> (Vec<u8>, Vec<u8>) {
        let mut key = (((JObjType::DirRec.as_value() as u64) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        key.extend_from_slice(&(name.len() as u16 + 1).to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        let mut value = vec![0u8; 18];
        value[0..8].copy_from_slice(&child.to_le_bytes());
        value[16..18].copy_from_slice(&file_type.to_le_bytes());
        (key, value)
    }

    /// A `FILE_EXTENT` record mapping a logical offset to a physical block.
    fn file_extent_record(obj_id: u64, logical: u64, len: u64, phys: u64) -> (Vec<u8>, Vec<u8>) {
        let mut key = (((JObjType::FileExtent.as_value() as u64) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        key.extend_from_slice(&logical.to_le_bytes());
        let mut value = vec![0u8; 24];
        value[0..8].copy_from_slice(&len.to_le_bytes());
        value[8..16].copy_from_slice(&phys.to_le_bytes());
        (key, value)
    }

    /// Builds one image holding a live catalog (root oid 100) and a
    /// snapshot catalog (root oid 200) at distinct block ranges, so
    /// `diff_snapshot` can read both from a single reader.
    fn two_catalogs(
        live: &[(Vec<u8>, Vec<u8>)],
        snap: &[(Vec<u8>, Vec<u8>)],
    ) -> (Catalog, Catalog, Vec<u8>) {
        let mut image = omap_phys(1); // block 0: live omap
        image.extend(omap_tree(100, 2)); // block 1: live omap tree
        image.extend(fs_leaf(live, true, true)); // block 2: live catalog leaf
        image.extend(omap_phys(4)); // block 3: snapshot omap
        image.extend(omap_tree(200, 5)); // block 4: snapshot omap tree
        image.extend(fs_leaf(snap, true, true)); // block 5: snapshot catalog leaf
        let live_omap = Omap::parse(&image[..BLK]).unwrap();
        let snap_omap = Omap::parse(&image[3 * BLK..4 * BLK]).unwrap();
        (
            Catalog::new(Oid(100), live_omap, BLK as u32, Xid(1)),
            Catalog::new(Oid(200), snap_omap, BLK as u32, Xid(1)),
            image,
        )
    }

    #[test]
    fn diff_snapshot_reconstructs_a_deleted_file_path() {
        // The snapshot holds root (2), inode 9 parented to root, and the
        // directory record naming it; the live volume has only root.
        let (live, snap, image) = two_catalogs(
            &[inode_record(2)],
            &[
                inode_record(2),
                drec(2, "gone.txt", 9, 8),
                inode_record_full(9, 2, 9, &[]),
            ],
        );
        let mut reader = Cursor::new(image);
        let deleted = diff_snapshot(&mut reader, &live, &snap, 1000).unwrap();
        assert_eq!(deleted.len(), 1);
        assert_eq!(deleted[0].obj_id, 9);
        assert_eq!(deleted[0].path, vec!["gone.txt".to_string()]);
        assert_eq!(deleted[0].provenance, Provenance::Snapshot(1000));
    }

    #[test]
    fn reads_a_deleted_file_content_from_the_snapshot() {
        // Inode 9 has a 4 KiB data stream; its single extent points at
        // block 6, which carries a distinctive byte pattern.
        let snap_records = [
            inode_record(2),
            drec(2, "doc.bin", 9, 8),
            inode_record_full(9, 2, 9, &dstream_xfields(BLK as u64)),
            file_extent_record(9, 0, BLK as u64, 6),
        ];
        let (live, snap, mut image) = two_catalogs(&[inode_record(2)], &snap_records);
        let mut content_block = vec![0xD7u8; BLK];
        content_block[0] = 0x42;
        image.extend_from_slice(&content_block); // block 6
        let mut reader = Cursor::new(image);

        let deleted = diff_snapshot(&mut reader, &live, &snap, 1000).unwrap();
        let recovered = read_deleted_content(&snap, &mut reader, &deleted[0], BLK as u32).unwrap();
        assert_eq!(recovered.len(), BLK);
        assert_eq!(recovered[0], 0x42);
        assert!(recovered[1..].iter().all(|&b| b == 0xD7));
    }

    /// A `CatalogRecord` from raw key/value bytes, for orphan-grouping tests.
    fn record(key: Vec<u8>, value: Vec<u8>) -> CatalogRecord {
        CatalogRecord {
            key_header: JKey::parse(&key).unwrap(),
            key,
            value,
        }
    }

    #[test]
    fn group_orphans_reassembles_a_recovered_object() {
        let (inode_key, inode_val) = inode_record_full(9, 2, 9, &[]);
        let (drec_key, drec_val) = drec(2, "salvaged.txt", 9, 8);
        let (ext_key, ext_val) = file_extent_record(9, 0, 4096, 60);
        let node = OrphanedNode {
            block: 500,
            records: vec![
                record(inode_key, inode_val),
                record(drec_key, drec_val),
                record(ext_key, ext_val),
            ],
        };
        let recovered = group_orphans(&[node]);
        assert_eq!(recovered.len(), 1);
        let obj = &recovered[0];
        assert_eq!(obj.obj_id, 9);
        assert!(obj.has_inode());
        assert_eq!(obj.name.as_deref(), Some("salvaged.txt"));
        assert_eq!(obj.extents.len(), 1);
        assert_eq!(obj.provenance, Provenance::Unallocated(500));
    }

    #[test]
    fn group_orphans_joins_extents_to_a_cloned_inode_by_private_id() {
        // A cloned file's inode object id (9) differs from its data-stream
        // id (77); its FILE_EXTENT records are keyed by the stream id.
        let (inode_key, inode_val) = inode_record_full(9, 2, 77, &[]);
        let (ext_key, ext_val) = file_extent_record(77, 0, 4096, 88);
        let node = OrphanedNode {
            block: 600,
            records: vec![record(inode_key, inode_val), record(ext_key, ext_val)],
        };
        let recovered = group_orphans(&[node]);
        // The inode and its extents reassemble into one candidate, not two.
        assert_eq!(recovered.len(), 1);
        let obj = &recovered[0];
        assert_eq!(obj.obj_id, 9);
        assert!(obj.has_inode());
        assert_eq!(obj.extents.len(), 1);
        assert_eq!(obj.extents[0].phys_block_num, 88);
    }

    #[test]
    fn group_orphans_marks_an_incomplete_candidate() {
        // Only an extent record survived — no inode was recovered.
        let (ext_key, ext_val) = file_extent_record(20, 0, 4096, 70);
        let node = OrphanedNode {
            block: 800,
            records: vec![record(ext_key, ext_val)],
        };
        let recovered = group_orphans(&[node]);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].obj_id, 20);
        assert!(!recovered[0].has_inode(), "missing inode must be visible");
        assert!(recovered[0].name.is_none());
        assert_eq!(recovered[0].extents.len(), 1);
    }

    #[test]
    fn group_orphans_of_nothing_is_empty() {
        assert!(group_orphans(&[]).is_empty());
    }

    #[test]
    fn salvage_rejects_a_btree_node_with_a_wrong_subtype() {
        // A block whose type is BTREE_NODE but whose subtype is OMAP (not
        // FSTREE) must not be salvaged. Replacing the guard's `||` with
        // `&&` would only reject blocks that fail BOTH conditions, so this
        // node — which fails only the subtype check — would be returned
        // with bogus records.
        let records = [inode_record(7)];
        let mut block = fs_leaf(&records, false, false);
        // o_type BTREE_NODE (0x03), o_subtype OMAP (0x0B) instead of FSTREE.
        block[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x03).to_le_bytes());
        block[0x1C..0x20].copy_from_slice(&0x0Bu32.to_le_bytes());
        let csum = checksum::fletcher64(&block[8..]);
        block[..8].copy_from_slice(&csum.to_le_bytes());

        let result = salvage_block(&block, 900).unwrap();
        assert!(
            result.is_none(),
            "BtreeNode with non-FsTree subtype must not be salvaged, got {result:?}"
        );
    }

    /// An xattr record with an embedded value, keyed off `obj_id`.
    fn xattr_record(obj_id: u64, name: &str, value: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use crate::xattr::{J_XATTR_VAL_HEADER_SIZE, XattrFlags};
        let mut key = (((JObjType::Xattr.as_value() as u64) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        let name_with_nul_len = (name.len() + 1) as u16;
        key.extend_from_slice(&name_with_nul_len.to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        let mut val = Vec::with_capacity(J_XATTR_VAL_HEADER_SIZE + value.len());
        val.extend_from_slice(&XattrFlags::DATA_EMBEDDED.bits().to_le_bytes());
        val.extend_from_slice(&(value.len() as u16).to_le_bytes());
        val.extend_from_slice(value);
        (key, val)
    }

    #[test]
    fn group_orphans_collects_xattr_records() {
        // Deleting the Xattr match arm in `group_orphans` would drop xattr
        // records on the floor; the candidate would have an empty xattrs
        // vector even when an xattr record was recovered.
        let (inode_key, inode_val) = inode_record_full(9, 2, 9, &[]);
        let (xattr_key, xattr_val) = xattr_record(9, "com.apple.fi", b"meta");
        let node = OrphanedNode {
            block: 700,
            records: vec![record(inode_key, inode_val), record(xattr_key, xattr_val)],
        };
        let recovered = group_orphans(&[node]);
        assert_eq!(recovered.len(), 1);
        let obj = &recovered[0];
        assert_eq!(obj.obj_id, 9);
        assert_eq!(obj.xattrs.len(), 1, "xattr record must be attached");
        assert_eq!(obj.xattrs[0].name, "com.apple.fi");
    }

    // --- scan_unallocated against a synthetic space manager ---------------

    /// Builds a space-manager block describing one fully-free chunk of
    /// `chunk_blocks` blocks.
    fn spaceman_block(
        block_size: u32,
        blocks_per_chunk: u32,
        chunk_count: u64,
        cib_addrs: &[u64],
    ) -> Vec<u8> {
        // Mirror the private layout constants from `space_manager.rs`.
        const SM_DEV_OFFSET: usize = OBJ_PHYS_SIZE + 16; // 48
        const SPACEMAN_DEVICE_SIZE: usize = 48;
        const SD_COUNT: usize = 2;
        let mut b = vec![0u8; block_size as usize];
        b[0x20..0x24].copy_from_slice(&block_size.to_le_bytes());
        b[0x24..0x28].copy_from_slice(&blocks_per_chunk.to_le_bytes());
        b[0x28..0x2C].copy_from_slice(&100u32.to_le_bytes()); // chunks_per_cib
        let dev = SM_DEV_OFFSET;
        b[dev..dev + 8].copy_from_slice(&(chunk_count * u64::from(blocks_per_chunk)).to_le_bytes());
        b[dev + 8..dev + 16].copy_from_slice(&chunk_count.to_le_bytes());
        b[dev + 16..dev + 20].copy_from_slice(&(cib_addrs.len() as u32).to_le_bytes());
        let free = chunk_count * u64::from(blocks_per_chunk);
        b[dev + 24..dev + 32].copy_from_slice(&free.to_le_bytes());
        let addr_off = SM_DEV_OFFSET + SD_COUNT * SPACEMAN_DEVICE_SIZE;
        b[dev + 32..dev + 36].copy_from_slice(&(addr_off as u32).to_le_bytes());
        for (i, &addr) in cib_addrs.iter().enumerate() {
            b[addr_off + i * 8..addr_off + i * 8 + 8].copy_from_slice(&addr.to_le_bytes());
        }
        b
    }

    /// Builds a chunk-info block holding one chunk with `free` free blocks,
    /// no bitmap (uniformly free if `free == chunk_blocks`).
    fn cib_block(chunk_blocks: u32, free: u32) -> Vec<u8> {
        const CIB_CHUNK_INFO_OFFSET: usize = OBJ_PHYS_SIZE + 8; // 40
        let mut b = vec![0u8; BLK];
        b[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&1u32.to_le_bytes());
        let ci = CIB_CHUNK_INFO_OFFSET;
        b[ci + 16..ci + 20].copy_from_slice(&chunk_blocks.to_le_bytes());
        b[ci + 20..ci + 24].copy_from_slice(&free.to_le_bytes());
        b[ci + 24..ci + 32].copy_from_slice(&0i64.to_le_bytes()); // no bitmap
        b
    }

    #[test]
    fn scan_unallocated_returns_orphans_inside_the_main_device_range() {
        // Five-block device, every block free; an orphan catalog leaf lives
        // at block 3. The scan must surface it.
        //
        // Killed mutants:
        //   * `scan_unallocated -> Ok(vec![])` — returning empty here is
        //     impossible when a valid orphan exists in the scanned range.
        //   * `>= with <` on the device-bound check — flipping the break
        //     condition would terminate the loop before any block is read.
        let sm_block = spaceman_block(BLK as u32, 8, 1, &[1]);
        let cib = cib_block(8, 8); // one uniformly-free chunk of 8 blocks
        let mut image = sm_block;
        image.extend(cib); // block 1: cib (only read on bitmap scans)
        image.extend(vec![0u8; BLK]); // block 2: pad
        // Block 3: a checksum-valid orphaned catalog leaf with one record.
        let records = [inode_record(42)];
        let mut orphan = fs_leaf(&records, false, true);
        let csum = checksum::fletcher64(&orphan[8..]);
        orphan[..8].copy_from_slice(&csum.to_le_bytes());
        image.extend(orphan); // block 3
        image.extend(vec![0u8; BLK]); // pad to ensure block 3 is readable

        let sm = SpaceManager::parse(image[..BLK].to_vec()).unwrap();
        let mut reader = Cursor::new(image);
        let found = scan_unallocated(&mut reader, &sm, 3, 4).unwrap();
        assert_eq!(found.len(), 1, "the orphan at block 3 must be salvaged");
        assert_eq!(found[0].block, 3);
        assert_eq!(found[0].records[0].key_header.obj_id, 42);
    }
}
