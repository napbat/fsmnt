//! Forensic synthesis — file timelines and clone-relationship maps.
//!
//! This module turns the parsed filesystem into the synthesized outputs an
//! analyst consumes: a chronological event timeline built from inode
//! timestamps, and a map of which files share physical extents (clones).
//!
//! Apple File System Reference, `07-file-system-objects.md`, `09-data-streams.md`.

use alloc::string::String;
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use crate::catalog::{Catalog, JObjType};
use crate::clones::ClassifiedExtent;
use crate::directory::{DirEntry, DirEntryType};
use crate::error::{ApfsError, Result};
use crate::inode::{Inode, ROOT_DIR_INO_NUM};
use crate::io::{Read, Seek};
use crate::time::ApfsTimestamp;

/// Maximum directory depth walked while building a timeline.
const MAX_TIMELINE_DEPTH: u32 = 256;

/// Which inode timestamp a timeline event records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampKind {
    /// The inode's creation time.
    Created,
    /// The inode's last content-modification time.
    Modified,
    /// The inode's last attribute-change time.
    Changed,
    /// The inode's last access time.
    Accessed,
}

/// One entry in a forensic timeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEvent {
    /// When the event occurred.
    pub time: ApfsTimestamp,
    /// Which timestamp the event came from.
    pub kind: TimestampKind,
    /// Object identifier of the inode.
    pub obj_id: u64,
    /// Absolute path of the inode within its volume.
    pub path: String,
}

/// Produces the four timeline events of one inode.
#[must_use]
pub fn inode_events(inode: &Inode, obj_id: u64, path: &str) -> Vec<TimelineEvent> {
    [
        (TimestampKind::Created, inode.created()),
        (TimestampKind::Modified, inode.modified()),
        (TimestampKind::Changed, inode.changed()),
        (TimestampKind::Accessed, inode.accessed()),
    ]
    .into_iter()
    .map(|(kind, time)| TimelineEvent {
        time,
        kind,
        obj_id,
        path: String::from(path),
    })
    .collect()
}

/// Builds a chronological timeline of every inode reachable from a volume's
/// root directory.
///
/// `hashed` selects the directory-entry key form (see
/// [`Directory::new`](crate::directory::Directory::new)). Events are returned
/// sorted by time, then by object id.
///
/// The catalog is scanned exactly twice — once for inodes, once for directory
/// records — and the directory tree is then walked entirely in memory, so
/// timeline synthesis stays linear in the number of records.
///
/// # Errors
///
/// Propagates catalog-walk and parsing errors, and returns
/// [`ApfsError::Malformed`] when the directory tree is nested more deeply
/// than `MAX_TIMELINE_DEPTH` (a sign of a cycle in a malformed volume).
pub fn build_timeline<T: Read + Seek>(
    reader: &mut T,
    catalog: &Catalog,
    hashed: bool,
) -> Result<Vec<TimelineEvent>> {
    let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
    for record in catalog.records_of_kind(reader, JObjType::Inode)? {
        inodes.insert(record.key_header.obj_id, Inode::parse(&record.value)?);
    }
    let mut children: BTreeMap<u64, Vec<DirEntry>> = BTreeMap::new();
    for record in catalog.records_of_kind(reader, JObjType::DirRec)? {
        let entry = DirEntry::from_record(&record, hashed)?;
        children
            .entry(record.key_header.obj_id)
            .or_default()
            .push(entry);
    }

    let mut events = Vec::new();
    if let Some(root) = inodes.get(&ROOT_DIR_INO_NUM) {
        events.extend(inode_events(root, ROOT_DIR_INO_NUM, "/"));
    }
    walk_timeline(&inodes, &children, ROOT_DIR_INO_NUM, "", 0, &mut events)?;
    events.sort_by(|a, b| a.time.cmp(&b.time).then(a.obj_id.cmp(&b.obj_id)));
    Ok(events)
}

/// Recursively collects timeline events from a directory and its children,
/// using the in-memory inode and directory-entry indexes.
fn walk_timeline(
    inodes: &BTreeMap<u64, Inode>,
    children: &BTreeMap<u64, Vec<DirEntry>>,
    dir_id: u64,
    prefix: &str,
    depth: u32,
    events: &mut Vec<TimelineEvent>,
) -> Result<()> {
    if depth >= MAX_TIMELINE_DEPTH {
        return Err(ApfsError::Malformed {
            structure: "directory tree",
            reason: "directory nesting exceeds the timeline depth limit",
        });
    }
    let Some(entries) = children.get(&dir_id) else {
        return Ok(());
    };
    for entry in entries {
        let mut path = String::from(prefix);
        path.push('/');
        path.push_str(&entry.name);
        if let Some(inode) = inodes.get(&entry.file_id) {
            events.extend(inode_events(inode, entry.file_id, &path));
        }
        if entry.file_type == DirEntryType::Directory {
            walk_timeline(inodes, children, entry.file_id, &path, depth + 1, events)?;
        }
    }
    Ok(())
}

/// A set of files that share a physical extent — copy-on-write clones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloneSet {
    /// The physical block address the files share.
    pub physical_block: u64,
    /// Object identifiers of the files sharing the extent, in ascending order.
    pub members: Vec<u64>,
}

/// Builds a clone-relationship map from per-file classified extents.
///
/// Each input pair is a file's object id and the classification of its
/// extents (from [`classify_extents`](crate::clones::classify_extents)). Files
/// that share a physical extent with a reference count above one are grouped
/// into a [`CloneSet`].
#[must_use]
pub fn build_clone_map(files: &[(u64, Vec<ClassifiedExtent>)]) -> Vec<CloneSet> {
    // physical block -> the object ids sharing it.
    let mut groups: Vec<(u64, Vec<u64>)> = Vec::new();
    for (obj_id, extents) in files {
        for extent in extents {
            if !extent.is_shared() {
                continue;
            }
            let block = extent.extent.phys_block_num;
            match groups.iter_mut().find(|(b, _)| *b == block) {
                Some((_, members)) => {
                    if !members.contains(obj_id) {
                        members.push(*obj_id);
                    }
                }
                None => groups.push((block, alloc::vec![*obj_id])),
            }
        }
    }

    let mut clone_sets: Vec<CloneSet> = groups
        .into_iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|(physical_block, mut members)| {
            members.sort_unstable();
            CloneSet {
                physical_block,
                members,
            }
        })
        .collect();
    clone_sets.sort_by_key(|set| set.physical_block);
    clone_sets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::{JObjType, OBJ_TYPE_SHIFT};
    use crate::directory::J_DREC_LEN_MASK;
    use crate::extent::FileExtent;
    use crate::inode::J_INODE_VAL_SIZE;
    use crate::object::OBJ_PHYSICAL;
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

    fn catalog_leaf(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0003u16.to_le_bytes());
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

    fn inode_record(obj_id: u64, mode: u16, create: u64) -> (Vec<u8>, Vec<u8>) {
        let key = (((JObjType::Inode.as_value() as u64) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        let mut value = vec![0u8; J_INODE_VAL_SIZE];
        value[0x10..0x18].copy_from_slice(&create.to_le_bytes()); // create_time
        value[0x50..0x52].copy_from_slice(&mode.to_le_bytes()); // mode
        (key, value)
    }

    fn drec_record(dir_id: u64, name: &str, child: u64, file_type: u16) -> (Vec<u8>, Vec<u8>) {
        let mut key = (((JObjType::DirRec.as_value() as u64) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        let len = name.len() as u32 + 1;
        key.extend_from_slice(&(len & J_DREC_LEN_MASK).to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        let mut value = vec![0u8; 18];
        value[0..8].copy_from_slice(&child.to_le_bytes());
        value[16..18].copy_from_slice(&file_type.to_le_bytes());
        (key, value)
    }

    #[test]
    fn builds_a_sorted_timeline() {
        // Root (2) contains file "old.txt" (10) created at t=100 and
        // "new.txt" (11) created at t=300.
        let records = vec![
            inode_record(2, 0o040_755, 50),
            drec_record(2, "old.txt", 10, 8),
            inode_record(10, 0o100_644, 100),
            drec_record(2, "new.txt", 11, 8),
            inode_record(11, 0o100_644, 300),
        ];
        let mut image = omap_phys(1);
        image.extend(omap_tree(400, 2));
        image.extend(catalog_leaf(&records));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(Oid(400), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        let timeline = build_timeline(&mut reader, &catalog, true).unwrap();
        // Three inodes x four timestamps.
        assert_eq!(timeline.len(), 12);
        // Events are returned sorted ascending by time.
        assert!(timeline.windows(2).all(|w| w[0].time <= w[1].time));
        // Creation events carry the resolved paths.
        let created: Vec<_> = timeline
            .iter()
            .filter(|e| e.kind == TimestampKind::Created)
            .map(|e| (e.time.nanos(), e.path.as_str()))
            .collect();
        assert!(created.contains(&(100, "/old.txt")));
        assert!(created.contains(&(300, "/new.txt")));
    }

    #[test]
    fn timeline_walks_into_nested_directories() {
        // Root (2) holds subdir "sub" (20, file_type 4) and regular
        // "shallow.txt" (10, file_type 8). "sub" itself holds "deep.txt"
        // (30). The walk must:
        //   * recurse into 20 (kills the == / != mutant on file_type),
        //   * pass depth + 1 (a `-` mutant underflows u32 and panics).
        let records = vec![
            inode_record(2, 0o040_755, 50),
            drec_record(2, "shallow.txt", 10, 8),
            inode_record(10, 0o100_644, 100),
            drec_record(2, "sub", 20, 4),
            inode_record(20, 0o040_755, 150),
            drec_record(20, "deep.txt", 30, 8),
            inode_record(30, 0o100_644, 200),
        ];
        let mut image = omap_phys(1);
        image.extend(omap_tree(400, 2));
        image.extend(catalog_leaf(&records));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(Oid(400), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        let timeline = build_timeline(&mut reader, &catalog, true).unwrap();
        // 4 inodes (root, shallow, sub, deep) x 4 timestamps each.
        assert_eq!(timeline.len(), 16);
        // The deep child's resolved path proves the recursion happened.
        let deep_paths: Vec<_> = timeline
            .iter()
            .filter(|e| e.obj_id == 30 && e.kind == TimestampKind::Created)
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(deep_paths, vec!["/sub/deep.txt"]);
    }

    #[test]
    fn timeline_rejects_a_directory_cycle() {
        // Dir 2 contains entry "loop" pointing back to dir 2. The walk's
        // depth counter must keep growing — a `* 1` mutant on `depth + 1`
        // would leave depth at zero and recurse until the stack blows.
        let records = vec![inode_record(2, 0o040_755, 50), drec_record(2, "loop", 2, 4)];
        let mut image = omap_phys(1);
        image.extend(omap_tree(400, 2));
        image.extend(catalog_leaf(&records));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(Oid(400), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        assert!(matches!(
            build_timeline(&mut reader, &catalog, true),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn inode_events_yields_four_events() {
        let inode = Inode::parse(&[0u8; J_INODE_VAL_SIZE]).unwrap();
        let events = inode_events(&inode, 5, "/file");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].kind, TimestampKind::Created);
        assert_eq!(events[3].kind, TimestampKind::Accessed);
    }

    /// A classified extent at `phys_block` with the given reference count.
    fn classified(phys_block: u64, refcnt: i32) -> ClassifiedExtent {
        ClassifiedExtent {
            extent: FileExtent {
                logical_addr: 0,
                length: 4096,
                phys_block_num: phys_block,
                crypto_id: 0,
            },
            refcnt: Some(refcnt),
        }
    }

    #[test]
    fn clone_map_groups_files_sharing_an_extent() {
        // Files 10 and 11 both reference shared block 500; file 12 has its
        // own exclusive block 600.
        let files = [
            (10u64, alloc::vec![classified(500, 2)]),
            (11u64, alloc::vec![classified(500, 2)]),
            (12u64, alloc::vec![classified(600, 1)]),
        ];
        let map = build_clone_map(&files);
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].physical_block, 500);
        assert_eq!(map[0].members, vec![10, 11]);
    }

    #[test]
    fn clone_map_is_empty_without_sharing() {
        let files = [
            (10u64, alloc::vec![classified(500, 1)]),
            (11u64, alloc::vec![classified(600, 1)]),
        ];
        assert!(build_clone_map(&files).is_empty());
    }

    #[test]
    fn clone_map_rejects_a_single_member_group() {
        // A lone file whose extent is shared-flagged (refcnt 2 in the
        // extent-reference tree) but with no peer in the input forms a
        // single-member group. The filter `members.len() > 1` must drop it;
        // a `>= 1` mutant would let it through as a fake clone set.
        let files = [(10u64, alloc::vec![classified(500, 2)])];
        assert!(build_clone_map(&files).is_empty());
    }
}
