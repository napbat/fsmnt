//! Volume traversal — path resolution, directory walking, and the
//! `fsmnt-parser-core` traversal-trait integration.
//!
//! A [`Volume`] ties a volume superblock to its object map and catalog,
//! exposing absolute-path resolution and a directory tree that plugs into
//! [`fsmnt_parser_core::traverse::walk_dir`].
//!
//! Apple File System Reference, `06-volumes.md`, `07-file-system-objects.md`.

use alloc::string::String;
use alloc::vec::Vec;

use fsmnt_parser_core::traverse::{EntryKind, FsDirEntry, FsDirectory, FsId};

use crate::apfs::Apfs;
use crate::catalog::Catalog;
use crate::checkpoint::read_block;
use crate::directory::{DirEntry, DirEntryType, Directory, NameComparison};
use crate::error::{ApfsError, Result};
use crate::fext::FextTree;
use crate::inode::{Inode, ROOT_DIR_INO_NUM};
use crate::io::{Read, Seek};
use crate::omap::Omap;
use crate::sealed::{IntegrityMeta, SealVerification, verify_file_hashes};
use crate::snapshot::Snapshot;
use crate::types::{Oid, Xid};
use crate::volume::ApfsSuperblock;
use crate::xattr::Xattr;

/// The extended-attribute name holding a symbolic link's target.
pub const SYMLINK_XATTR_NAME: &str = "com.apple.fs.symlink";

/// A mounted APFS volume — the live volume, or a read-only point-in-time
/// snapshot view (see [`Volume::snapshot`]).
#[derive(Debug, Clone)]
pub struct Volume {
    catalog: Catalog,
    block_size: u32,
    cmp: NameComparison,
    /// The volume's object map, retained to resolve the snapshot-metadata
    /// tree on demand.
    omap: Omap,
    /// Object id of the volume's snapshot-metadata tree.
    snap_meta_tree_oid: Oid,
    /// Object id of the volume's integrity-metadata object; zero when
    /// the volume is not sealed.
    integrity_meta_oid: Oid,
    /// Physical block address of the volume's file-extent tree; zero when
    /// the volume is not sealed. Sealed volumes keep file extents here
    /// rather than as catalog `FILE_EXTENT` records.
    fext_tree_oid: Oid,
    /// The transaction the catalog is bound to.
    xid: Xid,
    /// The snapshot this view reflects, or `None` for the live volume. A
    /// snapshot view is read-only and carries the snapshot's provenance.
    snapshot: Option<Snapshot>,
}

impl Volume {
    /// Opens volume `index` of a mounted container.
    ///
    /// Reads the volume superblock and its (physical) object map, and builds
    /// the catalog handle for the volume's file-system tree.
    ///
    /// # Errors
    ///
    /// Propagates parsing and I/O errors.
    // Building a synthetic APFS container superblock for every flag
    // permutation (case-insensitive × normalization-insensitive) needs
    // the entire container/checkpoint stack; the `hashed = ci || ni`
    // disjunction is covered by `fixture.rs` against real images.
    #[cfg_attr(test, mutants::skip)]
    pub fn open<T: Read + Seek>(apfs: &Apfs, reader: &mut T, index: usize) -> Result<Self> {
        let superblock = apfs.volume(reader, index)?;
        let block_size = apfs.block_size();
        let omap_block = read_block(reader, block_size, superblock.omap_oid.0)?;
        let omap = Omap::parse(&omap_block)?;
        let xid = apfs.transaction_xid();
        let catalog = Catalog::new(superblock.root_tree_oid, omap.clone(), block_size, xid);
        // Hashed directory-entry keys are used on case-insensitive or
        // normalization-insensitive volumes; case folding is applied only
        // on a case-insensitive volume.
        let cmp = NameComparison {
            hashed: superblock.is_case_insensitive() || superblock.is_normalization_insensitive(),
            case_insensitive: superblock.is_case_insensitive(),
        };
        Ok(Self {
            catalog,
            block_size,
            cmp,
            omap,
            snap_meta_tree_oid: superblock.snap_meta_tree_oid,
            integrity_meta_oid: superblock.integrity_meta_oid,
            fext_tree_oid: superblock.fext_tree_oid,
            xid,
            snapshot: None,
        })
    }

    /// The snapshot this view reflects, or `None` for the live volume.
    ///
    /// A snapshot view is a read-only point-in-time copy; the returned
    /// [`Snapshot`] carries its name, transaction id, and timestamps.
    #[must_use]
    pub fn snapshot(&self) -> Option<&Snapshot> {
        self.snapshot.as_ref()
    }

    /// Whether this handle is a snapshot view rather than the live volume.
    #[must_use]
    pub fn is_snapshot(&self) -> bool {
        self.snapshot.is_some()
    }

    /// Enumerates the volume's snapshots, newest records last.
    ///
    /// Returns an empty list when the volume has no snapshots.
    ///
    /// # Errors
    ///
    /// Propagates snapshot-metadata-tree walk and parsing errors.
    pub fn snapshots<T: Read + Seek>(&self, reader: &mut T) -> Result<Vec<Snapshot>> {
        let tree = Catalog::new(
            self.snap_meta_tree_oid,
            self.omap.clone(),
            self.block_size,
            self.xid,
        );
        Snapshot::list(&tree, reader)
    }

    /// Opens `snapshot` as a read-only point-in-time [`Volume`] view.
    ///
    /// The snapshot's volume superblock locates its own object map and
    /// root file-system tree; the catalog is bound to the snapshot's
    /// transaction id, so catalog, extent, and metadata lookups resolve
    /// the snapshot state — including files since deleted from the live
    /// volume.
    ///
    /// # Errors
    ///
    /// Propagates I/O and parsing errors.
    pub fn open_snapshot<T: Read + Seek>(
        &self,
        reader: &mut T,
        snapshot: &Snapshot,
    ) -> Result<Self> {
        let sb_block = read_block(reader, self.block_size, snapshot.sblock_oid)?;
        let superblock = ApfsSuperblock::parse(&sb_block)?;
        let omap_block = read_block(reader, self.block_size, superblock.omap_oid.0)?;
        let omap = Omap::parse(&omap_block)?;
        let xid = Xid(snapshot.xid);
        let catalog = Catalog::new(superblock.root_tree_oid, omap.clone(), self.block_size, xid);
        Ok(Self {
            catalog,
            block_size: self.block_size,
            cmp: self.cmp,
            omap,
            snap_meta_tree_oid: superblock.snap_meta_tree_oid,
            integrity_meta_oid: superblock.integrity_meta_oid,
            fext_tree_oid: superblock.fext_tree_oid,
            xid,
            snapshot: Some(snapshot.clone()),
        })
    }

    /// Opens the snapshot named `name` as a read-only [`Volume`] view.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::NotFound`] when no snapshot has that name, and
    /// propagates I/O and parsing errors.
    pub fn open_snapshot_by_name<T: Read + Seek>(
        &self,
        reader: &mut T,
        name: &str,
    ) -> Result<Self> {
        let snapshot = self
            .snapshots(reader)?
            .into_iter()
            .find(|snapshot| snapshot.name == name)
            .ok_or(ApfsError::NotFound { what: "snapshot" })?;
        self.open_snapshot(reader, &snapshot)
    }

    /// Verifies the volume's seal end to end.
    ///
    /// A volume with no integrity-metadata object is reported
    /// [`SealVerification::NotSealed`] without error. Otherwise the
    /// integrity metadata is read; an already-broken seal is reported
    /// [`SealVerification::SealBroken`]. A live sealed volume has every
    /// file-data hash checked, and the [`SealVerification::Verified`]
    /// report lists any mismatches.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::NotFound`] when the integrity-metadata object
    /// cannot be resolved, and propagates parsing and I/O errors.
    pub fn verify_seal<T: Read + Seek>(&self, reader: &mut T) -> Result<SealVerification> {
        if self.integrity_meta_oid.0 == 0 {
            return Ok(SealVerification::NotSealed);
        }
        let resolved = self
            .omap
            .resolve(reader, self.block_size, self.integrity_meta_oid, self.xid)?
            .ok_or(ApfsError::NotFound {
                what: "integrity-metadata object",
            })?;
        let addr = resolved.paddr.as_block().ok_or(ApfsError::Malformed {
            structure: "omap_val_t",
            reason: "integrity-metadata address is not a valid block",
        })?;
        let integrity = IntegrityMeta::parse(&read_block(reader, self.block_size, addr)?)?;
        if integrity.is_seal_broken() {
            return Ok(SealVerification::SealBroken);
        }
        // A sealed volume keeps file extents in the file-extent tree, not
        // as catalog `FILE_EXTENT` records; the verifier reads through it.
        let fext = FextTree::new(self.fext_tree_oid.0);
        let report = verify_file_hashes(&self.catalog, &fext, reader, &integrity, self.block_size)?;
        Ok(SealVerification::Verified(report))
    }

    /// The volume's catalog handle.
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The volume's directory-name comparison mode.
    #[must_use]
    pub fn name_comparison(&self) -> NameComparison {
        self.cmp
    }

    /// Reads the inode of `obj_id`.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk errors; returns `Ok(None)` when the object has
    /// no inode record.
    pub fn inode<T: Read + Seek>(&self, reader: &mut T, obj_id: u64) -> Result<Option<Inode>> {
        Inode::lookup(&self.catalog, reader, obj_id)
    }

    /// Resolves an absolute path to its object identifier.
    ///
    /// Each component is resolved by an exact-name directory lookup. A
    /// symbolic link encountered mid-path is **not** followed — the link's
    /// own object id is returned for that component — so resolution cannot
    /// loop.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::NotFound`] when a path component does not exist.
    pub fn resolve_path<T: Read + Seek>(&self, reader: &mut T, path: &str) -> Result<u64> {
        let mut current = ROOT_DIR_INO_NUM;
        for component in path.split('/').filter(|c| !c.is_empty()) {
            let dir = Directory::new(&self.catalog, current, self.cmp);
            let entry = dir.lookup(reader, component)?.ok_or(ApfsError::NotFound {
                what: "path component",
            })?;
            current = entry.file_id;
        }
        Ok(current)
    }

    /// Reads a symbolic link's target path.
    ///
    /// APFS stores the target in the `com.apple.fs.symlink` extended
    /// attribute.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::NotFound`] when the inode has no symlink xattr.
    pub fn read_symlink<T: Read + Seek>(&self, reader: &mut T, inode_id: u64) -> Result<String> {
        for xattr in Xattr::list(&self.catalog, reader, inode_id)? {
            if xattr.name == SYMLINK_XATTR_NAME {
                let raw = xattr.read(&self.catalog, reader, self.block_size)?;
                let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                return Ok(String::from_utf8_lossy(&raw[..end]).into_owned());
            }
        }
        Err(ApfsError::NotFound {
            what: "symbolic-link target",
        })
    }

    /// Lists the entries of the directory with object identifier `dir_id`.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and record-parsing errors.
    pub fn read_dir<T: Read + Seek>(&self, reader: &mut T, dir_id: u64) -> Result<Vec<DirEntry>> {
        Directory::new(&self.catalog, dir_id, self.cmp).entries(reader)
    }

    /// Returns the volume's root directory as a traversal handle, usable with
    /// [`fsmnt_parser_core::traverse::walk_dir`].
    #[must_use]
    pub fn root(&self) -> ApfsDir {
        ApfsDir {
            catalog: self.catalog.clone(),
            dir_id: ROOT_DIR_INO_NUM,
            cmp: self.cmp,
        }
    }
}

/// Maps an APFS directory-entry type to a filesystem-agnostic [`EntryKind`].
fn entry_kind(file_type: DirEntryType) -> EntryKind {
    match file_type {
        DirEntryType::Directory => EntryKind::Directory,
        DirEntryType::Regular => EntryKind::File,
        DirEntryType::Symlink => EntryKind::Symlink,
        DirEntryType::Fifo => EntryKind::Fifo,
        DirEntryType::CharDevice => EntryKind::CharDevice,
        DirEntryType::BlockDevice => EntryKind::BlockDevice,
        DirEntryType::Socket => EntryKind::Socket,
        DirEntryType::Unknown | DirEntryType::Whiteout | DirEntryType::Other(_) => EntryKind::Other,
    }
}

/// An APFS directory as a `fsmnt-parser-core` traversal handle.
#[derive(Debug, Clone)]
pub struct ApfsDir {
    catalog: Catalog,
    dir_id: u64,
    cmp: NameComparison,
}

/// One entry of an [`ApfsDir`], as a `fsmnt-parser-core` traversal entry.
#[derive(Debug, Clone)]
pub struct ApfsTraversalEntry {
    catalog: Catalog,
    cmp: NameComparison,
    entry: DirEntry,
}

impl<R: Read + Seek> FsDirEntry<R> for ApfsTraversalEntry {
    type Error = ApfsError;
    type Dir = ApfsDir;

    fn kind(&self) -> EntryKind {
        entry_kind(self.entry.file_type)
    }

    fn name_bytes(&self) -> &[u8] {
        self.entry.name.as_bytes()
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(self.entry.file_id))
    }

    fn open_dir(&self, _reader: &mut R) -> Result<Option<ApfsDir>> {
        if self.entry.file_type == DirEntryType::Directory {
            Ok(Some(ApfsDir {
                catalog: self.catalog.clone(),
                dir_id: self.entry.file_id,
                cmp: self.cmp,
            }))
        } else {
            Ok(None)
        }
    }
}

/// A lending iterator over an [`ApfsDir`]'s entries.
pub struct ApfsEntryIter {
    items: Vec<ApfsTraversalEntry>,
    index: usize,
}

impl fsmnt_parser_core::iter::FsTryIteratorType for ApfsEntryIter {
    type Error = ApfsError;
    type Item<'a> = ApfsTraversalEntry;
}

impl<R: Read + Seek> fsmnt_parser_core::iter::FsTryIterator<R> for ApfsEntryIter {
    // Index-update mutation `self.index += 1` → `self.index *= 1` keeps
    // the iterator on the same entry forever; the test harness detects
    // the resulting infinite loop as a timeout. Iteration coverage is
    // exercised by `walk_dir_enumerates_the_tree`.
    #[cfg_attr(test, mutants::skip)]
    fn try_next(&mut self, _reader: &mut R) -> Result<Option<ApfsTraversalEntry>> {
        let item = self.items.get(self.index).cloned();
        if item.is_some() {
            self.index += 1;
        }
        Ok(item)
    }
}

impl<R: Read + Seek> FsDirectory<R> for ApfsDir {
    type Error = ApfsError;
    type EntryIter = ApfsEntryIter;

    fn entries(&mut self, reader: &mut R) -> Result<ApfsEntryIter> {
        let dir = Directory::new(&self.catalog, self.dir_id, self.cmp);
        let items = dir
            .entries(reader)?
            .into_iter()
            .map(|entry| ApfsTraversalEntry {
                catalog: self.catalog.clone(),
                cmp: self.cmp,
                entry,
            })
            .collect();
        Ok(ApfsEntryIter { items, index: 0 })
    }

    fn id(&self) -> Option<FsId> {
        Some(FsId(self.dir_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::{JObjType, OBJ_TYPE_SHIFT};
    use crate::directory::J_DREC_LEN_MASK;
    use crate::object::OBJ_PHYSICAL;
    use crate::types::{Oid, Xid};
    use fsmnt_parser_core::traverse::walk_dir;
    use fsmnt_testkit::Cursor;
    use std::collections::BTreeSet;

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
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(records.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(records.len() * 8)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        let key_area = BTN_DATA_OFFSET + records.len() * 8;
        let value_end = BLK - BTREE_INFO_SIZE;
        let (mut kc, mut vc) = (0usize, 0usize);
        for (i, (key, value)) in records.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 8;
            b[toc..toc + 2].copy_from_slice(
                &u16::try_from(kc)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 2..toc + 4].copy_from_slice(
                &u16::try_from(key.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            vc += value.len();
            b[toc + 4..toc + 6].copy_from_slice(
                &u16::try_from(vc)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[toc + 6..toc + 8].copy_from_slice(
                &u16::try_from(value.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
            b[key_area + kc..key_area + kc + key.len()].copy_from_slice(key);
            b[value_end - vc..value_end - vc + value.len()].copy_from_slice(value);
            kc += key.len();
        }
        b
    }

    fn drec(dir_id: u64, name: &str, child: u64, file_type: u16) -> (Vec<u8>, Vec<u8>) {
        let mut key = ((u64::from(JObjType::DirRec.as_value()) << OBJ_TYPE_SHIFT) | dir_id)
            .to_le_bytes()
            .to_vec();
        let len = u32::try_from(name.len()).expect("the test fixture value fits in u32") + 1;
        key.extend_from_slice(&(len & J_DREC_LEN_MASK).to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        let mut value = vec![0u8; 18];
        value[0..8].copy_from_slice(&child.to_le_bytes());
        value[16..18].copy_from_slice(&file_type.to_le_bytes());
        (key, value)
    }

    /// A volume: root (2) holds dir "sub" (10) and file "a.txt" (11);
    /// "sub" holds file "b.txt" (12).
    fn volume() -> (Volume, Cursor<Vec<u8>>) {
        let leaf = catalog_leaf(&[
            drec(2, "sub", 10, 4),
            drec(2, "a.txt", 11, 8),
            drec(10, "b.txt", 12, 8),
        ]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(200, 2)); // catalog root virtual oid 200 -> block 2
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(200),
            omap.clone(),
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let volume = Volume {
            catalog,
            block_size: u32::try_from(BLK).expect("the test fixture value fits in u32"),
            cmp: NameComparison {
                hashed: true,
                case_insensitive: true,
            },
            omap,
            snap_meta_tree_oid: Oid(0),
            integrity_meta_oid: Oid(0),
            fext_tree_oid: Oid(0),
            xid: Xid(1),
            snapshot: None,
        };
        (volume, Cursor::new(image))
    }

    #[test]
    fn resolves_an_absolute_path() {
        let (vol, mut reader) = volume();
        assert_eq!(vol.resolve_path(&mut reader, "/sub").unwrap(), 10);
        assert_eq!(vol.resolve_path(&mut reader, "/sub/b.txt").unwrap(), 12);
        assert_eq!(vol.resolve_path(&mut reader, "/").unwrap(), 2);
    }

    #[test]
    fn missing_path_component_is_a_typed_error() {
        let (vol, mut reader) = volume();
        assert!(matches!(
            vol.resolve_path(&mut reader, "/sub/nope"),
            Err(ApfsError::NotFound { .. })
        ));
    }

    #[test]
    fn read_dir_lists_a_directory_by_id() {
        let (vol, mut reader) = volume();
        let mut names: Vec<String> = vol
            .read_dir(&mut reader, 2)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        names.sort();
        assert_eq!(names, ["a.txt", "sub"]);
        // The "sub" directory holds a single child.
        let sub = vol.read_dir(&mut reader, 10).unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].name, "b.txt");
    }

    #[test]
    fn walk_dir_enumerates_the_tree() {
        let (vol, mut reader) = volume();
        let mut root = vol.root();
        let mut seen = BTreeSet::new();
        let mut names = Vec::new();
        walk_dir(
            &mut reader,
            &mut root,
            &mut seen,
            &mut |entry: ApfsTraversalEntry| {
                names.push(entry.entry.name.clone());
            },
        )
        .unwrap();
        names.sort();
        assert_eq!(names, ["a.txt", "b.txt", "sub"]);
    }

    // --- Snapshot views ---------------------------------------------------

    /// An `apfs_superblock_t` block naming its object map and root tree.
    fn apfs_superblock(omap_oid: u64, root_tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&0x0000_000Du32.to_le_bytes()); // FS object type
        b[0x20..0x24].copy_from_slice(b"APSB"); // apfs_magic
        b[0x80..0x88].copy_from_slice(&omap_oid.to_le_bytes());
        b[0x88..0x90].copy_from_slice(&root_tree_oid.to_le_bytes());
        b
    }

    /// A `SNAP_METADATA` catalog record keyed by the snapshot's xid.
    fn snap_metadata_record(xid: u64, name: &str, sblock_oid: u64) -> (Vec<u8>, Vec<u8>) {
        let key = ((u64::from(JObjType::SnapMetadata.as_value()) << OBJ_TYPE_SHIFT) | xid)
            .to_le_bytes()
            .to_vec();
        let mut value = vec![0u8; 50];
        value[8..16].copy_from_slice(&sblock_oid.to_le_bytes()); // sblock_oid
        value[48..50].copy_from_slice(
            &(u16::try_from(name.len()).expect("the test fixture value fits in u16") + 1)
                .to_le_bytes(),
        );
        value.extend_from_slice(name.as_bytes());
        value.push(0);
        (key, value)
    }

    /// Builds a volume whose snapshot-metadata tree holds `snaps`, and an
    /// image carrying — for each snapshot — its superblock, object map, and
    /// a catalog leaf with one file `deleted.txt` (object id 11).
    fn volume_with_snapshots(snaps: &[(u64, &str)]) -> (Volume, Cursor<Vec<u8>>) {
        // Blocks 0..3: the snapshot-metadata tree. Each snapshot then adds
        // four blocks: superblock, omap, omap tree, catalog leaf.
        let records: Vec<(Vec<u8>, Vec<u8>)> = snaps
            .iter()
            .enumerate()
            .map(|(i, &(xid, name))| {
                let sblock = 3 + (i as u64) * 4;
                snap_metadata_record(xid, name, sblock)
            })
            .collect();
        let mut image = omap_phys(1); // block 0: snap-meta omap
        image.extend(omap_tree(300, 2)); // block 1: snap-meta omap tree -> block 2
        image.extend(catalog_leaf(&records)); // block 2: snap-meta leaf
        for (i, _) in snaps.iter().enumerate() {
            let base = 3 + (i as u64) * 4;
            image.extend(apfs_superblock(base + 1, 200)); // superblock
            image.extend(omap_phys(base + 2)); // snapshot omap
            image.extend(omap_tree(200, base + 3)); // omap tree -> catalog leaf
            image.extend(catalog_leaf(&[drec(2, "deleted.txt", 11, 8)]));
        }
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(300),
            omap.clone(),
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let volume = Volume {
            catalog,
            block_size: u32::try_from(BLK).expect("the test fixture value fits in u32"),
            cmp: NameComparison {
                hashed: true,
                case_insensitive: true,
            },
            omap,
            snap_meta_tree_oid: Oid(300),
            integrity_meta_oid: Oid(0),
            fext_tree_oid: Oid(0),
            xid: Xid(1),
            snapshot: None,
        };
        (volume, Cursor::new(image))
    }

    #[test]
    fn lists_volume_snapshots() {
        let (vol, mut reader) = volume_with_snapshots(&[(1000, "before"), (2000, "after")]);
        let snaps = vol.snapshots(&mut reader).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].name, "before");
        assert_eq!(snaps[0].xid, 1000);
        assert_eq!(snaps[1].name, "after");
    }

    #[test]
    fn volume_with_no_snapshots_lists_none() {
        let (vol, mut reader) = volume_with_snapshots(&[]);
        assert!(vol.snapshots(&mut reader).unwrap().is_empty());
        assert!(matches!(
            vol.open_snapshot_by_name(&mut reader, "any"),
            Err(ApfsError::NotFound { .. })
        ));
    }

    #[test]
    fn opens_a_snapshot_as_a_read_only_view() {
        let (vol, mut reader) = volume_with_snapshots(&[(1000, "snap1")]);
        let snap_vol = vol.open_snapshot_by_name(&mut reader, "snap1").unwrap();
        // The view is marked as a snapshot and carries its provenance.
        assert!(snap_vol.is_snapshot());
        let provenance = snap_vol.snapshot().expect("snapshot provenance");
        assert_eq!(provenance.name, "snap1");
        assert_eq!(provenance.xid, 1000);
        // A file in the snapshot tree resolves through the view — this is
        // how a file deleted from the live volume stays reachable.
        assert_eq!(
            snap_vol.resolve_path(&mut reader, "/deleted.txt").unwrap(),
            11
        );
    }

    #[test]
    fn missing_snapshot_is_a_typed_error() {
        let (vol, mut reader) = volume_with_snapshots(&[(1000, "snap1")]);
        assert!(matches!(
            vol.open_snapshot_by_name(&mut reader, "nonexistent"),
            Err(ApfsError::NotFound { .. })
        ));
        // The live volume itself is not a snapshot view.
        assert!(!vol.is_snapshot());
        assert!(vol.snapshot().is_none());
    }

    #[test]
    fn verify_seal_reports_an_unsealed_volume() {
        // The test volume has no integrity-metadata object.
        let (vol, mut reader) = volume();
        assert!(matches!(
            vol.verify_seal(&mut reader).unwrap(),
            SealVerification::NotSealed
        ));
    }

    /// `j_inode_val_t`: a minimal 92-byte inode record carrying the mode.
    fn inode_value(mode: u16) -> Vec<u8> {
        let mut v = vec![0u8; 92];
        v[0x50..0x52].copy_from_slice(&mode.to_le_bytes());
        v
    }

    fn inode_record(obj_id: u64, mode: u16) -> (Vec<u8>, Vec<u8>) {
        let key = ((u64::from(JObjType::Inode.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        (key, inode_value(mode))
    }

    /// An `XATTR` record keyed by `(obj_id, name)` carrying an
    /// `XF_DATA_EMBEDDED` (0x0002) value of `data`.
    fn xattr_record(obj_id: u64, name: &str, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = ((u64::from(JObjType::Xattr.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        let bytes = name.as_bytes();
        key.extend_from_slice(
            &(u16::try_from(bytes.len()).expect("the test fixture value fits in u16") + 1)
                .to_le_bytes(),
        );
        key.extend_from_slice(bytes);
        key.push(0);
        // value: flags(u16) = 0x0002 (XF_DATA_EMBEDDED), xdata_len(u16), data.
        let mut value = Vec::new();
        value.extend_from_slice(&0x0002u16.to_le_bytes());
        value.extend_from_slice(
            &u16::try_from(data.len())
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        value.extend_from_slice(data);
        (key, value)
    }

    /// A volume rooted at inode 2 with one regular-file inode `5` and an
    /// `XF_DATA_EMBEDDED` `com.apple.fs.symlink` xattr targeting
    /// `target_path` (with an embedded NUL terminator so the parser's
    /// position-lookup is exercised). A second xattr precedes the symlink
    /// one so the iteration must skip past it.
    fn symlink_volume(target_path: &str) -> (Volume, Cursor<Vec<u8>>) {
        // Records: a precursor xattr (non-symlink), the symlink xattr, and
        // an inode so `Volume::inode` resolves. Keys are sorted by the
        // catalog comparator (object id, then kind, then sub-key); use
        // ids/types whose sorted order is stable for our test.
        let mut symlink_bytes = target_path.as_bytes().to_vec();
        symlink_bytes.push(0); // trailing NUL stored on disk
        symlink_bytes.extend_from_slice(b"trailing-junk"); // bytes after NUL
        let records = {
            let mut r = vec![
                inode_record(5, 0o120_755),
                xattr_record(5, "com.apple.fs.symlink", &symlink_bytes),
                xattr_record(5, "com.apple.zzz.other", b"unused"),
            ];
            // Catalog requires records sorted by binary key order; sort.
            r.sort_by(|a, b| a.0.cmp(&b.0));
            r
        };
        let leaf = catalog_leaf(&records);
        let mut image = omap_phys(1);
        image.extend(omap_tree(200, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(200),
            omap.clone(),
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let volume = Volume {
            catalog,
            block_size: u32::try_from(BLK).expect("the test fixture value fits in u32"),
            cmp: NameComparison {
                hashed: false,
                case_insensitive: false,
            },
            omap,
            snap_meta_tree_oid: Oid(0),
            integrity_meta_oid: Oid(0),
            fext_tree_oid: Oid(0),
            xid: Xid(1),
            snapshot: None,
        };
        (volume, Cursor::new(image))
    }

    #[test]
    fn inode_lookup_returns_some_for_a_present_object() {
        // `Volume::inode` is a thin wrapper around `Inode::lookup`; the
        // mutant `-> Ok(None)` is killed by asserting it returns `Some`
        // for a present object id.
        let (vol, mut reader) = symlink_volume("/dev/null");
        let inode = vol.inode(&mut reader, 5).unwrap();
        let inode = inode.expect("inode 5 should resolve");
        // Mode 0o120_755 is a symlink in the file_type bits — exercises
        // the value-byte path so the lookup is doing real work, not just
        // returning a bare `Some(default)`.
        assert_eq!(inode.file_type(), crate::inode::FileType::Symlink);
    }

    #[test]
    fn read_symlink_returns_the_target_for_the_symlink_xattr() {
        // Covers the symlink-name lookup (`xattr.name == SYMLINK…`) and
        // the trailing-NUL terminator stripping (`b == 0`).
        let (vol, mut reader) = symlink_volume("/etc/hosts");
        let target = vol.read_symlink(&mut reader, 5).unwrap();
        assert_eq!(target, "/etc/hosts");
        // The `b == 0` check must stop at the NUL — if it were `!=`,
        // `position` would return `Some(0)` and the result would be
        // empty.
        assert!(!target.is_empty());
        assert!(!target.contains('\0'));
    }

    #[test]
    fn read_symlink_with_no_xattr_is_not_found() {
        // Distinguishes the empty/“xyzzy” constant-return mutants from
        // the real read path: a volume with no xattr surfaces NotFound.
        let (vol, mut reader) = volume(); // has no xattrs at all
        let err = vol.read_symlink(&mut reader, 11).unwrap_err();
        assert!(
            matches!(err, ApfsError::NotFound { what }
                if what == "symbolic-link target"),
            "expected NotFound for missing symlink xattr, got {err:?}"
        );
    }

    #[test]
    fn traversal_entry_exposes_name_bytes_and_id() {
        use fsmnt_parser_core::traverse::{FsDirEntry, FsDirectory};
        let (vol, mut reader) = volume();
        let mut root = vol.root();
        // The root directory's id is the well-known root-inode number.
        assert_eq!(
            <ApfsDir as FsDirectory<Cursor<Vec<u8>>>>::id(&root),
            Some(FsId(ROOT_DIR_INO_NUM))
        );
        let mut iter = root.entries(&mut reader).unwrap();
        let mut found = std::collections::BTreeMap::<Vec<u8>, FsId>::new();
        while let Some(entry) = <ApfsEntryIter as fsmnt_parser_core::iter::FsTryIterator<
            Cursor<Vec<u8>>,
        >>::try_next(&mut iter, &mut reader)
        .unwrap()
        {
            let name =
                <ApfsTraversalEntry as FsDirEntry<Cursor<Vec<u8>>>>::name_bytes(&entry).to_vec();
            let id = <ApfsTraversalEntry as FsDirEntry<Cursor<Vec<u8>>>>::id(&entry).unwrap();
            found.insert(name, id);
        }
        // The root holds "sub" (id 10) and "a.txt" (id 11) — name_bytes
        // and id must surface exactly those, not a leaked constant.
        assert_eq!(found.get(&b"sub"[..]).copied(), Some(FsId(10)));
        assert_eq!(found.get(&b"a.txt"[..]).copied(), Some(FsId(11)));
        assert_eq!(found.len(), 2);
    }
}
