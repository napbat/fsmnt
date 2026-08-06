//! Sparse files and clone (copy-on-write) extents.
//!
//! APFS files can be sparse — logical holes with no backing extent — and
//! cloned, where two files share the same physical extents copy-on-write.
//! Sharing is recorded in the physical-extent-reference tree: an extent with
//! a reference count above one is shared.
//!
//! Apple File System Reference, `09-data-streams.md`, `06-volumes.md`.

use alloc::vec::Vec;

use zerocopy::{FromBytes, I32, Immutable, KnownLayout, LittleEndian as LE, U64, Unaligned};

use crate::catalog::{Catalog, JObjType};
use crate::error::{ApfsError, Result};
use crate::extent::{File, FileExtent};
use crate::io::{Read, Seek};

/// Mask selecting the block length of a physical extent (`PEXT_LEN_MASK`).
pub const PEXT_LEN_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
/// Shift selecting the kind of a physical extent (`PEXT_KIND_SHIFT`).
pub const PEXT_KIND_SHIFT: u64 = 60;

/// The kind of an extent or record (`j_obj_kinds`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JObjKind {
    /// Any kind (`APFS_KIND_ANY`).
    Any,
    /// A newly created extent (`APFS_KIND_NEW`).
    New,
    /// An updated extent (`APFS_KIND_UPDATE`).
    Update,
    /// A dead extent pending deletion (`APFS_KIND_DEAD`).
    Dead,
    /// An extent whose reference count was updated (`APFS_KIND_UPDATE_REFCNT`).
    UpdateRefcnt,
    /// An invalid kind (`APFS_KIND_INVALID`).
    Invalid,
    /// A kind value this parser does not recognize.
    Unknown(u8),
}

impl JObjKind {
    /// Decodes a kind from its `j_obj_kinds` value.
    #[must_use]
    pub fn from_value(value: u8) -> Self {
        match value {
            0 => Self::Any,
            1 => Self::New,
            2 => Self::Update,
            3 => Self::Dead,
            4 => Self::UpdateRefcnt,
            255 => Self::Invalid,
            other => Self::Unknown(other),
        }
    }
}

/// On-disk `j_phys_ext_val_t` (20 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawPhysExtVal {
    len_and_kind: U64<LE>,
    owning_obj_id: U64<LE>,
    refcnt: I32<LE>,
}

/// A physical-extent record (`j_phys_ext_val_t`) from the extent-reference
/// tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalExtent {
    /// Length of the extent, in blocks.
    pub length_blocks: u64,
    /// The extent's kind.
    pub kind: JObjKind,
    /// Identifier of the file-system record that owns the extent.
    pub owning_obj_id: u64,
    /// The extent's reference count; a count above one means it is shared
    /// (cloned).
    pub refcnt: i32,
}

impl PhysicalExtent {
    /// Parses a `j_phys_ext_val_t` value.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short value.
    pub fn parse(value: &[u8]) -> Result<Self> {
        let (raw, _rest) =
            RawPhysExtVal::ref_from_prefix(value).map_err(|_| ApfsError::Truncated {
                structure: "j_phys_ext_val_t",
                expected: core::mem::size_of::<RawPhysExtVal>(),
                actual: value.len(),
            })?;
        let len_and_kind = raw.len_and_kind.get();
        Ok(Self {
            length_blocks: len_and_kind & PEXT_LEN_MASK,
            kind: JObjKind::from_value((len_and_kind >> PEXT_KIND_SHIFT) as u8),
            owning_obj_id: raw.owning_obj_id.get(),
            refcnt: raw.refcnt.get(),
        })
    }

    /// Whether the extent is shared by more than one file (a clone).
    #[must_use]
    pub fn is_shared(&self) -> bool {
        self.refcnt > 1
    }
}

/// The volume's physical-extent-reference tree.
///
/// Keyed by physical block address, it records the reference count of every
/// extent — the basis for recognizing clones.
#[derive(Debug, Clone)]
pub struct ExtentRefs {
    tree: Catalog,
}

impl ExtentRefs {
    /// Wraps the extent-reference tree as a lookup handle.
    ///
    /// `tree` is a [`Catalog`] built on the volume's `apfs_extentref_tree_oid`.
    #[must_use]
    pub fn new(tree: Catalog) -> Self {
        Self { tree }
    }

    /// Looks up the physical-extent record starting at `phys_block`.
    ///
    /// # Errors
    ///
    /// Propagates tree-walk and parsing errors.
    pub fn lookup<T: Read + Seek>(
        &self,
        reader: &mut T,
        phys_block: u64,
    ) -> Result<Option<PhysicalExtent>> {
        match self
            .tree
            .find_record(reader, phys_block, JObjType::Extent)?
        {
            Some(value) => Ok(Some(PhysicalExtent::parse(&value)?)),
            None => Ok(None),
        }
    }
}

/// A file extent paired with the sharing information from the extent-
/// reference tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedExtent {
    /// The file extent.
    pub extent: FileExtent,
    /// The physical extent's reference count, or `None` when no
    /// physical-extent record was found.
    pub refcnt: Option<i32>,
}

impl ClassifiedExtent {
    /// Whether the extent is shared with another file (a clone).
    #[must_use]
    pub fn is_shared(&self) -> bool {
        self.refcnt.is_some_and(|count| count > 1)
    }
}

/// Classifies each extent of `file` as exclusive or shared, using the
/// extent-reference tree.
///
/// # Errors
///
/// Propagates tree-walk and parsing errors.
pub fn classify_extents<T: Read + Seek>(
    file: &File,
    extent_refs: &ExtentRefs,
    reader: &mut T,
) -> Result<Vec<ClassifiedExtent>> {
    let mut classified = Vec::with_capacity(file.extents().len());
    for &extent in file.extents() {
        let refcnt = extent_refs
            .lookup(reader, extent.phys_block_num)?
            .map(|physical| physical.refcnt);
        classified.push(ClassifiedExtent { extent, refcnt });
    }
    Ok(classified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::object::OBJ_PHYSICAL;
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use fsmnt_testkit::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn kind_decodes_from_value() {
        assert_eq!(JObjKind::from_value(1), JObjKind::New);
        assert_eq!(JObjKind::from_value(4), JObjKind::UpdateRefcnt);
        assert_eq!(JObjKind::from_value(255), JObjKind::Invalid);
        assert_eq!(JObjKind::from_value(50), JObjKind::Unknown(50));
    }

    #[test]
    fn physical_extent_parses_length_kind_and_refcnt() {
        let mut value = vec![0u8; 20];
        // length 8 blocks, kind NEW (1) in the high nibble.
        let len_and_kind = (1u64 << PEXT_KIND_SHIFT) | 8;
        value[0..8].copy_from_slice(&len_and_kind.to_le_bytes());
        value[8..16].copy_from_slice(&77u64.to_le_bytes()); // owning_obj_id
        value[16..20].copy_from_slice(&3i32.to_le_bytes()); // refcnt
        let extent = PhysicalExtent::parse(&value).unwrap();
        assert_eq!(extent.length_blocks, 8);
        assert_eq!(extent.kind, JObjKind::New);
        assert_eq!(extent.owning_obj_id, 77);
        assert_eq!(extent.refcnt, 3);
        assert!(extent.is_shared());
    }

    #[test]
    fn physical_extent_refcnt_one_is_exclusive() {
        let mut value = vec![0u8; 20];
        value[0..8].copy_from_slice(&((1u64 << PEXT_KIND_SHIFT) | 1).to_le_bytes());
        value[16..20].copy_from_slice(&1i32.to_le_bytes());
        assert!(!PhysicalExtent::parse(&value).unwrap().is_shared());
    }

    #[test]
    fn physical_extent_rejects_short_value() {
        assert!(matches!(
            PhysicalExtent::parse(&[0u8; 8]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    // --- ExtentRefs lookup against a synthetic extent-reference tree ------

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

    fn extent_record(phys_block: u64, refcnt: i32) -> (Vec<u8>, Vec<u8>) {
        let key = ((u64::from(JObjType::Extent.as_value()) << OBJ_TYPE_SHIFT) | phys_block)
            .to_le_bytes()
            .to_vec();
        let mut value = vec![0u8; 20];
        value[0..8].copy_from_slice(&((1u64 << PEXT_KIND_SHIFT) | 1).to_le_bytes());
        value[16..20].copy_from_slice(&refcnt.to_le_bytes());
        (key, value)
    }

    #[test]
    fn extent_refs_report_the_reference_count() {
        // Block 3 is exclusive (refcnt 1); block 9 is cloned (refcnt 2).
        let leaf = catalog_leaf(&[extent_record(3, 1), extent_record(9, 2)]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(70, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(
            Oid(70),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let refs = ExtentRefs::new(tree);
        let mut reader = Cursor::new(image);

        assert_eq!(refs.lookup(&mut reader, 3).unwrap().unwrap().refcnt, 1);
        let cloned = refs.lookup(&mut reader, 9).unwrap().unwrap();
        assert!(cloned.is_shared());
        assert!(refs.lookup(&mut reader, 100).unwrap().is_none());
    }

    fn classified(refcnt: Option<i32>) -> ClassifiedExtent {
        ClassifiedExtent {
            extent: FileExtent {
                logical_addr: 0,
                length: 4096,
                phys_block_num: 5,
                crypto_id: 0,
            },
            refcnt,
        }
    }

    #[test]
    fn classified_extent_with_refcnt_above_one_is_shared() {
        // refcnt 2 means the physical extent is referenced by two files.
        assert!(classified(Some(2)).is_shared());
    }

    #[test]
    fn classified_extent_with_refcnt_one_is_not_shared() {
        // Boundary: refcnt == 1 means exclusive, not shared. Catches the
        // `> with >=` mutant on the predicate.
        assert!(!classified(Some(1)).is_shared());
    }

    #[test]
    fn classified_extent_without_a_record_is_not_shared() {
        // A None refcnt means no physical-extent record was found; the
        // extent cannot be claimed as shared.
        assert!(!classified(None).is_shared());
    }

    #[test]
    fn classify_extents_returns_one_entry_per_file_extent() {
        // Two file extents over blocks 3 (refcnt 1) and 9 (refcnt 2). The
        // classified output must keep that count and order, distinguishing
        // it from an empty-vec mutant.
        let leaf = catalog_leaf(&[extent_record(3, 1), extent_record(9, 2)]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(70, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(
            Oid(70),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let refs = ExtentRefs::new(tree);
        let mut reader = Cursor::new(image);

        let file = File::from_extents(
            8192,
            alloc::vec![
                FileExtent {
                    logical_addr: 0,
                    length: 4096,
                    phys_block_num: 3,
                    crypto_id: 0,
                },
                FileExtent {
                    logical_addr: 4096,
                    length: 4096,
                    phys_block_num: 9,
                    crypto_id: 0,
                },
            ],
        );
        let classified = classify_extents(&file, &refs, &mut reader).unwrap();
        assert_eq!(classified.len(), 2);
        assert_eq!(classified[0].refcnt, Some(1));
        assert_eq!(classified[1].refcnt, Some(2));
        assert!(!classified[0].is_shared());
        assert!(classified[1].is_shared());
    }
}
