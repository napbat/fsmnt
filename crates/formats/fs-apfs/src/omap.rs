//! The object map (`omap_phys_t`) — virtual-object to physical-block
//! resolution.
//!
//! Most APFS objects are *virtual*: addressed by object identifier and located
//! through an object map, a B-tree keyed by `(oid, xid)`. Resolving a virtual
//! object means finding the entry with a matching object id and the largest
//! transaction id not exceeding the requested one.
//!
//! Apple File System Reference, `05-object-maps.md`.

use core::cmp::Ordering;

use bitflags::bitflags;
use zerocopy::{FromBytes, I64, Immutable, KnownLayout, LittleEndian as LE, U32, U64, Unaligned};

use crate::btree::{BtreeNode, descend_le};
use crate::checkpoint::read_block;
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::object::{OBJ_PHYS_SIZE, ObjPhys};
use crate::types::{ObjectType, Oid, Paddr, Xid};

bitflags! {
    /// Object-map flags (`om_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OmapFlags: u32 {
        /// The object map is not managed by the standard reaper.
        const MANUALLY_MANAGED = 0x0000_0001;
        /// The object map is being encrypted.
        const ENCRYPTING = 0x0000_0002;
        /// The object map is being decrypted.
        const DECRYPTING = 0x0000_0004;
        /// The object map's encryption key is being rolled.
        const KEYROLLING = 0x0000_0008;
        /// The object map's crypto generation bit.
        const CRYPTO_GENERATION = 0x0000_0010;
    }
}

bitflags! {
    /// Object-map value flags (`ov_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OmapValFlags: u32 {
        /// The object was deleted; this mapping is a placeholder.
        const DELETED = 0x0000_0001;
        /// The mapping should not be replaced when the object is updated.
        const SAVED = 0x0000_0002;
        /// The mapped object is encrypted.
        const ENCRYPTED = 0x0000_0004;
        /// The mapped object is stored without an `obj_phys_t` header.
        const NOHEADER = 0x0000_0008;
        /// The mapping's crypto generation bit.
        const CRYPTO_GENERATION = 0x0000_0010;
    }
}

bitflags! {
    /// Object-map snapshot flags (`oms_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OmapSnapshotFlags: u32 {
        /// The snapshot has been deleted.
        const DELETED = 0x0000_0001;
        /// The snapshot has been reverted to.
        const REVERTED = 0x0000_0002;
    }
}

/// On-disk `omap_phys_t` (88 bytes).
#[allow(
    clippy::struct_field_names,
    reason = "the om_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawOmapPhys {
    om_o: [u8; OBJ_PHYS_SIZE],
    om_flags: U32<LE>,
    om_snap_count: U32<LE>,
    om_tree_type: U32<LE>,
    om_snapshot_tree_type: U32<LE>,
    om_tree_oid: U64<LE>,
    om_snapshot_tree_oid: U64<LE>,
    om_most_recent_snap: U64<LE>,
    om_pending_revert_min: U64<LE>,
    om_pending_revert_max: U64<LE>,
}

/// On-disk `omap_val_t` (16 bytes).
#[allow(
    clippy::struct_field_names,
    reason = "the ov_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawOmapVal {
    ov_flags: U32<LE>,
    ov_size: U32<LE>,
    ov_paddr: I64<LE>,
}

/// Size of an `omap_key_t` (`oid` + `xid`).
const OMAP_KEY_SIZE: usize = 16;

/// A resolved object-map value (`omap_val_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OmapValue {
    /// Flags describing the mapped object.
    pub flags: OmapValFlags,
    /// Size of the object in bytes.
    pub size: u32,
    /// Physical address of the object.
    pub paddr: Paddr,
}

/// A parsed object map (`omap_phys_t`).
#[derive(Debug, Clone)]
pub struct Omap {
    /// Object-map flags.
    pub flags: OmapFlags,
    /// Number of snapshots the object map has.
    pub snapshot_count: u32,
    /// Object id of the B-tree holding the object mappings.
    pub tree_oid: Oid,
    /// Object id of the B-tree holding snapshot information.
    pub snapshot_tree_oid: Oid,
    /// Transaction id of the most recent snapshot.
    pub most_recent_snap: Xid,
}

/// Orders two `omap_key_t` keys: object id ascending, then transaction id
/// ascending — the order in which the object-map B-tree stores its keys.
fn omap_key_cmp(a: &[u8], b: &[u8]) -> Ordering {
    let oid = read_u64(a, 0).cmp(&read_u64(b, 0));
    if oid != Ordering::Equal {
        return oid;
    }
    read_u64(a, 8).cmp(&read_u64(b, 8))
}

/// Reads a little-endian `u64` at byte offset `off`, treating a short slice
/// as zero-padded so a malformed key cannot panic.
//
// Equivalent-mutant skip: the `< vs <=` swap at the boundary only differs
// when `off == end`, where both branches copy an empty slice into an empty
// buffer and the result is identical (0).
#[cfg_attr(test, mutants::skip)]
fn read_u64(bytes: &[u8], off: usize) -> u64 {
    let mut buf = [0u8; 8];
    let end = (off + 8).min(bytes.len());
    if off < end {
        buf[..end - off].copy_from_slice(&bytes[off..end]);
    }
    u64::from_le_bytes(buf)
}

impl Omap {
    /// Parses an object map from its block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block or
    /// [`ApfsError::Malformed`] when the object header is not an object map.
    pub fn parse(block: &[u8]) -> Result<Self> {
        let raw = RawOmapPhys::ref_from_prefix(block)
            .map(|(raw, _rest)| raw)
            .map_err(|_| ApfsError::Truncated {
                structure: "omap_phys_t",
                expected: core::mem::size_of::<RawOmapPhys>(),
                actual: block.len(),
            })?;
        let header = ObjPhys::parse(block)?;
        if header.object_kind() != ObjectType::Omap {
            return Err(ApfsError::Malformed {
                structure: "omap_phys_t",
                reason: "object type is not an object map",
            });
        }
        Ok(Self {
            flags: OmapFlags::from_bits_retain(raw.om_flags.get()),
            snapshot_count: raw.om_snap_count.get(),
            tree_oid: Oid(raw.om_tree_oid.get()),
            snapshot_tree_oid: Oid(raw.om_snapshot_tree_oid.get()),
            most_recent_snap: Xid(raw.om_most_recent_snap.get()),
        })
    }

    /// Resolves a virtual object identifier to its physical location as of
    /// transaction `xid`.
    ///
    /// Returns the mapping with a matching object id and the largest
    /// transaction id `<= xid`, or `None` when the object map has no such
    /// entry. The object-map B-tree is a physical tree, so its nodes are read
    /// directly by block address.
    ///
    /// # Errors
    ///
    /// Propagates I/O and [`ApfsError::Malformed`] errors from the B-tree
    /// walk.
    pub fn resolve<R: Read + Seek>(
        &self,
        reader: &mut R,
        block_size: u32,
        oid: Oid,
        xid: Xid,
    ) -> Result<Option<OmapValue>> {
        // The object-map tree is a physical tree: its root is at the block
        // address held in `om_tree_oid`.
        let root = BtreeNode::parse(read_block(reader, block_size, self.tree_oid.0)?)?;

        let mut search = [0u8; OMAP_KEY_SIZE];
        search[0..8].copy_from_slice(&oid.0.to_le_bytes());
        search[8..16].copy_from_slice(&xid.0.to_le_bytes());

        let found = descend_le(
            root,
            reader,
            |reader, child| BtreeNode::parse(read_block(reader, block_size, child)?),
            &search,
            omap_key_cmp,
        )?;

        let Some((key, value)) = found else {
            return Ok(None);
        };
        // The predecessor may belong to an earlier object id; that means the
        // requested object has no mapping at or before `xid`.
        if read_u64(&key, 0) != oid.0 {
            return Ok(None);
        }
        let raw = RawOmapVal::ref_from_prefix(&value)
            .map(|(raw, _rest)| raw)
            .map_err(|_| ApfsError::Malformed {
                structure: "omap_val_t",
                reason: "value is shorter than omap_val_t",
            })?;
        let flags = OmapValFlags::from_bits_retain(raw.ov_flags.get());
        // A deletion tombstone is a placeholder, not a live mapping: a lookup
        // after the object was deleted must report it as not found.
        if flags.contains(OmapValFlags::DELETED) {
            return Ok(None);
        }
        Ok(Some(OmapValue {
            flags,
            size: raw.ov_size.get(),
            paddr: Paddr(raw.ov_paddr.get()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::object::OBJ_PHYSICAL;
    use std::io::Cursor;

    const BLK: usize = 4096;

    /// Builds an `omap_phys_t` block whose mapping tree is at `tree_oid`.
    fn omap_block(tree_oid: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x0B).to_le_bytes()); // OMAP
        b[0x24..0x28].copy_from_slice(&2u32.to_le_bytes()); // om_snap_count
        b[0x30..0x38].copy_from_slice(&tree_oid.to_le_bytes()); // om_tree_oid
        b
    }

    /// Builds a single root+leaf object-map B-tree node.
    ///
    /// `entries` is `(oid, xid, val_flags, val_size, paddr)`, pre-sorted by
    /// `(oid, xid)`.
    fn omap_tree_block(entries: &[(u64, u64, u32, u32, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        // btn_flags = ROOT | LEAF | FIXED_KV_SIZE.
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes());
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(entries.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        ); // btn_nkeys
        let toc_len = entries.len() * 4;
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(toc_len)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        ); // table_space.len

        let key_area = BTN_DATA_OFFSET + toc_len;
        let value_end = BLK - BTREE_INFO_SIZE;
        for (i, &(oid, xid, flags, size, paddr)) in entries.iter().enumerate() {
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
            b[vs..vs + 4].copy_from_slice(&flags.to_le_bytes());
            b[vs + 4..vs + 8].copy_from_slice(&size.to_le_bytes());
            b[vs + 8..vs + 16].copy_from_slice(&paddr.to_le_bytes());
        }
        // btree_info: bt_key_size 16, bt_val_size 16.
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 4..info + 8].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        ); // bt_node_size
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes()); // bt_key_size
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes()); // bt_val_size
        b
    }

    /// Spec example (`05-object-maps.md`): object 588 at three transactions.
    fn spec_example() -> (Omap, Cursor<Vec<u8>>) {
        // Block 0 = omap_phys, block 1 = the mapping tree.
        let mut image = omap_block(1);
        image.extend(omap_tree_block(&[
            (
                588,
                2101,
                0,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                200,
            ),
            (
                588,
                2202,
                0,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                300,
            ),
            (
                588,
                2300,
                0,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                100,
            ),
        ]));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (omap, Cursor::new(image))
    }

    #[test]
    fn parses_omap_phys() {
        let omap = Omap::parse(&omap_block(7)).unwrap();
        assert_eq!(omap.tree_oid, Oid(7));
        assert_eq!(omap.snapshot_count, 2);
    }

    #[test]
    fn rejects_a_non_omap_object_type() {
        let mut block = omap_block(7);
        block[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | 0x02).to_le_bytes()); // BTREE
        assert!(matches!(
            Omap::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn resolve_exact_transaction() {
        let (omap, mut reader) = spec_example();
        let value = omap
            .resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(588),
                Xid(2300),
            )
            .unwrap()
            .unwrap();
        assert_eq!(value.paddr, Paddr(100));
    }

    #[test]
    fn resolve_uses_largest_xid_not_exceeding_target() {
        let (omap, mut reader) = spec_example();
        // No entry at xid 2290; 2202 is the largest xid <= 2290.
        let value = omap
            .resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(588),
                Xid(2290),
            )
            .unwrap()
            .unwrap();
        assert_eq!(value.paddr, Paddr(300));
    }

    #[test]
    fn resolve_before_first_transaction_is_none() {
        let (omap, mut reader) = spec_example();
        assert!(
            omap.resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(588),
                Xid(2050)
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn resolve_unknown_object_is_none() {
        let (omap, mut reader) = spec_example();
        assert!(
            omap.resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(999),
                Xid(9999)
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn resolve_treats_a_deletion_tombstone_as_not_found() {
        // Object 70 has a live mapping at xid 10 and a DELETED tombstone at
        // xid 20. A lookup at xid 25 resolves the tombstone and must report
        // the object as gone; a lookup at xid 15 still sees the live entry.
        let mut image = omap_block(1);
        image.extend(omap_tree_block(&[
            (
                70,
                10,
                0,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                555,
            ),
            (
                70,
                20,
                OmapValFlags::DELETED.bits(),
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                777,
            ),
        ]));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let mut reader = Cursor::new(image);
        assert!(
            omap.resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(70),
                Xid(25)
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(
            omap.resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(70),
                Xid(15)
            )
            .unwrap()
            .unwrap()
            .paddr,
            Paddr(555)
        );
    }

    #[test]
    fn resolve_decodes_value_flags() {
        let mut image = omap_block(1);
        image.extend(omap_tree_block(&[(
            70,
            10,
            OmapValFlags::ENCRYPTED.bits() | OmapValFlags::SAVED.bits(),
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            555,
        )]));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let mut reader = Cursor::new(image);
        let value = omap
            .resolve(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Oid(70),
                Xid(10),
            )
            .unwrap()
            .unwrap();
        assert!(value.flags.contains(OmapValFlags::ENCRYPTED));
        assert!(value.flags.contains(OmapValFlags::SAVED));
        assert_eq!(value.paddr, Paddr(555));
    }
}
