//! Snapshot metadata.
//!
//! Snapshots are point-in-time, read-only views of a volume — local Time
//! Machine snapshots are a prime forensic artifact. Snapshot metadata lives
//! in `SNAP_METADATA` / `SNAP_NAME` records in the volume's snapshot-metadata
//! tree.
//!
//! Apple File System Reference, `12-snapshot-metadata.md`.

use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;

use crate::catalog::{Catalog, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::object::OBJ_PHYS_SIZE;
use crate::time::ApfsTimestamp;

/// Size of the fixed portion of `j_snap_metadata_val_t` (before `name`).
pub const J_SNAP_METADATA_VAL_SIZE: usize = 50;
/// Size of a `snap_meta_ext_t`.
pub const SNAP_META_EXT_SIZE: usize = 40;

bitflags! {
    /// Snapshot-metadata flags (`snap_meta_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SnapMetaFlags: u32 {
        /// The snapshot is pending conversion to dataless.
        const PENDING_DATALESS = 0x0000_0001;
        /// A merge of the snapshot is in progress.
        const MERGE_IN_PROGRESS = 0x0000_0002;
    }
}

/// A parsed snapshot of a volume (`j_snap_metadata` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// The snapshot's transaction identifier (its key's object id).
    pub xid: u64,
    /// Physical object id of the snapshot's volume superblock.
    pub sblock_oid: u64,
    /// Physical object id of the snapshot's extent-reference tree.
    pub extentref_tree_oid: u64,
    /// Snapshot creation time.
    pub create_time: ApfsTimestamp,
    /// Snapshot last-modified time.
    pub change_time: ApfsTimestamp,
    /// The `inum` field of the snapshot metadata.
    pub inum: u64,
    /// Snapshot flags.
    pub flags: SnapMetaFlags,
    /// The snapshot's name.
    pub name: String,
}

impl Snapshot {
    /// Enumerates every snapshot recorded in a volume's snapshot-metadata
    /// tree.
    ///
    /// `snap_meta_tree` is a [`Catalog`] built on the volume's
    /// `apfs_snap_meta_tree_oid`.
    ///
    /// # Errors
    ///
    /// Propagates tree-walk and parsing errors.
    pub fn list<T: Read + Seek>(snap_meta_tree: &Catalog, reader: &mut T) -> Result<Vec<Self>> {
        let mut snapshots = Vec::new();
        for record in snap_meta_tree.records_of_kind(reader, JObjType::SnapMetadata)? {
            snapshots.push(parse_snapshot(record.key_header.obj_id, &record.value)?);
        }
        Ok(snapshots)
    }
}

/// Parses a `j_snap_metadata_val_t` value into a [`Snapshot`].
fn parse_snapshot(xid: u64, value: &[u8]) -> Result<Snapshot> {
    if value.len() < J_SNAP_METADATA_VAL_SIZE {
        return Err(ApfsError::Truncated {
            structure: "j_snap_metadata_val_t",
            expected: J_SNAP_METADATA_VAL_SIZE,
            actual: value.len(),
        });
    }
    let u64_at = |off: usize| u64::from_le_bytes(value[off..off + 8].try_into().expect("8 bytes"));
    let name_len = usize::from(u16::from_le_bytes([value[48], value[49]]));
    let name_raw = value
        .get(J_SNAP_METADATA_VAL_SIZE..J_SNAP_METADATA_VAL_SIZE + name_len)
        .ok_or(ApfsError::Malformed {
            structure: "j_snap_metadata_val_t",
            reason: "snapshot name extends past the record",
        })?;
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Ok(Snapshot {
        xid,
        extentref_tree_oid: u64_at(0),
        sblock_oid: u64_at(8),
        create_time: ApfsTimestamp(u64_at(16)),
        change_time: ApfsTimestamp(u64_at(24)),
        inum: u64_at(32),
        flags: SnapMetaFlags::from_bits_retain(u32::from_le_bytes(
            value[44..48].try_into().expect("4 bytes"),
        )),
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
}

/// Looks up the transaction id of a snapshot by name, using the `SNAP_NAME`
/// records of the snapshot-metadata tree.
///
/// # Errors
///
/// Propagates tree-walk errors.
pub fn snapshot_xid_by_name<T: Read + Seek>(
    snap_meta_tree: &Catalog,
    reader: &mut T,
    name: &str,
) -> Result<Option<u64>> {
    for record in snap_meta_tree.records_of_kind(reader, JObjType::SnapName)? {
        // SNAP_NAME key: j_key_t, name_len (u16), name.
        let Some(len_bytes) = record.key.get(J_KEY_SIZE..J_KEY_SIZE + 2) else {
            continue;
        };
        let len = usize::from(u16::from_le_bytes([len_bytes[0], len_bytes[1]]));
        let Some(name_raw) = record.key.get(J_KEY_SIZE + 2..J_KEY_SIZE + 2 + len) else {
            continue;
        };
        let end = name_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_raw.len());
        if &name_raw[..end] == name.as_bytes() {
            let xid = record.value.get(0..8).ok_or(ApfsError::Truncated {
                structure: "j_snap_name_val_t",
                expected: 8,
                actual: record.value.len(),
            })?;
            return Ok(Some(u64::from_le_bytes(xid.try_into().expect("8 bytes"))));
        }
    }
    Ok(None)
}

/// Extended snapshot metadata (`snap_meta_ext_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapMetaExt {
    /// The structure's version.
    pub version: u32,
    /// Extended-metadata flags.
    pub flags: u32,
    /// The snapshot's transaction identifier.
    pub snap_xid: u64,
    /// The snapshot's UUID.
    pub uuid: [u8; 16],
    /// An opaque token associated with the snapshot.
    pub token: u64,
}

impl SnapMetaExt {
    /// Parses a bare `snap_meta_ext_t` (no leading `obj_phys_t` header).
    ///
    /// To parse a whole `snap_meta_ext_obj_phys_t` block, use
    /// [`SnapMetaExt::parse_object`] — the two cannot be told apart by length
    /// alone, so the caller must state which it holds.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short buffer.
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() < SNAP_META_EXT_SIZE {
            return Err(ApfsError::Truncated {
                structure: "snap_meta_ext_t",
                expected: SNAP_META_EXT_SIZE,
                actual: body.len(),
            });
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&body[16..32]);
        Ok(Self {
            version: u32::from_le_bytes(body[0..4].try_into().expect("4 bytes")),
            flags: u32::from_le_bytes(body[4..8].try_into().expect("4 bytes")),
            snap_xid: u64::from_le_bytes(body[8..16].try_into().expect("8 bytes")),
            uuid,
            token: u64::from_le_bytes(body[32..40].try_into().expect("8 bytes")),
        })
    }

    /// Parses a `snap_meta_ext_obj_phys_t` block — an `obj_phys_t` header
    /// followed by the `snap_meta_ext_t` body.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a buffer too short to hold the
    /// object header and the `snap_meta_ext_t`.
    pub fn parse_object(block: &[u8]) -> Result<Self> {
        let body = block.get(OBJ_PHYS_SIZE..).ok_or(ApfsError::Truncated {
            structure: "snap_meta_ext_obj_phys_t",
            expected: OBJ_PHYS_SIZE + SNAP_META_EXT_SIZE,
            actual: block.len(),
        })?;
        Self::parse(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::object::OBJ_PHYSICAL;
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use std::io::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn parses_a_snapshot_metadata_value() {
        let mut value = vec![0u8; J_SNAP_METADATA_VAL_SIZE];
        value[0..8].copy_from_slice(&111u64.to_le_bytes()); // extentref_tree_oid
        value[8..16].copy_from_slice(&222u64.to_le_bytes()); // sblock_oid
        value[16..24].copy_from_slice(&1_000u64.to_le_bytes()); // create_time
        value[44..48].copy_from_slice(&SnapMetaFlags::PENDING_DATALESS.bits().to_le_bytes());
        value[48..50].copy_from_slice(&5u16.to_le_bytes()); // name_len
        value.extend_from_slice(b"snap\0");
        let snap = parse_snapshot(2024, &value).unwrap();
        assert_eq!(snap.xid, 2024);
        assert_eq!(snap.sblock_oid, 222);
        assert_eq!(snap.extentref_tree_oid, 111);
        assert_eq!(snap.create_time, ApfsTimestamp(1_000));
        assert_eq!(snap.name, "snap");
        assert!(snap.flags.contains(SnapMetaFlags::PENDING_DATALESS));
    }

    #[test]
    fn snapshot_value_with_name_past_record_is_rejected() {
        let mut value = vec![0u8; J_SNAP_METADATA_VAL_SIZE];
        value[48..50].copy_from_slice(&80u16.to_le_bytes()); // claims 80-byte name
        assert!(matches!(
            parse_snapshot(1, &value),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn parses_snap_meta_ext() {
        let mut body = vec![0u8; SNAP_META_EXT_SIZE];
        body[0..4].copy_from_slice(&1u32.to_le_bytes());
        body[8..16].copy_from_slice(&777u64.to_le_bytes());
        body[16..32].copy_from_slice(&[0xAB; 16]);
        let ext = SnapMetaExt::parse(&body).unwrap();
        assert_eq!(ext.version, 1);
        assert_eq!(ext.snap_xid, 777);
        assert_eq!(ext.uuid, [0xAB; 16]);
    }

    #[test]
    fn snap_meta_ext_rejects_a_short_body() {
        // A body smaller than `SNAP_META_EXT_SIZE` (40) must fail truncation
        // checks — both the strict less-than and the equality boundary.
        assert!(matches!(
            SnapMetaExt::parse(&[0u8; 8]),
            Err(ApfsError::Truncated { .. })
        ));
        assert!(matches!(
            SnapMetaExt::parse(&[0u8; SNAP_META_EXT_SIZE - 1]),
            Err(ApfsError::Truncated { .. })
        ));
        // A body of exactly the expected size parses.
        assert!(SnapMetaExt::parse(&[0u8; SNAP_META_EXT_SIZE]).is_ok());
    }

    #[test]
    fn snap_meta_ext_parse_object_reports_full_expected_size() {
        // The error must declare the OBJ_PHYS header + body as the expected
        // length; an arithmetic typo (e.g. `*` for `+`) reports a wildly
        // different size and a downstream caller can no longer trust it.
        let err = SnapMetaExt::parse_object(&[0u8; 8]).unwrap_err();
        match err {
            ApfsError::Truncated {
                structure,
                expected,
                actual,
            } => {
                assert_eq!(structure, "snap_meta_ext_obj_phys_t");
                assert_eq!(expected, OBJ_PHYS_SIZE + SNAP_META_EXT_SIZE);
                assert_eq!(actual, 8);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_object_skips_exactly_one_object_header() {
        // A full block: obj_phys_t header, then the snap_meta_ext_t body.
        // `parse` on a header-stripped slice and `parse_object` on the whole
        // block must agree, with no second header strip.
        let mut block = vec![0u8; OBJ_PHYS_SIZE + SNAP_META_EXT_SIZE];
        block[OBJ_PHYS_SIZE..OBJ_PHYS_SIZE + 4].copy_from_slice(&2u32.to_le_bytes());
        block[OBJ_PHYS_SIZE + 8..OBJ_PHYS_SIZE + 16].copy_from_slice(&909u64.to_le_bytes());
        let ext = SnapMetaExt::parse_object(&block).unwrap();
        assert_eq!(ext.version, 2);
        assert_eq!(ext.snap_xid, 909);
        // The bare-struct parser, given the same body, agrees.
        assert_eq!(SnapMetaExt::parse(&block[OBJ_PHYS_SIZE..]).unwrap(), ext);
    }

    // --- Enumeration against a synthetic snapshot-metadata tree -----------

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

    fn snap_metadata_record(xid: u64, name: &str) -> (Vec<u8>, Vec<u8>) {
        let key = (((JObjType::SnapMetadata.as_value() as u64) << OBJ_TYPE_SHIFT) | xid)
            .to_le_bytes()
            .to_vec();
        let mut value = vec![0u8; J_SNAP_METADATA_VAL_SIZE];
        value[48..50].copy_from_slice(&(name.len() as u16 + 1).to_le_bytes());
        value.extend_from_slice(name.as_bytes());
        value.push(0);
        (key, value)
    }

    /// Builds a `SNAP_NAME` record. The key is `j_key_t` (8 bytes) followed by
    /// `name_len` (`u16`) and the null-terminated name; the value is the
    /// snapshot's 8-byte transaction id.
    fn snap_name_record(name: &str, xid: u64) -> (Vec<u8>, Vec<u8>) {
        let mut key = (((JObjType::SnapName.as_value() as u64) << OBJ_TYPE_SHIFT) | xid)
            .to_le_bytes()
            .to_vec();
        let name_len = name.len() as u16 + 1;
        key.extend_from_slice(&name_len.to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        let value = xid.to_le_bytes().to_vec();
        (key, value)
    }

    #[test]
    fn lists_volume_snapshots() {
        let leaf = catalog_leaf(&[
            snap_metadata_record(1000, "before-update"),
            snap_metadata_record(2000, "after-update"),
        ]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(300, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(Oid(300), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        let snaps = Snapshot::list(&tree, &mut reader).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].xid, 1000);
        assert_eq!(snaps[0].name, "before-update");
        assert_eq!(snaps[1].name, "after-update");
    }

    #[test]
    fn empty_tree_lists_no_snapshots() {
        let mut image = omap_phys(1);
        image.extend(omap_tree(300, 2));
        image.extend(catalog_leaf(&[]));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(Oid(300), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);
        assert!(Snapshot::list(&tree, &mut reader).unwrap().is_empty());
    }

    #[test]
    fn snapshot_xid_by_name_resolves_each_entry() {
        // Two SNAP_NAME records; both must round-trip through the by-name
        // lookup, and an absent name must report `None`. The xids are chosen
        // to be non-trivial (not 0 or 1) so a body that always returns
        // `Some(0)` or `Some(1)` is detected.
        let leaf = catalog_leaf(&[
            snap_name_record("before-update", 1000),
            snap_name_record("after-update", 2000),
        ]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(300, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(Oid(300), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        assert_eq!(
            snapshot_xid_by_name(&tree, &mut reader, "before-update").unwrap(),
            Some(1000),
        );
        assert_eq!(
            snapshot_xid_by_name(&tree, &mut reader, "after-update").unwrap(),
            Some(2000),
        );
        assert_eq!(
            snapshot_xid_by_name(&tree, &mut reader, "missing").unwrap(),
            None,
        );
    }

    #[test]
    fn snapshot_xid_by_name_matches_a_one_character_name() {
        // A one-character name keeps the SNAP_NAME key shorter than
        // 16 bytes (8 + 2 + 2 = 12) so an offset typo that widens the
        // length-prefix slice to `J_KEY_SIZE * 2` runs off the end of the
        // key and the lookup wrongly skips this record.
        let leaf = catalog_leaf(&[snap_name_record("a", 4_242)]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(300, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(Oid(300), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        assert_eq!(
            snapshot_xid_by_name(&tree, &mut reader, "a").unwrap(),
            Some(4_242),
        );
    }

    #[test]
    fn snapshot_xid_by_name_matches_an_unterminated_name() {
        // A name stored without a trailing null still matches — the parser
        // falls back to the full slice length. With the closure inverted
        // (`!=` instead of `==`), the first byte is treated as the
        // terminator, the comparison shrinks to an empty slice, and the
        // lookup returns `None`.
        let mut key = (((JObjType::SnapName.as_value() as u64) << OBJ_TYPE_SHIFT) | 5_555u64)
            .to_le_bytes()
            .to_vec();
        let name = b"unterm";
        key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        key.extend_from_slice(name);
        let value = 5_555u64.to_le_bytes().to_vec();

        let leaf = catalog_leaf(&[(key, value)]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(300, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let tree = Catalog::new(Oid(300), omap, BLK as u32, Xid(1));
        let mut reader = Cursor::new(image);

        assert_eq!(
            snapshot_xid_by_name(&tree, &mut reader, "unterm").unwrap(),
            Some(5_555),
        );
    }
}
