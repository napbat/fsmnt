//! Hard-link siblings (`j_sibling_link` / `j_sibling_map` records).
//!
//! A hard-linked file has one inode and several directory entries; APFS
//! records each link as a *sibling*. Sibling-link records find every link of
//! an inode; sibling-map records map a sibling identifier back to its inode.
//!
//! Apple File System Reference, `11-siblings.md`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::catalog::{Catalog, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};

/// One hard link of an inode (`j_sibling_link` record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingLink {
    /// The sibling's unique identifier.
    pub sibling_id: u64,
    /// Object identifier of the parent directory of this link.
    pub parent_id: u64,
    /// The link's name (UTF-8, without the trailing NUL).
    pub name: String,
}

impl SiblingLink {
    /// Lists every hard link of the inode `inode_id`.
    ///
    /// An inode with no sibling-link records has a single link; its name and
    /// parent come from its directory entry instead.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and parsing errors.
    pub fn list<T: Read + Seek>(
        catalog: &Catalog,
        reader: &mut T,
        inode_id: u64,
    ) -> Result<Vec<Self>> {
        let mut links = Vec::new();
        for record in catalog.records_for(reader, inode_id)? {
            if record.key_header.kind != JObjType::SiblingLink {
                continue;
            }
            links.push(parse_sibling_link(&record.key, &record.value)?);
        }
        Ok(links)
    }
}

/// Resolves a sibling identifier to the inode number of its underlying file
/// (`j_sibling_map` record).
///
/// # Errors
///
/// Propagates catalog-walk and parsing errors.
///
/// # Panics
///
/// Panics only if a catalog value slice returned for an exact eight-byte
/// range does not contain eight bytes.
pub fn resolve_sibling<T: Read + Seek>(
    catalog: &Catalog,
    reader: &mut T,
    sibling_id: u64,
) -> Result<Option<u64>> {
    let Some(value) = catalog.find_record(reader, sibling_id, JObjType::SiblingMap)? else {
        return Ok(None);
    };
    let file_id = value.get(0..8).ok_or(ApfsError::Truncated {
        structure: "j_sibling_map_val_t",
        expected: 8,
        actual: value.len(),
    })?;
    Ok(Some(u64::from_le_bytes(
        file_id.try_into().expect("8 bytes"),
    )))
}

/// Parses a `j_sibling_link` record into a [`SiblingLink`].
fn parse_sibling_link(key: &[u8], value: &[u8]) -> Result<SiblingLink> {
    let sibling_id = key
        .get(J_KEY_SIZE..J_KEY_SIZE + 8)
        .ok_or(ApfsError::Truncated {
            structure: "j_sibling_key_t",
            expected: J_KEY_SIZE + 8,
            actual: key.len(),
        })?;
    let sibling_id = u64::from_le_bytes(sibling_id.try_into().expect("8 bytes"));

    // Value: parent_id (u64), name_len (u16), name.
    let header = value.get(0..10).ok_or(ApfsError::Truncated {
        structure: "j_sibling_val_t",
        expected: 10,
        actual: value.len(),
    })?;
    let parent_id = u64::from_le_bytes(header[0..8].try_into().expect("8 bytes"));
    let name_len = usize::from(u16::from_le_bytes([header[8], header[9]]));
    let name_raw = value.get(10..10 + name_len).ok_or(ApfsError::Malformed {
        structure: "j_sibling_val_t",
        reason: "name extends past the record value",
    })?;
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    Ok(SiblingLink {
        sibling_id,
        parent_id,
        name: String::from_utf8_lossy(&name_raw[..name_end]).into_owned(),
    })
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
    fn parses_a_sibling_link() {
        let mut key = vec![0u8; J_KEY_SIZE];
        key.extend_from_slice(&501u64.to_le_bytes()); // sibling_id
        let mut value = Vec::new();
        value.extend_from_slice(&7u64.to_le_bytes()); // parent_id
        value.extend_from_slice(&6u16.to_le_bytes()); // name_len incl NUL
        value.extend_from_slice(b"link1\0");
        let link = parse_sibling_link(&key, &value).unwrap();
        assert_eq!(link.sibling_id, 501);
        assert_eq!(link.parent_id, 7);
        assert_eq!(link.name, "link1");
    }

    #[test]
    fn sibling_link_with_truncated_key_reports_expected_size() {
        // A key with only the J_KEY_SIZE header (no sibling_id suffix)
        // must be rejected as Truncated with `expected == J_KEY_SIZE + 8`.
        // Asserting the exact expected value catches mutations that
        // arithmetic-flip the constant (e.g. `+` → `-`/`*`).
        let key = vec![0u8; J_KEY_SIZE];
        let value = vec![0u8; 10];
        match parse_sibling_link(&key, &value) {
            Err(ApfsError::Truncated {
                expected, actual, ..
            }) => {
                assert_eq!(expected, J_KEY_SIZE + 8);
                assert_eq!(actual, J_KEY_SIZE);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn sibling_link_with_name_past_value_is_rejected() {
        let mut key = vec![0u8; J_KEY_SIZE + 8];
        key[J_KEY_SIZE..].copy_from_slice(&1u64.to_le_bytes());
        let mut value = Vec::new();
        value.extend_from_slice(&1u64.to_le_bytes());
        value.extend_from_slice(&50u16.to_le_bytes()); // claims a 50-byte name
        value.extend_from_slice(b"short");
        assert!(matches!(
            parse_sibling_link(&key, &value),
            Err(ApfsError::Malformed { .. })
        ));
    }

    // --- Enumeration and resolution against a synthetic catalog -----------

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

    fn key_for(obj_id: u64, kind: JObjType) -> Vec<u8> {
        ((u64::from(kind.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec()
    }

    fn link_record(inode: u64, sibling_id: u64, parent: u64, name: &str) -> (Vec<u8>, Vec<u8>) {
        let mut key = key_for(inode, JObjType::SiblingLink);
        key.extend_from_slice(&sibling_id.to_le_bytes());
        let mut value = Vec::new();
        value.extend_from_slice(&parent.to_le_bytes());
        value.extend_from_slice(
            &(u16::try_from(name.len()).expect("the test fixture value fits in u16") + 1)
                .to_le_bytes(),
        );
        value.extend_from_slice(name.as_bytes());
        value.push(0);
        (key, value)
    }

    fn map_record(sibling_id: u64, file_id: u64) -> (Vec<u8>, Vec<u8>) {
        (
            key_for(sibling_id, JObjType::SiblingMap),
            file_id.to_le_bytes().to_vec(),
        )
    }

    fn catalog(records: &[(Vec<u8>, Vec<u8>)]) -> (Catalog, Cursor<Vec<u8>>) {
        let mut image = omap_phys(1);
        image.extend(omap_tree(90, 2));
        image.extend(catalog_leaf(records));
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(90),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            Cursor::new(image),
        )
    }

    #[test]
    fn lists_every_hard_link_of_an_inode() {
        // Inode 30 has two hard links, with sibling ids 600 and 601.
        let (cat, mut reader) = catalog(&[
            link_record(30, 600, 2, "first"),
            link_record(30, 601, 9, "second"),
        ]);
        let links = SiblingLink::list(&cat, &mut reader, 30).unwrap();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].sibling_id, 600);
        assert_eq!(links[0].name, "first");
        assert_eq!(links[1].parent_id, 9);
    }

    #[test]
    fn a_file_with_no_siblings_lists_empty() {
        let (cat, mut reader) = catalog(&[link_record(30, 600, 2, "first")]);
        assert!(SiblingLink::list(&cat, &mut reader, 99).unwrap().is_empty());
    }

    #[test]
    fn resolves_a_sibling_id_to_its_inode() {
        let (cat, mut reader) = catalog(&[map_record(601, 30)]);
        assert_eq!(resolve_sibling(&cat, &mut reader, 601).unwrap(), Some(30));
        assert_eq!(resolve_sibling(&cat, &mut reader, 999).unwrap(), None);
    }
}
