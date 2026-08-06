//! Extended attributes (`j_xattr_val_t`).
//!
//! APFS extended attributes are `XATTR` records in the catalog. A small value
//! is stored inline in the record; a large one is stored as its own data
//! stream. Xattrs hold forensically rich data — Finder info, the quarantine
//! attribute, the `com.apple.decmpfs` compression header.
//!
//! Apple File System Reference, `07-file-system-objects.md`,
//! `09-data-streams.md`.

use alloc::string::String;
use alloc::vec::Vec;

use bitflags::bitflags;

use crate::catalog::{Catalog, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::extent::{DataStream, File, J_DSTREAM_SIZE};
use crate::io::{Read, Seek};

/// Size of the fixed portion of `j_xattr_val_t` (`flags` + `xdata_len`).
pub const J_XATTR_VAL_HEADER_SIZE: usize = 4;
/// Size of a `j_xattr_dstream_t` (`xattr_obj_id` + `j_dstream_t`).
pub const J_XATTR_DSTREAM_SIZE: usize = 8 + J_DSTREAM_SIZE;

bitflags! {
    /// Extended-attribute record flags (`j_xattr_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XattrFlags: u16 {
        /// The value is stored in its own data stream.
        const DATA_STREAM = 0x0001;
        /// The value is embedded in the record.
        const DATA_EMBEDDED = 0x0002;
        /// The attribute is owned by the file system, not a user.
        const FILE_SYSTEM_OWNED = 0x0004;
    }
}

/// Where an extended attribute's value is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XattrValue {
    /// The value is embedded directly in the record.
    Embedded(Vec<u8>),
    /// The value is stored in a separate data stream.
    Stream {
        /// Object identifier of the data stream holding the value.
        xattr_obj_id: u64,
        /// The data stream's metadata.
        dstream: DataStream,
    },
}

/// A parsed extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xattr {
    /// The attribute's name (UTF-8, without the trailing NUL).
    pub name: String,
    /// The attribute record's flags.
    pub flags: XattrFlags,
    /// Where the attribute's value lives.
    pub value: XattrValue,
}

impl Xattr {
    /// Lists every extended attribute of the object `obj_id`.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and parsing errors.
    pub fn list<T: Read + Seek>(
        catalog: &Catalog,
        reader: &mut T,
        obj_id: u64,
    ) -> Result<Vec<Self>> {
        let mut xattrs = Vec::new();
        for record in catalog.records_for(reader, obj_id)? {
            if record.key_header.kind != JObjType::Xattr {
                continue;
            }
            xattrs.push(parse_xattr(&record.key, &record.value)?);
        }
        Ok(xattrs)
    }

    /// Reads the attribute's full value.
    ///
    /// An embedded value is returned directly; a data-stream-backed value is
    /// read through its file extents.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk and I/O errors.
    pub fn read<T: Read + Seek>(
        &self,
        catalog: &Catalog,
        reader: &mut T,
        block_size: u32,
    ) -> Result<Vec<u8>> {
        match &self.value {
            XattrValue::Embedded(bytes) => Ok(bytes.clone()),
            XattrValue::Stream {
                xattr_obj_id,
                dstream,
            } => {
                let file = File::open(catalog, reader, *xattr_obj_id, dstream.size)?;
                file.read_all(reader, block_size)
            }
        }
    }
}

/// Whether both the data-stream and embedded flags are set.
///
/// The two flag bits are disjoint (0x0001 and 0x0002), so combining them
/// with `|` or `^` yields the same 0x0003 mask — an equivalent mutant the
/// fixture-based tests cannot distinguish.
#[cfg_attr(test, mutants::skip)]
fn has_both_storage_flags(flags: XattrFlags) -> bool {
    flags.contains(XattrFlags::DATA_STREAM | XattrFlags::DATA_EMBEDDED)
}

/// Parses an `XATTR` record into an [`Xattr`].
pub(crate) fn parse_xattr(key: &[u8], value: &[u8]) -> Result<Xattr> {
    // Key: j_key_t header, then a 2-byte name length and the name.
    let name_len_bytes = key
        .get(J_KEY_SIZE..J_KEY_SIZE + 2)
        .ok_or(ApfsError::Truncated {
            structure: "j_xattr_key_t",
            expected: J_KEY_SIZE + 2,
            actual: key.len(),
        })?;
    let name_len = usize::from(u16::from_le_bytes([name_len_bytes[0], name_len_bytes[1]]));
    let name_raw =
        key.get(J_KEY_SIZE + 2..J_KEY_SIZE + 2 + name_len)
            .ok_or(ApfsError::Malformed {
                structure: "j_xattr_key_t",
                reason: "name extends past the record key",
            })?;
    let name_end = name_raw
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(name_raw.len());
    let name = String::from_utf8_lossy(&name_raw[..name_end]).into_owned();

    // Value: flags, xdata_len, then the embedded data or a j_xattr_dstream_t.
    if value.len() < J_XATTR_VAL_HEADER_SIZE {
        return Err(ApfsError::Truncated {
            structure: "j_xattr_val_t",
            expected: J_XATTR_VAL_HEADER_SIZE,
            actual: value.len(),
        });
    }
    let flags = XattrFlags::from_bits_retain(u16::from_le_bytes([value[0], value[1]]));
    let xdata_len = usize::from(u16::from_le_bytes([value[2], value[3]]));
    let xdata = &value[J_XATTR_VAL_HEADER_SIZE..];

    // DATA_STREAM and DATA_EMBEDDED are mutually exclusive; a record with
    // both set is invalid, not a stream that happens to also claim embedded.
    // The `|` mask is equivalent to `^` because the two bits are disjoint
    // (0x0001 and 0x0002); the test below isolates that one operator.
    if has_both_storage_flags(flags) {
        return Err(ApfsError::Malformed {
            structure: "j_xattr_val_t",
            reason: "both the data-stream and embedded flags are set",
        });
    }
    let parsed = if flags.contains(XattrFlags::DATA_STREAM) {
        let stream = xdata
            .get(..J_XATTR_DSTREAM_SIZE)
            .ok_or(ApfsError::Truncated {
                structure: "j_xattr_dstream_t",
                expected: J_XATTR_DSTREAM_SIZE,
                actual: xdata.len(),
            })?;
        let xattr_obj_id = u64::from_le_bytes(stream[0..8].try_into().expect("8 bytes"));
        let dstream = DataStream::parse(&stream[8..])?;
        XattrValue::Stream {
            xattr_obj_id,
            dstream,
        }
    } else if flags.contains(XattrFlags::DATA_EMBEDDED) {
        let data = xdata.get(..xdata_len).ok_or(ApfsError::Malformed {
            structure: "j_xattr_val_t",
            reason: "embedded value extends past the record",
        })?;
        XattrValue::Embedded(data.to_vec())
    } else {
        return Err(ApfsError::Malformed {
            structure: "j_xattr_val_t",
            reason: "neither the embedded nor the data-stream flag is set",
        });
    };

    Ok(Xattr {
        name,
        flags,
        value: parsed,
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
    use fsmnt_testkit::Cursor;

    const BLK: usize = 4096;

    #[test]
    fn parses_an_embedded_xattr() {
        let mut key = vec![0u8; J_KEY_SIZE];
        key.extend_from_slice(&12u16.to_le_bytes()); // name_len incl NUL
        key.extend_from_slice(b"com.apple.fi\0");
        let mut value = Vec::new();
        value.extend_from_slice(&XattrFlags::DATA_EMBEDDED.bits().to_le_bytes());
        value.extend_from_slice(&5u16.to_le_bytes()); // xdata_len
        value.extend_from_slice(b"hello");
        let xattr = parse_xattr(&key, &value).unwrap();
        assert_eq!(xattr.name, "com.apple.fi");
        assert_eq!(xattr.value, XattrValue::Embedded(b"hello".to_vec()));
    }

    #[test]
    fn parses_a_data_stream_xattr() {
        let mut key = vec![0u8; J_KEY_SIZE];
        key.extend_from_slice(&4u16.to_le_bytes());
        key.extend_from_slice(b"big\0");
        let mut value = Vec::new();
        value.extend_from_slice(&XattrFlags::DATA_STREAM.bits().to_le_bytes());
        value.extend_from_slice(&0u16.to_le_bytes());
        value.extend_from_slice(&909u64.to_le_bytes()); // xattr_obj_id
        let mut dstream = vec![0u8; J_DSTREAM_SIZE];
        dstream[0..8].copy_from_slice(&65536u64.to_le_bytes()); // size
        value.extend_from_slice(&dstream);
        let xattr = parse_xattr(&key, &value).unwrap();
        match xattr.value {
            XattrValue::Stream {
                xattr_obj_id,
                dstream,
            } => {
                assert_eq!(xattr_obj_id, 909);
                assert_eq!(dstream.size, 65536);
            }
            other @ XattrValue::Embedded(_) => {
                panic!("expected a Stream value, got {other:?}")
            }
        }
    }

    #[test]
    fn rejects_a_truncated_key_with_the_correct_expected_size() {
        // A key that does not even hold the 2-byte name length must surface
        // a Truncated error whose `expected` is exactly J_KEY_SIZE + 2,
        // ruling out the - / * arithmetic mutants on that expression.
        let short_key = vec![0u8; J_KEY_SIZE]; // missing the 2 name-length bytes
        let value = {
            let mut v = Vec::new();
            v.extend_from_slice(&XattrFlags::DATA_EMBEDDED.bits().to_le_bytes());
            v.extend_from_slice(&0u16.to_le_bytes());
            v
        };
        let err = parse_xattr(&short_key, &value).unwrap_err();
        match err {
            ApfsError::Truncated {
                structure,
                expected,
                actual,
            } => {
                assert_eq!(structure, "j_xattr_key_t");
                assert_eq!(expected, J_KEY_SIZE + 2);
                assert_eq!(actual, J_KEY_SIZE);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_value_with_no_storage_flag() {
        let key = {
            let mut k = vec![0u8; J_KEY_SIZE];
            k.extend_from_slice(&2u16.to_le_bytes());
            k.extend_from_slice(b"x\0");
            k
        };
        let value = vec![0u8; J_XATTR_VAL_HEADER_SIZE]; // flags = 0
        assert!(matches!(
            parse_xattr(&key, &value),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_a_value_with_both_storage_flags() {
        let key = {
            let mut k = vec![0u8; J_KEY_SIZE];
            k.extend_from_slice(&2u16.to_le_bytes());
            k.extend_from_slice(b"x\0");
            k
        };
        let mut value = Vec::new();
        value.extend_from_slice(
            &(XattrFlags::DATA_STREAM | XattrFlags::DATA_EMBEDDED)
                .bits()
                .to_le_bytes(),
        );
        value.extend_from_slice(&0u16.to_le_bytes());
        assert!(matches!(
            parse_xattr(&key, &value),
            Err(ApfsError::Malformed { .. })
        ));
    }

    // --- Enumeration against a synthetic catalog --------------------------

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

    fn xattr_key(obj_id: u64, name: &str) -> Vec<u8> {
        let mut k = ((u64::from(JObjType::Xattr.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        let bytes = name.as_bytes();
        k.extend_from_slice(
            &(u16::try_from(bytes.len()).expect("the test fixture value fits in u16") + 1)
                .to_le_bytes(),
        );
        k.extend_from_slice(bytes);
        k.push(0);
        k
    }

    fn embedded_value(data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&XattrFlags::DATA_EMBEDDED.bits().to_le_bytes());
        v.extend_from_slice(
            &u16::try_from(data.len())
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        v.extend_from_slice(data);
        v
    }

    #[test]
    fn lists_and_reads_inode_xattrs() {
        let leaf = catalog_leaf(&[
            (
                xattr_key(8, "com.apple.quarantine"),
                embedded_value(b"q-data"),
            ),
            (
                xattr_key(8, "com.apple.FinderInfo"),
                embedded_value(&[0u8; 32]),
            ),
        ]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(80, 2));
        image.extend(leaf);
        let omap = Omap::parse(&image[..BLK]).unwrap();
        let catalog = Catalog::new(
            Oid(80),
            omap,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
            Xid(1),
        );
        let mut reader = Cursor::new(image);

        let xattrs = Xattr::list(&catalog, &mut reader, 8).unwrap();
        assert_eq!(xattrs.len(), 2);
        assert_eq!(xattrs[0].name, "com.apple.quarantine");
        let data = xattrs[0]
            .read(
                &catalog,
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
            )
            .unwrap();
        assert_eq!(data, b"q-data");
    }
}
