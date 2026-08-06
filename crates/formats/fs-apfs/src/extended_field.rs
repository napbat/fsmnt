//! Extended fields (`xf_blob_t` / `x_field_t`).
//!
//! Inodes and directory records carry a variable trailing region of extended
//! fields — an [`xf_blob_t`](ExtendedFields) header followed by `x_field_t`
//! descriptors and eight-byte-aligned packed values. Extended fields hold the
//! file name, data-stream info, document id, sparse byte count, and more.
//!
//! Apple File System Reference, `10-extended-fields.md`.

use alloc::vec::Vec;

use bitflags::bitflags;

use crate::error::{ApfsError, Result};

/// Size of the `xf_blob_t` header (`xf_num_exts` + `xf_used_data`).
pub const XF_BLOB_HEADER_SIZE: usize = 4;
/// Size of an `x_field_t` descriptor.
pub const X_FIELD_SIZE: usize = 4;

// Inode extended-field types (`INO_EXT_TYPE_*`).
/// The transaction id of the snapshot the inode belongs to.
pub const INO_EXT_TYPE_SNAP_XID: u8 = 1;
/// The object id of the inode's delta tree.
pub const INO_EXT_TYPE_DELTA_TREE_OID: u8 = 2;
/// The inode's document id.
pub const INO_EXT_TYPE_DOCUMENT_ID: u8 = 3;
/// The inode's name (the primary link name).
pub const INO_EXT_TYPE_NAME: u8 = 4;
/// The inode's previous file size.
pub const INO_EXT_TYPE_PREV_FSIZE: u8 = 5;
/// The inode's Finder info.
pub const INO_EXT_TYPE_FINDER_INFO: u8 = 7;
/// The inode's data stream (`j_dstream_t`).
pub const INO_EXT_TYPE_DSTREAM: u8 = 8;
/// The directory-statistics key of the inode.
pub const INO_EXT_TYPE_DIR_STATS_KEY: u8 = 10;
/// The file-system UUID the inode belongs to.
pub const INO_EXT_TYPE_FS_UUID: u8 = 11;
/// The number of sparse bytes in the inode's data.
pub const INO_EXT_TYPE_SPARSE_BYTES: u8 = 13;
/// The device identifier of a device-node inode.
pub const INO_EXT_TYPE_RDEV: u8 = 14;
/// Purgeable-state flags of the inode.
pub const INO_EXT_TYPE_PURGEABLE_FLAGS: u8 = 15;
/// The inode's original sync-root id.
pub const INO_EXT_TYPE_ORIG_SYNC_ROOT_ID: u8 = 16;

/// Directory-record extended-field type: a sibling identifier
/// (`DREC_EXT_TYPE_SIBLING_ID`).
pub const DREC_EXT_TYPE_SIBLING_ID: u8 = 1;

bitflags! {
    /// Extended-field flags (`x_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct XfFlags: u8 {
        /// The field's data depends on the file's data and is invalidated
        /// when the file is modified.
        const DATA_DEPENDENT = 0x01;
        /// The field is not copied when the file is cloned.
        const DO_NOT_COPY = 0x02;
        /// Child files inherit this field.
        const CHILDREN_INHERIT = 0x08;
        /// The field was added by a user-space program.
        const USER_FIELD = 0x10;
        /// The field was added by the kernel.
        const SYSTEM_FIELD = 0x20;
    }
}

/// One parsed extended field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XField {
    /// The field's type (`x_type`) — interpret against `INO_EXT_TYPE_*` for
    /// an inode's fields or `DREC_EXT_TYPE_*` for a directory record's.
    pub field_type: u8,
    /// The field's flags.
    pub flags: XfFlags,
    /// The field's data value.
    pub data: Vec<u8>,
}

/// A parsed collection of extended fields (`xf_blob_t`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtendedFields {
    /// The fields, in stored order.
    pub fields: Vec<XField>,
}

/// Rounds `value` up to the next multiple of eight.
fn align8(value: usize) -> usize {
    value.wrapping_add(7) & !7
}

impl ExtendedFields {
    /// Parses an extended-fields region (the `xfields` of an inode or
    /// directory record).
    ///
    /// An empty region parses to an empty collection.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] or [`ApfsError::Malformed`] when the
    /// descriptors or values do not fit the region.
    pub fn parse(region: &[u8]) -> Result<Self> {
        if region.is_empty() {
            return Ok(Self::default());
        }
        if region.len() < XF_BLOB_HEADER_SIZE {
            return Err(ApfsError::Truncated {
                structure: "xf_blob_t",
                expected: XF_BLOB_HEADER_SIZE,
                actual: region.len(),
            });
        }
        let num_exts = usize::from(u16::from_le_bytes([region[0], region[1]]));
        let used_data = usize::from(u16::from_le_bytes([region[2], region[3]]));

        // `xf_used_data` bounds the descriptor table plus its packed values;
        // any bytes past it are trailing slack and must not be consumed as
        // field data, even when the region itself is longer.
        let blob_end = XF_BLOB_HEADER_SIZE
            .checked_add(used_data)
            .filter(|&end| end <= region.len())
            .ok_or(ApfsError::Malformed {
                structure: "xf_blob_t",
                reason: "xf_used_data exceeds the region",
            })?;
        let descriptors_end = XF_BLOB_HEADER_SIZE
            .checked_add(num_exts.saturating_mul(X_FIELD_SIZE))
            .filter(|&end| end <= blob_end)
            .ok_or(ApfsError::Malformed {
                structure: "xf_blob_t",
                reason: "extended-field descriptors exceed the region",
            })?;
        let data_region = &region[descriptors_end..blob_end];

        let mut fields = Vec::with_capacity(num_exts);
        let mut cursor = 0usize;
        for i in 0..num_exts {
            let desc = XF_BLOB_HEADER_SIZE + i * X_FIELD_SIZE;
            let field_type = region[desc];
            let flags = XfFlags::from_bits_retain(region[desc + 1]);
            let size = usize::from(u16::from_le_bytes([region[desc + 2], region[desc + 3]]));

            let value = data_region.get(cursor..cursor.saturating_add(size)).ok_or(
                ApfsError::Malformed {
                    structure: "x_field_t",
                    reason: "extended-field value extends past the region",
                },
            )?;
            fields.push(XField {
                field_type,
                flags,
                data: value.to_vec(),
            });
            // Values are aligned to eight-byte boundaries.
            cursor = cursor.saturating_add(align8(size));
        }
        Ok(Self { fields })
    }

    /// Returns the first field of type `field_type`, if present.
    #[must_use]
    pub fn field(&self, field_type: u8) -> Option<&XField> {
        self.fields.iter().find(|f| f.field_type == field_type)
    }

    /// The inode's name from its `INO_EXT_TYPE_NAME` field, if present.
    ///
    /// Used for hard-linked files, where the name of each link is stored as
    /// an extended field rather than only in the directory entry.
    #[must_use]
    pub fn inode_name(&self) -> Option<&[u8]> {
        self.field(INO_EXT_TYPE_NAME).map(|f| f.data.as_slice())
    }

    /// The inode's data-stream bytes from its `INO_EXT_TYPE_DSTREAM` field,
    /// if present (a `j_dstream_t`, parsed by the data-stream module).
    #[must_use]
    pub fn dstream(&self) -> Option<&[u8]> {
        self.field(INO_EXT_TYPE_DSTREAM).map(|f| f.data.as_slice())
    }

    /// The number of sparse (hole) bytes in the inode's data, from its
    /// `INO_EXT_TYPE_SPARSE_BYTES` field, if present.
    #[must_use]
    pub fn sparse_byte_count(&self) -> Option<u64> {
        let field = self.field(INO_EXT_TYPE_SPARSE_BYTES)?;
        let bytes: [u8; 8] = field.data.get(..8)?.try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an `xf_blob_t` region from `(type, flags, data)` fields,
    /// eight-byte-aligning each value as APFS does.
    fn blob(fields: &[(u8, u8, Vec<u8>)]) -> Vec<u8> {
        let mut region = Vec::new();
        region.extend_from_slice(
            &u16::try_from(fields.len())
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        let used: usize = fields.len() * X_FIELD_SIZE
            + fields
                .iter()
                .map(|(_, _, d)| align8(d.len()))
                .sum::<usize>();
        region.extend_from_slice(
            &u16::try_from(used)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        for (ty, flags, data) in fields {
            region.push(*ty);
            region.push(*flags);
            region.extend_from_slice(
                &u16::try_from(data.len())
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            );
        }
        for (_, _, data) in fields {
            region.extend_from_slice(data);
            region.resize(region.len() + (align8(data.len()) - data.len()), 0);
        }
        region
    }

    #[test]
    fn empty_region_parses_to_no_fields() {
        assert!(ExtendedFields::parse(&[]).unwrap().fields.is_empty());
    }

    #[test]
    fn parses_inode_name_and_dstream_fields() {
        let region = blob(&[
            (
                INO_EXT_TYPE_NAME,
                XfFlags::SYSTEM_FIELD.bits(),
                b"hello\0".to_vec(),
            ),
            (INO_EXT_TYPE_DSTREAM, 0, vec![0xAB; 40]),
        ]);
        let xf = ExtendedFields::parse(&region).unwrap();
        assert_eq!(xf.fields.len(), 2);
        assert_eq!(xf.inode_name(), Some(b"hello\0".as_slice()));
        assert_eq!(xf.dstream(), Some([0xAB; 40].as_slice()));
        assert!(xf.fields[0].flags.contains(XfFlags::SYSTEM_FIELD));
    }

    #[test]
    fn second_value_is_eight_byte_aligned() {
        // A 6-byte first value is padded to 8 before the second value.
        let region = blob(&[
            (INO_EXT_TYPE_DOCUMENT_ID, 0, vec![1, 2, 3, 4, 5, 6]),
            (INO_EXT_TYPE_SPARSE_BYTES, 0, vec![9, 9, 9, 9, 9, 9, 9, 9]),
        ]);
        let xf = ExtendedFields::parse(&region).unwrap();
        assert_eq!(
            xf.field(INO_EXT_TYPE_DOCUMENT_ID).unwrap().data,
            vec![1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            xf.field(INO_EXT_TYPE_SPARSE_BYTES).unwrap().data,
            vec![9; 8]
        );
    }

    #[test]
    fn drec_sibling_id_field_is_addressable() {
        let region = blob(&[(DREC_EXT_TYPE_SIBLING_ID, 0, 42u64.to_le_bytes().to_vec())]);
        let xf = ExtendedFields::parse(&region).unwrap();
        let field = xf.field(DREC_EXT_TYPE_SIBLING_ID).unwrap();
        assert_eq!(
            u64::from_le_bytes(field.data.clone().try_into().unwrap()),
            42
        );
    }

    #[test]
    fn descriptors_past_the_region_are_rejected() {
        // Header claims 10 fields but the region holds none.
        let region = [10u8, 0, 0, 0];
        assert!(matches!(
            ExtendedFields::parse(&region),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn value_past_the_region_is_rejected() {
        // One descriptor (xf_used_data 4, covering just the descriptor)
        // claiming a 200-byte value with no data behind it.
        let region = [1u8, 0, 4, 0, INO_EXT_TYPE_NAME, 0, 200, 0];
        assert!(matches!(
            ExtendedFields::parse(&region),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn sparse_byte_count_returns_the_stored_value() {
        // INO_EXT_TYPE_SPARSE_BYTES carries a little-endian u64; the helper
        // must return that exact value, distinguishing it from None/0/1.
        let region = blob(&[(
            INO_EXT_TYPE_SPARSE_BYTES,
            0,
            12_345u64.to_le_bytes().to_vec(),
        )]);
        let xf = ExtendedFields::parse(&region).unwrap();
        assert_eq!(xf.sparse_byte_count(), Some(12_345));
    }

    #[test]
    fn sparse_byte_count_is_none_when_the_field_is_absent() {
        // A blob without an INO_EXT_TYPE_SPARSE_BYTES field returns None,
        // not the default zero/one a constant-return mutant would produce.
        let region = blob(&[(INO_EXT_TYPE_DOCUMENT_ID, 0, vec![1, 2, 3, 4])]);
        let xf = ExtendedFields::parse(&region).unwrap();
        assert_eq!(xf.sparse_byte_count(), None);
    }

    #[test]
    fn trailing_slack_past_xf_used_data_is_not_consumed() {
        // A valid one-field blob followed by 8 bytes of slack. A descriptor
        // size reaching into the slack must be rejected, not silently read.
        let mut region = blob(&[(INO_EXT_TYPE_DOCUMENT_ID, 0, vec![1, 2, 3, 4])]);
        let blob_len = region.len();
        region.extend_from_slice(&[0xFF; 8]);
        // The blob still parses: only the declared `xf_used_data` is used.
        let xf = ExtendedFields::parse(&region).unwrap();
        assert_eq!(
            xf.field(INO_EXT_TYPE_DOCUMENT_ID).unwrap().data,
            vec![1, 2, 3, 4]
        );

        // Widen the field's declared size to reach into the slack region.
        region[6..8].copy_from_slice(
            &u16::try_from(blob_len)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        assert!(matches!(
            ExtendedFields::parse(&region),
            Err(ApfsError::Malformed { .. })
        ));
    }
}
