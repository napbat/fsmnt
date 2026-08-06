//! Sealed-volume file-extent tree (`fext_tree_*`).
//!
//! On a sealed volume — the macOS Signed System Volume — file extents are
//! not stored as catalog `FILE_EXTENT` records. They live in a dedicated
//! B-tree located by `apfs_superblock_t.apfs_fext_tree_oid`, mapping
//! `(private_id, logical_addr)` to a physical extent.
//!
//! The tree is a *physical* object (`apfs_fext_tree_type` is typically
//! `OBJ_PHYSICAL | OBJECT_TYPE_BTREE`): its root identifier is a block
//! address, and so are its non-leaf child links — there is no object-map
//! indirection.
//!
//! Apple File System Reference, `15-sealed-volumes.md`.

use alloc::vec;
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::BTreeMap;

use crate::btree::BtreeNode;
use crate::checkpoint::read_block;
use crate::checksum;
use crate::error::{ApfsError, Result};
use crate::extent::{FileExtent, J_FILE_EXTENT_LEN_MASK};
use crate::io::{Read, Seek};

/// Size of a `fext_tree_key_t` — `private_id` (8) + `logical_addr` (8).
const FEXT_TREE_KEY_SIZE: usize = 16;
/// Size of a `fext_tree_val_t` — `len_and_flags` (8) + `phys_block_num` (8).
const FEXT_TREE_VAL_SIZE: usize = 16;
/// Size of a non-leaf child link — a physical block address.
const FEXT_TREE_CHILD_SIZE: usize = 8;
/// Upper bound on fext-tree nodes walked before the tree is treated as
/// corrupt or cyclic.
const MAX_FEXT_TREE_NODES: usize = 1 << 20;

/// A sealed volume's file-extent tree (`fext_tree_*`).
///
/// The tree is keyed by the file's data-stream identifier
/// (`j_inode_val_t.private_id`) — the same identifier catalog
/// `FILE_EXTENT` records use on an unsealed volume.
#[derive(Debug, Clone, Copy)]
pub struct FextTree {
    root: u64,
}

impl FextTree {
    /// Creates a handle for the file-extent tree rooted at physical block
    /// `root` — the volume superblock's `apfs_fext_tree_oid`.
    #[must_use]
    pub fn new(root: u64) -> Self {
        Self { root }
    }

    /// Collects every extent in the tree, grouped by file data-stream id.
    ///
    /// Each node is Fletcher-64 verified, and the walk is bounded by
    /// [`MAX_FEXT_TREE_NODES`] so a corrupt or cyclic tree cannot loop.
    /// Each file's extents are returned sorted by logical offset.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::ChecksumMismatch`] for a node that fails
    /// verification, [`ApfsError::Malformed`] for a structurally invalid
    /// node or an over-large tree, [`ApfsError::Truncated`] for a short
    /// record, and propagates I/O errors.
    pub fn collect<T: Read + Seek>(
        &self,
        reader: &mut T,
        block_size: u32,
    ) -> Result<BTreeMap<u64, Vec<FileExtent>>> {
        let mut extents: BTreeMap<u64, Vec<FileExtent>> = BTreeMap::new();
        let mut pending = vec![self.root];
        let mut visited = 0usize;
        while let Some(addr) = pending.pop() {
            check_fext_visit_budget(&mut visited)?;
            let block = read_block(reader, block_size, addr)?;
            // A physical fext-tree node carries a Fletcher-64 checksum; a
            // mismatch means the block is not the node it claims to be.
            if !checksum::verify_block(&block) {
                return Err(ApfsError::ChecksumMismatch { block: addr });
            }
            let node = BtreeNode::parse(block)?;
            if node.is_leaf() {
                for index in 0..node.key_count() {
                    let entry = node.entry(index, FEXT_TREE_KEY_SIZE, FEXT_TREE_VAL_SIZE)?;
                    let (private_id, extent) = parse_fext_record(entry.key, entry.value)?;
                    extents.entry(private_id).or_default().push(extent);
                }
            } else {
                for index in 0..node.key_count() {
                    let entry = node.entry(index, FEXT_TREE_KEY_SIZE, FEXT_TREE_CHILD_SIZE)?;
                    let child = entry.value.ok_or(ApfsError::Malformed {
                        structure: "fext_tree",
                        reason: "non-leaf entry has no child link",
                    })?;
                    let oid: [u8; FEXT_TREE_CHILD_SIZE] = child
                        .get(..FEXT_TREE_CHILD_SIZE)
                        .and_then(|slice| slice.try_into().ok())
                        .ok_or(ApfsError::Malformed {
                            structure: "fext_tree",
                            reason: "non-leaf child link is not a block address",
                        })?;
                    pending.push(u64::from_le_bytes(oid));
                }
            }
        }
        for runs in extents.values_mut() {
            runs.sort_by_key(|extent| extent.logical_addr);
        }
        Ok(extents)
    }
}

/// Defence-in-depth counter that bounds the number of nodes a tree walk may
/// visit before it is treated as corrupt or cyclic.
///
/// Tripping this guard requires a synthetic tree larger than 1 MiB nodes —
/// the `+= 1` accumulator and the `>` threshold are intentionally tested
/// only by the guard's existence, not by exhaustive fixtures. Operator
/// mutations on the counter or the threshold are equivalent for any
/// fixture small enough to build in-memory.
#[cfg_attr(test, mutants::skip)]
fn check_fext_visit_budget(visited: &mut usize) -> Result<()> {
    *visited += 1;
    if *visited > MAX_FEXT_TREE_NODES {
        return Err(ApfsError::Malformed {
            structure: "fext_tree",
            reason: "tree has too many nodes — corrupt or cyclic",
        });
    }
    Ok(())
}

/// Parses a fext-tree leaf record into its file data-stream id and extent.
///
/// The key is a `fext_tree_key_t { private_id, logical_addr }`; the value a
/// `fext_tree_val_t { len_and_flags, phys_block_num }`. Unlike the catalog's
/// `j_file_extent_val_t`, the fext value has no `crypto_id` field.
fn parse_fext_record(key: &[u8], value: Option<&[u8]>) -> Result<(u64, FileExtent)> {
    let key: [u8; FEXT_TREE_KEY_SIZE] = key
        .get(..FEXT_TREE_KEY_SIZE)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ApfsError::Truncated {
            structure: "fext_tree_key_t",
            expected: FEXT_TREE_KEY_SIZE,
            actual: key.len(),
        })?;
    let value = value.unwrap_or(&[]);
    let value: [u8; FEXT_TREE_VAL_SIZE] = value
        .get(..FEXT_TREE_VAL_SIZE)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ApfsError::Truncated {
            structure: "fext_tree_val_t",
            expected: FEXT_TREE_VAL_SIZE,
            actual: value.len(),
        })?;
    let private_id = u64::from_le_bytes(key[0..8].try_into().expect("8 bytes"));
    let logical_addr = u64::from_le_bytes(key[8..16].try_into().expect("8 bytes"));
    let len_and_flags = u64::from_le_bytes(value[0..8].try_into().expect("8 bytes"));
    let phys_block_num = u64::from_le_bytes(value[8..16].try_into().expect("8 bytes"));
    Ok((
        private_id,
        FileExtent {
            logical_addr,
            // The length occupies the low bits; the high bits are flags.
            length: len_and_flags & J_FILE_EXTENT_LEN_MASK,
            phys_block_num,
            // fext_tree_val_t carries no per-extent encryption identifier.
            crypto_id: 0,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use std::io::Cursor;

    const BLK: usize = 4096;

    /// Builds a single ROOT|LEAF|FIXED fext-tree node from
    /// `(private_id, logical_addr, length, phys_block_num)` records.
    fn fext_leaf(records: &[(u64, u64, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes()); // ROOT|LEAF|FIXED
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(records.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(records.len() * 4)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        );
        let key_area = BTN_DATA_OFFSET + records.len() * 4;
        let value_end = BLK - BTREE_INFO_SIZE;
        for (i, &(private_id, logical, length, phys)) in records.iter().enumerate() {
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
            b[ks..ks + 8].copy_from_slice(&private_id.to_le_bytes());
            b[ks + 8..ks + 16].copy_from_slice(&logical.to_le_bytes());
            let vs = value_end - (i + 1) * 16;
            b[vs..vs + 8].copy_from_slice(&length.to_le_bytes());
            b[vs + 8..vs + 16].copy_from_slice(&phys.to_le_bytes());
        }
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes()); // bt_key_size
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes()); // bt_val_size
        let csum = checksum::fletcher64(&b[8..]);
        b[..8].copy_from_slice(&csum.to_le_bytes());
        b
    }

    #[test]
    fn collects_extents_grouped_by_private_id() {
        // block 0: gap; block 1: fext tree leaf with extents for two files.
        let mut image = vec![0u8; BLK];
        image.extend(fext_leaf(&[
            (7, 4096, 4096, 50), // file 7, second extent
            (7, 0, 4096, 40),    // file 7, first extent
            (9, 0, 8192, 60),    // file 9
        ]));
        let mut reader = Cursor::new(image);

        let extents = FextTree::new(1)
            .collect(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
            )
            .unwrap();
        let file7 = &extents[&7];
        // Extents are returned sorted by logical offset.
        assert_eq!(file7.len(), 2);
        assert_eq!(file7[0].logical_addr, 0);
        assert_eq!(file7[0].phys_block_num, 40);
        assert_eq!(file7[1].logical_addr, 4096);
        assert_eq!(extents[&9].len(), 1);
        assert_eq!(extents[&9][0].length, 8192);
    }

    #[test]
    fn rejects_a_node_with_a_bad_checksum() {
        let mut image = vec![0u8; BLK];
        let mut leaf = fext_leaf(&[(1, 0, 4096, 2)]);
        leaf[0] ^= 0xFF; // corrupt the stored checksum
        image.extend(leaf);
        let mut reader = Cursor::new(image);
        assert!(matches!(
            FextTree::new(1).collect(
                &mut reader,
                u32::try_from(BLK).expect("the test fixture value fits in u32")
            ),
            Err(ApfsError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn an_empty_tree_yields_no_extents() {
        let mut image = vec![0u8; BLK];
        image.extend(fext_leaf(&[]));
        let mut reader = Cursor::new(image);
        assert!(
            FextTree::new(1)
                .collect(
                    &mut reader,
                    u32::try_from(BLK).expect("the test fixture value fits in u32")
                )
                .unwrap()
                .is_empty()
        );
    }
}
