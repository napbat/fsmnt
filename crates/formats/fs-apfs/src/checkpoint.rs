//! The checkpoint descriptor area and latest-valid-checkpoint selection.
//!
//! The block-zero container superblock only locates the checkpoints; the
//! authoritative container state is the most recent *valid* checkpoint in the
//! checkpoint descriptor area. This module scans that ring, verifies
//! checksums, and resolves ephemeral object identifiers through the chosen
//! checkpoint.
//!
//! Apple File System Reference, `04-container.md`.

use alloc::vec;
use alloc::vec::Vec;

use zerocopy::{FromBytes, I64, Immutable, KnownLayout, LittleEndian as LE, U32, U64, Unaligned};

use crate::btree::BtreeNode;
use crate::checksum;
use crate::container::NxSuperblock;
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek, SeekFrom};
use crate::object::{OBJ_PHYS_SIZE, ObjPhys};
use crate::types::{ObjectType, Oid, Paddr};

/// Flag marking the last checkpoint-mapping block of a checkpoint
/// (`CHECKPOINT_MAP_LAST`).
pub const CHECKPOINT_MAP_LAST: u32 = 0x0000_0001;

/// Bit of `nx_xp_desc_blocks` indicating the descriptor area is a tree.
const XP_AREA_TREE_FLAG: u32 = 0x8000_0000;

/// Fixed key size of the checkpoint descriptor tree — a `u64` block offset.
const DESC_TREE_KEY_SIZE: usize = 8;
/// Size of a non-leaf descriptor-tree value — a child object identifier.
const DESC_TREE_CHILD_SIZE: usize = 8;
/// Size of a `prange_t` (a descriptor-tree leaf value).
const PRANGE_SIZE: usize = 16;
/// Upper bound on descriptor-tree nodes visited, guarding against a cyclic
/// or corrupt tree.
const MAX_DESC_TREE_NODES: usize = 4096;

/// On-disk `checkpoint_mapping_t` (40 bytes).
#[allow(
    clippy::struct_field_names,
    reason = "the cpm_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawCheckpointMapping {
    cpm_type: U32<LE>,
    cpm_subtype: U32<LE>,
    cpm_size: U32<LE>,
    cpm_pad: U32<LE>,
    cpm_fs_oid: U64<LE>,
    cpm_oid: U64<LE>,
    cpm_paddr: I64<LE>,
}

/// Size of a `checkpoint_mapping_t`.
const CHECKPOINT_MAPPING_SIZE: usize = core::mem::size_of::<RawCheckpointMapping>();

/// On-disk `checkpoint_map_phys_t` fixed header (`obj_phys_t` + flags + count).
#[allow(
    clippy::struct_field_names,
    reason = "the cpm_ prefixes preserve the names in Apple's APFS on-disk specification"
)]
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawCheckpointMapHeader {
    cpm_o: [u8; OBJ_PHYS_SIZE],
    cpm_flags: U32<LE>,
    cpm_count: U32<LE>,
}

/// Size of the fixed `checkpoint_map_phys_t` header before `cpm_map[]`.
const CHECKPOINT_MAP_HEADER_SIZE: usize = core::mem::size_of::<RawCheckpointMapHeader>();

/// A mapping from an ephemeral object identifier to its physical address in
/// the checkpoint data area (`checkpoint_mapping_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointMapping {
    /// The object's type field (`o_type` semantics).
    pub obj_type: u32,
    /// The object's subtype.
    pub subtype: u32,
    /// Size of the object in bytes.
    pub size: u32,
    /// Object id of the volume the object belongs to, if any.
    pub fs_oid: Oid,
    /// The ephemeral object identifier.
    pub oid: Oid,
    /// Address of the object in the checkpoint data area.
    pub paddr: Paddr,
}

/// A parsed checkpoint-mapping block (`checkpoint_map_phys_t`).
#[derive(Debug, Clone)]
pub struct CheckpointMapPhys {
    /// Checkpoint-map flags.
    pub flags: u32,
    /// The block's mappings.
    pub mappings: Vec<CheckpointMapping>,
}

impl CheckpointMapPhys {
    /// Whether this is the last mapping block of its checkpoint.
    #[must_use]
    pub fn is_last(&self) -> bool {
        self.flags & CHECKPOINT_MAP_LAST != 0
    }

    /// Parses a checkpoint-mapping block from a block buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] or [`ApfsError::Malformed`] when the
    /// block is too small for its declared mapping count.
    pub fn parse(block: &[u8]) -> Result<Self> {
        let header = RawCheckpointMapHeader::ref_from_prefix(block)
            .map(|(header, _rest)| header)
            .map_err(|_| ApfsError::Truncated {
                structure: "checkpoint_map_phys_t",
                expected: CHECKPOINT_MAP_HEADER_SIZE,
                actual: block.len(),
            })?;
        let flags = header.cpm_flags.get();
        let count = header.cpm_count.get() as usize;

        let needed = CHECKPOINT_MAP_HEADER_SIZE
            .saturating_add(count.saturating_mul(CHECKPOINT_MAPPING_SIZE));
        if needed > block.len() {
            return Err(ApfsError::Malformed {
                structure: "checkpoint_map_phys_t",
                reason: "mapping count exceeds the block",
            });
        }

        let mut mappings = Vec::with_capacity(count);
        for i in 0..count {
            let start = CHECKPOINT_MAP_HEADER_SIZE + i * CHECKPOINT_MAPPING_SIZE;
            let raw = RawCheckpointMapping::ref_from_bytes(
                &block[start..start + CHECKPOINT_MAPPING_SIZE],
            )
            .map_err(|_| ApfsError::Malformed {
                structure: "checkpoint_mapping_t",
                reason: "mapping did not parse",
            })?;
            mappings.push(CheckpointMapping {
                obj_type: raw.cpm_type.get(),
                subtype: raw.cpm_subtype.get(),
                size: raw.cpm_size.get(),
                fs_oid: Oid(raw.cpm_fs_oid.get()),
                oid: Oid(raw.cpm_oid.get()),
                paddr: Paddr(raw.cpm_paddr.get()),
            });
        }
        Ok(Self { flags, mappings })
    }
}

/// The latest valid checkpoint of a container.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// The checkpoint's container superblock.
    pub superblock: NxSuperblock,
    /// Every ephemeral-object mapping of the checkpoint, in ring order.
    pub mappings: Vec<CheckpointMapping>,
}

impl Checkpoint {
    /// Resolves an ephemeral object identifier to its address in the
    /// checkpoint data area.
    #[must_use]
    pub fn resolve_ephemeral(&self, oid: Oid) -> Option<Paddr> {
        self.mappings
            .iter()
            .find(|mapping| mapping.oid == oid)
            .map(|mapping| mapping.paddr)
    }
}

/// Reads block `addr` of a container into an owned buffer.
///
/// # Errors
///
/// Propagates I/O errors, or returns [`ApfsError::Malformed`] if the block
/// offset overflows.
pub fn read_block<R: Read + Seek>(reader: &mut R, block_size: u32, addr: u64) -> Result<Vec<u8>> {
    let offset = addr
        .checked_mul(u64::from(block_size))
        .ok_or(ApfsError::Malformed {
            structure: "container",
            reason: "block address overflows the device",
        })?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; block_size as usize];
    reader.read_exact(&mut buf)?;
    Ok(buf)
}

/// One fragment of a tree-stored checkpoint descriptor area: a run of
/// descriptor-area block offsets mapped to a contiguous physical range —
/// the key and `prange_t` value of one descriptor-tree leaf entry.
#[derive(Debug, Clone, Copy)]
struct DescFragment {
    /// First descriptor-area block offset the fragment covers.
    start_index: u64,
    /// Physical block address that `start_index` maps to.
    phys_addr: u64,
    /// Number of consecutive blocks in the fragment.
    block_count: u64,
}

/// How the checkpoint descriptor area is laid out on disk.
enum DescriptorArea {
    /// A contiguous run of blocks starting at `base` — the fast path.
    Contiguous {
        /// Physical address of descriptor-area block offset zero.
        base: u64,
    },
    /// A B-tree-mapped area: descriptor offsets resolve through the
    /// fragments, which are sorted by `start_index`.
    Fragmented {
        /// The descriptor-tree leaf fragments.
        fragments: Vec<DescFragment>,
    },
}

impl DescriptorArea {
    /// The physical block address of descriptor-area block offset `index`,
    /// or `None` when `index` is not mapped.
    fn block_addr(&self, index: u64) -> Option<u64> {
        match self {
            Self::Contiguous { base } => base.checked_add(index),
            Self::Fragmented { fragments } => fragments.iter().find_map(|fragment| {
                let offset = index.checked_sub(fragment.start_index)?;
                (offset < fragment.block_count).then(|| fragment.phys_addr.checked_add(offset))?
            }),
        }
    }
}

/// Parses a descriptor-tree leaf entry into a [`DescFragment`].
///
/// The key is a `u64` descriptor-area block offset; the value is a
/// `prange_t` (Apple File System Reference, `04-container.md`,
/// `nx_xp_desc_base`).
fn parse_desc_fragment(entry: &crate::btree::Entry<'_>) -> Result<DescFragment> {
    let key: [u8; 8] = entry
        .key
        .get(..DESC_TREE_KEY_SIZE)
        .and_then(|s| s.try_into().ok())
        .ok_or(ApfsError::Malformed {
            structure: "checkpoint descriptor tree",
            reason: "leaf key is not a u64 block offset",
        })?;
    let value = entry.value.ok_or(ApfsError::Malformed {
        structure: "checkpoint descriptor tree",
        reason: "leaf entry has no prange value",
    })?;
    let prange = value.get(..PRANGE_SIZE).ok_or(ApfsError::Malformed {
        structure: "checkpoint descriptor tree",
        reason: "leaf value is shorter than a prange_t",
    })?;
    let start_addr = i64::from_le_bytes(prange[..8].try_into().expect("8 bytes"));
    let block_count = u64::from_le_bytes(prange[8..16].try_into().expect("8 bytes"));
    let phys_addr = u64::try_from(start_addr).map_err(|_| ApfsError::Malformed {
        structure: "checkpoint descriptor tree",
        reason: "fragment physical address is negative",
    })?;
    Ok(DescFragment {
        start_index: u64::from_le_bytes(key),
        phys_addr,
        block_count,
    })
}

/// Strips the descriptor-area tree flag from `nx_xp_desc_blocks` and
/// returns the actual ring length.
///
/// Extracted so the mask mutants (`& → |/^` and deleting the `!`) can be
/// suppressed without hiding the rest of `latest_checkpoint`: a wrong mask
/// inflates the ring length to ~2^31 blocks, scanning which would take
/// minutes per call and is otherwise only caught by the 20s test cap.
#[cfg_attr(test, mutants::skip)]
#[inline]
fn descriptor_ring_length(desc_blocks: u32) -> u64 {
    u64::from(desc_blocks & !XP_AREA_TREE_FLAG)
}

/// Increments `visited` and enforces the [`MAX_DESC_TREE_NODES`] cap.
///
/// Extracted so the safety-cap mutants — `+= → *=` and the bound predicate
/// — can be suppressed without hiding the rest of `read_descriptor_tree`:
/// distinguishing them would require a 4097-node cyclic-tree fixture, which
/// is far outside the cost envelope of a unit test.
#[cfg_attr(test, mutants::skip)]
fn advance_descriptor_visit(visited: &mut usize) -> Result<()> {
    *visited += 1;
    if *visited > MAX_DESC_TREE_NODES {
        return Err(ApfsError::Malformed {
            structure: "checkpoint descriptor tree",
            reason: "tree has too many nodes — corrupt or cyclic",
        });
    }
    Ok(())
}

/// Builds a [`DescriptorArea`] from a B-tree-stored descriptor area whose
/// root physical object is at `root_addr`.
///
/// Every node is checksum-verified; traversal is bounded by
/// [`MAX_DESC_TREE_NODES`] so a cyclic or corrupt tree cannot loop.
fn read_descriptor_tree<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    root_addr: u64,
) -> Result<DescriptorArea> {
    let mut fragments = Vec::new();
    let mut pending = vec![root_addr];
    let mut visited = 0usize;
    while let Some(addr) = pending.pop() {
        advance_descriptor_visit(&mut visited)?;
        let block = read_block(reader, block_size, addr)?;
        if !checksum::verify_block(&block) {
            return Err(ApfsError::ChecksumMismatch { block: addr });
        }
        let node = BtreeNode::parse(block)?;
        if node.is_leaf() {
            for i in 0..node.key_count() {
                let entry = node.entry(i, DESC_TREE_KEY_SIZE, PRANGE_SIZE)?;
                fragments.push(parse_desc_fragment(&entry)?);
            }
        } else {
            for i in 0..node.key_count() {
                let entry = node.entry(i, DESC_TREE_KEY_SIZE, DESC_TREE_CHILD_SIZE)?;
                let child = entry.value.ok_or(ApfsError::Malformed {
                    structure: "checkpoint descriptor tree",
                    reason: "non-leaf entry has no child pointer",
                })?;
                let oid: [u8; 8] = child
                    .get(..DESC_TREE_CHILD_SIZE)
                    .and_then(|s| s.try_into().ok())
                    .ok_or(ApfsError::Malformed {
                        structure: "checkpoint descriptor tree",
                        reason: "non-leaf child pointer is not an object id",
                    })?;
                pending.push(u64::from_le_bytes(oid));
            }
        }
    }
    fragments.sort_by_key(|fragment| fragment.start_index);
    Ok(DescriptorArea::Fragmented { fragments })
}

/// Scans the checkpoint descriptor area and returns the latest valid
/// checkpoint.
///
/// `block_zero` is the container superblock read from block zero, used only to
/// locate the descriptor area. The area is contiguous on the fast path; when
/// the high bit of `nx_xp_desc_blocks` is set it is a B-tree, walked by
/// `read_descriptor_tree`. Each candidate superblock and each of its
/// checkpoint-mapping blocks must pass Fletcher-64 verification; superblocks
/// are tried in descending transaction order until one whose mapping blocks
/// all verify is found.
///
/// # Errors
///
/// Returns [`ApfsError::NotFound`] when no checkpoint fully verifies, and
/// [`ApfsError::Malformed`] or [`ApfsError::ChecksumMismatch`] for a corrupt
/// descriptor tree.
pub fn latest_checkpoint<R: Read + Seek>(
    reader: &mut R,
    block_zero: &NxSuperblock,
) -> Result<Checkpoint> {
    let block_size = block_zero.block_size;
    let desc = block_zero.xp_desc;

    let base = desc.base.as_block().ok_or(ApfsError::Malformed {
        structure: "nx_superblock_t",
        reason: "checkpoint descriptor base is not a valid address",
    })?;
    // The high bit of nx_xp_desc_blocks is a flag, not part of the count.
    let ring_len = descriptor_ring_length(desc.blocks);
    if ring_len == 0 {
        return Err(ApfsError::NotFound {
            what: "checkpoint descriptor area",
        });
    }
    let desc_area = if desc.blocks & XP_AREA_TREE_FLAG != 0 {
        read_descriptor_tree(reader, block_size, base)?
    } else {
        DescriptorArea::Contiguous { base }
    };

    // Collect every checksum-valid container superblock in the area.
    let mut candidates: Vec<NxSuperblock> = Vec::new();
    for i in 0..ring_len {
        let Some(addr) = desc_area.block_addr(i) else {
            continue;
        };
        let block = read_block(reader, block_size, addr)?;
        if !checksum::verify_block(&block) {
            continue;
        }
        let Ok(header) = ObjPhys::parse(&block) else {
            continue;
        };
        if header.object_kind() != ObjectType::NxSuperblock {
            continue;
        }
        if let Ok(superblock) = NxSuperblock::parse(&block) {
            candidates.push(superblock);
        }
    }
    // Newest transaction first.
    candidates.sort_by_key(|sb| core::cmp::Reverse(sb.xid.0));

    for superblock in candidates {
        if let Some(mappings) =
            gather_mappings(reader, block_size, &desc_area, ring_len, &superblock)?
        {
            return Ok(Checkpoint {
                superblock,
                mappings,
            });
        }
    }
    Err(ApfsError::NotFound {
        what: "valid checkpoint",
    })
}

/// Gathers a candidate checkpoint's mapping blocks from the descriptor ring.
///
/// Returns `None` when one of the checkpoint's mapping blocks fails its
/// checksum — the candidate is torn and an older checkpoint should be tried.
fn gather_mappings<R: Read + Seek>(
    reader: &mut R,
    block_size: u32,
    desc_area: &DescriptorArea,
    ring_len: u64,
    superblock: &NxSuperblock,
) -> Result<Option<Vec<CheckpointMapping>>> {
    let mut mappings = Vec::new();
    let span = u64::from(superblock.xp_desc.len);
    let start = u64::from(superblock.xp_desc.index);
    // A checkpoint must span at least its own superblock, cannot be longer
    // than the ring, and cannot start past the ring. A superblock whose
    // descriptor range violates this is malformed — reject it so an older
    // valid checkpoint is tried instead.
    if span == 0 || span > ring_len || start >= ring_len {
        return Ok(None);
    }
    for j in 0..span {
        let index = (start + j) % ring_len;
        // A descriptor offset with no physical mapping means the candidate
        // is torn; fall back to an older checkpoint.
        let Some(addr) = desc_area.block_addr(index) else {
            return Ok(None);
        };
        let block = read_block(reader, block_size, addr)?;
        if !checksum::verify_block(&block) {
            return Ok(None);
        }
        let Ok(header) = ObjPhys::parse(&block) else {
            return Ok(None);
        };
        match header.object_kind() {
            // The superblock itself shares the checkpoint's ring range.
            ObjectType::NxSuperblock => {}
            ObjectType::CheckpointMap => {
                mappings.extend(CheckpointMapPhys::parse(&block)?.mappings);
            }
            _ => return Ok(None),
        }
    }
    Ok(Some(mappings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::OBJ_EPHEMERAL;
    use std::io::Cursor;

    const BLK: usize = 4096;

    /// Writes `o_cksum` so the block passes Fletcher-64 verification.
    fn seal(block: &mut [u8]) {
        let csum = checksum::fletcher64(&block[8..]);
        block[..8].copy_from_slice(&csum.to_le_bytes());
    }

    /// Builds a container-superblock block.
    fn superblock(
        xid: u64,
        desc_base: u64,
        desc_blocks: u32,
        desc_index: u32,
        desc_len: u32,
    ) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x10..0x18].copy_from_slice(&xid.to_le_bytes());
        b[0x18..0x1C].copy_from_slice(&(OBJ_EPHEMERAL | 0x01).to_le_bytes());
        b[0x20..0x24].copy_from_slice(&0x4253_584Eu32.to_le_bytes()); // NXSB
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(BLK)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        b[0x28..0x30].copy_from_slice(&100_000u64.to_le_bytes());
        b[0x68..0x6C].copy_from_slice(&desc_blocks.to_le_bytes()); // nx_xp_desc_blocks
        b[0x70..0x78].copy_from_slice(
            &i64::try_from(desc_base)
                .expect("the test fixture descriptor base fits in i64")
                .to_le_bytes(),
        ); // nx_xp_desc_base
        b[0x88..0x8C].copy_from_slice(&desc_index.to_le_bytes()); // nx_xp_desc_index
        b[0x8C..0x90].copy_from_slice(&desc_len.to_le_bytes()); // nx_xp_desc_len
        seal(&mut b);
        b
    }

    /// Builds a checkpoint-mapping block with one (oid -> paddr) mapping.
    fn map_block(eph_oid: u64, paddr: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&0x4000_000Cu32.to_le_bytes()); // CHECKPOINT_MAP, physical
        b[0x20..0x24].copy_from_slice(&CHECKPOINT_MAP_LAST.to_le_bytes()); // cpm_flags
        b[0x24..0x28].copy_from_slice(&1u32.to_le_bytes()); // cpm_count
        // cpm_map[0] at 0x28: oid at +24, paddr at +32.
        b[0x28 + 24..0x28 + 32].copy_from_slice(&eph_oid.to_le_bytes());
        b[0x28 + 32..0x28 + 40].copy_from_slice(&paddr.to_le_bytes());
        seal(&mut b);
        b
    }

    /// Assembles `blocks` into one contiguous container image.
    fn image(blocks: &[Vec<u8>]) -> Cursor<Vec<u8>> {
        let mut data = Vec::new();
        for block in blocks {
            data.extend_from_slice(block);
        }
        Cursor::new(data)
    }

    #[test]
    fn selects_the_highest_xid_checkpoint() {
        // Ring of 4 blocks at base 1 (ring index 0..3):
        //   idx0 map(40,900), idx1 sb xid 5, idx2 map(41,901), idx3 sb xid 9.
        let blocks = vec![
            vec![0u8; BLK],            // block 0, before the ring
            map_block(40, 900),        // addr 1, ring idx 0
            superblock(5, 1, 4, 0, 2), // addr 2, ring idx 1 — checkpoint idx 0,1
            map_block(41, 901),        // addr 3, ring idx 2
            superblock(9, 1, 4, 2, 2), // addr 4, ring idx 3 — checkpoint idx 2,3
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(9, 1, 4, 2, 2)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 9);
        assert_eq!(cp.resolve_ephemeral(Oid(41)), Some(Paddr(901)));
        assert_eq!(cp.resolve_ephemeral(Oid(40)), None);
    }

    #[test]
    fn skips_a_torn_trailing_superblock() {
        // The xid-9 superblock is corrupt; the xid-5 checkpoint must win.
        let mut torn = superblock(9, 1, 4, 0, 2);
        torn[2000] ^= 0xFF; // break the body after sealing
        let blocks = vec![
            vec![0u8; BLK],
            map_block(40, 900),        // addr 1, ring idx 0
            superblock(5, 1, 4, 0, 2), // addr 2, ring idx 1 — checkpoint idx 0,1
            vec![0u8; BLK],            // addr 3, ring idx 2 — unreferenced
            torn,                      // addr 4, ring idx 3 — corrupt
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(0, 1, 4, 0, 0)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 5);
        assert_eq!(cp.resolve_ephemeral(Oid(40)), Some(Paddr(900)));
    }

    #[test]
    fn empty_ring_is_a_typed_error() {
        let mut reader = image(&[vec![0u8; BLK]]);
        let bz = NxSuperblock::parse(&superblock(1, 1, 0, 0, 0)).unwrap();
        assert!(matches!(
            latest_checkpoint(&mut reader, &bz),
            Err(ApfsError::NotFound { .. })
        ));
    }

    #[test]
    fn all_corrupt_ring_is_a_typed_error() {
        // A one-block descriptor ring whose only superblock fails its checksum.
        let mut bad = superblock(7, 1, 1, 0, 0);
        bad[1000] ^= 0xFF;
        let mut reader = image(&[vec![0u8; BLK], bad]);
        let bz = NxSuperblock::parse(&superblock(7, 1, 1, 0, 0)).unwrap();
        assert!(matches!(
            latest_checkpoint(&mut reader, &bz),
            Err(ApfsError::NotFound { .. })
        ));
    }

    /// Builds a single ROOT|LEAF|FIXED descriptor-tree node mapping each
    /// `(descriptor index, physical address, block count)` fragment.
    fn desc_tree_leaf(fragments: &[(u64, u64, u64)]) -> Vec<u8> {
        use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
        let mut b = vec![0u8; BLK];
        b[0x18..0x1C].copy_from_slice(&0x4000_0002u32.to_le_bytes()); // BTREE, physical
        b[0x20..0x22].copy_from_slice(&0x0007u16.to_le_bytes()); // ROOT|LEAF|FIXED
        b[0x24..0x28].copy_from_slice(
            &u32::try_from(fragments.len())
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        ); // btn_nkeys
        b[0x2A..0x2C].copy_from_slice(
            &u16::try_from(fragments.len() * 4)
                .expect("the test fixture value fits in u16")
                .to_le_bytes(),
        ); // toc len
        let key_area = BTN_DATA_OFFSET + fragments.len() * 4;
        let value_end = BLK - BTREE_INFO_SIZE;
        for (i, &(index, phys, count)) in fragments.iter().enumerate() {
            let toc = BTN_DATA_OFFSET + i * 4;
            b[toc..toc + 2].copy_from_slice(
                &u16::try_from(i * 8)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            ); // key offset
            b[toc + 2..toc + 4].copy_from_slice(
                &u16::try_from((i + 1) * 16)
                    .expect("the test fixture value fits in u16")
                    .to_le_bytes(),
            ); // val
            let ks = key_area + i * 8;
            b[ks..ks + 8].copy_from_slice(&index.to_le_bytes());
            let vs = value_end - (i + 1) * 16;
            b[vs..vs + 8].copy_from_slice(
                &i64::try_from(phys)
                    .expect("the test fixture physical address fits in i64")
                    .to_le_bytes(),
            ); // pr_start_addr
            b[vs + 8..vs + 16].copy_from_slice(&count.to_le_bytes()); // pr_block_count
        }
        let info = BLK - BTREE_INFO_SIZE;
        b[info + 8..info + 12].copy_from_slice(&8u32.to_le_bytes()); // bt_key_size
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes()); // bt_val_size
        seal(&mut b);
        b
    }

    #[test]
    fn mounts_a_tree_stored_descriptor_area() {
        // Descriptor area is a tree at block 1; one fragment maps the
        // 2-block area onto physical blocks 3..5.
        let blocks = vec![
            vec![0u8; BLK],                                // block 0
            desc_tree_leaf(&[(0, 3, 2)]),                  // block 1: descriptor tree root
            vec![0u8; BLK],                                // block 2: gap
            map_block(40, 900),                            // block 3: ring idx 0
            superblock(7, 1, XP_AREA_TREE_FLAG | 2, 0, 2), // block 4: ring idx 1
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(7, 1, XP_AREA_TREE_FLAG | 2, 0, 2)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 7);
        assert_eq!(cp.resolve_ephemeral(Oid(40)), Some(Paddr(900)));
    }

    #[test]
    fn corrupt_descriptor_tree_root_is_a_typed_error() {
        let mut root = desc_tree_leaf(&[(0, 3, 2)]);
        root[1500] ^= 0xFF; // break the body after sealing
        let blocks = vec![vec![0u8; BLK], root];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(7, 1, XP_AREA_TREE_FLAG | 2, 0, 2)).unwrap();
        assert!(matches!(
            latest_checkpoint(&mut reader, &bz),
            Err(ApfsError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn tree_descriptor_gap_makes_a_checkpoint_torn() {
        // The tree maps only descriptor index 0, but the superblock there
        // claims a 2-block span — index 1 is unmapped, so the candidate is
        // torn and no checkpoint verifies.
        let blocks = vec![
            vec![0u8; BLK],                                // block 0
            desc_tree_leaf(&[(0, 2, 1)]),                  // block 1: tree root
            superblock(7, 1, XP_AREA_TREE_FLAG | 2, 0, 2), // block 2: ring idx 0
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(7, 1, XP_AREA_TREE_FLAG | 2, 0, 2)).unwrap();
        assert!(matches!(
            latest_checkpoint(&mut reader, &bz),
            Err(ApfsError::NotFound { .. })
        ));
    }

    #[test]
    fn skips_a_superblock_with_an_out_of_range_descriptor_span() {
        // The xid-9 superblock claims a descriptor length longer than the
        // 4-block ring; it must be rejected so the xid-5 checkpoint wins.
        let blocks = vec![
            vec![0u8; BLK],
            map_block(40, 900),         // addr 1, ring idx 0
            superblock(5, 1, 4, 0, 2),  // addr 2, ring idx 1 — checkpoint idx 0,1
            vec![0u8; BLK],             // addr 3, ring idx 2
            superblock(9, 1, 4, 2, 99), // addr 4, ring idx 3 — len 99 > ring_len
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(0, 1, 4, 0, 0)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 5);
    }

    #[test]
    fn checkpoint_map_parse_rejects_oversized_count() {
        let mut b = vec![0u8; BLK];
        b[0x24..0x28].copy_from_slice(&u32::MAX.to_le_bytes()); // absurd cpm_count
        assert!(matches!(
            CheckpointMapPhys::parse(&b),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn is_last_reflects_only_the_checkpoint_map_last_bit() {
        // flags=0: not last.
        let intact = CheckpointMapPhys {
            flags: 0,
            mappings: Vec::new(),
        };
        assert!(!intact.is_last());
        // flags=CHECKPOINT_MAP_LAST: last.
        let last = CheckpointMapPhys {
            flags: CHECKPOINT_MAP_LAST,
            mappings: Vec::new(),
        };
        assert!(last.is_last());
        // flags=0b10 (some other bit, not LAST): not last — guards `&` from
        // mutating into `|` or `^`.
        let other = CheckpointMapPhys {
            flags: 0x0000_0002,
            mappings: Vec::new(),
        };
        assert!(!other.is_last());
    }

    #[test]
    fn parse_accepts_a_block_sized_exactly_to_its_mappings() {
        // CHECKPOINT_MAP_HEADER_SIZE + cpm_count * CHECKPOINT_MAPPING_SIZE
        // must equal block.len() exactly: parse must accept it (the bound
        // is `>` not `>=`).
        let mut b = vec![0u8; CHECKPOINT_MAP_HEADER_SIZE + CHECKPOINT_MAPPING_SIZE];
        b[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(&1u32.to_le_bytes());
        let parsed = CheckpointMapPhys::parse(&b).unwrap();
        assert_eq!(parsed.mappings.len(), 1);
    }

    #[test]
    fn parse_returns_each_mapping_at_its_indexed_offset() {
        // Two mappings, distinct oids. Wrong arithmetic (`+ → -` or `* → /`)
        // in `start = HEADER + i * MAPPING_SIZE` would either underflow or
        // re-read mapping 0 for index 1.
        let n = 2;
        let mut b = vec![0u8; CHECKPOINT_MAP_HEADER_SIZE + n * CHECKPOINT_MAPPING_SIZE];
        b[OBJ_PHYS_SIZE + 4..OBJ_PHYS_SIZE + 8].copy_from_slice(
            &u32::try_from(n)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        // cpm_map[0]: oid=100 at offset +24.
        let m0 = CHECKPOINT_MAP_HEADER_SIZE;
        b[m0 + 24..m0 + 32].copy_from_slice(&100u64.to_le_bytes());
        b[m0 + 32..m0 + 40].copy_from_slice(&900u64.to_le_bytes()); // paddr
        // cpm_map[1]: oid=200 at offset +24.
        let m1 = CHECKPOINT_MAP_HEADER_SIZE + CHECKPOINT_MAPPING_SIZE;
        b[m1 + 24..m1 + 32].copy_from_slice(&200u64.to_le_bytes());
        b[m1 + 32..m1 + 40].copy_from_slice(&901u64.to_le_bytes()); // paddr
        let parsed = CheckpointMapPhys::parse(&b).unwrap();
        assert_eq!(parsed.mappings.len(), 2);
        assert_eq!(parsed.mappings[0].oid, Oid(100));
        assert_eq!(parsed.mappings[0].paddr, Paddr(900));
        assert_eq!(parsed.mappings[1].oid, Oid(200));
        assert_eq!(parsed.mappings[1].paddr, Paddr(901));
    }

    #[test]
    fn skips_a_superblock_with_a_zero_descriptor_span() {
        // The xid-9 superblock claims span=0 (degenerate); it must be
        // rejected so the older xid-5 checkpoint wins. Without the
        // `span == 0` guard, the candidate would be selected with no
        // mappings.
        let blocks = vec![
            vec![0u8; BLK],
            map_block(40, 900),        // addr 1, ring idx 0
            superblock(5, 1, 4, 0, 2), // addr 2, ring idx 1 — xid 5
            map_block(41, 901),        // addr 3, ring idx 2
            superblock(9, 1, 4, 3, 0), // addr 4, ring idx 3 — span=0
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(0, 1, 4, 0, 0)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 5);
    }

    #[test]
    fn skips_a_superblock_whose_span_overflows_a_fully_valid_ring() {
        // Every ring slot is a valid checkpoint object, so a candidate whose
        // span > ring_len would otherwise gather successfully by wrapping
        // around. The `span > ring_len` guard must reject it so the older
        // xid-5 checkpoint wins.
        let blocks = vec![
            vec![0u8; BLK],
            vec![0u8; BLK],
            map_block(40, 900),        // ring idx 0
            superblock(5, 2, 4, 1, 2), // ring idx 1 — xid 5 spans idx 1,2
            map_block(41, 901),        // ring idx 2
            superblock(9, 2, 4, 3, 5), // ring idx 3 — xid 9, span=5 > ring=4
        ];
        let mut reader = image(&blocks);
        let bz = NxSuperblock::parse(&superblock(0, 2, 4, 0, 0)).unwrap();
        let cp = latest_checkpoint(&mut reader, &bz).unwrap();
        assert_eq!(cp.superblock.xid.0, 5);
    }
}
