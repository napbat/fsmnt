use super::*;

/// Hash the `block_index`-th zero-padded `block_size` chunk of `buf`.
fn hash_padded(
    alg: VerityHashAlgorithm,
    salt: &[u8],
    buf: &[u8],
    block_index: usize,
    block_size: usize,
) -> Vec<u8> {
    let mut block = alloc::vec![0u8; block_size];
    let start = block_index * block_size;
    let end = (start + block_size).min(buf.len());
    if start < buf.len() {
        block[..end - start].copy_from_slice(&buf[start..end]);
    }
    hash_block(alg, salt, &block).as_slice().to_vec()
}

/// Build a complete in-memory Merkle tree over `data` and return
/// the descriptor + flat tree bytes (top-level first).
///
/// `levels[i]` is the concatenated hash content of tree level `i`
/// (level 0 = leaf hashes of data blocks). A level whose content
/// fits in one block is the top level; the root is the hash of
/// that single zero-padded block.
fn build_tree(data: &[u8], block_size: usize, salt: &[u8]) -> (VerityDescriptor, Vec<u8>) {
    let alg = VerityHashAlgorithm::Sha256;

    // Level 0 = hashes of zero-padded data blocks.
    let data_blocks = data.len().div_ceil(block_size).max(1);
    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut leaf = Vec::new();
    for b in 0..data_blocks {
        leaf.extend_from_slice(&hash_padded(alg, salt, data, b, block_size));
    }
    levels.push(leaf);

    // Build upper levels until a level fits in a single block.
    loop {
        let prev = levels.last().expect("at least one level");
        if prev.len() <= block_size {
            break;
        }
        let prev_blocks = prev.len().div_ceil(block_size);
        let mut next = Vec::new();
        for tb in 0..prev_blocks {
            next.extend_from_slice(&hash_padded(alg, salt, prev, tb, block_size));
        }
        levels.push(next);
    }

    // Root = hash of the (zero-padded) top-level block.
    let top = levels.last().expect("top level");
    let mut top_block = alloc::vec![0u8; block_size];
    top_block[..top.len()].copy_from_slice(top);
    let root = hash_block(alg, salt, &top_block).as_slice().to_vec();

    // Flatten levels top-first, each level padded to whole blocks.
    let mut tree = Vec::new();
    for level in levels.iter().rev() {
        let blocks = level.len().div_ceil(block_size).max(1);
        let mut padded = alloc::vec![0u8; blocks * block_size];
        padded[..level.len()].copy_from_slice(level);
        tree.extend_from_slice(&padded);
    }

    let descriptor = VerityDescriptor {
        algorithm: alg,
        log_blocksize: (block_size.trailing_zeros()).to_le_bytes()[0],
        data_size: data.len() as u64,
        root_hash: root,
        salt: salt.to_vec(),
        signature: Vec::new(),
    };
    (descriptor, tree)
}

/// In-memory tree-block reader: serves bytes from a flat buffer
/// laid out as `[tree bytes][descriptor]` starting at `tree_offset`.
struct MemReader {
    tree_offset: u64,
    tree: Vec<u8>,
    reads: usize,
}

impl TreeBlockReader for MemReader {
    fn read_exact_at(&mut self, offset: u64, out: &mut [u8]) -> Result<()> {
        self.reads += 1;
        let rel = usize::try_from(offset - self.tree_offset ).expect("the test fixture value fits in usize");
        out.fill(0);
        let end = (rel + out.len()).min(self.tree.len());
        if rel < self.tree.len() {
            out[..end - rel].copy_from_slice(&self.tree[rel..end]);
        }
        Ok(())
    }
}

fn padded_block(data: &[u8], block_index: usize, block_size: usize) -> Vec<u8> {
    let mut block = alloc::vec![0u8; block_size];
    let start = block_index * block_size;
    let end = (start + block_size).min(data.len());
    if start < data.len() {
        block[..end - start].copy_from_slice(&data[start..end]);
    }
    block
}

#[test]
fn single_block_tree_verifies() {
    let block_size = 1024;
    let data = alloc::vec![0xABu8; 700];
    let (descriptor, tree) = build_tree(&data, block_size, &[]);
    let mut verifier = VerityVerifier::new(7, descriptor, data.len() as u64).unwrap();
    let mut reader = MemReader {
        tree_offset: verifier.tree_offset,
        tree,
        reads: 0,
    };
    let block = padded_block(&data, 0, block_size);
    verifier.verify_data_block(&mut reader, 0, &block).unwrap();
}

#[test]
fn multi_level_tree_verifies_all_blocks() {
    // block_size 1024 holds 32 hashes; >32 data blocks forces 2+ levels.
    let block_size = 1024;
    let data: Vec<u8> = (0_usize..40 * block_size)
        .map(|i| (i % 251).to_le_bytes()[0])
        .collect();
    let (descriptor, tree) = build_tree(&data, block_size, b"verysalt");
    assert!(
        MerkleTreeParams::new(1, VerityHashAlgorithm::Sha256, 10, data.len() as u64,)
            .unwrap()
            .num_levels()
            >= 2
    );
    let mut verifier = VerityVerifier::new(9, descriptor, data.len() as u64).unwrap();
    let mut reader = MemReader {
        tree_offset: verifier.tree_offset,
        tree,
        reads: 0,
    };
    for b in 0..40 {
        let block = padded_block(&data, b, block_size);
        verifier
            .verify_data_block(&mut reader, (b * block_size) as u64, &block)
            .unwrap();
    }
    assert_eq!(reader.reads, 3, "two leaf blocks plus one root block");
    assert_eq!(verifier.cache.len(), 2, "one bounded slot per tree level");
    assert!(verifier.cache.iter().all(Option::is_some));
}

#[test]
fn tampered_data_block_is_rejected() {
    let block_size = 1024;
    let data = alloc::vec![0x11u8; 3000];
    let (descriptor, tree) = build_tree(&data, block_size, &[]);
    let mut verifier = VerityVerifier::new(3, descriptor, data.len() as u64).unwrap();
    let mut reader = MemReader {
        tree_offset: verifier.tree_offset,
        tree,
        reads: 0,
    };
    let mut block = padded_block(&data, 1, block_size);
    block[0] ^= 0xFF;
    let err = verifier
        .verify_data_block(&mut reader, block_size as u64, &block)
        .unwrap_err();
    match err {
        ExtError::VerityHashMismatch { inode: 3, offset } => {
            assert_eq!(offset, block_size as u64);
        }
        other => panic!("expected VerityHashMismatch, got {other:?}"),
    }
}

#[test]
fn tampered_tree_block_is_rejected() {
    let block_size = 1024;
    let data: Vec<u8> = (0_usize..40 * block_size)
        .map(|i| (i % 191).to_le_bytes()[0])
        .collect();
    let (descriptor, mut tree) = build_tree(&data, block_size, &[]);
    // Flip a byte in a leaf-level tree block (last level in the file).
    let last = tree.len() - 1;
    tree[last] ^= 0x01;
    let mut verifier = VerityVerifier::new(5, descriptor, data.len() as u64).unwrap();
    let mut reader = MemReader {
        tree_offset: verifier.tree_offset,
        tree,
        reads: 0,
    };
    // Block 39's leaf hash lives in the final leaf tree block.
    let block = padded_block(&data, 39, block_size);
    let err = verifier
        .verify_data_block(&mut reader, (39 * block_size) as u64, &block)
        .unwrap_err();
    assert!(matches!(err, ExtError::VerityHashMismatch { inode: 5, .. }));
}

#[test]
fn descriptor_parse_round_trip() {
    let mut bytes = alloc::vec![0u8; DESCRIPTOR_SIZE];
    bytes[0] = FSVERITY_VERSION;
    bytes[1] = HASH_ALG_SHA256;
    bytes[2] = 12; // log_blocksize
    bytes[3] = 4; // salt_size
    bytes[8..16].copy_from_slice(&4096u64.to_le_bytes());
    bytes[16..48].copy_from_slice(&[0x5Au8; 32]); // root hash (first 32)
    bytes[80..84].copy_from_slice(b"SALT");
    let parsed = VerityDescriptor::parse(1, &bytes).unwrap();
    assert_eq!(parsed.algorithm(), VerityHashAlgorithm::Sha256);
    assert_eq!(parsed.log_blocksize(), 12);
    assert_eq!(parsed.data_size(), 4096);
    assert_eq!(parsed.root_hash(), &[0x5Au8; 32]);
    assert_eq!(parsed.salt(), b"SALT");
    assert!(parsed.signature().is_empty());
}

#[test]
fn descriptor_rejects_bad_version() {
    let mut bytes = alloc::vec![0u8; DESCRIPTOR_SIZE];
    bytes[0] = 2;
    bytes[1] = HASH_ALG_SHA256;
    bytes[2] = 12;
    let err = VerityDescriptor::parse(1, &bytes).unwrap_err();
    assert!(matches!(
        err,
        ExtError::InvalidVerityDescriptor { inode: 1, .. }
    ));
}

#[test]
fn location_parse_extracts_pos_and_size() {
    let mut value = alloc::vec![0u8; 12];
    value[0..4].copy_from_slice(&256u32.to_le_bytes());
    value[4..12].copy_from_slice(&65536u64.to_le_bytes());
    let (pos, size) = VerityDescriptor::parse_location(1, &value).unwrap();
    assert_eq!(pos, 65536);
    assert_eq!(size, 256);
}

#[test]
fn signature_bytes_are_exposed_not_validated() {
    let mut bytes = alloc::vec![0u8; DESCRIPTOR_SIZE + 5];
    bytes[0] = FSVERITY_VERSION;
    bytes[1] = HASH_ALG_SHA256;
    bytes[2] = 12;
    bytes[4..8].copy_from_slice(&5u32.to_le_bytes()); // sig_size
    bytes[DESCRIPTOR_SIZE..].copy_from_slice(b"\x01\x02\x03\x04\x05");
    let parsed = VerityDescriptor::parse(1, &bytes).unwrap();
    assert_eq!(parsed.signature(), b"\x01\x02\x03\x04\x05");
}

/// End-to-end fs-verity tests against a synthesized ext4 image.
///
/// The image is built entirely in-Rust from the base `ext4.img`
/// fixture — no `mkfs`, no `sudo`. Inode 523 (`multiblock.bin`, a
/// 2-block extent file) is repurposed: its extent is rewritten to a
/// fresh contiguous run of free blocks, the file data + Merkle tree +
/// `fsverity_descriptor` are written into those blocks, the index-11
/// verity-location xattr is planted in the inode body, and
/// `VERITY_FL` / `RO_COMPAT_VERITY` are set. As an in-crate test
/// module it reuses the crate's own checksum writers
/// (`crate::checksum`) rather than reimplementing CRC32C.
#[cfg(test)]
mod integration_tests {
use alloc::vec;
use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::VerityHashAlgorithm;
use crate::checksum::{compute_inode_csum, compute_superblock_csum};
use crate::error::ExtError;
use crate::ext::Ext;
use crate::io::{FsReadSeek, SeekFrom};

const BLOCK_SIZE: usize = 4096;
const INODE_SIZE: usize = 256;
const VERITY_FILE_INO: u32 = 523;
const PLAIN_FILE_INO: u32 = 20; // hello.txt
/// Verity-protected payload size: spans three 4 KiB data blocks.
const DATA_SIZE: usize = 9000;
/// 64 KiB-aligned tree start => logical block 16 (kernel
/// `ext4_verity_metadata_pos`).
const TREE_LOGICAL_BLOCK: u64 = 16;
/// First free contiguous run in group 0 of `ext4.img` (verified
/// via the block bitmap).
const FIRST_FREE_PHYS: u64 = 1845;
/// `VERITY_FL` inode flag.
const VERITY_FL: u32 = 0x0010_0000;
/// `RO_COMPAT_VERITY` superblock feature bit.
const RO_COMPAT_VERITY: u32 = 0x8000;
/// `EXT4_XATTR_INDEX_VERITY` (kernel `fs/ext4/xattr.h`).
const XATTR_INDEX_VERITY: u8 = 11;

/// SHA-256 of one Merkle block with an empty salt (the fixture
/// uses `salt_size = 0`, so the kernel hash is plain
/// `SHA256(block)`).
fn hash_block(block: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(block);
    h.finalize().into()
}

/// Hash the `block_index`-th zero-padded `BLOCK_SIZE` chunk of
/// `buf`.
fn hash_padded(buf: &[u8], block_index: usize) -> [u8; 32] {
    hash_block(&padded_block(buf, block_index))
}

/// One zero-padded `BLOCK_SIZE` slice of `buf` at block `index`.
fn padded_block(buf: &[u8], index: usize) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    let start = index * BLOCK_SIZE;
    let end = (start + BLOCK_SIZE).min(buf.len());
    if start < buf.len() {
        block[..end - start].copy_from_slice(&buf[start..end]);
    }
    block
}

/// Build the Merkle tree over `data` (empty salt) and return
/// `(root_hash, flat_tree_top_first, tree_block_count)`.
///
/// `levels[i]` is the hash content of tree level `i` (level 0 =
/// leaf hashes); a level whose content fits in one block is the
/// top level.
fn build_merkle_tree(data: &[u8]) -> ([u8; 32], Vec<u8>, usize) {
    let data_blocks = data.len().div_ceil(BLOCK_SIZE).max(1);

    // Level 0: hash each zero-padded data block.
    let mut levels: Vec<Vec<u8>> = Vec::new();
    let mut leaf = Vec::new();
    for b in 0..data_blocks {
        leaf.extend_from_slice(&hash_padded(data, b));
    }
    levels.push(leaf);

    // Upper levels until a level fits in a single block.
    loop {
        let prev = levels.last().expect("level present");
        if prev.len() <= BLOCK_SIZE {
            break;
        }
        let prev_blocks = prev.len().div_ceil(BLOCK_SIZE);
        let mut next = Vec::new();
        for tb in 0..prev_blocks {
            next.extend_from_slice(&hash_padded(prev, tb));
        }
        levels.push(next);
    }

    // Root = hash of the zero-padded top-level block.
    let top = levels.last().expect("top level");
    let mut top_block = [0u8; BLOCK_SIZE];
    top_block[..top.len()].copy_from_slice(top);
    let root = hash_block(&top_block);

    // Flatten top-first, each level padded to whole blocks.
    let mut tree = Vec::new();
    for level in levels.iter().rev() {
        let blocks = level.len().div_ceil(BLOCK_SIZE).max(1);
        let mut padded = vec![0u8; blocks * BLOCK_SIZE];
        padded[..level.len()].copy_from_slice(level);
        tree.extend_from_slice(&padded);
    }
    let tree_blocks = tree.len() / BLOCK_SIZE;
    (root, tree, tree_blocks)
}

/// Build the 256-byte `fsverity_descriptor` (version 1, SHA-256,
/// `log_blocksize = 12`, empty salt, no signature).
fn build_descriptor(root: &[u8; 32], data_size: u64) -> Vec<u8> {
    let mut d = vec![0u8; 256];
    d[0] = 1; // version
    d[1] = 1; // hash_algorithm = SHA-256
    d[2] = 12; // log_blocksize
    d[3] = 0; // salt_size
    // sig_size (4..8) = 0
    d[8..16].copy_from_slice(&data_size.to_le_bytes());
    d[16..48].copy_from_slice(root);
    d
}

/// Group 0 inode-table block of `ext4.img` (64-bit group
/// descriptor: `bg_inode_table_lo` at 0x08, `_hi` at 0x28).
fn inode_table_block(image: &[u8]) -> u64 {
    let gd = &image[BLOCK_SIZE..BLOCK_SIZE + 64];
    let lo = u32::from_le_bytes(gd[8..12].try_into().expect("4 bytes"));
    let hi = u32::from_le_bytes(gd[40..44].try_into().expect("4 bytes"));
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Byte offset of inode `ino` within `image`.
fn inode_offset(image: &[u8], ino: u32) -> usize {
    let table = inode_table_block(image);
    usize::try_from(table * BLOCK_SIZE as u64 ).expect("the test fixture value fits in usize") + (ino - 1) as usize * INODE_SIZE
}

/// Filesystem checksum seed (`s_checksum_seed`, superblock offset
/// 0x270).
fn checksum_seed(image: &[u8]) -> u32 {
    u32::from_le_bytes(
        image[1024 + 0x270..1024 + 0x274]
            .try_into()
            .expect("4 bytes"),
    )
}

/// Number of Merkle tree blocks for a `DATA_SIZE` payload.
fn tree_block_count() -> usize {
    build_merkle_tree(&vec![0u8; DATA_SIZE]).2
}

/// Overwrite inode 523 with a single-extent verity inode and
/// recompute its CRC32C via `crate::checksum::compute_inode_csum`.
fn rewrite_inode(image: &mut [u8], total_logical_blocks: u32) {
    let off = inode_offset(image, VERITY_FILE_INO);
    let inode = &mut image[off..off + INODE_SIZE];

    // i_size_lo (0x04) and i_size_high (0x6C).
    inode[4..8].copy_from_slice(&(u32::try_from(DATA_SIZE).expect("the test fixture value fits in u32")).to_le_bytes());
    inode[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
    // i_flags (0x20): keep EXTENTS_FL (0x80000), add VERITY_FL.
    let flags = u32::from_le_bytes(inode[0x20..0x24].try_into().expect("4 bytes"));
    inode[0x20..0x24].copy_from_slice(&(flags | VERITY_FL).to_le_bytes());
    // i_blocks_lo (0x1C): 512-byte sectors covering the whole run.
    let sectors = u64::from(total_logical_blocks) * (BLOCK_SIZE as u64 / 512);
    inode[0x1C..0x20].copy_from_slice(&(u32::try_from(sectors).expect("the test fixture value fits in u32")).to_le_bytes());

    // Extent tree root in i_block (0x28..0x64): header + one leaf
    // extent mapping logical 0.. to the contiguous free run.
    let ib = &mut inode[0x28..0x64];
    ib.fill(0);
    ib[0..2].copy_from_slice(&0xF30Au16.to_le_bytes()); // eh_magic
    ib[2..4].copy_from_slice(&1u16.to_le_bytes()); // eh_entries
    ib[4..6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
    ib[6..8].copy_from_slice(&0u16.to_le_bytes()); // eh_depth
    // leaf extent at ib[12..24]: ee_block, ee_len, ee_start_hi, ee_start_lo
    ib[12..16].copy_from_slice(&0u32.to_le_bytes());
    ib[16..18].copy_from_slice(&(u16::try_from(total_logical_blocks).expect("the test fixture value fits in u16")).to_le_bytes());
    ib[18..20].copy_from_slice(&0u16.to_le_bytes());
    ib[20..24].copy_from_slice(&(u32::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in u32")).to_le_bytes());

    plant_verity_xattr(image, off);
    fix_inode_checksum(image, off);
}

/// Plant the index-11, empty-name verity-location xattr in the
/// inode body region (`128 + i_extra_isize ..`).
fn plant_verity_xattr(image: &mut [u8], inode_off: usize) {
    // i_extra_isize at offset 128..130 of the inode.
    let extra = u16::from_le_bytes(
        image[inode_off + 128..inode_off + 130]
            .try_into()
            .expect("2 bytes"),
    ) as usize;
    let xstart = inode_off + 128 + extra;

    // ext4_xattr_ibody_header: 4-byte magic.
    image[xstart..xstart + 4].copy_from_slice(&0xEA02_0000u32.to_le_bytes());

    // ext4_verity_descriptor_location value: desc_size, desc_pos.
    let desc_pos =
        TREE_LOGICAL_BLOCK * BLOCK_SIZE as u64 + tree_block_count() as u64 * BLOCK_SIZE as u64;
    let mut value: Vec<u8> = Vec::with_capacity(12);
    value.extend_from_slice(&256u32.to_le_bytes());
    value.extend_from_slice(&desc_pos.to_le_bytes());

    // Single ext4_xattr_entry at xstart+4: 16-byte header, empty
    // name. Value placed at the tail of the inode body;
    // e_value_offs is relative to the entry-list start (xstart+4).
    let entry = xstart + 4;
    let value_at = inode_off + INODE_SIZE - value.len();
    let e_value_offs = u16::try_from(value_at - (xstart + 4) ).expect("the test fixture value fits in u16");
    image[entry] = 0; // e_name_len
    image[entry + 1] = XATTR_INDEX_VERITY; // e_name_index
    image[entry + 2..entry + 4].copy_from_slice(&e_value_offs.to_le_bytes());
    image[entry + 4..entry + 8].copy_from_slice(&0u32.to_le_bytes()); // e_value_inum
    image[entry + 8..entry + 12].copy_from_slice(&(u32::try_from(value.len()).expect("the test fixture value fits in u32")).to_le_bytes()); // e_value_size
    image[entry + 12..entry + 16].copy_from_slice(&0u32.to_le_bytes()); // e_hash
    // Terminator (4-byte zero) immediately after the entry.
    image[entry + 16..entry + 20].copy_from_slice(&0u32.to_le_bytes());
    image[value_at..value_at + value.len()].copy_from_slice(&value);
}

/// Recompute the inode CRC32C with the crate's own
/// `compute_inode_csum` (`metadata_csum` mode, `has_hi = true`
/// since the 256-byte inode has `i_extra_isize >= 4`).
fn fix_inode_checksum(image: &mut [u8], inode_off: usize) {
    let seed = checksum_seed(image);
    let generation = u32::from_le_bytes(
        image[inode_off + 0x64..inode_off + 0x68]
            .try_into()
            .expect("4 bytes"),
    );
    let inode_buf = image[inode_off..inode_off + INODE_SIZE].to_vec();
    let (lo, hi) = compute_inode_csum(seed, VERITY_FILE_INO, generation, &inode_buf, true);
    image[inode_off + 0x7C..inode_off + 0x7E].copy_from_slice(&lo.to_le_bytes());
    image[inode_off + 0x82..inode_off + 0x84].copy_from_slice(&hi.to_le_bytes());
}

/// Set `RO_COMPAT_VERITY` and recompute the superblock CRC32C via
/// `crate::checksum::compute_superblock_csum`.
fn enable_verity_feature(image: &mut [u8]) {
    let ro = u32::from_le_bytes(image[1024 + 0x64..1024 + 0x68].try_into().expect("4 bytes"));
    image[1024 + 0x64..1024 + 0x68].copy_from_slice(&(ro | RO_COMPAT_VERITY).to_le_bytes());
    let mut sb = [0u8; 1024];
    sb.copy_from_slice(&image[1024..2048]);
    let csum = compute_superblock_csum(&sb);
    image[1024 + 0x3FC..1024 + 0x400].copy_from_slice(&csum.to_le_bytes());
}

/// Build a clean verity image: deterministic payload + Merkle tree
/// + descriptor written into the inode's freshly-mapped block run.
fn build_clean_image() -> Vec<u8> {
    let mut image = crate::test_support::load_clean_ext4_image();

    let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251).to_le_bytes()[0]).collect();
    let (root, tree, tree_blocks) = build_merkle_tree(&data);
    let descriptor = build_descriptor(&root, DATA_SIZE as u64);

    let data_blocks = DATA_SIZE.div_ceil(BLOCK_SIZE);
    // Logical layout: [data 0..data_blocks][gap][tree @16][descriptor].
    let total_logical = usize::try_from(TREE_LOGICAL_BLOCK).expect("the test fixture value fits in usize") + tree_blocks + 1;

    // Write data blocks.
    for b in 0..data_blocks {
        let phys = (usize::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in usize") + b) * BLOCK_SIZE;
        image[phys..phys + BLOCK_SIZE].copy_from_slice(&padded_block(&data, b));
    }
    // Zero the gap blocks between data and the tree.
    for b in data_blocks..usize::try_from(TREE_LOGICAL_BLOCK).expect("the test fixture value fits in usize") {
        let phys = (usize::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in usize") + b) * BLOCK_SIZE;
        image[phys..phys + BLOCK_SIZE].fill(0);
    }
    // Write the Merkle tree starting at logical block 16.
    let tree_phys = (usize::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in usize") + usize::try_from(TREE_LOGICAL_BLOCK).expect("the test fixture value fits in usize")) * BLOCK_SIZE;
    image[tree_phys..tree_phys + tree.len()].copy_from_slice(&tree);
    // Write the descriptor in the block following the tree.
    let desc_phys = tree_phys + tree.len();
    image[desc_phys..desc_phys + descriptor.len()].copy_from_slice(&descriptor);

    rewrite_inode(&mut image, u32::try_from(total_logical).expect("the test fixture value fits in u32"));
    enable_verity_feature(&mut image);
    image
}

/// Physical byte offset of data block `index` in a synthesized
/// image.
fn data_block_phys(index: usize) -> usize {
    (usize::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in usize") + index) * BLOCK_SIZE
}

/// Physical byte offset of the first Merkle-tree block.
fn tree_block_phys() -> usize {
    (usize::try_from(FIRST_FREE_PHYS).expect("the test fixture value fits in usize") + usize::try_from(TREE_LOGICAL_BLOCK).expect("the test fixture value fits in usize")) * BLOCK_SIZE
}

#[test]
fn clean_verity_file_reads_and_verifies() {
    let image = build_clean_image();
    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open synthesized verity image");

    let inode = ext.inode(&mut fs, VERITY_FILE_INO).expect("verity inode");
    assert!(inode.is_verity(), "inode 523 should report VERITY_FL");
    assert_eq!(inode.size(), DATA_SIZE as u64);

    let mut file = inode.open_file().expect("open verity file");
    let mut out = Vec::new();
    let mut buf = [0u8; 1000];
    loop {
        let n = file.read(&mut fs, &mut buf).expect("verity read");
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    let expected: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251).to_le_bytes()[0]).collect();
    assert_eq!(out, expected, "clean verity read must return file data");
}

#[test]
fn verity_descriptor_is_introspectable() {
    let image = build_clean_image();
    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open image");
    let inode = ext.inode(&mut fs, VERITY_FILE_INO).expect("verity inode");

    let descriptor = inode
        .verity_descriptor(&mut fs)
        .expect("descriptor parse")
        .expect("verity inode must yield a descriptor");
    assert_eq!(descriptor.algorithm(), VerityHashAlgorithm::Sha256);
    assert_eq!(descriptor.data_size(), DATA_SIZE as u64);
    assert_eq!(descriptor.log_blocksize(), 12);
    assert_eq!(descriptor.root_hash().len(), 32);
    assert!(descriptor.signature().is_empty());

    let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251).to_le_bytes()[0]).collect();
    let (root, _, _) = build_merkle_tree(&data);
    assert_eq!(descriptor.root_hash(), root);
}

#[test]
fn tampered_data_block_returns_hash_mismatch() {
    let mut image = build_clean_image();
    // Flip a byte inside data block 1 (file offset 4096..8192).
    image[data_block_phys(1) + 10] ^= 0xFF;

    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open image");
    let inode = ext.inode(&mut fs, VERITY_FILE_INO).expect("verity inode");
    let mut file = inode.open_file().expect("open verity file");

    // Seek into the tampered block and read it.
    file.seek(&mut fs, SeekFrom::Start(BLOCK_SIZE as u64))
        .expect("seek");
    let mut buf = [0u8; 64];
    let err = file
        .read(&mut fs, &mut buf)
        .expect_err("tampered read must fail");
    match err {
        ExtError::VerityHashMismatch { inode, offset } => {
            assert_eq!(inode, VERITY_FILE_INO);
            assert_eq!(offset, BLOCK_SIZE as u64);
        }
        other => panic!("expected VerityHashMismatch, got {other:?}"),
    }
}

#[test]
fn tampered_merkle_tree_block_returns_hash_mismatch() {
    let mut image = build_clean_image();
    // Flip a byte in the (single-level) Merkle tree leaf block.
    image[tree_block_phys() + 5] ^= 0x01;

    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open image");
    let inode = ext.inode(&mut fs, VERITY_FILE_INO).expect("verity inode");
    let mut file = inode.open_file().expect("open verity file");

    let mut buf = [0u8; 64];
    let err = file
        .read(&mut fs, &mut buf)
        .expect_err("tampered tree read must fail");
    assert!(
        matches!(err, ExtError::VerityHashMismatch { inode, .. } if inode == VERITY_FILE_INO),
        "tampered tree block must fail closed, got {err:?}"
    );
}

#[test]
fn non_verity_file_in_same_image_reads_normally() {
    let image = build_clean_image();
    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open image");

    let inode = ext.inode(&mut fs, PLAIN_FILE_INO).expect("plain inode");
    assert!(!inode.is_verity());
    let mut file = inode.open_file().expect("open plain file");
    let mut buf = [0u8; 64];
    let n = file.read(&mut fs, &mut buf).expect("plain read");
    assert_eq!(&buf[..n], b"Hello from ext4!\n");
}

#[test]
fn encrypted_verity_inode_fails_closed() {
    // ext4 permits ENCRYPT_FL + VERITY_FL together. The combined
    // mode is not verified, so opening such an inode must fail
    // closed rather than silently return unverified content.
    let mut image = build_clean_image();
    let off = inode_offset(&image, VERITY_FILE_INO);
    let flags = u32::from_le_bytes(image[off + 0x20..off + 0x24].try_into().expect("4 bytes"));
    let encrypt_fl = crate::inode::InodeFlags::ENCRYPT_FL.bits();
    image[off + 0x20..off + 0x24].copy_from_slice(&(flags | encrypt_fl).to_le_bytes());
    fix_inode_checksum(&mut image, off);

    let mut fs = fsmnt_testkit::Cursor::new(image);
    let ext = Ext::new(&mut fs).expect("open image");
    let inode = ext.inode(&mut fs, VERITY_FILE_INO).expect("verity inode");
    match inode.open_file() {
        Err(crate::error::ExtError::UnsupportedEncryptedVerity { inode: 523 }) => {}
        Err(other) => panic!("expected UnsupportedEncryptedVerity, got {other:?}"),
        Ok(_) => panic!("expected UnsupportedEncryptedVerity, got Ok"),
    }
}

#[test]
fn non_verity_descriptor_is_none() {
    let mut fs = crate::test_support::load_image("ext4.img");
    let ext = Ext::new(&mut fs).expect("open ext4.img");
    let inode = ext.inode(&mut fs, PLAIN_FILE_INO).expect("plain inode");
    assert!(!inode.is_verity());
    assert!(
        inode
            .verity_descriptor(&mut fs)
            .expect("descriptor query")
            .is_none()
    );
}
}
