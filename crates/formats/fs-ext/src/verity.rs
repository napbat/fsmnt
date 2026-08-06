//! ext4 fs-verity Merkle-tree verification for `VERITY_FL` inodes.
//!
//! fs-verity protects a file's contents with a SHA-256 (or SHA-512)
//! Merkle hash tree. This module parses the on-disk metadata and
//! verifies each data block against the tree on read, mirroring the
//! Linux kernel implementation in `fs/verity/` and `fs/ext4/verity.c`.
//!
//! # On-disk layout
//!
//! - The descriptor location is stored as an xattr in name_index 11
//!   (`EXT4_XATTR_INDEX_VERITY`) with an empty name — a 12-byte
//!   `struct ext4_verity_descriptor_location` (kernel
//!   `ext4_get_verity_descriptor_location`).
//! - The Merkle tree begins at byte offset `round_up(i_size, 65536)`
//!   within the inode's data stream (kernel `ext4_verity_metadata_pos`).
//! - The `fsverity_descriptor` is 256 bytes followed by `sig_size`
//!   signature bytes; `desc_pos`/`desc_size` from the xattr locate it.
//!
//! Tree and descriptor blocks live in logical blocks of the inode
//! *past* `ceil(i_size / block_size)` — `i_size` does not cover them.

#![cfg(feature = "verity")]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sha2::{Digest, Sha256, Sha512};
use zerocopy::byteorder::{U32, U64};
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, Unaligned};

use crate::error::{ExtError, Result};

/// fs-verity always rounds the Merkle tree start up to 64 KiB within
/// the data stream (kernel `ext4_verity_metadata_pos`).
const VERITY_METADATA_ALIGN: u64 = 65536;

/// Size of the fixed `fsverity_descriptor` header, excluding the
/// trailing signature bytes (kernel `struct fsverity_descriptor`).
const DESCRIPTOR_SIZE: usize = 256;

/// `fsverity_descriptor.version` must be 1 (kernel `FS_VERITY_VERSION`).
const FSVERITY_VERSION: u8 = 1;

/// SHA-256 hash algorithm id (kernel `FS_VERITY_HASH_ALG_SHA256`).
const HASH_ALG_SHA256: u8 = 1;
/// SHA-512 hash algorithm id (kernel `FS_VERITY_HASH_ALG_SHA512`).
const HASH_ALG_SHA512: u8 = 2;

/// Maximum salt length (kernel `FS_VERITY_MAX_SALT_SIZE`).
const MAX_SALT_SIZE: usize = 32;

/// On-disk `struct ext4_verity_descriptor_location` (12 bytes).
///
/// Mirrors `fs/ext4/verity.c` — stored as the index-11, empty-name
/// xattr value by `ext4_write_verity_descriptor`.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDescriptorLocation {
    /// Length in bytes of the `fsverity_descriptor` (+ signature).
    desc_size: U32<LE>,
    /// Byte offset of the descriptor within the file's data stream.
    desc_pos: U64<LE>,
}

const _: () = assert!(
    core::mem::size_of::<RawDescriptorLocation>() == 12,
    "RawDescriptorLocation must be exactly 12 bytes"
);

/// On-disk `struct fsverity_descriptor` header (256 bytes).
///
/// Mirrors `include/uapi/linux/fsverity.h`. Followed on disk by
/// `sig_size` bytes of PKCS#7 signature.
#[derive(FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawDescriptor {
    /// Descriptor format version; must be 1.
    version: u8,
    /// Hash algorithm: 1 = SHA-256, 2 = SHA-512.
    hash_algorithm: u8,
    /// `log2` of the Merkle tree block size.
    log_blocksize: u8,
    /// Salt length in bytes (`0..=32`).
    salt_size: u8,
    /// Length of the trailing PKCS#7 signature (0 if unsigned).
    sig_size: U32<LE>,
    /// Size of the file the Merkle tree was built over (== `i_size`).
    data_size: U64<LE>,
    /// Merkle tree root hash (only the first hash-len bytes are used).
    root_hash: [u8; 64],
    /// Salt prepended to every block before hashing.
    salt: [u8; 32],
    /// Reserved; must be zero.
    reserved: [u8; 144],
}

const _: () = assert!(
    core::mem::size_of::<RawDescriptor>() == DESCRIPTOR_SIZE,
    "RawDescriptor must be exactly 256 bytes"
);

/// fs-verity hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerityHashAlgorithm {
    /// SHA-256 (32-byte digest).
    Sha256,
    /// SHA-512 (64-byte digest).
    Sha512,
}

impl VerityHashAlgorithm {
    /// Digest length in bytes.
    fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// Parsed `fsverity_descriptor` for a `VERITY_FL` inode.
///
/// Exposes the hash algorithm, root hash, protected data size and the
/// raw PKCS#7 signature bytes. The signature chain is **not** validated
/// (out of scope) — `signature()` returns the bytes verbatim.
#[derive(Debug, Clone)]
pub struct VerityDescriptor {
    algorithm: VerityHashAlgorithm,
    log_blocksize: u8,
    data_size: u64,
    root_hash: Vec<u8>,
    salt: Vec<u8>,
    signature: Vec<u8>,
}

impl VerityDescriptor {
    /// Hash algorithm used by the Merkle tree.
    pub fn algorithm(&self) -> VerityHashAlgorithm {
        self.algorithm
    }

    /// `log2` of the Merkle tree block size.
    pub fn log_blocksize(&self) -> u8 {
        self.log_blocksize
    }

    /// Size of the file the tree was built over (equals `i_size`).
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    /// Merkle tree root hash (`digest_len` bytes).
    pub fn root_hash(&self) -> &[u8] {
        &self.root_hash
    }

    /// Salt prepended to each block before hashing (`0..=32` bytes).
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Raw PKCS#7 signature bytes (empty when the file is unsigned).
    ///
    /// The signature chain is intentionally **not** validated.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Parse the descriptor location from an index-11 verity xattr value.
    pub(crate) fn parse_location(inode: u32, value: &[u8]) -> Result<(u64, u32)> {
        let raw = RawDescriptorLocation::ref_from_bytes(value).map_err(|_| {
            ExtError::InvalidVerityDescriptor {
                inode,
                reason: "verity location xattr is not 12 bytes",
            }
        })?;
        Ok((raw.desc_pos.get(), raw.desc_size.get()))
    }

    /// Parse a descriptor from its 256-byte header plus signature bytes.
    pub(crate) fn parse(inode: u32, bytes: &[u8]) -> Result<Self> {
        let raw = RawDescriptor::ref_from_bytes(bytes.get(..DESCRIPTOR_SIZE).ok_or(
            ExtError::InvalidVerityDescriptor {
                inode,
                reason: "descriptor shorter than 256 bytes",
            },
        )?)
        .map_err(|_| ExtError::InvalidVerityDescriptor {
            inode,
            reason: "descriptor header failed to parse",
        })?;

        if raw.version != FSVERITY_VERSION {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "unsupported descriptor version",
            });
        }
        let algorithm = match raw.hash_algorithm {
            HASH_ALG_SHA256 => VerityHashAlgorithm::Sha256,
            HASH_ALG_SHA512 => VerityHashAlgorithm::Sha512,
            _ => {
                return Err(ExtError::InvalidVerityDescriptor {
                    inode,
                    reason: "unsupported verity hash algorithm",
                });
            }
        };
        let salt_size = raw.salt_size as usize;
        if salt_size > MAX_SALT_SIZE {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "salt_size exceeds 32 bytes",
            });
        }

        let sig_size = raw.sig_size.get() as usize;
        let signature = bytes
            .get(DESCRIPTOR_SIZE..DESCRIPTOR_SIZE + sig_size)
            .ok_or(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "descriptor truncated before end of signature",
            })?
            .to_vec();

        Ok(Self {
            algorithm,
            log_blocksize: raw.log_blocksize,
            data_size: raw.data_size.get(),
            root_hash: raw.root_hash[..algorithm.digest_len()].to_vec(),
            salt: raw.salt[..salt_size].to_vec(),
            signature,
        })
    }
}

/// Hash one Merkle block (data or tree) the way the kernel does.
///
/// Mirrors `fsverity_hash_block` in `fs/verity/hash_algs.c`: the salt
/// is prepended, padded up to `roundup(salt_size, hash_alg->block_size)`
/// (the internal block size — 64 for SHA-256, 128 for SHA-512), then the
/// block bytes are appended. With an empty salt this is just `H(block)`.
fn hash_block(algorithm: VerityHashAlgorithm, salt: &[u8], block: &[u8]) -> Vec<u8> {
    // fs/verity/hash_algs.c: hashstate is the salt padded to the
    // algorithm's internal block size; padding bytes are zero.
    let salt_block = match algorithm {
        VerityHashAlgorithm::Sha256 => 64usize,
        VerityHashAlgorithm::Sha512 => 128usize,
    };
    let padded = if salt.is_empty() {
        0
    } else {
        salt.len().div_ceil(salt_block) * salt_block
    };
    let mut padded_salt = Vec::with_capacity(padded);
    padded_salt.extend_from_slice(salt);
    padded_salt.resize(padded, 0);

    match algorithm {
        VerityHashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&padded_salt);
            hasher.update(block);
            hasher.finalize().to_vec()
        }
        VerityHashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(&padded_salt);
            hasher.update(block);
            hasher.finalize().to_vec()
        }
    }
}

/// Geometry of a Merkle tree, derived from the descriptor.
///
/// Mirrors the per-level arithmetic in `fsverity_init_merkle_tree_params`
/// (`fs/verity/open.c`). `level_start[i]` is the tree-block offset of
/// level `i` relative to the tree start; levels are laid out top-level
/// first, so `level_start[num_levels-1] == 0` and level 0 (leaves) is
/// last.
#[derive(Debug, Clone)]
struct MerkleTreeParams {
    block_size: u64,
    digest_len: usize,
    /// Number of hashes that fit in one tree block (`block_size / H`).
    hashes_per_block: u64,
    /// `level_start[i]` — block offset of level `i` from the tree start.
    level_start: Vec<u64>,
}

impl MerkleTreeParams {
    /// Compute tree geometry from `data_size` and block size.
    ///
    /// `fsverity_init_merkle_tree_params`: level 0 holds the hashes of
    /// the data blocks, so its tree-block count is
    /// `ceil(num_data_blocks / hashes_per_block)`. Each higher level
    /// hashes the level below, giving `ceil(prev_blocks / hpb)` tree
    /// blocks; iteration stops once a level holds a single block (the
    /// top level / root).
    fn new(
        inode: u32,
        algorithm: VerityHashAlgorithm,
        log_blocksize: u8,
        data_size: u64,
    ) -> Result<Self> {
        if !(10..=16).contains(&log_blocksize) {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "log_blocksize out of supported range",
            });
        }
        let block_size = 1u64 << log_blocksize;
        let digest_len = algorithm.digest_len();
        let hashes_per_block = block_size / digest_len as u64;
        if hashes_per_block < 2 {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "block holds fewer than two hashes",
            });
        }

        // fs/verity/open.c: level_blocks[] computed bottom-up. Each
        // level's tree-block count is `ceil(items_below / hpb)`, where
        // the items below level 0 are the data blocks themselves.
        let data_blocks = data_size.div_ceil(block_size).max(1);
        let mut level_blocks: Vec<u64> = Vec::new();
        let mut items = data_blocks;
        loop {
            let blocks = items.div_ceil(hashes_per_block);
            level_blocks.push(blocks);
            if blocks <= 1 {
                break;
            }
            items = blocks;
        }

        // Levels are laid out top-level first: assign offsets while
        // iterating from the top level down to level 0.
        let num_levels = level_blocks.len();
        let mut level_start = alloc::vec![0u64; num_levels];
        let mut offset = 0u64;
        for level in (0..num_levels).rev() {
            level_start[level] = offset;
            offset += level_blocks[level];
        }

        Ok(Self {
            block_size,
            digest_len,
            hashes_per_block,
            level_start,
        })
    }

    /// Number of tree levels (`>= 1`; 1 means the root covers leaves).
    fn num_levels(&self) -> usize {
        self.level_start.len()
    }
}

/// Verifies data blocks of a `VERITY_FL` inode against its Merkle tree.
///
/// Holds the parsed descriptor and tree geometry plus a cache of
/// already-verified tree blocks, so a sequential read does not
/// re-verify the same interior tree block repeatedly.
pub(crate) struct VerityVerifier {
    inode: u32,
    descriptor: VerityDescriptor,
    params: MerkleTreeParams,
    /// First byte of the Merkle tree within the inode's data stream.
    tree_offset: u64,
    /// Cache keyed by `(level, block_index)` of verified tree blocks.
    cache: BTreeMap<(usize, u64), Vec<u8>>,
}

/// Reads raw tree blocks for [`VerityVerifier::verify_data_block`].
///
/// Implemented over an [`ExtFile`](crate::file::ExtFile) so the
/// verifier stays decoupled from block resolution.
pub(crate) trait TreeBlockReader {
    /// Read `len` bytes at byte `offset` within the inode data stream.
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>>;
}

impl VerityVerifier {
    /// Build a verifier from a parsed descriptor and the file `i_size`.
    pub(crate) fn new(inode: u32, descriptor: VerityDescriptor, i_size: u64) -> Result<Self> {
        let params = MerkleTreeParams::new(
            inode,
            descriptor.algorithm,
            descriptor.log_blocksize,
            descriptor.data_size,
        )?;
        if descriptor.data_size != i_size {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "descriptor data_size does not match inode i_size",
            });
        }
        // fs/ext4/verity.c ext4_verity_metadata_pos: tree starts at the
        // 64 KiB-aligned offset past the protected data.
        let tree_offset = i_size.div_ceil(VERITY_METADATA_ALIGN) * VERITY_METADATA_ALIGN;
        Ok(Self {
            inode,
            descriptor,
            params,
            tree_offset,
            cache: BTreeMap::new(),
        })
    }

    /// Verify the data block containing byte `file_offset`.
    ///
    /// `block` is the full `block_size`-byte data block (zero-padded
    /// past `data_size` for the final block, exactly as the kernel
    /// hashes it in `verify_data_block`). Returns
    /// [`ExtError::VerityHashMismatch`] naming `file_offset` on any
    /// mismatch along the path from the leaf up to the root.
    pub(crate) fn verify_data_block<R: TreeBlockReader>(
        &mut self,
        reader: &mut R,
        file_offset: u64,
        block: &[u8],
    ) -> Result<()> {
        let block_index = file_offset / self.params.block_size;
        let alg = self.descriptor.algorithm;
        let salt = self.descriptor.salt.clone();

        // fs/verity/verify.c verify_data_block: hash the data block,
        // then walk up checking each level's stored hash.
        let mut want = hash_block(alg, &salt, block);
        let mut index = block_index;

        for level in 0..self.params.num_levels() {
            let tree_block_index = index / self.params.hashes_per_block;
            let slot = (index % self.params.hashes_per_block) as usize;
            let tree_block = self.tree_block(reader, level, tree_block_index)?;
            let off = slot * self.params.digest_len;
            let stored = &tree_block[off..off + self.params.digest_len];
            if stored != want.as_slice() {
                return Err(ExtError::VerityHashMismatch {
                    inode: self.inode,
                    offset: file_offset,
                });
            }
            // The parent of this tree block is verified one level up.
            want = hash_block(alg, &salt, &tree_block);
            index = tree_block_index;
        }

        // After the loop `want` is the hash of the top-level block;
        // it must equal the descriptor root hash.
        if want.as_slice() != self.descriptor.root_hash.as_slice() {
            return Err(ExtError::VerityHashMismatch {
                inode: self.inode,
                offset: file_offset,
            });
        }
        Ok(())
    }

    /// Fetch a tree block at `(level, index)`, using the cache.
    ///
    /// A cached block has already been confirmed against its parent;
    /// freshly-read blocks are verified by the caller's level walk.
    fn tree_block<R: TreeBlockReader>(
        &mut self,
        reader: &mut R,
        level: usize,
        index: u64,
    ) -> Result<Vec<u8>> {
        if let Some(cached) = self.cache.get(&(level, index)) {
            return Ok(cached.clone());
        }
        let level_block =
            self.params
                .level_start
                .get(level)
                .ok_or(ExtError::InvalidVerityDescriptor {
                    inode: self.inode,
                    reason: "tree level index out of range",
                })?;
        let byte_offset = self.tree_offset + (level_block + index) * self.params.block_size;
        let block = reader.read_at(byte_offset, self.params.block_size as usize)?;
        self.cache.insert((level, index), block.clone());
        Ok(block)
    }
}

#[cfg(test)]
mod tests {
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
        hash_block(alg, salt, &block)
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
        let root = hash_block(alg, salt, &top_block);

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
            log_blocksize: block_size.trailing_zeros() as u8,
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
    }

    impl TreeBlockReader for MemReader {
        fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
            let rel = (offset - self.tree_offset) as usize;
            let mut out = alloc::vec![0u8; len];
            let end = (rel + len).min(self.tree.len());
            if rel < self.tree.len() {
                out[..end - rel].copy_from_slice(&self.tree[rel..end]);
            }
            Ok(out)
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
        };
        let block = padded_block(&data, 0, block_size);
        verifier.verify_data_block(&mut reader, 0, &block).unwrap();
    }

    #[test]
    fn multi_level_tree_verifies_all_blocks() {
        // block_size 1024 holds 32 hashes; >32 data blocks forces 2+ levels.
        let block_size = 1024;
        let data: Vec<u8> = (0..40 * block_size).map(|i| (i % 251) as u8).collect();
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
        };
        for b in 0..40 {
            let block = padded_block(&data, b, block_size);
            verifier
                .verify_data_block(&mut reader, (b * block_size) as u64, &block)
                .unwrap();
        }
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
        let data: Vec<u8> = (0..40 * block_size).map(|i| (i % 191) as u8).collect();
        let (descriptor, mut tree) = build_tree(&data, block_size, &[]);
        // Flip a byte in a leaf-level tree block (last level in the file).
        let last = tree.len() - 1;
        tree[last] ^= 0x01;
        let mut verifier = VerityVerifier::new(5, descriptor, data.len() as u64).unwrap();
        let mut reader = MemReader {
            tree_offset: verifier.tree_offset,
            tree,
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
    /// VERITY_FL inode flag.
    const VERITY_FL: u32 = 0x0010_0000;
    /// RO_COMPAT_VERITY superblock feature bit.
    const RO_COMPAT_VERITY: u32 = 0x8000;
    /// EXT4_XATTR_INDEX_VERITY (kernel `fs/ext4/xattr.h`).
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
        (table * BLOCK_SIZE as u64) as usize + (ino - 1) as usize * INODE_SIZE
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
        inode[4..8].copy_from_slice(&(DATA_SIZE as u32).to_le_bytes());
        inode[0x6C..0x70].copy_from_slice(&0u32.to_le_bytes());
        // i_flags (0x20): keep EXTENTS_FL (0x80000), add VERITY_FL.
        let flags = u32::from_le_bytes(inode[0x20..0x24].try_into().expect("4 bytes"));
        inode[0x20..0x24].copy_from_slice(&(flags | VERITY_FL).to_le_bytes());
        // i_blocks_lo (0x1C): 512-byte sectors covering the whole run.
        let sectors = u64::from(total_logical_blocks) * (BLOCK_SIZE as u64 / 512);
        inode[0x1C..0x20].copy_from_slice(&(sectors as u32).to_le_bytes());

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
        ib[16..18].copy_from_slice(&(total_logical_blocks as u16).to_le_bytes());
        ib[18..20].copy_from_slice(&0u16.to_le_bytes());
        ib[20..24].copy_from_slice(&(FIRST_FREE_PHYS as u32).to_le_bytes());

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
        let e_value_offs = (value_at - (xstart + 4)) as u16;
        image[entry] = 0; // e_name_len
        image[entry + 1] = XATTR_INDEX_VERITY; // e_name_index
        image[entry + 2..entry + 4].copy_from_slice(&e_value_offs.to_le_bytes());
        image[entry + 4..entry + 8].copy_from_slice(&0u32.to_le_bytes()); // e_value_inum
        image[entry + 8..entry + 12].copy_from_slice(&(value.len() as u32).to_le_bytes()); // e_value_size
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

        let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251) as u8).collect();
        let (root, tree, tree_blocks) = build_merkle_tree(&data);
        let descriptor = build_descriptor(&root, DATA_SIZE as u64);

        let data_blocks = DATA_SIZE.div_ceil(BLOCK_SIZE);
        // Logical layout: [data 0..data_blocks][gap][tree @16][descriptor].
        let total_logical = TREE_LOGICAL_BLOCK as usize + tree_blocks + 1;

        // Write data blocks.
        for b in 0..data_blocks {
            let phys = (FIRST_FREE_PHYS as usize + b) * BLOCK_SIZE;
            image[phys..phys + BLOCK_SIZE].copy_from_slice(&padded_block(&data, b));
        }
        // Zero the gap blocks between data and the tree.
        for b in data_blocks..TREE_LOGICAL_BLOCK as usize {
            let phys = (FIRST_FREE_PHYS as usize + b) * BLOCK_SIZE;
            image[phys..phys + BLOCK_SIZE].fill(0);
        }
        // Write the Merkle tree starting at logical block 16.
        let tree_phys = (FIRST_FREE_PHYS as usize + TREE_LOGICAL_BLOCK as usize) * BLOCK_SIZE;
        image[tree_phys..tree_phys + tree.len()].copy_from_slice(&tree);
        // Write the descriptor in the block following the tree.
        let desc_phys = tree_phys + tree.len();
        image[desc_phys..desc_phys + descriptor.len()].copy_from_slice(&descriptor);

        rewrite_inode(&mut image, total_logical as u32);
        enable_verity_feature(&mut image);
        image
    }

    /// Physical byte offset of data block `index` in a synthesized
    /// image.
    fn data_block_phys(index: usize) -> usize {
        (FIRST_FREE_PHYS as usize + index) * BLOCK_SIZE
    }

    /// Physical byte offset of the first Merkle-tree block.
    fn tree_block_phys() -> usize {
        (FIRST_FREE_PHYS as usize + TREE_LOGICAL_BLOCK as usize) * BLOCK_SIZE
    }

    #[test]
    fn clean_verity_file_reads_and_verifies() {
        let image = build_clean_image();
        let mut fs = std::io::Cursor::new(image);
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
        let expected: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251) as u8).collect();
        assert_eq!(out, expected, "clean verity read must return file data");
    }

    #[test]
    fn verity_descriptor_is_introspectable() {
        let image = build_clean_image();
        let mut fs = std::io::Cursor::new(image);
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

        let data: Vec<u8> = (0..DATA_SIZE).map(|i| (i % 251) as u8).collect();
        let (root, _, _) = build_merkle_tree(&data);
        assert_eq!(descriptor.root_hash(), root);
    }

    #[test]
    fn tampered_data_block_returns_hash_mismatch() {
        let mut image = build_clean_image();
        // Flip a byte inside data block 1 (file offset 4096..8192).
        image[data_block_phys(1) + 10] ^= 0xFF;

        let mut fs = std::io::Cursor::new(image);
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

        let mut fs = std::io::Cursor::new(image);
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
        let mut fs = std::io::Cursor::new(image);
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

        let mut fs = std::io::Cursor::new(image);
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
