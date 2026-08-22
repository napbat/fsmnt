//! ext4 fs-verity Merkle-tree verification for `VERITY_FL` inodes.
//!
//! fs-verity protects a file's contents with a SHA-256 (or SHA-512)
//! Merkle hash tree. This module parses the on-disk metadata and
//! verifies each data block against the tree on read, mirroring the
//! Linux kernel implementation in `fs/verity/` and `fs/ext4/verity.c`.
//!
//! # On-disk layout
//!
//! - The descriptor location is stored as an xattr in `name_index` 11
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
    #[must_use]
    pub fn algorithm(&self) -> VerityHashAlgorithm {
        self.algorithm
    }

    /// `log2` of the Merkle tree block size.
    #[must_use]
    pub fn log_blocksize(&self) -> u8 {
        self.log_blocksize
    }

    /// Size of the file the tree was built over (equals `i_size`).
    #[must_use]
    pub fn data_size(&self) -> u64 {
        self.data_size
    }

    /// Merkle tree root hash (`digest_len` bytes).
    #[must_use]
    pub fn root_hash(&self) -> &[u8] {
        &self.root_hash
    }

    /// Salt prepended to each block before hashing (`0..=32` bytes).
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Raw PKCS#7 signature bytes (empty when the file is unsigned).
    ///
    /// The signature chain is intentionally **not** validated.
    #[must_use]
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
        let salt_size = usize::from(raw.salt_size);
        if salt_size > MAX_SALT_SIZE {
            return Err(ExtError::InvalidVerityDescriptor {
                inode,
                reason: "salt_size exceeds 32 bytes",
            });
        }

        let sig_size =
            usize::try_from(raw.sig_size.get()).map_err(|_| ExtError::InvalidVerityDescriptor {
                inode,
                reason: "signature size exceeds addressable memory",
            })?;
        let signature_end =
            DESCRIPTOR_SIZE
                .checked_add(sig_size)
                .ok_or(ExtError::InvalidVerityDescriptor {
                    inode,
                    reason: "signature end offset overflow",
                })?;
        let signature = bytes
            .get(DESCRIPTOR_SIZE..signature_end)
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
#[derive(Clone, Copy)]
struct HashValue {
    bytes: [u8; 64],
    len: usize,
}

impl HashValue {
    const fn as_slice(&self) -> &[u8] {
        self.bytes.split_at(self.len).0
    }
}

fn hash_block(algorithm: VerityHashAlgorithm, salt: &[u8], block: &[u8]) -> HashValue {
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
    let mut padded_salt = [0_u8; 128];
    padded_salt[..salt.len()].copy_from_slice(salt);

    match algorithm {
        VerityHashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&padded_salt[..padded]);
            hasher.update(block);
            let digest = hasher.finalize();
            let mut bytes = [0_u8; 64];
            bytes[..32].copy_from_slice(&digest);
            HashValue { bytes, len: 32 }
        }
        VerityHashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(&padded_salt[..padded]);
            hasher.update(block);
            let digest = hasher.finalize();
            let mut bytes = [0_u8; 64];
            bytes.copy_from_slice(&digest);
            HashValue { bytes, len: 64 }
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
        let hashes_per_block = block_size
            / u64::try_from(digest_len).expect("supported fs-verity digest lengths fit in u64");
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
    /// Last tree block used at each level.
    ///
    /// Sequential reads reuse each block for all of its child hashes while
    /// memory remains bounded by `tree_depth * block_size` for large files.
    cache: Vec<Option<CachedTreeBlock>>,
}

struct CachedTreeBlock {
    index: Option<u64>,
    bytes: Vec<u8>,
}

/// Reads raw tree blocks for [`VerityVerifier::verify_data_block`].
///
/// Implemented over an [`ExtFile`](crate::file::ExtFile) so the
/// verifier stays decoupled from block resolution.
pub(crate) trait TreeBlockReader {
    /// Fill `buffer` from byte `offset` within the inode data stream.
    fn read_exact_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()>;
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
        let mut cache = Vec::with_capacity(params.num_levels());
        cache.resize_with(params.num_levels(), || None);
        Ok(Self {
            inode,
            descriptor,
            params,
            tree_offset,
            cache,
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
        let salt_len = self.descriptor.salt.len();
        let mut salt = [0_u8; MAX_SALT_SIZE];
        salt[..salt_len].copy_from_slice(&self.descriptor.salt);
        let salt = &salt[..salt_len];

        // fs/verity/verify.c verify_data_block: hash the data block,
        // then walk up checking each level's stored hash.
        let mut want = hash_block(alg, salt, block);
        let mut index = block_index;

        for level in 0..self.params.num_levels() {
            let tree_block_index = index / self.params.hashes_per_block;
            let slot = usize::try_from(index % self.params.hashes_per_block).map_err(|_| {
                ExtError::InvalidVerityDescriptor {
                    inode: self.inode,
                    reason: "Merkle hash slot exceeds addressable memory",
                }
            })?;
            let digest_len = self.params.digest_len;
            let tree_block = self.tree_block(reader, level, tree_block_index)?;
            let off = slot * digest_len;
            let stored = &tree_block[off..off + digest_len];
            if stored != want.as_slice() {
                return Err(ExtError::VerityHashMismatch {
                    inode: self.inode,
                    offset: file_offset,
                });
            }
            // The parent of this tree block is verified one level up.
            want = hash_block(alg, salt, tree_block);
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
    ) -> Result<&[u8]> {
        let level_block =
            self.params
                .level_start
                .get(level)
                .ok_or(ExtError::InvalidVerityDescriptor {
                    inode: self.inode,
                    reason: "tree level index out of range",
                })?;
        let byte_offset = self.tree_offset + (level_block + index) * self.params.block_size;
        let block_size = usize::try_from(self.params.block_size).map_err(|_| {
            ExtError::InvalidVerityDescriptor {
                inode: self.inode,
                reason: "verity block size exceeds addressable memory",
            }
        })?;
        let cached = self
            .cache
            .get_mut(level)
            .ok_or(ExtError::InvalidVerityDescriptor {
                inode: self.inode,
                reason: "tree level cache index out of range",
            })?
            .get_or_insert_with(|| CachedTreeBlock {
                index: None,
                bytes: alloc::vec![0_u8; block_size],
            });
        if cached.index != Some(index) {
            // Clear the key before I/O so a partial read can never be treated
            // as a valid cache hit after the caller retries.
            cached.index = None;
            reader.read_exact_at(byte_offset, &mut cached.bytes)?;
            cached.index = Some(index);
        }
        Ok(&cached.bytes)
    }
}

#[cfg(test)]
#[path = "verity_tests/mod.rs"]
mod tests;
