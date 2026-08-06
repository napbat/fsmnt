//! Sealed-volume integrity metadata and file-content hash verification.
//!
//! A sealed volume — the macOS Signed System Volume — carries integrity
//! metadata (`integrity_meta_phys_t`) and per-file content hashes. Verifying
//! a file against its stored hash detects tampering of the system volume.
//!
//! Apple File System Reference, `15-sealed-volumes.md`.

use alloc::vec;
use alloc::vec::Vec;

use bitflags::bitflags;
use sha2::{Digest, Sha256, Sha384, Sha512, Sha512_256};

use crate::catalog::{Catalog, J_KEY_SIZE, JObjType};
use crate::error::{ApfsError, Result};
use crate::extent::File;
use crate::fext::FextTree;
use crate::io::{Read, Seek};
use crate::object::OBJ_PHYS_SIZE;

/// Largest hash this parser handles (`APFS_HASH_MAX_SIZE`).
pub const APFS_HASH_MAX_SIZE: usize = 64;
/// Bit shift selecting the type from a `j_file_info_key_t.info_and_lba`
/// (`J_FILE_INFO_TYPE_SHIFT`).
const J_FILE_INFO_TYPE_SHIFT: u64 = 56;
/// Mask selecting the LBA from `info_and_lba` (`J_FILE_INFO_LBA_MASK`).
const J_FILE_INFO_LBA_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;
/// `info_and_lba` type for a file-data-hash record (`APFS_FILE_INFO_DATA_HASH`).
const APFS_FILE_INFO_DATA_HASH: u64 = 1;
/// Offset of the fields following `obj_phys_t` in `integrity_meta_phys_t`.
const IM_FIELDS_OFFSET: usize = OBJ_PHYS_SIZE;
/// Size of the fixed `integrity_meta_phys_t` fields (before the root hash).
const INTEGRITY_META_FIXED_SIZE: usize = OBJ_PHYS_SIZE + 4 + 4 + 4 + 4 + 8 + 72;

bitflags! {
    /// Integrity-metadata flags (`integrity_meta_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IntegrityMetaFlags: u32 {
        /// The volume's seal has been broken by a modification.
        const SEAL_BROKEN = 1 << 0;
    }
}

/// A hash algorithm used by a sealed volume (`apfs_hash_type_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApfsHashType {
    /// SHA-256.
    Sha256,
    /// SHA-512/256.
    Sha512_256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// A hash-type value this parser does not recognize.
    Unknown(u32),
}

impl ApfsHashType {
    /// Decodes an `apfs_hash_type_t` value.
    #[must_use]
    pub fn from_value(value: u32) -> Self {
        match value {
            1 => Self::Sha256,
            2 => Self::Sha512_256,
            3 => Self::Sha384,
            4 => Self::Sha512,
            other => Self::Unknown(other),
        }
    }

    /// The digest size of the hash, in bytes, or `None` for an unknown type.
    #[must_use]
    pub fn hash_size(self) -> Option<usize> {
        match self {
            Self::Sha256 | Self::Sha512_256 => Some(32),
            Self::Sha384 => Some(48),
            Self::Sha512 => Some(64),
            Self::Unknown(_) => None,
        }
    }

    /// Computes the hash of `data` with this algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Unsupported`] for an unknown hash type.
    pub fn digest(self, data: &[u8]) -> Result<Vec<u8>> {
        let hash = match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha512_256 => Sha512_256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
            Self::Unknown(_) => {
                return Err(ApfsError::Unsupported("unrecognized integrity hash type"));
            }
        };
        Ok(hash)
    }

    /// Computes the hash of `data` and compares it to `expected`.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Unsupported`] for an unknown hash type.
    pub fn verify(self, data: &[u8], expected: &[u8]) -> Result<bool> {
        Ok(self.digest(data)? == expected)
    }
}

/// Parsed sealed-volume integrity metadata (`integrity_meta_phys_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityMeta {
    /// The structure's version (1 or 2).
    pub version: u32,
    /// Integrity-metadata flags.
    pub flags: IntegrityMetaFlags,
    /// The hash algorithm the volume's hashes use.
    pub hash_type: ApfsHashType,
    /// Transaction id at which the seal was broken, or zero if intact.
    pub broken_xid: u64,
    /// The volume's root hash.
    pub root_hash: Vec<u8>,
}

impl IntegrityMeta {
    /// Parses integrity metadata from its block.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short block, or
    /// [`ApfsError::Malformed`] when the root-hash offset is out of range.
    ///
    /// # Panics
    ///
    /// Panics only if a fixed-width integrity field ceases to fit the minimum
    /// block length checked before parsing.
    pub fn parse(block: &[u8]) -> Result<Self> {
        if block.len() < INTEGRITY_META_FIXED_SIZE {
            return Err(ApfsError::Truncated {
                structure: "integrity_meta_phys_t",
                expected: INTEGRITY_META_FIXED_SIZE,
                actual: block.len(),
            });
        }
        let u32_at =
            |off: usize| u32::from_le_bytes(block[off..off + 4].try_into().expect("4 bytes"));
        let version = u32_at(IM_FIELDS_OFFSET);
        let flags = IntegrityMetaFlags::from_bits_retain(u32_at(IM_FIELDS_OFFSET + 4));
        let hash_type = ApfsHashType::from_value(u32_at(IM_FIELDS_OFFSET + 8));
        let root_hash_offset = u32_at(IM_FIELDS_OFFSET + 12) as usize;
        let broken_xid = u64::from_le_bytes(
            block[IM_FIELDS_OFFSET + 16..IM_FIELDS_OFFSET + 24]
                .try_into()
                .expect("8 bytes"),
        );

        let hash_size = hash_type.hash_size().unwrap_or(APFS_HASH_MAX_SIZE);
        let root_hash = block
            .get(root_hash_offset..root_hash_offset + hash_size)
            .ok_or(ApfsError::Malformed {
                structure: "integrity_meta_phys_t",
                reason: "root-hash offset is out of range",
            })?
            .to_vec();

        Ok(Self {
            version,
            flags,
            hash_type,
            broken_xid,
            root_hash,
        })
    }

    /// Whether the volume's seal has been broken.
    #[must_use]
    pub fn is_seal_broken(&self) -> bool {
        self.flags.contains(IntegrityMetaFlags::SEAL_BROKEN) || self.broken_xid != 0
    }
}

/// A per-file content hash (`j_file_data_hash_val_t`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDataHash {
    /// Length, in blocks, of the data segment that was hashed.
    pub hashed_len: u16,
    /// The hash of that segment.
    pub hash: Vec<u8>,
}

impl FileDataHash {
    /// Parses a `j_file_data_hash_val_t` value.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short value or one whose hash
    /// runs past the record.
    pub fn parse(value: &[u8]) -> Result<Self> {
        if value.len() < 3 {
            return Err(ApfsError::Truncated {
                structure: "j_file_data_hash_val_t",
                expected: 3,
                actual: value.len(),
            });
        }
        let hashed_len = u16::from_le_bytes([value[0], value[1]]);
        let hash_size = usize::from(value[2]);
        let hash = value.get(3..3 + hash_size).ok_or(ApfsError::Truncated {
            structure: "j_file_data_hash_val_t",
            expected: 3 + hash_size,
            actual: value.len(),
        })?;
        Ok(Self {
            hashed_len,
            hash: hash.to_vec(),
        })
    }

    /// Verifies `data` against this stored hash under `hash_type`.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Unsupported`] for an unknown hash type.
    pub fn verify(&self, hash_type: ApfsHashType, data: &[u8]) -> Result<bool> {
        hash_type.verify(data, &self.hash)
    }
}

/// A file-content block whose hash does not match the sealed-volume
/// integrity record — the structured outcome of detected tampering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    /// Object identifier of the file (its inode number).
    pub obj_id: u64,
    /// Byte offset of the mismatching segment within the file.
    pub offset: u64,
    /// Length of the mismatching segment, in bytes.
    pub length: u64,
}

/// The result of verifying every file-data hash of a sealed volume.
#[derive(Debug, Clone)]
pub struct SealReport {
    /// The hash algorithm the volume's integrity metadata declares.
    pub hash_type: ApfsHashType,
    /// Number of file-data-hash segments verified.
    pub segments_verified: usize,
    /// Every segment whose content failed verification.
    pub mismatches: Vec<HashMismatch>,
}

impl SealReport {
    /// Whether every verified segment matched its stored hash.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// The outcome of a whole-volume seal verification.
#[derive(Debug, Clone)]
pub enum SealVerification {
    /// The volume is not a sealed volume — nothing to verify.
    NotSealed,
    /// The volume is sealed but its integrity metadata marks the seal
    /// already broken; per-file verification is not attempted.
    SealBroken,
    /// The volume was verified; the report lists any mismatches.
    Verified(SealReport),
}

/// Verifies every file-data hash recorded by a sealed volume.
///
/// Walks the catalog's `FILE_INFO` records, and for each data-hash record
/// reads the covered file segment, hashes it with the volume's algorithm,
/// and compares it to the stored hash (Apple File System Reference,
/// `15-sealed-volumes.md`, `j_file_info_key_t`). A segment that fails is
/// recorded as a [`HashMismatch`]; verification continues so the report is
/// complete.
///
/// A sealed volume keeps its file extents in the dedicated file-extent tree
/// (`fext`), not as catalog `FILE_EXTENT` records, so extents are resolved
/// through [`FextTree`]. The fext tree is keyed by the file's data-stream
/// `private_id`, which equals the `FILE_INFO` record's object id for the
/// uncloned files of a system volume.
///
/// # Errors
///
/// Returns [`ApfsError::Unsupported`] for an unknown hash type, and
/// propagates catalog-walk, fext-tree, and I/O errors.
///
/// # Panics
///
/// Panics only if a catalog key slice returned for an exact eight-byte range
/// does not contain eight bytes.
pub fn verify_file_hashes<T: Read + Seek>(
    catalog: &Catalog,
    fext: &FextTree,
    reader: &mut T,
    integrity: &IntegrityMeta,
    block_size: u32,
) -> Result<SealReport> {
    let mut report = SealReport {
        hash_type: integrity.hash_type,
        segments_verified: 0,
        mismatches: Vec::new(),
    };
    // Resolve the whole file-extent tree once; every hashed file then reads
    // through its own extents without re-walking the tree.
    let extents_by_id = fext.collect(reader, block_size)?;
    for record in catalog.records_of_kind(reader, JObjType::FileInfo)? {
        // j_file_info_key_t: a j_key_t header followed by info_and_lba.
        let Some(field) = record.key.get(J_KEY_SIZE..J_KEY_SIZE + 8) else {
            continue;
        };
        let info_and_lba = u64::from_le_bytes(field.try_into().expect("8 bytes"));
        // Only data-hash records carry a content hash to verify.
        if info_and_lba >> J_FILE_INFO_TYPE_SHIFT != APFS_FILE_INFO_DATA_HASH {
            continue;
        }
        let lba = info_and_lba & J_FILE_INFO_LBA_MASK;
        let file_hash = FileDataHash::parse(&record.value)?;
        let obj_id = record.key_header.obj_id;

        let offset = lba.saturating_mul(u64::from(block_size));
        let length = u64::from(file_hash.hashed_len).saturating_mul(u64::from(block_size));
        let file = File::from_extents(
            offset.saturating_add(length),
            extents_by_id.get(&obj_id).cloned().unwrap_or_default(),
        );
        let segment_len = usize::try_from(length).map_err(|_| ApfsError::Malformed {
            structure: "j_file_data_hash_val_t",
            reason: "hashed segment length exceeds the addressable range",
        })?;
        let mut segment = vec![0u8; segment_len];
        let read = file.read_at(reader, block_size, offset, &mut segment)?;
        segment.truncate(read);

        report.segments_verified += 1;
        if !file_hash.verify(integrity.hash_type, &segment)? {
            report.mismatches.push(HashMismatch {
                obj_id,
                offset,
                length,
            });
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_type_sizes() {
        assert_eq!(ApfsHashType::from_value(1).hash_size(), Some(32));
        assert_eq!(ApfsHashType::from_value(3).hash_size(), Some(48));
        assert_eq!(ApfsHashType::from_value(4).hash_size(), Some(64));
        assert_eq!(ApfsHashType::from_value(99).hash_size(), None);
    }

    #[test]
    fn sha256_digest_and_verify() {
        let hash = ApfsHashType::Sha256.digest(b"apfs").unwrap();
        assert_eq!(hash.len(), 32);
        assert!(ApfsHashType::Sha256.verify(b"apfs", &hash).unwrap());
        assert!(!ApfsHashType::Sha256.verify(b"tampered", &hash).unwrap());
    }

    #[test]
    fn unknown_hash_type_cannot_digest() {
        assert!(matches!(
            ApfsHashType::Unknown(7).digest(b"x"),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn parses_integrity_metadata() {
        let mut block = vec![0u8; 256];
        let off = IM_FIELDS_OFFSET;
        block[off..off + 4].copy_from_slice(&2u32.to_le_bytes()); // version
        block[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes()); // SHA-256
        block[off + 12..off + 16].copy_from_slice(
            &u32::try_from(INTEGRITY_META_FIXED_SIZE)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        // Root hash right after the fixed fields.
        block[INTEGRITY_META_FIXED_SIZE..INTEGRITY_META_FIXED_SIZE + 32].fill(0x5A);
        let im = IntegrityMeta::parse(&block).unwrap();
        assert_eq!(im.version, 2);
        assert_eq!(im.hash_type, ApfsHashType::Sha256);
        assert_eq!(im.root_hash, vec![0x5A; 32]);
        assert!(!im.is_seal_broken());
    }

    #[test]
    fn broken_seal_is_reported() {
        let mut block = vec![0u8; 256];
        let off = IM_FIELDS_OFFSET;
        block[off + 4..off + 8]
            .copy_from_slice(&IntegrityMetaFlags::SEAL_BROKEN.bits().to_le_bytes());
        block[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
        block[off + 12..off + 16].copy_from_slice(
            &u32::try_from(INTEGRITY_META_FIXED_SIZE)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        assert!(IntegrityMeta::parse(&block).unwrap().is_seal_broken());
    }

    #[test]
    fn integrity_meta_rejects_a_bad_root_hash_offset() {
        let mut block = vec![0u8; INTEGRITY_META_FIXED_SIZE];
        let off = IM_FIELDS_OFFSET;
        block[off + 8..off + 12].copy_from_slice(&1u32.to_le_bytes());
        block[off + 12..off + 16].copy_from_slice(&100_000u32.to_le_bytes());
        assert!(matches!(
            IntegrityMeta::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn parses_and_verifies_a_file_data_hash() {
        let content = b"system file content";
        let digest = ApfsHashType::Sha256.digest(content).unwrap();
        let mut value = Vec::new();
        value.extend_from_slice(&4u16.to_le_bytes()); // hashed_len
        value.push(u8::try_from(digest.len()).expect("the test fixture value fits in u8")); // hash_size
        value.extend_from_slice(&digest);
        let fdh = FileDataHash::parse(&value).unwrap();
        assert_eq!(fdh.hashed_len, 4);
        assert!(fdh.verify(ApfsHashType::Sha256, content).unwrap());
        assert!(!fdh.verify(ApfsHashType::Sha256, b"tampered").unwrap());
    }

    #[test]
    fn file_data_hash_rejects_a_short_value() {
        assert!(matches!(
            FileDataHash::parse(&[0u8, 0, 32]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn integrity_meta_fixed_size_is_one_hundred_twenty_eight_bytes() {
        // obj_phys_t (OBJ_PHYS_SIZE = 32) + version u32 + flags u32
        // + hash_type u32 + root_hash_offset u32 + broken_xid u64
        // + 72 bytes of reserved / pad fields = 128 bytes total.
        // Wrong arithmetic in the const would mis-size the truncation guard
        // and let undersized blocks past `IntegrityMeta::parse`.
        assert_eq!(INTEGRITY_META_FIXED_SIZE, 128);
        assert_eq!(
            INTEGRITY_META_FIXED_SIZE,
            OBJ_PHYS_SIZE + 4 + 4 + 4 + 4 + 8 + 72
        );
    }

    #[test]
    fn file_data_hash_rejects_a_two_byte_value() {
        // Two bytes is below the 3-byte minimum; the guard must reject it
        // rather than indexing past the buffer to read `value[2]`.
        assert!(matches!(
            FileDataHash::parse(&[0u8, 0]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn file_data_hash_accepts_a_three_byte_zero_hash_value() {
        // Three bytes — the minimum — with hash_size=0 is the empty-hash
        // record and must parse, not be rejected by a `<=` guard.
        let fdh = FileDataHash::parse(&[0u8, 0, 0]).unwrap();
        assert_eq!(fdh.hashed_len, 0);
        assert!(fdh.hash.is_empty());
    }

    #[test]
    fn file_data_hash_truncation_error_reports_three_plus_hash_size() {
        // A value declaring hash_size=8 but only 5 bytes long must report
        // expected=11 (3 + 8), never 3 * 8 = 24.
        let value = vec![0u8, 0, 8, 0xAA, 0xBB];
        let err = FileDataHash::parse(&value).unwrap_err();
        match err {
            ApfsError::Truncated {
                expected, actual, ..
            } => {
                assert_eq!(expected, 11);
                assert_eq!(actual, 5);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    // --- Whole-volume verification ----------------------------------------

    use crate::btree::{BTN_DATA_OFFSET, BTREE_INFO_SIZE};
    use crate::catalog::OBJ_TYPE_SHIFT;
    use crate::object::OBJ_PHYSICAL;
    use crate::omap::Omap;
    use crate::types::{Oid, Xid};
    use std::io::Cursor;

    const BLK: usize = 4096;

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

    /// A ROOT|LEAF|FIXED fext-tree node from
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
        b[info + 8..info + 12].copy_from_slice(&16u32.to_le_bytes());
        b[info + 12..info + 16].copy_from_slice(&16u32.to_le_bytes());
        let csum = crate::checksum::fletcher64(&b[8..]);
        b[..8].copy_from_slice(&csum.to_le_bytes());
        b
    }

    /// A `FILE_INFO` data-hash record covering the file's first block.
    fn file_info_record(obj_id: u64, content: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut key = ((u64::from(JObjType::FileInfo.as_value()) << OBJ_TYPE_SHIFT) | obj_id)
            .to_le_bytes()
            .to_vec();
        // info_and_lba: type DATA_HASH in the high byte, LBA 0.
        let info_and_lba = APFS_FILE_INFO_DATA_HASH << J_FILE_INFO_TYPE_SHIFT;
        key.extend_from_slice(&info_and_lba.to_le_bytes());
        let digest = ApfsHashType::Sha256.digest(content).unwrap();
        let mut value = Vec::new();
        value.extend_from_slice(&1u16.to_le_bytes()); // hashed_len: one block
        value.push(u8::try_from(digest.len()).expect("the test fixture value fits in u8"));
        value.extend_from_slice(&digest);
        (key, value)
    }

    /// An `integrity_meta_phys_t` block declaring `hash_type`.
    fn integrity_meta(hash_type: u32) -> Vec<u8> {
        let mut block = vec![0u8; 256];
        let off = IM_FIELDS_OFFSET;
        block[off..off + 4].copy_from_slice(&2u32.to_le_bytes()); // version
        block[off + 8..off + 12].copy_from_slice(&hash_type.to_le_bytes());
        block[off + 12..off + 16].copy_from_slice(
            &u32::try_from(INTEGRITY_META_FIXED_SIZE)
                .expect("the test fixture value fits in u32")
                .to_le_bytes(),
        );
        block
    }

    /// A sealed volume holding one file (object id 5) whose block-0 content
    /// is `content`. Block 2 is the catalog leaf (the `FILE_INFO` hash
    /// record), block 3 the content, block 4 the file-extent tree — extents
    /// live in the fext tree, not the catalog, exactly as on a real sealed
    /// volume.
    fn sealed_volume(content: &[u8]) -> (Catalog, FextTree, Cursor<Vec<u8>>) {
        let leaf = catalog_leaf(&[file_info_record(5, content)]);
        let mut image = omap_phys(1);
        image.extend(omap_tree(100, 2));
        image.extend(leaf); // block 2
        let mut block = vec![0u8; BLK];
        block[..content.len()].copy_from_slice(content);
        image.extend(block); // block 3
        image.extend(fext_leaf(&[(5, 0, BLK as u64, 3)])); // block 4
        let omap = Omap::parse(&image[..BLK]).unwrap();
        (
            Catalog::new(
                Oid(100),
                omap,
                u32::try_from(BLK).expect("the test fixture value fits in u32"),
                Xid(1),
            ),
            FextTree::new(4),
            Cursor::new(image),
        )
    }

    #[test]
    fn verify_file_hashes_passes_for_intact_content() {
        let content = vec![0xA5u8; BLK];
        let (catalog, fext, mut reader) = sealed_volume(&content);
        let integrity = IntegrityMeta::parse(&integrity_meta(1)).unwrap();
        let report = verify_file_hashes(
            &catalog,
            &fext,
            &mut reader,
            &integrity,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
        )
        .unwrap();
        assert_eq!(report.segments_verified, 1);
        assert!(report.is_intact());
    }

    #[test]
    fn verify_file_hashes_flags_a_tampered_block() {
        let content = vec![0xA5u8; BLK];
        let (catalog, fext, mut reader) = sealed_volume(&content);
        // Overwrite the on-disk content (block 3) after the hash was stored.
        reader.get_mut()[3 * BLK] ^= 0xFF;
        let integrity = IntegrityMeta::parse(&integrity_meta(1)).unwrap();
        let report = verify_file_hashes(
            &catalog,
            &fext,
            &mut reader,
            &integrity,
            u32::try_from(BLK).expect("the test fixture value fits in u32"),
        )
        .unwrap();
        assert_eq!(report.segments_verified, 1);
        assert!(!report.is_intact());
        assert_eq!(report.mismatches.len(), 1);
        assert_eq!(report.mismatches[0].obj_id, 5);
        assert_eq!(report.mismatches[0].offset, 0);
    }

    #[test]
    fn verify_file_hashes_rejects_an_unknown_hash_type() {
        let content = vec![0xA5u8; BLK];
        let (catalog, fext, mut reader) = sealed_volume(&content);
        let integrity = IntegrityMeta::parse(&integrity_meta(99)).unwrap();
        assert!(matches!(
            verify_file_hashes(
                &catalog,
                &fext,
                &mut reader,
                &integrity,
                u32::try_from(BLK).expect("the test fixture value fits in u32")
            ),
            Err(ApfsError::Unsupported(_))
        ));
    }
}
