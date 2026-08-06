//! The APFS container superblock (`nx_superblock_t`).
//!
//! The container superblock is the root of an APFS container: it carries the
//! block geometry, the checkpoint areas, the feature-flag triplet, and the
//! object identifiers of the space manager, object map, reaper, and volumes.
//!
//! Apple File System Reference, `04-container.md`.

use alloc::vec::Vec;

use bitflags::bitflags;
use zerocopy::{FromBytes, I64, Immutable, KnownLayout, LittleEndian as LE, U32, U64, Unaligned};

use crate::error::{ApfsError, Result};
use crate::object::OBJ_PHYS_SIZE;
use crate::types::{ObjectType, Oid, Paddr, Prange, RawPrange, Xid};

/// Container superblock magic (`NX_MAGIC` `'BSXN'`) as the little-endian
/// `u32` it forms on disk — the bytes `NXSB`.
pub const NX_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
/// Maximum number of volumes in a container (`NX_MAX_FILE_SYSTEMS`).
pub const NX_MAX_FILE_SYSTEMS: usize = 100;
/// Number of performance counters in the superblock (`NX_NUM_COUNTERS`).
pub const NX_NUM_COUNTERS: usize = 32;
/// Number of ephemeral-info entries (`NX_EPH_INFO_COUNT`).
pub const NX_EPH_INFO_COUNT: usize = 4;
/// Smallest permitted container block size (`NX_MINIMUM_BLOCK_SIZE`).
pub const NX_MINIMUM_BLOCK_SIZE: u32 = 4096;
/// Largest permitted container block size (`NX_MAXIMUM_BLOCK_SIZE`).
pub const NX_MAXIMUM_BLOCK_SIZE: u32 = 65536;

bitflags! {
    /// Container flags (`nx_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NxFlags: u64 {
        /// Reserved (`NX_RESERVED_1`).
        const RESERVED_1 = 0x0000_0001;
        /// Reserved (`NX_RESERVED_2`).
        const RESERVED_2 = 0x0000_0002;
        /// The container uses software encryption (`NX_CRYPTO_SW`).
        const CRYPTO_SW = 0x0000_0004;
    }
}

bitflags! {
    /// Optional container feature flags (`nx_features`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NxFeatures: u64 {
        /// The container supports defragmentation (`NX_FEATURE_DEFRAG`).
        const DEFRAG = 0x0000_0001;
        /// The container is using low-capacity Fusion-drive mode
        /// (`NX_FEATURE_LCFD`).
        const LCFD = 0x0000_0002;
    }
}

bitflags! {
    /// Incompatible container feature flags (`nx_incompatible_features`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NxIncompatFeatures: u64 {
        /// The original pre-release APFS format (`NX_INCOMPAT_VERSION1`).
        const VERSION1 = 0x0000_0001;
        /// The current APFS format (`NX_INCOMPAT_VERSION2`).
        const VERSION2 = 0x0000_0002;
        /// The container spans a Fusion drive (`NX_INCOMPAT_FUSION`).
        const FUSION = 0x0000_0100;
    }
}

/// Incompatible features this parser understands (`NX_SUPPORTED_INCOMPAT_MASK`).
///
/// VERSION2 (`0x0000_0002`) and FUSION (`0x0000_0100`) share no bits, so
/// combining them with `|` and with `^` is mathematically equivalent here;
/// only the `|` → `&` mutation changes the mask.
#[cfg_attr(test, mutants::skip)] // Equivalent: bit-disjoint OR == XOR.
#[must_use]
const fn nx_supported_incompat_mask() -> u64 {
    NxIncompatFeatures::VERSION2.bits() | NxIncompatFeatures::FUSION.bits()
}

/// On-disk `nx_superblock_t` (1408 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawNxSuperblock {
    nx_o: [u8; OBJ_PHYS_SIZE],
    nx_magic: U32<LE>,
    nx_block_size: U32<LE>,
    nx_block_count: U64<LE>,
    nx_features: U64<LE>,
    nx_readonly_compatible_features: U64<LE>,
    nx_incompatible_features: U64<LE>,
    nx_uuid: [u8; 16],
    nx_next_oid: U64<LE>,
    nx_next_xid: U64<LE>,
    nx_xp_desc_blocks: U32<LE>,
    nx_xp_data_blocks: U32<LE>,
    nx_xp_desc_base: I64<LE>,
    nx_xp_data_base: I64<LE>,
    nx_xp_desc_next: U32<LE>,
    nx_xp_data_next: U32<LE>,
    nx_xp_desc_index: U32<LE>,
    nx_xp_desc_len: U32<LE>,
    nx_xp_data_index: U32<LE>,
    nx_xp_data_len: U32<LE>,
    nx_spaceman_oid: U64<LE>,
    nx_omap_oid: U64<LE>,
    nx_reaper_oid: U64<LE>,
    nx_test_type: U32<LE>,
    nx_max_file_systems: U32<LE>,
    nx_fs_oid: [U64<LE>; NX_MAX_FILE_SYSTEMS],
    nx_counters: [U64<LE>; NX_NUM_COUNTERS],
    nx_blocked_out_prange: RawPrange,
    nx_evict_mapping_tree_oid: U64<LE>,
    nx_flags: U64<LE>,
    nx_efi_jumpstart: I64<LE>,
    nx_fusion_uuid: [u8; 16],
    nx_keylocker: RawPrange,
    nx_ephemeral_info: [U64<LE>; NX_EPH_INFO_COUNT],
    nx_test_oid: U64<LE>,
    nx_fusion_mt_oid: U64<LE>,
    nx_fusion_wbc_oid: U64<LE>,
    nx_fusion_wbc: RawPrange,
    nx_newest_mounted_version: U64<LE>,
    nx_mkb_locker: RawPrange,
}

/// Size of an `nx_superblock_t` on disk.
pub const NX_SUPERBLOCK_SIZE: usize = core::mem::size_of::<RawNxSuperblock>();

/// Locates a checkpoint area (`nx_xp_desc_*` or `nx_xp_data_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointArea {
    /// Number of blocks in the area. The high bit, if set, indicates the
    /// area is itself a B-tree rather than a contiguous range.
    pub blocks: u32,
    /// First block of the area (when stored contiguously).
    pub base: Paddr,
    /// Next index to write within the ring.
    pub next: u32,
    /// Index of the oldest valid entry in the ring.
    pub index: u32,
    /// Number of valid entries in the ring.
    pub len: u32,
}

/// A parsed, validated APFS container superblock.
#[derive(Debug, Clone)]
pub struct NxSuperblock {
    /// The transaction identifier of this superblock.
    pub xid: Xid,
    /// Block size of the container, in bytes.
    pub block_size: u32,
    /// Total number of blocks in the container.
    pub block_count: u64,
    /// Optional feature flags.
    pub features: NxFeatures,
    /// Read-only compatible feature flags (none are currently defined).
    pub readonly_compatible_features: u64,
    /// Incompatible feature flags.
    pub incompatible_features: NxIncompatFeatures,
    /// Container flags.
    pub flags: NxFlags,
    /// The container's UUID.
    pub uuid: [u8; 16],
    /// The next object identifier to be assigned.
    pub next_oid: Oid,
    /// The next transaction identifier to be assigned.
    pub next_xid: Xid,
    /// The checkpoint descriptor area.
    pub xp_desc: CheckpointArea,
    /// The checkpoint data area.
    pub xp_data: CheckpointArea,
    /// Object id of the space manager (an ephemeral object).
    pub spaceman_oid: Oid,
    /// Object id of the container object map (a physical object).
    pub omap_oid: Oid,
    /// Object id of the reaper (an ephemeral object).
    pub reaper_oid: Oid,
    /// Object ids of the container's volumes (the populated `nx_fs_oid`
    /// entries, virtual objects resolved through the container omap).
    pub fs_oids: Vec<Oid>,
    /// Physical address of the EFI jumpstart record, if any.
    pub efi_jumpstart: Paddr,
    /// Location of the container keybag.
    pub keylocker: Prange,
    /// Location of the Fusion write-back cache (`nx_fusion_wbc`); a zero
    /// range on a non-Fusion container.
    pub fusion_wbc: Prange,
}

impl NxSuperblock {
    /// Whether the container spans a Fusion drive — a fast solid-state
    /// device paired with a slower hard drive (`NX_INCOMPAT_FUSION`).
    #[must_use]
    pub fn is_fusion(&self) -> bool {
        self.incompatible_features
            .contains(NxIncompatFeatures::FUSION)
    }

    /// Parses and validates a container superblock from a block buffer.
    ///
    /// The block's Fletcher-64 checksum is **not** verified here; the
    /// checkpoint scan (`#213`) verifies superblock checksums while choosing
    /// the latest valid checkpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short buffer,
    /// [`ApfsError::InvalidMagic`] for a bad `nx_magic`, [`ApfsError::Malformed`]
    /// for a wrong object type or an out-of-range block size, or
    /// [`ApfsError::Unsupported`] for an unrecognized incompatible feature.
    pub fn parse(block: &[u8]) -> Result<Self> {
        let raw = RawNxSuperblock::ref_from_prefix(block)
            .map(|(raw, _rest)| raw)
            .map_err(|_| ApfsError::Truncated {
                structure: "nx_superblock_t",
                expected: NX_SUPERBLOCK_SIZE,
                actual: block.len(),
            })?;

        let header = crate::object::ObjPhys::parse(block)?;
        if header.object_kind() != ObjectType::NxSuperblock {
            return Err(ApfsError::Malformed {
                structure: "nx_superblock_t",
                reason: "object type is not a container superblock",
            });
        }

        let magic = raw.nx_magic.get();
        if magic != NX_MAGIC {
            return Err(ApfsError::InvalidMagic {
                structure: "nx_superblock_t",
                expected: NX_MAGIC,
                actual: magic,
            });
        }

        let block_size = raw.nx_block_size.get();
        if !(NX_MINIMUM_BLOCK_SIZE..=NX_MAXIMUM_BLOCK_SIZE).contains(&block_size)
            || !block_size.is_power_of_two()
        {
            return Err(ApfsError::Malformed {
                structure: "nx_superblock_t",
                reason: "block size is not a power of two within 4 KiB..=64 KiB",
            });
        }

        let incompatible_raw = raw.nx_incompatible_features.get();
        if incompatible_raw & !nx_supported_incompat_mask() != 0 {
            return Err(ApfsError::Unsupported(
                "unrecognized incompatible container feature flag",
            ));
        }

        // Only the first `nx_max_file_systems` slots hold real volumes;
        // nonzero values beyond the declared max are stale or crafted.
        let max_file_systems = raw.nx_max_file_systems.get() as usize;
        if max_file_systems > NX_MAX_FILE_SYSTEMS {
            return Err(ApfsError::Malformed {
                structure: "nx_superblock_t",
                reason: "nx_max_file_systems exceeds NX_MAX_FILE_SYSTEMS",
            });
        }
        let fs_oids = raw
            .nx_fs_oid
            .iter()
            .take(max_file_systems)
            .map(|oid| oid.get())
            .filter(|&oid| oid != 0)
            .map(Oid)
            .collect();

        Ok(Self {
            xid: Xid(header.xid),
            block_size,
            block_count: raw.nx_block_count.get(),
            features: NxFeatures::from_bits_retain(raw.nx_features.get()),
            readonly_compatible_features: raw.nx_readonly_compatible_features.get(),
            incompatible_features: NxIncompatFeatures::from_bits_retain(incompatible_raw),
            flags: NxFlags::from_bits_retain(raw.nx_flags.get()),
            uuid: raw.nx_uuid,
            next_oid: Oid(raw.nx_next_oid.get()),
            next_xid: Xid(raw.nx_next_xid.get()),
            xp_desc: CheckpointArea {
                blocks: raw.nx_xp_desc_blocks.get(),
                base: Paddr(raw.nx_xp_desc_base.get()),
                next: raw.nx_xp_desc_next.get(),
                index: raw.nx_xp_desc_index.get(),
                len: raw.nx_xp_desc_len.get(),
            },
            xp_data: CheckpointArea {
                blocks: raw.nx_xp_data_blocks.get(),
                base: Paddr(raw.nx_xp_data_base.get()),
                next: raw.nx_xp_data_next.get(),
                index: raw.nx_xp_data_index.get(),
                len: raw.nx_xp_data_len.get(),
            },
            spaceman_oid: Oid(raw.nx_spaceman_oid.get()),
            omap_oid: Oid(raw.nx_omap_oid.get()),
            reaper_oid: Oid(raw.nx_reaper_oid.get()),
            fs_oids,
            efi_jumpstart: Paddr(raw.nx_efi_jumpstart.get()),
            keylocker: Prange {
                start: Paddr(raw.nx_keylocker.pr_start_paddr.get()),
                block_count: raw.nx_keylocker.pr_block_count.get(),
            },
            fusion_wbc: Prange {
                start: Paddr(raw.nx_fusion_wbc.pr_start_paddr.get()),
                block_count: raw.nx_fusion_wbc.pr_block_count.get(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{OBJ_EPHEMERAL, OBJ_PHYS_SIZE};

    /// Builds a minimal valid container superblock block.
    fn build() -> Vec<u8> {
        let mut block = vec![0u8; NX_MINIMUM_BLOCK_SIZE as usize];
        // obj_phys: o_xid at 0x10, o_type at 0x18 (ephemeral NX_SUPERBLOCK).
        block[0x10..0x18].copy_from_slice(&7u64.to_le_bytes());
        // OBJECT_TYPE_NX_SUPERBLOCK == 1, with the ephemeral storage flag.
        block[0x18..0x1C].copy_from_slice(&(OBJ_EPHEMERAL | 0x01).to_le_bytes());
        // nx_magic at 0x20, nx_block_size at 0x24, nx_block_count at 0x28.
        block[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&NX_MINIMUM_BLOCK_SIZE.to_le_bytes());
        block[0x28..0x30].copy_from_slice(&100_000u64.to_le_bytes());
        // nx_omap_oid at 0xA0, nx_spaceman_oid at 0x98, nx_reaper_oid at 0xA8.
        block[0x98..0xA0].copy_from_slice(&3u64.to_le_bytes());
        block[0xA0..0xA8].copy_from_slice(&4u64.to_le_bytes());
        block[0xA8..0xB0].copy_from_slice(&5u64.to_le_bytes());
        // nx_max_file_systems at 0xB4.
        block[0xB4..0xB8].copy_from_slice(&(NX_MAX_FILE_SYSTEMS as u32).to_le_bytes());
        block
    }

    /// Writes a `u64` little-endian at `off`.
    fn put64(block: &mut [u8], off: usize, value: u64) {
        block[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn raw_superblock_is_1408_bytes() {
        assert_eq!(NX_SUPERBLOCK_SIZE, 1408);
        assert_eq!(OBJ_PHYS_SIZE, 32);
    }

    #[test]
    fn parses_a_valid_superblock() {
        let sb = NxSuperblock::parse(&build()).unwrap();
        assert_eq!(sb.block_size, 4096);
        assert_eq!(sb.block_count, 100_000);
        assert_eq!(sb.xid, Xid(7));
        assert_eq!(sb.spaceman_oid, Oid(3));
        assert_eq!(sb.omap_oid, Oid(4));
        assert_eq!(sb.reaper_oid, Oid(5));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut block = build();
        block[0x20..0x24].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        match NxSuperblock::parse(&block) {
            Err(ApfsError::InvalidMagic { actual, .. }) => assert_eq!(actual, 0xDEAD_BEEF),
            other => panic!("expected InvalidMagic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_non_superblock_object_type() {
        let mut block = build();
        // Object type 0x02 (BTREE) instead of 0x01 (NX_SUPERBLOCK).
        block[0x18..0x1C].copy_from_slice(&(OBJ_EPHEMERAL | 0x02).to_le_bytes());
        match NxSuperblock::parse(&block) {
            Err(ApfsError::Malformed { reason, .. }) => {
                assert_eq!(reason, "object type is not a container superblock");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn rejects_an_out_of_range_block_size() {
        let mut block = build();
        block[0x24..0x28].copy_from_slice(&5000u32.to_le_bytes()); // not a power of two
        assert!(matches!(
            NxSuperblock::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_an_unknown_incompatible_feature() {
        let mut block = build();
        // VERSION1 (0x1) is outside NX_SUPPORTED_INCOMPAT_MASK.
        put64(&mut block, 0x40, NxIncompatFeatures::VERSION1.bits());
        assert!(matches!(
            NxSuperblock::parse(&block),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn tolerates_unknown_optional_features() {
        let mut block = build();
        // An undefined optional-feature bit must not fail the parse.
        put64(&mut block, 0x30, 0x8000_0000);
        assert!(NxSuperblock::parse(&block).is_ok());
    }

    #[test]
    fn collects_only_populated_fs_oids() {
        let mut block = build();
        // nx_fs_oid starts at 0xB8; populate three entries.
        put64(&mut block, 0xB8, 21);
        put64(&mut block, 0xC0, 22);
        put64(&mut block, 0xC8, 23);
        let sb = NxSuperblock::parse(&block).unwrap();
        assert_eq!(sb.fs_oids, vec![Oid(21), Oid(22), Oid(23)]);
    }

    #[test]
    fn ignores_fs_oids_past_nx_max_file_systems() {
        let mut block = build();
        // Declare a two-volume container, then plant a nonzero OID in the
        // third slot — it must not be treated as a real volume.
        block[0xB4..0xB8].copy_from_slice(&2u32.to_le_bytes());
        put64(&mut block, 0xB8, 21);
        put64(&mut block, 0xC0, 22);
        put64(&mut block, 0xC8, 23);
        let sb = NxSuperblock::parse(&block).unwrap();
        assert_eq!(sb.fs_oids, vec![Oid(21), Oid(22)]);
    }

    #[test]
    fn rejects_nx_max_file_systems_above_the_limit() {
        let mut block = build();
        block[0xB4..0xB8].copy_from_slice(&(NX_MAX_FILE_SYSTEMS as u32 + 1).to_le_bytes());
        assert!(matches!(
            NxSuperblock::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_a_truncated_buffer() {
        match NxSuperblock::parse(&[0u8; 64]) {
            Err(ApfsError::Truncated { structure, .. }) => {
                assert_eq!(structure, "nx_superblock_t");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn is_fusion_reflects_the_fusion_incompat_flag() {
        // The default fixture has no incompatible-feature bits set, so the
        // container is not a Fusion drive.
        let plain = NxSuperblock::parse(&build()).unwrap();
        assert!(!plain.is_fusion(), "no FUSION flag must be non-fusion");

        // Setting the FUSION flag flips the predicate to true; both
        // assertions are needed to catch the `true`/`false` body mutants.
        let mut block = build();
        put64(&mut block, 0x40, NxIncompatFeatures::FUSION.bits());
        let fusion = NxSuperblock::parse(&block).unwrap();
        assert!(fusion.is_fusion(), "FUSION flag must mark the container");
    }

    #[test]
    fn accepts_a_combined_version2_and_fusion_feature_mask() {
        // Setting BOTH supported incompatible-feature bits must still parse.
        // Mutating the support mask's `|` to `&` would collapse it to zero
        // and reject any nonzero incompatible-feature combination.
        let mut block = build();
        let combined = NxIncompatFeatures::VERSION2.bits() | NxIncompatFeatures::FUSION.bits();
        put64(&mut block, 0x40, combined);
        let sb = NxSuperblock::parse(&block).unwrap();
        assert!(sb.is_fusion());
        assert!(
            sb.incompatible_features
                .contains(NxIncompatFeatures::VERSION2)
        );
    }
}
