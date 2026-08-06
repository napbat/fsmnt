//! General-purpose APFS on-disk primitives.
//!
//! Apple File System Reference, `01-general-purpose-types.md` and
//! `02-objects.md`: the building-block types shared by every container- and
//! file-system-layer structure.

use zerocopy::{FromBytes, I64, Immutable, KnownLayout, LittleEndian as LE, U64, Unaligned};

use crate::error::{ApfsError, Result};

/// An invalid object identifier (`OID_INVALID`).
pub const OID_INVALID: u64 = 0;
/// The reserved object identifier of the container superblock
/// (`OID_NX_SUPERBLOCK`).
pub const OID_NX_SUPERBLOCK: u64 = 1;
/// The number of object identifiers reserved for fixed-id objects
/// (`OID_RESERVED_COUNT`).
pub const OID_RESERVED_COUNT: u64 = 1024;

/// A physical block address (`paddr_t`).
///
/// Modeled as a signed integer to match Apple's IOKit-derived definition;
/// negative values are not valid addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Paddr(pub i64);

impl Paddr {
    /// Whether this is a usable on-disk address (non-negative).
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0 >= 0
    }

    /// The address as an unsigned block number, or `None` if negative.
    #[must_use]
    pub fn as_block(self) -> Option<u64> {
        u64::try_from(self.0).ok()
    }
}

/// An object identifier (`oid_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub u64);

impl Oid {
    /// Whether the identifier is anything other than `OID_INVALID`.
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0 != OID_INVALID
    }

    /// Whether the identifier falls in the Apple-reserved range
    /// (`< OID_RESERVED_COUNT`).
    #[must_use]
    pub fn is_reserved(self) -> bool {
        self.0 < OID_RESERVED_COUNT
    }
}

/// A transaction identifier (`xid_t`).
///
/// Zero is never a valid on-disk transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Xid(pub u64);

impl Xid {
    /// Whether the identifier is valid on disk (non-zero).
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0 != 0
    }
}

/// A 16-byte universally unique identifier (`uuid_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid(pub [u8; 16]);

/// The on-disk `prange_t` — a range of physical addresses (16 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
pub(crate) struct RawPrange {
    /// 0x00: the first block in the range.
    pub pr_start_paddr: I64<LE>,
    /// 0x08: the number of blocks in the range.
    pub pr_block_count: U64<LE>,
}

/// Size of a `prange_t` in bytes.
pub const PRANGE_SIZE: usize = core::mem::size_of::<RawPrange>();

/// A range of physical addresses (`prange_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prange {
    /// The first block in the range.
    pub start: Paddr,
    /// The number of blocks in the range.
    pub block_count: u64,
}

impl Prange {
    /// Parses a `prange_t` from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] when fewer than [`PRANGE_SIZE`] bytes
    /// are available.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let (raw, _rest) = RawPrange::ref_from_prefix(bytes).map_err(|_| ApfsError::Truncated {
            structure: "prange_t",
            expected: PRANGE_SIZE,
            actual: bytes.len(),
        })?;
        Ok(Self {
            start: Paddr(raw.pr_start_paddr.get()),
            block_count: raw.pr_block_count.get(),
        })
    }

    /// Whether the range is empty (no blocks).
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.block_count == 0
    }
}

/// Object type: a container-layer four-char code; not a 16-bit masked value.
pub const OBJECT_TYPE_CONTAINER_KEYBAG: u32 = u32::from_be_bytes(*b"keys");
/// Object type: a volume keybag four-char code.
pub const OBJECT_TYPE_VOLUME_KEYBAG: u32 = u32::from_be_bytes(*b"recs");
/// Object type: a media keybag four-char code.
pub const OBJECT_TYPE_MEDIA_KEYBAG: u32 = u32::from_be_bytes(*b"mkey");

/// A decoded APFS object type.
///
/// Most types are the low 16 bits of `o_type` / `o_subtype`; keybag
/// objects instead carry a full 32-bit four-char code, also decoded here.
///
/// Apple File System Reference, `02-objects.md`, "Object Types".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    /// No object type (`OBJECT_TYPE_INVALID`).
    Invalid,
    /// A container superblock (`nx_superblock_t`).
    NxSuperblock,
    /// A B-tree root node.
    Btree,
    /// A non-root B-tree node.
    BtreeNode,
    /// A space manager (`spaceman_phys_t`).
    Spaceman,
    /// A chunk-info address block.
    SpacemanCab,
    /// A chunk-info block.
    SpacemanCib,
    /// A space-manager free-space bitmap.
    SpacemanBitmap,
    /// A space-manager free-space queue.
    SpacemanFreeQueue,
    /// An extents-list tree.
    ExtentListTree,
    /// An object map (`omap_phys_t`).
    Omap,
    /// A checkpoint map (`checkpoint_map_phys_t`).
    CheckpointMap,
    /// A volume superblock (`apfs_superblock_t`).
    Fs,
    /// A file-system records tree (the catalog).
    FsTree,
    /// An extent-reference tree.
    BlockRefTree,
    /// A snapshot-metadata tree.
    SnapMetaTree,
    /// A container reaper.
    NxReaper,
    /// A reaper list.
    NxReapList,
    /// An object-map snapshot.
    OmapSnapshot,
    /// An EFI jumpstart record.
    EfiJumpstart,
    /// A Fusion middle tree.
    FusionMiddleTree,
    /// A Fusion write-back cache.
    NxFusionWbc,
    /// A Fusion write-back cache list.
    NxFusionWbcList,
    /// Encryption-rolling state.
    ErState,
    /// A general-purpose bitmap.
    GBitmap,
    /// A tree of general-purpose bitmaps.
    GBitmapTree,
    /// A general-purpose bitmap block.
    GBitmapBlock,
    /// An encryption-rolling recovery block.
    ErRecoveryBlock,
    /// An extended snapshot-metadata object.
    SnapMetaExt,
    /// Integrity metadata for a sealed volume.
    IntegrityMeta,
    /// A file-extent tree (sealed volumes).
    FextTree,
    /// Reserved type `0x20`.
    Reserved20,
    /// A test object type.
    Test,
    /// The container keybag (`OBJECT_TYPE_CONTAINER_KEYBAG`).
    ContainerKeybag,
    /// A volume keybag (`OBJECT_TYPE_VOLUME_KEYBAG`).
    VolumeKeybag,
    /// A media keybag (`OBJECT_TYPE_MEDIA_KEYBAG`).
    MediaKeybag,
    /// A type value APFS does not define.
    Unknown(u16),
}

impl ObjectType {
    /// Decodes the object type from a raw `o_type` or `o_subtype` field,
    /// discarding the flag bits.
    #[must_use]
    pub fn from_type_field(field: u32) -> Self {
        // Keybag objects carry a full 32-bit four-char-code type rather
        // than the usual 16-bit masked value, so they are matched against
        // the whole field before the mask is applied.
        match field {
            OBJECT_TYPE_CONTAINER_KEYBAG => return Self::ContainerKeybag,
            OBJECT_TYPE_VOLUME_KEYBAG => return Self::VolumeKeybag,
            OBJECT_TYPE_MEDIA_KEYBAG => return Self::MediaKeybag,
            _ => {}
        }
        match (field & crate::object::OBJECT_TYPE_MASK) as u16 {
            0x00 => Self::Invalid,
            0x01 => Self::NxSuperblock,
            0x02 => Self::Btree,
            0x03 => Self::BtreeNode,
            0x05 => Self::Spaceman,
            0x06 => Self::SpacemanCab,
            0x07 => Self::SpacemanCib,
            0x08 => Self::SpacemanBitmap,
            0x09 => Self::SpacemanFreeQueue,
            0x0A => Self::ExtentListTree,
            0x0B => Self::Omap,
            0x0C => Self::CheckpointMap,
            0x0D => Self::Fs,
            0x0E => Self::FsTree,
            0x0F => Self::BlockRefTree,
            0x10 => Self::SnapMetaTree,
            0x11 => Self::NxReaper,
            0x12 => Self::NxReapList,
            0x13 => Self::OmapSnapshot,
            0x14 => Self::EfiJumpstart,
            0x15 => Self::FusionMiddleTree,
            0x16 => Self::NxFusionWbc,
            0x17 => Self::NxFusionWbcList,
            0x18 => Self::ErState,
            0x19 => Self::GBitmap,
            0x1A => Self::GBitmapTree,
            0x1B => Self::GBitmapBlock,
            0x1C => Self::ErRecoveryBlock,
            0x1D => Self::SnapMetaExt,
            0x1E => Self::IntegrityMeta,
            0x1F => Self::FextTree,
            0x20 => Self::Reserved20,
            0xFF => Self::Test,
            other => Self::Unknown(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paddr_validity() {
        assert!(Paddr(0).is_valid());
        assert!(Paddr(4096).is_valid());
        assert!(!Paddr(-1).is_valid());
        assert_eq!(Paddr(4096).as_block(), Some(4096));
        assert_eq!(Paddr(-1).as_block(), None);
    }

    #[test]
    fn oid_predicates() {
        assert!(!Oid(OID_INVALID).is_valid());
        assert!(Oid(OID_NX_SUPERBLOCK).is_valid());
        assert!(Oid(OID_NX_SUPERBLOCK).is_reserved());
        assert!(Oid(OID_RESERVED_COUNT - 1).is_reserved());
        assert!(!Oid(OID_RESERVED_COUNT).is_reserved());
    }

    #[test]
    fn xid_zero_is_invalid() {
        assert!(!Xid(0).is_valid());
        assert!(Xid(1).is_valid());
    }

    #[test]
    fn prange_parses_from_16_bytes() {
        let mut buf = [0u8; PRANGE_SIZE];
        buf[0x00..0x08].copy_from_slice(&100i64.to_le_bytes());
        buf[0x08..0x10].copy_from_slice(&8u64.to_le_bytes());
        let range = Prange::parse(&buf).unwrap();
        assert_eq!(range.start, Paddr(100));
        assert_eq!(range.block_count, 8);
        assert!(!range.is_empty());
    }

    #[test]
    fn prange_is_empty_when_block_count_is_zero() {
        // An empty range (block_count == 0) must report is_empty(); a
        // non-zero count must not. A mutant that hard-codes either
        // branch is caught by the asymmetric expectation here.
        let mut buf = [0u8; PRANGE_SIZE];
        buf[0x00..0x08].copy_from_slice(&100i64.to_le_bytes());
        let empty = Prange::parse(&buf).unwrap();
        assert!(empty.is_empty());
        buf[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
        let non_empty = Prange::parse(&buf).unwrap();
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn prange_rejects_truncated_input() {
        match Prange::parse(&[0u8; PRANGE_SIZE - 1]) {
            Err(ApfsError::Truncated { structure, .. }) => assert_eq!(structure, "prange_t"),
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn object_type_decodes_known_values() {
        assert_eq!(ObjectType::from_type_field(0x01), ObjectType::NxSuperblock);
        assert_eq!(ObjectType::from_type_field(0x0B), ObjectType::Omap);
        assert_eq!(ObjectType::from_type_field(0x0D), ObjectType::Fs);
        assert_eq!(ObjectType::from_type_field(0x1E), ObjectType::IntegrityMeta);
        assert_eq!(ObjectType::from_type_field(0x20), ObjectType::Reserved20);
        assert_eq!(ObjectType::from_type_field(0x00), ObjectType::Invalid);
        assert_eq!(ObjectType::from_type_field(0xFF), ObjectType::Test);
    }

    #[test]
    fn object_type_ignores_flag_bits() {
        // OBJ_PHYSICAL | OBJ_ENCRYPTED set in the high bits must not change
        // the decoded type.
        assert_eq!(ObjectType::from_type_field(0x5000_000B), ObjectType::Omap);
    }

    #[test]
    fn object_type_unknown_fallback() {
        assert_eq!(
            ObjectType::from_type_field(0x0099),
            ObjectType::Unknown(0x0099)
        );
    }

    #[test]
    fn keybag_four_char_codes() {
        // 'keys' as a big-endian four-char code.
        assert_eq!(OBJECT_TYPE_CONTAINER_KEYBAG, 0x6B65_7973);
    }

    #[test]
    fn object_type_decodes_keybag_four_char_codes() {
        // A keybag object's full 32-bit type must classify correctly
        // rather than being truncated to an Unknown(...) by the mask.
        assert_eq!(
            ObjectType::from_type_field(OBJECT_TYPE_CONTAINER_KEYBAG),
            ObjectType::ContainerKeybag,
        );
        assert_eq!(
            ObjectType::from_type_field(OBJECT_TYPE_VOLUME_KEYBAG),
            ObjectType::VolumeKeybag,
        );
        assert_eq!(
            ObjectType::from_type_field(OBJECT_TYPE_MEDIA_KEYBAG),
            ObjectType::MediaKeybag,
        );
        // A normal masked type is unaffected.
        assert_eq!(ObjectType::from_type_field(0x4000_000B), ObjectType::Omap);
    }
}
