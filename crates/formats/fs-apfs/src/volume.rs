//! The APFS volume superblock (`apfs_superblock_t`).
//!
//! Each volume in a container has a volume superblock: it names the volume,
//! gives its role, feature flags, and the object identifiers of the volume's
//! object map and file-system trees.
//!
//! Apple File System Reference, `06-volumes.md`.

use alloc::string::String;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned};

use crate::error::{ApfsError, Result};
use crate::object::{OBJ_PHYS_SIZE, ObjPhys};
use crate::types::{ObjectType, Oid, Uuid};

/// Volume superblock magic (`APFS_MAGIC` `'BSPA'`) as the little-endian `u32`
/// it forms on disk — the bytes `APSB`.
pub const APFS_MAGIC: u32 = u32::from_le_bytes(*b"APSB");
/// Length of the volume name field (`APFS_VOLNAME_LEN`).
pub const APFS_VOLNAME_LEN: usize = 256;
/// Number of modification-history entries (`APFS_MAX_HIST`).
pub const APFS_MAX_HIST: usize = 8;

/// Incompatible volume features this parser understands
/// (`APFS_SUPPORTED_INCOMPAT_MASK`).
const APFS_SUPPORTED_INCOMPAT_MASK: u64 = 0x0000_007F;

bitflags! {
    /// Optional volume feature flags (`apfs_features`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ApfsFeatures: u64 {
        /// A pre-release defragmentation format.
        const DEFRAG_PRERELEASE = 0x0000_0001;
        /// Hard links are tracked with map records.
        const HARDLINK_MAP_RECORDS = 0x0000_0002;
        /// The volume supports defragmentation.
        const DEFRAG = 0x0000_0004;
        /// The volume uses strict access-time updates.
        const STRICTATIME = 0x0000_0008;
        /// System and data volumes share an inode-number space.
        const VOLGRP_SYSTEM_INO_SPACE = 0x0000_0010;
    }
}

bitflags! {
    /// Incompatible volume feature flags (`apfs_incompatible_features`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ApfsIncompatFeatures: u64 {
        /// Filenames are compared case-insensitively.
        const CASE_INSENSITIVE = 0x0000_0001;
        /// The volume contains dataless (purgeable) snapshots.
        const DATALESS_SNAPS = 0x0000_0002;
        /// Encryption has been rolled on the volume.
        const ENC_ROLLED = 0x0000_0004;
        /// Filenames are compared without Unicode normalization.
        const NORMALIZATION_INSENSITIVE = 0x0000_0008;
        /// A restore to the volume is incomplete.
        const INCOMPLETE_RESTORE = 0x0000_0010;
        /// The volume is sealed (integrity-verified).
        const SEALED_VOLUME = 0x0000_0020;
        /// Reserved feature bit.
        const RESERVED_40 = 0x0000_0040;
    }
}

bitflags! {
    /// Volume flags (`apfs_fs_flags`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ApfsFsFlags: u64 {
        /// The volume is not encrypted.
        const UNENCRYPTED = 0x0000_0001;
        /// Reserved.
        const RESERVED_2 = 0x0000_0002;
        /// Reserved.
        const RESERVED_4 = 0x0000_0004;
        /// The volume is encrypted with a single key.
        const ONEKEY = 0x0000_0008;
        /// The volume's space has spilled over to another volume.
        const SPILLEDOVER = 0x0000_0010;
        /// The spillover cleaner should run.
        const RUN_SPILLOVER_CLEANER = 0x0000_0020;
        /// The extent-reference tree is always consulted.
        const ALWAYS_CHECK_EXTENTREF = 0x0000_0040;
        /// Reserved.
        const RESERVED_80 = 0x0000_0080;
        /// Reserved.
        const RESERVED_100 = 0x0000_0100;
    }
}

/// The purpose a volume serves within its container (`apfs_role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeRole {
    /// No specific role.
    None,
    /// Immutable system content.
    System,
    /// User data (legacy single-volume layout).
    User,
    /// Recovery environment.
    Recovery,
    /// Virtual-memory backing store.
    Vm,
    /// Pre-boot environment.
    Preboot,
    /// OS installer.
    Installer,
    /// User and mutable system data (modern split-volume layout).
    Data,
    /// Cellular baseband firmware.
    Baseband,
    /// Software update staging.
    Update,
    /// Secured anti-replay storage (xART).
    Xart,
    /// Hardware-specific data.
    Hardware,
    /// Backup data.
    Backup,
    /// Enterprise-managed data.
    Enterprise,
    /// Pre-login content.
    Prelogin,
    /// A role value this parser does not recognize.
    Other(u16),
}

impl VolumeRole {
    /// Decodes the `apfs_role` field.
    #[must_use]
    pub fn from_field(role: u16) -> Self {
        match role {
            0x0000 => Self::None,
            0x0001 => Self::System,
            0x0002 => Self::User,
            0x0004 => Self::Recovery,
            0x0008 => Self::Vm,
            0x0010 => Self::Preboot,
            0x0020 => Self::Installer,
            0x0040 => Self::Data,
            0x0080 => Self::Baseband,
            0x00C0 => Self::Update,
            0x0100 => Self::Xart,
            0x0140 => Self::Hardware,
            0x0180 => Self::Backup,
            0x0240 => Self::Enterprise,
            0x02C0 => Self::Prelogin,
            other => Self::Other(other),
        }
    }
}

/// On-disk `apfs_superblock_t` (1056 bytes).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawApfsSuperblock {
    apfs_o: [u8; OBJ_PHYS_SIZE],
    apfs_magic: U32<LE>,
    apfs_fs_index: U32<LE>,
    apfs_features: U64<LE>,
    apfs_readonly_compatible_features: U64<LE>,
    apfs_incompatible_features: U64<LE>,
    apfs_unmount_time: U64<LE>,
    apfs_fs_reserve_block_count: U64<LE>,
    apfs_fs_quota_block_count: U64<LE>,
    apfs_fs_alloc_count: U64<LE>,
    /// `wrapped_meta_crypto_state_t` — decoded by the encryption work.
    apfs_meta_crypto: [u8; 20],
    apfs_root_tree_type: U32<LE>,
    apfs_extentref_tree_type: U32<LE>,
    apfs_snap_meta_tree_type: U32<LE>,
    apfs_omap_oid: U64<LE>,
    apfs_root_tree_oid: U64<LE>,
    apfs_extentref_tree_oid: U64<LE>,
    apfs_snap_meta_tree_oid: U64<LE>,
    apfs_revert_to_xid: U64<LE>,
    apfs_revert_to_sblock_oid: U64<LE>,
    apfs_next_obj_id: U64<LE>,
    apfs_num_files: U64<LE>,
    apfs_num_directories: U64<LE>,
    apfs_num_symlinks: U64<LE>,
    apfs_num_other_fsobjects: U64<LE>,
    apfs_num_snapshots: U64<LE>,
    apfs_total_blocks_alloced: U64<LE>,
    apfs_total_blocks_freed: U64<LE>,
    apfs_vol_uuid: [u8; 16],
    apfs_last_mod_time: U64<LE>,
    apfs_fs_flags: U64<LE>,
    /// `apfs_modified_by_t` — the formatter's identity.
    apfs_formatted_by: [u8; 48],
    /// `apfs_modified_by_t[APFS_MAX_HIST]` — modification history.
    apfs_modified_by: [u8; 48 * APFS_MAX_HIST],
    apfs_volname: [u8; APFS_VOLNAME_LEN],
    apfs_next_doc_id: U32<LE>,
    apfs_role: U16<LE>,
    reserved: U16<LE>,
    apfs_root_to_xid: U64<LE>,
    apfs_er_state_oid: U64<LE>,
    apfs_cloneinfo_id_epoch: U64<LE>,
    apfs_cloneinfo_xid: U64<LE>,
    apfs_snap_meta_ext_oid: U64<LE>,
    apfs_volume_group_id: [u8; 16],
    apfs_integrity_meta_oid: U64<LE>,
    apfs_fext_tree_oid: U64<LE>,
    apfs_fext_tree_type: U32<LE>,
    reserved_type: U32<LE>,
    reserved_oid: U64<LE>,
}

/// Size of an `apfs_superblock_t` on disk.
pub const APFS_SUPERBLOCK_SIZE: usize = core::mem::size_of::<RawApfsSuperblock>();

/// A parsed, validated APFS volume superblock.
#[derive(Debug, Clone)]
pub struct ApfsSuperblock {
    /// Index of this volume in the container's `nx_fs_oid` array.
    pub fs_index: u32,
    /// The volume's name.
    pub name: String,
    /// The volume's role.
    pub role: VolumeRole,
    /// Optional feature flags.
    pub features: ApfsFeatures,
    /// Read-only compatible feature flags (none are currently defined).
    pub readonly_compatible_features: u64,
    /// Incompatible feature flags.
    pub incompatible_features: ApfsIncompatFeatures,
    /// Volume flags.
    pub flags: ApfsFsFlags,
    /// The volume's UUID.
    pub vol_uuid: Uuid,
    /// UUID of the volume group, or all-zero when the volume is not grouped.
    pub volume_group_id: Uuid,
    /// Object id of the volume object map (a physical object).
    pub omap_oid: Oid,
    /// Object id of the root file-system tree (the catalog, a virtual object).
    pub root_tree_oid: Oid,
    /// Object id of the extent-reference tree.
    pub extentref_tree_oid: Oid,
    /// Object id of the snapshot-metadata tree.
    pub snap_meta_tree_oid: Oid,
    /// Object id of the integrity-metadata object (sealed volumes).
    pub integrity_meta_oid: Oid,
    /// Object id of the file-extent tree (sealed volumes).
    pub fext_tree_oid: Oid,
    /// Number of regular files on the volume.
    pub num_files: u64,
    /// Number of directories on the volume.
    pub num_directories: u64,
    /// Number of symbolic links on the volume.
    pub num_symlinks: u64,
    /// Number of other file-system objects on the volume.
    pub num_other_fsobjects: u64,
    /// Number of snapshots of the volume.
    pub num_snapshots: u64,
    /// Time the volume was last modified, in nanoseconds since the epoch.
    pub last_mod_time: u64,
    /// Time the volume was last unmounted, in nanoseconds since the epoch.
    pub unmount_time: u64,
}

impl ApfsSuperblock {
    /// Parses and validates a volume superblock from a block buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] for a short buffer,
    /// [`ApfsError::InvalidMagic`] for a bad `apfs_magic`,
    /// [`ApfsError::Malformed`] for a wrong object type, or
    /// [`ApfsError::Unsupported`] for an unrecognized incompatible feature.
    pub fn parse(block: &[u8]) -> Result<Self> {
        let raw = RawApfsSuperblock::ref_from_prefix(block)
            .map(|(raw, _rest)| raw)
            .map_err(|_| ApfsError::Truncated {
                structure: "apfs_superblock_t",
                expected: APFS_SUPERBLOCK_SIZE,
                actual: block.len(),
            })?;

        let header = ObjPhys::parse(block)?;
        if header.object_kind() != ObjectType::Fs {
            return Err(ApfsError::Malformed {
                structure: "apfs_superblock_t",
                reason: "object type is not a volume superblock",
            });
        }

        let magic = raw.apfs_magic.get();
        if magic != APFS_MAGIC {
            return Err(ApfsError::InvalidMagic {
                structure: "apfs_superblock_t",
                expected: APFS_MAGIC,
                actual: magic,
            });
        }

        let incompatible_raw = raw.apfs_incompatible_features.get();
        if incompatible_raw & !APFS_SUPPORTED_INCOMPAT_MASK != 0 {
            return Err(ApfsError::Unsupported(
                "unrecognized incompatible volume feature flag",
            ));
        }

        Ok(Self {
            fs_index: raw.apfs_fs_index.get(),
            name: volume_name(&raw.apfs_volname),
            role: VolumeRole::from_field(raw.apfs_role.get()),
            features: ApfsFeatures::from_bits_retain(raw.apfs_features.get()),
            readonly_compatible_features: raw.apfs_readonly_compatible_features.get(),
            incompatible_features: ApfsIncompatFeatures::from_bits_retain(incompatible_raw),
            flags: ApfsFsFlags::from_bits_retain(raw.apfs_fs_flags.get()),
            vol_uuid: Uuid(raw.apfs_vol_uuid),
            volume_group_id: Uuid(raw.apfs_volume_group_id),
            omap_oid: Oid(raw.apfs_omap_oid.get()),
            root_tree_oid: Oid(raw.apfs_root_tree_oid.get()),
            extentref_tree_oid: Oid(raw.apfs_extentref_tree_oid.get()),
            snap_meta_tree_oid: Oid(raw.apfs_snap_meta_tree_oid.get()),
            integrity_meta_oid: Oid(raw.apfs_integrity_meta_oid.get()),
            fext_tree_oid: Oid(raw.apfs_fext_tree_oid.get()),
            num_files: raw.apfs_num_files.get(),
            num_directories: raw.apfs_num_directories.get(),
            num_symlinks: raw.apfs_num_symlinks.get(),
            num_other_fsobjects: raw.apfs_num_other_fsobjects.get(),
            num_snapshots: raw.apfs_num_snapshots.get(),
            last_mod_time: raw.apfs_last_mod_time.get(),
            unmount_time: raw.apfs_unmount_time.get(),
        })
    }

    /// Whether filenames on the volume are compared case-insensitively.
    #[must_use]
    pub fn is_case_insensitive(&self) -> bool {
        self.incompatible_features
            .contains(ApfsIncompatFeatures::CASE_INSENSITIVE)
    }

    /// Whether filenames on the volume are compared without Unicode
    /// normalization.
    #[must_use]
    pub fn is_normalization_insensitive(&self) -> bool {
        self.incompatible_features
            .contains(ApfsIncompatFeatures::NORMALIZATION_INSENSITIVE)
    }

    /// Whether the volume is sealed (integrity-verified).
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.incompatible_features
            .contains(ApfsIncompatFeatures::SEALED_VOLUME)
    }

    /// Whether the volume is encrypted.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        !self.flags.contains(ApfsFsFlags::UNENCRYPTED)
    }
}

/// Extracts the volume name from the fixed `apfs_volname` field, stopping at
/// the first NUL and decoding the rest as lossy UTF-8.
fn volume_name(field: &[u8; APFS_VOLNAME_LEN]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::OBJ_VIRTUAL;
    use alloc::vec;

    /// Builds a minimal valid volume superblock block.
    fn build() -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        // obj_phys o_type at 0x18: OBJECT_TYPE_FS (0x0D), virtual storage.
        block[0x18..0x1C].copy_from_slice(&(OBJ_VIRTUAL | 0x0D).to_le_bytes());
        block[0x20..0x24].copy_from_slice(&APFS_MAGIC.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&3u32.to_le_bytes()); // apfs_fs_index
        block[0x80..0x88].copy_from_slice(&11u64.to_le_bytes()); // apfs_omap_oid
        block[0x88..0x90].copy_from_slice(&22u64.to_le_bytes()); // apfs_root_tree_oid
        block[0xB8..0xC0].copy_from_slice(&5u64.to_le_bytes()); // apfs_num_files
        // apfs_volname at 0x2C0.
        block[0x2C0..0x2C0 + 9].copy_from_slice(b"Macintosh");
        // apfs_role at 0x3C4.
        block[0x3C4..0x3C6].copy_from_slice(&0x0040u16.to_le_bytes()); // DATA
        block
    }

    fn put64(block: &mut [u8], off: usize, value: u64) {
        block[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn raw_superblock_is_1056_bytes() {
        assert_eq!(APFS_SUPERBLOCK_SIZE, 1056);
    }

    #[test]
    fn parses_a_valid_volume_superblock() {
        let sb = ApfsSuperblock::parse(&build()).unwrap();
        assert_eq!(sb.fs_index, 3);
        assert_eq!(sb.name, "Macintosh");
        assert_eq!(sb.role, VolumeRole::Data);
        assert_eq!(sb.omap_oid, Oid(11));
        assert_eq!(sb.root_tree_oid, Oid(22));
        assert_eq!(sb.num_files, 5);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut block = build();
        block[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            ApfsSuperblock::parse(&block),
            Err(ApfsError::InvalidMagic { .. })
        ));
    }

    #[test]
    fn rejects_a_non_volume_object_type() {
        let mut block = build();
        block[0x18..0x1C].copy_from_slice(&(OBJ_VIRTUAL | 0x02).to_le_bytes()); // BTREE
        assert!(matches!(
            ApfsSuperblock::parse(&block),
            Err(ApfsError::Malformed { .. })
        ));
    }

    #[test]
    fn rejects_an_unknown_incompatible_feature() {
        let mut block = build();
        put64(&mut block, 0x38, 0x0000_0100); // a bit outside APFS_SUPPORTED_INCOMPAT_MASK
        assert!(matches!(
            ApfsSuperblock::parse(&block),
            Err(ApfsError::Unsupported(_))
        ));
    }

    #[test]
    fn decodes_role_and_capability_predicates() {
        let mut block = build();
        block[0x3C4..0x3C6].copy_from_slice(&0x0001u16.to_le_bytes()); // SYSTEM
        put64(
            &mut block,
            0x38,
            ApfsIncompatFeatures::CASE_INSENSITIVE.bits()
                | ApfsIncompatFeatures::SEALED_VOLUME.bits(),
        );
        let sb = ApfsSuperblock::parse(&block).unwrap();
        assert_eq!(sb.role, VolumeRole::System);
        assert!(sb.is_case_insensitive());
        assert!(sb.is_sealed());
        assert!(!sb.is_normalization_insensitive());
    }

    #[test]
    fn capability_predicates_invert_when_their_flags_are_clear() {
        // A superblock with no incompatible feature bits: each predicate
        // must return false (catches `with true` constant-return mutants).
        let mut block = build();
        put64(&mut block, 0x38, 0);
        let sb = ApfsSuperblock::parse(&block).unwrap();
        assert!(!sb.is_case_insensitive());
        assert!(!sb.is_normalization_insensitive());
        assert!(!sb.is_sealed());
    }

    #[test]
    fn is_normalization_insensitive_is_true_when_its_flag_is_set() {
        // Catches `with false`: only the NORMALIZATION_INSENSITIVE bit set.
        let mut block = build();
        put64(
            &mut block,
            0x38,
            ApfsIncompatFeatures::NORMALIZATION_INSENSITIVE.bits(),
        );
        let sb = ApfsSuperblock::parse(&block).unwrap();
        assert!(sb.is_normalization_insensitive());
        assert!(!sb.is_case_insensitive());
        assert!(!sb.is_sealed());
    }

    #[test]
    fn unknown_role_falls_back_to_other() {
        let mut block = build();
        block[0x3C4..0x3C6].copy_from_slice(&0x0FFFu16.to_le_bytes());
        assert_eq!(
            ApfsSuperblock::parse(&block).unwrap().role,
            VolumeRole::Other(0x0FFF)
        );
    }

    #[test]
    fn truncated_buffer_is_rejected() {
        assert!(matches!(
            ApfsSuperblock::parse(&[0u8; 100]),
            Err(ApfsError::Truncated { .. })
        ));
    }

    #[test]
    fn encryption_predicate_reads_the_unencrypted_flag() {
        let mut block = build();
        put64(&mut block, 0x108, ApfsFsFlags::UNENCRYPTED.bits()); // apfs_fs_flags
        assert!(!ApfsSuperblock::parse(&block).unwrap().is_encrypted());

        let plain = build(); // apfs_fs_flags zero -> encrypted
        assert!(ApfsSuperblock::parse(&plain).unwrap().is_encrypted());
    }
}
