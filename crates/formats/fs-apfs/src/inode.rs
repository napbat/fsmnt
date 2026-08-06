//! Inode records (`j_inode_val_t`) — the core metadata of every file and
//! directory on a volume.
//!
//! Apple File System Reference, `07-file-system-objects.md` and
//! `08-file-system-constants.md`.

use alloc::vec::Vec;

use bitflags::bitflags;
use zerocopy::{
    FromBytes, I32, Immutable, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned,
};

use crate::catalog::{Catalog, JObjType};
use crate::error::{ApfsError, Result};
use crate::io::{Read, Seek};
use crate::time::ApfsTimestamp;

/// The invalid inode number (`INVALID_INO_NUM`).
pub const INVALID_INO_NUM: u64 = 0;
/// Inode number used as the parent of the root directory (`ROOT_DIR_PARENT`).
pub const ROOT_DIR_PARENT: u64 = 1;
/// Inode number of the volume root directory (`ROOT_DIR_INO_NUM`).
pub const ROOT_DIR_INO_NUM: u64 = 2;
/// Inode number of the private directory (`PRIV_DIR_INO_NUM`).
pub const PRIV_DIR_INO_NUM: u64 = 3;
/// Inode number of the snapshot directory (`SNAP_DIR_INO_NUM`).
pub const SNAP_DIR_INO_NUM: u64 = 6;
/// Inode number of the purgeable-data directory (`PURGEABLE_DIR_INO_NUM`).
pub const PURGEABLE_DIR_INO_NUM: u64 = 7;
/// First inode number available for user files (`MIN_USER_INO_NUM`).
pub const MIN_USER_INO_NUM: u64 = 16;

/// Mask selecting the file-type bits of a `mode_t` (`S_IFMT`).
pub const S_IFMT: u16 = 0o170_000;

bitflags! {
    /// Inode flags (`j_inode_flags`, the `internal_flags` field).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InodeFlags: u64 {
        /// The inode is an APFS-internal object, hidden from users.
        const IS_APFS_PRIVATE = 0x0000_0001;
        /// The directory maintains a `DIR_STATS` record.
        const MAINTAIN_DIR_STATS = 0x0000_0002;
        /// The directory is the origin of its directory statistics.
        const DIR_STATS_ORIGIN = 0x0000_0004;
        /// The inode's protection class was set explicitly.
        const PROT_CLASS_EXPLICIT = 0x0000_0008;
        /// The inode was created by cloning another inode.
        const WAS_CLONED = 0x0000_0010;
        /// Unused flag bit.
        const FLAG_UNUSED = 0x0000_0020;
        /// The inode has a security (ACL) extended attribute.
        const HAS_SECURITY_EA = 0x0000_0040;
        /// The inode is being truncated.
        const BEING_TRUNCATED = 0x0000_0080;
        /// The inode has a Finder-info extended attribute.
        const HAS_FINDER_INFO = 0x0000_0100;
        /// The file is sparse.
        const IS_SPARSE = 0x0000_0200;
        /// The inode has been cloned at least once.
        const WAS_EVER_CLONED = 0x0000_0400;
        /// An active file was trimmed.
        const ACTIVE_FILE_TRIMMED = 0x0000_0800;
        /// The inode's storage is pinned to the main (fast) device.
        const PINNED_TO_MAIN = 0x0000_1000;
        /// The inode's storage is pinned to the secondary device.
        const PINNED_TO_TIER2 = 0x0000_2000;
        /// The inode has a resource fork.
        const HAS_RSRC_FORK = 0x0000_4000;
        /// The inode explicitly has no resource fork.
        const NO_RSRC_FORK = 0x0000_8000;
        /// The inode's allocation has spilled over to another volume.
        const ALLOCATION_SPILLEDOVER = 0x0001_0000;
        /// The inode is a candidate for fast promotion to the fast device.
        const FAST_PROMOTE = 0x0002_0000;
        /// The `uncompressed_size` field is populated.
        const HAS_UNCOMPRESSED_SIZE = 0x0004_0000;
        /// The inode is purgeable.
        const IS_PURGEABLE = 0x0008_0000;
        /// The inode wants to become purgeable.
        const WANTS_TO_BE_PURGEABLE = 0x0010_0000;
        /// The inode is a sync-root.
        const IS_SYNC_ROOT = 0x0020_0000;
        /// The inode is exempt from snapshot copy-on-write.
        const SNAPSHOT_COW_EXEMPTION = 0x0040_0000;
    }
}

/// The POSIX file type of an inode, decoded from the `S_IFMT` bits of `mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// A named pipe (FIFO).
    Fifo,
    /// A character device.
    CharDevice,
    /// A directory.
    Directory,
    /// A block device.
    BlockDevice,
    /// A regular file.
    Regular,
    /// A symbolic link.
    Symlink,
    /// A socket.
    Socket,
    /// A whiteout entry.
    Whiteout,
    /// A mode whose type bits this parser does not recognize.
    Unknown(u16),
}

impl FileType {
    /// Decodes the file type from a `mode_t` value.
    #[must_use]
    pub fn from_mode(mode: u16) -> Self {
        match mode & S_IFMT {
            0o010_000 => Self::Fifo,
            0o020_000 => Self::CharDevice,
            0o040_000 => Self::Directory,
            0o060_000 => Self::BlockDevice,
            0o100_000 => Self::Regular,
            0o120_000 => Self::Symlink,
            0o140_000 => Self::Socket,
            0o160_000 => Self::Whiteout,
            other => Self::Unknown(other),
        }
    }
}

/// On-disk fixed portion of `j_inode_val_t` (92 bytes, before `xfields`).
#[derive(Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct RawJInodeVal {
    parent_id: U64<LE>,
    private_id: U64<LE>,
    create_time: U64<LE>,
    mod_time: U64<LE>,
    change_time: U64<LE>,
    access_time: U64<LE>,
    internal_flags: U64<LE>,
    nchildren_or_nlink: I32<LE>,
    default_protection_class: U32<LE>,
    write_generation_counter: U32<LE>,
    bsd_flags: U32<LE>,
    owner: U32<LE>,
    group: U32<LE>,
    mode: U16<LE>,
    pad1: U16<LE>,
    uncompressed_size: U64<LE>,
}

/// Size of the fixed portion of `j_inode_val_t`.
pub const J_INODE_VAL_SIZE: usize = core::mem::size_of::<RawJInodeVal>();

/// A parsed APFS inode.
#[derive(Debug, Clone)]
pub struct Inode {
    /// Inode number of the parent directory of the primary link.
    pub parent_id: u64,
    /// Identifier used by this file's data stream.
    pub private_id: u64,
    /// Creation time, in nanoseconds since the Unix epoch.
    pub create_time: u64,
    /// Last content-modification time, in nanoseconds since the Unix epoch.
    pub mod_time: u64,
    /// Last attribute-change time, in nanoseconds since the Unix epoch.
    pub change_time: u64,
    /// Last access time, in nanoseconds since the Unix epoch.
    pub access_time: u64,
    /// Inode flags.
    pub flags: InodeFlags,
    /// For a directory, the number of children; otherwise the hard-link count.
    nchildren_or_nlink: i32,
    /// Default protection class for files created in this directory.
    pub default_protection_class: u32,
    /// BSD flags (`chflags(2)`).
    pub bsd_flags: u32,
    /// Owning user identifier.
    pub owner: u32,
    /// Owning group identifier.
    pub group: u32,
    /// POSIX mode (file type and permission bits).
    pub mode: u16,
    /// Uncompressed size, valid only with `HAS_UNCOMPRESSED_SIZE`.
    pub uncompressed_size: u64,
    /// The raw extended-fields region, parsed by the extended-fields module.
    pub xfields: Vec<u8>,
}

impl Inode {
    /// Parses an inode from a `j_inode_val_t` record value.
    ///
    /// # Errors
    ///
    /// Returns [`ApfsError::Truncated`] when the value is shorter than the
    /// fixed inode structure.
    pub fn parse(value: &[u8]) -> Result<Self> {
        let (raw, xfields) =
            RawJInodeVal::ref_from_prefix(value).map_err(|_| ApfsError::Truncated {
                structure: "j_inode_val_t",
                expected: J_INODE_VAL_SIZE,
                actual: value.len(),
            })?;
        Ok(Self {
            parent_id: raw.parent_id.get(),
            private_id: raw.private_id.get(),
            create_time: raw.create_time.get(),
            mod_time: raw.mod_time.get(),
            change_time: raw.change_time.get(),
            access_time: raw.access_time.get(),
            flags: InodeFlags::from_bits_retain(raw.internal_flags.get()),
            nchildren_or_nlink: raw.nchildren_or_nlink.get(),
            default_protection_class: raw.default_protection_class.get(),
            bsd_flags: raw.bsd_flags.get(),
            owner: raw.owner.get(),
            group: raw.group.get(),
            mode: raw.mode.get(),
            uncompressed_size: raw.uncompressed_size.get(),
            xfields: xfields.to_vec(),
        })
    }

    /// Looks up the inode for `obj_id` in a volume catalog.
    ///
    /// # Errors
    ///
    /// Propagates catalog-walk errors; returns `Ok(None)` when the object has
    /// no inode record.
    pub fn lookup<T: Read + Seek>(
        catalog: &Catalog,
        reader: &mut T,
        obj_id: u64,
    ) -> Result<Option<Self>> {
        match catalog.find_record(reader, obj_id, JObjType::Inode)? {
            Some(value) => Ok(Some(Self::parse(&value)?)),
            None => Ok(None),
        }
    }

    /// The inode's POSIX file type.
    #[must_use]
    pub fn file_type(&self) -> FileType {
        FileType::from_mode(self.mode)
    }

    /// Whether the inode is a directory.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.file_type() == FileType::Directory
    }

    /// The POSIX permission bits of `mode` (the low 12 bits).
    #[must_use]
    pub fn permissions(&self) -> u16 {
        self.mode & 0o7777
    }

    /// The number of children of a directory inode.
    ///
    /// Meaningful only when [`Inode::is_directory`] is true.
    #[must_use]
    pub fn child_count(&self) -> i32 {
        self.nchildren_or_nlink
    }

    /// The hard-link count of a non-directory inode.
    ///
    /// Meaningful only when [`Inode::is_directory`] is false.
    #[must_use]
    pub fn link_count(&self) -> i32 {
        self.nchildren_or_nlink
    }

    /// The inode's creation time.
    #[must_use]
    pub fn created(&self) -> ApfsTimestamp {
        ApfsTimestamp(self.create_time)
    }

    /// The inode's last content-modification time.
    #[must_use]
    pub fn modified(&self) -> ApfsTimestamp {
        ApfsTimestamp(self.mod_time)
    }

    /// The inode's last attribute-change time.
    #[must_use]
    pub fn changed(&self) -> ApfsTimestamp {
        ApfsTimestamp(self.change_time)
    }

    /// The inode's last access time.
    #[must_use]
    pub fn accessed(&self) -> ApfsTimestamp {
        ApfsTimestamp(self.access_time)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a `j_inode_val_t` value with the given mode, flags, and link
    /// field, plus `xfield_bytes` of trailing extended-field data.
    fn inode_value(mode: u16, flags: u64, link: i32, xfield_bytes: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; J_INODE_VAL_SIZE];
        v[0x00..0x08].copy_from_slice(&7u64.to_le_bytes()); // parent_id
        v[0x08..0x10].copy_from_slice(&7u64.to_le_bytes()); // private_id
        v[0x10..0x18].copy_from_slice(&1_000u64.to_le_bytes()); // create_time
        v[0x18..0x20].copy_from_slice(&2_000u64.to_le_bytes()); // mod_time
        v[0x30..0x38].copy_from_slice(&flags.to_le_bytes()); // internal_flags
        v[0x38..0x3C].copy_from_slice(&link.to_le_bytes()); // nchildren/nlink
        v[0x48..0x4C].copy_from_slice(&501u32.to_le_bytes()); // owner
        v[0x4C..0x50].copy_from_slice(&20u32.to_le_bytes()); // group
        v[0x50..0x52].copy_from_slice(&mode.to_le_bytes()); // mode
        v[0x54..0x5C].copy_from_slice(&4096u64.to_le_bytes()); // uncompressed_size
        v.extend_from_slice(xfield_bytes);
        v
    }

    #[test]
    fn fixed_inode_value_is_92_bytes() {
        assert_eq!(J_INODE_VAL_SIZE, 92);
    }

    #[test]
    fn parses_a_directory_inode() {
        let value = inode_value(0o040_755, 0, 4, &[]);
        let inode = Inode::parse(&value).unwrap();
        assert_eq!(inode.file_type(), FileType::Directory);
        assert!(inode.is_directory());
        assert_eq!(inode.permissions(), 0o755);
        assert_eq!(inode.child_count(), 4);
        assert_eq!(inode.owner, 501);
        assert_eq!(inode.create_time, 1_000);
    }

    #[test]
    fn parses_a_regular_file_inode_with_flags() {
        let flags = InodeFlags::IS_SPARSE.bits() | InodeFlags::WAS_EVER_CLONED.bits();
        let value = inode_value(0o100_644, flags, 2, &[]);
        let inode = Inode::parse(&value).unwrap();
        assert_eq!(inode.file_type(), FileType::Regular);
        assert!(!inode.is_directory());
        assert_eq!(inode.link_count(), 2);
        assert!(inode.flags.contains(InodeFlags::IS_SPARSE));
        assert!(inode.flags.contains(InodeFlags::WAS_EVER_CLONED));
    }

    #[test]
    fn file_type_decodes_each_posix_type() {
        assert_eq!(FileType::from_mode(0o010_000), FileType::Fifo);
        assert_eq!(FileType::from_mode(0o020_644), FileType::CharDevice);
        assert_eq!(FileType::from_mode(0o060_644), FileType::BlockDevice);
        assert_eq!(FileType::from_mode(0o120_777), FileType::Symlink);
        assert_eq!(FileType::from_mode(0o140_000), FileType::Socket);
    }

    #[test]
    fn xfields_region_is_captured() {
        let value = inode_value(0o100_644, 0, 1, &[0xDE, 0xAD, 0xBE, 0xEF]);
        let inode = Inode::parse(&value).unwrap();
        assert_eq!(inode.xfields, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn truncated_inode_value_is_rejected() {
        assert!(matches!(
            Inode::parse(&[0u8; 20]),
            Err(ApfsError::Truncated { .. })
        ));
    }
}
