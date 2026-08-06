//! NTFS Reparse Point structured value implementation.
//!
//! Reparse points are an NTFS mechanism that allows extending filesystem functionality
//! through symbolic links, junctions, mount points, and other features like Windows
//! Overlay Filter (WOF) compression and deduplication.
//!
//! Reference: [MS-FSCC] Section 2.1.2

use arrayvec::ArrayVec;
use zerocopy::{FromBytes, Immutable, KnownLayout, LittleEndian, U16, U32, U64, Unaligned};

use crate::attribute::NtfsAttributeType;
use crate::attribute_value::{NtfsAttributeValue, NtfsResidentAttributeValue};
use crate::error::{NtfsError, Result};
use crate::guid::{GUID_SIZE, NtfsGuid};
use crate::helpers::{ReadOnlyCursor, read_pod};
use crate::io::{Read, Seek};
use crate::structured_values::{
    NtfsStructuredValue, NtfsStructuredValueFromResidentAttributeValue,
};
use crate::types::NtfsPosition;

/// Size of the common reparse point header (8 bytes).
mod links;
mod nfs;
mod point;

pub use links::*;
pub(super) use nfs::decode_utf16le;
use nfs::split_utf16le_null_terminated;
pub use nfs::*;
pub use point::*;

const REPARSE_POINT_HEADER_SIZE: usize = 8;

/// Maximum path buffer size for `no_std` compatibility (4KB should be sufficient for paths).
pub(super) const MAX_PATH_BUFFER_SIZE: usize = 4096;

/// Size of the symbolic link reparse data header (12 bytes, after common header).
const SYMLINK_REPARSE_DATA_HEADER_SIZE: usize = 12;

/// Size of the mount point reparse data header (8 bytes, after common header).
const MOUNT_POINT_REPARSE_DATA_HEADER_SIZE: usize = 8;

/// Size of the WSL symbolic link reparse data header (4 bytes, after common header).
const LX_SYMLINK_REPARSE_DATA_HEADER_SIZE: usize = 4;

/// Size of the App Execution Link reparse data header (4 bytes, after common header).
const APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE: usize = 4;

/// Size of the NFS reparse data header (8 bytes — the u64 type field).
const NFS_REPARSE_DATA_HEADER_SIZE: usize = 8;

/// Size of the NFS device data (8 bytes — major u32 + minor u32).
const NFS_DEVICE_DATA_SIZE: usize = 8;

/// Required version for WSL symbolic link reparse data.
const LX_SYMLINK_VERSION: u32 = 2;

/// Common header for all reparse points (8 bytes).
///
/// Reference: [MS-FSCC] 2.1.2.2 `REPARSE_DATA_BUFFER`
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct ReparsePointHeader {
    /// Reparse tag identifying the type and flags.
    reparse_tag: U32<LittleEndian>,
    /// Length of reparse data following this header (excludes header itself).
    reparse_data_length: U16<LittleEndian>,
    /// Reserved - SHOULD be 0, MUST be ignored.
    reserved: U16<LittleEndian>,
}

/// Header for symbolic link reparse data (12 bytes).
///
/// Reference: [MS-FSCC] 2.1.2.4 Symbolic Link Reparse Data Buffer
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct SymbolicLinkReparseDataHeader {
    /// Offset in `PathBuffer` where substitute name starts (in bytes).
    substitute_name_offset: U16<LittleEndian>,
    /// Length of substitute name (in bytes, excludes null terminator).
    substitute_name_length: U16<LittleEndian>,
    /// Offset in `PathBuffer` where print name starts (in bytes).
    print_name_offset: U16<LittleEndian>,
    /// Length of print name (in bytes, excludes null terminator).
    print_name_length: U16<LittleEndian>,
    /// Flags (0 = absolute, 1 = relative).
    flags: U32<LittleEndian>,
}

/// Header for mount point reparse data (8 bytes).
///
/// Reference: [MS-FSCC] 2.1.2.5 Mount Point Reparse Data Buffer
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct MountPointReparseDataHeader {
    /// Offset in `PathBuffer` where substitute name starts (in bytes).
    substitute_name_offset: U16<LittleEndian>,
    /// Length of substitute name (in bytes, excludes null terminator).
    substitute_name_length: U16<LittleEndian>,
    /// Offset in `PathBuffer` where print name starts (in bytes).
    print_name_offset: U16<LittleEndian>,
    /// Length of print name (in bytes, excludes null terminator).
    print_name_length: U16<LittleEndian>,
}

/// Header for WSL symbolic link reparse data (4 bytes).
///
/// Reference: [MS-FSCC] 2.1.2.7 LX SYMLINK Reparse Data Buffer
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct LxSymlinkReparseDataHeader {
    /// Version field - MUST be 2.
    version: U32<LittleEndian>,
}

/// Header for App Execution Link reparse data (4 bytes).
///
/// Used by UWP/MSIX app execution aliases (e.g., `python.exe`, `wt.exe`
/// in `%LOCALAPPDATA%\Microsoft\WindowsApps\`).
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct AppExecLinkReparseDataHeader {
    /// Version field (typically 3).
    version: U32<LittleEndian>,
}

/// Header for NFS reparse data.
///
/// Reference: [MS-FSCC] 2.1.2.6 NFS Reparse Data Buffer
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct NfsReparseDataHeader {
    /// Type field - identifies format of `DataBuffer`.
    nfs_type: U64<LittleEndian>,
}

/// Device data for NFS character and block special files (major + minor).
///
/// Reference: [MS-FSCC] 2.1.2.6
#[derive(Clone, Debug, FromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(C, packed)]
struct NfsDeviceData {
    /// Major device number.
    major: U32<LittleEndian>,
    /// Minor device number.
    minor: U32<LittleEndian>,
}

/// NFS special file type constants (ASCII strings as 64-bit integers).
///
/// Reference: [MS-FSCC] 2.1.2.6
pub mod nfs_types {
    /// NFS symbolic link (0x00000000014B4E4C).
    pub const NFS_SPECFILE_LNK: u64 = 0x0000_0000_014B_4E4C;
    /// NFS character special file (0x0000000000524843).
    pub const NFS_SPECFILE_CHR: u64 = 0x0000_0000_0052_4843;
    /// NFS block special file (0x00000000004B4C42).
    pub const NFS_SPECFILE_BLK: u64 = 0x0000_0000_004B_4C42;
    /// NFS FIFO / named pipe ("FIFO" as u64).
    pub const NFS_SPECFILE_FIFO: u64 = 0x0000_0000_4F46_4946;
    /// NFS socket ("SOCK" as u64).
    pub const NFS_SPECFILE_SOCK: u64 = 0x0000_0000_4B43_4F53;
}

/// Reparse tag constants for direct comparison.
///
/// Reference: [MS-FSCC] 2.1.2.1
pub mod reparse_tags {
    /// Reserved tag value 0.
    pub const RESERVED_ZERO: u32 = 0x0000_0000;
    /// Reserved tag value 1.
    pub const RESERVED_ONE: u32 = 0x0000_0001;
    /// Reserved tag value 2.
    pub const RESERVED_TWO: u32 = 0x0000_0002;
    /// Mount point or junction.
    pub const MOUNT_POINT: u32 = 0xA000_0003;
    /// Symbolic link.
    pub const SYMLINK: u32 = 0xA000_000C;
    /// Windows Overlay Filter (compression).
    pub const WOF: u32 = 0x8000_0017;
    /// Data deduplication.
    pub const DEDUP: u32 = 0x8000_0013;
    /// Network File System.
    pub const NFS: u32 = 0x8000_0014;
    /// App execution link for UWP apps.
    pub const APPEXECLINK: u32 = 0x8000_001B;
    /// Cloud Files / `OneDrive` (base tag).
    pub const CLOUD: u32 = 0x9000_001A;
    /// Projected File System (VFS for Git).
    pub const PROJFS: u32 = 0x9000_001C;
    /// WSL symbolic link.
    pub const LX_SYMLINK: u32 = 0xA000_001D;
    /// Azure File Sync.
    pub const STORAGE_SYNC: u32 = 0x8000_001E;
    /// Unix domain socket.
    pub const AF_UNIX: u32 = 0x8000_0023;
    /// WSL FIFO / named pipe.
    pub const LX_FIFO: u32 = 0x8000_0024;
    /// WSL character special file.
    pub const LX_CHR: u32 = 0x8000_0025;
    /// WSL block special file.
    pub const LX_BLK: u32 = 0x8000_0026;
    /// Distributed File System.
    pub const DFS: u32 = 0x8000_000A;
    /// DFS Replication.
    pub const DFSR: u32 = 0x8000_0012;
    /// WIM Mount filter.
    pub const WIM: u32 = 0x8000_0008;
    /// Single-instance storage.
    pub const SIS: u32 = 0x8000_0007;
    /// Global reparse - named pipe symlink.
    pub const GLOBAL_REPARSE: u32 = 0xA000_0019;
    /// Windows Container Isolation.
    pub const WCI: u32 = 0x8000_0018;
    /// Hierarchical Storage Management (version 1).
    pub const HSM: u32 = 0xC000_0004;
    /// Drive Extender.
    pub const DRIVE_EXTENDER: u32 = 0x8000_0005;
    /// Hierarchical Storage Management (version 2).
    pub const HSM2: u32 = 0x8000_0006;
    /// Cluster Shared Volume.
    pub const CSV: u32 = 0x8000_0009;
    /// Filter Manager test harness.
    pub const FILTER_MANAGER: u32 = 0x8000_000B;
    /// IIS cache.
    pub const IIS_CACHE: u32 = 0xA000_0010;
    /// `AppX` streaming.
    pub const APPXSTRM: u32 = 0xC000_0014;
    /// File placeholder (legacy, pre-OneDrive).
    pub const FILE_PLACEHOLDER: u32 = 0x8000_0015;
    /// Dynamic File Manager.
    pub const DFM: u32 = 0x8000_0016;
    /// Windows Container Isolation variant 1.
    pub const WCI_1: u32 = 0x9000_1018;
    /// WCI tombstone.
    pub const WCI_TOMBSTONE: u32 = 0xA000_001F;
    /// Unhandled reparse point.
    pub const UNHANDLED: u32 = 0x8000_0020;
    /// `OneDrive`.
    pub const ONEDRIVE: u32 = 0x8000_0021;
    /// `ProjFS` tombstone.
    pub const PROJFS_TOMBSTONE: u32 = 0xA000_0022;
    /// Storage Sync folder.
    pub const STORAGE_SYNC_FOLDER: u32 = 0x9000_0027;
    /// WCI link.
    pub const WCI_LINK: u32 = 0xA000_0027;
    /// WCI link variant 1.
    pub const WCI_LINK_1: u32 = 0xA000_1027;
}

/// Symbolic link flags.
///
/// Reference: [MS-FSCC] 2.1.2.4
pub mod symlink_flags {
    /// Substitute name is a full (absolute) path.
    pub const ABSOLUTE: u32 = 0x0000_0000;
    /// Substitute name is relative to the directory containing the symlink.
    pub const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;
}

/// Known NTFS reparse point tags.
///
/// This enum covers the most commonly encountered reparse tags.
/// Less common tags will be represented as `Unknown(u32)`.
///
/// Reference: [MS-FSCC] 2.1.2.1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NtfsReparseTag {
    // === Name Surrogate Tags (N bit set) ===
    /// Mount point or junction (0xA0000003).
    MountPoint,
    /// Symbolic link (0xA000000C).
    SymbolicLink,
    /// WSL symbolic link (0xA000001D).
    LxSymlink,
    /// Global reparse - named pipe symlink (0xA0000019).
    GlobalReparse,

    // === Filter Driver Tags ===
    /// Windows Overlay Filter - compression (0x80000017).
    Wof,
    /// Data deduplication (0x80000013).
    Dedup,
    /// Network File System (0x80000014).
    Nfs,
    /// App execution link for UWP apps (0x8000001B).
    AppExecLink,
    /// Azure File Sync (0x8000001E).
    StorageSync,
    /// Distributed File System (0x8000000A).
    Dfs,
    /// DFS Replication (0x80000012).
    Dfsr,
    /// WIM Mount filter (0x80000008).
    Wim,
    /// Single-instance storage (0x80000007).
    Sis,

    // === Cloud/Projected FS Tags (D bit set) ===
    /// Cloud Files / `OneDrive` (0x9000X01A variants).
    Cloud,
    /// Projected File System - VFS for Git (0x9000001C).
    ProjFs,

    // === WSL Special File Tags ===
    /// Unix domain socket (0x80000023).
    AfUnix,
    /// WSL FIFO / named pipe (0x80000024).
    LxFifo,
    /// WSL character special file (0x80000025).
    LxChr,
    /// WSL block special file (0x80000026).
    LxBlk,

    // === Container Isolation Tags ===
    /// Windows Container Isolation (0x80000018).
    Wci,
    /// Windows Container Isolation variant 1 (0x90001018).
    Wci1,
    /// WCI tombstone (0xA000001F).
    WciTombstone,
    /// WCI link (0xA0000027).
    WciLink,
    /// WCI link variant 1 (0xA0001027).
    WciLink1,

    // === Storage Management Tags ===
    /// Hierarchical Storage Management v1 (0xC0000004).
    Hsm,
    /// Drive Extender (0x80000005).
    DriveExtender,
    /// Hierarchical Storage Management v2 (0x80000006).
    Hsm2,
    /// Cluster Shared Volume (0x80000009).
    Csv,
    /// Filter Manager test harness (0x8000000B).
    FilterManager,
    /// IIS cache (0xA0000010).
    IisCache,
    /// `AppX` streaming (0xC0000014).
    Appxstrm,
    /// File placeholder - legacy, pre-OneDrive (0x80000015).
    FilePlaceholder,
    /// Dynamic File Manager (0x80000016).
    Dfm,
    /// Unhandled reparse point (0x80000020).
    Unhandled,
    /// `OneDrive` (0x80000021).
    OneDrive,
    /// `ProjFS` tombstone (0xA0000022).
    ProjFsTombstone,
    /// Storage Sync folder (0x90000027).
    StorageSyncFolder,

    /// Unknown or unrecognized reparse tag.
    Unknown(u32),
}

impl NtfsReparseTag {
    /// Returns the raw u32 tag value.
    #[must_use]
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::MountPoint => reparse_tags::MOUNT_POINT,
            Self::SymbolicLink => reparse_tags::SYMLINK,
            Self::LxSymlink => reparse_tags::LX_SYMLINK,
            Self::GlobalReparse => reparse_tags::GLOBAL_REPARSE,
            Self::Wof => reparse_tags::WOF,
            Self::Dedup => reparse_tags::DEDUP,
            Self::Nfs => reparse_tags::NFS,
            Self::AppExecLink => reparse_tags::APPEXECLINK,
            Self::StorageSync => reparse_tags::STORAGE_SYNC,
            Self::Dfs => reparse_tags::DFS,
            Self::Dfsr => reparse_tags::DFSR,
            Self::Wim => reparse_tags::WIM,
            Self::Sis => reparse_tags::SIS,
            Self::Cloud => reparse_tags::CLOUD,
            Self::ProjFs => reparse_tags::PROJFS,
            Self::AfUnix => reparse_tags::AF_UNIX,
            Self::LxFifo => reparse_tags::LX_FIFO,
            Self::LxChr => reparse_tags::LX_CHR,
            Self::LxBlk => reparse_tags::LX_BLK,
            Self::Wci => reparse_tags::WCI,
            Self::Wci1 => reparse_tags::WCI_1,
            Self::WciTombstone => reparse_tags::WCI_TOMBSTONE,
            Self::WciLink => reparse_tags::WCI_LINK,
            Self::WciLink1 => reparse_tags::WCI_LINK_1,
            Self::Hsm => reparse_tags::HSM,
            Self::DriveExtender => reparse_tags::DRIVE_EXTENDER,
            Self::Hsm2 => reparse_tags::HSM2,
            Self::Csv => reparse_tags::CSV,
            Self::FilterManager => reparse_tags::FILTER_MANAGER,
            Self::IisCache => reparse_tags::IIS_CACHE,
            Self::Appxstrm => reparse_tags::APPXSTRM,
            Self::FilePlaceholder => reparse_tags::FILE_PLACEHOLDER,
            Self::Dfm => reparse_tags::DFM,
            Self::Unhandled => reparse_tags::UNHANDLED,
            Self::OneDrive => reparse_tags::ONEDRIVE,
            Self::ProjFsTombstone => reparse_tags::PROJFS_TOMBSTONE,
            Self::StorageSyncFolder => reparse_tags::STORAGE_SYNC_FOLDER,
            Self::Unknown(v) => *v,
        }
    }

    /// Returns true if this is a Microsoft-owned tag (M bit set).
    #[must_use]
    pub fn is_microsoft(&self) -> bool {
        self.as_u32() & 0x8000_0000 != 0
    }

    /// Returns true if this is a name surrogate (N bit set).
    ///
    /// Name surrogates represent another named entity (symlinks, junctions).
    #[must_use]
    pub fn is_name_surrogate(&self) -> bool {
        self.as_u32() & 0x2000_0000 != 0
    }

    /// Returns true if the directory bit is set (D bit).
    ///
    /// Indicates directory with this tag can have children.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.as_u32() & 0x1000_0000 != 0
    }

    /// Returns true if this is a reserved tag value.
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        matches!(self.as_u32(), 0..=2)
    }

    /// Parse a raw u32 tag value into a known or unknown tag.
    #[must_use]
    pub fn from_u32(value: u32) -> Self {
        // Check for Cloud Files variants (0x9000X01A pattern where X is 0-F)
        if (value & 0xFFFF_0FFF) == 0x9000_001A {
            return Self::Cloud;
        }
        match value {
            reparse_tags::MOUNT_POINT => Self::MountPoint,
            reparse_tags::SYMLINK => Self::SymbolicLink,
            reparse_tags::LX_SYMLINK => Self::LxSymlink,
            reparse_tags::GLOBAL_REPARSE => Self::GlobalReparse,
            reparse_tags::WOF => Self::Wof,
            reparse_tags::DEDUP => Self::Dedup,
            reparse_tags::NFS => Self::Nfs,
            reparse_tags::APPEXECLINK => Self::AppExecLink,
            reparse_tags::STORAGE_SYNC => Self::StorageSync,
            reparse_tags::DFS => Self::Dfs,
            reparse_tags::DFSR => Self::Dfsr,
            reparse_tags::WIM => Self::Wim,
            reparse_tags::SIS => Self::Sis,
            reparse_tags::PROJFS => Self::ProjFs,
            reparse_tags::AF_UNIX => Self::AfUnix,
            reparse_tags::LX_FIFO => Self::LxFifo,
            reparse_tags::LX_CHR => Self::LxChr,
            reparse_tags::LX_BLK => Self::LxBlk,
            reparse_tags::WCI => Self::Wci,
            reparse_tags::WCI_1 => Self::Wci1,
            reparse_tags::WCI_TOMBSTONE => Self::WciTombstone,
            reparse_tags::WCI_LINK => Self::WciLink,
            reparse_tags::WCI_LINK_1 => Self::WciLink1,
            reparse_tags::HSM => Self::Hsm,
            reparse_tags::DRIVE_EXTENDER => Self::DriveExtender,
            reparse_tags::HSM2 => Self::Hsm2,
            reparse_tags::CSV => Self::Csv,
            reparse_tags::FILTER_MANAGER => Self::FilterManager,
            reparse_tags::IIS_CACHE => Self::IisCache,
            reparse_tags::APPXSTRM => Self::Appxstrm,
            reparse_tags::FILE_PLACEHOLDER => Self::FilePlaceholder,
            reparse_tags::DFM => Self::Dfm,
            reparse_tags::UNHANDLED => Self::Unhandled,
            reparse_tags::ONEDRIVE => Self::OneDrive,
            reparse_tags::PROJFS_TOMBSTONE => Self::ProjFsTombstone,
            reparse_tags::STORAGE_SYNC_FOLDER => Self::StorageSyncFolder,
            _ => Self::Unknown(value),
        }
    }
}

#[cfg(test)]
#[path = "reparse_point_tests/mod.rs"]
mod tests;
