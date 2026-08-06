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
const REPARSE_POINT_HEADER_SIZE: usize = 8;

/// Maximum path buffer size for no_std compatibility (4KB should be sufficient for paths).
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
/// Reference: [MS-FSCC] 2.1.2.2 REPARSE_DATA_BUFFER
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
    /// Offset in PathBuffer where substitute name starts (in bytes).
    substitute_name_offset: U16<LittleEndian>,
    /// Length of substitute name (in bytes, excludes null terminator).
    substitute_name_length: U16<LittleEndian>,
    /// Offset in PathBuffer where print name starts (in bytes).
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
    /// Offset in PathBuffer where substitute name starts (in bytes).
    substitute_name_offset: U16<LittleEndian>,
    /// Length of substitute name (in bytes, excludes null terminator).
    substitute_name_length: U16<LittleEndian>,
    /// Offset in PathBuffer where print name starts (in bytes).
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
    /// Type field - identifies format of DataBuffer.
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
    /// Cloud Files / OneDrive (base tag).
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
    /// AppX streaming.
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
    /// OneDrive.
    pub const ONEDRIVE: u32 = 0x8000_0021;
    /// ProjFS tombstone.
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
    /// Cloud Files / OneDrive (0x9000X01A variants).
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
    /// AppX streaming (0xC0000014).
    Appxstrm,
    /// File placeholder - legacy, pre-OneDrive (0x80000015).
    FilePlaceholder,
    /// Dynamic File Manager (0x80000016).
    Dfm,
    /// Unhandled reparse point (0x80000020).
    Unhandled,
    /// OneDrive (0x80000021).
    OneDrive,
    /// ProjFS tombstone (0xA0000022).
    ProjFsTombstone,
    /// Storage Sync folder (0x90000027).
    StorageSyncFolder,

    /// Unknown or unrecognized reparse tag.
    Unknown(u32),
}

impl NtfsReparseTag {
    /// Returns the raw u32 tag value.
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
    pub fn is_microsoft(&self) -> bool {
        self.as_u32() & 0x8000_0000 != 0
    }

    /// Returns true if this is a name surrogate (N bit set).
    ///
    /// Name surrogates represent another named entity (symlinks, junctions).
    pub fn is_name_surrogate(&self) -> bool {
        self.as_u32() & 0x2000_0000 != 0
    }

    /// Returns true if the directory bit is set (D bit).
    ///
    /// Indicates directory with this tag can have children.
    pub fn is_directory(&self) -> bool {
        self.as_u32() & 0x1000_0000 != 0
    }

    /// Returns true if this is a reserved tag value.
    pub fn is_reserved(&self) -> bool {
        matches!(self.as_u32(), 0..=2)
    }

    /// Parse a raw u32 tag value into a known or unknown tag.
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

/// Parsed NTFS reparse point data.
///
/// This is the main structured value for the $REPARSE_POINT attribute (0xC0).
/// It contains the reparse tag, optional GUID (for third-party reparse points),
/// and the raw reparse data.
///
/// Use [`as_symbolic_link`](Self::as_symbolic_link) or [`as_mount_point`](Self::as_mount_point)
/// to parse the data as a specific reparse point type.
///
/// Reference: [MS-FSCC] 2.1.2.2, 2.1.2.3
#[derive(Clone, Debug)]
pub struct NtfsReparsePoint {
    /// Raw reparse tag value.
    tag: u32,
    /// For third-party reparse points, the owner GUID.
    guid: Option<NtfsGuid>,
    /// Raw reparse data (after header, excluding GUID if present).
    data: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsReparsePoint {
    /// Creates an [`NtfsReparsePoint`] directly from a byte slice.
    ///
    /// This is useful for testing and fuzzing, bypassing the attribute value
    /// parsing layer.
    pub fn from_bytes(data: &[u8], position: NtfsPosition) -> Result<Self> {
        let value_length = data.len() as u64;
        let mut cursor = ReadOnlyCursor::new(data);
        Self::new(&mut cursor, position, value_length)
    }

    fn new<T>(r: &mut T, position: NtfsPosition, value_length: u64) -> Result<Self>
    where
        T: Read,
    {
        if value_length < REPARSE_POINT_HEADER_SIZE as u64 {
            return Err(NtfsError::InvalidReparsePointData {
                position,
                reason: "reparse point data too small for header",
            });
        }

        let header = read_pod::<T, ReparsePointHeader, REPARSE_POINT_HEADER_SIZE>(r)?;
        let tag = header.reparse_tag.get();
        let data_length = header.reparse_data_length.get() as usize;

        // Check if this is a Microsoft reparse point (M bit set)
        let is_microsoft = tag & 0x8000_0000 != 0;

        // For third-party reparse points, read the GUID
        let guid = if !is_microsoft && data_length >= GUID_SIZE {
            Some(read_pod::<T, NtfsGuid, GUID_SIZE>(r)?)
        } else {
            None
        };

        // Calculate remaining data length
        let remaining_data_length = if guid.is_some() {
            data_length.saturating_sub(GUID_SIZE)
        } else {
            data_length
        };

        if remaining_data_length > MAX_PATH_BUFFER_SIZE {
            return Err(NtfsError::ReparseDataTooLarge {
                position,
                size: remaining_data_length,
                max_size: MAX_PATH_BUFFER_SIZE,
            });
        }

        // Read the remaining reparse data
        let mut data = ArrayVec::from([0u8; MAX_PATH_BUFFER_SIZE]);
        r.read_exact(&mut data[..remaining_data_length])?;
        data.truncate(remaining_data_length);

        Ok(Self { tag, guid, data })
    }

    /// Returns the raw reparse tag value.
    pub fn tag(&self) -> u32 {
        self.tag
    }

    /// Returns the parsed reparse tag (known or unknown).
    pub fn tag_type(&self) -> NtfsReparseTag {
        NtfsReparseTag::from_u32(self.tag)
    }

    /// Returns true if this is a Microsoft-owned reparse point.
    pub fn is_microsoft(&self) -> bool {
        self.tag & 0x8000_0000 != 0
    }

    /// Returns true if this is a name surrogate (symlink/junction).
    pub fn is_name_surrogate(&self) -> bool {
        self.tag & 0x2000_0000 != 0
    }

    /// Returns the third-party GUID if this is not a Microsoft reparse point.
    pub fn guid(&self) -> Option<&NtfsGuid> {
        self.guid.as_ref()
    }

    /// Returns the raw reparse data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Attempts to parse as a symbolic link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_SYMLINK`.
    pub fn as_symbolic_link(&self) -> Result<NtfsSymbolicLink> {
        NtfsSymbolicLink::from_reparse_point(self)
    }

    /// Attempts to parse as a mount point/junction.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_MOUNT_POINT`.
    pub fn as_mount_point(&self) -> Result<NtfsMountPoint> {
        NtfsMountPoint::from_reparse_point(self)
    }

    /// Attempts to parse as a WSL symbolic link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_LX_SYMLINK`.
    pub fn as_lx_symlink(&self) -> Result<NtfsLxSymlink> {
        NtfsLxSymlink::from_reparse_point(self)
    }

    /// Attempts to parse as a UWP app execution link.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_APPEXECLINK`.
    pub fn as_app_exec_link(&self) -> Result<NtfsAppExecLink> {
        NtfsAppExecLink::from_reparse_point(self)
    }

    /// Attempts to parse as an NFS reparse point.
    ///
    /// Returns an error if the reparse tag is not `IO_REPARSE_TAG_NFS`.
    pub fn as_nfs_reparse_point(&self) -> Result<NtfsNfsReparsePoint> {
        NtfsNfsReparsePoint::from_reparse_point(self)
    }
}

impl_structured_value_via_new!(NtfsReparsePoint, NtfsAttributeType::ReparsePoint);

impl<'n, 'f> NtfsStructuredValueFromResidentAttributeValue<'n, 'f> for NtfsReparsePoint {
    fn from_resident_attribute_value(value: NtfsResidentAttributeValue<'f>) -> Result<Self> {
        let position = value.data_position();
        let value_length = value.len();

        let mut cursor = ReadOnlyCursor::new(value.data());
        Self::new(&mut cursor, position, value_length)
    }
}

/// Parsed symbolic link reparse point.
///
/// A symbolic link has two names:
/// - **Substitute name**: The target path used for resolution.
/// - **Print name**: A display-friendly path for the user.
///
/// Reference: [MS-FSCC] 2.1.2.4
#[derive(Clone, Debug)]
pub struct NtfsSymbolicLink {
    /// The target path (substitute name) as UTF-16LE bytes.
    substitute_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// The display path (print name) as UTF-16LE bytes.
    print_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// True if this is a relative symlink.
    is_relative: bool,
}

impl NtfsSymbolicLink {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::SYMLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::SYMLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < SYMLINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "symbolic link data too small for header",
            });
        }

        // Parse the header
        let header = SymbolicLinkReparseDataHeader::read_from_bytes(
            &data[..SYMLINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse symbolic link header",
        })?;

        let substitute_name_offset = header.substitute_name_offset.get() as usize;
        let substitute_name_length = header.substitute_name_length.get() as usize;
        let print_name_offset = header.print_name_offset.get() as usize;
        let print_name_length = header.print_name_length.get() as usize;
        let flags = header.flags.get();

        let path_buffer = &data[SYMLINK_REPARSE_DATA_HEADER_SIZE..];

        // Extract substitute name
        let substitute_name_end = substitute_name_offset + substitute_name_length;
        if substitute_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name extends beyond path buffer",
            });
        }
        let mut substitute_name = ArrayVec::new();
        substitute_name
            .try_extend_from_slice(&path_buffer[substitute_name_offset..substitute_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name too large",
            })?;

        // Extract print name
        let print_name_end = print_name_offset + print_name_length;
        if print_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name extends beyond path buffer",
            });
        }
        let mut print_name = ArrayVec::new();
        print_name
            .try_extend_from_slice(&path_buffer[print_name_offset..print_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name too large",
            })?;

        let is_relative = flags & symlink_flags::SYMLINK_FLAG_RELATIVE != 0;

        Ok(Self {
            substitute_name,
            print_name,
            is_relative,
        })
    }

    /// Returns the substitute name as UTF-16LE bytes.
    pub fn substitute_name_bytes(&self) -> &[u8] {
        &self.substitute_name
    }

    /// Returns the print name as UTF-16LE bytes.
    pub fn print_name_bytes(&self) -> &[u8] {
        &self.print_name
    }

    /// Returns true if this is a relative symbolic link.
    pub fn is_relative(&self) -> bool {
        self.is_relative
    }

    /// Decodes the substitute name to a String.
    pub fn substitute_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.substitute_name)
    }

    /// Decodes the print name to a String.
    pub fn print_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.print_name)
    }
}

/// Parsed mount point/junction reparse point.
///
/// A mount point (also known as a junction) has two names:
/// - **Substitute name**: The target path used for resolution.
/// - **Print name**: A display-friendly path for the user.
///
/// Unlike symbolic links, mount points do NOT have a flags field and
/// cannot be relative.
///
/// Reference: [MS-FSCC] 2.1.2.5
#[derive(Clone, Debug)]
pub struct NtfsMountPoint {
    /// The target path (substitute name) as UTF-16LE bytes.
    substitute_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// The display path (print name) as UTF-16LE bytes.
    print_name: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsMountPoint {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::MOUNT_POINT {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::MOUNT_POINT,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < MOUNT_POINT_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "mount point data too small for header",
            });
        }

        // Parse the header
        let header = MountPointReparseDataHeader::read_from_bytes(
            &data[..MOUNT_POINT_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse mount point header",
        })?;

        let substitute_name_offset = header.substitute_name_offset.get() as usize;
        let substitute_name_length = header.substitute_name_length.get() as usize;
        let print_name_offset = header.print_name_offset.get() as usize;
        let print_name_length = header.print_name_length.get() as usize;

        let path_buffer = &data[MOUNT_POINT_REPARSE_DATA_HEADER_SIZE..];

        // Extract substitute name
        let substitute_name_end = substitute_name_offset + substitute_name_length;
        if substitute_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name extends beyond path buffer",
            });
        }
        let mut substitute_name = ArrayVec::new();
        substitute_name
            .try_extend_from_slice(&path_buffer[substitute_name_offset..substitute_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "substitute name too large",
            })?;

        // Extract print name
        let print_name_end = print_name_offset + print_name_length;
        if print_name_end > path_buffer.len() {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name extends beyond path buffer",
            });
        }
        let mut print_name = ArrayVec::new();
        print_name
            .try_extend_from_slice(&path_buffer[print_name_offset..print_name_end])
            .map_err(|_| NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "print name too large",
            })?;

        Ok(Self {
            substitute_name,
            print_name,
        })
    }

    /// Returns the substitute name as UTF-16LE bytes.
    pub fn substitute_name_bytes(&self) -> &[u8] {
        &self.substitute_name
    }

    /// Returns the print name as UTF-16LE bytes.
    pub fn print_name_bytes(&self) -> &[u8] {
        &self.print_name
    }

    /// Decodes the substitute name to a String.
    pub fn substitute_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.substitute_name)
    }

    /// Decodes the print name to a String.
    pub fn print_name(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.print_name)
    }
}

/// Parsed WSL symbolic link reparse point.
///
/// WSL symlinks store a UTF-8 target path (not UTF-16LE like Windows symlinks).
/// The reparse data contains a 4-byte version header followed by the raw
/// UTF-8 target path bytes with no null terminator.
///
/// Reference: [MS-FSCC] 2.1.2.7
#[derive(Clone, Debug)]
pub struct NtfsLxSymlink {
    /// The target path as UTF-8 bytes.
    target_path: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsLxSymlink {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::LX_SYMLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::LX_SYMLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < LX_SYMLINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WSL symlink data too small for header",
            });
        }

        let header = LxSymlinkReparseDataHeader::read_from_bytes(
            &data[..LX_SYMLINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse WSL symlink header",
        })?;

        if header.version.get() != LX_SYMLINK_VERSION {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unsupported WSL symlink version (expected 2)",
            });
        }

        let path_bytes = &data[LX_SYMLINK_REPARSE_DATA_HEADER_SIZE..];
        let mut target_path = ArrayVec::new();
        target_path.try_extend_from_slice(path_bytes).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "WSL symlink target path too large",
            }
        })?;

        Ok(Self { target_path })
    }

    /// Returns the target path as raw UTF-8 bytes.
    pub fn target_path_bytes(&self) -> &[u8] {
        &self.target_path
    }

    /// Validates and returns the target path as a string slice.
    pub fn target_path(&self) -> Result<&str> {
        core::str::from_utf8(&self.target_path).map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "WSL symlink target path is not valid UTF-8",
        })
    }
}

/// Parsed UWP app execution link reparse point.
///
/// AppExecLink reparse points are used by Windows to create execution aliases
/// for UWP/MSIX apps (e.g., `python.exe`, `wt.exe` in
/// `%LOCALAPPDATA%\Microsoft\WindowsApps\`).
///
/// The reparse data contains a 4-byte version header followed by
/// null-terminated UTF-16LE strings for package ID, entry point,
/// executable path, and optionally application type.
#[derive(Clone, Debug)]
pub struct NtfsAppExecLink {
    /// Version from the header (typically 3).
    version: u32,
    /// Package family name as UTF-16LE bytes.
    package_id: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Application user model ID as UTF-16LE bytes.
    entry_point: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Target executable path as UTF-16LE bytes.
    executable: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
    /// Application type as UTF-16LE bytes (may be empty).
    application_type: ArrayVec<u8, MAX_PATH_BUFFER_SIZE>,
}

impl NtfsAppExecLink {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::APPEXECLINK {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::APPEXECLINK,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink data too small for header",
            });
        }

        let header = AppExecLinkReparseDataHeader::read_from_bytes(
            &data[..APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE],
        )
        .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse AppExecLink header",
        })?;

        let version = header.version.get();
        let string_data = &data[APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE..];

        // Split on UTF-16LE null terminators (0x00, 0x00).
        // We expect 3 required strings + 1 optional.
        let strings = split_utf16le_null_terminated(string_data)?;

        if strings.len() < 3 {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink data contains fewer than 3 strings",
            });
        }

        let mut package_id = ArrayVec::new();
        package_id.try_extend_from_slice(strings[0]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink package ID too large",
            }
        })?;

        let mut entry_point = ArrayVec::new();
        entry_point.try_extend_from_slice(strings[1]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink entry point too large",
            }
        })?;

        let mut executable = ArrayVec::new();
        executable.try_extend_from_slice(strings[2]).map_err(|_| {
            NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "AppExecLink executable path too large",
            }
        })?;

        let mut application_type = ArrayVec::new();
        if strings.len() > 3 {
            application_type
                .try_extend_from_slice(strings[3])
                .map_err(|_| NtfsError::InvalidReparsePointData {
                    position: NtfsPosition::none(),
                    reason: "AppExecLink application type too large",
                })?;
        }

        Ok(Self {
            version,
            package_id,
            entry_point,
            executable,
            application_type,
        })
    }

    /// Returns the header version (typically 3).
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Returns the package family name as UTF-16LE bytes.
    pub fn package_id_bytes(&self) -> &[u8] {
        &self.package_id
    }

    /// Returns the application user model ID as UTF-16LE bytes.
    pub fn entry_point_bytes(&self) -> &[u8] {
        &self.entry_point
    }

    /// Returns the executable path as UTF-16LE bytes.
    pub fn executable_bytes(&self) -> &[u8] {
        &self.executable
    }

    /// Returns the application type as UTF-16LE bytes (may be empty).
    pub fn application_type_bytes(&self) -> &[u8] {
        &self.application_type
    }

    /// Decodes the package family name to a String.
    pub fn package_id(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.package_id)
    }

    /// Decodes the application user model ID to a String.
    pub fn entry_point(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.entry_point)
    }

    /// Decodes the executable path to a String.
    pub fn executable(&self) -> Result<alloc::string::String> {
        decode_utf16le(&self.executable)
    }

    /// Decodes the application type to a String, if present.
    ///
    /// Returns `None` if the application type string was not included
    /// in the reparse data.
    pub fn application_type(&self) -> Option<Result<alloc::string::String>> {
        if self.application_type.is_empty() {
            None
        } else {
            Some(decode_utf16le(&self.application_type))
        }
    }
}

/// Parsed NFS reparse point representing a POSIX special file.
///
/// NFS reparse points encode POSIX file types not native to NTFS. The
/// reparse data contains an 8-byte type field followed by type-specific
/// data.
///
/// Reference: [MS-FSCC] 2.1.2.6
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum NtfsNfsReparsePoint {
    /// POSIX symbolic link with a Unicode (UTF-16LE) target path.
    SymbolicLink {
        /// Target path as UTF-16LE bytes (not null-terminated).
        target: alloc::boxed::Box<ArrayVec<u8, MAX_PATH_BUFFER_SIZE>>,
    },
    /// Character special device with major and minor numbers.
    CharacterDevice {
        /// Major device number.
        major: u32,
        /// Minor device number.
        minor: u32,
    },
    /// Block special device with major and minor numbers.
    BlockDevice {
        /// Major device number.
        major: u32,
        /// Minor device number.
        minor: u32,
    },
    /// FIFO (named pipe).
    Fifo,
    /// Socket.
    Socket,
}

impl NtfsNfsReparsePoint {
    fn from_reparse_point(reparse_point: &NtfsReparsePoint) -> Result<Self> {
        if reparse_point.tag != reparse_tags::NFS {
            return Err(NtfsError::ReparseTagMismatch {
                position: NtfsPosition::none(),
                expected: reparse_tags::NFS,
                actual: reparse_point.tag,
            });
        }

        let data = reparse_point.data();
        if data.len() < NFS_REPARSE_DATA_HEADER_SIZE {
            return Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "NFS reparse data too small for header",
            });
        }

        let header = NfsReparseDataHeader::read_from_bytes(&data[..NFS_REPARSE_DATA_HEADER_SIZE])
            .map_err(|_| NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "failed to parse NFS reparse header",
        })?;

        let nfs_type = header.nfs_type.get();
        let payload = &data[NFS_REPARSE_DATA_HEADER_SIZE..];

        match nfs_type {
            nfs_types::NFS_SPECFILE_LNK => {
                let mut target = ArrayVec::new();
                target.try_extend_from_slice(payload).map_err(|_| {
                    NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS symlink target path too large",
                    }
                })?;
                Ok(Self::SymbolicLink {
                    target: alloc::boxed::Box::new(target),
                })
            }
            nfs_types::NFS_SPECFILE_CHR => {
                if payload.len() < NFS_DEVICE_DATA_SIZE {
                    return Err(NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS character device data too small",
                    });
                }
                let dev = NfsDeviceData::read_from_bytes(&payload[..NFS_DEVICE_DATA_SIZE])
                    .map_err(|_| NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "failed to parse NFS character device data",
                    })?;
                Ok(Self::CharacterDevice {
                    major: dev.major.get(),
                    minor: dev.minor.get(),
                })
            }
            nfs_types::NFS_SPECFILE_BLK => {
                if payload.len() < NFS_DEVICE_DATA_SIZE {
                    return Err(NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "NFS block device data too small",
                    });
                }
                let dev = NfsDeviceData::read_from_bytes(&payload[..NFS_DEVICE_DATA_SIZE])
                    .map_err(|_| NtfsError::InvalidReparsePointData {
                        position: NtfsPosition::none(),
                        reason: "failed to parse NFS block device data",
                    })?;
                Ok(Self::BlockDevice {
                    major: dev.major.get(),
                    minor: dev.minor.get(),
                })
            }
            nfs_types::NFS_SPECFILE_FIFO => Ok(Self::Fifo),
            nfs_types::NFS_SPECFILE_SOCK => Ok(Self::Socket),
            _ => Err(NtfsError::InvalidReparsePointData {
                position: NtfsPosition::none(),
                reason: "unknown NFS special file type",
            }),
        }
    }

    /// Returns the NFS type constant for this reparse point.
    pub fn nfs_type(&self) -> u64 {
        match self {
            Self::SymbolicLink { .. } => nfs_types::NFS_SPECFILE_LNK,
            Self::CharacterDevice { .. } => nfs_types::NFS_SPECFILE_CHR,
            Self::BlockDevice { .. } => nfs_types::NFS_SPECFILE_BLK,
            Self::Fifo => nfs_types::NFS_SPECFILE_FIFO,
            Self::Socket => nfs_types::NFS_SPECFILE_SOCK,
        }
    }

    /// Returns the symlink target as raw UTF-16LE bytes.
    ///
    /// Returns `None` if this is not a symbolic link.
    pub fn target_path_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::SymbolicLink { target } => Some(target),
            _ => None,
        }
    }

    /// Decodes the symlink target to a String.
    ///
    /// Returns `None` if this is not a symbolic link.
    pub fn target_path(&self) -> Option<Result<alloc::string::String>> {
        match self {
            Self::SymbolicLink { target } => Some(decode_utf16le(target)),
            _ => None,
        }
    }

    /// Returns the major device number.
    ///
    /// Returns `None` if this is not a character or block device.
    pub fn major(&self) -> Option<u32> {
        match self {
            Self::CharacterDevice { major, .. } | Self::BlockDevice { major, .. } => Some(*major),
            _ => None,
        }
    }

    /// Returns the minor device number.
    ///
    /// Returns `None` if this is not a character or block device.
    pub fn minor(&self) -> Option<u32> {
        match self {
            Self::CharacterDevice { minor, .. } | Self::BlockDevice { minor, .. } => Some(*minor),
            _ => None,
        }
    }
}

/// Splits a UTF-16LE byte buffer on null terminators (U+0000).
///
/// Returns slices of the content between null terminators, excluding the
/// null terminators themselves. Handles the common case where the final
/// string may or may not have a trailing null.
///
/// Returns an error if the data has an odd number of bytes, since
/// UTF-16LE requires 2-byte alignment.
// mutants::skip: the loop guard `i + 1 < data.len()` has two equivalent
// mutations. After the odd-length early return, `data.len()` is always even
// and `i` always even (starts 0, `i += 2`), so `i + 1` is always odd and can
// never equal `data.len()`. Therefore `< -> <=` (differs only at
// `i + 1 == len`) and `+ -> *` on the guard (`i * 1 == i`, and `i < len` ⟺
// `i + 1 < len` for even i and even len) produce identical behaviour for every
// input — provably equivalent. The killable index mutation `data[i + 1]`
// (1278) is covered by test_split_utf16le_high_byte_not_a_terminator and the
// non-terminating `i += 2 -> i *= 2` mutation (1282) is caught by the harness
// timeout; both are exercised, but the fn must be skipped wholesale because
// `#[mutants::skip]` cannot target a single expression.
#[cfg_attr(test, mutants::skip)]
fn split_utf16le_null_terminated(data: &[u8]) -> Result<alloc::vec::Vec<&[u8]>> {
    if !data.len().is_multiple_of(2) {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "UTF-16LE string data has odd number of bytes",
        });
    }

    let mut result = alloc::vec::Vec::new();
    let mut start = 0;

    // Walk in 2-byte steps looking for U+0000 (0x00, 0x00)
    let mut i = 0;
    while i + 1 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 {
            result.push(&data[start..i]);
            start = i + 2;
        }
        i += 2;
    }

    // If there's a trailing string without a null terminator, include it
    if start < data.len() {
        result.push(&data[start..]);
    }

    Ok(result)
}

/// Decodes UTF-16LE bytes to a String.
pub(super) fn decode_utf16le(bytes: &[u8]) -> Result<alloc::string::String> {
    use alloc::string::String;
    use alloc::vec::Vec;

    if !bytes.len().is_multiple_of(2) {
        return Err(NtfsError::InvalidReparsePointData {
            position: NtfsPosition::none(),
            reason: "UTF-16LE data has odd number of bytes",
        });
    }

    let u16_iter = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]));

    let chars: Vec<u16> = u16_iter.collect();
    String::from_utf16(&chars).map_err(|_| NtfsError::InvalidReparsePointData {
        position: NtfsPosition::none(),
        reason: "invalid UTF-16LE data",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // NtfsReparseTag::as_u32() tests
    // ========================================

    #[test]
    fn test_as_u32_known_tags() {
        assert_eq!(NtfsReparseTag::MountPoint.as_u32(), 0xA000_0003);
        assert_eq!(NtfsReparseTag::SymbolicLink.as_u32(), 0xA000_000C);
        assert_eq!(NtfsReparseTag::LxSymlink.as_u32(), 0xA000_001D);
        assert_eq!(NtfsReparseTag::GlobalReparse.as_u32(), 0xA000_0019);
        assert_eq!(NtfsReparseTag::Wof.as_u32(), 0x8000_0017);
        assert_eq!(NtfsReparseTag::Dedup.as_u32(), 0x8000_0013);
        assert_eq!(NtfsReparseTag::Nfs.as_u32(), 0x8000_0014);
        assert_eq!(NtfsReparseTag::AppExecLink.as_u32(), 0x8000_001B);
        assert_eq!(NtfsReparseTag::StorageSync.as_u32(), 0x8000_001E);
        assert_eq!(NtfsReparseTag::Dfs.as_u32(), 0x8000_000A);
        assert_eq!(NtfsReparseTag::Dfsr.as_u32(), 0x8000_0012);
        assert_eq!(NtfsReparseTag::Wim.as_u32(), 0x8000_0008);
        assert_eq!(NtfsReparseTag::Sis.as_u32(), 0x8000_0007);
        assert_eq!(NtfsReparseTag::Cloud.as_u32(), 0x9000_001A);
        assert_eq!(NtfsReparseTag::ProjFs.as_u32(), 0x9000_001C);
        assert_eq!(NtfsReparseTag::AfUnix.as_u32(), 0x8000_0023);
        assert_eq!(NtfsReparseTag::LxFifo.as_u32(), 0x8000_0024);
        assert_eq!(NtfsReparseTag::LxChr.as_u32(), 0x8000_0025);
        assert_eq!(NtfsReparseTag::LxBlk.as_u32(), 0x8000_0026);
        assert_eq!(NtfsReparseTag::Wci.as_u32(), 0x8000_0018);
        assert_eq!(NtfsReparseTag::Wci1.as_u32(), 0x9000_1018);
        assert_eq!(NtfsReparseTag::WciTombstone.as_u32(), 0xA000_001F);
        assert_eq!(NtfsReparseTag::WciLink.as_u32(), 0xA000_0027);
        assert_eq!(NtfsReparseTag::WciLink1.as_u32(), 0xA000_1027);
        assert_eq!(NtfsReparseTag::Hsm.as_u32(), 0xC000_0004);
        assert_eq!(NtfsReparseTag::DriveExtender.as_u32(), 0x8000_0005);
        assert_eq!(NtfsReparseTag::Hsm2.as_u32(), 0x8000_0006);
        assert_eq!(NtfsReparseTag::Csv.as_u32(), 0x8000_0009);
        assert_eq!(NtfsReparseTag::FilterManager.as_u32(), 0x8000_000B);
        assert_eq!(NtfsReparseTag::IisCache.as_u32(), 0xA000_0010);
        assert_eq!(NtfsReparseTag::Appxstrm.as_u32(), 0xC000_0014);
        assert_eq!(NtfsReparseTag::FilePlaceholder.as_u32(), 0x8000_0015);
        assert_eq!(NtfsReparseTag::Dfm.as_u32(), 0x8000_0016);
        assert_eq!(NtfsReparseTag::Unhandled.as_u32(), 0x8000_0020);
        assert_eq!(NtfsReparseTag::OneDrive.as_u32(), 0x8000_0021);
        assert_eq!(NtfsReparseTag::ProjFsTombstone.as_u32(), 0xA000_0022);
        assert_eq!(NtfsReparseTag::StorageSyncFolder.as_u32(), 0x9000_0027);
    }

    #[test]
    fn test_as_u32_unknown_tag() {
        assert_eq!(NtfsReparseTag::Unknown(0x12345678).as_u32(), 0x12345678);
        assert_eq!(NtfsReparseTag::Unknown(0).as_u32(), 0);
        assert_eq!(NtfsReparseTag::Unknown(u32::MAX).as_u32(), u32::MAX);
    }

    // ========================================
    // NtfsReparseTag::is_microsoft() tests
    // ========================================

    #[test]
    fn test_is_microsoft_with_m_bit_set() {
        // M bit is 0x8000_0000 - all known Microsoft tags have this bit set
        assert!(NtfsReparseTag::MountPoint.is_microsoft()); // 0xA0000003
        assert!(NtfsReparseTag::SymbolicLink.is_microsoft()); // 0xA000000C
        assert!(NtfsReparseTag::Wof.is_microsoft()); // 0x80000017
        assert!(NtfsReparseTag::Cloud.is_microsoft()); // 0x9000001A
        assert!(NtfsReparseTag::ProjFs.is_microsoft()); // 0x9000001C
    }

    #[test]
    fn test_is_microsoft_without_m_bit() {
        // Tags without M bit (third-party)
        assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_microsoft());
        assert!(!NtfsReparseTag::Unknown(0x7FFF_FFFF).is_microsoft());
        assert!(!NtfsReparseTag::Unknown(0x0000_0001).is_microsoft());
    }

    // ========================================
    // NtfsReparseTag::is_name_surrogate() tests
    // ========================================

    #[test]
    fn test_is_name_surrogate_with_n_bit_set() {
        // N bit is 0x2000_0000 - name surrogates represent another named entity
        assert!(NtfsReparseTag::MountPoint.is_name_surrogate()); // 0xA0000003
        assert!(NtfsReparseTag::SymbolicLink.is_name_surrogate()); // 0xA000000C
        assert!(NtfsReparseTag::LxSymlink.is_name_surrogate()); // 0xA000001D
        assert!(NtfsReparseTag::GlobalReparse.is_name_surrogate()); // 0xA0000019
    }

    #[test]
    fn test_is_name_surrogate_without_n_bit() {
        // These tags are NOT name surrogates (no N bit)
        assert!(!NtfsReparseTag::Wof.is_name_surrogate()); // 0x80000017
        assert!(!NtfsReparseTag::Dedup.is_name_surrogate()); // 0x80000013
        assert!(!NtfsReparseTag::Cloud.is_name_surrogate()); // 0x9000001A
        assert!(!NtfsReparseTag::ProjFs.is_name_surrogate()); // 0x9000001C
        assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_name_surrogate());
    }

    // ========================================
    // NtfsReparseTag::is_directory() tests
    // ========================================

    #[test]
    fn test_is_directory_with_d_bit_set() {
        // D bit is 0x1000_0000 - indicates directory with tag can have children
        assert!(NtfsReparseTag::Cloud.is_directory()); // 0x9000001A
        assert!(NtfsReparseTag::ProjFs.is_directory()); // 0x9000001C
    }

    #[test]
    fn test_is_directory_without_d_bit() {
        // These tags do NOT have D bit set
        assert!(!NtfsReparseTag::MountPoint.is_directory()); // 0xA0000003
        assert!(!NtfsReparseTag::SymbolicLink.is_directory()); // 0xA000000C
        assert!(!NtfsReparseTag::Wof.is_directory()); // 0x80000017
        assert!(!NtfsReparseTag::Unknown(0x0000_0000).is_directory());
    }

    // ========================================
    // NtfsReparseTag::is_reserved() tests
    // ========================================

    #[test]
    fn test_is_reserved_values() {
        assert!(NtfsReparseTag::Unknown(0).is_reserved());
        assert!(NtfsReparseTag::Unknown(1).is_reserved());
        assert!(NtfsReparseTag::Unknown(2).is_reserved());
    }

    #[test]
    fn test_is_reserved_non_reserved_values() {
        assert!(!NtfsReparseTag::Unknown(3).is_reserved());
        assert!(!NtfsReparseTag::MountPoint.is_reserved());
        assert!(!NtfsReparseTag::SymbolicLink.is_reserved());
        assert!(!NtfsReparseTag::Unknown(0x8000_0000).is_reserved());
    }

    // ========================================
    // NtfsReparseTag::from_u32() tests
    // ========================================

    #[test]
    fn test_from_u32_known_tags() {
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_0003),
            NtfsReparseTag::MountPoint
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_000C),
            NtfsReparseTag::SymbolicLink
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_001D),
            NtfsReparseTag::LxSymlink
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_0019),
            NtfsReparseTag::GlobalReparse
        );
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0017), NtfsReparseTag::Wof);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0013), NtfsReparseTag::Dedup);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0014), NtfsReparseTag::Nfs);
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_001B),
            NtfsReparseTag::AppExecLink
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_001E),
            NtfsReparseTag::StorageSync
        );
        assert_eq!(NtfsReparseTag::from_u32(0x8000_000A), NtfsReparseTag::Dfs);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0012), NtfsReparseTag::Dfsr);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0008), NtfsReparseTag::Wim);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0007), NtfsReparseTag::Sis);
        assert_eq!(
            NtfsReparseTag::from_u32(0x9000_001C),
            NtfsReparseTag::ProjFs
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0023),
            NtfsReparseTag::AfUnix
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0024),
            NtfsReparseTag::LxFifo
        );
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0025), NtfsReparseTag::LxChr);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0026), NtfsReparseTag::LxBlk);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0018), NtfsReparseTag::Wci);
        assert_eq!(NtfsReparseTag::from_u32(0x9000_1018), NtfsReparseTag::Wci1);
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_001F),
            NtfsReparseTag::WciTombstone
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_0027),
            NtfsReparseTag::WciLink
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_1027),
            NtfsReparseTag::WciLink1
        );
        assert_eq!(NtfsReparseTag::from_u32(0xC000_0004), NtfsReparseTag::Hsm);
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0005),
            NtfsReparseTag::DriveExtender
        );
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0006), NtfsReparseTag::Hsm2);
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0009), NtfsReparseTag::Csv);
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_000B),
            NtfsReparseTag::FilterManager
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_0010),
            NtfsReparseTag::IisCache
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xC000_0014),
            NtfsReparseTag::Appxstrm
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0015),
            NtfsReparseTag::FilePlaceholder
        );
        assert_eq!(NtfsReparseTag::from_u32(0x8000_0016), NtfsReparseTag::Dfm);
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0020),
            NtfsReparseTag::Unhandled
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x8000_0021),
            NtfsReparseTag::OneDrive
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xA000_0022),
            NtfsReparseTag::ProjFsTombstone
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x9000_0027),
            NtfsReparseTag::StorageSyncFolder
        );
    }

    #[test]
    fn test_from_u32_cloud_variants() {
        // Cloud Files uses 0x9000X01A pattern where X is 0-F
        assert_eq!(NtfsReparseTag::from_u32(0x9000_001A), NtfsReparseTag::Cloud);
        assert_eq!(NtfsReparseTag::from_u32(0x9000_101A), NtfsReparseTag::Cloud);
        assert_eq!(NtfsReparseTag::from_u32(0x9000_201A), NtfsReparseTag::Cloud);
        assert_eq!(NtfsReparseTag::from_u32(0x9000_F01A), NtfsReparseTag::Cloud);
    }

    #[test]
    fn test_from_u32_cloud_rejects_near_misses() {
        // Bits 16-27 must be zero for Cloud family
        assert_ne!(NtfsReparseTag::from_u32(0x9ABC_F01A), NtfsReparseTag::Cloud,);
        // Wrong low 12 bits
        assert_ne!(NtfsReparseTag::from_u32(0x9000_001B), NtfsReparseTag::Cloud,);
        // Wrong high nibble
        assert_ne!(NtfsReparseTag::from_u32(0x8000_001A), NtfsReparseTag::Cloud,);
    }

    #[test]
    fn test_from_u32_unknown_tags() {
        assert_eq!(
            NtfsReparseTag::from_u32(0x1234_5678),
            NtfsReparseTag::Unknown(0x1234_5678)
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0x0000_0000),
            NtfsReparseTag::Unknown(0x0000_0000)
        );
        assert_eq!(
            NtfsReparseTag::from_u32(0xFFFF_FFFF),
            NtfsReparseTag::Unknown(0xFFFF_FFFF)
        );
    }

    // ========================================
    // reparse_tags module constants tests
    // ========================================

    #[test]
    fn test_reparse_tags_constants() {
        assert_eq!(reparse_tags::RESERVED_ZERO, 0x0000_0000);
        assert_eq!(reparse_tags::RESERVED_ONE, 0x0000_0001);
        assert_eq!(reparse_tags::RESERVED_TWO, 0x0000_0002);
        assert_eq!(reparse_tags::MOUNT_POINT, 0xA000_0003);
        assert_eq!(reparse_tags::SYMLINK, 0xA000_000C);
        assert_eq!(reparse_tags::WOF, 0x8000_0017);
        assert_eq!(reparse_tags::DEDUP, 0x8000_0013);
        assert_eq!(reparse_tags::NFS, 0x8000_0014);
        assert_eq!(reparse_tags::APPEXECLINK, 0x8000_001B);
        assert_eq!(reparse_tags::CLOUD, 0x9000_001A);
        assert_eq!(reparse_tags::PROJFS, 0x9000_001C);
        assert_eq!(reparse_tags::LX_SYMLINK, 0xA000_001D);
        assert_eq!(reparse_tags::STORAGE_SYNC, 0x8000_001E);
        assert_eq!(reparse_tags::AF_UNIX, 0x8000_0023);
        assert_eq!(reparse_tags::LX_FIFO, 0x8000_0024);
        assert_eq!(reparse_tags::LX_CHR, 0x8000_0025);
        assert_eq!(reparse_tags::LX_BLK, 0x8000_0026);
        assert_eq!(reparse_tags::DFS, 0x8000_000A);
        assert_eq!(reparse_tags::DFSR, 0x8000_0012);
        assert_eq!(reparse_tags::WIM, 0x8000_0008);
        assert_eq!(reparse_tags::SIS, 0x8000_0007);
        assert_eq!(reparse_tags::GLOBAL_REPARSE, 0xA000_0019);
        assert_eq!(reparse_tags::WCI, 0x8000_0018);
        assert_eq!(reparse_tags::HSM, 0xC000_0004);
        assert_eq!(reparse_tags::DRIVE_EXTENDER, 0x8000_0005);
        assert_eq!(reparse_tags::HSM2, 0x8000_0006);
        assert_eq!(reparse_tags::CSV, 0x8000_0009);
        assert_eq!(reparse_tags::FILTER_MANAGER, 0x8000_000B);
        assert_eq!(reparse_tags::IIS_CACHE, 0xA000_0010);
        assert_eq!(reparse_tags::APPXSTRM, 0xC000_0014);
        assert_eq!(reparse_tags::FILE_PLACEHOLDER, 0x8000_0015);
        assert_eq!(reparse_tags::DFM, 0x8000_0016);
        assert_eq!(reparse_tags::WCI_1, 0x9000_1018);
        assert_eq!(reparse_tags::WCI_TOMBSTONE, 0xA000_001F);
        assert_eq!(reparse_tags::UNHANDLED, 0x8000_0020);
        assert_eq!(reparse_tags::ONEDRIVE, 0x8000_0021);
        assert_eq!(reparse_tags::PROJFS_TOMBSTONE, 0xA000_0022);
        assert_eq!(reparse_tags::STORAGE_SYNC_FOLDER, 0x9000_0027);
        assert_eq!(reparse_tags::WCI_LINK, 0xA000_0027);
        assert_eq!(reparse_tags::WCI_LINK_1, 0xA000_1027);
    }

    // ========================================
    // symlink_flags module constants tests
    // ========================================

    #[test]
    fn test_symlink_flags_constants() {
        assert_eq!(symlink_flags::ABSOLUTE, 0x0000_0000);
        assert_eq!(symlink_flags::SYMLINK_FLAG_RELATIVE, 0x0000_0001);
    }

    // ========================================
    // decode_utf16le tests (via helper)
    // ========================================

    #[test]
    fn test_decode_utf16le_valid_ascii() {
        // "test" in UTF-16LE: t=0x74, e=0x65, s=0x73, t=0x74
        let bytes = [0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00];
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_decode_utf16le_empty() {
        let bytes: [u8; 0] = [];
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_decode_utf16le_unicode() {
        // "日本" (Japan) in UTF-16LE: 日=0x65E5, 本=0x672C
        let bytes = [0xE5, 0x65, 0x2C, 0x67];
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, "日本");
    }

    #[test]
    fn test_decode_utf16le_odd_bytes_error() {
        // Odd number of bytes should fail
        let bytes = [0x74, 0x00, 0x65];
        let result = decode_utf16le(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_utf16le_path_like() {
        // "C:\test" in UTF-16LE
        let bytes = [
            0x43, 0x00, // C
            0x3A, 0x00, // :
            0x5C, 0x00, // \
            0x74, 0x00, // t
            0x65, 0x00, // e
            0x73, 0x00, // s
            0x74, 0x00, // t
        ];
        let result = decode_utf16le(&bytes).unwrap();
        assert_eq!(result, "C:\\test");
    }

    // ========================================
    // Roundtrip tests for from_u32 / as_u32
    // ========================================

    // ========================================
    // NtfsLxSymlink tests
    // ========================================

    /// Helper: build an NtfsReparsePoint with the given tag and data.
    fn make_reparse_point(tag: u32, data: &[u8]) -> NtfsReparsePoint {
        NtfsReparsePoint {
            tag,
            guid: None,
            data: {
                let mut av = ArrayVec::new();
                av.try_extend_from_slice(data).expect("test data too large");
                av
            },
        }
    }

    #[test]
    fn test_lx_symlink_simple_path() {
        // Version 2, target = "/usr/bin/test"
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // version
        data.extend_from_slice(b"/usr/bin/test");
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let lx = rp.as_lx_symlink().unwrap();
        assert_eq!(lx.target_path().unwrap(), "/usr/bin/test");
        assert_eq!(lx.target_path_bytes(), b"/usr/bin/test");
    }

    #[test]
    fn test_lx_symlink_relative_path() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(b"../lib/libfoo.so");
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let lx = rp.as_lx_symlink().unwrap();
        assert_eq!(lx.target_path().unwrap(), "../lib/libfoo.so");
    }

    #[test]
    fn test_lx_symlink_empty_path() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        // No path bytes after header
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let lx = rp.as_lx_symlink().unwrap();
        assert_eq!(lx.target_path().unwrap(), "");
        assert!(lx.target_path_bytes().is_empty());
    }

    #[test]
    fn test_lx_symlink_wrong_tag() {
        let data = 2u32.to_le_bytes();
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let err = rp.as_lx_symlink().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
                if expected == reparse_tags::LX_SYMLINK && actual == reparse_tags::SYMLINK)
        );
    }

    #[test]
    fn test_lx_symlink_truncated_header() {
        // Only 3 bytes — not enough for a 4-byte version field
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &[0x02, 0x00, 0x00]);
        let err = rp.as_lx_symlink().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_lx_symlink_wrong_version() {
        let data = 1u32.to_le_bytes(); // version 1, not 2
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let err = rp.as_lx_symlink().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("version")
        ));
    }

    #[test]
    fn test_lx_symlink_invalid_utf8() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0xFF, 0xFE, 0x80]); // invalid UTF-8
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let lx = rp.as_lx_symlink().unwrap();
        // Raw bytes are accessible
        assert_eq!(lx.target_path_bytes(), &[0xFF, 0xFE, 0x80]);
        // But decoding to str fails
        assert!(lx.target_path().is_err());
    }

    #[test]
    fn test_lx_symlink_unicode_path() {
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice("/home/用户/文件".as_bytes());
        let rp = make_reparse_point(reparse_tags::LX_SYMLINK, &data);
        let lx = rp.as_lx_symlink().unwrap();
        assert_eq!(lx.target_path().unwrap(), "/home/用户/文件");
    }

    // ========================================
    // NtfsAppExecLink tests
    // ========================================

    /// Helper: encode a UTF-16LE null-terminated string.
    fn utf16le_null(s: &str) -> Vec<u8> {
        let mut bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0x00, 0x00]); // null terminator
        bytes
    }

    #[test]
    fn test_app_exec_link_full() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes()); // version
        data.extend_from_slice(&utf16le_null("Microsoft.WindowsTerminal_8wekyb3d8bbwe"));
        data.extend_from_slice(&utf16le_null("Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"));
        data.extend_from_slice(&utf16le_null(r"C:\Program Files\WindowsApps\wt.exe"));
        data.extend_from_slice(&utf16le_null("0"));

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let ael = rp.as_app_exec_link().unwrap();

        assert_eq!(ael.version(), 3);
        assert_eq!(
            ael.package_id().unwrap(),
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
        );
        assert_eq!(
            ael.entry_point().unwrap(),
            "Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"
        );
        assert_eq!(
            ael.executable().unwrap(),
            r"C:\Program Files\WindowsApps\wt.exe"
        );
        assert_eq!(ael.application_type().unwrap().unwrap(), "0");
    }

    #[test]
    fn test_app_exec_link_three_strings() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&utf16le_null("PackageId"));
        data.extend_from_slice(&utf16le_null("EntryPoint"));
        data.extend_from_slice(&utf16le_null("Executable"));
        // No application_type

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let ael = rp.as_app_exec_link().unwrap();

        assert_eq!(ael.package_id().unwrap(), "PackageId");
        assert_eq!(ael.entry_point().unwrap(), "EntryPoint");
        assert_eq!(ael.executable().unwrap(), "Executable");
        assert!(ael.application_type().is_none());
    }

    #[test]
    fn test_app_exec_link_wrong_tag() {
        let data = 3u32.to_le_bytes();
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let err = rp.as_app_exec_link().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
                if expected == reparse_tags::APPEXECLINK && actual == reparse_tags::MOUNT_POINT)
        );
    }

    #[test]
    fn test_app_exec_link_truncated_header() {
        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &[0x03, 0x00, 0x00]);
        let err = rp.as_app_exec_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_app_exec_link_too_few_strings() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&utf16le_null("OnlyOne"));
        data.extend_from_slice(&utf16le_null("OnlyTwo"));
        // Only 2 strings — need at least 3

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let err = rp.as_app_exec_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("fewer than 3")
        ));
    }

    #[test]
    fn test_app_exec_link_empty_strings() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&utf16le_null(""));
        data.extend_from_slice(&utf16le_null(""));
        data.extend_from_slice(&utf16le_null(""));

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let ael = rp.as_app_exec_link().unwrap();
        assert_eq!(ael.package_id().unwrap(), "");
        assert_eq!(ael.entry_point().unwrap(), "");
        assert_eq!(ael.executable().unwrap(), "");
    }

    #[test]
    fn test_app_exec_link_unicode_paths() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&utf16le_null("パッケージ"));
        data.extend_from_slice(&utf16le_null("エントリ"));
        data.extend_from_slice(&utf16le_null("C:\\プログラム\\app.exe"));

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let ael = rp.as_app_exec_link().unwrap();
        assert_eq!(ael.package_id().unwrap(), "パッケージ");
        assert_eq!(ael.entry_point().unwrap(), "エントリ");
        assert_eq!(ael.executable().unwrap(), "C:\\プログラム\\app.exe");
    }

    // ========================================
    // split_utf16le_null_terminated tests
    // ========================================

    #[test]
    fn test_split_utf16le_three_strings() {
        // "A\0B\0C\0" in UTF-16LE
        let data = [
            0x41, 0x00, 0x00, 0x00, // "A" + null
            0x42, 0x00, 0x00, 0x00, // "B" + null
            0x43, 0x00, 0x00, 0x00, // "C" + null
        ];
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], &[0x41, 0x00]);
        assert_eq!(parts[1], &[0x42, 0x00]);
        assert_eq!(parts[2], &[0x43, 0x00]);
    }

    #[test]
    fn test_split_utf16le_no_trailing_null() {
        // "A\0B" — second string has no null terminator
        let data = [
            0x41, 0x00, 0x00, 0x00, // "A" + null
            0x42, 0x00, // "B" without null
        ];
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], &[0x41, 0x00]);
        assert_eq!(parts[1], &[0x42, 0x00]);
    }

    #[test]
    fn test_split_utf16le_empty() {
        let parts = split_utf16le_null_terminated(&[]).unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn test_split_utf16le_single_null() {
        // Just a null terminator — one empty string
        let data = [0x00, 0x00];
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 1);
        assert!(parts[0].is_empty());
    }

    #[test]
    fn test_split_utf16le_odd_length_error() {
        // Odd number of bytes — invalid UTF-16LE
        let data = [0x41, 0x00, 0x00];
        let err = split_utf16le_null_terminated(&data).unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("odd number of bytes")
        ));
    }

    #[test]
    fn test_app_exec_link_odd_length_payload() {
        // AppExecLink with odd-length string data should fail early
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&[0x41, 0x00, 0x42]); // 3 bytes — odd
        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let err = rp.as_app_exec_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("odd number of bytes")
        ));
    }

    // ========================================
    // NtfsNfsReparsePoint tests
    // ========================================

    /// Helper: build NFS reparse data with type and payload.
    fn make_nfs_data(nfs_type: u64, payload: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&nfs_type.to_le_bytes());
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn test_nfs_symbolic_link() {
        // Target = "/mnt/share" in UTF-16LE
        let target_utf16: Vec<u8> = "/mnt/share"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &target_utf16);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(nfs, NtfsNfsReparsePoint::SymbolicLink { .. }));
        assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_LNK);
        assert_eq!(nfs.target_path().unwrap().unwrap(), "/mnt/share");
        assert_eq!(nfs.target_path_bytes().unwrap(), target_utf16.as_slice());
        assert!(nfs.major().is_none());
        assert!(nfs.minor().is_none());
    }

    #[test]
    fn test_nfs_symbolic_link_empty_target() {
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &[]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(nfs, NtfsNfsReparsePoint::SymbolicLink { .. }));
        assert_eq!(nfs.target_path().unwrap().unwrap(), "");
        assert!(nfs.target_path_bytes().unwrap().is_empty());
    }

    #[test]
    fn test_nfs_symbolic_link_unicode_target() {
        // Target = "/home/用户" in UTF-16LE
        let target_utf16: Vec<u8> = "/home/用户"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &target_utf16);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert_eq!(nfs.target_path().unwrap().unwrap(), "/home/用户");
    }

    #[test]
    fn test_nfs_character_device() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5u32.to_le_bytes()); // major
        payload.extend_from_slice(&1u32.to_le_bytes()); // minor
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(
            nfs,
            NtfsNfsReparsePoint::CharacterDevice { major: 5, minor: 1 }
        ));
        assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_CHR);
        assert_eq!(nfs.major(), Some(5));
        assert_eq!(nfs.minor(), Some(1));
        assert!(nfs.target_path().is_none());
        assert!(nfs.target_path_bytes().is_none());
    }

    #[test]
    fn test_nfs_block_device() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&8u32.to_le_bytes()); // major
        payload.extend_from_slice(&0u32.to_le_bytes()); // minor
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_BLK, &payload);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(
            nfs,
            NtfsNfsReparsePoint::BlockDevice { major: 8, minor: 0 }
        ));
        assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_BLK);
        assert_eq!(nfs.major(), Some(8));
        assert_eq!(nfs.minor(), Some(0));
    }

    #[test]
    fn test_nfs_fifo() {
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_FIFO, &[]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(nfs, NtfsNfsReparsePoint::Fifo));
        assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_FIFO);
        assert!(nfs.target_path().is_none());
        assert!(nfs.major().is_none());
    }

    #[test]
    fn test_nfs_socket() {
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_SOCK, &[]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert!(matches!(nfs, NtfsNfsReparsePoint::Socket));
        assert_eq!(nfs.nfs_type(), nfs_types::NFS_SPECFILE_SOCK);
    }

    #[test]
    fn test_nfs_wrong_tag() {
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_FIFO, &[]);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let err = rp.as_nfs_reparse_point().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
                if expected == reparse_tags::NFS && actual == reparse_tags::SYMLINK)
        );
    }

    #[test]
    fn test_nfs_truncated_header() {
        // Only 7 bytes — not enough for the 8-byte type field
        let rp = make_reparse_point(reparse_tags::NFS, &[0x00; 7]);
        let err = rp.as_nfs_reparse_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_nfs_unknown_type() {
        let data = make_nfs_data(0xDEAD_BEEF_CAFE_BABE, &[]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let err = rp.as_nfs_reparse_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("unknown NFS")
        ));
    }

    #[test]
    fn test_nfs_chr_truncated_device_data() {
        // Type field says CHR but only 4 bytes of device data (need 8)
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &[0x01, 0x00, 0x00, 0x00]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let err = rp.as_nfs_reparse_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_nfs_blk_truncated_device_data() {
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_BLK, &[0x01, 0x00, 0x00, 0x00]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let err = rp.as_nfs_reparse_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_nfs_device_max_values() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        payload.extend_from_slice(&u32::MAX.to_le_bytes());
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();

        assert_eq!(nfs.major(), Some(u32::MAX));
        assert_eq!(nfs.minor(), Some(u32::MAX));
    }

    #[test]
    fn test_nfs_symbolic_link_odd_byte_target() {
        // 3 bytes is not valid UTF-16LE — raw bytes are stored, decode fails
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_LNK, &[0x41, 0x00, 0x42]);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();
        assert_eq!(nfs.target_path_bytes().unwrap(), &[0x41, 0x00, 0x42]);
        let err = nfs.target_path().unwrap().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("odd number of bytes")
        ));
    }

    #[test]
    fn test_nfs_chr_extra_trailing_data() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&[0xFF; 16]); // extra trailing data
        let data = make_nfs_data(nfs_types::NFS_SPECFILE_CHR, &payload);
        let rp = make_reparse_point(reparse_tags::NFS, &data);
        let nfs = rp.as_nfs_reparse_point().unwrap();
        assert_eq!(nfs.major(), Some(5));
        assert_eq!(nfs.minor(), Some(1));
    }

    #[test]
    fn test_nfs_type_constants() {
        assert_eq!(nfs_types::NFS_SPECFILE_LNK, 0x0000_0000_014B_4E4C);
        assert_eq!(nfs_types::NFS_SPECFILE_CHR, 0x0000_0000_0052_4843);
        assert_eq!(nfs_types::NFS_SPECFILE_BLK, 0x0000_0000_004B_4C42);
        assert_eq!(nfs_types::NFS_SPECFILE_FIFO, 0x0000_0000_4F46_4946);
        assert_eq!(nfs_types::NFS_SPECFILE_SOCK, 0x0000_0000_4B43_4F53);
    }

    // ========================================
    // Roundtrip tests for from_u32 / as_u32
    // ========================================

    #[test]
    fn test_roundtrip_known_tags() {
        let tags = [
            NtfsReparseTag::MountPoint,
            NtfsReparseTag::SymbolicLink,
            NtfsReparseTag::LxSymlink,
            NtfsReparseTag::GlobalReparse,
            NtfsReparseTag::Wof,
            NtfsReparseTag::Dedup,
            NtfsReparseTag::Nfs,
            NtfsReparseTag::AppExecLink,
            NtfsReparseTag::StorageSync,
            NtfsReparseTag::Dfs,
            NtfsReparseTag::Dfsr,
            NtfsReparseTag::Wim,
            NtfsReparseTag::Sis,
            NtfsReparseTag::Cloud,
            NtfsReparseTag::ProjFs,
            NtfsReparseTag::AfUnix,
            NtfsReparseTag::LxFifo,
            NtfsReparseTag::LxChr,
            NtfsReparseTag::LxBlk,
            NtfsReparseTag::Wci,
            NtfsReparseTag::Wci1,
            NtfsReparseTag::WciTombstone,
            NtfsReparseTag::WciLink,
            NtfsReparseTag::WciLink1,
            NtfsReparseTag::Hsm,
            NtfsReparseTag::DriveExtender,
            NtfsReparseTag::Hsm2,
            NtfsReparseTag::Csv,
            NtfsReparseTag::FilterManager,
            NtfsReparseTag::IisCache,
            NtfsReparseTag::Appxstrm,
            NtfsReparseTag::FilePlaceholder,
            NtfsReparseTag::Dfm,
            NtfsReparseTag::Unhandled,
            NtfsReparseTag::OneDrive,
            NtfsReparseTag::ProjFsTombstone,
            NtfsReparseTag::StorageSyncFolder,
        ];

        for tag in tags {
            let raw = tag.as_u32();
            let parsed = NtfsReparseTag::from_u32(raw);
            assert_eq!(tag, parsed, "Roundtrip failed for {:?}", tag);
        }
    }

    // ========================================
    // NtfsReparsePoint struct method tests
    // ========================================

    /// Parses a reparse point through its real `from_bytes` constructor.
    /// `tag` is the 4-byte tag; `data` is the reparse data after the
    /// 8-byte common header. `reparse_data_length` is set to `data.len()`.
    fn parse_reparse_point(tag: u32, data: &[u8]) -> NtfsReparsePoint {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tag.to_le_bytes()); // reparse_tag (offset 0)
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes()); // reparse_data_length (offset 4)
        buf.extend_from_slice(&0u16.to_le_bytes()); // reserved (offset 6)
        buf.extend_from_slice(data);
        NtfsReparsePoint::from_bytes(&buf, NtfsPosition::none()).expect("valid reparse point")
    }

    #[test]
    fn test_reparse_point_is_microsoft_true() {
        // SYMLINK tag 0xA000_000C has the M bit (0x8000_0000) set.
        let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 12]);
        assert!(rp.is_microsoft());
        assert_eq!(rp.tag(), reparse_tags::SYMLINK);
    }

    #[test]
    fn test_reparse_point_is_microsoft_false() {
        // A third-party tag without the M bit. data_length < GUID_SIZE so
        // no GUID is consumed and parsing succeeds with empty data.
        let rp = parse_reparse_point(0x0000_0042, &[]);
        assert!(!rp.is_microsoft());
    }

    #[test]
    fn test_reparse_point_is_name_surrogate_true() {
        // SYMLINK tag 0xA000_000C has the N bit (0x2000_0000) set.
        let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 12]);
        assert!(rp.is_name_surrogate());
    }

    #[test]
    fn test_reparse_point_is_name_surrogate_false() {
        // WOF tag 0x8000_0017 is Microsoft (M bit) but NOT a name surrogate
        // (N bit 0x2000_0000 clear). This distinguishes is_name_surrogate
        // from is_microsoft and pins the exact bit mask.
        let rp = parse_reparse_point(reparse_tags::WOF, &[]);
        assert!(rp.is_microsoft());
        assert!(!rp.is_name_surrogate());
    }

    #[test]
    fn test_reparse_point_guid_present_for_third_party() {
        // Third-party tag (no M bit) with >= 16 bytes of data: the parser
        // consumes a GUID. Use a recognizable GUID byte pattern.
        let guid_bytes: [u8; GUID_SIZE] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&guid_bytes); // GUID
        data.extend_from_slice(&[0xAA, 0xBB]); // trailing reparse data
        let rp = parse_reparse_point(0x0000_0042, &data);
        let guid = rp.guid().expect("third-party reparse point carries a GUID");
        // data1 is the first little-endian u32 of the GUID.
        assert_eq!(guid.data1(), 0x0403_0201);
        // The GUID is stripped from the remaining data.
        assert_eq!(rp.data(), &[0xAA, 0xBB]);
    }

    #[test]
    fn test_reparse_point_guid_absent_for_microsoft() {
        // Microsoft reparse points never carry a GUID even with long data.
        let rp = parse_reparse_point(reparse_tags::SYMLINK, &[0u8; 32]);
        assert!(rp.guid().is_none());
        assert_eq!(rp.data().len(), 32);
    }

    // ========================================
    // NtfsSymbolicLink::from_reparse_point tests
    // ========================================

    /// Builds symbolic link reparse data: 12-byte header + path buffer.
    /// Substitute name is placed at offset 0, print name after it.
    fn symlink_data(substitute: &[u8], print: &[u8], relative: bool) -> Vec<u8> {
        let sub_off = 0u16;
        let sub_len = substitute.len() as u16;
        let print_off = substitute.len() as u16;
        let print_len = print.len() as u16;
        let flags: u32 = if relative {
            symlink_flags::SYMLINK_FLAG_RELATIVE
        } else {
            0
        };

        let mut data = Vec::new();
        data.extend_from_slice(&sub_off.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&sub_len.to_le_bytes()); // substitute_name_length
        data.extend_from_slice(&print_off.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&print_len.to_le_bytes()); // print_name_length
        data.extend_from_slice(&flags.to_le_bytes()); // flags
        data.extend_from_slice(substitute);
        data.extend_from_slice(print);
        data
    }

    #[test]
    fn test_symbolic_link_absolute() {
        let substitute: Vec<u8> = r"\??\C:\target"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let print: Vec<u8> = r"C:\target"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = symlink_data(&substitute, &print, false);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let sym = rp.as_symbolic_link().unwrap();

        assert_eq!(sym.substitute_name_bytes(), &substitute[..]);
        assert_eq!(sym.print_name_bytes(), &print[..]);
        assert_eq!(sym.substitute_name().unwrap(), r"\??\C:\target");
        assert_eq!(sym.print_name().unwrap(), r"C:\target");
        assert!(!sym.is_relative());
    }

    #[test]
    fn test_symbolic_link_relative() {
        let substitute: Vec<u8> = "..\\sibling"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let print: Vec<u8> = "sibling"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = symlink_data(&substitute, &print, true);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let sym = rp.as_symbolic_link().unwrap();

        assert!(sym.is_relative());
        assert_eq!(sym.substitute_name().unwrap(), "..\\sibling");
        assert_eq!(sym.print_name().unwrap(), "sibling");
    }

    #[test]
    fn test_symbolic_link_nonzero_offsets() {
        // Place the substitute name after the print name in the buffer so
        // a nonzero substitute_name_offset is exercised. This pins the
        // `substitute_name_offset + substitute_name_length` arithmetic.
        let print: Vec<u8> = "P".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let substitute: Vec<u8> = "TARGET"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        let mut data = Vec::new();
        // substitute placed after print: offset = print.len()
        data.extend_from_slice(&(print.len() as u16).to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&(substitute.len() as u16).to_le_bytes()); // substitute_name_length
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&(print.len() as u16).to_le_bytes()); // print_name_length
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&print);
        data.extend_from_slice(&substitute);

        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let sym = rp.as_symbolic_link().unwrap();
        assert_eq!(sym.substitute_name().unwrap(), "TARGET");
        assert_eq!(sym.print_name().unwrap(), "P");
    }

    #[test]
    fn test_symbolic_link_wrong_tag() {
        let data = symlink_data(&[0, 0], &[0, 0], false);
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let err = rp.as_symbolic_link().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
                if expected == reparse_tags::SYMLINK && actual == reparse_tags::MOUNT_POINT)
        );
    }

    #[test]
    fn test_symbolic_link_truncated_header() {
        // 11 bytes < 12-byte symlink header.
        let rp = make_reparse_point(reparse_tags::SYMLINK, &[0u8; 11]);
        let err = rp.as_symbolic_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_symbolic_link_substitute_beyond_buffer() {
        // substitute_name_length claims more bytes than the path buffer has.
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&100u16.to_le_bytes()); // substitute_name_length (too big)
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&[0u8; 4]); // only 4 bytes of path buffer
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let err = rp.as_symbolic_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("substitute name extends")
        ));
    }

    #[test]
    fn test_symbolic_link_print_beyond_buffer() {
        // print_name_offset + length exceeds the path buffer, but substitute
        // fits. This isolates the print-name bounds check from the substitute
        // check (distinguishing `print_name_end > path_buffer.len()`).
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&2u16.to_le_bytes()); // substitute_name_length (fits)
        data.extend_from_slice(&2u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&100u16.to_le_bytes()); // print_name_length (too big)
        data.extend_from_slice(&0u32.to_le_bytes()); // flags
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 bytes of path buffer
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let err = rp.as_symbolic_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("print name extends")
        ));
    }

    #[test]
    fn test_symbolic_link_header_only_accepted() {
        // data.len() == SYMLINK_REPARSE_DATA_HEADER_SIZE (12): the `<` check is
        // false, so an empty-path symlink (both names zero-length at offset 0)
        // is accepted. A `< -> <=` mutant would reject len == 12.
        let data = symlink_data(&[], &[], false);
        assert_eq!(data.len(), SYMLINK_REPARSE_DATA_HEADER_SIZE);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let sym = rp.as_symbolic_link().unwrap();
        assert_eq!(sym.substitute_name().unwrap(), "");
        assert_eq!(sym.print_name().unwrap(), "");
        assert!(sym.substitute_name_bytes().is_empty());
    }

    #[test]
    fn test_symbolic_link_exact_fit_boundary() {
        // print name occupies exactly the rest of the buffer: print_name_end
        // == path_buffer.len() must be accepted (boundary for `>` vs `>=`).
        let sub: Vec<u8> = "A".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let print: Vec<u8> = "BB".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let data = symlink_data(&sub, &print, false);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let sym = rp.as_symbolic_link().unwrap();
        assert_eq!(sym.substitute_name().unwrap(), "A");
        assert_eq!(sym.print_name().unwrap(), "BB");
    }

    // ========================================
    // NtfsMountPoint::from_reparse_point tests
    // ========================================

    /// Builds mount point reparse data: 8-byte header + path buffer.
    fn mount_point_data(substitute: &[u8], print: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&(substitute.len() as u16).to_le_bytes()); // substitute_name_length
        data.extend_from_slice(&(substitute.len() as u16).to_le_bytes()); // print_name_offset
        data.extend_from_slice(&(print.len() as u16).to_le_bytes()); // print_name_length
        data.extend_from_slice(substitute);
        data.extend_from_slice(print);
        data
    }

    #[test]
    fn test_mount_point_basic() {
        let substitute: Vec<u8> = r"\??\Volume{1}"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let print: Vec<u8> = r"D:\mount"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let data = mount_point_data(&substitute, &print);
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let mp = rp.as_mount_point().unwrap();

        assert_eq!(mp.substitute_name_bytes(), &substitute[..]);
        assert_eq!(mp.print_name_bytes(), &print[..]);
        assert_eq!(mp.substitute_name().unwrap(), r"\??\Volume{1}");
        assert_eq!(mp.print_name().unwrap(), r"D:\mount");
    }

    #[test]
    fn test_mount_point_nonzero_print_offset() {
        // print name placed after substitute; pins print_name_offset +
        // print_name_length arithmetic and substitute_name_end arithmetic.
        let substitute: Vec<u8> = "AB".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let print: Vec<u8> = "CDE".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let data = mount_point_data(&substitute, &print);
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let mp = rp.as_mount_point().unwrap();
        assert_eq!(mp.substitute_name().unwrap(), "AB");
        assert_eq!(mp.print_name().unwrap(), "CDE");
    }

    #[test]
    fn test_mount_point_header_only_accepted() {
        // data.len() == MOUNT_POINT_REPARSE_DATA_HEADER_SIZE (8): the `<` check
        // is false, so an empty-path mount point is accepted. A `< -> <=`
        // mutant would reject len == 8.
        let data = mount_point_data(&[], &[]);
        assert_eq!(data.len(), MOUNT_POINT_REPARSE_DATA_HEADER_SIZE);
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let mp = rp.as_mount_point().unwrap();
        assert_eq!(mp.substitute_name().unwrap(), "");
        assert_eq!(mp.print_name().unwrap(), "");
        assert!(mp.substitute_name_bytes().is_empty());
    }

    #[test]
    fn test_mount_point_substitute_exact_fit() {
        // substitute_name_end == path_buffer.len() exactly (substitute fills
        // the whole buffer, print is empty at offset 0). The original `>` is
        // false (accept); a `> -> >=` mutant at line 798 would reject the
        // exact-fit case. The successful parse kills `> -> >=`.
        let substitute: Vec<u8> = "FULL"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&(substitute.len() as u16).to_le_bytes()); // substitute_name_length
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length (empty)
        data.extend_from_slice(&substitute); // path buffer == substitute exactly
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let mp = rp.as_mount_point().unwrap();
        assert_eq!(mp.substitute_name().unwrap(), "FULL");
        assert_eq!(mp.print_name().unwrap(), "");
    }

    #[test]
    fn test_mount_point_wrong_tag() {
        let data = mount_point_data(&[0, 0], &[0, 0]);
        let rp = make_reparse_point(reparse_tags::SYMLINK, &data);
        let err = rp.as_mount_point().unwrap_err();
        assert!(
            matches!(err, NtfsError::ReparseTagMismatch { expected, actual, .. }
                if expected == reparse_tags::MOUNT_POINT && actual == reparse_tags::SYMLINK)
        );
    }

    #[test]
    fn test_mount_point_truncated_header() {
        // 7 bytes < 8-byte mount point header.
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &[0u8; 7]);
        let err = rp.as_mount_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("too small")
        ));
    }

    #[test]
    fn test_mount_point_substitute_beyond_buffer() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&100u16.to_le_bytes()); // substitute_name_length (too big)
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&0u16.to_le_bytes()); // print_name_length
        data.extend_from_slice(&[0u8; 4]); // only 4 bytes of path buffer
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let err = rp.as_mount_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("substitute name extends")
        ));
    }

    #[test]
    fn test_mount_point_print_beyond_buffer() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u16.to_le_bytes()); // substitute_name_offset
        data.extend_from_slice(&2u16.to_le_bytes()); // substitute_name_length (fits)
        data.extend_from_slice(&2u16.to_le_bytes()); // print_name_offset
        data.extend_from_slice(&100u16.to_le_bytes()); // print_name_length (too big)
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4 bytes of path buffer
        let rp = make_reparse_point(reparse_tags::MOUNT_POINT, &data);
        let err = rp.as_mount_point().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("print name extends")
        ));
    }

    // ========================================
    // NtfsAppExecLink raw-bytes accessors
    // ========================================

    #[test]
    fn test_app_exec_link_raw_bytes_accessors() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u32.to_le_bytes());
        data.extend_from_slice(&utf16le_null("Pkg"));
        data.extend_from_slice(&utf16le_null("Entry"));
        data.extend_from_slice(&utf16le_null("Exec"));
        data.extend_from_slice(&utf16le_null("AppType"));

        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let ael = rp.as_app_exec_link().unwrap();

        // Raw UTF-16LE bytes (no trailing null) for each string.
        let pkg: Vec<u8> = "Pkg".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let entry: Vec<u8> = "Entry"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let exec: Vec<u8> = "Exec"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let app_type: Vec<u8> = "AppType"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        assert_eq!(ael.package_id_bytes(), &pkg[..]);
        assert_eq!(ael.entry_point_bytes(), &entry[..]);
        assert_eq!(ael.executable_bytes(), &exec[..]);
        assert_eq!(ael.application_type_bytes(), &app_type[..]);
    }

    #[test]
    fn test_app_exec_link_minimum_header_size() {
        // Exactly 4 bytes (just the version, no strings) must be accepted by
        // the `data.len() < APP_EXEC_LINK_REPARSE_DATA_HEADER_SIZE` check, but
        // then rejected for having fewer than 3 strings. This pins the `<`
        // boundary (4 bytes is not "too small").
        let data = 3u32.to_le_bytes();
        let rp = make_reparse_point(reparse_tags::APPEXECLINK, &data);
        let err = rp.as_app_exec_link().unwrap_err();
        assert!(matches!(
            err,
            NtfsError::InvalidReparsePointData { reason, .. }
                if reason.contains("fewer than 3")
        ));
    }

    // ========================================
    // split_utf16le_null_terminated termination
    // ========================================

    #[test]
    fn test_split_utf16le_long_buffer_terminates() {
        // A multi-string buffer with explicit null terminators: asserts the
        // 2-byte-step loop walks the whole buffer and terminates promptly,
        // pinning the `i + 1 < data.len()` / `i += 2` index arithmetic.
        let mut data = Vec::new();
        for _ in 0..64 {
            data.extend_from_slice(&[0x41, 0x00, 0x00, 0x00]); // "A" + null
        }
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 64);
        for part in &parts {
            assert_eq!(*part, &[0x41, 0x00]);
        }
    }

    #[test]
    fn test_split_utf16le_two_strings_offsets() {
        // "AB\0C\0": first string is 2 code units, splitting at byte index 4.
        // Pins start = i + 2 and the index walk position exactly.
        let data = [
            0x41, 0x00, 0x42, 0x00, 0x00, 0x00, // "AB" + null
            0x43, 0x00, 0x00, 0x00, // "C" + null
        ];
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], &[0x41, 0x00, 0x42, 0x00]);
        assert_eq!(parts[1], &[0x43, 0x00]);
    }

    #[test]
    fn test_split_utf16le_high_byte_not_a_terminator() {
        // A single code unit U+0100 = bytes [0x00, 0x01]: the low byte is 0 but
        // the high byte is not, so it is NOT a U+0000 terminator. The genuine
        // check requires BOTH data[i] == 0 AND data[i + 1] == 0. A `data[i + 1]
        // -> data[i * 1]` (= data[i]) mutation would test data[i] twice, see
        // `0 == 0 && 0 == 0`, and wrongly split here. Asserting a single
        // non-empty string kills the `i + 1 -> i * 1` index mutation (1278).
        let data = [0x00, 0x01, 0x42, 0x00]; // U+0100 then 'B'
        let parts = split_utf16le_null_terminated(&data).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], &[0x00, 0x01, 0x42, 0x00]);
    }
}
