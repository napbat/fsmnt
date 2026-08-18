//! Cross-platform block-device abstraction for `fsmnt`.
//!
//! This crate provides everything needed to go from "a raw block device or
//! disk image" to "a partition-scoped reader plus a detected filesystem
//! type", without containing any platform-specific filesystem driver:
//!
//! - [`HostDriveEnumerator`] — the trait platform crates
//!   (`fsmnt-device-windows`, `fsmnt-device-linux`, `fsmnt-device-macos`)
//!   implement to enumerate and open physical drives.
//! - [`Disk`] / [`DiskLayout`] — partition-table detection (GPT/MBR) and
//!   on-demand partition entry access over any `Read + Seek` source.
//! - [`ImageContainer`] / [`ImageReader`] — a common decoded-media contract
//!   plus automatic raw/EWF/VHD/VHDX image opening.
//! - [`PartitionReader`] — a reader windowed to one partition's extent.
//! - [`HostVolumeResolver`] / [`LogicalVolume`] — the graph edge from a
//!   physical partition extent to one or more operating-system logical block
//!   views, including stacked and multi-disk storage.
//! - [`DeviceSet`] / [`assemble_raw_volume`] — native multi-device
//!   filesystem input and reusable linear, striped, or mirrored raw mappings.
//! - [`DetectedBootSector`] — filesystem/partition-table classification
//!   from raw boot-sector bytes. The portable parsing types and functions
//!   are re-exported from `fsmnt-parser-core` so this crate does not carry a
//!   second implementation.
//! - [`FilesystemDriver`] / [`DriverRegistry`] — the plug-in point through
//!   which filesystem parsers (NTFS, FAT, ext, APFS, …) turn a partition
//!   reader into a mountable
//!   [`TargetFilesystem`](fsmnt_core::TargetFilesystem).  `fsmnt` ships no
//!   parsers of its own.
//!
//! Device-facing I/O traits come from `nostdio` with its `std` feature at
//! this boundary. Filesystem-format crates remain independently
//! `no_std`-capable.

mod detection;
mod disk;
mod drive;
mod driver;
mod image;
mod partition_reader;
mod sector_reader;
mod source;
mod tolerant_reader;

pub use detection::{
    detect_backup_boot_sector_at, detect_boot_sector_at, detect_boot_sector_within,
    ext_backup_superblock_at, ext_backup_superblock_info_at,
};
pub use disk::{Disk, DiskLayout};
pub use drive::{
    HostDriveBusType, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo,
    HostDriveResult,
};
pub use driver::{
    DeviceReader, DriverRegistry, FilesystemDriver, FilesystemMemberDiscovery, FilesystemMemberId,
    FilesystemOpenOptions, FilesystemRoot, FilesystemRootParseError, ResolvedFilesystem,
    ResolvedMemberDiscovery, reject_unsupported_recovery,
};
pub use fsmnt_parser_core::boot_sector::{
    BOOT_SECTOR_SIZE, BTRFS_PRIMARY_SUPERBLOCK_OFFSET, BTRFS_SUPERBLOCK_MAGIC,
    BTRFS_SUPERBLOCK_PROBE_SIZE, BootSectorDiagnosis, BootSectorHeader, BootSectorUnknownReason,
    DetectedBootSector, DosBpb, ExFatBootSector, ExtBackupSuperblock, ExtSuperblockInfo,
    FS_DETECT_PROBE_SIZE, Fat16Ebpb, Fat32Ebpb, FilesystemType, NtfsEbpb, ParseError,
    ParsedBootSector, diagnose_boot_sector, ext_backup_superblock_group,
    ext_backup_superblock_info, ext_superblock_info, is_btrfs_primary_superblock,
    parse_boot_sector,
};
pub use fsmnt_parser_core::partition::{
    GptHeader, GptPartitionEntry, Mbr, MbrPartitionEntry, read_gpt_header,
};
pub use image::{ImageContainer, ImageFormat, ImageOpenError, ImageReader};
pub use partition_reader::PartitionReader;
pub use sector_reader::SectorReader;
pub use source::{
    AssembledVolume, BlockZone, BlockZoneCondition, BlockZoneReporter, BlockZoneType, DeviceMember,
    DeviceSet, DeviceSetError, HostVolumeResolver, LogicalVolume, LogicalVolumeId,
    PartitionAddress, PhysicalExtent, RawAssemblyError, RawVolumeLayout, SourceMemberId,
    SourceOrigin, SourceSelection, VolumeSelectionError, assemble_raw_volume,
    select_logical_volume,
};
pub use tolerant_reader::{ReadSubstitutions, TolerantReader};
