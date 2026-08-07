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
//! - [`PartitionReader`] — a reader windowed to one partition's extent.
//! - [`DetectedBootSector`] — filesystem/partition-table classification
//!   from raw boot-sector bytes. The portable parsing types and functions
//!   are re-exported from `fsmnt-parser-core` so this crate does not carry a
//!   second implementation.
//! - [`FilesystemDriver`] / [`DriverRegistry`] — the plug-in point through
//!   which filesystem parsers (NTFS, FAT, ext, APFS, …) turn a partition
//!   reader into a mountable
//!   [`TargetFilesystem`](fsmnt_core::TargetFilesystem).  `fsmnt` ships no
//!   parsers of its own.

mod disk;
mod drive;
mod driver;
mod partition_reader;

pub use disk::{Disk, DiskLayout};
pub use drive::{
    HostDriveBusType, HostDriveEnumerator, HostDriveError, HostDriveId, HostDriveInfo,
    HostDriveResult,
};
pub use driver::{DeviceReader, DriverRegistry, FilesystemDriver};
pub use fsmnt_parser_core::boot_sector::{
    BOOT_SECTOR_SIZE, BootSectorDiagnosis, BootSectorHeader, BootSectorUnknownReason,
    DetectedBootSector, DosBpb, ExFatBootSector, FS_DETECT_PROBE_SIZE, Fat16Ebpb, Fat32Ebpb,
    FilesystemType, NtfsEbpb, ParseError, ParsedBootSector, diagnose_boot_sector,
    parse_boot_sector,
};
pub use fsmnt_parser_core::partition::{
    GptHeader, GptPartitionEntry, Mbr, MbrPartitionEntry, read_gpt_header,
};
pub use partition_reader::PartitionReader;
