//! Read-only Btrfs format support.
//!
//! The parser validates superblocks, metadata blocks, and data checksums;
//! traverses filesystem trees and subvolumes; maps common single- and
//! multi-device chunk profiles; and reads sparse, inline, and compressed
//! files. It remains `no_std`-capable: enable `std` when zlib, LZO, or Zstandard
//! decompression is required.
//!
//! Multi-device opens accept missing members when the active chunk profiles
//! remain readable. RAID5/6 reads reconstruct unavailable or silently corrupt
//! data through P/Q parity. Pending tree logs and extent-tree-v2 global
//! checksum roots are applied during read-only initialization. When the live
//! root or chunk tree is damaged, typed superblock root backups provide
//! newest-first read-only recovery.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod bytes;
mod checksum;
mod chunk;
mod error;
mod file;
#[cfg(feature = "fuzzing")]
/// Internal parser entry points used by the workspace fuzz targets.
#[doc(hidden)]
pub mod fuzzing;
mod item;
mod key;
mod raid56;
mod superblock;
mod tree;
mod volume;

pub use checksum::ChecksumType;
pub use error::{BtrfsError, Result};
pub use fsmnt_parser_core::io;
pub use item::{BtrfsFileType, BtrfsInode, BtrfsTimestamp};
pub use key::DiskKey;
pub use superblock::{
    BtrfsBackupTreeRoot, BtrfsDeviceSource, BtrfsRootBackup, BtrfsSuperblock, BtrfsZone,
    BtrfsZoneCondition, BtrfsZoneType, BtrfsZonedDevice, MAX_ZONE_SIZE, MIN_ZONE_SIZE,
    PRIMARY_SUPERBLOCK_OFFSET, SUPERBLOCK_MAGIC, SUPERBLOCK_MIRROR_OFFSETS, SUPERBLOCK_SIZE,
    ZONED_SUPERBLOCK_LOG_OFFSETS, probe_zoned_superblock,
};
pub use volume::{Btrfs, BtrfsDeviceIdentity, BtrfsDirEntry, BtrfsEntry, BtrfsRecovery};

#[cfg(test)]
mod tests;
