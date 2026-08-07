//! Read-only Btrfs format support.
//!
//! The parser validates superblocks, metadata blocks, and data checksums;
//! traverses filesystem trees and subvolumes; maps common single- and
//! multi-device chunk profiles; and reads sparse, inline, and compressed
//! files. It remains `no_std`-capable: enable `std` when zlib, LZO, or Zstandard
//! decompression is required.
//!
//! Multi-device opens currently require every declared member. RAID5/6 data
//! stripes are read directly from healthy members; degraded parity
//! reconstruction is outside this read-only parser's current scope.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

mod bytes;
mod checksum;
mod chunk;
mod error;
mod file;
mod item;
mod key;
mod superblock;
mod tree;
mod volume;

pub use checksum::ChecksumType;
pub use error::{BtrfsError, Result};
pub use fsmnt_parser_core::io;
pub use item::{BtrfsFileType, BtrfsInode, BtrfsTimestamp};
pub use key::DiskKey;
pub use superblock::{
    BtrfsSuperblock, PRIMARY_SUPERBLOCK_OFFSET, SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE,
};
pub use volume::{Btrfs, BtrfsDirEntry, BtrfsEntry};

#[cfg(test)]
mod tests;
