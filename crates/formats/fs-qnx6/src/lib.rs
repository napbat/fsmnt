//! Read-only parser for QNX6 Power-Safe filesystems.
//!
//! QNX6 stores two copy-on-write filesystem snapshots. Each snapshot has a
//! checksummed superblock and a serial number; the valid copy with the newer
//! serial owns the inode, allocation-bitmap, and long-filename trees exposed
//! by this crate. File data and all three metadata files use the same uniform
//! 16-pointer tree layout.
//!
//! The crate is `no_std` by default. Enable `std` when opening ordinary
//! `std::io::Read + std::io::Seek` sources.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
mod fs;
mod inode;
mod superblock;
#[cfg(test)]
mod tests;
mod tree;

pub use error::{Qnx6Error, Result};
pub use fs::{Qnx6, Qnx6DirectoryEntry};
pub use inode::{Qnx6FileType, Qnx6Inode};
pub use superblock::{
    ByteOrder, QNX6_BOOT_AREA_SIZE, QNX6_DATA_AREA_OFFSET, QNX6_ROOT_INODE,
    QNX6_SUPERBLOCK_AREA_SIZE, QNX6_SUPERBLOCK_SIZE, Qnx6RootNode, Qnx6Superblock, SuperblockCopy,
    qnx6_crc32,
};

pub use fsmnt_parser_core::io;
