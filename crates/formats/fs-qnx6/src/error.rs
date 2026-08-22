//! QNX6 parser errors.

use thiserror::Error;

use crate::io;
#[cfg(feature = "std")]
use fsmnt_parser_core::error::IoError;
use fsmnt_parser_core::error::{self as parser_error, ParserError};

/// Result type returned by the QNX6 parser.
pub type Result<T, E = Qnx6Error> = core::result::Result<T, E>;

/// A malformed QNX6 structure, unsupported geometry, or reader failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Qnx6Error {
    /// Neither superblock copy was readable and structurally valid.
    #[error("neither QNX6 superblock copy is valid")]
    NoValidSuperblock,

    /// A superblock did not carry the QNX6 magic in either byte order.
    #[error("invalid QNX6 superblock magic")]
    InvalidMagic,

    /// A superblock's stored CRC does not cover its bytes 8 through 511.
    #[error("QNX6 superblock checksum mismatch: stored {stored:#010x}, calculated {actual:#010x}")]
    ChecksumMismatch {
        /// Checksum recorded by the superblock.
        stored: u32,
        /// Checksum calculated from the covered bytes.
        actual: u32,
    },

    /// The filesystem block size is not one of QNX6's supported sizes.
    #[error("invalid QNX6 block size {0}; expected 512, 1024, 2048, or 4096")]
    InvalidBlockSize(u32),

    /// A free-space or inode count exceeds its corresponding total.
    #[error("invalid QNX6 superblock counts: {0}")]
    InvalidCounts(&'static str),

    /// A metadata or file tree uses more indirection than the format allows.
    #[error("QNX6 {tree} tree has {levels} levels; maximum is 5")]
    InvalidTreeDepth {
        /// Tree whose root carried the invalid value.
        tree: &'static str,
        /// Indirection level recorded on disk.
        levels: u8,
    },

    /// Both checksummed copies stand up but disagree on immutable geometry.
    #[error("QNX6 superblock copies disagree on immutable volume geometry")]
    ConflictingSuperblocks,

    /// Checked arithmetic rejected a corrupt on-disk value.
    #[error("QNX6 offset or length overflow while calculating {0}")]
    Overflow(&'static str),

    /// An inode number is zero or exceeds the superblock's inode count.
    #[error("QNX6 inode {inode} is outside the valid range 1..={maximum}")]
    InvalidInodeNumber {
        /// Requested inode number.
        inode: u32,
        /// Maximum inode number declared by the filesystem.
        maximum: u32,
    },

    /// A block pointer names a block beyond the filesystem's data area.
    #[error("QNX6 block pointer {block} is outside the {maximum}-block filesystem")]
    InvalidBlockPointer {
        /// Invalid filesystem block number.
        block: u32,
        /// Total number of filesystem blocks.
        maximum: u32,
    },

    /// A logical block cannot be represented by a tree's pointer depth.
    #[error("QNX6 logical block {block} exceeds a {levels}-level tree's capacity")]
    TreeCapacityExceeded {
        /// Logical block index requested from the file.
        block: u64,
        /// Indirection level recorded by the tree root.
        levels: u8,
    },

    /// A metadata file is shorter than the superblock count requires.
    #[error("QNX6 {tree} metadata file is too short for byte range {offset}..{end}")]
    MetadataTooShort {
        /// Metadata tree being read.
        tree: &'static str,
        /// First requested byte.
        offset: u64,
        /// Exclusive requested end.
        end: u64,
    },

    /// The root inode is not a directory.
    #[error("QNX6 root inode is not a directory")]
    RootNotDirectory,

    /// A requested directory operation targeted a non-directory inode.
    #[error("QNX6 inode {0} is not a directory")]
    NotADirectory(u32),

    /// A requested file operation targeted a directory.
    #[error("QNX6 inode {0} is a directory")]
    NotAFile(u32),

    /// A directory contains a partial or malformed fixed-size record.
    #[error("invalid QNX6 directory record at byte {offset}: {reason}")]
    InvalidDirectoryEntry {
        /// Byte offset within the directory file.
        offset: u64,
        /// Structural rule that the entry violated.
        reason: &'static str,
    },

    /// A long-filename block declares more bytes than the format permits.
    #[error("invalid QNX6 long filename length {length} at block index {index}")]
    InvalidLongName {
        /// Index in the long-filename metadata file.
        index: u32,
        /// Name length recorded in the block.
        length: u16,
    },

    /// A path component was not present in its parent directory.
    #[error("QNX6 entry not found")]
    NotFound,

    /// A file or directory is too large to represent in this process.
    #[error("QNX6 object length {0} cannot be allocated in this process")]
    ObjectTooLarge(u64),

    /// Reserving memory for parser output failed.
    #[error("could not allocate memory for QNX6 parser output")]
    AllocationFailed,

    /// The underlying source could not be read or sought.
    #[error("QNX6 I/O error: {0:?}")]
    Io(io::Error),
}

impl From<io::Error> for Qnx6Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(feature = "std")]
impl From<IoError> for Qnx6Error {
    fn from(error: IoError) -> Self {
        Self::Io(error.into())
    }
}

impl ParserError for Qnx6Error {
    fn io_kind(&self) -> Option<parser_error::ErrorKind> {
        let Self::Io(error) = self else {
            return None;
        };
        #[cfg(feature = "std")]
        {
            Some(parser_error::ErrorKind::from(error.kind()))
        }
        #[cfg(not(feature = "std"))]
        {
            Some(error.kind())
        }
    }

    fn byte_offset(&self) -> Option<u64> {
        match self {
            Self::InvalidDirectoryEntry { offset, .. } => Some(*offset),
            _ => None,
        }
    }
}
