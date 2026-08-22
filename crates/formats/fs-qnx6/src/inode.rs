//! QNX6 inode records.

use crate::Result;
use crate::superblock::ByteOrder;
use crate::tree::TreeDescriptor;

/// Size of one on-disk QNX6 inode record.
pub(crate) const QNX6_INODE_SIZE: usize = 0x80;

/// POSIX object kind encoded in an inode's mode field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Qnx6FileType {
    /// Regular file.
    Regular,
    /// Directory file containing 32-byte name records.
    Directory,
    /// Symbolic link whose target is stored as file data.
    SymbolicLink,
    /// Named pipe.
    Fifo,
    /// Character-special object.
    CharacterDevice,
    /// Block-special object.
    BlockDevice,
    /// Unix-domain socket.
    Socket,
    /// Unrecognized or unset mode bits.
    Unknown,
}

impl Qnx6FileType {
    /// Whether this type is a directory.
    #[must_use]
    pub const fn is_directory(self) -> bool {
        matches!(self, Self::Directory)
    }

    /// Whether this type is a regular file.
    #[must_use]
    pub const fn is_regular(self) -> bool {
        matches!(self, Self::Regular)
    }

    /// Whether this type is a symbolic link.
    #[must_use]
    pub const fn is_symbolic_link(self) -> bool {
        matches!(self, Self::SymbolicLink)
    }
}

/// One parsed 128-byte QNX6 inode-table record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qnx6Inode {
    number: u32,
    tree: TreeDescriptor,
    uid: u32,
    gid: u32,
    created_time: u32,
    modified_time: u32,
    accessed_time: u32,
    changed_time: u32,
    mode: u16,
    extended_mode: u16,
    status: u8,
}

impl Qnx6Inode {
    pub(crate) fn from_bytes(number: u32, bytes: &[u8], order: ByteOrder) -> Result<Self> {
        Ok(Self {
            number,
            tree: TreeDescriptor::parse(bytes, 0, 36, 100, order, "file")?,
            uid: order.read_u32(bytes, 8),
            gid: order.read_u32(bytes, 12),
            created_time: order.read_u32(bytes, 16),
            modified_time: order.read_u32(bytes, 20),
            accessed_time: order.read_u32(bytes, 24),
            changed_time: order.read_u32(bytes, 28),
            mode: order.read_u16(bytes, 32),
            extended_mode: order.read_u16(bytes, 34),
            status: bytes[101],
        })
    }

    /// One-based inode number.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Logical byte length of the object data.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.tree.size()
    }

    /// POSIX owner ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// POSIX group ID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// File creation time as unsigned Unix seconds.
    #[must_use]
    pub const fn created_time(&self) -> u32 {
        self.created_time
    }

    /// File modification time as unsigned Unix seconds.
    #[must_use]
    pub const fn modified_time(&self) -> u32 {
        self.modified_time
    }

    /// File access time as unsigned Unix seconds.
    #[must_use]
    pub const fn accessed_time(&self) -> u32 {
        self.accessed_time
    }

    /// Inode-change time as unsigned Unix seconds.
    #[must_use]
    pub const fn changed_time(&self) -> u32 {
        self.changed_time
    }

    /// Complete POSIX mode, including object kind and permission bits.
    #[must_use]
    pub const fn mode(&self) -> u16 {
        self.mode
    }

    /// QNX-specific extended mode bits.
    #[must_use]
    pub const fn extended_mode(&self) -> u16 {
        self.extended_mode
    }

    /// Object kind decoded from the POSIX mode.
    #[must_use]
    pub const fn file_type(&self) -> Qnx6FileType {
        match self.mode & 0o170_000 {
            0o100_000 => Qnx6FileType::Regular,
            0o040_000 => Qnx6FileType::Directory,
            0o120_000 => Qnx6FileType::SymbolicLink,
            0o010_000 => Qnx6FileType::Fifo,
            0o020_000 => Qnx6FileType::CharacterDevice,
            0o060_000 => Qnx6FileType::BlockDevice,
            0o140_000 => Qnx6FileType::Socket,
            _ => Qnx6FileType::Unknown,
        }
    }

    /// Permission and special-mode bits without the object-kind mask.
    #[must_use]
    pub const fn permissions(&self) -> u16 {
        self.mode & 0o007_777
    }

    /// Format-defined inode status byte.
    #[must_use]
    pub const fn status(&self) -> u8 {
        self.status
    }

    /// Number of indirect pointer levels used by this object.
    #[must_use]
    pub const fn levels(&self) -> u8 {
        self.tree.levels()
    }

    pub(crate) const fn tree(&self) -> &TreeDescriptor {
        &self.tree
    }
}
