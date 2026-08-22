//! QNX6 superblock parsing and snapshot selection fields.

use crate::tree::TreeDescriptor;
use crate::{Qnx6Error, Result};

use fsmnt_parser_core::boot_sector::qnx6::SUPERBLOCK_MAGIC as QNX6_MAGIC;
pub use fsmnt_parser_core::boot_sector::qnx6::{
    BOOT_AREA_SIZE as QNX6_BOOT_AREA_SIZE, DATA_AREA_OFFSET as QNX6_DATA_AREA_OFFSET,
    SUPERBLOCK_AREA_SIZE as QNX6_SUPERBLOCK_AREA_SIZE, SUPERBLOCK_SIZE as QNX6_SUPERBLOCK_SIZE,
};

/// Number of the filesystem root inode.
pub const QNX6_ROOT_INODE: u32 = 1;

/// Maximum supported tree-indirection level.
pub(crate) const QNX6_MAX_LEVELS: u8 = 5;

/// Marker used for an unused QNX6 block pointer.
pub(crate) const QNX6_UNUSED_BLOCK: u32 = u32::MAX;

/// Byte order selected when the filesystem was formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteOrder {
    /// Least-significant byte first.
    Little,
    /// Most-significant byte first.
    Big,
}

impl ByteOrder {
    pub(crate) fn read_u16(self, bytes: &[u8], offset: usize) -> u16 {
        let raw = [bytes[offset], bytes[offset + 1]];
        match self {
            Self::Little => u16::from_le_bytes(raw),
            Self::Big => u16::from_be_bytes(raw),
        }
    }

    pub(crate) fn read_u32(self, bytes: &[u8], offset: usize) -> u32 {
        let raw = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ];
        match self {
            Self::Little => u32::from_le_bytes(raw),
            Self::Big => u32::from_be_bytes(raw),
        }
    }

    pub(crate) fn read_u64(self, bytes: &[u8], offset: usize) -> u64 {
        let raw = [
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ];
        match self {
            Self::Little => u64::from_le_bytes(raw),
            Self::Big => u64::from_be_bytes(raw),
        }
    }
}

/// Which of the paired superblock areas owns the selected snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuperblockCopy {
    /// Superblock after the 8 KiB boot area.
    Primary,
    /// Superblock in the trailing 4 KiB area.
    Secondary,
}

/// Root descriptor for a QNX6 metadata tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qnx6RootNode {
    tree: TreeDescriptor,
    mode: u8,
}

impl Qnx6RootNode {
    fn parse(bytes: &[u8], offset: usize, order: ByteOrder, tree: &'static str) -> Result<Self> {
        Ok(Self {
            tree: TreeDescriptor::parse(bytes, offset, offset + 8, offset + 72, order, tree)?,
            mode: bytes[offset + 73],
        })
    }

    /// Logical byte length of the metadata file below this root.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.tree.size()
    }

    /// Number of indirect pointer levels between this root and data blocks.
    #[must_use]
    pub const fn levels(&self) -> u8 {
        self.tree.levels()
    }

    /// Format-defined root mode byte.
    #[must_use]
    pub const fn mode(&self) -> u8 {
        self.mode
    }

    pub(crate) const fn tree(&self) -> &TreeDescriptor {
        &self.tree
    }
}

/// One validated QNX6 superblock snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Qnx6Superblock {
    byte_order: ByteOrder,
    checksum: u32,
    serial: u64,
    created_time: u32,
    accessed_time: u32,
    flags: u32,
    version_major: u16,
    version_minor: u16,
    volume_id: [u8; 16],
    block_size: u32,
    num_inodes: u32,
    free_inodes: u32,
    num_blocks: u32,
    free_blocks: u32,
    allocation_group: u32,
    inode_root: Qnx6RootNode,
    bitmap_root: Qnx6RootNode,
    long_name_root: Qnx6RootNode,
    unknown_root: Qnx6RootNode,
}

impl Qnx6Superblock {
    /// Parse and checksum a 512-byte standard QNX6 superblock.
    ///
    /// # Errors
    ///
    /// Returns an error for a short record, wrong magic, checksum mismatch,
    /// unsupported block size, impossible counts, or excessive tree depth.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < QNX6_SUPERBLOCK_SIZE {
            return Err(Qnx6Error::NoValidSuperblock);
        }
        let byte_order =
            if u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4])) == QNX6_MAGIC {
                ByteOrder::Little
            } else if u32::from_be_bytes(bytes[..4].try_into().unwrap_or([0; 4])) == QNX6_MAGIC {
                ByteOrder::Big
            } else {
                return Err(Qnx6Error::InvalidMagic);
            };
        let checksum = byte_order.read_u32(bytes, 4);
        let actual = qnx6_crc32(&bytes[8..QNX6_SUPERBLOCK_SIZE]);
        if checksum != actual {
            return Err(Qnx6Error::ChecksumMismatch {
                stored: checksum,
                actual,
            });
        }
        let block_size = byte_order.read_u32(bytes, 48);
        if !matches!(block_size, 512 | 1024 | 2048 | 4096) {
            return Err(Qnx6Error::InvalidBlockSize(block_size));
        }
        let num_inodes = byte_order.read_u32(bytes, 52);
        let free_inodes = byte_order.read_u32(bytes, 56);
        if num_inodes == 0 || free_inodes > num_inodes {
            return Err(Qnx6Error::InvalidCounts("free inodes exceed total inodes"));
        }
        let num_blocks = byte_order.read_u32(bytes, 60);
        let free_blocks = byte_order.read_u32(bytes, 64);
        if num_blocks == 0 || free_blocks > num_blocks {
            return Err(Qnx6Error::InvalidCounts("free blocks exceed total blocks"));
        }
        let mut volume_id = [0_u8; 16];
        volume_id.copy_from_slice(&bytes[32..48]);
        Ok(Self {
            byte_order,
            checksum,
            serial: byte_order.read_u64(bytes, 8),
            created_time: byte_order.read_u32(bytes, 16),
            accessed_time: byte_order.read_u32(bytes, 20),
            flags: byte_order.read_u32(bytes, 24),
            version_major: byte_order.read_u16(bytes, 28),
            version_minor: byte_order.read_u16(bytes, 30),
            volume_id,
            block_size,
            num_inodes,
            free_inodes,
            num_blocks,
            free_blocks,
            allocation_group: byte_order.read_u32(bytes, 68),
            inode_root: Qnx6RootNode::parse(bytes, 72, byte_order, "inode")?,
            bitmap_root: Qnx6RootNode::parse(bytes, 152, byte_order, "bitmap")?,
            long_name_root: Qnx6RootNode::parse(bytes, 232, byte_order, "long-filename")?,
            unknown_root: Qnx6RootNode::parse(bytes, 312, byte_order, "unknown")?,
        })
    }

    /// Filesystem byte order.
    #[must_use]
    pub const fn byte_order(&self) -> ByteOrder {
        self.byte_order
    }

    /// Stored checksum covering bytes 8 through 511.
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Copy-on-write snapshot serial number.
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }

    /// Filesystem creation time as unsigned Unix seconds.
    #[must_use]
    pub const fn created_time(&self) -> u32 {
        self.created_time
    }

    /// Last filesystem access time as unsigned Unix seconds.
    #[must_use]
    pub const fn accessed_time(&self) -> u32 {
        self.accessed_time
    }

    /// On-disk filesystem flags.
    #[must_use]
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// First filesystem-version field.
    #[must_use]
    pub const fn version_major(&self) -> u16 {
        self.version_major
    }

    /// Second filesystem-version field.
    #[must_use]
    pub const fn version_minor(&self) -> u16 {
        self.version_minor
    }

    /// Persistent 16-byte volume identifier.
    #[must_use]
    pub const fn volume_id(&self) -> &[u8; 16] {
        &self.volume_id
    }

    /// Logical filesystem block size in bytes.
    #[must_use]
    pub const fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Total number of inode-table entries.
    #[must_use]
    pub const fn num_inodes(&self) -> u32 {
        self.num_inodes
    }

    /// Number of currently free inode-table entries.
    #[must_use]
    pub const fn free_inodes(&self) -> u32 {
        self.free_inodes
    }

    /// Number of addressable filesystem data blocks.
    #[must_use]
    pub const fn num_blocks(&self) -> u32 {
        self.num_blocks
    }

    /// Number of currently free filesystem data blocks.
    #[must_use]
    pub const fn free_blocks(&self) -> u32 {
        self.free_blocks
    }

    /// Allocation-group field recorded by the active snapshot.
    #[must_use]
    pub const fn allocation_group(&self) -> u32 {
        self.allocation_group
    }

    /// Root of the inode-table metadata file.
    #[must_use]
    pub const fn inode_root(&self) -> &Qnx6RootNode {
        &self.inode_root
    }

    /// Root of the allocation-bitmap metadata file.
    #[must_use]
    pub const fn bitmap_root(&self) -> &Qnx6RootNode {
        &self.bitmap_root
    }

    /// Root of the long-filename metadata file.
    #[must_use]
    pub const fn long_name_root(&self) -> &Qnx6RootNode {
        &self.long_name_root
    }

    /// Fourth format-internal metadata root.
    #[must_use]
    pub const fn unknown_root(&self) -> &Qnx6RootNode {
        &self.unknown_root
    }

    /// Byte offset of this volume's secondary superblock.
    ///
    /// # Errors
    ///
    /// Returns an error if corrupt geometry overflows `u64`.
    pub fn secondary_offset(&self) -> Result<u64> {
        u64::from(self.num_blocks)
            .checked_mul(u64::from(self.block_size))
            .and_then(|bytes| bytes.checked_add(QNX6_DATA_AREA_OFFSET))
            .ok_or(Qnx6Error::Overflow("secondary superblock offset"))
    }

    /// Total volume length implied by the superblock geometry.
    ///
    /// # Errors
    ///
    /// Returns an error if corrupt geometry overflows `u64`.
    pub fn volume_size(&self) -> Result<u64> {
        self.secondary_offset()?
            .checked_add(QNX6_SUPERBLOCK_AREA_SIZE)
            .ok_or(Qnx6Error::Overflow("volume size"))
    }

    pub(crate) fn immutable_geometry_matches(&self, other: &Self) -> bool {
        self.byte_order == other.byte_order
            && self.version_major == other.version_major
            && self.version_minor == other.version_minor
            && self.volume_id == other.volume_id
            && self.block_size == other.block_size
            && self.num_inodes == other.num_inodes
            && self.num_blocks == other.num_blocks
    }
}

/// QNX6's non-reflected CRC-32, initialized to zero with no final XOR.
#[must_use]
pub fn qnx6_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x04C1_1DB7
            };
        }
    }
    crc
}
