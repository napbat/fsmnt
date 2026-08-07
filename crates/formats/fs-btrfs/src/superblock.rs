//! Primary-superblock parsing and validation.

use crate::bytes::{array, slice, u16_at, u32_at, u64_at};
use crate::checksum::ChecksumType;
use crate::error::{BtrfsError, Result};

pub use fsmnt_parser_core::boot_sector::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET as PRIMARY_SUPERBLOCK_OFFSET,
    BTRFS_SUPERBLOCK_MAGIC as SUPERBLOCK_MAGIC,
};

/// Size of one serialized Btrfs superblock.
pub const SUPERBLOCK_SIZE: usize = 0x1000;

/// Maximum number of bytes reserved for bootstrap chunk items.
pub const SYSTEM_CHUNK_ARRAY_CAPACITY: usize = 2048;

const MIN_VOLUME_BYTES: u64 = PRIMARY_SUPERBLOCK_OFFSET + 0x1000;
const FSID_OFFSET: usize = 0x20;
const PHYSICAL_ADDRESS_OFFSET: usize = 0x30;
const MAGIC_OFFSET: usize = 0x40;
const GENERATION_OFFSET: usize = 0x48;
const ROOT_OFFSET: usize = 0x50;
const CHUNK_ROOT_OFFSET: usize = 0x58;
const TOTAL_BYTES_OFFSET: usize = 0x70;
const BYTES_USED_OFFSET: usize = 0x78;
const ROOT_DIR_OBJECT_ID_OFFSET: usize = 0x80;
const NUM_DEVICES_OFFSET: usize = 0x88;
const SECTOR_SIZE_OFFSET: usize = 0x90;
const NODE_SIZE_OFFSET: usize = 0x94;
const SYSTEM_CHUNK_ARRAY_SIZE_OFFSET: usize = 0xa0;
const COMPAT_FLAGS_OFFSET: usize = 0xac;
const COMPAT_RO_FLAGS_OFFSET: usize = 0xb4;
const INCOMPAT_FLAGS_OFFSET: usize = 0xbc;
const CHECKSUM_TYPE_OFFSET: usize = 0xc4;
const ROOT_LEVEL_OFFSET: usize = 0xc6;
const CHUNK_ROOT_LEVEL_OFFSET: usize = 0xc7;
const DEVICE_ITEM_OFFSET: usize = 0xc9;
const DEVICE_ID_OFFSET: usize = DEVICE_ITEM_OFFSET;
const DEVICE_UUID_OFFSET: usize = DEVICE_ITEM_OFFSET + 0x42;
const LABEL_OFFSET: usize = 0x12b;
const LABEL_SIZE: usize = 0x100;
const METADATA_UUID_OFFSET: usize = 0x23b;
const SYSTEM_CHUNK_ARRAY_OFFSET: usize = 0x32b;
const MAX_BLOCK_SIZE: u32 = 65_536;
const MIN_SECTOR_SIZE: u32 = 4096;
const MAX_TREE_LEVELS: u8 = 8;
const METADATA_UUID_INCOMPAT: u64 = 1_u64 << 10;
const SIMPLE_QUOTA_INCOMPAT: u64 = 1_u64 << 16;
const SUPPORTED_INCOMPAT_FLAGS: u64 = 0x1fff | SIMPLE_QUOTA_INCOMPAT;

/// Validated metadata from a primary Btrfs superblock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsSuperblock {
    fsid: [u8; 16],
    metadata_uuid: [u8; 16],
    physical_address: u64,
    generation: u64,
    root: u64,
    chunk_root: u64,
    total_bytes: u64,
    bytes_used: u64,
    root_dir_object_id: u64,
    num_devices: u64,
    sector_size: u32,
    node_size: u32,
    compat_flags: u64,
    compat_ro_flags: u64,
    incompat_flags: u64,
    checksum_type: ChecksumType,
    root_level: u8,
    chunk_root_level: u8,
    device_id: u64,
    device_uuid: [u8; 16],
    label: [u8; LABEL_SIZE],
    system_chunk_array: [u8; SYSTEM_CHUNK_ARRAY_CAPACITY],
    system_chunk_array_size: usize,
}

struct VolumeGeometry {
    total_bytes: u64,
    bytes_used: u64,
    num_devices: u64,
    sector_size: u32,
    node_size: u32,
}

struct TreeRoots {
    root: u64,
    root_level: u8,
    chunk_root: u64,
    chunk_root_level: u8,
}

impl BtrfsSuperblock {
    /// Parse and validate bytes read from the primary superblock location.
    ///
    /// Validation covers the signature, self-address, checksum, volume
    /// geometry, tree roots, and bootstrap chunk-array bounds.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when a required field is absent, inconsistent,
    /// unsupported, or fails checksum validation.
    pub fn from_primary_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(BtrfsError::BufferTooSmall {
                expected: SUPERBLOCK_SIZE,
                actual: data.len(),
            });
        }
        let data = &data[..SUPERBLOCK_SIZE];
        let (physical_address, checksum_type) = validate_primary_header(data)?;
        let incompat_flags = validate_incompat_features(data)?;
        let geometry = parse_volume_geometry(data)?;
        let roots = parse_tree_roots(data, geometry.sector_size)?;
        let (system_chunk_array, system_chunk_array_size) = parse_system_chunk_array(data)?;

        Ok(Self {
            fsid: array(data, FSID_OFFSET)?,
            metadata_uuid: array(data, METADATA_UUID_OFFSET)?,
            physical_address,
            generation: u64_at(data, GENERATION_OFFSET)?,
            root: roots.root,
            chunk_root: roots.chunk_root,
            total_bytes: geometry.total_bytes,
            bytes_used: geometry.bytes_used,
            root_dir_object_id: u64_at(data, ROOT_DIR_OBJECT_ID_OFFSET)?,
            num_devices: geometry.num_devices,
            sector_size: geometry.sector_size,
            node_size: geometry.node_size,
            compat_flags: u64_at(data, COMPAT_FLAGS_OFFSET)?,
            compat_ro_flags: u64_at(data, COMPAT_RO_FLAGS_OFFSET)?,
            incompat_flags,
            checksum_type,
            root_level: roots.root_level,
            chunk_root_level: roots.chunk_root_level,
            device_id: u64_at(data, DEVICE_ID_OFFSET)?,
            device_uuid: array(data, DEVICE_UUID_OFFSET)?,
            label: array(data, LABEL_OFFSET)?,
            system_chunk_array,
            system_chunk_array_size,
        })
    }

    /// Filesystem UUID in on-disk byte order.
    #[must_use]
    pub const fn fsid(&self) -> &[u8; 16] {
        &self.fsid
    }

    /// UUID expected in tree-block headers.
    ///
    /// Filesystems using the `METADATA_UUID` incompatibility feature carry a
    /// separate metadata UUID; older filesystems use the visible FSID.
    #[must_use]
    pub const fn tree_uuid(&self) -> &[u8; 16] {
        if self.incompat_flags & METADATA_UUID_INCOMPAT == 0 {
            &self.fsid
        } else {
            &self.metadata_uuid
        }
    }

    /// Physical byte address recorded for this superblock.
    #[must_use]
    pub const fn physical_address(&self) -> u64 {
        self.physical_address
    }

    /// Transaction generation committed by this superblock.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Logical address of the root-tree root block.
    #[must_use]
    pub const fn root(&self) -> u64 {
        self.root
    }

    /// Level of the root-tree root block.
    #[must_use]
    pub const fn root_level(&self) -> u8 {
        self.root_level
    }

    /// Logical address of the chunk-tree root block.
    #[must_use]
    pub const fn chunk_root(&self) -> u64 {
        self.chunk_root
    }

    /// Level of the chunk-tree root block.
    #[must_use]
    pub const fn chunk_root_level(&self) -> u8 {
        self.chunk_root_level
    }

    /// Declared filesystem capacity in bytes.
    #[must_use]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Declared allocated space in bytes.
    #[must_use]
    pub const fn bytes_used(&self) -> u64 {
        self.bytes_used
    }

    /// Object identifier of the root-tree directory.
    #[must_use]
    pub const fn root_dir_object_id(&self) -> u64 {
        self.root_dir_object_id
    }

    /// Number of devices belonging to the filesystem.
    #[must_use]
    pub const fn num_devices(&self) -> u64 {
        self.num_devices
    }

    /// Minimum data allocation and checksum unit in bytes.
    #[must_use]
    pub const fn sector_size(&self) -> u32 {
        self.sector_size
    }

    /// B-tree node size in bytes.
    #[must_use]
    pub const fn node_size(&self) -> u32 {
        self.node_size
    }

    /// Compatible feature flags.
    #[must_use]
    pub const fn compat_flags(&self) -> u64 {
        self.compat_flags
    }

    /// Read-only-compatible feature flags.
    #[must_use]
    pub const fn compat_ro_flags(&self) -> u64 {
        self.compat_ro_flags
    }

    /// Incompatible feature flags.
    #[must_use]
    pub const fn incompat_flags(&self) -> u64 {
        self.incompat_flags
    }

    /// Checksum algorithm used by this filesystem.
    #[must_use]
    pub const fn checksum_type(&self) -> ChecksumType {
        self.checksum_type
    }

    /// Filesystem-local identifier of the device carrying this superblock.
    #[must_use]
    pub const fn device_id(&self) -> u64 {
        self.device_id
    }

    /// UUID of the device carrying this superblock.
    #[must_use]
    pub const fn device_uuid(&self) -> &[u8; 16] {
        &self.device_uuid
    }

    /// Serialized bootstrap chunk records.
    #[must_use]
    pub fn system_chunk_array(&self) -> &[u8] {
        &self.system_chunk_array[..self.system_chunk_array_size]
    }

    /// Volume label bytes, truncated at the first null byte.
    #[must_use]
    pub fn label_bytes(&self) -> &[u8] {
        let length = self
            .label
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.label.len());
        &self.label[..length]
    }

    /// UTF-8 volume label, or `None` when the on-disk label is not UTF-8.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        core::str::from_utf8(self.label_bytes()).ok()
    }
}

fn validate_primary_header(data: &[u8]) -> Result<(u64, ChecksumType)> {
    let actual_magic = array(data, MAGIC_OFFSET)?;
    if actual_magic != SUPERBLOCK_MAGIC {
        return Err(BtrfsError::InvalidMagic {
            actual: actual_magic,
        });
    }

    let physical_address = u64_at(data, PHYSICAL_ADDRESS_OFFSET)?;
    if physical_address != PRIMARY_SUPERBLOCK_OFFSET {
        return Err(BtrfsError::InvalidPhysicalAddress {
            actual: physical_address,
        });
    }

    let checksum_type = ChecksumType::from_raw(u16_at(data, CHECKSUM_TYPE_OFFSET)?)?;
    if !checksum_type.verify(&data[..32], &data[32..]) {
        return Err(BtrfsError::InvalidChecksum {
            structure: "primary superblock",
            logical: physical_address,
        });
    }
    Ok((physical_address, checksum_type))
}

fn validate_incompat_features(data: &[u8]) -> Result<u64> {
    let flags = u64_at(data, INCOMPAT_FLAGS_OFFSET)?;
    let unsupported = flags & !SUPPORTED_INCOMPAT_FLAGS;
    if unsupported != 0 {
        return Err(BtrfsError::UnsupportedIncompatFeatures { flags: unsupported });
    }
    Ok(flags)
}

fn parse_volume_geometry(data: &[u8]) -> Result<VolumeGeometry> {
    let total_bytes = u64_at(data, TOTAL_BYTES_OFFSET)?;
    if total_bytes < MIN_VOLUME_BYTES {
        return Err(BtrfsError::InvalidTotalBytes {
            actual: total_bytes,
        });
    }
    let bytes_used = u64_at(data, BYTES_USED_OFFSET)?;
    if bytes_used > total_bytes {
        return Err(BtrfsError::InvalidBytesUsed {
            bytes_used,
            total_bytes,
        });
    }

    let num_devices = u64_at(data, NUM_DEVICES_OFFSET)?;
    if num_devices == 0 {
        return Err(BtrfsError::InvalidDeviceCount);
    }

    let sector_size = u32_at(data, SECTOR_SIZE_OFFSET)?;
    if !sector_size.is_power_of_two() || !(MIN_SECTOR_SIZE..=MAX_BLOCK_SIZE).contains(&sector_size)
    {
        return Err(BtrfsError::InvalidSectorSize {
            actual: sector_size,
        });
    }
    let node_size = u32_at(data, NODE_SIZE_OFFSET)?;
    if !node_size.is_power_of_two() || !(sector_size..=MAX_BLOCK_SIZE).contains(&node_size) {
        return Err(BtrfsError::InvalidNodeSize {
            actual: node_size,
            sector_size,
        });
    }

    Ok(VolumeGeometry {
        total_bytes,
        bytes_used,
        num_devices,
        sector_size,
        node_size,
    })
}

fn parse_tree_roots(data: &[u8], sector_size: u32) -> Result<TreeRoots> {
    let root = u64_at(data, ROOT_OFFSET)?;
    let root_level = data[ROOT_LEVEL_OFFSET];
    validate_tree_root("root", root, root_level, sector_size)?;
    let chunk_root = u64_at(data, CHUNK_ROOT_OFFSET)?;
    let chunk_root_level = data[CHUNK_ROOT_LEVEL_OFFSET];
    validate_tree_root("chunk", chunk_root, chunk_root_level, sector_size)?;
    Ok(TreeRoots {
        root,
        root_level,
        chunk_root,
        chunk_root_level,
    })
}

fn parse_system_chunk_array(data: &[u8]) -> Result<([u8; SYSTEM_CHUNK_ARRAY_CAPACITY], usize)> {
    let size_raw = u32_at(data, SYSTEM_CHUNK_ARRAY_SIZE_OFFSET)?;
    let size = usize::try_from(size_raw).map_err(|_| BtrfsError::IntegerOverflow)?;
    if size > SYSTEM_CHUNK_ARRAY_CAPACITY {
        return Err(BtrfsError::InvalidSystemChunkArraySize { actual: size_raw });
    }
    let mut chunks = [0_u8; SYSTEM_CHUNK_ARRAY_CAPACITY];
    chunks[..size].copy_from_slice(slice(data, SYSTEM_CHUNK_ARRAY_OFFSET, size)?);
    Ok((chunks, size))
}

fn validate_tree_root(tree: &'static str, logical: u64, level: u8, sector_size: u32) -> Result<()> {
    if logical == 0 || level >= MAX_TREE_LEVELS || !logical.is_multiple_of(u64::from(sector_size)) {
        return Err(BtrfsError::InvalidTreeRoot {
            tree,
            logical,
            level,
        });
    }
    Ok(())
}
