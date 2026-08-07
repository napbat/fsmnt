//! Primary-superblock parsing and validation.

use crate::checksum::ChecksumType;
use crate::chunk::{MIN_SYSTEM_CHUNK_ARRAY_SIZE, parse_system_chunks};
use crate::error::{BtrfsError, Result};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned,
};

pub use fsmnt_parser_core::boot_sector::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET as PRIMARY_SUPERBLOCK_OFFSET,
    BTRFS_SUPERBLOCK_MAGIC as SUPERBLOCK_MAGIC,
};

/// Size of one serialized Btrfs superblock.
pub const SUPERBLOCK_SIZE: usize = 0x1000;

/// Maximum number of bytes reserved for bootstrap chunk items.
pub const SYSTEM_CHUNK_ARRAY_CAPACITY: usize = 2048;

const MIN_VOLUME_BYTES: u64 = PRIMARY_SUPERBLOCK_OFFSET + 0x1000;
const LABEL_SIZE: usize = 0x100;
const SUPERBLOCK_TRAILING_SIZE: usize = 1237;
const MAX_BLOCK_SIZE: u32 = 65_536;
const MIN_SECTOR_SIZE: u32 = 4096;
const MAX_TREE_LEVELS: u8 = 8;
const METADATA_UUID_INCOMPAT: u64 = 1_u64 << 10;
const SIMPLE_QUOTA_INCOMPAT: u64 = 1_u64 << 16;
const SUPPORTED_INCOMPAT_FLAGS: u64 = 0x1fff | SIMPLE_QUOTA_INCOMPAT;
const SUPPORTED_SUPERBLOCK_FLAGS: u64 = (1_u64 << 0) | (1_u64 << 1) | (1_u64 << 2) | (7_u64 << 32);

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct RawDeviceItem {
    pub(crate) device_id: U64<LE>,
    pub(crate) total_bytes: U64<LE>,
    pub(crate) bytes_used: U64<LE>,
    _io_align: U32<LE>,
    _io_width: U32<LE>,
    pub(crate) sector_size: U32<LE>,
    _device_type: U64<LE>,
    _generation: U64<LE>,
    _start_offset: U64<LE>,
    _device_group: U32<LE>,
    _seek_speed: u8,
    _bandwidth: u8,
    pub(crate) uuid: [u8; 16],
    pub(crate) fsid: [u8; 16],
}

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
pub(crate) struct RawSuperblock {
    pub(crate) checksum: [u8; 32],
    pub(crate) fsid: [u8; 16],
    pub(crate) physical_address: U64<LE>,
    pub(crate) flags: U64<LE>,
    pub(crate) magic: [u8; 8],
    pub(crate) generation: U64<LE>,
    pub(crate) root: U64<LE>,
    pub(crate) chunk_root: U64<LE>,
    pub(crate) log_root: U64<LE>,
    _unused_log_root_transid: U64<LE>,
    pub(crate) total_bytes: U64<LE>,
    pub(crate) bytes_used: U64<LE>,
    pub(crate) root_dir_object_id: U64<LE>,
    pub(crate) num_devices: U64<LE>,
    pub(crate) sector_size: U32<LE>,
    pub(crate) node_size: U32<LE>,
    pub(crate) leaf_size: U32<LE>,
    pub(crate) stripe_size: U32<LE>,
    pub(crate) system_chunk_array_size: U32<LE>,
    pub(crate) chunk_root_generation: U64<LE>,
    pub(crate) compat_flags: U64<LE>,
    pub(crate) compat_ro_flags: U64<LE>,
    pub(crate) incompat_flags: U64<LE>,
    pub(crate) checksum_type: U16<LE>,
    pub(crate) root_level: u8,
    pub(crate) chunk_root_level: u8,
    pub(crate) log_root_level: u8,
    pub(crate) device: RawDeviceItem,
    pub(crate) label: [u8; LABEL_SIZE],
    _cache_generation: U64<LE>,
    _uuid_tree_generation: U64<LE>,
    pub(crate) metadata_uuid: [u8; 16],
    _global_root_count: U64<LE>,
    _remap_root: U64<LE>,
    _remap_root_generation: U64<LE>,
    _remap_root_level: u8,
    _reserved: [u8; 199],
    pub(crate) system_chunk_array: [u8; SYSTEM_CHUNK_ARRAY_CAPACITY],
    _trailing: [u8; SUPERBLOCK_TRAILING_SIZE],
}

const _: [(); 98] = [(); core::mem::size_of::<RawDeviceItem>()];
const _: [(); SUPERBLOCK_SIZE] = [(); core::mem::size_of::<RawSuperblock>()];

/// Validated metadata from a primary Btrfs superblock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsSuperblock {
    fsid: [u8; 16],
    metadata_uuid: [u8; 16],
    physical_address: u64,
    generation: u64,
    root: u64,
    chunk_root: u64,
    chunk_root_generation: u64,
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
        let raw = RawSuperblock::ref_from_bytes(data).map_err(|_| BtrfsError::BufferTooSmall {
            expected: SUPERBLOCK_SIZE,
            actual: data.len(),
        })?;
        let (physical_address, checksum_type) = validate_primary_header(data, raw)?;
        let incompat_flags = validate_incompat_features(raw)?;
        let geometry = parse_volume_geometry(raw)?;
        let roots = parse_tree_roots(raw, geometry.sector_size)?;
        validate_device_item(raw, incompat_flags, geometry.sector_size)?;
        let (system_chunk_array, system_chunk_array_size) = parse_system_chunk_array(raw)?;
        parse_system_chunks(
            &system_chunk_array[..system_chunk_array_size],
            geometry.sector_size,
            incompat_flags,
        )?;

        Ok(Self {
            fsid: raw.fsid,
            metadata_uuid: raw.metadata_uuid,
            physical_address,
            generation: raw.generation.get(),
            root: roots.root,
            chunk_root: roots.chunk_root,
            chunk_root_generation: raw.chunk_root_generation.get(),
            total_bytes: geometry.total_bytes,
            bytes_used: geometry.bytes_used,
            root_dir_object_id: raw.root_dir_object_id.get(),
            num_devices: geometry.num_devices,
            sector_size: geometry.sector_size,
            node_size: geometry.node_size,
            compat_flags: raw.compat_flags.get(),
            compat_ro_flags: raw.compat_ro_flags.get(),
            incompat_flags,
            checksum_type,
            root_level: roots.root_level,
            chunk_root_level: roots.chunk_root_level,
            device_id: raw.device.device_id.get(),
            device_uuid: raw.device.uuid,
            label: raw.label,
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

    /// Transaction generation expected in the chunk-tree root block.
    #[must_use]
    pub const fn chunk_root_generation(&self) -> u64 {
        self.chunk_root_generation
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

fn validate_primary_header(data: &[u8], raw: &RawSuperblock) -> Result<(u64, ChecksumType)> {
    let actual_magic = raw.magic;
    if actual_magic != SUPERBLOCK_MAGIC {
        return Err(BtrfsError::InvalidMagic {
            actual: actual_magic,
        });
    }

    let physical_address = raw.physical_address.get();
    if physical_address != PRIMARY_SUPERBLOCK_OFFSET {
        return Err(BtrfsError::InvalidPhysicalAddress {
            actual: physical_address,
        });
    }
    let unsupported_flags = raw.flags.get() & !SUPPORTED_SUPERBLOCK_FLAGS;
    if unsupported_flags != 0 {
        return Err(BtrfsError::UnsupportedSuperblockFlags {
            flags: unsupported_flags,
        });
    }

    let checksum_type = ChecksumType::from_raw(raw.checksum_type.get())?;
    if !checksum_type.verify(&raw.checksum, &data[32..]) {
        return Err(BtrfsError::InvalidChecksum {
            structure: "primary superblock",
            logical: physical_address,
        });
    }
    Ok((physical_address, checksum_type))
}

fn validate_incompat_features(raw: &RawSuperblock) -> Result<u64> {
    let flags = raw.incompat_flags.get();
    let unsupported = flags & !SUPPORTED_INCOMPAT_FLAGS;
    if unsupported != 0 {
        return Err(BtrfsError::UnsupportedIncompatFeatures { flags: unsupported });
    }
    Ok(flags)
}

fn parse_volume_geometry(raw: &RawSuperblock) -> Result<VolumeGeometry> {
    let total_bytes = raw.total_bytes.get();
    if total_bytes < MIN_VOLUME_BYTES {
        return Err(BtrfsError::InvalidTotalBytes {
            actual: total_bytes,
        });
    }
    let bytes_used = raw.bytes_used.get();
    if bytes_used > total_bytes {
        return Err(BtrfsError::InvalidBytesUsed {
            bytes_used,
            total_bytes,
        });
    }

    let num_devices = raw.num_devices.get();
    if num_devices == 0 {
        return Err(BtrfsError::InvalidDeviceCount);
    }

    let sector_size = raw.sector_size.get();
    if !sector_size.is_power_of_two() || !(MIN_SECTOR_SIZE..=MAX_BLOCK_SIZE).contains(&sector_size)
    {
        return Err(BtrfsError::InvalidSectorSize {
            actual: sector_size,
        });
    }
    let node_size = raw.node_size.get();
    if !node_size.is_power_of_two() || !(sector_size..=MAX_BLOCK_SIZE).contains(&node_size) {
        return Err(BtrfsError::InvalidNodeSize {
            actual: node_size,
            sector_size,
        });
    }
    if raw.leaf_size.get() != node_size {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "leaf_size",
            value: u64::from(raw.leaf_size.get()),
        });
    }
    if !raw.stripe_size.get().is_power_of_two() {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "stripe_size",
            value: u64::from(raw.stripe_size.get()),
        });
    }
    let minimum_bytes_used = u64::from(node_size)
        .checked_mul(6)
        .ok_or(BtrfsError::IntegerOverflow)?;
    if bytes_used < minimum_bytes_used {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "bytes_used",
            value: bytes_used,
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

fn parse_tree_roots(raw: &RawSuperblock, sector_size: u32) -> Result<TreeRoots> {
    let root = raw.root.get();
    let root_level = raw.root_level;
    validate_tree_root("root", root, root_level, sector_size)?;
    let chunk_root = raw.chunk_root.get();
    let chunk_root_level = raw.chunk_root_level;
    validate_tree_root("chunk", chunk_root, chunk_root_level, sector_size)?;
    let log_root = raw.log_root.get();
    let log_root_level = raw.log_root_level;
    if log_root_level >= MAX_TREE_LEVELS || !log_root.is_multiple_of(u64::from(sector_size)) {
        return Err(BtrfsError::InvalidTreeRoot {
            tree: "log",
            logical: log_root,
            level: log_root_level,
        });
    }
    Ok(TreeRoots {
        root,
        root_level,
        chunk_root,
        chunk_root_level,
    })
}

fn validate_device_item(raw: &RawSuperblock, incompat_flags: u64, sector_size: u32) -> Result<()> {
    if raw.device.device_id.get() == 0 {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "device_id",
            value: 0,
        });
    }
    if raw.device.sector_size.get() != sector_size {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "device_sector_size",
            value: u64::from(raw.device.sector_size.get()),
        });
    }
    if raw.device.bytes_used.get() > raw.device.total_bytes.get() {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "device_bytes_used",
            value: raw.device.bytes_used.get(),
        });
    }
    let tree_uuid = if incompat_flags & METADATA_UUID_INCOMPAT != 0 {
        raw.metadata_uuid
    } else {
        raw.fsid
    };
    if raw.device.fsid != tree_uuid {
        return Err(BtrfsError::SuperblockUuidMismatch);
    }
    Ok(())
}

fn parse_system_chunk_array(
    raw: &RawSuperblock,
) -> Result<([u8; SYSTEM_CHUNK_ARRAY_CAPACITY], usize)> {
    let size_raw = raw.system_chunk_array_size.get();
    let size = usize::try_from(size_raw).map_err(|_| BtrfsError::IntegerOverflow)?;
    if !(MIN_SYSTEM_CHUNK_ARRAY_SIZE..=SYSTEM_CHUNK_ARRAY_CAPACITY).contains(&size) {
        return Err(BtrfsError::InvalidSystemChunkArraySize { actual: size_raw });
    }
    let mut chunks = [0_u8; SYSTEM_CHUNK_ARRAY_CAPACITY];
    chunks[..size].copy_from_slice(&raw.system_chunk_array[..size]);
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

#[cfg(feature = "fuzzing")]
pub(crate) fn normalize_for_fuzzing(
    data: &mut [u8],
    checksum_type: ChecksumType,
    requested_sector_size: u32,
) -> bool {
    if data.len() != SUPERBLOCK_SIZE {
        return false;
    }
    {
        let Ok(raw) = RawSuperblock::mut_from_bytes(data) else {
            return false;
        };
        let sector_size = if requested_sector_size.is_power_of_two()
            && (MIN_SECTOR_SIZE..=MAX_BLOCK_SIZE).contains(&requested_sector_size)
        {
            requested_sector_size
        } else {
            MIN_SECTOR_SIZE
        };
        let minimum_bytes_used = u64::from(sector_size) * 6;
        let total_bytes = raw
            .total_bytes
            .get()
            .max(MIN_VOLUME_BYTES)
            .max(minimum_bytes_used);
        let incompat_flags = raw.incompat_flags.get() & SUPPORTED_INCOMPAT_FLAGS;

        raw.checksum.fill(0);
        raw.physical_address = U64::new(PRIMARY_SUPERBLOCK_OFFSET);
        raw.flags = U64::new(raw.flags.get() & SUPPORTED_SUPERBLOCK_FLAGS);
        raw.magic = SUPERBLOCK_MAGIC;
        raw.root = U64::new(aligned_nonzero(raw.root.get(), sector_size));
        raw.chunk_root = U64::new(aligned_nonzero(raw.chunk_root.get(), sector_size));
        raw.log_root = U64::new(aligned(raw.log_root.get(), sector_size));
        raw.total_bytes = U64::new(total_bytes);
        raw.bytes_used = U64::new(raw.bytes_used.get().clamp(minimum_bytes_used, total_bytes));
        raw.root_dir_object_id = U64::new(6);
        raw.num_devices = U64::new(raw.num_devices.get().clamp(1, 32));
        raw.sector_size = U32::new(sector_size);
        raw.node_size = U32::new(sector_size);
        raw.leaf_size = U32::new(sector_size);
        raw.stripe_size = U32::new(sector_size);
        raw.incompat_flags = U64::new(incompat_flags);
        raw.checksum_type = U16::new(checksum_type.raw());
        raw.root_level %= MAX_TREE_LEVELS;
        raw.chunk_root_level %= MAX_TREE_LEVELS;
        raw.log_root_level %= MAX_TREE_LEVELS;
        raw.device.device_id = U64::new(raw.device.device_id.get().max(1));
        raw.device.total_bytes = U64::new(total_bytes);
        raw.device.bytes_used = raw.bytes_used;
        raw.device.sector_size = U32::new(sector_size);
        raw.device.fsid = if incompat_flags & METADATA_UUID_INCOMPAT != 0 {
            raw.metadata_uuid
        } else {
            raw.fsid
        };
        let system_chunk = crate::chunk::canonical_system_chunk(
            0x10_0000,
            sector_size,
            raw.device.device_id.get(),
            raw.device.uuid,
        );
        raw.system_chunk_array.fill(0);
        raw.system_chunk_array[..system_chunk.len()].copy_from_slice(&system_chunk);
        raw.system_chunk_array_size =
            U32::new(u32::try_from(system_chunk.len()).expect("system chunk capacity fits u32"));
    }
    let checksum = checksum_type.compute(&data[32..]);
    let Ok(raw) = RawSuperblock::mut_from_bytes(data) else {
        return false;
    };
    raw.checksum = checksum;
    true
}

#[cfg(feature = "fuzzing")]
fn aligned(value: u64, sector_size: u32) -> u64 {
    let sector_size = u64::from(sector_size);
    value / sector_size * sector_size
}

#[cfg(feature = "fuzzing")]
fn aligned_nonzero(value: u64, sector_size: u32) -> u64 {
    let aligned = aligned(value, sector_size);
    if aligned == 0 {
        u64::from(sector_size)
    } else {
        aligned
    }
}
