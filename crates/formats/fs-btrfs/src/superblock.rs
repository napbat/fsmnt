//! Superblock-mirror parsing, validation, and selection.

mod backup;
mod zoned;

use alloc::vec::Vec;

use crate::checksum::ChecksumType;
use crate::chunk::{MIN_SYSTEM_CHUNK_ARRAY_SIZE, parse_system_chunks};
use crate::error::{BtrfsError, Result};
use fsmnt_parser_core::io::{Read, Seek, SeekFrom};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U16, U32, U64, Unaligned,
};

pub use backup::{BtrfsBackupTreeRoot, BtrfsRootBackup};
use backup::{ROOT_BACKUP_COUNT, RawRootBackup, parse_root_backups};
pub use fsmnt_parser_core::boot_sector::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET as PRIMARY_SUPERBLOCK_OFFSET,
    BTRFS_SUPERBLOCK_MAGIC as SUPERBLOCK_MAGIC,
};
use zoned::SuperblockLocation;
pub use zoned::{
    BtrfsDeviceSource, BtrfsZone, BtrfsZoneCondition, BtrfsZoneType, BtrfsZonedDevice,
    MAX_ZONE_SIZE, MIN_ZONE_SIZE, ZONED_SUPERBLOCK_LOG_OFFSETS,
};

/// Size of one serialized Btrfs superblock.
pub const SUPERBLOCK_SIZE: usize = 0x1000;

/// Physical offsets of Btrfs's primary and backup superblock mirrors.
pub const SUPERBLOCK_MIRROR_OFFSETS: [u64; 3] = [
    PRIMARY_SUPERBLOCK_OFFSET,
    64 * 1024 * 1024,
    256 * 1024 * 1024 * 1024,
];

/// Maximum number of bytes reserved for bootstrap chunk items.
pub const SYSTEM_CHUNK_ARRAY_CAPACITY: usize = 2048;

const MIN_VOLUME_BYTES: u64 = PRIMARY_SUPERBLOCK_OFFSET + 0x1000;
const LABEL_SIZE: usize = 0x100;
const SUPERBLOCK_PADDING_SIZE: usize = 565;
const MAX_BLOCK_SIZE: u32 = 65_536;
const MIN_SECTOR_SIZE: u32 = 4096;
const MAX_TREE_LEVELS: u8 = 8;
const METADATA_UUID_INCOMPAT: u64 = 1_u64 << 10;
const MIXED_GROUPS_INCOMPAT: u64 = 1_u64 << 2;
const ZONED_INCOMPAT: u64 = 1_u64 << 12;
pub(crate) const EXTENT_TREE_V2_INCOMPAT: u64 = 1_u64 << 13;
pub(crate) const RAID_STRIPE_TREE_INCOMPAT: u64 = 1_u64 << 14;
const SIMPLE_QUOTA_INCOMPAT: u64 = 1_u64 << 16;
pub(crate) const REMAP_TREE_INCOMPAT: u64 = 1_u64 << 17;
const NO_HOLES_INCOMPAT: u64 = 1_u64 << 9;
const FREE_SPACE_TREE_COMPAT_RO: u64 = 1_u64 << 0;
const FREE_SPACE_TREE_VALID_COMPAT_RO: u64 = 1_u64 << 1;
const BLOCK_GROUP_TREE_COMPAT_RO: u64 = 1_u64 << 3;
const EXTENT_TREE_V2_REQUIRED_COMPAT_RO: u64 =
    FREE_SPACE_TREE_COMPAT_RO | FREE_SPACE_TREE_VALID_COMPAT_RO | BLOCK_GROUP_TREE_COMPAT_RO;
const REMAP_TREE_REQUIRED_COMPAT_RO: u64 = EXTENT_TREE_V2_REQUIRED_COMPAT_RO;
const SUPERBLOCK_FLAG_SEEDING: u64 = 1_u64 << 32;
const SUPPORTED_INCOMPAT_FLAGS: u64 = 0x7fff | SIMPLE_QUOTA_INCOMPAT | REMAP_TREE_INCOMPAT;
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
    pub(crate) log_root_transid: U64<LE>,
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
    pub(crate) global_root_count: U64<LE>,
    pub(crate) remap_root: U64<LE>,
    pub(crate) remap_root_generation: U64<LE>,
    pub(crate) remap_root_level: u8,
    _reserved: [u8; 199],
    pub(crate) system_chunk_array: [u8; SYSTEM_CHUNK_ARRAY_CAPACITY],
    pub(crate) root_backups: [RawRootBackup; ROOT_BACKUP_COUNT],
    _padding: [u8; SUPERBLOCK_PADDING_SIZE],
}

const _: [(); 98] = [(); core::mem::size_of::<RawDeviceItem>()];
const _: [(); SUPERBLOCK_SIZE] = [(); core::mem::size_of::<RawSuperblock>()];

/// Validated metadata from a Btrfs superblock mirror.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsSuperblock {
    fsid: [u8; 16],
    metadata_uuid: [u8; 16],
    physical_address: u64,
    flags: u64,
    generation: u64,
    root: u64,
    chunk_root: u64,
    chunk_root_generation: u64,
    log_root: u64,
    log_root_transid: u64,
    total_bytes: u64,
    bytes_used: u64,
    root_dir_object_id: u64,
    num_devices: u64,
    sector_size: u32,
    node_size: u32,
    compat_flags: u64,
    compat_ro_flags: u64,
    incompat_flags: u64,
    global_root_count: u64,
    remap_root: u64,
    remap_root_generation: u64,
    remap_root_level: u8,
    checksum_type: ChecksumType,
    root_level: u8,
    chunk_root_level: u8,
    log_root_level: u8,
    device_id: u64,
    device_uuid: [u8; 16],
    label: [u8; LABEL_SIZE],
    system_chunk_array: [u8; SYSTEM_CHUNK_ARRAY_CAPACITY],
    system_chunk_array_size: usize,
    root_backups: Vec<BtrfsRootBackup>,
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
    log_root: u64,
    log_root_level: u8,
    remap_root: u64,
    remap_root_level: u8,
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
        Self::from_bytes_at(data, PRIMARY_SUPERBLOCK_OFFSET)
    }

    /// Parse and validate bytes read at one Btrfs superblock-mirror offset.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when the bytes are short, the superblock's
    /// self-address differs from `physical_address`, or any checksum,
    /// structural, geometry, or feature validation fails.
    pub fn from_bytes_at(data: &[u8], physical_address: u64) -> Result<Self> {
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
        let (physical_address, checksum_type) = validate_header(data, raw, physical_address)?;
        let incompat_flags = validate_features(raw)?;
        if raw.flags.get() & SUPERBLOCK_FLAG_SEEDING != 0
            && incompat_flags & METADATA_UUID_INCOMPAT != 0
        {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "seeding_metadata_uuid",
                value: incompat_flags,
            });
        }
        let geometry = parse_volume_geometry(raw)?;
        let roots = parse_tree_roots(raw, geometry.sector_size)?;
        let root_backups = parse_root_backups(
            &raw.root_backups,
            geometry.sector_size,
            raw.generation.get(),
        );
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
            flags: raw.flags.get(),
            generation: raw.generation.get(),
            root: roots.root,
            chunk_root: roots.chunk_root,
            chunk_root_generation: raw.chunk_root_generation.get(),
            log_root: roots.log_root,
            log_root_transid: raw.log_root_transid.get(),
            total_bytes: geometry.total_bytes,
            bytes_used: geometry.bytes_used,
            root_dir_object_id: raw.root_dir_object_id.get(),
            num_devices: geometry.num_devices,
            sector_size: geometry.sector_size,
            node_size: geometry.node_size,
            compat_flags: raw.compat_flags.get(),
            compat_ro_flags: raw.compat_ro_flags.get(),
            incompat_flags,
            global_root_count: raw.global_root_count.get(),
            remap_root: roots.remap_root,
            remap_root_generation: raw.remap_root_generation.get(),
            remap_root_level: roots.remap_root_level,
            checksum_type,
            root_level: roots.root_level,
            chunk_root_level: roots.chunk_root_level,
            log_root_level: roots.log_root_level,
            device_id: raw.device.device_id.get(),
            device_uuid: raw.device.uuid,
            label: raw.label,
            system_chunk_array,
            system_chunk_array_size,
            root_backups,
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

    /// Whether this member is a read-only seed filesystem.
    #[must_use]
    pub const fn is_seeding(&self) -> bool {
        self.flags & SUPERBLOCK_FLAG_SEEDING != 0
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

    /// Logical address of the pending tree-log root, when crash recovery is required.
    #[must_use]
    pub const fn log_root(&self) -> Option<u64> {
        if self.log_root == 0 {
            None
        } else {
            Some(self.log_root)
        }
    }

    /// Legacy transaction field stored beside the tree-log root.
    ///
    /// Current Linux writers leave this field at zero. Tree-log block
    /// generations are validated against [`Self::generation`] instead.
    #[must_use]
    pub const fn log_root_transid(&self) -> u64 {
        self.log_root_transid
    }

    /// Level of the pending tree-log root block.
    #[must_use]
    pub const fn log_root_level(&self) -> u8 {
        self.log_root_level
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

    /// Whether the filesystem uses Btrfs's zoned-device allocation model.
    #[must_use]
    pub const fn is_zoned(&self) -> bool {
        self.incompat_flags & ZONED_INCOMPAT != 0
    }

    /// Whether data extents may use mappings stored in the RAID stripe tree.
    #[must_use]
    pub const fn has_raid_stripe_tree(&self) -> bool {
        self.incompat_flags & RAID_STRIPE_TREE_INCOMPAT != 0
    }

    /// Whether remapped logical ranges are described by a direct remap-tree root.
    #[must_use]
    pub const fn has_remap_tree(&self) -> bool {
        self.incompat_flags & REMAP_TREE_INCOMPAT != 0
    }

    /// Logical address of the remap-tree root block, when the feature is active.
    #[must_use]
    pub const fn remap_root(&self) -> Option<u64> {
        if self.has_remap_tree() {
            Some(self.remap_root)
        } else {
            None
        }
    }

    /// Generation expected in the direct remap-tree root block.
    #[must_use]
    pub const fn remap_root_generation(&self) -> Option<u64> {
        if self.has_remap_tree() {
            Some(self.remap_root_generation)
        } else {
            None
        }
    }

    /// Level of the direct remap-tree root block.
    #[must_use]
    pub const fn remap_root_level(&self) -> Option<u8> {
        if self.has_remap_tree() {
            Some(self.remap_root_level)
        } else {
            None
        }
    }

    /// Number of extent-tree-v2 global root sets.
    ///
    /// Legacy filesystems report zero. An extent-tree-v2 filesystem has one
    /// extent, checksum, and free-space root for every identifier in
    /// `0..global_root_count`.
    #[must_use]
    pub const fn global_root_count(&self) -> u64 {
        self.global_root_count
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

    /// Valid historical root sets embedded in this superblock mirror.
    ///
    /// Empty or structurally invalid optional records are omitted. Records
    /// retain their physical array slot and on-disk rotation order.
    #[must_use]
    pub fn root_backups(&self) -> &[BtrfsRootBackup] {
        &self.root_backups
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

pub(crate) fn read_best_superblock<R: Read + Seek>(reader: &mut R) -> Result<BtrfsSuperblock> {
    let locations = SUPERBLOCK_MIRROR_OFFSETS.map(|mirror_address| SuperblockLocation {
        read_offset: mirror_address,
        mirror_address,
    });
    read_best_superblock_at_locations(reader, locations)
}

pub(crate) fn read_best_zoned_superblock<R: Read + Seek>(
    reader: &mut R,
    zoned: &BtrfsZonedDevice,
) -> Result<BtrfsSuperblock> {
    let locations = zoned.superblock_locations()?;
    let superblock = read_best_superblock_at_locations(reader, locations)?;
    if !superblock.is_zoned() {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "zoned_device_without_zoned_feature",
            value: superblock.incompat_flags(),
        });
    }
    Ok(superblock)
}

/// Probe the current superblock-log records of a zoned device for Btrfs
/// identity without fully validating the filesystem.
///
/// The reader position is restored before this function returns.
///
/// # Errors
///
/// Returns an error when the zone report is inconsistent, a candidate cannot
/// be read, or the original reader position cannot be restored.
pub fn probe_zoned_superblock<R: Read + Seek + ?Sized>(
    reader: &mut R,
    zoned: &BtrfsZonedDevice,
) -> Result<bool> {
    let original_position = reader.stream_position()?;
    let result = probe_zoned_superblock_inner(reader, zoned);
    let restored = reader.seek(SeekFrom::Start(original_position));
    match (result, restored) {
        (Ok(found), Ok(_)) => Ok(found),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn probe_zoned_superblock_inner<R: Read + Seek + ?Sized>(
    reader: &mut R,
    zoned: &BtrfsZonedDevice,
) -> Result<bool> {
    for location in zoned.superblock_locations()? {
        reader.seek(SeekFrom::Start(location.read_offset))?;
        let mut data = [0_u8; SUPERBLOCK_SIZE];
        reader.read_exact(&mut data)?;
        let raw = RawSuperblock::ref_from_bytes(&data).map_err(|_| BtrfsError::BufferTooSmall {
            expected: SUPERBLOCK_SIZE,
            actual: data.len(),
        })?;
        if raw.magic == SUPERBLOCK_MAGIC
            && raw.physical_address.get() == location.mirror_address
            && raw.incompat_flags.get() & ZONED_INCOMPAT != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_best_superblock_at_locations<R, I>(reader: &mut R, locations: I) -> Result<BtrfsSuperblock>
where
    R: Read + Seek,
    I: IntoIterator<Item = SuperblockLocation>,
{
    let mut best: Option<(BtrfsSuperblock, u64)> = None;
    let mut first_error = None;
    for location in locations {
        let candidate = read_superblock_at(reader, location);
        match candidate {
            Ok(candidate)
                if best
                    .as_ref()
                    .is_none_or(|(current, _)| candidate.generation() > current.generation()) =>
            {
                best = Some((candidate, location.read_offset));
            }
            Ok(_) => {}
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
    }
    let (best, read_offset) =
        best.ok_or_else(|| first_error.unwrap_or(BtrfsError::ZonedSuperblockNotFound))?;
    let superblock_size =
        u64::try_from(SUPERBLOCK_SIZE).map_err(|_| BtrfsError::IntegerOverflow)?;
    let position = read_offset
        .checked_add(superblock_size)
        .ok_or(BtrfsError::IntegerOverflow)?;
    reader.seek(SeekFrom::Start(position))?;
    Ok(best)
}

fn read_superblock_at<R: Read + Seek>(
    reader: &mut R,
    location: SuperblockLocation,
) -> Result<BtrfsSuperblock> {
    reader.seek(SeekFrom::Start(location.read_offset))?;
    let mut data = [0_u8; SUPERBLOCK_SIZE];
    reader.read_exact(&mut data)?;
    BtrfsSuperblock::from_bytes_at(&data, location.mirror_address)
}

fn validate_header(
    data: &[u8],
    raw: &RawSuperblock,
    expected_physical_address: u64,
) -> Result<(u64, ChecksumType)> {
    let actual_magic = raw.magic;
    if actual_magic != SUPERBLOCK_MAGIC {
        return Err(BtrfsError::InvalidMagic {
            actual: actual_magic,
        });
    }

    let physical_address = raw.physical_address.get();
    if physical_address != expected_physical_address {
        return Err(BtrfsError::InvalidPhysicalAddress {
            expected: expected_physical_address,
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
            structure: if expected_physical_address == PRIMARY_SUPERBLOCK_OFFSET {
                "primary superblock"
            } else {
                "backup superblock"
            },
            logical: physical_address,
        });
    }
    Ok((physical_address, checksum_type))
}

fn validate_features(raw: &RawSuperblock) -> Result<u64> {
    let flags = raw.incompat_flags.get();
    let unsupported = flags & !SUPPORTED_INCOMPAT_FLAGS;
    if unsupported != 0 {
        return Err(BtrfsError::UnsupportedIncompatFeatures { flags: unsupported });
    }
    if flags & EXTENT_TREE_V2_INCOMPAT != 0 {
        let compat_ro = raw.compat_ro_flags.get();
        let missing_compat_ro = EXTENT_TREE_V2_REQUIRED_COMPAT_RO & !compat_ro;
        if missing_compat_ro != 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "extent_tree_v2_missing_compat_ro",
                value: missing_compat_ro,
            });
        }
        if flags & NO_HOLES_INCOMPAT == 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "extent_tree_v2_no_holes",
                value: flags,
            });
        }
        if raw.global_root_count.get() == 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "global_root_count",
                value: 0,
            });
        }
    } else if raw.global_root_count.get() != 0 {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "global_root_count_without_extent_tree_v2",
            value: raw.global_root_count.get(),
        });
    }
    if flags & REMAP_TREE_INCOMPAT != 0 {
        let compat_ro = raw.compat_ro_flags.get();
        let missing_compat_ro = REMAP_TREE_REQUIRED_COMPAT_RO & !compat_ro;
        if missing_compat_ro != 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "remap_tree_missing_compat_ro",
                value: missing_compat_ro,
            });
        }
        if flags & NO_HOLES_INCOMPAT == 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "remap_tree_no_holes",
                value: flags,
            });
        }
        let incompatible = flags & (MIXED_GROUPS_INCOMPAT | ZONED_INCOMPAT);
        if incompatible != 0 {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "remap_tree_incompatible_features",
                value: incompatible,
            });
        }
    } else if raw.remap_root.get() != 0
        || raw.remap_root_generation.get() != 0
        || raw.remap_root_level != 0
    {
        return Err(BtrfsError::InvalidSuperblockField {
            field: "remap_root_without_feature",
            value: raw.remap_root.get(),
        });
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
    let remap_root = raw.remap_root.get();
    let remap_root_level = raw.remap_root_level;
    if raw.incompat_flags.get() & REMAP_TREE_INCOMPAT != 0 {
        validate_tree_root("remap", remap_root, remap_root_level, sector_size)?;
        let remap_generation = raw.remap_root_generation.get();
        if remap_generation == 0 || remap_generation > raw.generation.get() {
            return Err(BtrfsError::InvalidSuperblockField {
                field: "remap_root_generation",
                value: remap_generation,
            });
        }
    }
    Ok(TreeRoots {
        root,
        root_level,
        chunk_root,
        chunk_root_level,
        log_root,
        log_root_level,
        remap_root,
        remap_root_level,
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
        let incompat_flags = raw.incompat_flags.get()
            & SUPPORTED_INCOMPAT_FLAGS
            & !(RAID_STRIPE_TREE_INCOMPAT | REMAP_TREE_INCOMPAT);

        raw.checksum.fill(0);
        raw.physical_address = U64::new(PRIMARY_SUPERBLOCK_OFFSET);
        raw.flags = U64::new(raw.flags.get() & SUPPORTED_SUPERBLOCK_FLAGS);
        raw.magic = SUPERBLOCK_MAGIC;
        raw.root = U64::new(aligned_nonzero(raw.root.get(), sector_size));
        raw.chunk_root = U64::new(aligned_nonzero(raw.chunk_root.get(), sector_size));
        raw.log_root = U64::new(aligned(raw.log_root.get(), sector_size));
        raw.remap_root = U64::new(0);
        raw.remap_root_generation = U64::new(0);
        raw.remap_root_level = 0;
        raw.total_bytes = U64::new(total_bytes);
        raw.bytes_used = U64::new(raw.bytes_used.get().clamp(minimum_bytes_used, total_bytes));
        raw.root_dir_object_id = U64::new(6);
        raw.num_devices = U64::new(raw.num_devices.get().clamp(1, 32));
        raw.sector_size = U32::new(sector_size);
        raw.node_size = U32::new(sector_size);
        raw.leaf_size = U32::new(sector_size);
        raw.stripe_size = U32::new(sector_size);
        raw.incompat_flags = U64::new(incompat_flags);
        if incompat_flags & EXTENT_TREE_V2_INCOMPAT != 0 {
            raw.compat_ro_flags =
                U64::new(raw.compat_ro_flags.get() | EXTENT_TREE_V2_REQUIRED_COMPAT_RO);
            raw.global_root_count = U64::new(raw.global_root_count.get().max(1));
        } else {
            raw.global_root_count = U64::new(0);
        }
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
        raw.root_backups.as_mut_bytes().fill(0);
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
