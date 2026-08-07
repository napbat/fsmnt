use crate::error::{BtrfsError, Result};

pub use fsmnt_parser_core::boot_sector::{
    BTRFS_PRIMARY_SUPERBLOCK_OFFSET as PRIMARY_SUPERBLOCK_OFFSET,
    BTRFS_SUPERBLOCK_MAGIC as SUPERBLOCK_MAGIC,
};

/// Size of one serialized Btrfs superblock.
pub const SUPERBLOCK_SIZE: usize = 0x1000;

const MIN_VOLUME_BYTES: u64 = PRIMARY_SUPERBLOCK_OFFSET + 0x1000;
const FSID_OFFSET: usize = 0x20;
const FSID_SIZE: usize = 0x10;
const PHYSICAL_ADDRESS_OFFSET: usize = 0x30;
const MAGIC_OFFSET: usize = 0x40;
const GENERATION_OFFSET: usize = 0x48;
const TOTAL_BYTES_OFFSET: usize = 0x70;
const BYTES_USED_OFFSET: usize = 0x78;
const ROOT_DIR_OBJECT_ID_OFFSET: usize = 0x80;
const NUM_DEVICES_OFFSET: usize = 0x88;
const SECTOR_SIZE_OFFSET: usize = 0x90;
const NODE_SIZE_OFFSET: usize = 0x94;
const DEVICE_ITEM_OFFSET: usize = 0xc9;
const DEVICE_ID_OFFSET: usize = DEVICE_ITEM_OFFSET;
const DEVICE_UUID_OFFSET: usize = DEVICE_ITEM_OFFSET + 0x42;
const LABEL_OFFSET: usize = 0x12b;
const LABEL_SIZE: usize = 0x100;
const MAX_BLOCK_SIZE: u32 = 65_536;
const MIN_SECTOR_SIZE: u32 = 4096;

/// Validated metadata from a primary Btrfs superblock.
///
/// This initial parser covers identification and core volume geometry. It
/// does not yet verify the checksum or interpret tree roots and feature flags.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtrfsSuperblock {
    fsid: [u8; 16],
    physical_address: u64,
    generation: u64,
    total_bytes: u64,
    bytes_used: u64,
    root_dir_object_id: u64,
    num_devices: u64,
    sector_size: u32,
    node_size: u32,
    device_id: u64,
    device_uuid: [u8; 16],
    label: [u8; LABEL_SIZE],
}

impl BtrfsSuperblock {
    /// Parse and validate bytes read from the primary superblock location.
    ///
    /// # Errors
    ///
    /// Returns [`BtrfsError`] when the buffer is short or when the signature,
    /// self-address, size, device count, or block geometry is invalid.
    pub fn from_primary_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < SUPERBLOCK_SIZE {
            return Err(BtrfsError::BufferTooSmall {
                expected: SUPERBLOCK_SIZE,
                actual: data.len(),
            });
        }

        let mut actual_magic = [0_u8; 8];
        actual_magic.copy_from_slice(&data[MAGIC_OFFSET..MAGIC_OFFSET + SUPERBLOCK_MAGIC.len()]);
        if actual_magic != SUPERBLOCK_MAGIC {
            return Err(BtrfsError::InvalidMagic {
                actual: actual_magic,
            });
        }

        let physical_address = read_u64(data, PHYSICAL_ADDRESS_OFFSET);
        if physical_address != PRIMARY_SUPERBLOCK_OFFSET {
            return Err(BtrfsError::InvalidPhysicalAddress {
                actual: physical_address,
            });
        }

        let total_bytes = read_u64(data, TOTAL_BYTES_OFFSET);
        if total_bytes < MIN_VOLUME_BYTES {
            return Err(BtrfsError::InvalidTotalBytes {
                actual: total_bytes,
            });
        }
        let bytes_used = read_u64(data, BYTES_USED_OFFSET);
        if bytes_used > total_bytes {
            return Err(BtrfsError::InvalidBytesUsed {
                bytes_used,
                total_bytes,
            });
        }

        let num_devices = read_u64(data, NUM_DEVICES_OFFSET);
        if num_devices == 0 {
            return Err(BtrfsError::InvalidDeviceCount);
        }

        let sector_size = read_u32(data, SECTOR_SIZE_OFFSET);
        if !sector_size.is_power_of_two()
            || !(MIN_SECTOR_SIZE..=MAX_BLOCK_SIZE).contains(&sector_size)
        {
            return Err(BtrfsError::InvalidSectorSize {
                actual: sector_size,
            });
        }
        let node_size = read_u32(data, NODE_SIZE_OFFSET);
        if !node_size.is_power_of_two() || !(sector_size..=MAX_BLOCK_SIZE).contains(&node_size) {
            return Err(BtrfsError::InvalidNodeSize {
                actual: node_size,
                sector_size,
            });
        }

        let mut fsid = [0_u8; FSID_SIZE];
        fsid.copy_from_slice(&data[FSID_OFFSET..FSID_OFFSET + FSID_SIZE]);
        let mut device_uuid = [0_u8; FSID_SIZE];
        device_uuid.copy_from_slice(&data[DEVICE_UUID_OFFSET..DEVICE_UUID_OFFSET + FSID_SIZE]);
        let mut label = [0_u8; LABEL_SIZE];
        label.copy_from_slice(&data[LABEL_OFFSET..LABEL_OFFSET + LABEL_SIZE]);

        Ok(Self {
            fsid,
            physical_address,
            generation: read_u64(data, GENERATION_OFFSET),
            total_bytes,
            bytes_used,
            root_dir_object_id: read_u64(data, ROOT_DIR_OBJECT_ID_OFFSET),
            num_devices,
            sector_size,
            node_size,
            device_id: read_u64(data, DEVICE_ID_OFFSET),
            device_uuid,
            label,
        })
    }

    /// Filesystem UUID in on-disk byte order.
    #[must_use]
    pub const fn fsid(&self) -> &[u8; 16] {
        &self.fsid
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

    /// Object identifier of the top-level directory.
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

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}
