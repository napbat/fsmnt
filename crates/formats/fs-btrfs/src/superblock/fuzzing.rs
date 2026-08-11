use super::{
    ChecksumType, EXTENT_TREE_V2_INCOMPAT, EXTENT_TREE_V2_REQUIRED_COMPAT_RO, FromBytes, IntoBytes,
    MAX_BLOCK_SIZE, MAX_TREE_LEVELS, METADATA_UUID_INCOMPAT, MIN_SECTOR_SIZE, MIN_VOLUME_BYTES,
    PRIMARY_SUPERBLOCK_OFFSET, RAID_STRIPE_TREE_INCOMPAT, REMAP_TREE_INCOMPAT, RawSuperblock,
    SUPERBLOCK_MAGIC, SUPERBLOCK_SIZE, SUPPORTED_INCOMPAT_FLAGS, SUPPORTED_SUPERBLOCK_FLAGS, U16,
    U32, U64,
};

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

fn aligned(value: u64, sector_size: u32) -> u64 {
    let sector_size = u64::from(sector_size);
    value / sector_size * sector_size
}

fn aligned_nonzero(value: u64, sector_size: u32) -> u64 {
    let aligned = aligned(value, sector_size);
    if aligned == 0 {
        u64::from(sector_size)
    } else {
        aligned
    }
}
