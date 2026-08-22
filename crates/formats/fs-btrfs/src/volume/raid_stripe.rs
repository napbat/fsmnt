//! Data-extent mappings stored in the RAID stripe tree.

use alloc::vec::Vec;

use fsmnt_parser_core::io::{Read, Seek};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, LittleEndian as LE, U64, Unaligned};

use super::Btrfs;
use crate::chunk::{ChunkMapping, MappedSegment, PhysicalLocation};
use crate::tree::TreeItem;
use crate::{BtrfsError, DiskKey, Result};

const RAID_STRIPE_TREE_OBJECT_ID: u64 = 12;
const RAID_STRIPE_KEY: u8 = 230;
const RAID_STRIDE_SIZE: usize = 16;

#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(C)]
struct RawRaidStride {
    device_id: U64<LE>,
    physical: U64<LE>,
}

const _: [(); RAID_STRIDE_SIZE] = [(); core::mem::size_of::<RawRaidStride>()];

impl<R: Read + Seek> Btrfs<R> {
    pub(super) fn load_raid_stripe_root(&mut self) -> Result<()> {
        if !self.superblock().has_raid_stripe_tree() {
            return Ok(());
        }
        let root = self.lookup_tree_root(RAID_STRIPE_TREE_OBJECT_ID)?;
        self.read_tree_block(
            root.logical,
            root.level,
            root.tree_id,
            root.expected_generation,
            None,
        )?;
        self.raid_stripe_root = Some(root);
        Ok(())
    }

    pub(super) fn map_raid_stripe(
        &mut self,
        chunk: &ChunkMapping,
        logical: u64,
        requested: usize,
    ) -> Result<MappedSegment> {
        let root = self
            .raid_stripe_root
            .ok_or(BtrfsError::RaidStripeMissing { logical })?;
        let target = DiskKey {
            object_id: logical,
            item_type: RAID_STRIPE_KEY,
            offset: u64::MAX,
        };
        let item = self
            .find_predecessor(root, target)?
            .ok_or(BtrfsError::RaidStripeMissing { logical })?;
        map_item(
            &item,
            chunk,
            logical,
            requested,
            self.superblock().sector_size(),
        )
    }
}

fn map_item(
    item: &TreeItem,
    chunk: &ChunkMapping,
    logical: u64,
    requested: usize,
    sector_size: u32,
) -> Result<MappedSegment> {
    let expected_strides = chunk
        .raid_stripe_count()
        .ok_or(BtrfsError::InvalidRaidStripeItem { logical })?;
    let expected_size = expected_strides
        .checked_mul(RAID_STRIDE_SIZE)
        .ok_or(BtrfsError::IntegerOverflow)?;
    let item_end = item
        .key
        .object_id
        .checked_add(item.key.offset)
        .ok_or(BtrfsError::InvalidRaidStripeItem { logical })?;
    let chunk_end = chunk
        .logical
        .checked_add(chunk.length)
        .ok_or(BtrfsError::InvalidRaidStripeItem { logical })?;
    let sector_size = u64::from(sector_size);
    let valid = item.key.item_type == RAID_STRIPE_KEY
        && item.key.offset != 0
        && sector_size != 0
        && item.key.object_id.is_multiple_of(sector_size)
        && item.key.offset.is_multiple_of(sector_size)
        && item.key.object_id >= chunk.logical
        && item_end <= chunk_end
        && logical >= item.key.object_id
        && logical < item_end
        && item.data.len() == expected_size;
    if !valid {
        return Err(if item.key.item_type == RAID_STRIPE_KEY {
            BtrfsError::InvalidRaidStripeItem { logical }
        } else {
            BtrfsError::RaidStripeMissing { logical }
        });
    }

    let offset = logical - item.key.object_id;
    let remaining = item.key.offset - offset;
    let requested = u64::try_from(requested).map_err(|_| BtrfsError::IntegerOverflow)?;
    let length =
        usize::try_from(remaining.min(requested)).map_err(|_| BtrfsError::IntegerOverflow)?;
    let mut locations = Vec::with_capacity(expected_strides);
    for stride in item.data.as_chunks::<RAID_STRIDE_SIZE>().0 {
        let raw = RawRaidStride::ref_from_bytes(stride)
            .map_err(|_| BtrfsError::InvalidRaidStripeItem { logical })?;
        let device_id = raw.device_id.get();
        let physical = raw.physical.get();
        let device_uuid = chunk
            .device_uuid(device_id)
            .ok_or(BtrfsError::InvalidRaidStripeItem { logical })?;
        if device_id == 0
            || !physical.is_multiple_of(sector_size)
            || physical.checked_add(item.key.offset).is_none()
        {
            return Err(BtrfsError::InvalidRaidStripeItem { logical });
        }
        locations.push(PhysicalLocation {
            device_id,
            device_uuid,
            offset: physical
                .checked_add(offset)
                .ok_or(BtrfsError::InvalidRaidStripeItem { logical })?,
        });
    }
    Ok(MappedSegment {
        locations,
        length,
        raid56: None,
    })
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use zerocopy::IntoBytes;

    use super::{RAID_STRIPE_KEY, RawRaidStride, map_item};
    use crate::chunk::{ChunkMapping, ChunkStripe};
    use crate::tree::TreeItem;
    use crate::{BtrfsError, DiskKey};

    const TYPE_DATA: u64 = 1;
    const PROFILE_RAID1: u64 = 1_u64 << 4;
    const PROFILE_RAID5: u64 = 1_u64 << 7;

    fn stripe(device_id: u64, offset: u64) -> ChunkStripe {
        ChunkStripe {
            device_id,
            offset,
            device_uuid: [u8::try_from(device_id).unwrap_or_default(); 16],
        }
    }

    fn mapping(profile: u64, sub_stripes: u16, stripes: Vec<ChunkStripe>) -> ChunkMapping {
        ChunkMapping {
            logical: 0x10_0000,
            length: 0x40_0000,
            stripe_length: 0x1_0000,
            flags: TYPE_DATA | profile,
            sub_stripes,
            stripes,
        }
    }

    #[test]
    fn maps_each_recorded_copy_and_caps_at_item_end() {
        let chunk = mapping(
            PROFILE_RAID1,
            0,
            vec![stripe(1, 0x20_0000), stripe(2, 0x40_0000)],
        );
        let mut data = Vec::new();
        for (device_id, physical) in [(1, 0x30_0000), (2, 0x50_0000)] {
            data.extend_from_slice(
                RawRaidStride {
                    device_id: zerocopy::U64::new(device_id),
                    physical: zerocopy::U64::new(physical),
                }
                .as_bytes(),
            );
        }
        let item = TreeItem {
            key: DiskKey {
                object_id: chunk.logical,
                item_type: RAID_STRIPE_KEY,
                offset: 0x20_000,
            },
            data,
        };
        let mapped = map_item(&item, &chunk, chunk.logical + 0x10_000, 0x20_000, 4096)
            .expect("stripe mapping");
        assert_eq!(mapped.length, 0x10_000);
        assert_eq!(mapped.locations[0].offset, 0x31_0000);
        assert_eq!(mapped.locations[1].offset, 0x51_0000);
    }

    #[test]
    fn rejects_wrong_stride_count_devices_and_profiles() {
        let chunk = mapping(
            PROFILE_RAID1,
            0,
            vec![stripe(1, 0x20_0000), stripe(2, 0x40_0000)],
        );
        let item = TreeItem {
            key: DiskKey {
                object_id: chunk.logical,
                item_type: RAID_STRIPE_KEY,
                offset: 4096,
            },
            data: RawRaidStride {
                device_id: zerocopy::U64::new(99),
                physical: zerocopy::U64::new(0x30_0000),
            }
            .as_bytes()
            .to_vec(),
        };
        assert!(matches!(
            map_item(&item, &chunk, chunk.logical, 4096, 4096),
            Err(BtrfsError::InvalidRaidStripeItem { .. })
        ));

        let raid5 = mapping(
            PROFILE_RAID5,
            0,
            vec![stripe(1, 0), stripe(2, 0), stripe(3, 0)],
        );
        assert!(matches!(
            map_item(&item, &raid5, raid5.logical, 4096, 4096),
            Err(BtrfsError::InvalidRaidStripeItem { .. })
        ));
    }
}
