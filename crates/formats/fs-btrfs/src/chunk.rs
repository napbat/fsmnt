//! Logical-to-physical chunk mappings, including mirrored and striped layouts.

use alloc::vec::Vec;

use crate::bytes::{array, slice, u16_at, u64_at};
use crate::key::{DISK_KEY_SIZE, DiskKey};
use crate::{BtrfsError, Result};

pub(crate) const CHUNK_ITEM_KEY: u8 = 228;
const FIRST_CHUNK_TREE_OBJECT_ID: u64 = 256;
const CHUNK_HEADER_SIZE: usize = 48;
const STRIPE_SIZE: usize = 32;
const BTRFS_STRIPE_LENGTH: u64 = 64 * 1024;

const PROFILE_RAID0: u64 = 1_u64 << 3;
const PROFILE_RAID1: u64 = 1_u64 << 4;
const PROFILE_DUP: u64 = 1_u64 << 5;
const PROFILE_RAID10: u64 = 1_u64 << 6;
const PROFILE_RAID5: u64 = 1_u64 << 7;
const PROFILE_RAID6: u64 = 1_u64 << 8;
const PROFILE_RAID1C3: u64 = 1_u64 << 9;
const PROFILE_RAID1C4: u64 = 1_u64 << 10;
const PROFILE_MASK: u64 = PROFILE_RAID0
    | PROFILE_RAID1
    | PROFILE_DUP
    | PROFILE_RAID10
    | PROFILE_RAID5
    | PROFILE_RAID6
    | PROFILE_RAID1C3
    | PROFILE_RAID1C4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkStripe {
    pub(crate) device_id: u64,
    pub(crate) offset: u64,
    pub(crate) device_uuid: [u8; 16],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ChunkMapping {
    pub(crate) logical: u64,
    pub(crate) length: u64,
    pub(crate) stripe_length: u64,
    pub(crate) flags: u64,
    pub(crate) sub_stripes: u16,
    pub(crate) stripes: Vec<ChunkStripe>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalLocation {
    pub(crate) device_id: u64,
    pub(crate) offset: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MappedSegment {
    pub(crate) locations: Vec<PhysicalLocation>,
    pub(crate) length: usize,
}

impl ChunkMapping {
    pub(crate) fn parse(logical: u64, data: &[u8]) -> Result<Self> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(BtrfsError::InvalidChunk { logical });
        }
        let stripe_count = usize::from(u16_at(data, 44)?);
        let stripe_bytes = stripe_count
            .checked_mul(STRIPE_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let expected = CHUNK_HEADER_SIZE
            .checked_add(stripe_bytes)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if stripe_count == 0 || data.len() < expected {
            return Err(BtrfsError::InvalidChunk { logical });
        }

        let mut stripes = Vec::with_capacity(stripe_count);
        for index in 0..stripe_count {
            let offset = CHUNK_HEADER_SIZE
                .checked_add(
                    index
                        .checked_mul(STRIPE_SIZE)
                        .ok_or(BtrfsError::IntegerOverflow)?,
                )
                .ok_or(BtrfsError::IntegerOverflow)?;
            stripes.push(ChunkStripe {
                device_id: u64_at(data, offset)?,
                offset: u64_at(data, offset + 8)?,
                device_uuid: array(data, offset + 16)?,
            });
        }

        let mapping = Self {
            logical,
            length: u64_at(data, 0)?,
            stripe_length: u64_at(data, 16)?,
            flags: u64_at(data, 24)?,
            sub_stripes: u16_at(data, 46)?,
            stripes,
        };
        mapping.validate()?;
        Ok(mapping)
    }

    pub(crate) fn serialized_size(data: &[u8], logical: u64) -> Result<usize> {
        if data.len() < CHUNK_HEADER_SIZE {
            return Err(BtrfsError::InvalidChunk { logical });
        }
        CHUNK_HEADER_SIZE
            .checked_add(
                usize::from(u16_at(data, 44)?)
                    .checked_mul(STRIPE_SIZE)
                    .ok_or(BtrfsError::IntegerOverflow)?,
            )
            .ok_or(BtrfsError::IntegerOverflow)
    }

    fn validate(&self) -> Result<()> {
        let profile = self.flags & PROFILE_MASK;
        let stripe_count = self.stripes.len();
        let valid = self.length != 0
            && self.stripe_length == BTRFS_STRIPE_LENGTH
            && match profile {
                0 => stripe_count == 1,
                PROFILE_DUP | PROFILE_RAID1 | PROFILE_RAID5 => stripe_count >= 2,
                PROFILE_RAID0 => !self.stripes.is_empty(),
                PROFILE_RAID1C3 | PROFILE_RAID6 => stripe_count >= 3,
                PROFILE_RAID1C4 => stripe_count >= 4,
                PROFILE_RAID10 => {
                    let copies = usize::from(self.sub_stripes);
                    copies >= 2 && stripe_count >= copies && stripe_count.is_multiple_of(copies)
                }
                _ => false,
            };
        if !valid {
            return Err(BtrfsError::InvalidChunk {
                logical: self.logical,
            });
        }
        self.logical
            .checked_add(self.length)
            .ok_or(BtrfsError::InvalidChunk {
                logical: self.logical,
            })?;
        Ok(())
    }

    pub(crate) fn contains(&self, logical: u64) -> bool {
        logical >= self.logical && logical < self.logical.saturating_add(self.length)
    }

    pub(crate) fn map(&self, logical: u64, requested: usize) -> Result<MappedSegment> {
        if !self.contains(logical) {
            return Err(BtrfsError::LogicalAddressUnmapped { logical });
        }
        let relative = logical - self.logical;
        let chunk_remaining = self.length - relative;
        let requested_u64 = u64::try_from(requested).map_err(|_| BtrfsError::IntegerOverflow)?;
        let maximum = chunk_remaining.min(requested_u64);
        let profile = self.flags & PROFILE_MASK;

        match profile {
            0 | PROFILE_DUP | PROFILE_RAID1 | PROFILE_RAID1C3 | PROFILE_RAID1C4 => {
                self.map_mirrored(relative, maximum)
            }
            PROFILE_RAID0 => self.map_raid0(relative, maximum),
            PROFILE_RAID10 => self.map_raid10(relative, maximum),
            PROFILE_RAID5 => self.map_raid56(relative, maximum, 1),
            PROFILE_RAID6 => self.map_raid56(relative, maximum, 2),
            _ => Err(BtrfsError::UnsupportedChunkProfile { profile }),
        }
    }

    fn map_mirrored(&self, relative: u64, maximum: u64) -> Result<MappedSegment> {
        let mut locations = Vec::with_capacity(self.stripes.len());
        for stripe in &self.stripes {
            locations.push(PhysicalLocation {
                device_id: stripe.device_id,
                offset: stripe
                    .offset
                    .checked_add(relative)
                    .ok_or(BtrfsError::IntegerOverflow)?,
            });
        }
        Ok(MappedSegment {
            locations,
            length: usize::try_from(maximum).map_err(|_| BtrfsError::IntegerOverflow)?,
        })
    }

    fn map_raid0(&self, relative: u64, maximum: u64) -> Result<MappedSegment> {
        let stripe_number = relative / self.stripe_length;
        let stripe_count =
            u64::try_from(self.stripes.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_index = usize::try_from(stripe_number % stripe_count)
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_set = stripe_number / stripe_count;
        let within_stripe = relative % self.stripe_length;
        let contiguous = maximum.min(self.stripe_length - within_stripe);
        let stripe = &self.stripes[stripe_index];
        let stripe_set_offset = stripe_set
            .checked_mul(self.stripe_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let physical = stripe
            .offset
            .checked_add(stripe_set_offset)
            .and_then(|value| value.checked_add(within_stripe))
            .ok_or(BtrfsError::IntegerOverflow)?;
        Ok(MappedSegment {
            locations: alloc::vec![PhysicalLocation {
                device_id: stripe.device_id,
                offset: physical,
            }],
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
        })
    }

    fn map_raid10(&self, relative: u64, maximum: u64) -> Result<MappedSegment> {
        let copies = usize::from(self.sub_stripes);
        let data_stripes = self.stripes.len() / copies;
        let data_stripes_u64 =
            u64::try_from(data_stripes).map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_number = relative / self.stripe_length;
        let data_index = usize::try_from(stripe_number % data_stripes_u64)
            .map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_set = stripe_number / data_stripes_u64;
        let within_stripe = relative % self.stripe_length;
        let contiguous = maximum.min(self.stripe_length - within_stripe);
        let first_replica = data_index
            .checked_mul(copies)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let stripe_set_offset = stripe_set
            .checked_mul(self.stripe_length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let mut locations = Vec::with_capacity(copies);
        for stripe in &self.stripes[first_replica..first_replica + copies] {
            let physical = stripe
                .offset
                .checked_add(stripe_set_offset)
                .and_then(|value| value.checked_add(within_stripe))
                .ok_or(BtrfsError::IntegerOverflow)?;
            locations.push(PhysicalLocation {
                device_id: stripe.device_id,
                offset: physical,
            });
        }
        Ok(MappedSegment {
            locations,
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
        })
    }

    fn map_raid56(
        &self,
        relative: u64,
        maximum: u64,
        parity_stripes: usize,
    ) -> Result<MappedSegment> {
        let data_stripes =
            self.stripes
                .len()
                .checked_sub(parity_stripes)
                .ok_or(BtrfsError::InvalidChunk {
                    logical: self.logical,
                })?;
        let data_stripes_u64 =
            u64::try_from(data_stripes).map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_number = relative / self.stripe_length;
        let data_index = stripe_number % data_stripes_u64;
        let full_stripe = stripe_number / data_stripes_u64;
        let stripe_count =
            u64::try_from(self.stripes.len()).map_err(|_| BtrfsError::IntegerOverflow)?;
        let stripe_index = usize::try_from(
            full_stripe
                .checked_add(data_index)
                .ok_or(BtrfsError::IntegerOverflow)?
                % stripe_count,
        )
        .map_err(|_| BtrfsError::IntegerOverflow)?;
        let within_stripe = relative % self.stripe_length;
        let contiguous = maximum.min(self.stripe_length - within_stripe);
        let stripe = &self.stripes[stripe_index];
        let physical = stripe
            .offset
            .checked_add(
                full_stripe
                    .checked_mul(self.stripe_length)
                    .ok_or(BtrfsError::IntegerOverflow)?,
            )
            .and_then(|offset| offset.checked_add(within_stripe))
            .ok_or(BtrfsError::IntegerOverflow)?;
        Ok(MappedSegment {
            locations: alloc::vec![PhysicalLocation {
                device_id: stripe.device_id,
                offset: physical,
            }],
            length: usize::try_from(contiguous).map_err(|_| BtrfsError::IntegerOverflow)?,
        })
    }
}

pub(crate) fn parse_system_chunks(data: &[u8]) -> Result<Vec<ChunkMapping>> {
    let mut chunks = Vec::new();
    let mut position = 0_usize;
    while position < data.len() {
        let key_end = position
            .checked_add(DISK_KEY_SIZE)
            .ok_or(BtrfsError::IntegerOverflow)?;
        let key = DiskKey::parse(slice(data, position, DISK_KEY_SIZE)?)?;
        if key.object_id != FIRST_CHUNK_TREE_OBJECT_ID || key.item_type != CHUNK_ITEM_KEY {
            return Err(BtrfsError::MalformedItem {
                object_id: key.object_id,
                item_type: key.item_type,
                offset: key.offset,
            });
        }
        let chunk_data = data.get(key_end..).ok_or(BtrfsError::InvalidChunk {
            logical: key.offset,
        })?;
        let size = ChunkMapping::serialized_size(chunk_data, key.offset)?;
        chunks.push(ChunkMapping::parse(
            key.offset,
            slice(chunk_data, 0, size)?,
        )?);
        position = key_end
            .checked_add(size)
            .ok_or(BtrfsError::IntegerOverflow)?;
    }
    sort_and_validate_chunks(&mut chunks)?;
    Ok(chunks)
}

pub(crate) fn merge_chunk(chunks: &mut Vec<ChunkMapping>, candidate: ChunkMapping) -> Result<()> {
    if let Some(existing) = chunks
        .iter()
        .find(|existing| existing.logical == candidate.logical)
    {
        if existing == &candidate {
            return Ok(());
        }
        return Err(BtrfsError::InvalidChunk {
            logical: candidate.logical,
        });
    }
    chunks.push(candidate);
    sort_and_validate_chunks(chunks)
}

fn sort_and_validate_chunks(chunks: &mut [ChunkMapping]) -> Result<()> {
    chunks.sort_unstable_by_key(|chunk| chunk.logical);
    for pair in chunks.windows(2) {
        let previous_end = pair[0]
            .logical
            .checked_add(pair[0].length)
            .ok_or(BtrfsError::IntegerOverflow)?;
        if previous_end > pair[1].logical {
            return Err(BtrfsError::OverlappingChunks {
                logical: pair[1].logical,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stripe(device_id: u64, offset: u64) -> ChunkStripe {
        ChunkStripe {
            device_id,
            offset,
            device_uuid: [0_u8; 16],
        }
    }

    fn mapping(flags: u64, sub_stripes: u16, stripes: Vec<ChunkStripe>) -> ChunkMapping {
        ChunkMapping {
            logical: 0x10_0000,
            length: 0x40_0000,
            stripe_length: 0x1_0000,
            flags,
            sub_stripes,
            stripes,
        }
    }

    #[test]
    fn single_mapping_preserves_relative_offset() {
        let chunk = mapping(0, 0, alloc::vec![stripe(7, 0x20_0000)]);
        chunk.validate().expect("single chunk");
        let mapped = chunk.map(0x12_3456, 4096).expect("map");

        assert_eq!(mapped.length, 4096);
        assert_eq!(
            mapped.locations,
            alloc::vec![PhysicalLocation {
                device_id: 7,
                offset: 0x22_3456
            }]
        );
    }

    #[test]
    fn raid1_exposes_every_replica() {
        let chunk = mapping(
            PROFILE_RAID1,
            0,
            alloc::vec![stripe(1, 0x20_0000), stripe(2, 0x30_0000)],
        );
        chunk.validate().expect("raid1 chunk");
        let mapped = chunk.map(0x11_0000, 512).expect("map");

        assert_eq!(
            mapped.locations,
            alloc::vec![
                PhysicalLocation {
                    device_id: 1,
                    offset: 0x21_0000
                },
                PhysicalLocation {
                    device_id: 2,
                    offset: 0x31_0000
                }
            ]
        );
    }

    #[test]
    fn raid0_interleaves_at_stripe_boundaries() {
        let chunk = mapping(
            PROFILE_RAID0,
            0,
            alloc::vec![stripe(1, 0x20_0000), stripe(2, 0x30_0000)],
        );
        chunk.validate().expect("raid0 chunk");

        let first = chunk.map(0x10_8000, 0x1_0000).expect("first");
        assert_eq!(first.length, 0x8000);
        assert_eq!(first.locations[0].device_id, 1);
        assert_eq!(first.locations[0].offset, 0x20_8000);

        let second = chunk.map(0x11_0000, 0x1_0000).expect("second");
        assert_eq!(second.locations[0].device_id, 2);
        assert_eq!(second.locations[0].offset, 0x30_0000);

        let third = chunk.map(0x12_0000, 0x1_0000).expect("third");
        assert_eq!(third.locations[0].device_id, 1);
        assert_eq!(third.locations[0].offset, 0x21_0000);
    }

    #[test]
    fn single_device_raid0_maps_like_one_data_stripe() {
        let chunk = mapping(PROFILE_RAID0, 0, alloc::vec![stripe(1, 0x20_0000)]);
        chunk.validate().expect("one-stripe raid0");

        let mapped = chunk.map(0x11_0000, 4096).expect("map");
        assert_eq!(mapped.locations[0].device_id, 1);
        assert_eq!(mapped.locations[0].offset, 0x21_0000);
    }

    #[test]
    fn raid10_groups_replicas_per_data_stripe() {
        let chunk = mapping(
            PROFILE_RAID10,
            2,
            alloc::vec![
                stripe(1, 0x20_0000),
                stripe(2, 0x30_0000),
                stripe(3, 0x40_0000),
                stripe(4, 0x50_0000),
            ],
        );
        chunk.validate().expect("raid10 chunk");

        let first = chunk.map(0x10_0000, 4096).expect("first");
        assert_eq!(
            first
                .locations
                .iter()
                .map(|location| location.device_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        let second = chunk.map(0x11_0000, 4096).expect("second");
        assert_eq!(
            second
                .locations
                .iter()
                .map(|location| location.device_id)
                .collect::<Vec<_>>(),
            [3, 4]
        );
    }

    #[test]
    fn raid5_skips_rotating_parity_stripes() {
        let chunk = mapping(
            PROFILE_RAID5,
            0,
            alloc::vec![
                stripe(1, 0x20_0000),
                stripe(2, 0x30_0000),
                stripe(3, 0x40_0000),
            ],
        );
        chunk.validate().expect("structurally valid raid5");

        let first = chunk.map(0x10_0000, 4096).expect("first data stripe");
        assert_eq!(first.locations[0].device_id, 1);
        assert_eq!(first.locations[0].offset, 0x20_0000);

        let second = chunk.map(0x11_0000, 4096).expect("second data stripe");
        assert_eq!(second.locations[0].device_id, 2);
        assert_eq!(second.locations[0].offset, 0x30_0000);

        let rotated = chunk.map(0x12_0000, 4096).expect("rotated parity");
        assert_eq!(rotated.locations[0].device_id, 2);
        assert_eq!(rotated.locations[0].offset, 0x31_0000);
    }

    #[test]
    fn raid6_skips_both_rotating_parity_stripes() {
        let chunk = mapping(
            PROFILE_RAID6,
            0,
            alloc::vec![
                stripe(1, 0x20_0000),
                stripe(2, 0x30_0000),
                stripe(3, 0x40_0000),
                stripe(4, 0x50_0000),
            ],
        );
        chunk.validate().expect("structurally valid raid6");

        let rotated = chunk.map(0x12_0000, 4096).expect("second full stripe");
        assert_eq!(rotated.locations[0].device_id, 2);
        assert_eq!(rotated.locations[0].offset, 0x31_0000);
    }
}
